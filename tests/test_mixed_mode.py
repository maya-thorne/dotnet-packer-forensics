"""
Unit and Integration Test Suite for Native Mixed-Mode PE & CIL-Native Transition Tracer.
Validates VTableFixup parsing, CIL/native execution boundary tracing, unmanaged exports, TLS hooks,
risk scoring, directory export, path traversal security, and CLI flags.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import shutil
import struct
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union
import unittest

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.mixed_mode import (
    CILNativeTransition,
    Cor20Flag,
    MixedModeAnalysisResult,
    MixedModeAnalyzer,
    MixedModeType,
    RiskSeverity,
    SecurityError,
    TransitionDirection,
    TransitionType,
    VTFixupFlag,
    VTFixupParser,
    VTFixupType,
    zeroize_buffer,
)
from dotnet_deobfuscator.mixed_mode.analyzer import _safe_path, calculate_entropy


def build_synthetic_pe(
    is_pe32_plus: bool = False,
    has_clr: bool = True,
    cor_flags: int = Cor20Flag.COMIMAGE_FLAGS_ILONLY,
    entry_token: int = 0x06000001,
    vtfixup_slots: Optional[List[int]] = None,
    vtfixup_type_flags: int = VTFixupFlag.COR_VTABLE_32BIT | VTFixupFlag.COR_VTABLE_FROM_UNMANAGED,
    export_funcs: Optional[List[Tuple[str, int]]] = None,
    tls_callbacks: Optional[List[int]] = None,
    native_code_payload: bytes = b"\x90\x90\xC3",
) -> bytes:
    """Constructs a well-formed PE executable with structured CLR, VTFixups, Exports, and TLS."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)

    pe_sig = b"PE\x00\x00"
    machine = 0x8664 if is_pe32_plus else 0x014C
    num_sections = 1
    opt_size = 240 if is_pe32_plus else 224
    chars = 0x0022
    file_hdr = struct.pack("<HHIIIHH", machine, num_sections, 0, 0, 0, opt_size, chars)

    magic = 0x020B if is_pe32_plus else 0x010B
    entry_point_rva = 0x1000
    image_base = 0x140000000 if is_pe32_plus else 0x400000
    sec_align = 0x1000
    file_align = 0x200

    if is_pe32_plus:
        opt_hdr_prefix = struct.pack(
            "<HBBIIIII" + "QIIHHHHHHIIIIHHQQQQII",
            magic, 14, 0, 0x1000, 0, 0, entry_point_rva, 0x1000,
            image_base, sec_align, file_align, 6, 0, 0, 0, 4, 0,
            0, 0x10000, 0x1000, 0, 3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
    else:
        opt_hdr_prefix = struct.pack(
            "<HBBIIIIII" + "IIIHHHHHHIIIIHHIIIIII",
            magic, 14, 0, 0x1000, 0, 0, entry_point_rva, 0x1000, 0x1000,
            image_base, sec_align, file_align, 6, 0, 0, 0, 4, 0,
            0, 0x10000, 0x1000, 0, 3, 0x8160,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )

    data_dirs = [bytearray(8) for _ in range(16)]
    raw_sec_offset = 0x400
    sec_vaddr = 0x1000
    sec_buf = bytearray()

    # 1. Native Code
    sec_buf.extend(native_code_payload)
    while len(sec_buf) % 16 != 0:
        sec_buf.append(0)

    # 2. Cor20Header placeholder
    cor20_rva = sec_vaddr + len(sec_buf)
    cor20_size = 72
    cor20_offset_in_sec = len(sec_buf)
    sec_buf.extend(b"\x00" * 72)

    # 3. VTFixups
    vtfixup_rva = 0
    vtfixup_hdr_size = 0
    slots_rva = 0
    if vtfixup_slots is not None:
        while len(sec_buf) % 16 != 0:
            sec_buf.append(0)
        vtfixup_rva = sec_vaddr + len(sec_buf)
        is_64 = bool(vtfixup_type_flags & VTFixupFlag.COR_VTABLE_64BIT)
        slot_width = 8 if is_64 else 4
        slots_rva = vtfixup_rva + 8
        hdr = struct.pack("<IHH", slots_rva, len(vtfixup_slots), vtfixup_type_flags)
        sec_buf.extend(hdr)
        for tok in vtfixup_slots:
            sec_buf.extend(struct.pack("<Q" if is_64 else "<I", tok))
        vtfixup_hdr_size = len(hdr)

    # 4. Exports
    export_rva = 0
    export_size = 0
    if export_funcs is not None:
        while len(sec_buf) % 16 != 0:
            sec_buf.append(0)
        export_rva = sec_vaddr + len(sec_buf)
        num_funcs = len(export_funcs)
        addr_funcs_rva = export_rva + 40
        addr_names_rva = addr_funcs_rva + (num_funcs * 4)
        addr_ords_rva = addr_names_rva + (num_funcs * 4)
        dll_name_rva = addr_ords_rva + (num_funcs * 2)
        dll_name_b = b"TestBridge.dll\x00"

        str_rvas = []
        cur_str_rva = dll_name_rva + len(dll_name_b)
        for name_str, _ in export_funcs:
            str_rvas.append(cur_str_rva)
            cur_str_rva += len(name_str.encode("latin1")) + 1

        exp_dir = struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0, dll_name_rva, 1, num_funcs, num_funcs,
            addr_funcs_rva, addr_names_rva, addr_ords_rva,
        )
        sec_buf.extend(exp_dir)
        for _, fn_rva in export_funcs:
            actual_fn_rva = (slots_rva if vtfixup_slots else sec_vaddr) if fn_rva == 0 else fn_rva
            sec_buf.extend(struct.pack("<I", actual_fn_rva))
        for nr in str_rvas:
            sec_buf.extend(struct.pack("<I", nr))
        for idx in range(num_funcs):
            sec_buf.extend(struct.pack("<H", idx))
        sec_buf.extend(dll_name_b)
        for name_str, _ in export_funcs:
            sec_buf.extend(name_str.encode("latin1") + b"\x00")

        export_size = (sec_vaddr + len(sec_buf)) - export_rva
        data_dirs[0] = struct.pack("<II", export_rva, export_size)

    # 5. TLS
    tls_rva = 0
    tls_size = 0
    if tls_callbacks is not None:
        while len(sec_buf) % 16 != 0:
            sec_buf.append(0)
        tls_rva = sec_vaddr + len(sec_buf)
        ptr_size = 8 if is_pe32_plus else 4
        tls_dir_size = 40 if is_pe32_plus else 24
        cb_array_rva = tls_rva + tls_dir_size
        cb_array_va = image_base + cb_array_rva
        if is_pe32_plus:
            tls_hdr = struct.pack("<QQQQII", 0, 0, 0, cb_array_va, 0, 0)
        else:
            tls_hdr = struct.pack("<IIIIII", 0, 0, 0, cb_array_va, 0, 0)
        sec_buf.extend(tls_hdr)
        for cb in tls_callbacks:
            sec_buf.extend(struct.pack("<Q" if is_pe32_plus else "<I", image_base + cb))
        sec_buf.extend(struct.pack("<Q" if is_pe32_plus else "<I", 0))
        tls_size = (sec_vaddr + len(sec_buf)) - tls_rva
        data_dirs[9] = struct.pack("<II", tls_rva, tls_size)

    # 6. Cor20Header
    if has_clr:
        data_dirs[14] = struct.pack("<II", cor20_rva, cor20_size)
        cor20_header = struct.pack(
            "<IHHIIIIIIIIIIIIIIII",
            72, 2, 5, 0x2000, 0x500, cor_flags, entry_token,
            0, 0, 0, 0, 0, 0, vtfixup_rva, vtfixup_hdr_size, 0, 0, 0, 0,
        )
        sec_buf[cor20_offset_in_sec : cor20_offset_in_sec + 72] = cor20_header

    while len(sec_buf) % file_align != 0:
        sec_buf.append(0)

    raw_sec_size = len(sec_buf)
    v_sec_size = max(raw_sec_size, 0x1000)
    sec_name = b".text\x00\x00\x00"
    sec_chars = 0x60000020
    sec_hdr = struct.pack("<8sIIIIIIHHI", sec_name, v_sec_size, sec_vaddr, raw_sec_size, raw_sec_offset, 0, 0, 0, 0, sec_chars)

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(file_hdr)
    pe.extend(opt_hdr_prefix)
    for dd in data_dirs:
        pe.extend(dd)
    pe.extend(sec_hdr)

    while len(pe) < raw_sec_offset:
        pe.append(0)

    pe.extend(sec_buf)
    return bytes(pe)


class TestNativeMixedModeForensics(unittest.TestCase):
    """Test suite validating native mixed-mode PE forensic analysis."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_mm_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pure_managed_assembly_classification(self):
        """Pure managed assembly with COMIMAGE_FLAGS_ILONLY and no VTFixups."""
        pe_bytes = build_synthetic_pe(
            has_clr=True,
            cor_flags=Cor20Flag.COMIMAGE_FLAGS_ILONLY,
            entry_token=0x06000001,
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="pure_managed.exe")
        self.assertFalse(res.telemetry.is_mixed_mode)
        self.assertEqual(res.telemetry.mixed_mode_type, MixedModeType.PURE_MANAGED.value)
        self.assertEqual(res.telemetry.confidence, "HIGH")
        self.assertIn("COMIMAGE_FLAGS_ILONLY", res.telemetry.cor20_flags)
        self.assertFalse(res.telemetry.has_native_entrypoint)
        self.assertEqual(res.telemetry.vtfixup_tables_count, 0)
        self.assertIn(res.telemetry.risk_severity, [RiskSeverity.INFORMATIONAL.value, RiskSeverity.LOW.value])

    def test_pure_native_pe_classification(self):
        """Standard PE executable with no CLR Cor20Header."""
        pe_bytes = build_synthetic_pe(has_clr=False)
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="native_only.exe")
        self.assertFalse(res.telemetry.is_mixed_mode)
        self.assertEqual(res.telemetry.mixed_mode_type, MixedModeType.PURE_NATIVE.value)
        self.assertEqual(res.telemetry.confidence, "HIGH")
        self.assertEqual(len(res.telemetry.cor20_flags), 0)

    def test_mixed_mode_ijwh_detection_cleared_ilonly(self):
        """Mixed-mode assembly with COMIMAGE_FLAGS_ILONLY cleared."""
        pe_bytes = build_synthetic_pe(
            has_clr=True,
            cor_flags=0,
            entry_token=0x06000002,
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="mixed_ijwh.exe")
        self.assertTrue(res.telemetry.is_mixed_mode)
        self.assertEqual(res.telemetry.mixed_mode_type, MixedModeType.MIXED_MODE_IJWH.value)
        self.assertEqual(res.telemetry.confidence, "HIGH")
        self.assertNotIn("COMIMAGE_FLAGS_ILONLY", res.telemetry.cor20_flags)
        self.assertTrue(any("COMIMAGE_FLAGS_ILONLY cleared" in a for a in res.telemetry.anomalies))
        self.assertGreaterEqual(res.telemetry.risk_score, 30)

    def test_native_entrypoint_transition_tracing(self):
        """Mixed-mode PE with COMIMAGE_FLAGS_NATIVE_ENTRYPOINT pointing to native bootstrap code."""
        native_ep_rva = 0x1000
        pe_bytes = build_synthetic_pe(
            has_clr=True,
            cor_flags=Cor20Flag.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT,
            entry_token=native_ep_rva,
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="native_ep.exe")
        self.assertTrue(res.telemetry.is_mixed_mode)
        self.assertTrue(res.telemetry.has_native_entrypoint)
        self.assertEqual(res.telemetry.native_entrypoint_rva, native_ep_rva)

        ep_transitions = [t for t in res.transitions if t.transition_type == TransitionType.NATIVE_ENTRYPOINT]
        self.assertEqual(len(ep_transitions), 1)
        self.assertEqual(ep_transitions[0].direction, TransitionDirection.NATIVE_TO_MANAGED)
        self.assertIn("0x00001000", ep_transitions[0].source_location)

    def test_vtable_fixups_32bit_parsing(self):
        """Parses 32-bit VTableFixup table with MethodDef target tokens."""
        pe_bytes = build_synthetic_pe(
            has_clr=True,
            cor_flags=0,
            vtfixup_slots=[0x06000001, 0x06000002],
            vtfixup_type_flags=VTFixupFlag.COR_VTABLE_32BIT | VTFixupFlag.COR_VTABLE_FROM_UNMANAGED,
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="vtfixup_32.exe")
        self.assertTrue(res.telemetry.is_mixed_mode)
        self.assertEqual(res.telemetry.vtfixup_tables_count, 1)

        tbl = res.vtfixup_tables[0]
        self.assertEqual(tbl.slot_count, 2)
        self.assertEqual(tbl.fixup_type, VTFixupType.SLOT_32BIT)
        self.assertIn("COR_VTABLE_FROM_UNMANAGED", tbl.flags_names)

        self.assertEqual(len(tbl.slots), 2)
        slot0 = tbl.slots[0]
        self.assertEqual(slot0.target_token_hex, "0x06000001")
        self.assertEqual(slot0.token_type_name, "MethodDef")
        self.assertTrue(slot0.is_from_unmanaged)

        slot1 = tbl.slots[1]
        self.assertEqual(slot1.target_token_hex, "0x06000002")

        vtf_transitions = [t for t in res.transitions if t.transition_type == TransitionType.VTFIXUP_THUNK]
        self.assertEqual(len(vtf_transitions), 2)
        self.assertEqual(vtf_transitions[0].direction, TransitionDirection.NATIVE_TO_MANAGED)

    def test_vtable_fixups_64bit_parsing(self):
        """Parses 64-bit VTableFixup table with 8-byte slots."""
        pe_bytes = build_synthetic_pe(
            is_pe32_plus=True,
            has_clr=True,
            cor_flags=0,
            vtfixup_slots=[0x0600000A, 0x0600000B],
            vtfixup_type_flags=VTFixupFlag.COR_VTABLE_64BIT | VTFixupFlag.COR_VTABLE_FROM_UNMANAGED,
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="vtfixup_64.exe")
        self.assertTrue(res.telemetry.is_mixed_mode)
        self.assertEqual(res.telemetry.vtfixup_tables_count, 1)
        tbl = res.vtfixup_tables[0]
        self.assertEqual(tbl.fixup_type, VTFixupType.SLOT_64BIT)
        self.assertEqual(len(tbl.slots), 2)
        self.assertEqual(tbl.slots[0].target_token_hex, "0x0600000A")
        self.assertEqual(tbl.slots[1].target_token_hex, "0x0600000B")

    def test_unmanaged_export_bridges(self):
        """Detects unmanaged PE exports that bridge to managed VTFixup tokens."""
        pe_bytes = build_synthetic_pe(
            has_clr=True,
            cor_flags=0,
            vtfixup_slots=[0x06000020],
            export_funcs=[("ManagedEntryThunk", 0)],  # 0 indicates target matches VTFixup slot
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="exported_bridge.dll")
        self.assertTrue(res.telemetry.is_mixed_mode)
        self.assertEqual(len(res.export_bridges), 1)

        bridge = res.export_bridges[0]
        self.assertTrue(bridge.is_vtfixup_thunk)
        self.assertEqual(bridge.export_name, "ManagedEntryThunk")
        self.assertEqual(bridge.linked_token_hex, "0x06000020")

        exp_transitions = [t for t in res.transitions if t.transition_type == TransitionType.UNMANAGED_EXPORT]
        self.assertGreaterEqual(len(exp_transitions), 1)
        self.assertIn("0x06000020", exp_transitions[0].target_location)

    def test_native_tls_callbacks_detection(self):
        """Identifies native TLS callbacks executing prior to CLR runtime."""
        pe_bytes = build_synthetic_pe(
            has_clr=True,
            cor_flags=0,
            tls_callbacks=[0x1000],
        )
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="tls_hook.exe")
        self.assertTrue(res.telemetry.is_mixed_mode)
        self.assertEqual(res.telemetry.tls_callbacks_count, 1)

        tls_transitions = [t for t in res.transitions if t.transition_type == TransitionType.TLS_CALLBACK]
        self.assertEqual(len(tls_transitions), 1)
        self.assertTrue(tls_transitions[0].is_suspicious)
        self.assertIn("High-risk evasion vector", tls_transitions[0].risk_factor)

    def test_risk_scoring_and_anomaly_telemetry(self):
        """Validates cumulative risk score calculation and severity levels."""
        # 1. Low risk pure managed
        pe_pure = build_synthetic_pe(has_clr=True, cor_flags=Cor20Flag.COMIMAGE_FLAGS_ILONLY)
        res_pure = MixedModeAnalyzer.analyze(pe_pure)
        self.assertEqual(res_pure.telemetry.risk_severity, RiskSeverity.INFORMATIONAL.value)

        # 2. Critical risk mixed-mode with native EP, TLS callbacks, and VTFixup
        pe_complex = build_synthetic_pe(
            has_clr=True,
            cor_flags=Cor20Flag.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT,
            entry_token=0x1000,
            vtfixup_slots=[0x06000050],
            export_funcs=[("BridgeFunc", 0)],
            tls_callbacks=[0x1000],
        )
        res_complex = MixedModeAnalyzer.analyze(pe_complex)
        self.assertGreaterEqual(res_complex.telemetry.risk_score, 75)
        self.assertEqual(res_complex.telemetry.risk_severity, RiskSeverity.CRITICAL.value)

    def test_directory_export_and_path_traversal_defense(self):
        """Verifies safe file export and prevents directory traversal attacks."""
        pe_bytes = build_synthetic_pe(has_clr=True, cor_flags=0)
        res = MixedModeAnalyzer.analyze(pe_bytes, file_name="export_test.exe")

        out_dir = os.path.join(self.temp_dir, "mm_export")
        export_summary = MixedModeAnalyzer.export_to_directory(res, output_dir=out_dir)

        self.assertTrue(os.path.exists(export_summary["manifest_file"]))
        self.assertTrue(os.path.exists(export_summary["transitions_file"]))
        self.assertTrue(os.path.exists(export_summary["vtfixups_file"]))

        # Verify JSON contents
        with open(export_summary["manifest_file"], "r", encoding="utf-8") as f:
            manifest = json.load(f)
            self.assertEqual(manifest["file_name"], "export_test.exe")
            self.assertTrue(manifest["telemetry"]["is_mixed_mode"])

        # Test path traversal defense
        with self.assertRaises(SecurityError):
            _safe_path(out_dir, "../../escaped.txt")

    def test_zeroize_buffer_memory_safety(self):
        """Verifies zeroize_buffer zeroes all bytes in memory."""
        secret = bytearray(b"SENSITIVE_KEY_AND_DECRYPTED_TOKEN_BUFFER")
        self.assertNotEqual(secret, bytearray(len(secret)))
        zeroize_buffer(secret)
        self.assertEqual(secret, bytearray(len(secret)))

    def test_core_facade_and_cli_integration(self):
        """Validates DotNetPackerCore mixed-mode facade and CLI flags."""
        pe_bytes = build_synthetic_pe(has_clr=True, cor_flags=0)
        target_path = os.path.join(self.temp_dir, "cli_mixed.exe")
        with open(target_path, "wb") as f:
            f.write(pe_bytes)

        # 1. DotNetPackerCore static analysis
        report = DotNetPackerCore.analyze_file(target_path)
        self.assertIn("mixed_mode", report)
        self.assertTrue(report["mixed_mode"]["is_mixed_mode"])

        # 2. DotNetPackerCore analyze_mixed_mode
        mm_res = DotNetPackerCore.analyze_mixed_mode(target_path)
        self.assertIsInstance(mm_res, MixedModeAnalysisResult)
        self.assertTrue(mm_res.telemetry.is_mixed_mode)

        # 3. CLI execution with --mixed-mode and --trace-transitions
        exit_code = main([target_path, "--mixed-mode", "--trace-transitions"])
        self.assertEqual(exit_code, 0)

        # 4. CLI export with --mixed-mode-out
        export_out = os.path.join(self.temp_dir, "cli_mm_out")
        exit_code = main([target_path, "--mixed-mode-out", export_out])
        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(os.path.join(export_out, "mixed_mode_manifest.json")))


if __name__ == "__main__":
    unittest.main()
