"""
Comprehensive Unit & Integration Test Suite for Native AOT & ReadyToRun (R2R) PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import io
import json
import os
import struct
import sys
import tempfile
import unittest

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.native_aot import (
    AOTSymbolParser,
    AOTVersion,
    CompilationType,
    DisassembledMethod,
    MethodDefEntry,
    NativeAOTAnalysisResult,
    NativeAOTAnalyzer,
    NativeAOTTelemetry,
    NativeDisassembler,
    NativeSymbol,
    R2RHeader,
    R2RInstruction,
    R2RParser,
    R2RSection,
    R2RSectionType,
    RuntimeFunctionEntry,
    SecurityError,
    TargetArchitecture,
    safe_path,
    zeroize_buffer,
)
from dotnet_deobfuscator.report_formatter import format_text_report


class TestNativeAOTModels(unittest.TestCase):
    """Tests data models, enums, security sanitizers, and serialization."""

    def test_compilation_type_enum(self):
        self.assertEqual(CompilationType.READYTORUN_R2R.value, "readytorun_r2r")
        self.assertEqual(CompilationType.NATIVE_AOT.value, "native_aot")
        self.assertEqual(CompilationType.HYBRID_AOT_MANAGED.value, "hybrid_aot_managed")
        self.assertEqual(CompilationType.STANDARD_MANAGED.value, "standard_managed")
        self.assertEqual(CompilationType.STANDARD_NATIVE.value, "standard_native")
        self.assertEqual(CompilationType.CORRUPTED_OR_ANOMALOUS.value, "corrupted_or_anomalous")

    def test_r2r_section_type_names(self):
        self.assertEqual(R2RSectionType.get_name(100), "COMPILER_IDENTIFIER")
        self.assertEqual(R2RSectionType.get_name(102), "RUNTIME_FUNCTIONS")
        self.assertEqual(R2RSectionType.get_name(103), "METHODDEF_ENTRYPOINTS")
        self.assertEqual(R2RSectionType.get_name(999), "UNKNOWN_SECTION_999")

    def test_dataclasses_to_dict(self):
        hdr = R2RHeader(0x00525452, "RTR", 11, 0, 0, 4, 0x2000)
        self.assertEqual(hdr.to_dict()["magic_str"], "RTR")
        self.assertEqual(hdr.to_dict()["major_version"], 11)

        sec = R2RSection(100, "COMPILER_IDENTIFIER", 0x2020, 32, 0x420, "Compiler ID")
        self.assertEqual(sec.to_dict()["type_id"], 100)

        rf = RuntimeFunctionEntry(0, 0x1000, 0x1080, 128, 0x3000, 0x06000001, "Main")
        self.assertEqual(rf.to_dict()["start_rva"], 0x1000)

        me = MethodDefEntry(0x06000001, "0x06000001", 0, 0x1000, "Main")
        self.assertEqual(me.to_dict()["token_hex"], "0x06000001")

        sym = NativeSymbol(None, "RhpNewFast", "RhpNewFast", 0x4000, 64, "runtime_helper", True)
        self.assertTrue(sym.to_dict()["is_runtime_helper"])

        ins = R2RInstruction(0x1000, "CALL", "0x4000 <RhpNewFast>", "E8FB2F0000", 5, True, False, 0x4000, "RhpNewFast")
        self.assertTrue(ins.to_dict()["is_call"])

        dm = DisassembledMethod("Main", 0x06000001, 0x1000, 0x1080, 128, [ins], 1, 1, ["RhpNewFast"])
        d_dict = dm.to_dict()
        self.assertEqual(d_dict["name"], "Main")
        self.assertEqual(len(d_dict["instructions"]), 1)

    def test_safe_path_security(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            valid = safe_path(tmp_dir, "summary.json")
            self.assertTrue(valid.startswith(os.path.realpath(tmp_dir)))
            with self.assertRaises(SecurityError):
                safe_path(tmp_dir, "../../../evil.txt")
            with self.assertRaises(SecurityError):
                safe_path(tmp_dir, "subdir/../../escape.txt")

    def test_zeroize_buffer(self):
        buf = bytearray(b"SENSITIVE_AOT_METADATA_SECRET")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(buf)))
        zeroize_buffer(None)  # None check


def _build_synthetic_r2r_pe() -> bytes:
    """Helper to synthesize a valid 64-bit PE binary with ReadyToRun header and sections."""
    # We construct a 4096-byte PE image with DOS header, NT headers, Cor20Header, and R2R sections
    buf = bytearray(4096)
    # DOS Header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 0x80

    # PE Signature
    struct.pack_into("<4s", buf, 0x80, b"PE\x00\x00")
    # File Header: machine=0x8664 (x64), num_sections=2, opt_hdr_size=240, characteristics=0x0022
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 2, 0, 0, 0, 240, 0x0022)

    # Optional Header (PE32+ 64-bit: magic=0x20B)
    opt_start = 0x98
    struct.pack_into("<H", buf, opt_start, 0x20B)
    struct.pack_into("<I", buf, opt_start + 16, 0x1000)  # AddressOfEntryPoint = 0x1000
    struct.pack_into("<I", buf, opt_start + 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", buf, opt_start + 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", buf, opt_start + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", buf, opt_start + 36, 0x200)   # FileAlignment
    struct.pack_into("<I", buf, opt_start + 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", buf, opt_start + 60, 0x400)   # SizeOfHeaders
    struct.pack_into("<I", buf, opt_start + 108, 16)     # NumberOfRvaAndSizes = 16

    # DataDirectory[14] = CLR Cor20Header: RVA = 0x2000, Size = 72
    clr_dir_off = opt_start + 224
    struct.pack_into("<II", buf, clr_dir_off, 0x2000, 72)

    # Section Headers (starts at opt_start + 240 = 0x188)
    # Section 1: .text (RVA: 0x1000, VSize: 0x1000, RawOff: 0x400, RawSize: 0x600)
    sec1_off = opt_start + 240
    struct.pack_into("<8sIIIIIIHHI", buf, sec1_off, b".text\x00\x00\x00", 0x1000, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    # Section 2: .r2r (RVA: 0x2000, VSize: 0x1000, RawOff: 0xA00, RawSize: 0x600)
    sec2_off = sec1_off + 40
    struct.pack_into("<8sIIIIIIHHI", buf, sec2_off, b".r2r\x00\x00\x00\x00", 0x1000, 0x2000, 0x600, 0xA00, 0, 0, 0, 0, 0x40000040)

    # In .text (RawOff: 0x400, RVA: 0x1000): Put native method instructions
    # Method 1 (RVA: 0x1000 - 0x1020):
    # push rbp (0x55); mov rbp, rsp (0x48 0x89 0xE5); sub rsp, 0x20 (0x48 0x83 0xEC 0x20);
    # call rel32 (0xE8 ...); add rsp, 0x20 (0x48 0x83 0xC4 0x20); pop rbp (0x5D); ret (0xC3)
    method1 = bytes([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x20, 0x00, 0x00, 0x00,  # call 0x102D
        0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3, 0x90
    ])
    buf[0x400 : 0x400 + len(method1)] = method1

    # In .r2r (RawOff: 0xA00, RVA: 0x2000): Cor20Header (72 bytes)
    # Cor20Header.cb = 72, MajorRuntimeVersion=2, MinorRuntimeVersion=5, Flags=1 (ILONLY)
    struct.pack_into("<IIHH", buf, 0xA00, 72, 0, 2, 5)
    # ManagedNativeHeader is at offset 0x40 in Cor20Header (0xA40): RVA = 0x2050, Size = 128
    struct.pack_into("<II", buf, 0xA40, 0x2050, 128)

    # At RVA 0x2050 (RawOff: 0xA50): READYTORUN_HEADER
    # Magic=0x00525452 ('RTR\0'), Major=11, Minor=0, Flags=0, NumberOfSections=3
    struct.pack_into("<IHHII", buf, 0xA50, 0x00525452, 11, 0, 0, 3)

    # READYTORUN_SECTION 1: COMPILER_IDENTIFIER (100) -> RVA 0x2100, Size 32 (RawOff: 0xB00)
    struct.pack_into("<III", buf, 0xA60, 100, 0x2100, 32)
    # READYTORUN_SECTION 2: RUNTIME_FUNCTIONS (102) -> RVA 0x2140, Size 24 (RawOff: 0xB40) (2 entries, 12 bytes each)
    struct.pack_into("<III", buf, 0xA6C, 102, 0x2140, 24)
    # READYTORUN_SECTION 3: METHODDEF_ENTRYPOINTS (103) -> RVA 0x2180, Size 16 (RawOff: 0xB80)
    struct.pack_into("<III", buf, 0xA78, 103, 0x2180, 16)

    # Data for Section 1: Compiler ID at 0xB00
    compiler_id = b"Crossgen2 8.0.23531.1\x00"
    buf[0xB00 : 0xB00 + len(compiler_id)] = compiler_id

    # Data for Section 2: RUNTIME_FUNCTIONS at 0xB40 (2 functions: [0x1000, 0x1020, 0x3000], [0x1020, 0x1050, 0x3020])
    struct.pack_into("<III", buf, 0xB40, 0x1000, 0x1020, 0x3000)
    struct.pack_into("<III", buf, 0xB4C, 0x1020, 0x1050, 0x3020)

    # Data for Section 3: METHODDEF_ENTRYPOINTS at 0xB80: Pairs of (Token, FuncIndex)
    struct.pack_into("<II", buf, 0xB80, 0x06000001, 0)
    struct.pack_into("<II", buf, 0xB88, 0x06000002, 1)

    return bytes(buf)


def _build_synthetic_native_aot_pe() -> bytes:
    """Helper to synthesize a valid pure Native AOT PE binary (.NET 8/9 AOT)."""
    buf = bytearray(4096)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # PE Signature
    struct.pack_into("<4s", buf, 0x80, b"PE\x00\x00")
    # File Header: machine=0x8664 (x64), num_sections=2, opt_hdr_size=240, characteristics=0x0022
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 2, 0, 0, 0, 240, 0x0022)

    # Optional Header
    opt_start = 0x98
    struct.pack_into("<H", buf, opt_start, 0x20B)
    struct.pack_into("<I", buf, opt_start + 16, 0x1000)  # Entrypoint = 0x1000
    struct.pack_into("<I", buf, opt_start + 108, 16)

    # Pure native: Cor20Header DataDirectory[14] RVA is 0!
    clr_dir_off = opt_start + 224
    struct.pack_into("<II", buf, clr_dir_off, 0, 0)

    # Section 1: .managedcode (Native AOT section!)
    sec1_off = opt_start + 240
    struct.pack_into("<8sIIIIIIHHI", buf, sec1_off, b".managed", 0x1000, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    # Section 2: .modules (Module descriptor table)
    sec2_off = sec1_off + 40
    struct.pack_into("<8sIIIIIIHHI", buf, sec2_off, b".modules", 0x1000, 0x2000, 0x600, 0xA00, 0, 0, 0, 0, 0x40000040)

    # In .managedcode (0x400): method instructions
    method = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])
    buf[0x400 : 0x400 + len(method)] = method

    # In .modules (0xA00): Embed Redhawk helper identifiers and reflection symbols
    helpers_blob = b"RhpReversePInvoke\x00RhpNewFast\x00RhpAssignRef\x00RhGetRuntimeVersion\x00System_Console_WriteLine\x00Program_Main\x00"
    buf[0xA00 : 0xA00 + len(helpers_blob)] = helpers_blob

    # Add .NET 8 / 9 marker
    ver_marker = b"Microsoft.NETCore.App/8.0.4 NativeAOT\x00"
    buf[0xB00 : 0xB00 + len(ver_marker)] = ver_marker

    return bytes(buf)


class TestR2RParser(unittest.TestCase):
    """Tests ReadyToRun header, sections, and RUNTIME_FUNCTION parsing."""

    def test_parse_synthetic_r2r_pe(self):
        pe_bytes = _build_synthetic_r2r_pe()
        sec_rva_map = [(0x1000, 0x1000, 0x400, 0x600), (0x2000, 0x1000, 0xA00, 0x600)]
        hdr, secs, funcs, eps, comp_id = R2RParser.parse(pe_bytes, sec_rva_map, managed_native_rva=0x2050)

        self.assertIsNotNone(hdr)
        self.assertEqual(hdr.magic_str, "RTR")
        self.assertEqual(hdr.major_version, 11)
        self.assertEqual(len(secs), 3)
        self.assertEqual(comp_id, "Crossgen2 8.0.23531.1")
        self.assertEqual(len(funcs), 2)
        self.assertEqual(len(eps), 2)

        # Cross-reference verification
        self.assertEqual(funcs[0].method_token, 0x06000001)
        self.assertEqual(funcs[0].start_rva, 0x1000)
        self.assertEqual(funcs[0].end_rva, 0x1020)
        self.assertEqual(funcs[0].size_bytes, 32)
        self.assertEqual(funcs[1].method_token, 0x06000002)

    def test_find_r2r_header_fallback_scan(self):
        pe_bytes = _build_synthetic_r2r_pe()
        sec_rva_map = [(0x1000, 0x1000, 0x400, 0x600), (0x2000, 0x1000, 0xA00, 0x600)]
        # Pass 0 for managed_native_rva to trigger section scan
        loc = R2RParser.find_r2r_header(pe_bytes, sec_rva_map, managed_native_rva=0)
        self.assertIsNotNone(loc)
        off, rva = loc
        self.assertEqual(off, 0xA50)
        self.assertEqual(rva, 0x2050)

    def test_corrupted_r2r_header(self):
        corrupted = bytearray(_build_synthetic_r2r_pe())
        # Break magic
        corrupted[0xA50 : 0xA54] = b"XXXX"
        sec_rva_map = [(0x1000, 0x1000, 0x400, 0x600), (0x2000, 0x1000, 0xA00, 0x600)]
        hdr, secs, funcs, eps, comp_id = R2RParser.parse(corrupted, sec_rva_map, managed_native_rva=0x2050)
        self.assertIsNone(hdr)
        self.assertEqual(len(secs), 0)


class TestAOTSymbolParser(unittest.TestCase):
    """Tests Native AOT symbol demangling, helper scanning, and version inference."""

    def test_scan_for_helpers(self):
        data = b"SomeCode\x00RhpNewFast\x00SomeMoreCode\x00RhpReversePInvoke\x00RhpThrowEx\x00"
        detected = AOTSymbolParser.scan_for_helpers(data)
        self.assertIn("RhpNewFast", detected)
        self.assertIn("RhpReversePInvoke", detected)
        self.assertIn("RhpThrowEx", detected)
        self.assertNotIn("RhpInitialDynamicInterfaceDispatch", detected)

    def test_infer_aot_version(self):
        v9 = AOTSymbolParser.infer_aot_version(b"", [], compiler_id="Crossgen2 9.0.0-rtm")
        self.assertEqual(v9, AOTVersion.DOTNET_9)

        v8 = AOTSymbolParser.infer_aot_version(b"CoreCLR 8.0.23", [])
        self.assertEqual(v8, AOTVersion.DOTNET_8)

        v7 = AOTSymbolParser.infer_aot_version(b"Microsoft.NETCore.App/7.0.1", [])
        self.assertEqual(v7, AOTVersion.DOTNET_7)

        v_helpers = AOTSymbolParser.infer_aot_version(b"", ["RhpNewFast", "RhpReversePInvoke"], sections=[".managedcode"])
        self.assertEqual(v_helpers, AOTVersion.DOTNET_8)

    def test_demangle_symbol_name(self):
        self.assertEqual(
            AOTSymbolParser.demangle_symbol_name("System_Private_CoreLib_System_Console_WriteLine"),
            "System.Console.WriteLine",
        )
        self.assertEqual(
            AOTSymbolParser.demangle_symbol_name("Program_Main"),
            "Program.Main",
        )
        self.assertEqual(
            AOTSymbolParser.demangle_symbol_name("MyClass__ctor"),
            "MyClass..ctor",
        )
        self.assertEqual(
            AOTSymbolParser.demangle_symbol_name("Rhp_AssignRef"),
            "AssignRef",
        )


class TestNativeDisassembler(unittest.TestCase):
    """Tests native machine code instruction decoding and basic block analysis."""

    def test_disassemble_x64_method(self):
        # Instructions:
        # 0x1000: 55                      PUSH RBP
        # 0x1001: 48 89 E5                MOV RBP, RSP
        # 0x1004: 48 83 EC 20             SUB RSP, 0x20
        # 0x1008: 31 C0                   XOR EAX, EAX
        # 0x100A: 85 C0                   TEST EAX, EAX
        # 0x100C: 74 05                   JE 0x1013
        # 0x100E: E8 10 00 00 00          CALL 0x1023
        # 0x1013: 48 83 C4 20             ADD RSP, 0x20
        # 0x1017: 5D                      POP RBP
        # 0x1018: C3                      RET
        code = bytes([
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
            0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05,
            0xE8, 0x10, 0x00, 0x00, 0x00,
            0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3
        ])
        known_helpers = {0x1023: "RhpNewFast"}
        dm = NativeDisassembler.disassemble_method(code, 0x1000, name="TestMethod", known_helpers=known_helpers)

        self.assertEqual(dm.name, "TestMethod")
        self.assertEqual(dm.calls_count, 1)
        self.assertIn("RhpNewFast", dm.helpers_called)
        self.assertGreaterEqual(dm.blocks_count, 2)  # At least 2 basic blocks due to JE branch

        # Verify CALL instruction was properly annotated
        call_ins = [i for i in dm.instructions if i.is_call][0]
        self.assertEqual(call_ins.mnemonic, "CALL")
        self.assertEqual(call_ins.helper_name, "RhpNewFast")
        self.assertEqual(call_ins.target_rva, 0x1023)

    def test_indirect_call_and_jmp(self):
        # 0xFF 0x15 disp32 -> CALL [RIP + disp32]
        code = bytes([0xFF, 0x15, 0x20, 0x00, 0x00, 0x00, 0xC3])
        dm = NativeDisassembler.disassemble_method(code, 0x2000, known_helpers={0x2026: "RhpAssignRef"})
        self.assertTrue(dm.instructions[0].is_call)
        self.assertEqual(dm.instructions[0].helper_name, "RhpAssignRef")


class TestNativeAOTAnalyzerAndExport(unittest.TestCase):
    """Tests full analyzer inspection and directory export across R2R and AOT binaries."""

    def test_analyze_readytorun_pe(self):
        pe_bytes = _build_synthetic_r2r_pe()
        res = NativeAOTAnalyzer.analyze(pe_bytes, file_name="r2r_sample.dll")

        self.assertEqual(res.telemetry.compilation_type, "readytorun_r2r")
        self.assertTrue(res.telemetry.is_readytorun)
        self.assertEqual(res.telemetry.confidence, "HIGH")
        self.assertEqual(res.telemetry.compiler_identifier, "Crossgen2 8.0.23531.1")
        self.assertEqual(res.telemetry.r2r_sections_count, 3)
        self.assertEqual(res.telemetry.runtime_functions_count, 2)
        self.assertEqual(len(res.disassembled_methods), 2)

    def test_analyze_native_aot_pe(self):
        pe_bytes = _build_synthetic_native_aot_pe()
        res = NativeAOTAnalyzer.analyze(pe_bytes, file_name="native_aot_sample.exe")

        self.assertEqual(res.telemetry.compilation_type, "native_aot")
        self.assertTrue(res.telemetry.is_native_aot)
        self.assertEqual(res.telemetry.confidence, "HIGH")
        self.assertIn(".managed", res.telemetry.managed_code_sections)
        self.assertIn("RhpNewFast", res.telemetry.rhp_helpers_detected)
        self.assertEqual(res.telemetry.inferred_dotnet_version, ".NET 8 Native AOT")
        self.assertGreaterEqual(len(res.symbols), 2)

    def test_analyze_corrupted_data(self):
        res = NativeAOTAnalyzer.analyze(b"NOT_A_PE_FILE_GARBAGE", file_name="corrupted.bin")
        self.assertEqual(res.telemetry.compilation_type, "corrupted_or_anomalous")
        self.assertEqual(res.telemetry.confidence, "NONE")
        self.assertGreaterEqual(len(res.telemetry.anomalies), 1)

    def test_export_to_directory(self):
        pe_bytes = _build_synthetic_r2r_pe()
        res = NativeAOTAnalyzer.analyze(pe_bytes, file_name="r2r_export.dll")

        with tempfile.TemporaryDirectory() as tmp_dir:
            exp_res = NativeAOTAnalyzer.export_to_directory(res, output_dir=tmp_dir)
            self.assertTrue(exp_res["success"])
            self.assertIn("summary_json", exp_res["exported_files"])
            self.assertIn("sections_json", exp_res["exported_files"])
            self.assertIn("disassembly_txt", exp_res["exported_files"])
            self.assertIn("disassembly_json", exp_res["exported_files"])

            with open(exp_res["exported_files"]["summary_json"], "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertEqual(data["telemetry"]["compilation_type"], "readytorun_r2r")

            with open(exp_res["exported_files"]["disassembly_txt"], "r", encoding="utf-8") as f:
                txt = f.read()
                self.assertIn("Native AOT / ReadyToRun Disassembly", txt)


class TestCoreIntegrationAndCLI(unittest.TestCase):
    """Tests DotNetPackerCore facade methods, report formatting, and CLI arguments."""

    def test_core_analyze_bytes_integration(self):
        pe_bytes = _build_synthetic_r2r_pe()
        report = DotNetPackerCore.analyze_bytes(pe_bytes, file_name="target_r2r.exe")
        self.assertIn("native_aot", report)
        self.assertTrue(report["native_aot"]["is_readytorun"])
        self.assertEqual(report["native_aot"]["compilation_type"], "readytorun_r2r")

        # Test text report formatting
        formatted = format_text_report(report)
        self.assertIn("--- [Native AOT & ReadyToRun (R2R) PE Forensics] ---", formatted)
        self.assertIn("Crossgen2 8.0.23531.1", formatted)

    def test_core_analyze_native_aot_file(self):
        pe_bytes = _build_synthetic_r2r_pe()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(pe_bytes)
            tmp_path = f.name
        try:
            res = DotNetPackerCore.analyze_native_aot(tmp_path)
            self.assertTrue(res.telemetry.is_readytorun)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_cli_native_aot_flags(self):
        pe_bytes = _build_synthetic_r2r_pe()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(pe_bytes)
            tmp_path = f.name

        with tempfile.TemporaryDirectory() as out_dir:
            try:
                old_stdout = sys.stdout
                sys.stdout = io.StringIO()
                # Run CLI with --native-aot, --r2r-disasm, --aot-symbols, --native-aot-out
                rc = main([tmp_path, "--native-aot", "--r2r-disasm", "--aot-symbols", "--native-aot-out", out_dir])
                out = sys.stdout.getvalue()
                sys.stdout = old_stdout

                self.assertEqual(rc, 0)
                self.assertIn("Native AOT / R2R Inspection", out)
                self.assertIn("Crossgen2 8.0.23531.1", out)
                self.assertTrue(os.path.exists(os.path.join(out_dir, "summary.json")))
            finally:
                sys.stdout = old_stdout
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
