"""
Unit & Integration Tests for JIT Compilation Tracing & Bytecode Capture Subsystem.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import struct
import tempfile
import unittest

from dotnet_deobfuscator import (
    CapturedMethod,
    CaptureSource,
    CipherFamily,
    CORINFO_METHOD_INFO,
    DotNetPackerCore,
    JITAssemblyRestorer,
    JITCaptureOptions,
    JITCaptureResult,
    JITCaptureTelemetry,
    JITExecutionState,
    JITHookDetector,
    JITHookSignature,
    JITHookType,
    JITTraceParser,
    JITTracerEngine,
    OptimizationTier,
    VirtualJITCompiler,
    calculate_entropy,
    zeroize_buffer,
)
from dotnet_deobfuscator.jit_tracer.models import SecurityError, safe_path
from dotnet_deobfuscator.cli_args import build_parser


class TestJITTracerModels(unittest.TestCase):
    """Tests for JIT data structures, enums, and security primitives."""

    def test_enums_and_dataclasses(self):
        self.assertEqual(JITHookType.CORJIT_COMPILEMETHOD.value, "corjit_compilemethod")
        self.assertEqual(JITExecutionState.VALIDATED.value, "validated")
        self.assertEqual(CaptureSource.EMULATED_JIT.value, "emulated_jit")
        self.assertEqual(OptimizationTier.TIER_0_MINOPT.value, "tier_0_minopt")
        self.assertEqual(CipherFamily.LCG_PRNG.value, "lcg_prng")

        info = CORINFO_METHOD_INFO(ftn=0x1000, scope=0x2000, ILCode=0x3000, ILCodeSize=24)
        info_d = info.to_dict()
        self.assertEqual(info_d["ILCodeSize"], 24)
        self.assertEqual(info_d["ftn"], "0x1000")

        hook = JITHookSignature(
            hook_type=JITHookType.CORJIT_COMPILEMETHOD,
            target_module="clrjit.dll",
            hook_pattern="vtable_slot_0",
            detected_rva=0x1500,
            confidence=0.95,
            description="Slot 0 hook",
            protector_name="TestProtector",
        )
        hook_d = hook.to_dict()
        self.assertEqual(hook_d["hook_type"], "corjit_compilemethod")
        self.assertEqual(hook_d["confidence"], 0.95)

        method = CapturedMethod(
            token=0x06000001,
            name="Test",
            declaring_type="Prog",
            rva=0x2050,
            il_bytes=b"\x02\x2A",
            il_size=2,
            header_format="Tiny",
            max_stack=8,
            local_sig_token=0,
            eh_clause_count=0,
            cipher_detected=CipherFamily.NONE,
            capture_source=CaptureSource.EMULATED_JIT,
            state=JITExecutionState.VALIDATED,
            sha256="abc",
            disassembly_preview=["IL_0000: ldarg.0", "IL_0001: ret"],
            entropy=1.0,
        )
        method_d = method.to_dict()
        self.assertEqual(method_d["token"], "0x6000001")
        self.assertEqual(method_d["il_hex"], "022a")
        self.assertEqual(len(method_d["disassembly_preview"]), 2)

    def test_security_primitives(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = safe_path("clean.txt", tmp_dir)
            self.assertTrue(os.path.realpath(p).startswith(os.path.realpath(tmp_dir)))

            with self.assertRaises(SecurityError):
                safe_path("../outside.txt", tmp_dir)
            with self.assertRaises(SecurityError):
                safe_path("", tmp_dir)

        # Buffer zeroization
        b_mut = bytearray(b"secret_key_material_12345678")
        zeroize_buffer(b_mut)
        self.assertEqual(b_mut, bytearray(len(b_mut)))

        # Entropy
        ent_zero = calculate_entropy(b"\x00" * 100)
        self.assertEqual(ent_zero, 0.0)
        ent_high = calculate_entropy(bytes(range(256)))
        self.assertAlmostEqual(ent_high, 8.0, places=2)


class TestJITHookDetector(unittest.TestCase):
    """Tests static inspection and signature detection for CLR JIT hooks."""

    def test_empty_and_corrupted_data(self):
        self.assertEqual(JITHookDetector.detect_hooks(b""), [])
        self.assertEqual(JITHookDetector.detect_hooks(b"short_bytes"), [])

    def test_jit_module_and_export_references(self):
        sample = b"MZ" + (b"\x00" * 60) + b"This binary imports clrjit.dll and calls getJit and compileMethod."
        hooks = JITHookDetector.detect_hooks(sample)
        self.assertTrue(len(hooks) >= 2)
        modules = [h.target_module for h in hooks]
        self.assertIn("clrjit.dll", modules)

    def test_protector_jit_patterns(self):
        # ConfuserEx AntiTamper
        sample_tamper = b"MZ" + (b"\x00" * 60) + b"ConfusedByAttribute...AntiTamper... .tamper"
        hooks_tamper = JITHookDetector.detect_hooks(sample_tamper)
        tamper_matches = [h for h in hooks_tamper if h.protector_name == "ConfuserEx AntiTamper"]
        self.assertTrue(len(tamper_matches) > 0)

        # .NET Reactor NecroBit
        sample_reactor = b"MZ" + (b"\x00" * 60) + b"Protected by .NET Reactor with NecroBit .necro"
        hooks_reactor = JITHookDetector.detect_hooks(sample_reactor)
        reactor_matches = [h for h in hooks_reactor if h.protector_name == ".NET Reactor NecroBit"]
        self.assertTrue(len(reactor_matches) > 0)

        # ILProtector
        sample_ilp = b"MZ" + (b"\x00" * 60) + b"ILProtector ProtectMethods invocation"
        hooks_ilp = JITHookDetector.detect_hooks(sample_ilp)
        ilp_matches = [h for h in hooks_ilp if h.protector_name == "ILProtector"]
        self.assertTrue(len(ilp_matches) > 0)

    def test_native_detours_and_vtable_overrides(self):
        # 14-byte 64-bit indirect jump detour (FF 25 00 00 00 00 <8-byte addr>)
        target_addr = struct.pack("<Q", 0x7FFF12345678)
        detour_bytes = b"MZ" + (b"\x00" * 62) + b"\xFF\x25\x00\x00\x00\x00" + target_addr
        hooks_detour = JITHookDetector.detect_hooks(detour_bytes)
        detour_matches = [h for h in hooks_detour if h.hook_pattern == "rip_relative_indirect_detour"]
        self.assertTrue(len(detour_matches) > 0)

        # VTable slot 0 write (48 89 08)
        vtable_bytes = b"MZ" + (b"\x00" * 62) + b"\x48\x89\x08"
        hooks_vtable = JITHookDetector.detect_hooks(vtable_bytes)
        vtable_matches = [h for h in hooks_vtable if h.hook_pattern == "vtable_slot_0_overwrite"]
        self.assertTrue(len(vtable_matches) > 0)


class TestVirtualJITCompiler(unittest.TestCase):
    """Tests virtual CLR JIT compilation, opcode validation, and disassembly preview."""

    def test_compile_tiny_method(self):
        # Tiny header: code_size=4 -> header_byte = (4 << 2) | 0x02 = 0x12
        # CIL opcodes: ldarg.0 (0x02), ldc.i4.1 (0x17), add (0x58), ret (0x2A)
        tiny_body = b"\x12\x02\x17\x58\x2A"
        method = VirtualJITCompiler.compile_method(
            token=0x06000001,
            raw_body_bytes=tiny_body,
            rva=0x2000,
            name="AddOne",
            declaring_type="Calculator",
        )
        self.assertEqual(method.header_format, "Tiny")
        self.assertEqual(method.il_size, 4)
        self.assertEqual(method.state, JITExecutionState.VALIDATED)
        self.assertTrue(any("ldarg.0" in line for line in method.disassembly_preview))
        self.assertTrue(any("ret" in line for line in method.disassembly_preview))

    def test_compile_fat_method(self):
        # Fat header: flags_size=0x3003 (Fat format, 3 dwords = 12 bytes header)
        # maxStack=16, code_size=5, localSigTok=0x11000001
        header = struct.pack("<HHII", 0x3003, 16, 5, 0x11000001)
        cil_bytes = b"\x02\x16\x58\x17\x2A"  # ldarg.0, ldc.i4.0, add, ldc.i4.1, ret
        fat_body = header + cil_bytes

        method = VirtualJITCompiler.compile_method(
            token=0x06000002,
            raw_body_bytes=fat_body,
            rva=0x2100,
            name="FatMethod",
        )
        self.assertEqual(method.header_format, "Fat")
        self.assertEqual(method.max_stack, 16)
        self.assertEqual(method.local_sig_token, 0x11000001)
        self.assertEqual(method.il_size, 5)
        self.assertEqual(method.state, JITExecutionState.VALIDATED)

    def test_emulate_decryption_stub(self):
        # Encrypt a tiny method using LCG PRNG
        plain_body = b"\x12\x02\x17\x58\x2A"
        token = 0x06000010
        seed = 0x1337BEEF

        encrypted = bytearray(plain_body)
        state = (token ^ seed) & 0xFFFFFFFF
        for i in range(len(encrypted)):
            state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
            encrypted[i] ^= (state >> 16) & 0xFF

        method = VirtualJITCompiler.emulate_decryption_stub(
            token=token,
            encrypted_chunk=bytes(encrypted),
            cipher=CipherFamily.LCG_PRNG,
            seed=seed,
            name="DecryptedMethod",
        )
        self.assertEqual(method.cipher_detected, CipherFamily.LCG_PRNG)
        self.assertEqual(method.header_format, "Tiny")
        self.assertEqual(method.il_size, 4)
        self.assertEqual(method.il_bytes, b"\x02\x17\x58\x2A")

    def test_two_byte_cil_disassembly(self):
        # 0xFE 0x01 = ceq
        two_byte_cil = b"\x02\x03\xFE\x01\x2A"
        disasm = VirtualJITCompiler.disassemble_cil(two_byte_cil)
        self.assertTrue(any("ceq" in line for line in disasm))
        self.assertTrue(any("ret" in line for line in disasm))


class TestJITTraceParser(unittest.TestCase):
    """Tests parsing diverse external JIT traces: JSON, CSV, binary JITD, and text logs."""

    def test_parse_json_trace(self):
        trace_json = json.dumps([
            {
                "token": "0x06000001",
                "name": "Main",
                "declaring_type": "Program",
                "rva": "0x2050",
                "il_hex": "120217582A",
            },
            {
                "token": "0x06000002",
                "name": "Compute",
                "declaring_type": "Program",
                "rva": "0x2070",
                "il_hex": "1202162A",
            },
        ]).encode("utf-8")

        methods = JITTraceParser.parse_trace_data(trace_json)
        self.assertEqual(len(methods), 2)
        self.assertEqual(methods[0].name, "Main")
        self.assertEqual(methods[0].token, 0x06000001)
        self.assertEqual(methods[1].token, 0x06000002)

    def test_parse_csv_trace(self):
        csv_text = "token,name,declaring_type,il_hex,rva\n0x06000005,Helper,Util,12022A,0x2090\n".encode("utf-8")
        methods = JITTraceParser.parse_trace_data(csv_text)
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].token, 0x06000005)
        self.assertEqual(methods[0].name, "Helper")

    def test_parse_binary_jitd(self):
        # JITD stream: magic JITD (4b), count uint32 (4b), then records [token(4b), rva(4b), il_size(4b), bytes]
        record_bytes = b"\x12\x02\x2A"
        header = b"JITD" + struct.pack("<I", 1)
        rec = struct.pack("<III", 0x06000008, 0x3000, len(record_bytes)) + record_bytes
        data = header + rec

        methods = JITTraceParser.parse_trace_data(data)
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].token, 0x06000008)
        self.assertEqual(methods[0].rva, 0x3000)

    def test_parse_text_log(self):
        text_log = (
            "[JIT] compileMethod token: 0x0600000A, IL: 12 02 17 58 2A\n"
            "[JIT] compileMethod token: 0x0600000B, IL: 12 02 2A\n"
        ).encode("utf-8")
        methods = JITTraceParser.parse_trace_data(text_log)
        self.assertEqual(len(methods), 2)
        self.assertEqual(methods[0].token, 0x0600000A)
        self.assertEqual(methods[1].token, 0x0600000B)


class TestJITAssemblyRestorer(unittest.TestCase):
    """Tests PE container reconstruction and CIL disassembly listing."""

    def test_reconstruct_minimal_pe(self):
        method = VirtualJITCompiler.compile_method(
            token=0x06000001,
            raw_body_bytes=b"\x12\x02\x17\x58\x2A",
            name="Main",
        )
        pe_bytes = JITAssemblyRestorer.reconstruct_pe(None, [method])
        self.assertTrue(len(pe_bytes) >= 0x400)
        self.assertEqual(pe_bytes[:2], b"MZ")
        self.assertIn(b".jitcapt", pe_bytes)

    def test_generate_disassembly_listing(self):
        method = VirtualJITCompiler.compile_method(
            token=0x06000001,
            raw_body_bytes=b"\x12\x02\x17\x58\x2A",
            name="ComputeKey",
            declaring_type="LicenseValidator",
        )
        listing = JITAssemblyRestorer.generate_disassembly_listing([method])
        self.assertIn(".class public auto ansi beforefieldinit LicenseValidator", listing)
        self.assertIn(".method public hidebysig instance void ComputeKey()", listing)
        self.assertIn("ldarg.0", listing)


class TestJITTracerEngineAndCLI(unittest.TestCase):
    """Tests high-level analyzer facade, directory export, and CLI integration."""

    def test_analyze_bytes_and_export(self):
        # Sample PE binary with .tamper section simulation
        data = b"MZ" + (b"\x00" * 60) + b"ConfusedByAttribute...AntiTamper... .tamper" + (b"\x02\x17\x58\x2A" * 20)
        opts = JITCaptureOptions(emulate_unpacker=True, max_methods=5)
        res = JITTracerEngine.analyze_bytes(data, file_name="sample.exe", options=opts)

        self.assertTrue(res.is_hooked)
        self.assertEqual(res.primary_protector, "ConfuserEx AntiTamper")
        self.assertTrue(len(res.captured_methods) > 0)
        self.assertTrue(res.reconstructed_pe_bytes is not None)

        # Test safe directory export
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = os.path.join(tmp_dir, "jit_export")
            manifest = JITTracerEngine.export_to_directory(res, output_dir=out_dir)
            self.assertIn("summary_path", manifest)
            self.assertIn("methods_path", manifest)
            self.assertIn("disassembly_path", manifest)
            self.assertIn("restored_pe_path", manifest)
            self.assertTrue(os.path.exists(manifest["summary_path"]))
            self.assertTrue(os.path.exists(manifest["disassembly_path"]))

    def test_core_facade_and_collector_integration(self):
        data = b"MZ" + (b"\x00" * 60) + b"clrjit.dll getJit compileMethod .necro" + (b"\x12\x02\x2A" * 10)
        report = DotNetPackerCore.analyze_bytes(data, file_name="test_jit.exe")

        self.assertIn("jit_tracer", report)
        jt = report["jit_tracer"]
        self.assertTrue(jt["hooks_detected"] > 0)
        self.assertTrue(jt["is_hooked"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            target_pe = os.path.join(tmp_dir, "test_target.exe")
            with open(target_pe, "wb") as f:
                f.write(data)

            jit_res = DotNetPackerCore.trace_jit_compilation(target_pe)
            self.assertEqual(jit_res.file_name, "test_target.exe")
            self.assertTrue(len(jit_res.hooks) > 0)

            exp_res = DotNetPackerCore.export_jit_trace(target_pe, output_dir=os.path.join(tmp_dir, "jit_out"))
            self.assertTrue(len(exp_res["exported_files"]) >= 4)

    def test_cli_argument_parsing(self):
        parser = build_parser()
        args = parser.parse_args(["sample.exe", "--jit-trace", "--jit-max-methods", "50", "--jit-restore-pe"])
        self.assertTrue(args.jit_trace)
        self.assertEqual(args.jit_max_methods, 50)
        self.assertTrue(args.jit_restore_pe)


if __name__ == "__main__":
    unittest.main()
