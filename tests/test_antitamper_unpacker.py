"""
Comprehensive Unit & Integration Test Suite for CLI Metadata Anti-Tamper & JIT Dumper.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import struct
import tempfile
import unittest

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.report_formatter import format_text_report
from dotnet_deobfuscator.unpackers.antitamper import AntiTamperUnpacker
from dotnet_deobfuscator.unpackers.antitamper_jit import (
    AntiTamperDecrypter,
    CorILMethodParser,
    JITDumperInterface,
)
from dotnet_deobfuscator.unpackers.antitamper_models import (
    AntiTamperDetectionResult,
    AntiTamperType,
    CorILMethodFormat,
    CorILMethodHeader,
    JITMethodRecord,
    SecurityError,
    hex_to_token,
    token_to_hex,
)


def make_synthetic_pe(section_name: bytes = b".text\x00\x00\x00") -> bytearray:
    """Constructs minimal valid 32-bit PE binary buffer for testing."""
    buf = bytearray(4096)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # NT Header
    struct.pack_into("<I", buf, 0x80, 0x00004550)  # 'PE\0\0'
    struct.pack_into("<H", buf, 0x84, 0x014C)      # i386
    struct.pack_into("<H", buf, 0x86, 1)           # 1 section
    struct.pack_into("<H", buf, 0x94, 0x00E0)      # Optional Header size: 224 bytes
    struct.pack_into("<H", buf, 0x96, 0x0102)      # Executable image

    # Optional Header (PE32)
    opt_base = 0x98
    struct.pack_into("<H", buf, opt_base, 0x010B)  # PE32 magic
    struct.pack_into("<I", buf, opt_base + 16, 0x1000)  # EntryPoint
    struct.pack_into("<I", buf, opt_base + 32, 0x2000)  # SectionAlignment
    struct.pack_into("<I", buf, opt_base + 36, 0x0200)  # FileAlignment
    struct.pack_into("<I", buf, opt_base + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", buf, opt_base + 60, 0x0200)  # SizeOfHeaders
    struct.pack_into("<H", buf, opt_base + 68, 2)       # Windows CUI
    struct.pack_into("<I", buf, opt_base + 116, 16)     # NumberOfRvaAndSizes

    # Section 1 (.text)
    sect_base = 0x178
    buf[sect_base : sect_base + 8] = section_name
    struct.pack_into("<I", buf, sect_base + 8, 0x0200)   # VirtualSize
    struct.pack_into("<I", buf, sect_base + 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", buf, sect_base + 16, 0x0200)  # SizeOfRawData
    struct.pack_into("<I", buf, sect_base + 20, 0x0200)  # PointerToRawData
    struct.pack_into("<I", buf, sect_base + 36, 0x60000020)  # Code, Executable, Readable

    # Code payload in .text section
    buf[0x0200 : 0x0200 + 4] = b"\x16\x2A\x00\x00"  # ldc.i4.0, ret
    return buf


class TestCorILMethodParser(unittest.TestCase):
    """Tests for ECMA-335 CorILMethod header parser and builder."""

    def test_tiny_method_parse_and_build(self):
        cil_code = b"\x17\x0A\x06\x2A"  # ldc.i4.1, stloc.0, ldloc.0, ret (4 bytes)
        tiny_body = CorILMethodParser.build_tiny_method(cil_code)
        self.assertEqual(len(tiny_body), 5)  # 1 byte header + 4 bytes code
        self.assertEqual(tiny_body[0], (4 << 2) | 0x02)

        hdr = CorILMethodParser.parse_method_header(tiny_body)
        self.assertIsNotNone(hdr)
        self.assertEqual(hdr.format, CorILMethodFormat.TINY)
        self.assertEqual(hdr.header_size, 1)
        self.assertEqual(hdr.code_size, 4)
        self.assertEqual(hdr.code_bytes, cil_code)
        self.assertEqual(hdr.max_stack, 8)
        self.assertEqual(hdr.total_size, 5)

    def test_fat_method_parse_and_build(self):
        cil_code = bytes(range(70))  # 70 bytes > 64 bytes -> Fat format
        fat_body = CorILMethodParser.build_fat_method(
            cil_code, max_stack=16, local_sig=0x11000002
        )
        self.assertEqual(len(fat_body), 12 + 70)

        hdr = CorILMethodParser.parse_method_header(fat_body)
        self.assertIsNotNone(hdr)
        self.assertEqual(hdr.format, CorILMethodFormat.FAT)
        self.assertEqual(hdr.header_size, 12)
        self.assertEqual(hdr.code_size, 70)
        self.assertEqual(hdr.max_stack, 16)
        self.assertEqual(hdr.local_var_sig_tok, 0x11000002)
        self.assertEqual(hdr.code_bytes, cil_code)

    def test_validate_cil_instructions(self):
        valid_cil = b"\x02\x28\x01\x00\x00\x06\x2A"  # ldarg.0, call, ret
        is_valid, ops = CorILMethodParser.validate_cil_instructions(valid_cil)
        self.assertTrue(is_valid)
        self.assertIn("0x02", ops)
        self.assertIn("0x2A", ops)

        # High entropy random noise should fail
        noise = bytes([0xFF, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A])
        is_valid_noise, _ = CorILMethodParser.validate_cil_instructions(noise)
        self.assertFalse(is_valid_noise)

    def test_token_conversion_helpers(self):
        token = 0x06000123
        hex_str = token_to_hex(token)
        self.assertEqual(hex_str, "0x06000123")
        self.assertEqual(hex_to_token(hex_str), token)
        self.assertEqual(hex_to_token("100663587"), token)


class TestAntiTamperDecrypter(unittest.TestCase):
    """Tests for anti-tamper cryptographic stream decryption algorithms."""

    def test_lcg_stream_roundtrip(self):
        original = b"This is a protected .NET method bytecode stream."
        seed = 0x12345678
        encrypted = AntiTamperDecrypter.decrypt_lcg_stream(original, seed=seed)
        self.assertNotEqual(original, encrypted)
        decrypted = AntiTamperDecrypter.decrypt_lcg_stream(encrypted, seed=seed)
        self.assertEqual(original, decrypted)

    def test_token_keyed_xor_roundtrip(self):
        original = b"\x02\x17\x58\x2A" * 8
        token = 0x06000005
        salt = 0xABCD1234
        enc = AntiTamperDecrypter.decrypt_token_keyed_xor(original, token=token, salt=salt)
        self.assertNotEqual(original, enc)
        dec = AntiTamperDecrypter.decrypt_token_keyed_xor(enc, token=token, salt=salt)
        self.assertEqual(original, dec)

    def test_rolling_xor_roundtrip(self):
        key = b"\xAA\xBB\xCC\xDD"
        plaintext = b"TestPayloadBytecodeForRollingKey"
        enc = AntiTamperDecrypter.decrypt_rolling_xor(plaintext, key)
        self.assertNotEqual(plaintext, enc)

    def test_zeroize_buffer(self):
        buf = bytearray(b"SecretKeyMaterial12345")
        AntiTamperDecrypter.zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(buf)))


class TestJITDumperInterface(unittest.TestCase):
    """Tests for In-Memory CLR JIT Dumper data ingestion and export."""

    def test_ingest_json_dump_valid(self):
        dump_data = {
            "methods": [
                {
                    "token": "0x06000001",
                    "name": "TargetMethodA",
                    "rva": 4096,
                    "cil_hex": "170A062A",  # ldc.i4.1, stloc.0, ldloc.0, ret
                },
                {
                    "token": "0x06000002",
                    "name": "TargetMethodB",
                    "rva": 4120,
                    "cil_hex": "162A",      # ldc.i4.0, ret
                },
            ]
        }
        records = JITDumperInterface.ingest_json_dump(dump_data)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].token, 0x06000001)
        self.assertEqual(records[0].rid, 1)
        self.assertEqual(records[0].name, "TargetMethodA")
        self.assertEqual(records[0].cil_bytes, bytes.fromhex("170A062A"))
        self.assertTrue(records[0].verified_cil)
        self.assertTrue(len(records[0].raw_method_body) > 0)

    def test_ingest_json_dump_with_raw_body(self):
        tiny_body = CorILMethodParser.build_tiny_method(b"\x16\x2A")
        dump_data = [
            {
                "token": 0x06000010,
                "body_hex": tiny_body.hex(),
            }
        ]
        records = JITDumperInterface.ingest_json_dump(dump_data)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].token, 0x06000010)
        self.assertEqual(records[0].code_size, 2)
        self.assertEqual(records[0].cil_bytes, b"\x16\x2A")

    def test_ingest_raw_jit_stream(self):
        method_cil = b"\x17\x2A"
        # Pack JITD stream: magic (4), count (4), record (20 + 2 = 22)
        header = b"JITD" + struct.pack("<I", 1)
        rec = struct.pack("<IIIHHI", 0x06000007, 0x2000, 2, 8, 0x02, 0) + method_cil
        records = JITDumperInterface.ingest_raw_jit_stream(header + rec)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].token, 0x06000007)
        self.assertEqual(records[0].code_size, 2)
        self.assertEqual(records[0].cil_bytes, method_cil)

    def test_export_jit_json_roundtrip(self):
        rec = JITMethodRecord(
            token=0x06000001,
            rid=1,
            name="Method_0001",
            rva=0x1000,
            format="Tiny",
            code_size=2,
            max_stack=8,
            local_var_sig_tok=0,
            cil_bytes=b"\x16\x2A",
            raw_method_body=CorILMethodParser.build_tiny_method(b"\x16\x2A"),
        )
        json_str = JITDumperInterface.export_jit_json([rec])
        parsed = json.loads(json_str)
        self.assertEqual(parsed["method_count"], 1)
        self.assertEqual(parsed["methods"][0]["token"], "0x06000001")


class TestAntiTamperUnpacker(unittest.TestCase):
    """Tests for static heuristic detection, container carving, and PE assembly restoration."""

    def test_detect_clean_binary(self):
        pe = make_synthetic_pe()
        detect_res = AntiTamperUnpacker.detect(bytes(pe))
        self.assertFalse(detect_res["is_tampered"])
        self.assertEqual(detect_res["confidence"], "NONE")

    def test_detect_tampered_pe_section(self):
        pe = make_synthetic_pe(section_name=b".tamper\x00")
        # Add high entropy bytes to .tamper section
        pe[0x0200 : 0x0400] = bytes((x * 37) % 256 for x in range(512))
        detect_res = AntiTamperUnpacker.detect(bytes(pe))
        self.assertTrue(detect_res["is_tampered"])
        self.assertIn(".tamper", detect_res["anti_tamper_sections"])

    def test_detect_jit_hook_signatures(self):
        pe = make_synthetic_pe()
        pe.extend(b"clrjit.dll\x00compileMethod\x00ICorJitCompiler\x00")
        detect_res = AntiTamperUnpacker.detect(bytes(pe))
        self.assertTrue(detect_res["is_tampered"])
        self.assertIn("clrjit.dll", detect_res["jit_signatures"])
        self.assertIn("compileMethod", detect_res["jit_signatures"])
        self.assertIn("Generic CLR JIT Hook", detect_res["detected_types"])

    def test_detect_confuserex_antitamper(self):
        pe = make_synthetic_pe()
        pe.extend(b"Confuser.Runtime.AntiTamper\x00AntiTamperNormal\x00")
        detect_res = AntiTamperUnpacker.detect(bytes(pe))
        self.assertTrue(detect_res["is_tampered"])
        self.assertIn("ConfuserEx Normal AntiTamper", detect_res["detected_types"])

    def test_extract_encrypted_containers(self):
        pe = make_synthetic_pe(section_name=b".confuse")
        pe[0x0200 : 0x0400] = bytes((x * 43) % 256 for x in range(512))
        containers = AntiTamperUnpacker.extract_encrypted_containers(bytes(pe))
        self.assertTrue(len(containers) >= 1)
        self.assertEqual(containers[0].name, ".confuse")

    def test_restore_assembly_with_methods(self):
        pe = make_synthetic_pe()
        pe.extend(b"compileMethod\x00")  # Hook to be neutralized
        rec = JITMethodRecord(
            token=0x06000001,
            rid=1,
            name="RestoredMethod1",
            rva=0,
            format="Tiny",
            code_size=2,
            max_stack=8,
            local_var_sig_tok=0,
            cil_bytes=b"\x16\x2A",
            raw_method_body=CorILMethodParser.build_tiny_method(b"\x16\x2A"),
        )
        rebuilt_pe, rep = AntiTamperUnpacker.restore_assembly(bytes(pe), [rec])
        self.assertEqual(rep["section_injected"], ".antitamper")
        self.assertEqual(rep["methods_restored_count"], 1)
        self.assertIn(b".antitam", rebuilt_pe)
        # Ensure compileMethod signature was neutralized to zeroes
        self.assertNotIn(b"compileMethod", rebuilt_pe)

    def test_unpack_to_directory(self):
        pe = make_synthetic_pe()
        with tempfile.TemporaryDirectory() as tmp_dir:
            dump_file = os.path.join(tmp_dir, "jit_dump.json")
            with open(dump_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "methods": [
                            {"token": "0x06000001", "cil_hex": "170A062A"},
                            {"token": "0x06000002", "cil_hex": "162A"},
                        ]
                    },
                    f,
                )

            out_dir = os.path.join(tmp_dir, "out_antitamper")
            res = AntiTamperUnpacker.unpack_to_directory(
                bytes(pe), output_dir=out_dir, jit_dump_file=dump_file
            )

            self.assertEqual(res["methods_count"], 2)
            self.assertTrue(os.path.exists(res["restored_binary"]))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "dumped_methods.json")))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "antitamper_manifest.json")))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "methods", "method_06000001.cil")))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "methods", "method_06000002.cil")))

    def test_security_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(SecurityError):
                AntiTamperUnpacker._safe_path(tmp_dir, "../../../escaped.exe")

    def test_security_payload_size_limit(self):
        oversized = bytes(101 * 1024 * 1024)  # > 100 MB
        with self.assertRaises(SecurityError):
            AntiTamperUnpacker.restore_assembly(oversized, [])


class TestCoreAndCLIIntegration(unittest.TestCase):
    """Integration tests verifying DotNetPackerCore and CLI flags."""

    def test_core_analyze_file_includes_antitamper(self):
        pe = make_synthetic_pe(section_name=b".atamp\x00\x00")
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(pe)
            tmp_path = f.name

        try:
            res = DotNetPackerCore.analyze_file(tmp_path)
            self.assertIn("anti_tamper", res)
            at = res["anti_tamper"]
            self.assertTrue(at["detected"])
            self.assertIn(".atamp", at["anti_tamper_sections"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_core_restore_antitamper_file(self):
        pe = make_synthetic_pe()
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_path = os.path.join(tmp_dir, "target.exe")
            with open(target_path, "wb") as f:
                f.write(pe)

            out_path = os.path.join(tmp_dir, "restored.exe")
            rebuilt_bytes, rep = DotNetPackerCore.restore_antitamper(
                target_path, output_path=out_path
            )
            self.assertTrue(os.path.exists(out_path))
            self.assertEqual(len(rebuilt_bytes), rep["restored_pe_size"])

    def test_format_text_report_antitamper_section(self):
        report = {
            "file": "test.exe",
            "size_bytes": 1024,
            "elapsed_ms": 1.2,
            "sha256": "dummy_hash",
            "is_pe": True,
            "is_dotnet": True,
            "entropy": 5.5,
            "detected_protectors": [],
            "overlay": {"has_overlay": False},
            "unpacked_payload": {"success": False},
            "anti_tamper": {
                "detected": True,
                "confidence": "HIGH",
                "detected_types": ["ConfuserEx JIT Hook AntiTamper"],
                "jit_signatures": ["compileMethod", "clrjit.dll"],
                "corrupted_streams": ["Missing #Strings and #US"],
                "anti_tamper_sections": [".tamper"],
                "encrypted_methods_count": 10,
            },
        }
        text = format_text_report(report)
        self.assertIn("--- [CLI Metadata Anti-Tamper Forensics & JIT Dumper] ---", text)
        self.assertIn("Anti-Tamper Protection Detected! (Confidence: HIGH)", text)
        self.assertIn("ConfuserEx JIT Hook AntiTamper", text)

    def test_cli_antitamper_flags(self):
        pe = make_synthetic_pe()
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_path = os.path.join(tmp_dir, "target.exe")
            with open(target_path, "wb") as f:
                f.write(pe)

            dump_file = os.path.join(tmp_dir, "dump.json")
            with open(dump_file, "w", encoding="utf-8") as f:
                json.dump({"methods": [{"token": "0x06000001", "cil_hex": "162A"}]}, f)

            out_restored = os.path.join(tmp_dir, "out_restored.exe")
            argv = [
                target_path,
                "--anti-tamper",
                "--anti-tamper-out",
                out_restored,
                "--dump-jit",
                dump_file,
            ]
            exit_code = main(argv)
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(out_restored))

    def test_cli_antitamper_dir_flag(self):
        pe = make_synthetic_pe()
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_path = os.path.join(tmp_dir, "target.exe")
            with open(target_path, "wb") as f:
                f.write(pe)

            out_dir = os.path.join(tmp_dir, "antitamper_dir")
            argv = [target_path, "--anti-tamper-dir", out_dir]
            exit_code = main(argv)
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(out_dir))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "restored_antitamper.exe")))


if __name__ == "__main__":
    unittest.main()
