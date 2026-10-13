"""
Comprehensive Unit & Integration Test Suite for .NET Reactor & NecroBit Unpacker.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import io
import os
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.reactor import (
    DotNetReactorUnpacker,
    SecurityError,
)


class TestDotNetReactorUnpacker(unittest.TestCase):
    """Verifies .NET Reactor detection, envelope stripping, and NecroBit CIL restoration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_reactor_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _build_synthetic_pe(
        self,
        section_name: bytes = b".text\x00\x00\x00",
        is_dotnet: bool = True,
        extra_sections: list = None,
    ) -> bytes:
        """Constructs minimal valid PE binary for testing."""
        buf = bytearray(4096)
        # DOS Header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 0x80)

        # NT Header
        struct.pack_into("<I", buf, 0x80, 0x00004550)  # 'PE\0\0'
        num_sections = 1 + (len(extra_sections) if extra_sections else 0)
        struct.pack_into("<H", buf, 0x84, 0x014C)      # i386
        struct.pack_into("<H", buf, 0x86, num_sections)
        struct.pack_into("<H", buf, 0x94, 0x00E0)      # Optional Header size: 224 bytes
        struct.pack_into("<H", buf, 0x96, 0x0102)      # Executable image

        # Optional Header (PE32)
        opt_base = 0x98
        struct.pack_into("<H", buf, opt_base, 0x010B)  # PE32 magic
        struct.pack_into("<I", buf, opt_base + 16, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<I", buf, opt_base + 32, 0x2000)  # SectionAlignment
        struct.pack_into("<I", buf, opt_base + 36, 0x0200)  # FileAlignment
        struct.pack_into("<I", buf, opt_base + 56, 0x4000)  # SizeOfImage
        struct.pack_into("<I", buf, opt_base + 60, 0x0200)  # SizeOfHeaders
        struct.pack_into("<H", buf, opt_base + 68, 2)       # Windows CUI
        struct.pack_into("<I", buf, opt_base + 116, 16)     # NumberOfRvaAndSizes

        if is_dotnet:
            # DataDirectory[14] = CLR Cor20Header (cb=72)
            cor20_dd = opt_base + 96 + 14 * 8
            struct.pack_into("<II", buf, cor20_dd, 0x2000, 72)
            # Inject Cor20Header at 0x200
            struct.pack_into("<II", buf, 0x200, 72, 0x00020005)
            # MetaData RVA
            struct.pack_into("<II", buf, 0x208, 0x2048, 256)
            # BSJB metadata marker
            buf[0x248:0x24C] = b"BSJB"

        # Section 1 Header
        sec_base = opt_base + 224
        buf[sec_base : sec_base + 8] = section_name[:8]
        struct.pack_into("<I", buf, sec_base + 8, 0x1000)   # VirtualSize
        struct.pack_into("<I", buf, sec_base + 12, 0x1000)  # VirtualAddress
        struct.pack_into("<I", buf, sec_base + 16, 0x0200)  # SizeOfRawData
        struct.pack_into("<I", buf, sec_base + 20, 0x0200)  # PointerToRawData
        struct.pack_into("<I", buf, sec_base + 36, 0x60000020)  # Code, Executable, Read

        max_offset = 0x400
        if extra_sections:
            for idx, (s_name, s_vaddr, s_rptr, s_rsize) in enumerate(extra_sections):
                s_off = sec_base + (idx + 1) * 40
                buf[s_off : s_off + 8] = s_name[:8]
                struct.pack_into("<I", buf, s_off + 8, s_rsize)
                struct.pack_into("<I", buf, s_off + 12, s_vaddr)
                struct.pack_into("<I", buf, s_off + 16, s_rsize)
                struct.pack_into("<I", buf, s_off + 20, s_rptr)
                struct.pack_into("<I", buf, s_off + 36, 0xC0000040)
                if s_rptr + s_rsize > max_offset:
                    max_offset = s_rptr + s_rsize

        return bytes(buf[:max_offset])

    # -------------------------------------------------------------------------
    # 1. Detection Tests
    # -------------------------------------------------------------------------

    def test_detect_clean_binary_negative(self):
        """Verifies clean binary produces negative detection."""
        pe = self._build_synthetic_pe()
        res = DotNetReactorUnpacker.detect(pe)
        self.assertFalse(res["is_reactor"])
        self.assertEqual(res["confidence"], "NONE")
        self.assertFalse(res["has_necrobit"])
        self.assertFalse(res["is_native_envelope"])

    def test_detect_reactor_markers(self):
        """Verifies detection of .NET Reactor markers and section names."""
        pe = bytearray(self._build_synthetic_pe(section_name=b".reactor\x00"))
        pe.extend(b"Protected with .NET Reactor by Eziriz (NecroBit)")
        res = DotNetReactorUnpacker.detect(bytes(pe))
        self.assertTrue(res["is_reactor"])
        self.assertEqual(res["confidence"], "HIGH")
        self.assertIn(".NET Reactor", res["markers_found"])
        self.assertIn("Eziriz", res["markers_found"])
        self.assertIn("NecroBit", res["markers_found"])
        self.assertTrue(res["has_necrobit"])

    # -------------------------------------------------------------------------
    # 2. CIL Method Header & Opcode Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_cil_tiny_method_header(self):
        """Verifies CorILMethod_TinyFormat parsing and validation."""
        # Tiny header: code_size = 2 -> (2 << 2) | 0x02 = 0x0A
        # Bytecode: 0x00 (nop), 0x2A (ret)
        tiny_body = bytes([0x0A, 0x00, 0x2A])
        hdr = DotNetReactorUnpacker.parse_cil_method_header(tiny_body)
        self.assertTrue(hdr["valid"])
        self.assertEqual(hdr["format"], "CorILMethod_TinyFormat")
        self.assertEqual(hdr["code_size"], 2)
        self.assertEqual(hdr["cil_bytecode"], b"\x00\x2A")
        self.assertTrue(DotNetReactorUnpacker.validate_cil_bytecode(hdr["cil_bytecode"]))

    def test_parse_cil_fat_method_header(self):
        """Verifies CorILMethod_FatFormat parsing and validation."""
        # Fat header (12 bytes):
        # Flags_Size: 0x3003 (Size=3 dwords = 12 bytes, Format=Fat)
        # MaxStack: 8, CodeSize: 5, LocalVarSigTok: 0x11000001
        header = struct.pack("<HHI I", 0x3003, 8, 5, 0x11000001)
        # CIL: 0x02 (ldarg.0), 0x73 0x01 0x00 0x06 (newobj), 0x2A (ret) -> code_size = 6
        header = struct.pack("<HHI I", 0x3003, 8, 6, 0x11000001)
        bytecode = b"\x02\x73\x01\x00\x00\x2A"
        fat_body = header + bytecode

        hdr = DotNetReactorUnpacker.parse_cil_method_header(fat_body)
        self.assertTrue(hdr["valid"])
        self.assertEqual(hdr["format"], "CorILMethod_FatFormat")
        self.assertEqual(hdr["header_size"], 12)
        self.assertEqual(hdr["code_size"], 6)
        self.assertEqual(hdr["max_stack"], 8)
        self.assertEqual(hdr["local_vars_token"], 0x11000001)
        self.assertEqual(hdr["cil_bytecode"], bytecode)
        self.assertTrue(DotNetReactorUnpacker.validate_cil_bytecode(hdr["cil_bytecode"]))

    def test_parse_cil_invalid_header(self):
        """Verifies invalid or truncated CIL headers are rejected safely."""
        self.assertFalse(DotNetReactorUnpacker.parse_cil_method_header(b"")["valid"])
        # Tiny with truncated bytecode
        self.assertFalse(DotNetReactorUnpacker.parse_cil_method_header(bytes([0x3A, 0x00]))["valid"])
        # Invalid header flags
        self.assertFalse(DotNetReactorUnpacker.parse_cil_method_header(bytes([0x01, 0x00]))["valid"])

    # -------------------------------------------------------------------------
    # 3. NecroBit Encryption & Decryption Tests
    # -------------------------------------------------------------------------

    def _create_synthetic_necrobit_container(
        self, methods: dict, seed: int = 0x14725836
    ) -> bytes:
        """Generates synthetic NecroBit method container for testing."""
        buf = bytearray(b"NECRO\x00")
        buf.extend(struct.pack("<I", len(methods)))
        for token, plain_body in methods.items():
            # Encrypt method body matching DotNetReactorUnpacker key schedule
            t_b0 = token & 0xFF
            t_b1 = (token >> 8) & 0xFF
            t_b2 = (token >> 16) & 0xFF
            t_b3 = (token >> 24) & 0xFF
            key_schedule = [t_b0 ^ 0x5A, t_b1 ^ 0xA5, t_b2 ^ 0x3C, t_b3 ^ 0xC3]

            enc = bytearray(len(plain_body))
            for i, b in enumerate(plain_body):
                enc[i] = b ^ key_schedule[i % 4] ^ ((seed >> (i % 24)) & 0xFF)

            buf.extend(struct.pack("<II", token, len(enc)))
            buf.extend(enc)
        return bytes(buf)

    def test_necrobit_method_extraction_and_decryption(self):
        """Verifies extraction and decryption of NecroBit method repository."""
        token1 = 0x06000001
        token2 = 0x06000002
        body1 = bytes([0x0A, 0x02, 0x2A])  # Tiny: ldarg.0; ret
        body2 = bytes([0x0A, 0x00, 0x2A])  # Tiny: nop; ret

        seed = 0x14725836
        container = self._create_synthetic_necrobit_container(
            {token1: body1, token2: body2}, seed=seed
        )

        pe = bytearray(self._build_synthetic_pe())
        pe.extend(container)

        extracted = DotNetReactorUnpacker.extract_necrobit_methods(bytes(pe), seed=seed)
        self.assertEqual(len(extracted), 2)
        self.assertIn(token1, extracted)
        self.assertIn(token2, extracted)

        m1 = extracted[token1]
        self.assertEqual(m1["method_body_bytes"], body1)
        self.assertTrue(m1["is_valid_cil"])
        self.assertEqual(m1["code_size"], 2)

        m2 = extracted[token2]
        self.assertEqual(m2["method_body_bytes"], body2)
        self.assertTrue(m2["is_valid_cil"])

    # -------------------------------------------------------------------------
    # 4. Native Stub Envelope Stripping Tests
    # -------------------------------------------------------------------------

    def test_strip_native_envelope_direct_embedded(self):
        """Verifies carving and de-enveloping of embedded managed .NET PE."""
        inner_managed_pe = self._build_synthetic_pe(section_name=b".text\x00\x00\x00", is_dotnet=True)
        # Outer native PE without .NET Cor20Header
        outer_native_pe = bytearray(
            self._build_synthetic_pe(section_name=b".reactor\x00", is_dotnet=False)
        )
        # Embed managed PE
        embed_offset = len(outer_native_pe)
        outer_native_pe.extend(inner_managed_pe)

        carved, report = DotNetReactorUnpacker.strip_native_envelope(bytes(outer_native_pe))
        self.assertIsNotNone(carved)
        self.assertTrue(report["is_enveloped"])
        self.assertTrue(report["is_valid_managed_pe"])
        self.assertEqual(carved, inner_managed_pe)

    def test_strip_native_envelope_xor_encoded(self):
        """Verifies de-enveloping of single-byte XOR protected embedded PE."""
        inner_managed_pe = self._build_synthetic_pe(is_dotnet=True)
        xor_key = 0x7A
        xor_payload = bytes([b ^ xor_key for b in inner_managed_pe])

        outer = bytearray(self._build_synthetic_pe(section_name=b".reactor\x00", is_dotnet=False))
        # Point .reactor raw pointer to our encrypted payload
        sec_off = 0x80 + 24 + 224 + 40
        # Replace section raw offset to end of headers
        outer.extend(b"\x00" * (0x600 - len(outer)))
        # Update PointerToRawData of .reactor
        struct.pack_into("<I", outer, 0x80 + 24 + 224 + 20, 0x600)
        outer.extend(xor_payload)

        carved, report = DotNetReactorUnpacker.strip_native_envelope(bytes(outer))
        self.assertIsNotNone(carved)
        self.assertTrue(report["is_enveloped"])
        self.assertEqual(carved[:64], inner_managed_pe[:64])

    # -------------------------------------------------------------------------
    # 5. Full Assembly Restoration Tests
    # -------------------------------------------------------------------------

    def test_restore_necrobit_assembly_reconstruction(self):
        """Verifies that restoring NecroBit methods appends .necro section and updates headers."""
        token = 0x06000005
        body = bytes([0x0A, 0x02, 0x2A])  # ldarg.0; ret
        container = self._create_synthetic_necrobit_container({token: body})

        base_pe = bytearray(self._build_synthetic_pe())
        base_pe.extend(container)

        rebuilt, rep = DotNetReactorUnpacker.restore_necrobit_assembly(bytes(base_pe))
        self.assertTrue(rep["success"])
        self.assertEqual(rep["methods_restored_count"], 1)
        self.assertIn("0x06000005", rep["restored_tokens"])
        self.assertGreater(len(rebuilt), len(base_pe))

        # Check that .necro section was added
        self.assertIn(b".necro", rebuilt)
        # Check that NumberOfSections was incremented
        e_lfanew = struct.unpack_from("<I", rebuilt, 0x3C)[0]
        num_sec = struct.unpack_from("<H", rebuilt, e_lfanew + 6)[0]
        self.assertEqual(num_sec, 2)

    # -------------------------------------------------------------------------
    # 6. Directory Unpacking & Security Tests
    # -------------------------------------------------------------------------

    def test_unpack_to_directory_success(self):
        """Verifies safe file extraction to target output directory."""
        inner_pe = self._build_synthetic_pe(is_dotnet=True)
        outer = bytearray(self._build_synthetic_pe(section_name=b".reactor\x00", is_dotnet=False))
        outer.extend(inner_pe)

        written = DotNetReactorUnpacker.unpack_to_directory(bytes(outer), self.temp_dir)
        self.assertGreaterEqual(len(written), 1)
        out_file = written[0]["output_path"]
        self.assertTrue(os.path.isfile(out_file))
        self.assertEqual(written[0]["sha256"], hashlib.sha256(inner_pe).hexdigest())

    def test_unpack_to_directory_path_traversal_defense(self):
        """Verifies that malicious path traversal filenames are blocked."""
        malicious_payload = [
            {
                "original_name": "../../bad.exe",
                "output_filename": "../../bad.exe",
                "size_bytes": 10,
                "sha256": "abc",
                "artifact_type": "Attack",
                "payload_bytes": b"malicious",
            }
        ]
        with patch.object(DotNetReactorUnpacker, "unpack", return_value=malicious_payload):
            with self.assertRaises(SecurityError):
                DotNetReactorUnpacker.unpack_to_directory(b"dummy", self.temp_dir)

    # -------------------------------------------------------------------------
    # 7. Core Orchestrator & CLI Integration Tests
    # -------------------------------------------------------------------------

    def test_core_analyze_file_with_reactor(self):
        """Verifies DotNetPackerCore.analyze_file integrates reactor telemetry."""
        pe = bytearray(self._build_synthetic_pe(section_name=b".reactor\x00"))
        pe.extend(b".NET Reactor by Eziriz NecroBit")
        test_file = os.path.join(self.temp_dir, "test_reactor.exe")
        with open(test_file, "wb") as f:
            f.write(pe)

        report = DotNetPackerCore.analyze_file(test_file)
        self.assertIn("reactor", report)
        self.assertTrue(report["reactor"]["detected"])
        self.assertEqual(report["reactor"]["confidence"], "HIGH")

    def test_core_strip_envelope_api(self):
        """Verifies DotNetPackerCore.strip_reactor_envelope API."""
        inner = self._build_synthetic_pe(is_dotnet=True)
        outer = bytearray(self._build_synthetic_pe(section_name=b".reactor\x00", is_dotnet=False))
        outer.extend(inner)

        in_path = os.path.join(self.temp_dir, "enveloped.exe")
        out_path = os.path.join(self.temp_dir, "stripped.dll")
        with open(in_path, "wb") as f:
            f.write(outer)

        success = DotNetPackerCore.strip_reactor_envelope(in_path, out_path)
        self.assertTrue(success)
        self.assertTrue(os.path.isfile(out_path))
        self.assertEqual(os.path.getsize(out_path), len(inner))

    def test_cli_flags_reactor_execution(self):
        """Verifies CLI execution with --strip-envelope and --restore-necrobit flags."""
        token = 0x06000008
        body = bytes([0x0A, 0x02, 0x2A])
        container = self._create_synthetic_necrobit_container({token: body})

        base_pe = bytearray(self._build_synthetic_pe(section_name=b".reactor\x00"))
        base_pe.extend(b".NET Reactor")
        base_pe.extend(container)

        in_file = os.path.join(self.temp_dir, "cli_reactor.exe")
        with open(in_file, "wb") as f:
            f.write(base_pe)

        out_necro = os.path.join(self.temp_dir, "cli_necro_out.exe")
        ret = main([in_file, "--restore-necrobit", "--necrobit-out", out_necro])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.isfile(out_necro))


if __name__ == "__main__":
    unittest.main()
