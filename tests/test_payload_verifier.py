"""
Unit and integration tests for PayloadVerifier regression test harness.
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
from dotnet_deobfuscator.payload_verifier import (
    BitwiseDiff,
    PayloadVerificationResult,
    PayloadVerifier,
    PEStructureReport,
    VerificationFinding,
)


class TestPayloadVerifier(unittest.TestCase):
    """Exhaustive test suite for forensic payload verification and PE structural integrity."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.sample_bytes = b"Hello, Forensics World 2026!"
        self.sample_sha256 = hashlib.sha256(self.sample_bytes).hexdigest()
        self.sample_sha1 = hashlib.sha1(self.sample_bytes).hexdigest()
        self.sample_md5 = hashlib.md5(self.sample_bytes).hexdigest()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _build_synthetic_pe(
        self,
        with_cor20: bool = False,
        with_bsjb: bool = False,
        corrupt_dos: bool = False,
        corrupt_nt: bool = False,
        raw_overflow: bool = False,
    ) -> bytes:
        """Constructs an in-memory synthetic PE binary for rigorous edge-case testing."""
        e_lfanew = 0x80
        total_size = 4096
        buf = bytearray(total_size)

        # 1. DOS Header
        if not corrupt_dos:
            buf[0:2] = b"MZ"
        else:
            buf[0:2] = b"XX"
        struct.pack_into("<I", buf, 0x3C, e_lfanew)

        # 2. NT Signature
        if not corrupt_nt:
            buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
        else:
            buf[e_lfanew : e_lfanew + 4] = b"BAD!"

        # 3. File Header (x86, 2 sections, opt header size 224, chars 0x102)
        struct.pack_into("<HHIIIHH", buf, e_lfanew + 4, 0x014C, 2, 0, 0, 0, 224, 0x0102)

        # 4. Optional Header (PE32 magic 0x10B, SectionAlignment 0x1000, FileAlignment 0x200)
        opt_off = e_lfanew + 24
        struct.pack_into("<H", buf, opt_off, 0x010B)
        struct.pack_into("<I", buf, opt_off + 16, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<I", buf, opt_off + 28, 0x00400000)  # ImageBase
        struct.pack_into("<I", buf, opt_off + 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", buf, opt_off + 36, 0x200)  # FileAlignment
        struct.pack_into("<H", buf, opt_off + 68, 3)  # Subsystem: Windows CUI
        struct.pack_into("<I", buf, opt_off + 92, 16)  # NumberOfRvaAndSizes

        # DataDirectory[14] = CLR COM Descriptor (Directory entry 14)
        if with_cor20:
            dd_cor20 = opt_off + 96 + (14 * 8)
            struct.pack_into("<II", buf, dd_cor20, 0x1000, 72)

        # 5. Section Table
        sec_off = opt_off + 224
        # Section 1: .text (VA 0x1000, VSize 0x400, RawPtr 0x200, RawSize 0x400)
        buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
        raw_size_s1 = 0x8000 if raw_overflow else 0x400
        struct.pack_into("<IIII", buf, sec_off + 8, 0x400, 0x1000, raw_size_s1, 0x200)

        # Section 2: .rdata (VA 0x2000, VSize 0x400, RawPtr 0x600, RawSize 0x400)
        sec2_off = sec_off + 40
        buf[sec2_off : sec2_off + 8] = b".rdata\x00\x00"
        struct.pack_into("<IIII", buf, sec2_off + 8, 0x400, 0x2000, 0x400, 0x600)

        # 6. Populate .text payload data
        if with_cor20:
            # Cor20Header at VA 0x1000 -> Raw offset 0x200
            cor_raw = 0x200
            struct.pack_into("<I", buf, cor_raw, 72)  # cb = 72
            struct.pack_into("<HH", buf, cor_raw + 4, 2, 5)  # runtime 2.5
            struct.pack_into("<II", buf, cor_raw + 8, 0x1050, 128)  # MetaData RVA 0x1050, size 128
            struct.pack_into("<I", buf, cor_raw + 16, 1)  # Flags: COMIMAGE_FLAGS_ILONLY

            if with_bsjb:
                # BSJB metadata header at RVA 0x1050 -> Raw offset 0x250
                md_raw = 0x250
                struct.pack_into("<I", buf, md_raw, 0x424A5342)  # 'BSJB'
                # Embed stream identifiers
                buf[md_raw + 16 : md_raw + 64] = b"#Strings\x00#US\x00#Blob\x00#GUID\x00#~\x00"

        return bytes(buf)

    def test_compute_hashes(self):
        """Validates accuracy of cryptographic hash calculations."""
        hashes = PayloadVerifier.compute_hashes(self.sample_bytes)
        self.assertEqual(hashes["sha256"], self.sample_sha256)
        self.assertEqual(hashes["sha1"], self.sample_sha1)
        self.assertEqual(hashes["md5"], self.sample_md5)

    def test_compute_entropy(self):
        """Validates Shannon entropy calculations for boundary cases."""
        self.assertEqual(PayloadVerifier.compute_entropy(b""), 0.0)
        self.assertEqual(PayloadVerifier.compute_entropy(b"\x00" * 500), 0.0)
        diverse = bytes(range(256)) * 4
        ent = PayloadVerifier.compute_entropy(diverse)
        self.assertAlmostEqual(ent, 8.0, places=2)

    def test_bitwise_exact_match(self):
        """Verifies bitwise identity between identical byte payloads."""
        match, diff = PayloadVerifier.compare_bitwise(self.sample_bytes, self.sample_bytes)
        self.assertTrue(match)
        self.assertIsNone(diff)

    def test_bitwise_divergence_diagnostics(self):
        """Validates detection and pinpointing of byte deviations."""
        orig = bytearray(b"0123456789ABCDEF0123456789ABCDEF")
        mutated = bytearray(orig)
        mutated[12] = 0xFF  # Deviate at index 12

        match, diff = PayloadVerifier.compare_bitwise(bytes(mutated), bytes(orig))
        self.assertFalse(match)
        self.assertIsNotNone(diff)
        self.assertEqual(diff.offset, 12)
        self.assertEqual(diff.expected_byte, ord("C"))
        self.assertEqual(diff.actual_byte, 0xFF)
        self.assertTrue(diff.length_match)
        self.assertEqual(diff.total_mismatches, 1)
        self.assertIn("0x0000000C", diff.hex_context)

    def test_bitwise_length_mismatch(self):
        """Validates handling of binaries with differing lengths."""
        b1 = b"ABCDEFG"
        b2 = b"ABCDEFGH"

        match, diff = PayloadVerifier.compare_bitwise(b1, b2)
        self.assertFalse(match)
        self.assertIsNotNone(diff)
        self.assertEqual(diff.offset, 7)
        self.assertFalse(diff.length_match)
        self.assertEqual(diff.size_expected, 8)
        self.assertEqual(diff.size_actual, 7)

    def test_pe_structure_valid_binary(self):
        """Validates PE structural parsing on valid synthetic binary."""
        pe_bytes = self._build_synthetic_pe(with_cor20=True, with_bsjb=True)
        report, findings = PayloadVerifier.verify_pe_structure(pe_bytes)

        self.assertTrue(report.is_pe)
        self.assertTrue(report.is_dotnet)
        self.assertTrue(report.has_cor20_header)
        self.assertTrue(report.cor20_valid)
        self.assertTrue(report.metadata_header_found)
        self.assertIn("#Strings", report.metadata_streams)
        self.assertEqual(report.section_count, 2)
        self.assertEqual(len(report.sections), 2)
        self.assertEqual(report.sections[0].name, ".text")
        self.assertEqual(report.sections[1].name, ".rdata")

    def test_pe_structure_dos_header_anomalies(self):
        """Validates handling of corrupted or missing DOS headers."""
        pe_bad_dos = self._build_synthetic_pe(corrupt_dos=True)
        report, findings = PayloadVerifier.verify_pe_structure(pe_bad_dos, strict=False)
        self.assertIn("Missing or corrupted DOS magic ('MZ')", report.anomalies)

    def test_pe_structure_nt_signature_corruption(self):
        """Validates rejection of corrupted NT headers in strict mode."""
        pe_bad_nt = self._build_synthetic_pe(corrupt_nt=True)
        report, findings = PayloadVerifier.verify_pe_structure(pe_bad_nt, strict=True)
        self.assertFalse(report.is_pe)
        self.assertTrue(any(f.category == "NT_HEADER" and f.severity == "FAIL" for f in findings))

    def test_pe_structure_section_overflow(self):
        """Validates detection of physical section bounds exceeding file length."""
        pe_overflow = self._build_synthetic_pe(raw_overflow=True)
        report, findings = PayloadVerifier.verify_pe_structure(pe_overflow, strict=False)
        self.assertFalse(report.sections[0].is_valid_bounds)
        self.assertTrue(any(f.category == "SECTION_TABLE" and "exceed file size" in f.message for f in findings))

    def test_verify_payload_buffer_golden_hash(self):
        """Tests end-to-end buffer verification against expected SHA-256."""
        res_pass = PayloadVerifier.verify_payload_buffer(
            self.sample_bytes, expected_sha256=self.sample_sha256
        )
        self.assertTrue(res_pass.passed)
        self.assertEqual(res_pass.sha256, self.sample_sha256)

        res_fail = PayloadVerifier.verify_payload_buffer(
            self.sample_bytes, expected_sha256="0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.assertFalse(res_fail.passed)

    def test_verify_payload_file_and_reference(self):
        """Tests verifying payloads written to disk against reference baselines."""
        target_file = os.path.join(self.tmp_dir.name, "target.bin")
        ref_file = os.path.join(self.tmp_dir.name, "ref.bin")

        with open(target_file, "wb") as f:
            f.write(self.sample_bytes)
        with open(ref_file, "wb") as f:
            f.write(self.sample_bytes)

        res = PayloadVerifier.verify_payload_file(target_file, reference_path=ref_file)
        self.assertTrue(res.passed)
        self.assertTrue(res.bitwise_match)

    def test_verify_directory_audit(self):
        """Tests auditing an entire directory of payloads."""
        f1 = os.path.join(self.tmp_dir.name, "payload1.bin")
        f2 = os.path.join(self.tmp_dir.name, "payload2.bin")

        with open(f1, "wb") as f:
            f.write(b"Payload Alpha 1")
        with open(f2, "wb") as f:
            f.write(b"Payload Beta 2")

        golden = {
            "payload1.bin": hashlib.sha256(b"Payload Alpha 1").hexdigest(),
            "payload2.bin": hashlib.sha256(b"Payload Beta 2").hexdigest(),
        }

        results = PayloadVerifier.verify_directory(self.tmp_dir.name, golden_hashes=golden)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.passed for r in results))

    def test_real_sample_unpacked_output(self):
        """Tests verification on authentic samples/unpacked_output.bin and packed binary."""
        sample_path = os.path.join("samples", "unpacked_output.bin")
        if not os.path.exists(sample_path):
            self.skipTest("samples/unpacked_output.bin not available")

        expected_hash = "d69af30aa22b5cf12531470881b484ef4d1b06fd7044b266e1b1bae35d7029c2"
        res = PayloadVerifier.verify_payload_file(sample_path, expected_sha256=expected_hash)
        self.assertTrue(res.passed)
        self.assertEqual(res.sha256, expected_hash)

        # Test real packed PE binary
        packed_path = os.path.join("samples", "xorPacker_packed_sample.exe")
        if os.path.exists(packed_path):
            res_packed = PayloadVerifier.verify_payload_file(packed_path)
            self.assertTrue(res_packed.passed)
            self.assertTrue(res_packed.pe_structure.is_pe)
            self.assertGreater(res_packed.pe_structure.section_count, 0)

    def test_core_orchestrator_verify_methods(self):
        """Validates that DotNetPackerCore exposes verification interfaces seamlessly."""
        pe_bytes = self._build_synthetic_pe(with_cor20=True)
        res = DotNetPackerCore.verify_payload_buffer(pe_bytes)
        self.assertTrue(res.passed)
        self.assertTrue(res.pe_structure.is_pe)
        self.assertTrue(res.pe_structure.is_dotnet)

    def test_cli_verify_flag_execution(self):
        """Validates CLI execution with --verify and --expected-sha256."""
        target_file = os.path.join(self.tmp_dir.name, "cli_test.exe")
        pe_bytes = self._build_synthetic_pe()
        with open(target_file, "wb") as f:
            f.write(pe_bytes)

        expected_hash = hashlib.sha256(pe_bytes).hexdigest()

        # Run text format
        code = main([target_file, "--verify", "--expected-sha256", expected_hash])
        self.assertEqual(code, 0)

        # Run json format
        code_json = main([target_file, "--verify", "--format", "json"])
        self.assertEqual(code_json, 0)

        # Run with wrong hash (should exit with code 2)
        code_fail = main([target_file, "--verify", "--expected-sha256", "0" * 64])
        self.assertEqual(code_fail, 2)

    def test_cli_verify_against_bitwise(self):
        """Validates CLI --verify-against bitwise comparison."""
        target_file = os.path.join(self.tmp_dir.name, "orig.bin")
        ref_file = os.path.join(self.tmp_dir.name, "same.bin")
        diff_file = os.path.join(self.tmp_dir.name, "diff.bin")

        with open(target_file, "wb") as f:
            f.write(self.sample_bytes)
        with open(ref_file, "wb") as f:
            f.write(self.sample_bytes)
        with open(diff_file, "wb") as f:
            f.write(b"Different content!")

        # Identical binaries -> pass
        code_pass = main([target_file, "--verify-against", ref_file])
        self.assertEqual(code_pass, 0)

        # Divergent binaries -> fail
        code_fail = main([target_file, "--verify-against", diff_file])
        self.assertEqual(code_fail, 2)


if __name__ == "__main__":
    unittest.main()
