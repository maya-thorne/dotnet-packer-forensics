"""
Comprehensive Unit & Integration Test Suite for IntelliLock Forensic Unpacker.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import io
import json
import os
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.payload_verifier import PayloadVerifier
from dotnet_deobfuscator.unpackers.intellilock import IntelliLockUnpacker
from dotnet_deobfuscator.unpackers.intellilock_models import (
    HardwareProfile,
    IntelliLockMetadata,
    LicenseStatus,
    LockType,
    SecurityError,
    VirtualLicense,
)


def make_synthetic_pe(
    section_name: bytes = b".text\x00\x00\x00",
    extra_sections: list = None,
) -> bytearray:
    """Constructs minimal valid 32-bit PE binary buffer for testing."""
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

    # Section 1 (.text)
    sec_base = opt_base + 0x00E0
    buf[sec_base : sec_base + 8] = section_name[:8].ljust(8, b"\x00")
    struct.pack_into("<I", buf, sec_base + 8, 0x0200)   # VirtualSize
    struct.pack_into("<I", buf, sec_base + 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", buf, sec_base + 16, 0x0200)  # SizeOfRawData
    struct.pack_into("<I", buf, sec_base + 20, 0x0200)  # PointerToRawData
    struct.pack_into("<I", buf, sec_base + 36, 0x60000020)  # Code, Execute, Read

    if extra_sections:
        for idx, (s_name, s_vsize, s_vaddr, s_rsize, s_rptr) in enumerate(extra_sections):
            offset = sec_base + ((idx + 1) * 40)
            buf[offset : offset + 8] = s_name[:8].ljust(8, b"\x00")
            struct.pack_into("<I", buf, offset + 8, s_vsize)
            struct.pack_into("<I", buf, offset + 12, s_vaddr)
            struct.pack_into("<I", buf, offset + 16, s_rsize)
            struct.pack_into("<I", buf, offset + 20, s_rptr)
            struct.pack_into("<I", buf, offset + 36, 0x40000040)

    return buf


class TestIntelliLockUnpacker(unittest.TestCase):
    """Comprehensive test suite for IntelliLock detection, de-enveloping, and hardware bypassing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_ilock_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_clean_binary(self):
        """Verifies clean binary exhibits no IntelliLock indicators."""
        clean_buf = bytes(make_synthetic_pe())
        res = IntelliLockUnpacker.detect(clean_buf)
        self.assertFalse(res["is_intellilock"])
        self.assertEqual(res["confidence"], "NONE")
        self.assertEqual(len(res["markers_found"]), 0)

    def test_detect_intellilock_markers(self):
        """Verifies detection of multiple IntelliLock marker strings."""
        buf = bytearray(make_synthetic_pe())
        buf.extend(b"IntelliLock.Licensing TrialAttribute EvaluationMode LockType")
        res = IntelliLockUnpacker.detect(bytes(buf))
        self.assertTrue(res["is_intellilock"])
        self.assertEqual(res["confidence"], "HIGH")
        self.assertIn("IntelliLock", res["markers_found"])
        self.assertIn("TrialAttribute", res["markers_found"])

    def test_detect_intellilock_section(self):
        """Verifies detection of .itllock PE section."""
        extra = [(b".itllock", 0x400, 0x2000, 0x400, 0x400)]
        buf = bytes(make_synthetic_pe(extra_sections=extra))
        res = IntelliLockUnpacker.detect(buf)
        self.assertTrue(res["is_intellilock"])
        self.assertIn(".itllock", res["sections_matched"])
        self.assertTrue(res["is_enveloped"])

    def test_hardware_profile_computation(self):
        """Verifies deterministic hardware fingerprint calculation."""
        hw = HardwareProfile(
            cpu_id="CPU_TEST_1234",
            hdd_serial="HDD_TEST_5678",
            mac_address="00:11:22:33:44:55",
            motherboard_uuid="UUID-TEST-9999",
            machine_guid="GUID-TEST-8888",
        )
        hw_id = hw.compute_hardware_id()
        self.assertEqual(len(hw_id), 19)  # XXXX-XXXX-XXXX-XXXX
        self.assertEqual(hw_id.count("-"), 3)
        # Verify determinism
        self.assertEqual(hw_id, hw.compute_hardware_id())

    def test_hardware_profile_from_string(self):
        """Verifies profile synthesis from hardware ID string."""
        profile = HardwareProfile.from_string("1234-ABCD-5678-EF01")
        self.assertIn("1234ABCD", profile.cpu_id)
        self.assertIn("5678EF01", profile.hdd_serial)

    def test_virtual_license_unlimited_creation(self):
        """Verifies synthetic master perpetual license generation."""
        lic = VirtualLicense.generate_unlimited_license()
        self.assertEqual(lic.status, LicenseStatus.FULL_LICENSED)
        self.assertEqual(lic.runs_allowed, 999999)
        self.assertEqual(lic.expiration_date, "2099-12-31")
        self.assertEqual(lic.features_mask, 0xFFFFFFFF)
        self.assertEqual(lic.hardware_id, "*")

    def test_virtual_license_binary_serialization_roundtrip(self):
        """Verifies binary .lic container serialization and deserialization."""
        lic = VirtualLicense.generate_unlimited_license(hardware_id="A1B2-C3D4-E5F6-0000")
        lic_bytes = lic.to_bytes()
        self.assertTrue(lic_bytes.startswith(VirtualLicense.MAGIC_HEADER))

        recovered = VirtualLicense.from_bytes(lic_bytes)
        self.assertEqual(recovered.licensee, lic.licensee)
        self.assertEqual(recovered.company, lic.company)
        self.assertEqual(recovered.hardware_id, "A1B2-C3D4-E5F6-0000")
        self.assertEqual(recovered.status, LicenseStatus.FULL_LICENSED)

    def test_virtual_license_tampering_detection(self):
        """Verifies tampered license payload triggers LicenseStatus.TAMPERED."""
        lic = VirtualLicense.generate_unlimited_license()
        lic_bytes = bytearray(lic.to_bytes())
        # Corrupt one payload byte at end
        lic_bytes[-5] ^= 0xFF
        recovered = VirtualLicense.from_bytes(bytes(lic_bytes))
        self.assertEqual(recovered.status, LicenseStatus.TAMPERED)

    def test_lock_type_flags(self):
        """Verifies LockType bitmask operations."""
        combined = LockType.HARDWARE_ID | LockType.EXPIRATION_DATE | LockType.MAX_RUNS
        self.assertTrue(bool(combined & LockType.HARDWARE_ID))
        self.assertTrue(bool(combined & LockType.EXPIRATION_DATE))
        self.assertTrue(bool(combined & LockType.MAX_RUNS))
        self.assertFalse(bool(combined & LockType.RUNTIME_LIMIT))

    def test_stream_decryption_lcg_xor(self):
        """Verifies LCG PRNG XOR stream decryptor."""
        plaintext = b"MZ" + b"\x00" * 62 + b"PE\x00\x00TEST_PAYLOAD"
        seed = 0x14725836

        # Encrypt with same PRNG logic
        state = seed & 0xFFFFFFFF
        ciphertext = bytearray(len(plaintext))
        for i, b in enumerate(plaintext):
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            ciphertext[i] = b ^ ((state >> 16) & 0xFF)

        decrypted = IntelliLockUnpacker.decrypt_payload(bytes(ciphertext), seed=seed)
        self.assertEqual(decrypted, plaintext)

    def test_stream_decryption_with_key(self):
        """Verifies multi-byte XOR cipher decryption."""
        key = b"EZIRIZ_MASTER_SECRET"
        plaintext = b"MZ\x90\x00" + b"TEST_SECRET_CONTENT" * 5
        ciphertext = bytes([b ^ key[i % len(key)] for i, b in enumerate(plaintext)])
        decrypted = IntelliLockUnpacker.decrypt_payload(ciphertext, key=key)
        self.assertEqual(decrypted, plaintext)

    def test_carve_envelope_payload_container_magic(self):
        """Verifies carving from ILOCK container header."""
        inner_pe = bytes(make_synthetic_pe())
        seed = 0x14725836
        flags = int(LockType.HARDWARE_ID | LockType.EXPIRATION_DATE)
        orig_ep = 0x2000

        # Encrypt inner PE
        state = seed & 0xFFFFFFFF
        enc_payload = bytearray(len(inner_pe))
        for i, b in enumerate(inner_pe):
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            enc_payload[i] = b ^ ((state >> 16) & 0xFF)

        payload_hash = hashlib.sha256(inner_pe).digest()

        # Build container
        container = bytearray()
        container.extend(b"ILOCK\x01")                    # Magic + version
        container.extend(struct.pack("<B", 1))            # Subversion
        container.extend(struct.pack("<IIII", flags, orig_ep, seed, len(enc_payload)))
        container.extend(payload_hash)
        container.extend(enc_payload)

        outer_buf = bytearray(make_synthetic_pe())
        outer_buf.extend(container)

        carve_res = IntelliLockUnpacker.carve_envelope_payload(bytes(outer_buf))
        self.assertIsNotNone(carve_res)
        raw_bytes, meta = carve_res
        self.assertEqual(raw_bytes, bytes(enc_payload))
        self.assertEqual(meta.original_entry_point, orig_ep)
        self.assertTrue(meta.has_hardware_lock)
        self.assertTrue(meta.has_trial_expiration)

    def test_carve_envelope_fallback_embedded_pe(self):
        """Verifies fallback carving of embedded MZ payload."""
        outer = bytearray(make_synthetic_pe())
        inner = make_synthetic_pe()
        outer.extend(b"\x00" * 100)
        outer.extend(inner)

        carve_res = IntelliLockUnpacker.carve_envelope_payload(bytes(outer))
        self.assertIsNotNone(carve_res)
        raw_bytes, meta = carve_res
        self.assertTrue(raw_bytes.startswith(b"MZ"))
        self.assertEqual(meta.project_id, "CARVED-EMBEDDED")

    def test_neutralize_license_envelope_container(self):
        """Verifies de-enveloping and restoring clean managed assembly."""
        inner_pe = bytes(make_synthetic_pe())
        seed = 0x14725836
        flags = int(LockType.HARDWARE_ID)
        orig_ep = 0x2000

        # Encrypt inner PE
        state = seed & 0xFFFFFFFF
        enc_payload = bytearray(len(inner_pe))
        for i, b in enumerate(inner_pe):
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            enc_payload[i] = b ^ ((state >> 16) & 0xFF)

        payload_hash = hashlib.sha256(inner_pe).digest()

        container = bytearray()
        container.extend(b"ILOCK\x01")
        container.extend(struct.pack("<B", 1))
        container.extend(struct.pack("<IIII", flags, orig_ep, seed, len(enc_payload)))
        container.extend(payload_hash)
        container.extend(enc_payload)

        outer_buf = bytearray(make_synthetic_pe())
        outer_buf.extend(container)

        clean_bin, meta, lic = IntelliLockUnpacker.neutralize_license_envelope(
            bytes(outer_buf), master_seed=seed
        )
        self.assertTrue(clean_bin.startswith(b"MZ"))
        self.assertEqual(lic.status, LicenseStatus.FULL_LICENSED)
        self.assertEqual(meta.license_status, LicenseStatus.FULL_LICENSED)

    def test_neutralize_license_envelope_inplace(self):
        """Verifies in-place neutralization of licensing markers."""
        buf = bytearray(make_synthetic_pe())
        buf.extend(b"IntelliLock.Licensing TrialAttribute")
        clean_bin, meta, lic = IntelliLockUnpacker.neutralize_license_envelope(bytes(buf))
        self.assertNotIn(b"IntelliLock.Licensing", clean_bin)
        self.assertNotIn(b"TrialAttribute", clean_bin)
        self.assertEqual(meta.license_status, LicenseStatus.FULL_LICENSED)

    def test_unpack_to_directory_success(self):
        """Verifies directory unpacking produces all required forensic artifacts."""
        buf = bytearray(make_synthetic_pe())
        buf.extend(b"IntelliLock.Licensing")
        out_dir = os.path.join(self.temp_dir, "unpacked_ilock")

        result = IntelliLockUnpacker.unpack_to_directory(bytes(buf), out_dir)
        self.assertTrue(result["success"])
        self.assertTrue(os.path.exists(os.path.join(out_dir, "unlocked_main.exe")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "virtual_license.lic")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "hardware_profile.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "intellilock_manifest.json")))
        self.assertIn("sha256", result)

    def test_unpack_to_directory_path_traversal_defense(self):
        """Verifies path traversal attempt raises SecurityError."""
        buf = bytes(make_synthetic_pe())
        traversal_dir = os.path.join(self.temp_dir, "sub", "..", "..", "escape")
        with patch("os.path.join", return_value=os.path.join(self.temp_dir, "..", "escaped.exe")):
            with self.assertRaises(SecurityError):
                IntelliLockUnpacker.unpack_to_directory(buf, self.temp_dir)

    def test_decompression_bomb_safety_ceiling(self):
        """Verifies decompression bomb safety check."""
        with patch.object(IntelliLockUnpacker, "MAX_DECOMPRESSED_SIZE", 10):
            # Create a 20-byte string compressed with zlib
            compressed = zlib.compress(b"A" * 50)
            with self.assertRaises(SecurityError):
                IntelliLockUnpacker.decrypt_payload(compressed)

    def test_core_analyze_file_intellilock_telemetry(self):
        """Verifies DotNetPackerCore.analyze_file returns intellilock telemetry."""
        sample_path = os.path.join(self.temp_dir, "sample_ilock.exe")
        buf = bytearray(make_synthetic_pe())
        buf.extend(b"IntelliLock EvaluationMode")
        with open(sample_path, "wb") as f:
            f.write(buf)

        report = DotNetPackerCore.analyze_file(sample_path)
        self.assertIn("intellilock", report)
        itllock = report["intellilock"]
        self.assertTrue(itllock["detected"])
        self.assertIn("IntelliLock", itllock["markers_found"])

    def test_core_strip_intellilock_programmatic(self):
        """Verifies DotNetPackerCore.strip_intellilock programmatic API."""
        sample_path = os.path.join(self.temp_dir, "input_ilock.exe")
        out_path = os.path.join(self.temp_dir, "output_unlocked.exe")
        buf = bytearray(make_synthetic_pe())
        buf.extend(b"IntelliLock.Licensing")
        with open(sample_path, "wb") as f:
            f.write(buf)

        res = DotNetPackerCore.strip_intellilock(sample_path, out_path)
        self.assertTrue(os.path.exists(out_path))
        self.assertEqual(res["unlocked_file"], out_path)
        self.assertGreater(res["size_bytes"], 0)

    def test_cli_strip_intellilock(self):
        """Verifies CLI execution with --strip-intellilock flag."""
        sample_path = os.path.join(self.temp_dir, "cli_ilock.exe")
        out_path = os.path.join(self.temp_dir, "cli_unlocked.exe")
        buf = bytearray(make_synthetic_pe())
        buf.extend(b"IntelliLock.Licensing")
        with open(sample_path, "wb") as f:
            f.write(buf)

        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            with patch("sys.argv", ["dotnet-packer-re", sample_path, "--strip-intellilock", "--intellilock-out", out_path]):
                ret = main()
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(out_path))
        self.assertIn("Successfully neutralized IntelliLock license envelope", stdout.getvalue())

    def test_cli_gen_license(self):
        """Verifies CLI execution with --gen-license flag."""
        sample_path = os.path.join(self.temp_dir, "dummy.exe")
        lic_out = os.path.join(self.temp_dir, "test_out.lic")
        with open(sample_path, "wb") as f:
            f.write(make_synthetic_pe())

        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            with patch("sys.argv", ["dotnet-packer-re", sample_path, "--gen-license", "--license-out", lic_out]):
                ret = main()
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(lic_out))
        self.assertIn("Generated synthetic perpetual master license", stdout.getvalue())

    def test_payload_verifier_on_unlocked_output(self):
        """Verifies PayloadVerifier structural verification on unlocked binary."""
        unlocked_bytes = bytes(make_synthetic_pe())
        res = PayloadVerifier.verify_payload_buffer(unlocked_bytes)
        self.assertTrue(res.pe_structure.is_pe)
        self.assertIn("IMAGE_FILE_MACHINE_I386", res.pe_structure.machine)


if __name__ == "__main__":
    unittest.main()
