"""
Comprehensive Unit & Integration Test Suite for Native Multi-Architecture Demuxer & Platform Router.
Engineered & Audited by Maya Thorne.
"""

import io
import json
import os
import shutil
import struct
import tempfile
import unittest
import zlib

from dotnet_deobfuscator import (
    BinaryFormat,
    DemuxSource,
    DotNetPackerCore,
    NativeDemuxerEngine,
    NativeDemuxerTelemetry,
    NativeDemuxerUnpacker,
    NativePayloadInfo,
    PlatformRouteResult,
    TargetArchitecture,
    TargetOS,
)
from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.unpackers.native_demuxer_engine import zeroize_buffer
from dotnet_deobfuscator.unpackers.native_demuxer_models import SecurityError


def create_mock_pe(
    machine: int = 0x014C,
    magic: int = 0x010B,
    export_name: str = "test_module.dll",
    payload_size: int = 1024,
) -> bytes:
    """Helper to synthesize a minimal valid PE binary with specified machine and export name."""
    pe = bytearray(payload_size)
    # DOS Header
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)  # e_lfanew = 0x80

    # NT Headers
    struct.pack_into("<I", pe, 0x80, 0x00004550)  # "PE\0\0"
    struct.pack_into("<H", pe, 0x84, machine)      # Machine
    struct.pack_into("<H", pe, 0x86, 1)           # NumberOfSections = 1
    struct.pack_into("<H", pe, 0x94, 0xE0)        # SizeOfOptionalHeader
    struct.pack_into("<H", pe, 0x96, 0x2102)      # Characteristics: EXECUTABLE | DLL

    # Optional Header
    struct.pack_into("<H", pe, 0x98, magic)       # 0x10B (PE32) or 0x20B (PE32+)
    struct.pack_into("<I", pe, 0x98 + 16, 0x1000) # AddressOfEntryPoint
    struct.pack_into("<I", pe, 0x98 + 28, 0x00400000)  # ImageBase
    struct.pack_into("<I", pe, 0x98 + 32, 0x1000) # SectionAlignment
    struct.pack_into("<I", pe, 0x98 + 36, 0x200)  # FileAlignment
    struct.pack_into("<I", pe, 0x98 + 56, payload_size)  # SizeOfImage
    struct.pack_into("<I", pe, 0x98 + 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", pe, 0x98 + 68, 3)      # Subsystem: Windows CUI
    struct.pack_into("<I", pe, 0x98 + 92 if magic == 0x10B else 0x98 + 108, 16)  # NumberOfRvaAndSizes

    # Export Directory Table RVA
    dd_offset = 0x98 + (96 if magic == 0x10B else 112)
    struct.pack_into("<II", pe, dd_offset, 0x1000, 0x100)  # Export Directory RVA 0x1000, Size 0x100

    # Section Header (.rdata at raw 0x200, VAddr 0x1000)
    sec_off = 0x80 + 24 + 0xE0
    pe[sec_off : sec_off + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", pe, sec_off + 8, 0x200, 0x1000, payload_size - 0x200, 0x200)
    struct.pack_into("<I", pe, sec_off + 36, 0x40000040)  # INITIALIZED_DATA | READ

    # In section at raw 0x200 (RVA 0x1000): IMAGE_EXPORT_DIRECTORY
    # Offset 12 is Name RVA -> 0x1040
    struct.pack_into("<I", pe, 0x200 + 12, 0x1040)
    # At raw 0x240 (RVA 0x1040): ASCII export_name
    exp_bytes = export_name.encode("ascii") + b"\x00"
    pe[0x240 : 0x240 + len(exp_bytes)] = exp_bytes

    return bytes(pe)


def create_mock_elf(ei_class: int = 1, e_machine: int = 0x03) -> bytes:
    """Helper to synthesize a minimal mock ELF binary."""
    elf = bytearray(512)
    elf[0:4] = b"\x7fELF"
    elf[4] = ei_class  # 1 = 32-bit, 2 = 64-bit
    elf[5] = 1         # little-endian
    elf[6] = 1         # version
    struct.pack_into("<H", elf, 18, e_machine)
    return bytes(elf)


def create_mock_macho(cputype: int = 0x01000007, is_64: bool = True) -> bytes:
    """Helper to synthesize a minimal mock Mach-O binary."""
    macho = bytearray(512)
    magic = 0xFEEDFACF if is_64 else 0xFEEDFACE
    struct.pack_into("<I", macho, 0, magic)
    struct.pack_into("<I", macho, 4, cputype)
    return bytes(macho)


class TestNativeDemuxerSuite(unittest.TestCase):
    """Test suite for Native Multi-Architecture Demuxer and Platform Router."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_native_demux_")
        self.pe_x86 = create_mock_pe(machine=0x014C, magic=0x010B, export_name="sqlite3_x86.dll")
        self.pe_x64 = create_mock_pe(machine=0x8664, magic=0x020B, export_name="sqlite3_x64.dll")
        self.pe_arm64 = create_mock_pe(machine=0xAA64, magic=0x020B, export_name="sqlite3_arm64.dll")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_inspect_binary_format_pe(self):
        """Validates PE architecture inspection for x86, x64, and ARM64."""
        fmt, arch, os_t, machine, subsys, exp_name = NativeDemuxerEngine.inspect_binary_format(self.pe_x86)
        self.assertEqual(fmt, BinaryFormat.PE32)
        self.assertEqual(arch, TargetArchitecture.X86)
        self.assertEqual(os_t, TargetOS.WINDOWS)
        self.assertEqual(machine, 0x014C)
        self.assertEqual(exp_name, "sqlite3_x86.dll")

        fmt, arch, os_t, machine, subsys, exp_name = NativeDemuxerEngine.inspect_binary_format(self.pe_x64)
        self.assertEqual(fmt, BinaryFormat.PE32_PLUS)
        self.assertEqual(arch, TargetArchitecture.X64)
        self.assertEqual(machine, 0x8664)
        self.assertEqual(exp_name, "sqlite3_x64.dll")

        fmt, arch, os_t, machine, subsys, exp_name = NativeDemuxerEngine.inspect_binary_format(self.pe_arm64)
        self.assertEqual(fmt, BinaryFormat.PE32_PLUS)
        self.assertEqual(arch, TargetArchitecture.ARM64)
        self.assertEqual(machine, 0xAA64)
        self.assertEqual(exp_name, "sqlite3_arm64.dll")

    def test_inspect_binary_format_elf_and_macho(self):
        """Validates ELF and Mach-O inspection."""
        elf_x64 = create_mock_elf(ei_class=2, e_machine=0x3E)
        fmt, arch, os_t, machine, _, _ = NativeDemuxerEngine.inspect_binary_format(elf_x64)
        self.assertEqual(fmt, BinaryFormat.ELF64)
        self.assertEqual(arch, TargetArchitecture.X64)
        self.assertEqual(os_t, TargetOS.LINUX)

        elf_arm64 = create_mock_elf(ei_class=2, e_machine=0xB7)
        fmt, arch, os_t, machine, _, _ = NativeDemuxerEngine.inspect_binary_format(elf_arm64)
        self.assertEqual(fmt, BinaryFormat.ELF64)
        self.assertEqual(arch, TargetArchitecture.ARM64)

        macho_arm64 = create_mock_macho(cputype=0x0100000C, is_64=True)
        fmt, arch, os_t, cputype, _, _ = NativeDemuxerEngine.inspect_binary_format(macho_arm64)
        self.assertEqual(fmt, BinaryFormat.MACHO64)
        self.assertEqual(arch, TargetArchitecture.ARM64)
        self.assertEqual(os_t, TargetOS.OSX)

    def test_zeroize_buffer(self):
        """Validates in-memory buffer wiping with zeroize_buffer."""
        buf = bytearray(b"SENSITIVE_KEY_AND_DECRYPTED_BYTES_1234567890")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(buf)))

    def test_decompress_payload(self):
        """Validates Costura DeflateStream and zlib payload decompression."""
        raw_text = b"MZ\x90\x00TestDecompressedPayloadData12345" * 10
        # Costura Deflate format: 4-byte uncompressed length prefix + DeflateStream
        compressed = struct.pack("<I", len(raw_text)) + zlib.compress(raw_text)[2:-4]
        decomp, was_comp, orig_len = NativeDemuxerEngine.decompress_payload(compressed)
        self.assertTrue(was_comp)
        self.assertEqual(decomp, raw_text)

    def test_demux_multi_arch_carving(self):
        """Tests discovery and extraction of multiplexed multi-architecture native binaries."""
        # Create a carrier binary containing x86, x64, and ARM64 payloads
        carrier = bytearray(create_mock_pe(machine=0x014C, payload_size=2048))
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x86)
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x64)
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_arm64)

        telemetry, payloads = NativeDemuxerUnpacker.demux(bytes(carrier))
        self.assertTrue(telemetry.is_multi_arch)
        self.assertIn("x86", telemetry.architectures_found)
        self.assertIn("x64", telemetry.architectures_found)
        self.assertIn("arm64", telemetry.architectures_found)
        self.assertGreaterEqual(len(payloads), 3)

    def test_architecture_mismatch_detection(self):
        """Tests detection of spoofed or mismatched architecture declarations."""
        # Build binary with costura32 naming pattern, but embed x64 PE
        carrier = bytearray(create_mock_pe(machine=0x014C, payload_size=1024))
        # Add string marker declaring costura32
        carrier.extend(b"\x00\x00costura32.corrupted.dll\x00\x00")
        # Followed by x64 binary
        carrier.extend(self.pe_x64)

        telemetry, payloads = NativeDemuxerUnpacker.demux(bytes(carrier))
        # Find the x64 payload that was tagged as costura32
        mismatched = [p for p in payloads if p.mismatch_detected]
        self.assertGreaterEqual(len(mismatched), 1)
        self.assertTrue(telemetry.has_architecture_mismatch)
        self.assertGreaterEqual(telemetry.mismatch_count, 1)

    def test_platform_routing_exact(self):
        """Tests exact match platform routing."""
        payload_x86 = NativePayloadInfo(
            name="native_x86.dll", target_arch=TargetArchitecture.X86, target_os=TargetOS.WINDOWS,
            format=BinaryFormat.PE32, source=DemuxSource.OVERLAY_CARVED, size_bytes=1024,
            sha256="hash1", sha1="s1", md5="m1", entropy=1.0, is_pe=True, machine_code=0x014C,
            machine_hex="0x014C", raw_data=self.pe_x86,
        )
        payload_x64 = NativePayloadInfo(
            name="native_x64.dll", target_arch=TargetArchitecture.X64, target_os=TargetOS.WINDOWS,
            format=BinaryFormat.PE32_PLUS, source=DemuxSource.OVERLAY_CARVED, size_bytes=1024,
            sha256="hash2", sha1="s2", md5="m2", entropy=1.0, is_pe=True, machine_code=0x8664,
            machine_hex="0x8664", raw_data=self.pe_x64,
        )
        payloads = [payload_x86, payload_x64]

        res = NativeDemuxerEngine.route_for_platform(payloads, TargetOS.WINDOWS, TargetArchitecture.X86)
        self.assertEqual(res.resolution_status, "RESOLVED_EXACT")
        self.assertEqual(res.matched_payload["name"], "native_x86.dll")

        res64 = NativeDemuxerEngine.route_for_platform(payloads, TargetOS.WINDOWS, TargetArchitecture.X64)
        self.assertEqual(res64.resolution_status, "RESOLVED_EXACT")
        self.assertEqual(res64.matched_payload["name"], "native_x64.dll")

    def test_platform_routing_fallback_wow64(self):
        """Tests WoW64 fallback resolution on x64 when only x86 payload is available."""
        payload_x86 = NativePayloadInfo(
            name="only_x86.dll", target_arch=TargetArchitecture.X86, target_os=TargetOS.WINDOWS,
            format=BinaryFormat.PE32, source=DemuxSource.COSTURA_NATIVE, size_bytes=1024,
            sha256="h1", sha1="s1", md5="m1", entropy=1.0, is_pe=True, machine_code=0x014C,
            machine_hex="0x014C", raw_data=self.pe_x86,
        )
        res = NativeDemuxerEngine.route_for_platform([payload_x86], TargetOS.WINDOWS, TargetArchitecture.X64)
        self.assertEqual(res.resolution_status, "RESOLVED_FALLBACK")
        self.assertEqual(res.matched_payload["name"], "only_x86.dll")
        self.assertTrue(any("WoW64" in s for s in res.fallback_chain))

    def test_platform_routing_fallback_arm64_emulation(self):
        """Tests Windows on ARM emulation fallback when ARM64 is requested but only x64 is available."""
        payload_x64 = NativePayloadInfo(
            name="only_x64.dll", target_arch=TargetArchitecture.X64, target_os=TargetOS.WINDOWS,
            format=BinaryFormat.PE32_PLUS, source=DemuxSource.COSTURA_NATIVE, size_bytes=1024,
            sha256="h2", sha1="s2", md5="m2", entropy=1.0, is_pe=True, machine_code=0x8664,
            machine_hex="0x8664", raw_data=self.pe_x64,
        )
        res = NativeDemuxerEngine.route_for_platform([payload_x64], TargetOS.WINDOWS, TargetArchitecture.ARM64)
        self.assertEqual(res.resolution_status, "RESOLVED_FALLBACK")
        self.assertEqual(res.matched_payload["name"], "only_x64.dll")

    def test_platform_routing_missing_arch(self):
        """Tests routing failure when requested architecture cannot be satisfied."""
        payload_x86 = NativePayloadInfo(
            name="only_x86.dll", target_arch=TargetArchitecture.X86, target_os=TargetOS.WINDOWS,
            format=BinaryFormat.PE32, source=DemuxSource.COSTURA_NATIVE, size_bytes=1024,
            sha256="h1", sha1="s1", md5="m1", entropy=1.0, is_pe=True, machine_code=0x014C,
            machine_hex="0x014C", raw_data=self.pe_x86,
        )
        res = NativeDemuxerEngine.route_for_platform([payload_x86], TargetOS.LINUX, TargetArchitecture.ARM64)
        self.assertEqual(res.resolution_status, "UNRESOLVED_MISSING_ARCH")
        self.assertIsNone(res.matched_payload)

    def test_safe_path_traversal_defense(self):
        """Validates path traversal prevention in directory exporter."""
        base_dir = os.path.join(self.temp_dir, "safe_base")
        os.makedirs(base_dir, exist_ok=True)
        with self.assertRaises(SecurityError):
            NativeDemuxerUnpacker._safe_path(base_dir, "../../malicious.exe")

    def test_unpack_to_directory(self):
        """Tests directory export of demuxed payloads and routing manifest generation."""
        carrier = bytearray(create_mock_pe(machine=0x014C, payload_size=2048))
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x86)
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x64)

        out_dir = os.path.join(self.temp_dir, "demux_out")
        res = NativeDemuxerUnpacker.unpack_to_directory(bytes(carrier), output_dir=out_dir)

        self.assertGreaterEqual(res["total_extracted"], 2)
        self.assertTrue(os.path.exists(res["manifest_path"]))

        # Verify manifest content
        with open(res["manifest_path"], "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertIn("routing_simulation", manifest)
        self.assertIn("extracted_payloads", manifest)

        # Verify architecture folder creation
        self.assertTrue(os.path.isdir(os.path.join(out_dir, "x86")) or os.path.isdir(os.path.join(out_dir, "x64")))

    def test_core_analyze_and_report_integration(self):
        """Tests DotNetPackerCore orchestration and text report formatting integration."""
        carrier = bytearray(create_mock_pe(machine=0x014C, payload_size=2048))
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x86)
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x64)

        target_file = os.path.join(self.temp_dir, "multi_arch_test.exe")
        with open(target_file, "wb") as f:
            f.write(carrier)

        report = DotNetPackerCore.analyze_file(target_file)
        self.assertIn("native_demuxer", report)
        self.assertTrue(report["native_demuxer"]["detected"])
        self.assertIn("x86", report["native_demuxer"]["architectures_found"])

        # Test CLI report text formatting
        from dotnet_deobfuscator.report_formatter import format_text_report
        text_rep = format_text_report(report)
        self.assertIn("--- [Native Multi-Architecture Resource Demuxer & Platform Router] ---", text_rep)
        self.assertIn("Total Payloads", text_rep)

    def test_cli_demux_flags(self):
        """Tests CLI arguments --demux-native and --demux-out."""
        carrier = bytearray(create_mock_pe(machine=0x014C, payload_size=2048))
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x86)
        carrier.extend(b"\x00" * 512)
        carrier.extend(self.pe_x64)

        target_file = os.path.join(self.temp_dir, "cli_multi_test.exe")
        with open(target_file, "wb") as f:
            f.write(carrier)

        demux_dir = os.path.join(self.temp_dir, "cli_demux_dir")
        ret = main([target_file, "--demux-native", "--demux-out", demux_dir, "--route-arch", "x64"])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(demux_dir, "routing_manifest.json")))


if __name__ == "__main__":
    unittest.main()
