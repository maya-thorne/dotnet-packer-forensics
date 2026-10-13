"""
Comprehensive Unit & Integration Test Suite for Anti-Dump Healer & Scylla Normalizer.
Engineered & Audited by Maya Thorne.
"""

import io
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator import DotNetPackerCore
from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.unpackers.antidump import AntiDumpUnpacker
from dotnet_deobfuscator.unpackers.antidump_healer import AntiDumpHealer
from dotnet_deobfuscator.unpackers.antidump_models import (
    AntiDumpHealOptions,
    AntiDumpTechnique,
    DumpSource,
    SecurityError,
)


def create_mock_pe_dump(
    erase_dos: bool = False,
    erase_pe: bool = False,
    is_mem_dump: bool = True,
    strip_names: bool = False,
    include_bsjb: bool = True,
    strip_cor20: bool = True,
) -> bytes:
    """Helper to synthesize a test PE / process memory dump with configurable corruptions."""
    # 0x000 - 0x080: DOS Header
    dos_hdr = bytearray(0x80)
    if not erase_dos:
        dos_hdr[0:2] = b"MZ"
        struct.pack_into("<I", dos_hdr, 0x3C, 0x80)  # e_lfanew -> 0x80

    # 0x080 - 0x170: NT Headers (PE Signature, File Header, Optional Header)
    nt_hdr = bytearray(0xF8)
    if not erase_pe:
        nt_hdr[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", nt_hdr, 4, 0x014C)   # Machine: I386
    struct.pack_into("<H", nt_hdr, 6, 2)        # NumberOfSections: 2
    struct.pack_into("<H", nt_hdr, 20, 0xE0)    # SizeOfOptionalHeader
    struct.pack_into("<H", nt_hdr, 22, 0x0102)  # Characteristics: EXECUTABLE | 32BIT

    # Optional Header
    struct.pack_into("<H", nt_hdr, 24, 0x010B)  # Magic: PE32
    struct.pack_into("<I", nt_hdr, 40, 0x2000)  # AddressOfEntryPoint
    struct.pack_into("<I", nt_hdr, 52, 0x00400000)  # ImageBase
    struct.pack_into("<I", nt_hdr, 56, 0x2000)  # SectionAlignment
    struct.pack_into("<I", nt_hdr, 60, 0x200 if not is_mem_dump else 0x2000)  # FileAlignment
    struct.pack_into("<I", nt_hdr, 80, 0x6000)  # SizeOfImage
    struct.pack_into("<I", nt_hdr, 84, 0x200)   # SizeOfHeaders
    struct.pack_into("<H", nt_hdr, 68, 3)       # Subsystem: Windows CUI
    struct.pack_into("<I", nt_hdr, 116, 16)     # NumberOfRvaAndSizes

    # Data Directory[14] (CLR Cor20Header)
    if not strip_cor20:
        struct.pack_into("<II", nt_hdr, 120 + (14 * 8), 0x2050, 72)

    # 0x178 - 0x1C8: Section Table (2 sections: .text @ 0x2000, .rdata @ 0x4000)
    sec_table = bytearray(80)
    # Sec 1: .text
    sec1_name = b"\x00" * 8 if strip_names else b".text\x00\x00\x00"
    sec_table[0:8] = sec1_name
    struct.pack_into("<I", sec_table, 8, 0x1000)   # VirtualSize
    struct.pack_into("<I", sec_table, 12, 0x2000)  # VirtualAddress
    struct.pack_into("<I", sec_table, 16, 0x1000)  # RawSize
    struct.pack_into("<I", sec_table, 20, 0x2000 if is_mem_dump else 0x200)  # RawPointer
    struct.pack_into("<I", sec_table, 36, 0x60000020)  # Characteristics: CODE

    # Sec 2: .rdata
    sec2_name = b"\x00" * 8 if strip_names else b".rdata\x00\x00"
    sec_table[40:48] = sec2_name
    struct.pack_into("<I", sec_table, 48, 0x1000)  # VirtualSize
    struct.pack_into("<I", sec_table, 52, 0x4000)  # VirtualAddress
    struct.pack_into("<I", sec_table, 56, 0x1000)  # RawSize
    struct.pack_into("<I", sec_table, 60, 0x4000 if is_mem_dump else 0x1200)  # RawPointer
    struct.pack_into("<I", sec_table, 76, 0x40000040)  # Characteristics: DATA

    # Total buffer size for memory dump layout: up to 0x5000 bytes
    total_len = 0x5000 if is_mem_dump else 0x2200
    blob = bytearray(total_len)
    blob[0:0x80] = dos_hdr
    blob[0x80 : 0x80 + len(nt_hdr)] = nt_hdr
    blob[0x80 + len(nt_hdr) : 0x80 + len(nt_hdr) + len(sec_table)] = sec_table

    # Add BSJB metadata in .text section
    if include_bsjb:
        bsjb_pos = 0x2000 if is_mem_dump else 0x200
        # "BSJB" magic (0x424A5342)
        blob[bsjb_pos : bsjb_pos + 4] = b"BSJB"
        struct.pack_into("<HH", blob, bsjb_pos + 4, 1, 1)  # Version 1.1
        ver_str = b"v4.0.30319\x00\x00"
        struct.pack_into("<I", blob, bsjb_pos + 12, len(ver_str))
        blob[bsjb_pos + 16 : bsjb_pos + 16 + len(ver_str)] = ver_str
        stream_pos = bsjb_pos + 16 + len(ver_str)
        struct.pack_into("<HH", blob, stream_pos, 0, 5)  # 5 streams

    return bytes(blob)


class TestAntiDumpHealer(unittest.TestCase):
    """Test suite verifying anti-dump heuristics, Scylla dump unmapping, and PE restoration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_antidump_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_clean_pe(self):
        """A clean PE binary with intact headers should not be flagged as anti-dump."""
        data = create_mock_pe_dump(
            erase_dos=False, erase_pe=False, is_mem_dump=False, strip_names=False, strip_cor20=False
        )
        telem = AntiDumpHealer.detect(data)
        self.assertTrue(telem.original_header_intact)
        self.assertFalse(telem.is_anti_dump_detected)
        self.assertEqual(telem.confidence, "LOW")


    def test_detect_erased_dos_header(self):
        """Erased DOS header should be detected immediately."""
        data = create_mock_pe_dump(erase_dos=True, erase_pe=False, is_mem_dump=True)
        telem = AntiDumpHealer.detect(data)
        self.assertFalse(telem.original_header_intact)
        self.assertIn(AntiDumpTechnique.ERASED_DOS_HEADER, telem.detected_techniques)
        self.assertTrue(telem.is_anti_dump_detected)

    def test_detect_virtual_memory_layout(self):
        """VirtualAddress == RawPointer indicates a process memory dump."""
        data = create_mock_pe_dump(erase_dos=False, erase_pe=False, is_mem_dump=True)
        telem = AntiDumpHealer.detect(data)
        self.assertIn(AntiDumpTechnique.VIRTUAL_MEMORY_LAYOUT, telem.detected_techniques)
        self.assertEqual(telem.dump_source, DumpSource.RAW_VIRTUAL_MEM)

    def test_detect_stripped_section_names(self):
        """Zeroed section names should be flagged as stripped section table."""
        data = create_mock_pe_dump(strip_names=True, is_mem_dump=True)
        telem = AntiDumpHealer.detect(data)
        self.assertIn(AntiDumpTechnique.STRIPPED_SECTION_TABLE, telem.detected_techniques)

    def test_detect_confuserex_antidump_pattern(self):
        """ConfuserEx Anti-Dump runtime pattern marker should trigger detection."""
        base_data = create_mock_pe_dump(erase_dos=True)
        corrupted = base_data + b"\x00\x00Confuser.Runtime.AntiDump\x00\x00"
        telem = AntiDumpHealer.detect(corrupted)
        self.assertIn(AntiDumpTechnique.CONFUSEREX_ANTIDUMP, telem.detected_techniques)
        self.assertEqual(telem.confidence, "HIGH")

    def test_scan_bsjb_metadata(self):
        """BSJB scanner correctly identifies offset and version string."""
        data = create_mock_pe_dump(include_bsjb=True)
        info = AntiDumpHealer.scan_bsjb_metadata(data)
        self.assertIsNotNone(info)
        offset, est_size, ver_str = info
        self.assertIn("v4.0.30319", ver_str)
        self.assertGreater(est_size, 0)

    def test_build_clr_import_table(self):
        """Synthesized CLR import table contains valid mscoree.dll bootstrap thunk."""
        blob, desc_rva, iat_rva, info = AntiDumpHealer.build_clr_import_table(
            image_base=0x00400000, target_rva=0x6000, is_dll=False
        )
        self.assertEqual(info.dll_name, "mscoree.dll")
        self.assertEqual(info.symbol_name, "_CorExeMain")
        # Entry point jump is FF 25 <IAT_VA>
        self.assertEqual(blob[0:2], b"\xFF\x25")
        jump_target = struct.unpack_from("<I", blob, 2)[0]
        self.assertEqual(jump_target, 0x00400000 + iat_rva)
        self.assertIn(b"mscoree.dll", blob)
        self.assertIn(b"_CorExeMain", blob)

    def test_heal_dump_erased_dos_and_pe(self):
        """Healing a dump with erased DOS and PE headers successfully restores valid PE executable."""
        dump_data = create_mock_pe_dump(erase_dos=True, erase_pe=True, is_mem_dump=True, strip_names=True)
        healed_bytes, result = AntiDumpHealer.heal_dump(dump_data)

        self.assertTrue(result.is_healed)
        self.assertEqual(healed_bytes[:2], b"MZ")
        e_lfanew = struct.unpack_from("<I", healed_bytes, 0x3C)[0]
        self.assertEqual(healed_bytes[e_lfanew : e_lfanew + 4], b"PE\x00\x00")
        self.assertGreater(result.healed_size, 0)
        self.assertTrue(len(result.sha256) == 64)
        self.assertIn("Restored DOS magic signature (0x5A4D)", result.telemetry.actions)

    def test_heal_dump_unmap_memory_layout(self):
        """Memory dump unmapping repacks sections into sequential file-aligned layout."""
        dump_data = create_mock_pe_dump(erase_dos=False, erase_pe=False, is_mem_dump=True)
        options = AntiDumpHealOptions(target_file_alignment=0x200, unmap_virtual_memory=True)
        healed_bytes, result = AntiDumpHealer.heal_dump(dump_data, options=options)

        self.assertTrue(result.is_healed)
        # All sections should have raw pointers aligned to 0x200
        for s in result.sections:
            self.assertEqual(s.raw_ptr % 0x200, 0)
            self.assertEqual(s.raw_size % 0x200, 0)

    def test_heal_dump_synthesize_cor20(self):
        """Cor20Header is synthesized and connected to DataDirectory[14]."""
        dump_data = create_mock_pe_dump(strip_cor20=True, include_bsjb=True)
        healed_bytes, result = AntiDumpHealer.heal_dump(dump_data)

        self.assertTrue(result.telemetry.cor20_synthesized)
        self.assertIsNotNone(result.telemetry.cor20_rva)

        # Check DataDirectory[14]
        e_lfanew = struct.unpack_from("<I", healed_bytes, 0x3C)[0]
        dd_offset = e_lfanew + 24 + 96
        cor20_rva, cor20_size = struct.unpack_from("<II", healed_bytes, dd_offset + (14 * 8))
        self.assertEqual(cor20_size, 72)
        self.assertEqual(cor20_rva, result.telemetry.cor20_rva)

    def test_heal_dump_synthesize_sections_when_stripped(self):
        """Completely missing section table is synthesized from memory regions."""
        # Buffer with only BSJB metadata and no section table
        blob = bytearray(0x3000)
        blob[0x2000 : 0x2004] = b"BSJB"
        struct.pack_into("<HH", blob, 0x2004, 1, 1)
        ver_str = b"v4.0.30319\x00"
        struct.pack_into("<I", blob, 0x200C, len(ver_str))
        blob[0x2010 : 0x2010 + len(ver_str)] = ver_str
        struct.pack_into("<HH", blob, 0x2010 + len(ver_str), 0, 3)

        healed_bytes, result = AntiDumpHealer.heal_dump(bytes(blob))
        self.assertTrue(result.is_healed)
        self.assertGreaterEqual(len(result.sections), 1)
        self.assertTrue(any(s.name == ".text" for s in result.sections))

    def test_unpack_to_directory_safe(self):
        """AntiDumpUnpacker.unpack_to_directory writes all artifacts safely."""
        dump_data = create_mock_pe_dump(erase_dos=True, is_mem_dump=True)
        out_dir = os.path.join(self.temp_dir, "unpacked_dump")
        res = AntiDumpUnpacker.unpack_to_directory(dump_data, out_dir)

        self.assertTrue(os.path.isdir(out_dir))
        self.assertIn("healed_dump.exe", res["exported_files"])
        self.assertIn("antidump_telemetry.json", res["exported_files"])
        self.assertTrue(os.path.exists(os.path.join(out_dir, "healed_dump.exe")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "antidump_telemetry.json")))

    def test_path_traversal_prevention(self):
        """Malicious relative output paths raise SecurityError."""
        with self.assertRaises(SecurityError):
            AntiDumpUnpacker._safe_path(self.temp_dir, "../../escaped.exe")


    def test_buffer_size_limit_security(self):
        """Buffers exceeding safety limit are rejected."""
        # We simulate this with an oversized check
        with self.assertRaises(SecurityError):
            AntiDumpHealer.detect(b"X" * (257 * 1024 * 1024))

    def test_core_integration(self):
        """DotNetPackerCore orchestration APIs work seamlessly."""
        dump_data = create_mock_pe_dump(erase_dos=True, is_mem_dump=True)
        dump_file = os.path.join(self.temp_dir, "sample.dmp")
        with open(dump_file, "wb") as f:
            f.write(dump_data)

        # 1. detect_anti_dump
        detect_res = DotNetPackerCore.detect_anti_dump(dump_file)
        self.assertTrue(detect_res["is_anti_dump"])

        # 2. heal_anti_dump
        healed_out = os.path.join(self.temp_dir, "healed.exe")
        healed_pe, rep = DotNetPackerCore.heal_anti_dump(dump_file, output_path=healed_out)
        self.assertTrue(rep["is_healed"])
        self.assertTrue(os.path.exists(healed_out))

        # 3. analyze_file includes anti_dump telemetry
        full_analysis = DotNetPackerCore.analyze_file(dump_file)
        self.assertIn("anti_dump", full_analysis)
        self.assertTrue(full_analysis["anti_dump"]["detected"])

    def test_cli_flags(self):
        """CLI handles --heal-dump and --anti-dump-dir without error."""
        dump_data = create_mock_pe_dump(erase_dos=True, is_mem_dump=True)
        dump_file = os.path.join(self.temp_dir, "cli_dump.bin")
        healed_file = os.path.join(self.temp_dir, "cli_healed.exe")
        dir_out = os.path.join(self.temp_dir, "cli_antidump_dir")
        with open(dump_file, "wb") as f:
            f.write(dump_data)

        # Test --heal-dump --heal-out
        code = main([dump_file, "--heal-dump", "--heal-out", healed_file])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(healed_file))

        # Test --anti-dump-dir
        code = main([dump_file, "--anti-dump-dir", dir_out])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isdir(dir_out))


if __name__ == "__main__":
    unittest.main()
