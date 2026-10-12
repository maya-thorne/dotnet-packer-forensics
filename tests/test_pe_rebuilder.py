"""
Comprehensive Unit Tests for PE Header & Section Rebuilder Module.
Engineered & Audited by Maya Thorne.
"""

import io
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator.cli import main as cli_main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.pe_rebuilder import (
    PERebuilder,
    PERebuildOptions,
    PERebuildReport,
    SectionHeader,
)


def create_synthetic_pe(
    dos_magic: bytes = b"MZ",
    pe_sig: bytes = b"PE\x00\x00",
    machine: int = 0x014C,
    num_sections: int = 2,
    opt_size: int = 0xE0,
    magic: int = 0x10B,
    sec_align: int = 0x2000,
    file_align: int = 0x200,
    is_mem_dump: bool = False,
    include_cor20: bool = False,
    zero_cor20_dir: bool = False,
    include_security_dir: bool = False,
) -> bytes:
    """Builds a deterministic synthetic PE executable buffer for testing."""
    pe_offset = 0x80
    buf = bytearray(0x8000)

    # DOS Header
    buf[0:2] = dos_magic
    struct.pack_into("<I", buf, 0x3C, pe_offset)

    # NT Header
    buf[pe_offset : pe_offset + 4] = pe_sig
    struct.pack_into("<H", buf, pe_offset + 4, machine)
    struct.pack_into("<H", buf, pe_offset + 6, num_sections)
    struct.pack_into("<H", buf, pe_offset + 20, opt_size)
    struct.pack_into("<H", buf, pe_offset + 22, 0x0102)  # Executable 32-bit

    # Optional Header
    struct.pack_into("<H", buf, pe_offset + 24, magic)
    struct.pack_into("<I", buf, pe_offset + 40, 0x2000)  # EntryPoint RVA
    struct.pack_into("<I", buf, pe_offset + 56, sec_align)
    struct.pack_into("<I", buf, pe_offset + 60, file_align)
    struct.pack_into("<I", buf, pe_offset + 80, 0x6000)  # SizeOfImage
    struct.pack_into("<I", buf, pe_offset + 84, 0x400)   # SizeOfHeaders
    struct.pack_into("<H", buf, pe_offset + 68, 3)       # Subsystem Windows CUI
    struct.pack_into("<I", buf, pe_offset + 116, 16)    # NumberOfRvaAndSizes

    data_dir_base = pe_offset + 24 + 96

    # Security Directory (Entry 4)
    if include_security_dir:
        struct.pack_into("<II", buf, data_dir_base + (4 * 8), 0x5000, 0x200)

    # Cor20 Header / COM Descriptor (Entry 14)
    cor20_rva = 0x2050
    if include_cor20 and not zero_cor20_dir:
        struct.pack_into("<II", buf, data_dir_base + (14 * 8), cor20_rva, 72)

    # Section Headers
    sec_hdr_start = pe_offset + 24 + opt_size
    sec_names = [b".text\x00\x00\x00", b".rsrc\x00\x00\x00"]

    for i in range(num_sections):
        entry = sec_hdr_start + (i * 40)
        buf[entry : entry + 8] = sec_names[i]
        vsize = 0x1500
        vaddr = 0x2000 * (i + 1)
        rsize = 0x1600 if not is_mem_dump else vsize
        rptr = (0x400 + (i * 0x1600)) if not is_mem_dump else vaddr

        struct.pack_into("<I", buf, entry + 8, vsize)
        struct.pack_into("<I", buf, entry + 12, vaddr)
        struct.pack_into("<I", buf, entry + 16, rsize)
        struct.pack_into("<I", buf, entry + 20, rptr)
        struct.pack_into("<I", buf, entry + 36, 0x60000020)  # Read + Execute + Code

        # Section payload
        payload_ptr = rptr if not is_mem_dump else vaddr
        if payload_ptr + 100 <= len(buf):
            buf[payload_ptr : payload_ptr + 32] = f"SECTION_PAYLOAD_{i}_DATA".encode("ascii")

    # If Cor20 is enabled, write Cor20Header and BSJB metadata into .text payload
    if include_cor20:
        target_offset = cor20_rva if is_mem_dump else (0x400 + 0x50)
        # cb=72, major=2, minor=5, MetaData RVA=0x2200, MetaData Size=128
        struct.pack_into("<IHHII", buf, target_offset, 72, 2, 5, 0x2200, 128)
        # Write BSJB metadata at RVA 0x2200
        bsjb_offset = 0x2200 if is_mem_dump else (0x400 + 0x200)
        buf[bsjb_offset : bsjb_offset + 4] = b"BSJB"

    actual_len = 0x400 + (num_sections * 0x1600) if not is_mem_dump else (0x2000 * (num_sections + 1))
    return bytes(buf[:actual_len])


class TestPERebuilder(unittest.TestCase):
    """Test suite covering PE header, section table, and CLR metadata reconstruction."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_pe_rebuilder_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_anomalies_valid_pe(self):
        pe = create_synthetic_pe()
        diag = PERebuilder.detect_anomalies(pe)
        self.assertTrue(diag["is_pe"])
        self.assertFalse(diag["is_memory_dump"])
        self.assertEqual(len(diag["anomalies"]), 0)

    def test_detect_anomalies_corrupted_dos_and_lfanew(self):
        pe = bytearray(create_synthetic_pe())
        pe[0:2] = b"\x00\x00"  # Destroy MZ
        struct.pack_into("<I", pe, 0x3C, 0xFFFF0000)  # Invalid e_lfanew
        diag = PERebuilder.detect_anomalies(bytes(pe))
        self.assertFalse(diag["is_pe"])
        self.assertTrue(any("Missing or corrupted DOS magic" in a for a in diag["anomalies"]))
        self.assertTrue(any("Corrupted e_lfanew pointer" in a for a in diag["anomalies"]))

    def test_detect_anomalies_memory_dump_layout(self):
        pe = create_synthetic_pe(is_mem_dump=True)
        diag = PERebuilder.detect_anomalies(pe)
        self.assertTrue(diag["is_pe"])
        self.assertTrue(diag["is_memory_dump"])
        self.assertTrue(any("Process memory dump layout detected" in a for a in diag["anomalies"]))

    def test_rebuild_corrupted_dos_header_and_stub(self):
        pe = bytearray(create_synthetic_pe())
        pe[0:2] = b"\x00\x00"
        struct.pack_into("<I", pe, 0x3C, 0)
        # Clear DOS stub
        pe[0x40:0x80] = b"\x00" * 64

        rebuilt, report = PERebuilder.rebuild(bytes(pe))
        self.assertTrue(report.is_repaired)
        self.assertEqual(rebuilt[:2], b"MZ")
        new_lfanew = struct.unpack_from("<I", rebuilt, 0x3C)[0]
        self.assertEqual(new_lfanew, 0x80)
        self.assertEqual(rebuilt[new_lfanew : new_lfanew + 4], b"PE\x00\x00")
        self.assertIn("This program cannot be run in DOS mode", rebuilt[0x40:0x80].decode("latin1", errors="ignore"))

    def test_rebuild_corrupted_nt_signature_and_machine(self):
        pe = bytearray(create_synthetic_pe())
        pe_offset = 0x80
        pe[pe_offset : pe_offset + 4] = b"\x00\x00\x00\x00"
        struct.pack_into("<H", pe, pe_offset + 4, 0)  # Invalid machine

        rebuilt, report = PERebuilder.rebuild(bytes(pe))
        self.assertTrue(report.is_repaired)
        self.assertEqual(rebuilt[pe_offset : pe_offset + 4], b"PE\x00\x00")
        rebuilt_machine = struct.unpack_from("<H", rebuilt, pe_offset + 4)[0]
        self.assertEqual(rebuilt_machine, 0x014C)

    def test_rebuild_section_alignments_and_offsets(self):
        pe = bytearray(create_synthetic_pe())
        sec_entry = 0x80 + 24 + 0xE0
        # Set unaligned raw size and bad pointer
        struct.pack_into("<I", pe, sec_entry + 16, 0x123)
        struct.pack_into("<I", pe, sec_entry + 20, 0x333)

        rebuilt, report = PERebuilder.rebuild(bytes(pe))
        self.assertTrue(report.is_repaired)
        new_rsize = struct.unpack_from("<I", rebuilt, sec_entry + 16)[0]
        new_rptr = struct.unpack_from("<I", rebuilt, sec_entry + 20)[0]
        self.assertEqual(new_rsize % 0x200, 0)
        self.assertEqual(new_rptr % 0x200, 0)

    def test_rebuild_sanitize_section_names(self):
        pe = bytearray(create_synthetic_pe())
        sec_entry = 0x80 + 24 + 0xE0
        pe[sec_entry : sec_entry + 8] = b"\x00\x01\x02\x03\x04\x05\x06\x07"

        rebuilt, report = PERebuilder.rebuild(bytes(pe))
        self.assertTrue(report.is_repaired)
        sec_name = rebuilt[sec_entry : sec_entry + 8].decode("latin1").strip("\x00")
        self.assertTrue(sec_name.startswith(".sec0"))

    def test_rebuild_memory_dump_unmapping(self):
        pe = create_synthetic_pe(is_mem_dump=True)
        rebuilt, report = PERebuilder.rebuild(pe, PERebuildOptions(unmap_memory_dump=True))
        self.assertTrue(report.is_repaired)
        self.assertTrue(report.is_memory_dump)

        # In unmapped file, raw pointers should follow sequentially starting from aligned headers
        sec_entry = 0x80 + 24 + 0xE0
        rptr_0 = struct.unpack_from("<I", rebuilt, sec_entry + 20)[0]
        rsize_0 = struct.unpack_from("<I", rebuilt, sec_entry + 16)[0]
        rptr_1 = struct.unpack_from("<I", rebuilt, sec_entry + 40 + 20)[0]

        aligned_hdr_size = struct.unpack_from("<I", rebuilt, 0x80 + 84)[0]
        self.assertEqual(rptr_0, aligned_hdr_size)
        self.assertEqual(rptr_1, rptr_0 + rsize_0)
        # Content from virtual address should be copied correctly
        self.assertIn(b"SECTION_PAYLOAD_0_DATA", rebuilt)
        self.assertIn(b"SECTION_PAYLOAD_1_DATA", rebuilt)

    def test_rebuild_strip_invalid_security_directory(self):
        pe = create_synthetic_pe(include_security_dir=True)
        sec_dir_offset = 0x80 + 24 + 96 + (4 * 8)
        rva_before = struct.unpack_from("<I", pe, sec_dir_offset)[0]
        self.assertNotEqual(rva_before, 0)

        rebuilt, report = PERebuilder.rebuild(pe)
        self.assertTrue(report.is_repaired)
        rva_after = struct.unpack_from("<I", rebuilt, sec_dir_offset)[0]
        size_after = struct.unpack_from("<I", rebuilt, sec_dir_offset + 4)[0]
        self.assertEqual(rva_after, 0)
        self.assertEqual(size_after, 0)

    def test_rebuild_cor20_header_recovery_anti_dump(self):
        # Create a .NET PE where Cor20 directory entry is zeroed (Anti-Dump trick)
        pe = create_synthetic_pe(include_cor20=True, zero_cor20_dir=True)
        cor20_dir_offset = 0x80 + 24 + 96 + (14 * 8)
        self.assertEqual(struct.unpack_from("<I", pe, cor20_dir_offset)[0], 0)

        rebuilt, report = PERebuilder.rebuild(pe)
        self.assertTrue(report.is_repaired)
        self.assertTrue(report.cor20_recovered)
        clr_rva_after = struct.unpack_from("<I", rebuilt, cor20_dir_offset)[0]
        clr_size_after = struct.unpack_from("<I", rebuilt, cor20_dir_offset + 4)[0]
        self.assertEqual(clr_rva_after, 0x2050)
        self.assertEqual(clr_size_after, 72)

    def test_rebuild_bounds_check_truncated_input(self):
        truncated = b"MZ" + b"\x00" * 20
        rebuilt, report = PERebuilder.rebuild(truncated)
        self.assertFalse(report.is_repaired)
        self.assertEqual(rebuilt, truncated)

    def test_core_integration_rebuild_pe_file(self):
        input_path = os.path.join(self.temp_dir, "damaged.exe")
        output_path = os.path.join(self.temp_dir, "fixed.exe")

        damaged = bytearray(create_synthetic_pe())
        damaged[0:2] = b"\x00\x00"  # Destroy MZ
        with open(input_path, "wb") as f:
            f.write(damaged)

        report = DotNetPackerCore.rebuild_pe(input_path, output_path)
        self.assertTrue(report.is_repaired)
        self.assertTrue(os.path.exists(output_path))
        with open(output_path, "rb") as f:
            content = f.read()
        self.assertEqual(content[:2], b"MZ")

    def test_core_integration_analyze_file_diagnostics(self):
        pe_path = os.path.join(self.temp_dir, "sample.exe")
        with open(pe_path, "wb") as f:
            f.write(create_synthetic_pe())

        analysis = DotNetPackerCore.analyze_file(pe_path)
        self.assertIn("pe_rebuilder", analysis)
        self.assertTrue(analysis["pe_rebuilder"]["is_valid_pe"])
        self.assertFalse(analysis["pe_rebuilder"]["repair_recommended"])

    def test_cli_rebuild_flag_execution(self):
        input_path = os.path.join(self.temp_dir, "cli_damaged.exe")
        out_path = os.path.join(self.temp_dir, "cli_fixed.exe")
        damaged = bytearray(create_synthetic_pe())
        damaged[0:2] = b"\x00\x00"
        with open(input_path, "wb") as f:
            f.write(damaged)

        code = cli_main([input_path, "--rebuild", "--rebuild-out", out_path])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_path))
        with open(out_path, "rb") as f:
            self.assertEqual(f.read()[:2], b"MZ")


if __name__ == "__main__":
    unittest.main()
