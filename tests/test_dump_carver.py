"""
Unit and Integration Tests for Kernel Memory Dump Carving and Residual CIL Metadata Reconstructor.
Engineered & Audited by Maya Thorne.
"""

import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.dump_carver import (
    AssemblyReconstructor,
    BSJBCarver,
    CarverAnomalyFlag,
    CarvedAssembly,
    CarvedMethod,
    CarvedString,
    CILMethodHeaderFormat,
    DumpCarverResult,
    DumpCarverTelemetry,
    DumpFormat,
    KernelDumpCarver,
    MemoryRange,
    MethodCarver,
    MinidumpParser,
    SecurityError,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)


class TestDumpCarverModelsAndSecurity(unittest.TestCase):
    """Tests data models, serialization, and security primitives."""

    def test_enums_and_dataclasses(self):
        self.assertEqual(DumpFormat.MINIDUMP_MDMP.value, "minidump_mdmp")
        self.assertEqual(DumpFormat.KERNEL_CRASH_DUMP.value, "kernel_crash_dump")
        self.assertEqual(CILMethodHeaderFormat.TINY.value, "tiny")
        self.assertEqual(CILMethodHeaderFormat.FAT.value, "fat")

        mr = MemoryRange(start_va=0x10000000, size=4096, file_offset=0x200)
        d_mr = mr.to_dict()
        self.assertEqual(d_mr["size"], 4096)
        self.assertIn("start_va", d_mr)

        cs = CarvedString(heap="#US", offset=10, value="ForensicSecret", length=14)
        self.assertEqual(cs.to_dict()["value"], "ForensicSecret")

        cm = CarvedMethod(
            token=0x06000001,
            offset=100,
            format=CILMethodHeaderFormat.TINY,
            max_stack=8,
            code_size=2,
            local_sig_tok=0,
            bytecode_hex="172A",
            entropy=1.0,
            instructions_count=2,
            has_valid_termination=True,
        )
        d_cm = cm.to_dict()
        self.assertEqual(d_cm["token"], "0x6000001")
        self.assertEqual(d_cm["format"], "tiny")

    def test_safe_path_security(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            real_tmp = os.path.realpath(tmp_dir)
            valid = safe_path(tmp_dir, "clean/artifact.exe")
            self.assertTrue(valid.startswith(real_tmp))

            with self.assertRaises(SecurityError):
                safe_path(tmp_dir, "../../escaped.exe")

            with self.assertRaises(SecurityError):
                safe_path(tmp_dir, "sub/../../../etc/passwd")

    def test_zeroize_buffer(self):
        buf = bytearray(b"SENSITIVE_KEY_MATERIAL")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(b"SENSITIVE_KEY_MATERIAL")))

    def test_calculate_entropy(self):
        self.assertEqual(calculate_entropy(b""), 0.0)
        self.assertEqual(calculate_entropy(b"\x00" * 100), 0.0)
        all_bytes = bytes(range(256))
        self.assertAlmostEqual(calculate_entropy(all_bytes), 8.0, places=3)


class TestMinidumpParser(unittest.TestCase):
    """Tests Windows Minidump (MDMP) parser and memory stream extraction."""

    def test_identify_format(self):
        self.assertEqual(MinidumpParser.identify_format(b""), DumpFormat.CORRUPTED_OR_UNKNOWN)
        self.assertEqual(MinidumpParser.identify_format(b"MDMP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DumpFormat.MINIDUMP_MDMP)
        self.assertEqual(MinidumpParser.identify_format(b"PAGE_DUMP_HEADER_123456789"), DumpFormat.KERNEL_CRASH_DUMP)
        self.assertEqual(MinidumpParser.identify_format(b"RANDOM_RAW_MEMORY_DATA_HERE"), DumpFormat.RAW_MEMORY_BLOCK)

    def test_parse_synthetic_minidump(self):
        # Create minimal synthetic MDMP:
        # Header (32 bytes):
        #   0x00: "MDMP"
        #   0x04: Version (0x0000A793)
        #   0x08: NumberOfStreams (2)
        #   0x0C: StreamDirectoryRva (32)
        #   0x10: CheckSum, TimeDateStamp, Flags
        # Directory (2 * 12 = 24 bytes, offset 32):
        #   Entry 0: SystemInfoStream (type 7), size 16, rva 56
        #   Entry 1: MemoryListStream (type 5), size 20, rva 72
        # SystemInfo payload (16 bytes, offset 56): arch=9 (x64)
        # MemoryList payload (20 bytes, offset 72):
        #   NumberOfMemoryRanges (1)
        #   Descriptor (16 bytes): StartOfMemoryRange=0x00400000, DataSize=64, Rva=92
        # Memory payload (64 bytes, offset 92)
        hdr = bytearray(156)
        hdr[0:4] = b"MDMP"
        struct.pack_into("<IIII", hdr, 4, 0xA793, 2, 32, 0)

        # Directory Entry 0: SystemInfo
        struct.pack_into("<III", hdr, 32, 7, 16, 56)
        # Directory Entry 1: MemoryList
        struct.pack_into("<III", hdr, 44, 5, 20, 72)

        # SystemInfo payload
        struct.pack_into("<H", hdr, 56, 9)  # x64

        # MemoryList payload: 1 range
        struct.pack_into("<I", hdr, 72, 1)  # 1 range
        struct.pack_into("<QII", hdr, 76, 0x00400000, 64, 92)

        # Memory payload at 92: some bytes
        hdr[92:156] = b"\x90" * 64

        ranges, modules, sys_info = MinidumpParser.parse_minidump(bytes(hdr))
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0].start_va, 0x00400000)
        self.assertEqual(ranges[0].size, 64)
        self.assertEqual(ranges[0].file_offset, 92)
        self.assertEqual(sys_info.get("processor_architecture"), "x64")

    def test_parse_memory64_list_stream(self):
        # Header with Memory64ListStream (type 9)
        hdr = bytearray(128)
        hdr[0:4] = b"MDMP"
        struct.pack_into("<IIII", hdr, 4, 0xA793, 1, 32, 0)
        # Entry: Memory64ListStream, size 32, rva 44
        struct.pack_into("<III", hdr, 32, 9, 32, 44)

        # Memory64 payload: NumberOfRanges=1, BaseRva=76
        struct.pack_into("<QQ", hdr, 44, 1, 76)
        # Descriptor: StartOfMemoryRange=0x10000000, DataSize=32
        struct.pack_into("<QQ", hdr, 60, 0x10000000, 32)
        hdr[76:108] = b"A" * 32

        ranges, _, _ = MinidumpParser.parse_minidump(bytes(hdr))
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0].start_va, 0x10000000)
        self.assertEqual(ranges[0].size, 32)
        self.assertEqual(ranges[0].file_offset, 76)

    def test_extract_linear_ranges(self):
        data = b"\x00" * 1024
        ranges = MinidumpParser.extract_linear_ranges(data)
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0].size, 1024)


class TestBSJBCarver(unittest.TestCase):
    """Tests ECMA-335 BSJB signature and metadata stream carving."""

    @staticmethod
    def _create_synthetic_bsjb() -> Tuple[bytes, int]:
        """Creates valid BSJB metadata buffer with #Strings, #US, and #~ streams."""
        buf = bytearray(1024)
        bsjb_off = 32

        # 1. Header: "BSJB" + Major(1) + Minor(1) + Reserved(0) + VerLen(12)
        ver_str = b"v4.0.30319\x00\x00"
        struct.pack_into("<4sHHII", buf, bsjb_off, b"BSJB", 1, 1, 0, len(ver_str))
        buf[bsjb_off + 16 : bsjb_off + 16 + len(ver_str)] = ver_str

        after_ver = bsjb_off + 16 + len(ver_str)
        # Flags(0), NumStreams(3)
        struct.pack_into("<HH", buf, after_ver, 0, 3)

        stream_desc_off = after_ver + 4
        # Stream 0: #Strings (rel_offset 128 from BSJB, size 64)
        struct.pack_into("<II", buf, stream_desc_off, 128, 64)
        buf[stream_desc_off + 8 : stream_desc_off + 20] = b"#Strings\x00\x00\x00\x00"  # 12 bytes
        stream_desc_off += 20

        # Stream 1: #US (rel_offset 192 from BSJB, size 64)
        struct.pack_into("<II", buf, stream_desc_off, 192, 64)
        buf[stream_desc_off + 8 : stream_desc_off + 12] = b"#US\x00"  # 4 bytes
        stream_desc_off += 12

        # Stream 2: #~ (rel_offset 256 from BSJB, size 64)
        struct.pack_into("<II", buf, stream_desc_off, 256, 64)
        buf[stream_desc_off + 8 : stream_desc_off + 12] = b"#~\x00\x00"  # 4 bytes

        # Populate #Strings at bsjb_off + 128:
        # 0x00 is empty string, then "TestModule\0", "EntryPointMethod\0"
        str_start = bsjb_off + 128
        buf[str_start] = 0
        buf[str_start + 1 : str_start + 12] = b"TestModule\x00"
        buf[str_start + 12 : str_start + 29] = b"EntryPointMethod\x00"

        # Populate #US at bsjb_off + 192:
        # 0x00, then compressed len (5 chars = 10 bytes + 1 flag byte = 11: 0x0B)
        # UTF-16LE for "Hello" (10 bytes) + flag 0x00
        us_start = bsjb_off + 192
        buf[us_start] = 0
        buf[us_start + 1] = 11  # length = 11 bytes
        hello_utf16 = "Hello".encode("utf-16le")
        buf[us_start + 2 : us_start + 2 + len(hello_utf16)] = hello_utf16
        buf[us_start + 2 + len(hello_utf16)] = 0  # flag byte

        # Populate #~ at bsjb_off + 256:
        # Reserved(0), Major(2), Minor(0), HeapSizes(0), Reserved(1), Valid mask, Sorted mask
        table_start = bsjb_off + 256
        # Set bits 0 (Module), 2 (TypeDef), 6 (MethodDef), 0x20 (Assembly)
        valid_mask = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 32)
        struct.pack_into("<IBBBBQQ", buf, table_start, 0, 2, 0, 0, 1, valid_mask, 0)
        # Table row counts: 4 uint32s
        struct.pack_into("<IIII", buf, table_start + 24, 1, 3, 5, 1)

        return bytes(buf), bsjb_off

    def test_scan_and_parse_bsjb(self):
        data, bsjb_off = self._create_synthetic_bsjb()
        roots = BSJBCarver.scan_bsjb_roots(data)
        self.assertIn(bsjb_off, roots)

        info = BSJBCarver.parse_bsjb_header(data, bsjb_off)
        self.assertIsNotNone(info)
        self.assertEqual(info["version"], "v4.0.30319")
        self.assertEqual(info["streams_count"], 3)
        self.assertIn("#Strings", info["streams"])
        self.assertIn("#US", info["streams"])
        self.assertIn("#~", info["streams"])

    def test_extract_strings_and_tables(self):
        data, bsjb_off = self._create_synthetic_bsjb()
        info = BSJBCarver.parse_bsjb_header(data, bsjb_off)

        us_desc = info["streams"]["#US"]
        us_strings = BSJBCarver.extract_user_strings(data, us_desc["offset"], us_desc["size"])
        self.assertTrue(any(s.value == "Hello" for s in us_strings))

        str_desc = info["streams"]["#Strings"]
        id_strings = BSJBCarver.extract_identifier_strings(data, str_desc["offset"], str_desc["size"])
        vals = [s.value for s in id_strings]
        self.assertIn("TestModule", vals)
        self.assertIn("EntryPointMethod", vals)

        table_desc = info["streams"]["#~"]
        tables = BSJBCarver.parse_metadata_tables(data, table_desc["offset"], table_desc["size"])
        row_counts = tables["table_row_counts"]
        self.assertEqual(row_counts.get("Module"), 1)
        self.assertEqual(row_counts.get("TypeDef"), 3)
        self.assertEqual(row_counts.get("MethodDef"), 5)
        self.assertEqual(row_counts.get("Assembly"), 1)


class TestMethodCarver(unittest.TestCase):
    """Tests residual CIL method body identification and validation."""

    def test_carve_tiny_method(self):
        # Tiny header: lower 2 bits = 0x02. Code size = 2 (byte = (2 << 2) | 0x02 = 0x0A)
        # Bytecode: 0x17 (ldc.i4.1), 0x2A (ret)
        raw_method = bytes([0x0A, 0x17, 0x2A])
        data = b"\x00" * 16 + raw_method + b"\x00" * 16

        methods = MethodCarver.scan_methods(data)
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].format, CILMethodHeaderFormat.TINY)
        self.assertEqual(methods[0].code_size, 2)
        self.assertEqual(methods[0].bytecode_hex, "172A")
        self.assertTrue(methods[0].has_valid_termination)

    def test_carve_fat_method(self):
        # Fat header (12 bytes, aligned to 4):
        # Flags_and_size: (3 << 12) | 0x0003 = 0x3003
        # MaxStack: 8, CodeSize: 4, LocalSigTok: 0
        # Bytecode: 0x00, 0x16, 0x26, 0x2A (nop, ldc.i4.0, pop, ret)
        hdr = struct.pack("<HHII", 0x3003, 8, 4, 0)
        bytecode = b"\x00\x16\x26\x2A"
        data = b"\x00" * 16 + hdr + bytecode + b"\x00" * 16

        methods = MethodCarver.scan_methods(data)
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].format, CILMethodHeaderFormat.FAT)
        self.assertEqual(methods[0].code_size, 4)
        self.assertEqual(methods[0].bytecode_hex, "0016262A")
        self.assertTrue(methods[0].has_valid_termination)

    def test_reject_invalid_code(self):
        # All zeroes or random non-CIL bytes
        data = b"\xFF\xFF\xFF\xFF" * 16
        methods = MethodCarver.scan_methods(data)
        self.assertEqual(len(methods), 0)


class TestAssemblyReconstructor(unittest.TestCase):
    """Tests PE container synthesis and memory layout unmapping."""

    def test_synthesize_pe_wrapper(self):
        data, bsjb_off = TestBSJBCarver._create_synthetic_bsjb()
        info = BSJBCarver.parse_bsjb_header(data, bsjb_off)

        methods = [
            CarvedMethod(
                token=0x06000001,
                offset=0,
                format=CILMethodHeaderFormat.TINY,
                max_stack=8,
                code_size=2,
                local_sig_tok=0,
                bytecode_hex="172A",
                entropy=1.0,
                instructions_count=2,
                has_valid_termination=True,
            )
        ]

        pe_bytes = AssemblyReconstructor.synthesize_pe_wrapper(data, bsjb_off, info, methods)
        self.assertIsNotNone(pe_bytes)
        self.assertTrue(pe_bytes.startswith(b"MZ"))

        # Verify PE headers
        pe_ptr = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        self.assertEqual(pe_bytes[pe_ptr : pe_ptr + 4], b"PE\x00\x00")

        # Verify CLR header data directory
        opt_hdr = pe_ptr + 24
        clr_dir_rva, clr_dir_sz = struct.unpack_from("<II", pe_bytes, opt_hdr + 96 + (14 * 8))
        self.assertGreater(clr_dir_rva, 0)
        self.assertEqual(clr_dir_sz, 72)

        # Verify reconstruct_from_memory facade
        carved_asm = AssemblyReconstructor.reconstruct_from_memory(data, bsjb_off, info, methods)
        self.assertIsNotNone(carved_asm)
        self.assertTrue(carved_asm.is_pe_valid)
        self.assertTrue(carved_asm.is_reconstructed)


class TestKernelDumpCarverAnalyzer(unittest.TestCase):
    """End-to-end tests for KernelDumpCarver, Core integration, and CLI."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_dump_carver_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_end_to_end_analyze_and_export(self):
        data, bsjb_off = TestBSJBCarver._create_synthetic_bsjb()
        dmp_path = os.path.join(self.temp_dir, "crash_sample.dmp")
        with open(dmp_path, "wb") as f:
            f.write(data)

        # 1. Run KernelDumpCarver.analyze_file
        res = KernelDumpCarver.analyze_file(dmp_path)
        self.assertIsInstance(res, DumpCarverResult)
        self.assertGreater(res.telemetry.bsjb_roots_found, 0)
        self.assertGreater(len(res.carved_strings), 0)

        # 2. Run export_to_directory
        export_out = os.path.join(self.temp_dir, "export_carved")
        exp_summary = KernelDumpCarver.export_to_directory(res, export_out)
        self.assertTrue(os.path.exists(os.path.join(export_out, "summary.json")))
        self.assertTrue(os.path.exists(os.path.join(export_out, "extracted_strings.txt")))
        self.assertGreaterEqual(exp_summary["strings_exported"], 1)

        # 3. Test DotNetPackerCore integration
        core_res = DotNetPackerCore.carve_dump(dmp_path)
        self.assertEqual(core_res.telemetry.bsjb_roots_found, res.telemetry.bsjb_roots_found)

        core_exp = DotNetPackerCore.export_carved_dump(
            dmp_path, output_dir=os.path.join(self.temp_dir, "core_export")
        )
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "core_export", "summary.json")))

    def test_cli_execution(self):
        data, bsjb_off = TestBSJBCarver._create_synthetic_bsjb()
        dmp_path = os.path.join(self.temp_dir, "test_target.dmp")
        with open(dmp_path, "wb") as f:
            f.write(data)

        out_dir = os.path.join(self.temp_dir, "cli_dump_out")
        code = main([
            dmp_path,
            "--dump-carver",
            "--dump-extract-methods",
            "--dump-out",
            out_dir,
            "--format",
            "json",
        ])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "summary.json")))


if __name__ == "__main__":
    unittest.main()
