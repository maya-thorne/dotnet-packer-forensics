"""
Unit tests for Costura.Fody embedded assembly unpacking and resource forensics.
"""

import os
import shutil
import struct
import tempfile
import unittest
import zlib

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.costura import CosturaUnpacker


def create_minimal_pe_with_resources(resource_entries: list) -> bytes:
    """
    Helper to synthesize a minimal PE .NET assembly with CLI header,
    Cor20Header, Metadata with #Strings, and Resources data.
    resource_entries: list of tuples (resource_name: str, resource_bytes: bytes, is_compressed: bool)
    """
    # 1. Prepare resource data block
    res_bytes_list = []
    names_list = []
    for name, raw_bytes, is_comp in resource_entries:
        names_list.append(name)
        if is_comp:
            # Compress using raw deflate (RFC 1951)
            comp_data = zlib.compress(raw_bytes)[2:-4]  # strip zlib header and adler32
            # Prepend 4-byte little-endian length of compressed chunk
            res_chunk = struct.pack("<I", len(comp_data)) + comp_data
        else:
            res_chunk = struct.pack("<I", len(raw_bytes)) + raw_bytes
        res_bytes_list.append(res_chunk)

    all_resources_blob = b"".join(res_bytes_list)

    # 2. Prepare #Strings stream and metadata
    strings_blob = b"\x00" + b"\x00".join(n.encode("utf-8") for n in names_list) + b"\x00"
    # Metadata Root (BSJB)
    v_str = b"v4.0.30319\x00\x00"  # 12 bytes aligned
    stream_name = b"#Strings\x00\x00\x00\x00"  # 12 bytes
    stream_header = struct.pack("<II", 32 + 8 + len(stream_name), len(strings_blob)) + stream_name
    # BSJB Header: Magic (4) + Major(2) + Minor(2) + Reserved(4) + Length(4) + Version + Flags(2) + StreamsCount(2)
    meta_hdr = b"BSJB\x01\x00\x01\x00\x00\x00\x00\x00" + struct.pack("<I", len(v_str)) + v_str + struct.pack("<HH", 0, 1)
    meta_blob = meta_hdr + stream_header + strings_blob

    # 3. Construct PE Sections:
    # Section .text at RVA 0x2000: contains Cor20Header and Metadata
    # Section .rsrc at RVA 0x4000: contains Resources
    sec1_vaddr = 0x2000
    sec1_rptr = 0x200
    sec2_vaddr = 0x4000
    sec2_rptr = 0x200 + 0x600  # 0x800

    # Cor20Header (72 bytes):
    # cb(4), Major(2), Minor(2), MetaData(RVA, Size)(8), Flags(4), EntryPoint(4), Resources(RVA, Size)(8)...
    cor20_rva = sec1_vaddr
    meta_rva = sec1_vaddr + 0x80
    res_rva = sec2_vaddr

    cor20_hdr = (
        struct.pack("<IHH", 72, 2, 5)
        + struct.pack("<II", meta_rva, len(meta_blob))
        + struct.pack("<II", 1, 0)
        + struct.pack("<II", res_rva, len(all_resources_blob))
        + (b"\x00" * 40)
    )

    sec1_data = cor20_hdr.ljust(0x80, b"\x00") + meta_blob
    sec1_data = sec1_data.ljust(0x600, b"\x00")

    sec2_data = all_resources_blob.ljust(0x400, b"\x00")

    # DOS Header
    dos_hdr = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x80) + (b"\x00" * 64)

    # PE Signature + File Header
    pe_sig = b"PE\x00\x00"
    file_hdr = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0xE0, 0x0102)

    # Optional Header (PE32: 224 bytes = 0xE0)
    # Magic=0x10B, DataDirectory[14] is CLI Header at offset 208
    opt_hdr_start = struct.pack("<HBBIIIIII", 0x10B, 14, 0, len(sec1_data), 0, 0, 0x2000, 0x2000, 0)
    opt_hdr_middle = struct.pack("<IIIHHHHHHIIIIHHIIIIII", 0x400000, 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, 0x6000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    # Data directories (16 entries * 8 bytes = 128 bytes)
    data_dirs = [struct.pack("<II", 0, 0) for _ in range(16)]
    # Set CLI Header at index 14
    data_dirs[14] = struct.pack("<II", cor20_rva, len(cor20_hdr))
    opt_hdr = (opt_hdr_start + opt_hdr_middle + b"".join(data_dirs))[:0xE0]

    # Section Headers (40 bytes each)
    # Name(8), VSize(4), VAddr(4), RSize(4), RPtr(4), ...
    sec1_hdr = b".text\x00\x00\x00" + struct.pack("<IIII", len(sec1_data), sec1_vaddr, len(sec1_data), sec1_rptr) + (b"\x00" * 16)
    sec2_hdr = b".rsrc\x00\x00\x00" + struct.pack("<IIII", len(sec2_data), sec2_vaddr, len(sec2_data), sec2_rptr) + (b"\x00" * 16)

    headers = (dos_hdr[:0x80] + pe_sig + file_hdr + opt_hdr + sec1_hdr + sec2_hdr).ljust(0x200, b"\x00")
    return headers + sec1_data + sec2_data


class TestCosturaUnpacker(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_costura_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detect_costura_signatures(self):
        sample_data = b"Some random prefix costura.newtonsoft.json.dll.compressed and costura32.sqlite.dll and Fody"
        detection = CosturaUnpacker.detect(sample_data)
        self.assertTrue(detection["is_costura"])
        self.assertEqual(detection["confidence"], "HIGH")
        self.assertIn("costura.newtonsoft.json.dll.compressed", detection["resource_candidates"])

    def test_decompress_payload_rfc1951(self):
        plain_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00PE\x00\x00MockAssemblyData"
        # Standard raw deflate
        raw_deflate = zlib.compress(plain_payload)[2:-4]
        decompressed = CosturaUnpacker.decompress_payload(raw_deflate, is_compressed=True)
        self.assertEqual(decompressed, plain_payload)

    def test_decompress_payload_length_prefixed(self):
        plain_payload = b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00LengthPrefixedRawDeflateBytes"
        raw_deflate = zlib.compress(plain_payload)[2:-4]
        # Prepend 4-byte little-endian length
        prefixed = struct.pack("<I", len(plain_payload)) + raw_deflate
        decompressed = CosturaUnpacker.decompress_payload(prefixed, is_compressed=True)
        self.assertEqual(decompressed, plain_payload)

    def test_filename_sanitization_and_traversal_defense(self):
        # 1. Normal Costura DLL
        n1 = CosturaUnpacker.sanitize_filename("costura.newtonsoft.json.dll.compressed")
        self.assertEqual(n1, "newtonsoft.json.dll")

        # 2. Architecture-specific native DLLs
        n2 = CosturaUnpacker.sanitize_filename("costura32.sqlite.interop.dll.compressed")
        self.assertEqual(n2, "costura32_sqlite.interop.dll")

        n3 = CosturaUnpacker.sanitize_filename("costura64.sqlite.interop.dll.compressed")
        self.assertEqual(n3, "costura64_sqlite.interop.dll")

        # 3. Path traversal attack attempt
        n4 = CosturaUnpacker.sanitize_filename("../../etc/passwd.dll.compressed")
        self.assertEqual(n4, "passwd.dll")

        n5 = CosturaUnpacker.sanitize_filename("C:\\Windows\\System32\\cmd.exe.dll")
        self.assertEqual(n5, "cmd.exe.dll")

    def test_synthetic_pe_resource_extraction(self):
        # Construct synthetic PE DLL payload
        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\x90" * 100)
        inner_pdb = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00PDBPayloadSymbols"

        entries = [
            ("costura.mycustomplugin.dll.compressed", inner_pe, True),
            ("costura.mycustomplugin.pdb.compressed", inner_pdb, True),
        ]

        full_exe_bytes = create_minimal_pe_with_resources(entries)

        # Run CosturaUnpacker.unpack
        unpacked = CosturaUnpacker.unpack(full_exe_bytes)
        self.assertEqual(len(unpacked), 2)

        dll_item = next(p for p in unpacked if p["output_filename"] == "mycustomplugin.dll")
        self.assertEqual(dll_item["payload_bytes"], inner_pe)
        self.assertTrue(dll_item["is_pe"])
        self.assertFalse(dll_item["is_pdb"])

        pdb_item = next(p for p in unpacked if p["output_filename"] == "mycustomplugin.pdb")
        self.assertEqual(pdb_item["payload_bytes"], inner_pdb)
        self.assertFalse(pdb_item["is_pe"])
        self.assertTrue(pdb_item["is_pdb"])

        # Test extraction to directory
        out_dir = os.path.join(self.test_dir, "unpacked_costura")
        written = CosturaUnpacker.unpack_to_directory(full_exe_bytes, out_dir)
        self.assertEqual(len(written), 2)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "mycustomplugin.dll")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "mycustomplugin.pdb")))

    def test_core_and_cli_costura_integration(self):
        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\xCC" * 80)
        entries = [
            ("costura.utility.core.dll.compressed", inner_pe, True)
        ]
        exe_bytes = create_minimal_pe_with_resources(entries)
        sample_path = os.path.join(self.test_dir, "sample_costura.exe")
        with open(sample_path, "wb") as f:
            f.write(exe_bytes)

        # Test DotNetPackerCore.analyze_file
        report = DotNetPackerCore.analyze_file(sample_path)
        self.assertTrue(report["costura"]["detected"])
        self.assertEqual(report["costura"]["payloads_count"], 1)
        self.assertEqual(report["costura"]["payloads"][0]["output_filename"], "utility.core.dll")

        # Test CLI execution
        out_extract_dir = os.path.join(self.test_dir, "cli_extracted")
        ret = main([sample_path, "-d", out_extract_dir])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(out_extract_dir, "utility.core.dll")))

    def test_uncompressed_resource_extraction(self):
        inner_dll = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00UncompressedPayload"
        entries = [
            ("costura.uncompressed.assembly.dll", inner_dll, False)
        ]
        exe_bytes = create_minimal_pe_with_resources(entries)
        unpacked = CosturaUnpacker.unpack(exe_bytes)
        self.assertEqual(len(unpacked), 1)
        self.assertEqual(unpacked[0]["output_filename"], "uncompressed.assembly.dll")
        self.assertEqual(unpacked[0]["payload_bytes"], inner_dll)

    def test_heuristic_carving_fallback(self):
        # Corrupted CLI binary with Costura markers and embedded deflate stream
        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00CarvedRawPEPayload"
        raw_comp = zlib.compress(inner_pe)[2:-4]
        # Build raw mock buffer without CLI tables
        mock_raw = (
            b"MZ" + (b"\x00" * 100)
            + b"costura.carved.module.dll.compressed"
            + (b"\x00" * 8)
            + struct.pack("<I", len(raw_comp))
            + raw_comp
            + (b"\x00" * 100)
        )
        unpacked = CosturaUnpacker.unpack(mock_raw)
        self.assertGreaterEqual(len(unpacked), 1)
        match = next(p for p in unpacked if p["output_filename"] == "carved.module.dll")
        self.assertEqual(match["payload_bytes"], inner_pe)
        self.assertTrue(match["is_pe"])

    def test_core_unpack_to_file_single_costura(self):
        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\xAA" * 50)
        entries = [
            ("costura.standalone.dll.compressed", inner_pe, True)
        ]
        exe_bytes = create_minimal_pe_with_resources(entries)
        sample_path = os.path.join(self.test_dir, "single_costura.exe")
        with open(sample_path, "wb") as f:
            f.write(exe_bytes)

        out_file = os.path.join(self.test_dir, "extracted_standalone.dll")
        success = DotNetPackerCore.unpack_to_file(sample_path, out_file)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(out_file))
        with open(out_file, "rb") as f:
            self.assertEqual(f.read(), inner_pe)


if __name__ == "__main__":
    unittest.main()

