"""
Unit tests for ConfuserEx modular protector unpacking, string decryption, and resource forensics.
"""

import gzip
import io
import json
import os
import shutil
import struct
import tempfile
import unittest
import zlib

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.confuserex import ConfuserExUnpacker, SecurityError


def create_confuser_synthetic_pe(resource_chunks, markers: list = None) -> bytes:
    """
    Synthesizes a minimal PE .NET assembly with CLI header, Cor20Header,
    Metadata containing ConfuserEx markers and strings, and Resources data.
    """
    if markers is None:
        markers = ["ConfusedByAttribute", "ConfuserEx v1.0.0", "AntiDump", "AntiTamper", "Constants"]

    if isinstance(resource_chunks, bytes):
        resource_chunks = [resource_chunks]

    res_bytes_list = []
    for chunk in resource_chunks:
        res_bytes_list.append(struct.pack("<I", len(chunk)) + chunk)
    all_resources_blob = b"".join(res_bytes_list)

    # 2. Prepare #Strings stream and metadata
    strings_blob = b"\x00" + b"\x00".join(m.encode("utf-8") for m in markers) + b"\x00"
    v_str = b"v4.0.30319\x00\x00"  # 12 bytes aligned
    stream_name = b"#Strings\x00\x00\x00\x00"  # 12 bytes
    stream_header = struct.pack("<II", 32 + 8 + len(stream_name), len(strings_blob)) + stream_name
    meta_hdr = b"BSJB\x01\x00\x01\x00\x00\x00\x00\x00" + struct.pack("<I", len(v_str)) + v_str + struct.pack("<HH", 0, 1)
    meta_blob = meta_hdr + stream_header + strings_blob

    # 3. PE Sections: .text (Cor20Header + Metadata) and .rsrc (Resources)
    sec1_vaddr = 0x2000
    sec1_rptr = 0x200
    sec2_vaddr = 0x4000
    sec2_rptr = 0x200 + 0x600  # 0x800

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
    opt_hdr_start = struct.pack("<HBBIIIIII", 0x10B, 14, 0, len(sec1_data), 0, 0, 0x2000, 0x2000, 0)
    opt_hdr_middle = struct.pack("<IIIHHHHHHIIIIHHIIIIII", 0x400000, 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, 0x6000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    data_dirs = [struct.pack("<II", 0, 0) for _ in range(16)]
    data_dirs[14] = struct.pack("<II", cor20_rva, len(cor20_hdr))
    opt_hdr = (opt_hdr_start + opt_hdr_middle + b"".join(data_dirs))[:0xE0]

    sec1_hdr = b".text\x00\x00\x00" + struct.pack("<IIII", len(sec1_data), sec1_vaddr, len(sec1_data), sec1_rptr) + (b"\x00" * 16)
    sec2_hdr = b".rsrc\x00\x00\x00" + struct.pack("<IIII", len(sec2_data), sec2_vaddr, len(sec2_data), sec2_rptr) + (b"\x00" * 16)

    headers = (dos_hdr[:0x80] + pe_sig + file_hdr + opt_hdr + sec1_hdr + sec2_hdr).ljust(0x200, b"\x00")
    return headers + sec1_data + sec2_data


def build_confuser_catalog(entries: list) -> bytes:
    """
    Builds a ConfuserEx custom catalog buffer:
    [count: uint32] ([name_len: uint32][name: utf-8][data_len: uint32][data: compressed_or_raw])*
    entries: list of tuples (name: str, raw_payload: bytes, compress_format: str)
    """
    chunks = [struct.pack("<I", len(entries))]
    for name, payload, comp in entries:
        if comp == "deflate":
            comp_bytes = zlib.compress(payload)[2:-4]  # RFC 1951 raw deflate
        elif comp == "zlib":
            comp_bytes = zlib.compress(payload)
        elif comp == "gzip":
            comp_bytes = gzip.compress(payload)
        else:
            comp_bytes = payload

        name_utf8 = name.encode("utf-8")
        chunks.append(struct.pack("<I", len(name_utf8)))
        chunks.append(name_utf8)
        chunks.append(struct.pack("<I", len(comp_bytes)))
        chunks.append(comp_bytes)
    return b"".join(chunks)


class TestConfuserExUnpacker(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_confuserex_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_detection_markers_and_protections(self):
        raw = b"MZ" + (b"\x00" * 20) + b"ConfusedByAttribute" + b"__AntiDump__" + b"AntiTamper" + b"Constants"
        result = ConfuserExUnpacker.detect(raw)
        self.assertTrue(result["is_confuserex"])
        self.assertEqual(result["confidence"], "HIGH")
        self.assertTrue(result["has_antidump"])
        self.assertTrue(result["has_antitamper"])
        self.assertTrue(result["has_constants"])
        self.assertIn("Anti-Dump", result["detected_protections"])
        self.assertIn("Anti-Tamper", result["detected_protections"])
        self.assertIn("Constants Encryption", result["detected_protections"])

    def test_detection_mangled_unicode_names(self):
        mangled = "NormalClass" + "\u200b\u200c\u200d\u202a\u202b\u202c\u202d\u202e\u2060\ufeff" * 2
        raw = mangled.encode("utf-8") + b"ConfuserEx"
        result = ConfuserExUnpacker.detect(raw)
        self.assertTrue(result["is_confuserex"])
        self.assertGreater(result["obfuscated_names_count"], 10)
        self.assertIn("Name Protection (Unicode Renamer)", result["detected_protections"])

    def test_detection_clean_binary(self):
        clean = b"MZ" + (b"\x00" * 200) + b"System.Console.WriteLine"
        result = ConfuserExUnpacker.detect(clean)
        self.assertFalse(result["is_confuserex"])
        self.assertEqual(result["confidence"], "NONE")
        self.assertEqual(len(result["detected_protections"]), 0)

    def test_xorshift32_keystream_cipher(self):
        seed = 0x1337BEEF
        length = 64
        stream1 = ConfuserExUnpacker.xorshift32_keystream(seed, length)
        stream2 = ConfuserExUnpacker.xorshift32_keystream(seed, length)
        self.assertEqual(len(stream1), length)
        self.assertEqual(stream1, stream2)

        plaintext = b"Secret forensic decryption payload text for ConfuserEx engine."
        encrypted = bytes(b ^ k for b, k in zip(plaintext, stream1[:len(plaintext)]))
        self.assertNotEqual(plaintext, encrypted)

        decrypted = bytes(b ^ k for b, k in zip(encrypted, stream1[:len(plaintext)]))
        self.assertEqual(plaintext, decrypted)

    def test_lcg_keystream_cipher(self):
        seed = 0xCAFEBABE
        length = 48
        stream = ConfuserExUnpacker.lcg_keystream(seed, length)
        self.assertEqual(len(stream), length)

        plaintext = b"Testing Linear Congruential Generator decryption"
        encrypted = bytes(b ^ k for b, k in zip(plaintext, stream[:len(plaintext)]))
        decrypted = bytes(b ^ k for b, k in zip(encrypted, stream[:len(plaintext)]))
        self.assertEqual(plaintext, decrypted)

    def test_derive_key_schedule_and_multibyte_xor(self):
        seed = 0x12345678
        key = ConfuserExUnpacker.derive_key_schedule(seed, key_len=16)
        self.assertEqual(len(key), 16)

        plaintext = b"Payload with multi-byte repeating key schedule forensics"
        encrypted = ConfuserExUnpacker.xor_crypt(plaintext, key)
        self.assertNotEqual(plaintext, encrypted)
        decrypted = ConfuserExUnpacker.xor_crypt(encrypted, key)
        self.assertEqual(plaintext, decrypted)

    def test_evaluate_plaintext_score(self):
        natural_text = b"This is a legitimate decrypted string table with connection strings and API keys."
        random_bytes = bytes([(i * 73 + 129) % 256 for i in range(256)])
        score_text = ConfuserExUnpacker.evaluate_plaintext_score(natural_text)
        score_random = ConfuserExUnpacker.evaluate_plaintext_score(random_bytes)
        self.assertGreater(score_text, 0.70)
        self.assertLess(score_random, 0.50)

    def test_parse_string_table_7bit_and_le32(self):
        s1 = "ApiKey_9876"
        chunk1 = bytes([len(s1)]) + s1.encode("utf-8")
        s2 = "SqlConnectionString"
        chunk2 = struct.pack("<I", len(s2)) + s2.encode("utf-8")
        chunk3 = struct.pack("<i", 42000)

        table = chunk1 + chunk2 + chunk3
        parsed = ConfuserExUnpacker.parse_string_table(table)
        self.assertIn(s1, parsed["strings"])
        self.assertIn(s2, parsed["strings"])
        self.assertTrue(any(c["type"] == "int32" for c in parsed["constants"]))

    def test_decrypt_constants_with_known_seed_xorshift(self):
        s1 = "https://internal.api.endpoint/v1/auth"
        s2 = "BearerToken_secret_key_abcdef123456"
        table = bytes([len(s1)]) + s1.encode("utf-8") + bytes([len(s2)]) + s2.encode("utf-8")

        seed = 0x5A5A5A5A
        keystream = ConfuserExUnpacker.xorshift32_keystream(seed, len(table))
        encrypted = bytes(b ^ k for b, k in zip(table, keystream))

        res = ConfuserExUnpacker.decrypt_constants(encrypted, seed=seed, mode="xorshift")
        self.assertTrue(res["success"])
        self.assertEqual(res["mode"], "xorshift")
        self.assertIn(s1, res["strings"])
        self.assertIn(s2, res["strings"])

    def test_decrypt_constants_with_known_seed_lcg(self):
        s1 = "DatabaseConnectionStringServer=127.0.0.1"
        table = bytes([len(s1)]) + s1.encode("utf-8")

        seed = 0x0000002A
        keystream = ConfuserExUnpacker.lcg_keystream(seed, len(table))
        encrypted = bytes(b ^ k for b, k in zip(table, keystream))

        res = ConfuserExUnpacker.decrypt_constants(encrypted, seed=seed, mode="lcg")
        self.assertTrue(res["success"])
        self.assertEqual(res["mode"], "lcg")
        self.assertIn(s1, res["strings"])

    def test_decrypt_constants_automatic_recovery_1byte_xor(self):
        s1 = "ConfuserEx_Decrypted_String_Constant_Alpha"
        s2 = "ConfuserEx_Decrypted_String_Constant_Beta"
        table = bytes([len(s1)]) + s1.encode("utf-8") + bytes([len(s2)]) + s2.encode("utf-8")

        xor_key = 0x7A
        encrypted = bytes(b ^ xor_key for b in table)

        res = ConfuserExUnpacker.decrypt_constants(encrypted, mode="auto")
        self.assertTrue(res["success"])
        self.assertEqual(res["recovered_key"], bytes([xor_key]))
        self.assertIn(s1, res["strings"])
        self.assertIn(s2, res["strings"])

    def test_decompress_payload_formats(self):
        original = b"This is a forensic decompression payload test buffer representing assembly IL bytes."

        # 1. Raw Deflate
        raw_deflate = zlib.compress(original)[2:-4]
        self.assertEqual(ConfuserExUnpacker.decompress_payload(raw_deflate), original)

        # 2. 4-byte LE length prefix + Deflate
        le_deflate = struct.pack("<I", len(original)) + raw_deflate
        self.assertEqual(ConfuserExUnpacker.decompress_payload(le_deflate), original)

        # 3. Standard Zlib
        std_zlib = zlib.compress(original)
        self.assertEqual(ConfuserExUnpacker.decompress_payload(std_zlib), original)

        # 4. Standard Gzip
        std_gzip = gzip.compress(original)
        self.assertEqual(ConfuserExUnpacker.decompress_payload(std_gzip), original)

        # 5. Raw fallback
        self.assertEqual(ConfuserExUnpacker.decompress_payload(original), original)

    def test_decompress_bomb_limit(self):
        # Valid payload within ceiling
        normal_data = b"SafeDecompressedContent" * 100
        comp = zlib.compress(normal_data)
        decomp = ConfuserExUnpacker.decompress_payload(comp)
        self.assertEqual(decomp, normal_data)

        # Enforce safety ceiling test
        original_limit = ConfuserExUnpacker.MAX_DECOMPRESSED_SIZE
        try:
            ConfuserExUnpacker.MAX_DECOMPRESSED_SIZE = 50
            bomb_payload = zlib.compress(b"A" * 1000)
            with self.assertRaises(ValueError):
                ConfuserExUnpacker.decompress_payload(bomb_payload)
        finally:
            ConfuserExUnpacker.MAX_DECOMPRESSED_SIZE = original_limit

    def test_parse_resource_catalog_confuser_format(self):
        mock_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\x11" * 100)
        mock_png = b"\x89PNG\r\n\x1a\n" + (b"\x22" * 50)
        mock_xml = b"<?xml version=\"1.0\"?><configuration></configuration>"

        entries = [
            ("CoreModule.dll", mock_pe, "deflate"),
            ("logo.png", mock_png, "zlib"),
            ("app.config", mock_xml, "raw"),
        ]

        catalog = build_confuser_catalog(entries)
        items = ConfuserExUnpacker.parse_resource_catalog(catalog)
        self.assertEqual(len(items), 3)

        pe_item = next(i for i in items if i["output_filename"] == "CoreModule.dll")
        self.assertTrue(pe_item["is_pe"])
        self.assertEqual(pe_item["resource_type"], "Managed Assembly (PE)")
        self.assertEqual(pe_item["payload_bytes"], mock_pe)

        png_item = next(i for i in items if i["output_filename"] == "logo.png")
        self.assertEqual(png_item["resource_type"], "PNG Image")
        self.assertEqual(png_item["payload_bytes"], mock_png)

        xml_item = next(i for i in items if i["output_filename"] == "app.config")
        self.assertEqual(xml_item["resource_type"], "XML Document / Configuration")
        self.assertEqual(xml_item["payload_bytes"], mock_xml)

    def test_synthetic_pe_cli_resource_extraction(self):
        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\x33" * 80)
        entries = [
            ("Confuser.Plugin.dll", inner_pe, "deflate")
        ]
        catalog = build_confuser_catalog(entries)
        pe_bytes = create_confuser_synthetic_pe(catalog)

        unpacked = ConfuserExUnpacker.unpack(pe_bytes)
        self.assertEqual(len(unpacked), 1)
        self.assertEqual(unpacked[0]["output_filename"], "Confuser.Plugin.dll")
        self.assertEqual(unpacked[0]["payload_bytes"], inner_pe)
        self.assertTrue(unpacked[0]["is_pe"])

    def test_heuristic_carving_fallback(self):
        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\x44" * 60)
        entries = [
            ("Carved.Resource.dll", inner_pe, "deflate")
        ]
        catalog = build_confuser_catalog(entries)
        mock_raw = (
            b"MZ" + (b"\x00" * 80)
            + b"Confuser.Runtime"
            + (b"\x00" * 4)
            + struct.pack("<I", len(catalog))
            + catalog
            + (b"\x00" * 80)
        )

        unpacked = ConfuserExUnpacker.unpack(mock_raw)
        self.assertGreaterEqual(len(unpacked), 1)
        match = next(p for p in unpacked if p["output_filename"] == "Carved.Resource.dll")
        self.assertEqual(match["payload_bytes"], inner_pe)

    def test_path_traversal_sanitization(self):
        malicious_names = [
            ("../../etc/passwd", "passwd"),
            ("..\\..\\Windows\\System32\\calc.exe", "calc.exe"),
            ("/var/root/.ssh/id_rsa", "id_rsa"),
            ("....//....//payload.dll", "payload.dll"),
        ]
        for bad_name, expected in malicious_names:
            sanitized = ConfuserExUnpacker.sanitize_filename(bad_name)
            self.assertEqual(sanitized, expected)

        entries = [
            ("safe_module.dll", b"MZ" + (b"\x00" * 60) + b"PE\x00\x00Test", "raw")
        ]
        catalog = build_confuser_catalog(entries)
        pe_bytes = create_confuser_synthetic_pe(catalog)

        out_dir = os.path.join(self.test_dir, "extracted")
        written = ConfuserExUnpacker.unpack_to_directory(pe_bytes, out_dir)
        self.assertEqual(len(written), 1)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "safe_module.dll")))

    def test_zeroize_memory_wiping(self):
        buf = bytearray(b"HighlySensitiveKeyBytesBuffer1234")
        self.assertNotEqual(buf, bytearray(len(buf)))
        ConfuserExUnpacker.zeroize(buf)
        self.assertEqual(buf, bytearray(len(buf)))

    def test_core_and_cli_integration(self):
        # 1. Create a synthetic ConfuserEx protected sample with both catalog and encrypted constants
        s1 = "ConfuserEx_Decrypted_String_001"
        s2 = "ConfuserEx_Decrypted_String_002"
        string_table = bytes([len(s1)]) + s1.encode("utf-8") + bytes([len(s2)]) + s2.encode("utf-8")

        xor_key = 0x55
        enc_table = bytes(b ^ xor_key for b in string_table)

        inner_pe = b"MZ" + (b"\x00" * 58) + struct.pack("<I", 0x40) + b"PE\x00\x00" + (b"\x77" * 40)
        entries = [
            ("EmbeddedPayload.dll", inner_pe, "deflate")
        ]
        catalog = build_confuser_catalog(entries)
        pe_bytes = create_confuser_synthetic_pe([catalog, enc_table])

        sample_path = os.path.join(self.test_dir, "sample_confuser.exe")
        with open(sample_path, "wb") as f:
            f.write(pe_bytes)

        # 2. Test DotNetPackerCore.analyze_file
        report = DotNetPackerCore.analyze_file(sample_path)
        self.assertTrue(report["confuserex"]["detected"])
        self.assertEqual(report["confuserex"]["confidence"], "HIGH")
        self.assertGreaterEqual(report["confuserex"]["resources_count"], 1)

        # 3. Test DotNetPackerCore.dump_strings
        strings = DotNetPackerCore.dump_strings(sample_path)
        self.assertIn(s1, strings)
        self.assertIn(s2, strings)

        # 4. Test DotNetPackerCore.unpack_to_dir
        extract_dir = os.path.join(self.test_dir, "extracted_res")
        written = DotNetPackerCore.unpack_to_dir(sample_path, extract_dir)
        self.assertGreaterEqual(len(written), 1)
        self.assertTrue(os.path.exists(os.path.join(extract_dir, "EmbeddedPayload.dll")))

        # 5. Test CLI with --dump-strings
        ret = main([sample_path, "--dump-strings"])
        self.assertEqual(ret, 0)

        # 6. Test CLI with --format json
        ret_json = main([sample_path, "--format", "json"])
        self.assertEqual(ret_json, 0)

        # 7. Test CLI with -d unpack-dir
        cli_dir = os.path.join(self.test_dir, "cli_dir")
        ret_dir = main([sample_path, "-d", cli_dir])
        self.assertEqual(ret_dir, 0)
        self.assertTrue(os.path.exists(os.path.join(cli_dir, "EmbeddedPayload.dll")))


if __name__ == "__main__":
    unittest.main()
