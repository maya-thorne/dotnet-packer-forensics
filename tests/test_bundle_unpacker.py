"""
Unit & Integration Tests for .NET Single-File Host (AppHost / Bundle) Extraction Engine.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import shutil
import struct
import tempfile
import unittest
import zlib

from dotnet_deobfuscator.bundle import (
    DOTNET_BUNDLE_MARKER,
    WARP_MAGIC,
    BundleDecompressor,
    BundleEntry,
    BundleExtractionResult,
    BundleFileType,
    BundleHeader,
    BundleHeaderParser,
    BundleMarkerScanner,
    BundleOptions,
    BundleTelemetry,
    BundleVersion,
    CompressionKind,
    SecurityError,
    SingleFileBundleEngine,
    SuperPackerKind,
    VirtualBundleVolume,
    calculate_entropy,
    read_7bit_encoded_int,
    safe_path,
    write_7bit_encoded_int,
    zeroize_buffer,
)
from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore


class TestBundleUnpacker(unittest.TestCase):
    """Comprehensive test harness for .NET Single-File Host and AppHost bundles."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_bundle_")

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_models_and_enums(self):
        """Verifies enum values and dictionary serialization for bundle models."""
        self.assertEqual(BundleFileType.ASSEMBLY.value, "assembly")
        self.assertEqual(BundleFileType.NATIVE_BINARY.value, "native_binary")
        self.assertEqual(BundleFileType.PDB_FILE.value, "pdb_file")
        self.assertEqual(BundleFileType.DEPS_JSON.value, "deps_json")
        self.assertEqual(BundleFileType.RUNTIME_CONFIG_JSON.value, "runtime_config_json")
        self.assertEqual(BundleVersion.V6_NET6_PLUS.value, "v6_net6_plus")
        self.assertEqual(SuperPackerKind.DOTNET_APPHOST.value, "dotnet_apphost")

        entry = BundleEntry(
            offset=100,
            size=200,
            compressed_size=150,
            file_type=BundleFileType.ASSEMBLY,
            relative_path="CoreLib.dll",
            sha256="abc123",
            entropy=5.6789,
            is_compressed=True,
            is_pe=True,
            is_dotnet=True,
        )
        d = entry.to_dict()
        self.assertEqual(d["offset"], 100)
        self.assertEqual(d["file_type"], "assembly")
        self.assertTrue(d["is_compressed"])

        hdr = BundleHeader(
            major_version=6,
            minor_version=0,
            file_count=1,
            bundle_id="guid-1234",
            entries=[entry],
        )
        hd = hdr.to_dict()
        self.assertEqual(hd["major_version"], 6)
        self.assertEqual(hd["entries_count"], 1)

    def test_02_security_safe_path(self):
        """Verifies safe_path sanitization and strict rejection of path traversal."""
        base = os.path.realpath(self.tmp_dir)
        p1 = safe_path("System.Private.CoreLib.dll", base)
        self.assertTrue(p1.startswith(base))
        self.assertTrue(p1.endswith("System.Private.CoreLib.dll"))

        p2 = safe_path("runtimes/win-x64/native/sqlite.dll", base)
        self.assertTrue(p2.startswith(base))

        # Traversal attempts must fail
        with self.assertRaises(SecurityError):
            safe_path("../../escaped.dll", base)

        with self.assertRaises(SecurityError):
            safe_path("/etc/shadow", base)

        with self.assertRaises(SecurityError):
            safe_path("C:\\Windows\\System32\\cmd.exe", base)

    def test_03_zeroize_and_entropy(self):
        """Tests cryptographic buffer wiping and Shannon entropy calculations."""
        buf = bytearray(b"SecretPayloadKeyBytes1234")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(b"SecretPayloadKeyBytes1234")))

        # Entropy tests
        self.assertEqual(calculate_entropy(b""), 0.0)
        zero_ent = calculate_entropy(b"\x00" * 100)
        self.assertEqual(zero_ent, 0.0)
        rand_bytes = bytes([i % 256 for i in range(256)])
        self.assertGreater(calculate_entropy(rand_bytes), 7.9)

    def test_04_7bit_encoded_int_roundtrip(self):
        """Verifies 7-bit encoded integer LEB128 serialization."""
        test_values = [0, 1, 127, 128, 255, 300, 16384, 65536, 1000000]
        for val in test_values:
            encoded = write_7bit_encoded_int(val)
            decoded, consumed = read_7bit_encoded_int(encoded, 0)
            self.assertEqual(val, decoded)
            self.assertEqual(len(encoded), consumed)

    def test_05_marker_scanner_detection(self):
        """Verifies detection of .NET bundle marker and third-party superpackers."""
        bundle_bytes = SingleFileBundleEngine.synthesize_test_bundle(
            files={"app.dll": (b"MZ\x90\x00" + b"\x00" * 60, BundleFileType.ASSEMBLY)},
            major_version=6,
        )
        res = BundleMarkerScanner.scan_dotnet_marker(bundle_bytes)
        self.assertIsNotNone(res)
        marker_off, hdr_off = res
        self.assertGreater(marker_off, 0)
        self.assertGreater(hdr_off, 0)

        kind, meta = BundleMarkerScanner.identify_packer(bundle_bytes)
        self.assertEqual(kind, SuperPackerKind.DOTNET_APPHOST)
        self.assertTrue(meta["has_marker"])

        # Warp marker test
        warp_dummy = b"MZ" + b"\x00" * 100 + WARP_MAGIC + b"\x00" * 20
        w_kind, w_meta = BundleMarkerScanner.identify_packer(warp_dummy)
        self.assertEqual(w_kind, SuperPackerKind.WARP)

        # Clean binary with no marker
        clean_bytes = b"MZ\x90\x00" + b"\x00" * 200
        c_kind, c_meta = BundleMarkerScanner.identify_packer(clean_bytes)
        self.assertEqual(c_kind, SuperPackerKind.NONE)

    def test_06_header_parser_v1_v2_v6(self):
        """Verifies header serialization and parsing across .NET bundle versions."""
        # Test v1 (.NET Core 3.x)
        v1_bytes = SingleFileBundleEngine.synthesize_test_bundle(
            files={
                "ManagedApp.dll": (b"MZ" + b"ManagedAppPEPayload", BundleFileType.ASSEMBLY),
                "App.pdb": (b"BSJB" + b"PdbSymbolsData", BundleFileType.PDB_FILE),
            },
            major_version=1,
            bundle_id="netcore3-bundle-test",
        )
        marker_info = BundleMarkerScanner.scan_dotnet_marker(v1_bytes)
        self.assertIsNotNone(marker_info)
        hdr1 = BundleHeaderParser.parse_header(v1_bytes, marker_info[1], marker_info[0])
        self.assertEqual(hdr1.major_version, 1)
        self.assertEqual(hdr1.file_count, 2)
        self.assertEqual(hdr1.bundle_id, "netcore3-bundle-test")
        self.assertEqual(len(hdr1.entries), 2)

        # Test v6 (.NET 6/7/8/9/10) with compression
        v6_bytes = SingleFileBundleEngine.synthesize_test_bundle(
            files={
                "System.Text.Json.dll": (b"MZ" + b"\x00" * 200, BundleFileType.ASSEMBLY),
                "appsettings.json": (b'{"Logging": {"LogLevel": "Debug"}}', BundleFileType.CONTENT),
                "e_sqlite3.dll": (b"MZ" + b"NativeSqliteDllContent", BundleFileType.NATIVE_BINARY),
            },
            major_version=6,
            compress=True,
            bundle_id="net9-bundle-test",
        )
        marker_info6 = BundleMarkerScanner.scan_dotnet_marker(v6_bytes)
        self.assertIsNotNone(marker_info6)
        hdr6 = BundleHeaderParser.parse_header(v6_bytes, marker_info6[1], marker_info6[0])
        self.assertEqual(hdr6.major_version, 6)
        self.assertEqual(hdr6.file_count, 3)
        self.assertTrue(hdr6.is_compressed)
        for e in hdr6.entries:
            self.assertTrue(e.is_compressed)
            self.assertGreater(e.compressed_size, 0)

    def test_07_decompressor(self):
        """Tests stream decompression across raw deflate and standard zlib."""
        payload = b"Hello, .NET 9 Single-File Host World! " * 10
        # Raw deflate
        comp_raw = zlib.compress(payload)[2:-4]  # Strip zlib header and adler32
        decomp, kind = BundleDecompressor.decompress(comp_raw, expected_size=len(payload))
        self.assertEqual(decomp, payload)
        self.assertEqual(kind, CompressionKind.DEFLATE)

        # Standard zlib
        comp_zlib = zlib.compress(payload)
        decomp2, kind2 = BundleDecompressor.decompress(comp_zlib, expected_size=len(payload))
        self.assertEqual(decomp2, payload)

        # Zip bomb prevention
        with self.assertRaises(SecurityError):
            BundleDecompressor.decompress(comp_zlib, expected_size=600 * 1024 * 1024)

    def test_08_virtual_volume_mounting_and_navigation(self):
        """Verifies VirtualBundleVolume filesystem tree, path lookup, and filtering."""
        files = {
            "MyApp.dll": (b"MZ" + b"\x00" * 50, BundleFileType.ASSEMBLY),
            "MyApp.pdb": (b"PDB_CONTENT", BundleFileType.PDB_FILE),
            "runtimes/win-x64/native/libnative.dll": (b"MZ" + b"NATIVE", BundleFileType.NATIVE_BINARY),
            "app.runtimeconfig.json": (b'{"runtimeOptions": {}}', BundleFileType.RUNTIME_CONFIG_JSON),
        }
        bundle_data = SingleFileBundleEngine.synthesize_test_bundle(files, major_version=6)

        volume = SingleFileBundleEngine.mount(bundle_data)
        self.assertIsNotNone(volume)
        paths = volume.list_paths()
        self.assertEqual(len(paths), 4)
        self.assertIn("MyApp.dll", paths)
        self.assertIn("runtimes/win-x64/native/libnative.dll", paths)

        # Read bytes
        extracted_dll = volume.read_file_bytes("MyApp.dll")
        self.assertEqual(extracted_dll, files["MyApp.dll"][0])

        # Tree rendering
        tree_text = volume.render_tree()
        self.assertIn("MyApp.dll", tree_text)
        self.assertIn("runtimes/", tree_text)

        # Category filtering
        asms = volume.filter_entries("assemblies")
        self.assertEqual(len(asms), 1)
        self.assertEqual(asms[0].relative_path, "MyApp.dll")

        natives = volume.filter_entries("native")
        self.assertEqual(len(natives), 1)

        summary = volume.get_summary()
        self.assertEqual(summary["total_files"], 4)
        self.assertEqual(summary["assembly_count"], 1)
        self.assertEqual(summary["native_count"], 1)

    def test_09_full_unbundling_and_directory_export(self):
        """Tests complete forensic unbundling and safe export with volume manifest."""
        files = {
            "System.Private.CoreLib.dll": (b"MZ" + b"\x00" * 120, BundleFileType.ASSEMBLY),
            "MyApp.deps.json": (b'{"targets": {}}', BundleFileType.DEPS_JSON),
            "sub/module.dll": (b"MZ" + b"\x00" * 80, BundleFileType.ASSEMBLY),
        }
        bundle_data = SingleFileBundleEngine.synthesize_test_bundle(
            files, major_version=6, compress=True, bundle_id="export-test-guid"
        )

        res = SingleFileBundleEngine.unbundle_bytes(bundle_data, file_name="singlefile_test.exe")
        self.assertTrue(res.is_bundle)
        self.assertEqual(len(res.extracted_files), 3)
        self.assertEqual(res.telemetry.total_files, 3)
        self.assertEqual(res.telemetry.assembly_count, 2)
        self.assertEqual(res.telemetry.config_count, 1)

        # Export to temporary directory
        out_dir = os.path.join(self.tmp_dir, "extracted_bundle")
        exp_res = SingleFileBundleEngine.export_to_directory(res, output_dir=out_dir)
        self.assertEqual(exp_res["extracted_count"], 3)
        self.assertTrue(os.path.exists(exp_res["manifest_file"]))

        # Verify extracted file content
        extracted_corelib = os.path.join(out_dir, "System.Private.CoreLib.dll")
        self.assertTrue(os.path.exists(extracted_corelib))
        with open(extracted_corelib, "rb") as f:
            self.assertEqual(f.read(), files["System.Private.CoreLib.dll"][0])

        # Verify manifest json
        with open(exp_res["manifest_file"], "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertTrue(manifest["is_bundle"])
        self.assertEqual(manifest["extracted_count"], 3)  # 3 payload files
        self.assertEqual(len(exp_res["exported_files"]), 4)  # 3 payload files + 1 manifest file

    def test_10_core_facade_integration(self):
        """Verifies DotNetPackerCore unbundle, mount, and export methods."""
        files = {
            "PayloadApp.dll": (b"MZ" + b"\x00" * 40, BundleFileType.ASSEMBLY),
            "payload.pdb": (b"SYMBOLS", BundleFileType.PDB_FILE),
        }
        bundle_bytes = SingleFileBundleEngine.synthesize_test_bundle(files, major_version=6)
        bundle_file = os.path.join(self.tmp_dir, "core_app.exe")
        with open(bundle_file, "wb") as f:
            f.write(bundle_bytes)

        # 1. unbundle_file
        ub_res = DotNetPackerCore.unbundle_file(bundle_file)
        self.assertTrue(ub_res.is_bundle)
        self.assertEqual(ub_res.telemetry.total_files, 2)

        # 2. mount_bundle_volume
        vol = DotNetPackerCore.mount_bundle_volume(bundle_file)
        self.assertIsNotNone(vol)
        self.assertIn("PayloadApp.dll", vol.list_paths())

        # 3. export_bundle
        exp_out = os.path.join(self.tmp_dir, "core_export")
        exp_info = DotNetPackerCore.export_bundle(bundle_file, output_dir=exp_out)
        self.assertEqual(exp_info["extracted_count"], 2)

        # 4. analyze_bytes incorporates bundle telemetry
        rep = DotNetPackerCore.analyze_bytes(bundle_bytes, file_name="core_app.exe")
        self.assertIn("bundle", rep)
        self.assertTrue(rep["bundle"]["is_bundle"])
        self.assertEqual(rep["bundle"]["packer_kind"], "dotnet_apphost")
        self.assertEqual(rep["bundle"]["total_files"], 2)

    def test_11_cli_bundle_flags(self):
        """Verifies CLI execution with --bundle, --bundle-mount, and --bundle-out."""
        files = {
            "CliTest.dll": (b"MZ" + b"\x00" * 30, BundleFileType.ASSEMBLY),
        }
        bundle_bytes = SingleFileBundleEngine.synthesize_test_bundle(files, major_version=6)
        bundle_path = os.path.join(self.tmp_dir, "cli_bundle.exe")
        with open(bundle_path, "wb") as f:
            f.write(bundle_bytes)

        out_dir = os.path.join(self.tmp_dir, "cli_bundle_out")
        # Run CLI with bundle unbundling and volume mounting
        exit_code = main([
            bundle_path,
            "--bundle",
            "--bundle-mount",
            "--bundle-out", out_dir,
            "--format", "text",
        ])
        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(out_dir))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "CliTest.dll")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "bundle_manifest.json")))

    def test_12_malformed_and_truncated_bounds(self):
        """Verifies graceful handling of truncated or corrupted bundle headers."""
        # Truncated header (file_count indicates entries follow, but buffer terminates immediately)
        header_payload = struct.pack("<III", 6, 0, 5) + b"\x04guid"
        header_off = 10
        corrupted = b"MZ" + b"\x00" * 8 + header_payload + struct.pack("<q", header_off) + DOTNET_BUNDLE_MARKER
        res = SingleFileBundleEngine.unbundle_bytes(corrupted, file_name="corrupt.exe")
        self.assertTrue(res.is_bundle)
        self.assertGreater(len(res.errors), 0)

        # Marker with out-of-bounds header offset (fails marker scanning)
        invalid_marker = b"MZ" + b"\x00" * 20 + struct.pack("<q", 999999999) + DOTNET_BUNDLE_MARKER
        res2 = SingleFileBundleEngine.unbundle_bytes(invalid_marker, file_name="invalid.exe")
        self.assertFalse(res2.is_bundle)


if __name__ == "__main__":
    unittest.main()
