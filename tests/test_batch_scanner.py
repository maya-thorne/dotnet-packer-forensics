"""
Unit and Integration Test Suite for Batch Forensic Automation Engine & PE Directory Scanner.
Engineered & Audited by Maya Thorne.
"""

import io
import json
import os
import shutil
import struct
import sys
import tempfile
import time
from typing import Any, Dict, List
import unittest
from unittest.mock import patch

from dotnet_deobfuscator import DotNetPackerCore
from dotnet_deobfuscator.batch import (
    BatchDirectoryScanner,
    BatchForensicEngine,
    BatchReporter,
    BatchScanOptions,
    BatchScanReport,
    BatchScanSummary,
    FileScanStatus,
    SecurityError,
    SingleScanResult,
    ThreatLevel,
    safe_path,
    zeroize_buffer,
)
from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.fuzzing import SyntheticMutatedBinaryGenerator


class TestBatchModelsAndSanitizers(unittest.TestCase):
    """Validates data structures, enums, path containment, and memory zeroization."""

    def test_enums_and_ordering(self) -> None:
        self.assertEqual([s.value for s in FileScanStatus], ["scanned", "packed", "clean", "skipped", "error", "timeout"])
        self.assertEqual([ThreatLevel.CLEAN.score, ThreatLevel.LOW.score, ThreatLevel.MEDIUM.score, ThreatLevel.HIGH.score, ThreatLevel.CRITICAL.score], [0, 1, 2, 3, 4])
        self.assertTrue(ThreatLevel.CLEAN < ThreatLevel.LOW < ThreatLevel.MEDIUM < ThreatLevel.HIGH < ThreatLevel.CRITICAL)
        self.assertEqual(ThreatLevel.from_str("high"), ThreatLevel.HIGH)
        self.assertEqual(ThreatLevel.from_str("UNKNOWN"), ThreatLevel.LOW)

    def test_threat_level_and_status_from_str_resilience(self) -> None:
        self.assertEqual(ThreatLevel.from_str(ThreatLevel.CRITICAL), ThreatLevel.CRITICAL)
        self.assertEqual(ThreatLevel.from_str(ThreatLevel.HIGH), ThreatLevel.HIGH)
        self.assertEqual(ThreatLevel.from_str("CRITICAL"), ThreatLevel.CRITICAL)
        self.assertEqual(ThreatLevel.from_str("ThreatLevel.HIGH"), ThreatLevel.HIGH)
        self.assertEqual(ThreatLevel.from_str("nonexistent"), ThreatLevel.LOW)
        self.assertEqual(FileScanStatus.from_str(FileScanStatus.TIMEOUT), FileScanStatus.TIMEOUT)
        self.assertEqual(FileScanStatus.from_str("FileScanStatus.PACKED"), FileScanStatus.PACKED)
        self.assertEqual(FileScanStatus.from_str("clean"), FileScanStatus.CLEAN)

    def test_zeroize_buffer(self) -> None:
        buf = bytearray(b"sensitive_protector_key_deadbeef")
        self.assertTrue(any(b != 0 for b in buf))
        zeroize_buffer(buf)
        self.assertTrue(all(b == 0 for b in buf))

        # None / empty resilience
        zeroize_buffer(bytearray())
        zeroize_buffer(None)  # type: ignore

    def test_safe_path_security(self) -> None:
        with tempfile.TemporaryDirectory() as base_tmp:
            valid_p = safe_path(base_tmp, "sample.exe")
            self.assertTrue(valid_p.startswith(os.path.realpath(base_tmp)))

            nested_p = safe_path(base_tmp, os.path.join("subdir", "file.dll"))
            self.assertTrue(nested_p.startswith(os.path.realpath(base_tmp)))

            with self.assertRaises(SecurityError):
                safe_path(base_tmp, os.path.join("..", "..", "evil.exe"))

            with self.assertRaises(SecurityError):
                safe_path(base_tmp, "../payload.bin")

    def test_safe_path_root_drive_handling(self) -> None:
        root_dir = "C:\\" if os.name == "nt" else "/"
        p = safe_path(root_dir, "test.exe")
        self.assertTrue(p.startswith(os.path.realpath(root_dir)))

    def test_models_to_dict(self) -> None:
        opts = BatchScanOptions(target_dir="/tmp/test", workers=2)
        res = SingleScanResult(
            file_path="/tmp/test/sample.exe",
            file_name="sample.exe",
            file_size=1024,
            sha256="abc123",
            status=FileScanStatus.PACKED,
            threat_level=ThreatLevel.HIGH,
            is_pe=True,
            is_dotnet=True,
            protectors=["ConfuserEx"],
        )
        summary = BatchScanSummary(total_files_discovered=1, total_files_scanned=1)
        report = BatchScanReport(options=opts, summary=summary, results=[res])

        d = report.to_dict()
        self.assertEqual(d["scanner_version"], "2.9.0")
        self.assertEqual(d["summary"]["total_files_discovered"], 1)
        self.assertEqual(len(d["results"]), 1)
        self.assertEqual(d["results"][0]["status"], "packed")
        self.assertEqual(d["results"][0]["threat_level"], "high")

    def test_single_scan_result_to_dict_string_status(self) -> None:
        res = SingleScanResult(
            file_path="/test/file.exe", file_name="file.exe", file_size=100, sha256="",
            status="clean", threat_level="clean", is_pe=True, is_dotnet=False,  # type: ignore
        )
        d = res.to_dict()
        self.assertEqual(d["status"], "clean")
        self.assertEqual(d["threat_level"], "clean")


class TestDirectoryDiscoveryAndFiltering(unittest.TestCase):
    """Tests file discovery, recursion, pattern filtering, and size thresholds."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.sub_dir = os.path.join(self.temp_dir, "nested")
        os.makedirs(self.sub_dir, exist_ok=True)

        # Create test files
        self.f_root_exe = os.path.join(self.temp_dir, "target.exe")
        self.f_root_dll = os.path.join(self.temp_dir, "library.dll")
        self.f_root_txt = os.path.join(self.temp_dir, "readme.txt")
        self.f_sub_exe = os.path.join(self.sub_dir, "nested.exe")
        self.f_sub_bin = os.path.join(self.sub_dir, "data.bin")

        for p, sz in [(self.f_root_exe, 500), (self.f_root_dll, 1200), (self.f_root_txt, 200), (self.f_sub_exe, 800), (self.f_sub_bin, 3000)]:
            with open(p, "wb") as f:
                f.write(b"X" * sz)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_discovery_shallow_vs_recursive(self) -> None:
        opts_shallow = BatchScanOptions(target_dir=self.temp_dir, recursive=False)
        shallow_files = BatchDirectoryScanner.discover_files(opts_shallow)
        self.assertEqual(len(shallow_files), 3)

        opts_recursive = BatchScanOptions(target_dir=self.temp_dir, recursive=True)
        recursive_files = BatchDirectoryScanner.discover_files(opts_recursive)
        self.assertEqual(len(recursive_files), 5)

    def test_pattern_matching(self) -> None:
        opts_pattern = BatchScanOptions(target_dir=self.temp_dir, recursive=True, pattern="*.exe")
        exe_files = BatchDirectoryScanner.discover_files(opts_pattern)
        self.assertEqual(len(exe_files), 2)
        self.assertTrue(all(f.endswith(".exe") for f in exe_files))

        opts_multi = BatchScanOptions(
            target_dir=self.temp_dir, recursive=True, pattern="*.exe,*.dll"
        )
        multi_files = BatchDirectoryScanner.discover_files(opts_multi)
        self.assertEqual(len(multi_files), 3)

    def test_size_filtering(self) -> None:
        opts_size = BatchScanOptions(
            target_dir=self.temp_dir, recursive=True, min_size_bytes=600, max_size_bytes=2000
        )
        size_files = BatchDirectoryScanner.discover_files(opts_size)
        self.assertEqual(len(size_files), 2)  # 1200 bytes and 800 bytes

    def test_fast_pe_prefilter(self) -> None:
        pe_bytes = SyntheticMutatedBinaryGenerator.generate_baseline_pe()
        self.assertTrue(BatchDirectoryScanner.is_pe_buffer(pe_bytes))
        self.assertFalse(BatchDirectoryScanner.is_pe_buffer(b"NOT_A_PE_BINARY"))
        self.assertFalse(BatchDirectoryScanner.is_pe_buffer(b"MZ" + b"\x00" * 20))

        # Test is_pe_file
        test_pe_path = os.path.join(self.temp_dir, "valid.pe")
        with open(test_pe_path, "wb") as f:
            f.write(pe_bytes)
        self.assertTrue(BatchDirectoryScanner.is_pe_file(test_pe_path))
        self.assertFalse(BatchDirectoryScanner.is_pe_file(self.f_root_txt))
        self.assertFalse(BatchDirectoryScanner.is_pe_file(os.path.join(self.temp_dir, "nonexistent.exe")))

    def test_pattern_matching_edge_cases(self) -> None:
        self.assertTrue(BatchDirectoryScanner.matches_pattern("sample.exe", ""))
        self.assertTrue(BatchDirectoryScanner.matches_pattern("sample.exe", "   "))
        self.assertTrue(BatchDirectoryScanner.matches_pattern("sample.exe", ", ; "))
        self.assertTrue(BatchDirectoryScanner.matches_pattern("sample.exe", "*.dll; *.exe"))
        self.assertTrue(BatchDirectoryScanner.matches_pattern("sample.EXE", "*.exe"))
        self.assertFalse(BatchDirectoryScanner.matches_pattern("sample.txt", "*.exe, *.dll"))

    def test_is_pe_file_large_dos_stub(self) -> None:
        dos_hdr = bytearray(b"MZ" + b"\x00" * 0x3A)
        target_offset = 0x1200
        dos_hdr[0x3C:0x40] = struct.pack("<I", target_offset)
        full_data = bytearray(dos_hdr)
        full_data.extend(b"\x00" * (target_offset - len(dos_hdr)))
        full_data.extend(b"PE\x00\x00" + b"\x00" * 200)

        large_stub_path = os.path.join(self.temp_dir, "large_stub.exe")
        with open(large_stub_path, "wb") as f:
            f.write(full_data)

        self.assertTrue(BatchDirectoryScanner.is_pe_file(large_stub_path))

    def test_discovery_inaccessible_entry_resilience(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, recursive=False)

        class MockDirEntry:
            def __init__(self, name: str, path: str, fail: bool = False):
                self.name = name
                self.path = path
                self.fail = fail

            def is_file(self) -> bool:
                if self.fail:
                    raise PermissionError("Access denied on protected object")
                return True

            def stat(self):
                class StatRes:
                    st_size = 500
                return StatRes()

        class MockScandirContext:
            def __enter__(self):
                return [
                    MockDirEntry("normal.exe", "/fake/normal.exe", fail=False),
                    MockDirEntry("locked.sys", "/fake/locked.sys", fail=True),
                ]

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        with patch("os.scandir", return_value=MockScandirContext()):
            discovered = BatchDirectoryScanner.discover_files(opts)
            self.assertEqual(len(discovered), 1)
            self.assertIn("normal.exe", discovered[0])


class TestMultiThreadedScannerAndConcurrency(unittest.TestCase):
    """Tests multi-threaded worker pool, timeout isolation, and threat classification."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_pe = SyntheticMutatedBinaryGenerator.generate_baseline_pe()

        for i in range(4):
            with open(os.path.join(self.temp_dir, f"sample_{i+1:02d}.exe"), "wb") as f:
                f.write(self.baseline_pe)
        with open(os.path.join(self.temp_dir, "plain.txt"), "wb") as f:
            f.write(b"plain non-executable text data")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_concurrent_scanning_and_progress_callback(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=3, pe_only=True)
        progress_calls = []

        def on_progress(done: int, total: int, res: SingleScanResult) -> None:
            progress_calls.append((done, total, res.file_name))

        report = BatchDirectoryScanner.scan_directory(opts, progress_callback=on_progress)
        self.assertEqual(report.summary.total_files_discovered, 5)
        self.assertEqual(report.summary.total_pe_files, 4)
        self.assertEqual(report.summary.total_files_skipped, 1)  # plain.txt skipped by pe_only
        self.assertEqual(len(progress_calls), 5)
        self.assertGreater(report.summary.elapsed_seconds, 0.0)

    def test_per_file_timeout_handling(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=2, timeout_sec=0.1)

        def slow_scan(file_path: str, options: BatchScanOptions) -> SingleScanResult:
            time.sleep(0.3)
            return SingleScanResult(
                file_path=file_path, file_name=os.path.basename(file_path), file_size=10,
                sha256="", status=FileScanStatus.CLEAN, threat_level=ThreatLevel.CLEAN,
                is_pe=True, is_dotnet=True,
            )

        with patch.object(BatchDirectoryScanner, "scan_single_file", side_effect=slow_scan):
            report = BatchDirectoryScanner.scan_directory(opts)
            self.assertGreater(report.summary.total_timeouts, 0)
            self.assertTrue(any(r.status == FileScanStatus.TIMEOUT for r in report.results))

    def test_queued_tasks_do_not_prematurely_timeout(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=1, timeout_sec=0.25)

        def moderate_scan(file_path: str, options: BatchScanOptions) -> SingleScanResult:
            time.sleep(0.04)
            return SingleScanResult(
                file_path=file_path, file_name=os.path.basename(file_path), file_size=10,
                sha256="", status=FileScanStatus.CLEAN, threat_level=ThreatLevel.CLEAN,
                is_pe=True, is_dotnet=True,
            )

        with patch.object(BatchDirectoryScanner, "scan_single_file", side_effect=moderate_scan):
            report = BatchDirectoryScanner.scan_directory(opts)
            self.assertEqual(report.summary.total_timeouts, 0)
            self.assertEqual(len(report.results), 5)
            self.assertTrue(all(r.status == FileScanStatus.CLEAN for r in report.results))

    def test_batch_scanning_with_unpack_payloads(self) -> None:
        unpack_out = os.path.join(self.temp_dir, "unpacked_extracted")
        opts = BatchScanOptions(
            target_dir=self.temp_dir,
            workers=2,
            unpack_payloads=True,
            unpack_out_dir=unpack_out,
        )
        report = BatchDirectoryScanner.scan_directory(opts)
        self.assertEqual(report.summary.total_files_discovered, 5)
        self.assertNotIn("unpack_all_to_dir() takes 2 positional arguments", str(report.to_dict()))
        self.assertNotIn("Unpacking error", str(report.to_dict()))
        pe_results = [r for r in report.results if r.is_pe]
        self.assertEqual(len(pe_results), 4)
        self.assertTrue(all(r.unpacked_count > 0 for r in pe_results))
        self.assertTrue(all(len(r.unpacked_files) > 0 for r in pe_results))

    def test_safe_getsize_resilience(self) -> None:
        size = BatchDirectoryScanner._safe_getsize(os.path.join(self.temp_dir, "nonexistent_file.bin"))
        self.assertEqual(size, 0)

    def test_error_isolation(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=2)
        orig_scan = BatchDirectoryScanner.scan_single_file

        def failing_scan(file_path: str, options: BatchScanOptions) -> SingleScanResult:
            if "sample_02" in file_path:
                raise RuntimeError("Simulated crash in parser")
            return orig_scan(file_path, options)

        with patch.object(BatchDirectoryScanner, "scan_single_file", side_effect=failing_scan):
            report = BatchDirectoryScanner.scan_directory(opts)
            self.assertEqual(report.summary.total_errors, 1)
            error_item = [r for r in report.results if "sample_02" in r.file_name][0]
            self.assertEqual(error_item.status, FileScanStatus.ERROR)
            self.assertIn("Simulated crash", error_item.error_message or "")

    def test_threat_level_classifier(self) -> None:
        t_crit = BatchDirectoryScanner.classify_threat_level(["AntiTamper"], [], 0, True)
        self.assertEqual(t_crit, ThreatLevel.CRITICAL)

        t_high = BatchDirectoryScanner.classify_threat_level(["Eazfuscator"], [], 0, True)
        self.assertEqual(t_high, ThreatLevel.HIGH)

        t_med = BatchDirectoryScanner.classify_threat_level([], ["Corrupted PE Header", "Odd Alignment"], 0, True)
        self.assertEqual(t_med, ThreatLevel.MEDIUM)

        t_low = BatchDirectoryScanner.classify_threat_level([], ["Mild Section Slack"], 500, True)
        self.assertEqual(t_low, ThreatLevel.LOW)

        t_clean = BatchDirectoryScanner.classify_threat_level([], [], 0, True)
        self.assertEqual(t_clean, ThreatLevel.CLEAN)

    def test_threat_level_classifier_normalized_protectors(self) -> None:
        self.assertEqual(BatchDirectoryScanner.classify_threat_level(["Eazfuscator.NET"], [], 0, True), ThreatLevel.HIGH)
        self.assertEqual(BatchDirectoryScanner.classify_threat_level(["Babel Obfuscator"], [], 0, True), ThreatLevel.HIGH)
        self.assertEqual(BatchDirectoryScanner.classify_threat_level(["Costura"], [], 0, True), ThreatLevel.MEDIUM)
        self.assertEqual(BatchDirectoryScanner.classify_threat_level(["xorPacker"], [], 0, True), ThreatLevel.MEDIUM)
        self.assertEqual(BatchDirectoryScanner.classify_threat_level(["AntiDump"], [], 0, True), ThreatLevel.CRITICAL)

    def test_deterministic_results_sorting(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=3)
        report = BatchDirectoryScanner.scan_directory(opts)
        paths = [r.file_path for r in report.results]
        self.assertEqual(paths, sorted(paths))

    def test_dynamic_worker_replenishment_on_timeout(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=2, timeout_sec=0.15)

        def slow_worker(file_path: str, options: BatchScanOptions) -> SingleScanResult:
            if "sample_01" in file_path or "sample_02" in file_path:
                time.sleep(2.0)
            return SingleScanResult(
                file_path=file_path, file_name=os.path.basename(file_path), file_size=10,
                sha256="", status=FileScanStatus.CLEAN, threat_level=ThreatLevel.CLEAN,
                is_pe=True, is_dotnet=True,
            )

        with patch.object(BatchDirectoryScanner, "scan_single_file", side_effect=slow_worker):
            t0 = time.perf_counter()
            report = BatchDirectoryScanner.scan_directory(opts)
            elapsed = time.perf_counter() - t0
            self.assertEqual(report.summary.total_timeouts, 2)
            self.assertEqual(len(report.results), 5)
            self.assertLess(elapsed, 1.2)

    def test_unpack_payloads_with_invalid_filename_characters(self) -> None:
        unpack_out = os.path.join(self.temp_dir, "unpacked_special")
        weird_p = os.path.join(self.temp_dir, "weird_bad_chars.exe")
        with open(weird_p, "wb") as f:
            f.write(self.baseline_pe)
        opts = BatchScanOptions(target_dir=self.temp_dir, workers=2, unpack_payloads=True, unpack_out_dir=unpack_out)
        report = BatchDirectoryScanner.scan_directory(opts)
        self.assertNotIn("Unpacking error", str(report.to_dict()))


class TestBatchReportersAndExports(unittest.TestCase):
    """Tests Console Table, CSV, JSON, and Self-Contained HTML Dashboard generation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        opts = BatchScanOptions(target_dir="/forensics/samples", workers=4)
        summary = BatchScanSummary(
            total_files_discovered=3, total_files_scanned=2, total_files_skipped=1,
            total_pe_files=2, total_dotnet_files=2, total_packed_files=1, total_clean_files=1,
            threat_counts={"clean": 1, "low": 0, "medium": 0, "high": 1, "critical": 0},
            protector_counts={"ConfuserEx": 1}, total_bytes_scanned=20480, elapsed_seconds=0.25,
            scan_rate_files_per_sec=8.0, scan_rate_mb_per_sec=0.08,
        )
        r1 = SingleScanResult(
            file_path="/forensics/samples/packed.exe", file_name="packed.exe", file_size=12000,
            sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            status=FileScanStatus.PACKED, threat_level=ThreatLevel.HIGH, is_pe=True, is_dotnet=True,
            protectors=["ConfuserEx"], scan_duration_ms=45.2,
        )
        r2 = SingleScanResult(
            file_path="/forensics/samples/clean.exe", file_name="clean.exe", file_size=8480,
            sha256="ffff0000aaaabbbbccccddddeeeeffff11112222333344445555666677778888",
            status=FileScanStatus.CLEAN, threat_level=ThreatLevel.CLEAN, is_pe=True, is_dotnet=True,
            scan_duration_ms=22.1,
        )
        r3 = SingleScanResult(
            file_path="/forensics/samples/<malicious>&escape.bin", file_name="<malicious>&escape.bin",
            file_size=500, sha256="33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222",
            status=FileScanStatus.SKIPPED, threat_level=ThreatLevel.CLEAN, is_pe=False, is_dotnet=False,
            scan_duration_ms=2.0,
        )
        self.report = BatchScanReport(options=opts, summary=summary, results=[r1, r2, r3])

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_console_table_formatting(self) -> None:
        table_str = BatchReporter.format_console_table(self.report)
        self.assertIn("DOTNET PACKER FORENSICS - BATCH DIRECTORY SCAN REPORT", table_str)
        self.assertIn("packed.exe", table_str)
        self.assertIn("clean.exe", table_str)
        self.assertIn("ConfuserEx", table_str)
        self.assertIn("CRITICAL: 0", table_str)
        self.assertIn("HIGH: 1", table_str)

    def test_json_export(self) -> None:
        json_path = os.path.join(self.temp_dir, "report.json")
        out_p = BatchReporter.export_json(self.report, json_path)
        self.assertEqual(out_p, json_path)
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["scanner_version"], "2.9.0")
        self.assertEqual(len(data["results"]), 3)
        self.assertEqual(data["summary"]["total_packed_files"], 1)

    def test_csv_export(self) -> None:
        csv_path = os.path.join(self.temp_dir, "report.csv")
        out_p = BatchReporter.export_csv(self.report, csv_path)
        self.assertEqual(out_p, csv_path)
        self.assertTrue(os.path.exists(csv_path))

        with open(csv_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertGreaterEqual(len(lines), 4)
        self.assertIn("file_path,file_name,file_size_bytes", lines[0])
        self.assertIn("packed.exe", lines[1])

    def test_self_contained_html_dashboard_security(self) -> None:
        html_path = os.path.join(self.temp_dir, "dashboard.html")
        out_p = BatchReporter.generate_html_dashboard(self.report, html_path)
        self.assertEqual(out_p, html_path)
        self.assertTrue(os.path.exists(html_path))

        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Strict security: verify NO external CDN or external URL dependencies
        self.assertNotIn("http://", content)
        self.assertNotIn("https://", content)

        # Strict escaping: verify entities are properly escaped
        self.assertNotIn("<malicious>&escape.bin", content)
        self.assertIn("&lt;malicious&gt;&amp;escape.bin", content)

        # Dashboard elements present
        self.assertIn("Batch PE Forensic Dashboard", content)
        self.assertIn("ConfuserEx", content)
        self.assertIn("filterTable()", content)

    def test_html_dashboard_formatting_polish(self) -> None:
        html_path = os.path.join(self.temp_dir, "dashboard_polish.html")
        r_err = SingleScanResult(
            file_path="/samples/err.exe", file_name="err.exe", file_size=0, sha256="",
            status=FileScanStatus.ERROR, threat_level=ThreatLevel.LOW, is_pe=False, is_dotnet=False,
            error_message="Short err",
        )
        report_with_err = BatchScanReport(
            options=self.report.options, summary=self.report.summary, results=[r_err]
        )
        BatchReporter.generate_html_dashboard(report_with_err, html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn(">Short err</div>", content)
        self.assertNotIn("Short err...</div>", content)
        self.assertIn(">-</td>", content)

    def test_reporters_and_scanner_string_status_resilience(self) -> None:
        res = SingleScanResult(
            file_path="/samples/manual.exe", file_name="manual.exe", file_size=1000,
            sha256="abc", status="packed", threat_level="high", is_pe=True, is_dotnet=True, protectors=["Costura"],  # type: ignore
        )
        self.assertIsInstance(res.status, FileScanStatus)
        self.assertIsInstance(res.threat_level, ThreatLevel)
        rep = BatchScanReport(options=self.report.options, summary=self.report.summary, results=[res])
        txt = BatchReporter.format_console_table(rep)
        self.assertIn("PACKED", txt)
        csv_p = os.path.join(self.temp_dir, "test_str.csv")
        BatchReporter.export_csv(rep, csv_p)
        self.assertTrue(os.path.exists(csv_p))
        html_p = os.path.join(self.temp_dir, "test_str.html")
        BatchReporter.generate_html_dashboard(rep, html_p)
        self.assertTrue(os.path.exists(html_p))

    def test_unicode_and_special_character_filenames(self) -> None:
        u_dir = tempfile.mkdtemp()
        try:
            pe_data = SyntheticMutatedBinaryGenerator.generate_baseline_pe()
            test_names = [
                "한글_샘플_01.exe",
                "日本語テスト.dll",
                "русский_файл.exe",
                "sample 🚀 emoji.exe",
                "weird#name%20!@^&().exe",
            ]
            for name in test_names:
                with open(os.path.join(u_dir, name), "wb") as f:
                    f.write(pe_data)

            opts = BatchScanOptions(target_dir=u_dir, workers=2)
            report = BatchDirectoryScanner.scan_directory(opts)
            self.assertEqual(report.summary.total_files_discovered, 5)
            self.assertEqual(report.summary.total_pe_files, 5)

            table = BatchReporter.format_console_table(report)
            self.assertIn("DOTNET PACKER FORENSICS", table)

            j_p = os.path.join(u_dir, "rep.json")
            BatchReporter.export_json(report, j_p)
            with open(j_p, "r", encoding="utf-8") as f:
                j_obj = json.load(f)
            self.assertEqual(len(j_obj["results"]), 5)

            c_p = os.path.join(u_dir, "rep.csv")
            BatchReporter.export_csv(report, c_p)
            with open(c_p, "r", encoding="utf-8") as f:
                c_lines = f.readlines()
            self.assertEqual(len(c_lines), 6)

            h_p = os.path.join(u_dir, "rep.html")
            BatchReporter.generate_html_dashboard(report, h_p)
            with open(h_p, "r", encoding="utf-8") as f:
                h_text = f.read()
            self.assertIn("Batch PE Forensic Dashboard", h_text)
            self.assertIn("sample 🚀 emoji.exe", h_text)
        finally:
            shutil.rmtree(u_dir, ignore_errors=True)


class TestBatchForensicEngineAndCoreFacade(unittest.TestCase):
    """Tests BatchForensicEngine execution and DotNetPackerCore facade integration."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.out_dir = os.path.join(self.temp_dir, "batch_out")
        self.baseline_pe = SyntheticMutatedBinaryGenerator.generate_baseline_pe()

        with open(os.path.join(self.temp_dir, "app1.exe"), "wb") as f:
            f.write(self.baseline_pe)
        with open(os.path.join(self.temp_dir, "app2.exe"), "wb") as f:
            f.write(self.baseline_pe)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_engine_run_with_auto_output_directory(self) -> None:
        opts = BatchScanOptions(target_dir=self.temp_dir, output_dir=self.out_dir, workers=2)
        report = BatchForensicEngine.run(opts)

        self.assertEqual(report.summary.total_files_discovered, 2)
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "batch_report.json")))
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "batch_report.csv")))
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "batch_dashboard.html")))

    def test_core_facade_batch_scan(self) -> None:
        report = DotNetPackerCore.batch_scan(
            target_dir=self.temp_dir,
            workers=2,
            pattern="*.exe",
        )
        self.assertEqual(report.summary.total_files_discovered, 2)
        self.assertIsInstance(report, BatchScanReport)

        export_paths = DotNetPackerCore.export_batch_report(report, output_dir=self.out_dir)
        self.assertIn("json", export_paths)
        self.assertIn("csv", export_paths)
        self.assertIn("html", export_paths)

    def test_core_facade_batch_scan_unpack_args(self) -> None:
        unpack_dest = os.path.join(self.temp_dir, "facade_unpacked")
        report = DotNetPackerCore.batch_scan(
            target_dir=self.temp_dir,
            workers=2,
            unpack_payloads=True,
            unpack_out_dir=unpack_dest,
        )
        self.assertEqual(report.summary.total_files_discovered, 2)
        pe_items = [r for r in report.results if r.is_pe]
        self.assertTrue(all(r.unpacked_count > 0 for r in pe_items))


class TestBatchCLIIntegration(unittest.TestCase):
    """Tests CLI commands, argument parsing, formats, and failure modes."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.out_dir = os.path.join(self.temp_dir, "cli_out")
        self.baseline_pe = SyntheticMutatedBinaryGenerator.generate_baseline_pe()

        with open(os.path.join(self.temp_dir, "sample.exe"), "wb") as f:
            f.write(self.baseline_pe)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_batch_text_table_stdout(self) -> None:
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["--batch", self.temp_dir, "--batch-workers", "2"])
        self.assertEqual(code, 0)
        output = captured.getvalue()
        self.assertIn("DOTNET PACKER FORENSICS - BATCH DIRECTORY SCAN REPORT", output)
        self.assertIn("sample.exe", output)

    def test_cli_batch_json_stdout(self) -> None:
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["--batch", self.temp_dir, "--format", "json"])
        self.assertEqual(code, 0)
        output = captured.getvalue()
        data = json.loads(output)
        self.assertEqual(data["scanner_version"], "2.9.0")
        self.assertEqual(data["summary"]["total_files_discovered"], 1)

    def test_cli_batch_with_target_positional(self) -> None:
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main([self.temp_dir, "--batch"])
        self.assertEqual(code, 0)
        self.assertIn("BATCH DIRECTORY SCAN REPORT", captured.getvalue())

    def test_cli_batch_exports_all(self) -> None:
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["--batch", self.temp_dir, "--batch-out", self.out_dir])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "batch_report.json")))
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "batch_report.csv")))
        self.assertTrue(os.path.exists(os.path.join(self.out_dir, "batch_dashboard.html")))

    def test_cli_batch_missing_directory_error(self) -> None:
        captured_err = io.StringIO()
        with patch("sys.stderr", captured_err):
            code = main(["--batch"])
        self.assertEqual(code, 2)
        self.assertIn("Target directory for batch scanning is required", captured_err.getvalue())

    def test_cli_batch_nonexistent_directory(self) -> None:
        captured_err = io.StringIO()
        with patch("sys.stderr", captured_err):
            code = main(["--batch", "/path/that/does/not/exist/at/all"])
        self.assertEqual(code, 1)
        self.assertIn("Batch forensic scan failed", captured_err.getvalue())


if __name__ == "__main__":
    unittest.main()
