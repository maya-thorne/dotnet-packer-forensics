"""
Comprehensive Unit & Integration Test Suite for Multi-Engine Binary Diffing.
Engineered & Audited by Maya Thorne.
"""

import io
import json
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator.diffing import (
    ASTDiffer,
    BinaryDiffEngine,
    BinaryDiffOptions,
    BinaryDiffResult,
    BytecodeDiffer,
    CFGDiffer,
    ChangeType,
    DiffCategory,
    DiffEngine,
    HTMLDiffReporter,
    MetadataDiffer,
    ObfuscationImpact,
    SecurityError,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)
from dotnet_deobfuscator import DotNetPackerCore
from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.fuzzing import SyntheticMutatedBinaryGenerator


class TestBinaryDiffingSuite(unittest.TestCase):
    """Test suite covering data models, sub-differs, orchestrator, and CLI interface."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="diff_test_")
        self.baseline_pe = SyntheticMutatedBinaryGenerator.generate_baseline_pe(is_64bit=False)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_security_zeroize_buffer(self):
        """Validates that zeroize_buffer zeroes mutable memory safely."""
        buf = bytearray(b"SENSITIVE_DIFF_DATA_12345")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(buf)))

        mv = memoryview(bytearray(b"MEMORY_VIEW_KEY_67890"))
        zeroize_buffer(mv)
        self.assertEqual(bytes(mv), b"\x00" * len(mv))

        # Test immutable buffer does not raise exception
        zeroize_buffer(b"IMMUTABLE_BYTES")

    def test_security_safe_path_traversal_defense(self):
        """Verifies directory traversal attempts are strictly intercepted."""
        base = os.path.join(self.temp_dir, "export_zone")
        os.makedirs(base, exist_ok=True)

        valid = safe_path(base, "diff_report.html")
        self.assertTrue(valid.startswith(os.path.realpath(base)))

        valid_nested = safe_path(base, "reports/diff.json")
        self.assertTrue(valid_nested.startswith(os.path.realpath(base)))

        with self.assertRaises(SecurityError):
            safe_path(base, "../../../etc/passwd")

        with self.assertRaises(SecurityError):
            safe_path(base, "sub/../../../../escaped.txt")

    def test_calculate_entropy(self):
        """Verifies Shannon entropy calculation on null, uniform, and pseudo-random byte sequences."""
        self.assertEqual(calculate_entropy(b""), 0.0)
        self.assertEqual(calculate_entropy(b"\x00" * 100), 0.0)
        # Uniform 256 bytes
        uniform = bytes(range(256))
        self.assertAlmostEqual(calculate_entropy(uniform), 8.0, places=2)

    def test_metadata_differ_identical(self):
        """Validates that identical PE binaries yield 100% metadata similarity."""
        diff = MetadataDiffer.compare(self.baseline_pe, self.baseline_pe)
        self.assertEqual(diff.similarity_score, 1.0)
        self.assertEqual(len(diff.header_changes), 0)
        self.assertEqual(len(diff.injected_sections), 0)
        for s in diff.section_diffs:
            self.assertEqual(s.change_type, ChangeType.UNCHANGED)
            self.assertEqual(s.raw_size_delta, 0)
            self.assertFalse(s.is_injected)

    def test_metadata_differ_section_injection(self):
        """Verifies detection of injected protector sections (.necro, .eazvm)."""
        # Inject synthetic .necro section into PE section table
        mutated = bytearray(self.baseline_pe)
        e_lfanew = struct.unpack_from("<I", mutated, 60)[0]
        num_sec = struct.unpack_from("<H", mutated, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", mutated, e_lfanew + 20)[0]
        sec_start = e_lfanew + 24 + opt_hdr_size

        # Increment section count
        struct.pack_into("<H", mutated, e_lfanew + 6, num_sec + 1)
        # Append .necro section entry
        new_sec_offset = sec_start + (num_sec * 40)
        if new_sec_offset + 40 <= len(mutated):
            mutated[new_sec_offset:new_sec_offset+8] = b".necro\x00\x00"
            struct.pack_into("<IIII", mutated, new_sec_offset + 8, 0x1000, 0x4000, 0x1000, len(mutated))
            mutated.extend(b"\x90" * 0x1000)

            diff = MetadataDiffer.compare(self.baseline_pe, bytes(mutated))
            self.assertIn(".necro", diff.injected_sections)
            self.assertLess(diff.similarity_score, 1.0)
            sec_names = [s.name for s in diff.section_diffs]
            self.assertIn(".necro", sec_names)

    def test_bytecode_differ_identical_and_normalization(self):
        """Verifies CIL bytecode differ behavior on identical and normalized opcodes."""
        # Simple method: ldc.i4.0; stloc.0; ldloc.0; ret
        code = b"\x16\xfe\x0e\x00\x00\x11\x00\x2a"
        score, metrics = BytecodeDiffer.compare_bytecodes(code, code)
        self.assertEqual(score, 1.0)
        self.assertEqual(metrics["opcode_jaccard"], 1.0)
        self.assertEqual(metrics["token_edit_similarity"], 1.0)

        # Mutated method with different constants: ldc.i4.1; stloc.0; ldloc.0; ret
        code_b = b"\x17\xfe\x0e\x00\x00\x11\x00\x2a"
        score_mut, metrics_mut = BytecodeDiffer.compare_bytecodes(code, code_b)
        # Because ldc.i4 is normalized, similarity should be very high
        self.assertGreaterEqual(score_mut, 0.9)

    def test_bytecode_differ_edit_distance_and_ngrams(self):
        """Validates edit distance and n-gram calculation across diverging instructions."""
        code_a = b"\x16\x17\x18\x2a"  # ldc.i4.0; ldc.i4.1; ldc.i4.2; ret
        code_b = b"\x20\x00\x00\x00\x00\x2a"  # ldc.i4 0; ret
        score, metrics = BytecodeDiffer.compare_bytecodes(code_a, code_b)
        self.assertLess(score, 1.0)
        self.assertGreater(score, 0.0)
        self.assertIn("opcode_jaccard", metrics)
        self.assertIn("n_gram_similarity", metrics)

    def test_cfg_differ_identical_and_cyclomatic_delta(self):
        """Verifies CFG graph comparison and cyclomatic complexity metrics."""
        code_linear = b"\x16\x2a"  # ldc.i4.0; ret
        score, metrics = CFGDiffer.compare_method_cfgs(code_linear, code_linear)
        self.assertEqual(score, 1.0)
        self.assertEqual(metrics["cyclomatic_delta"], 0)
        self.assertFalse(metrics["is_flattened"])

        # Method with conditional branch: ldc.i4.0; brtrue.s +2; ldc.i4.1; ret; ret
        code_branch = b"\x16\x2d\x01\x17\x2a\x2a"
        score_br, metrics_br = CFGDiffer.compare_method_cfgs(code_linear, code_branch)
        self.assertLess(score_br, 1.0)
        self.assertGreaterEqual(metrics_br["cyclomatic_delta"], 0)

    def test_cfg_differ_control_flow_flattening_detection(self):
        """Validates heuristic detection of state-machine dispatcher flattening."""
        # Baseline linear method (1 block)
        code_linear = b"\x16\x17\x18\x19\x1a\x2a"
        # Synthetic flattened dispatcher: switch statement with 4 targets looping back
        # switch (0x45): count (4), targets...
        code_flat = bytearray()
        # Dispatcher block
        code_flat.extend(b"\x11\x00")  # ldloc.0
        code_flat.extend(b"\x45\x04\x00\x00\x00")  # switch count=4
        # 4 relative offsets (e.g. 16, 20, 24, 28)
        code_flat.extend(struct.pack("<IIII", 16, 20, 24, 28))
        # Target 1
        code_flat.extend(b"\x16\x38\xe0\xff\xff\xff")  # ldc.i4.0; br back to dispatcher
        # Target 2
        code_flat.extend(b"\x17\x38\xd5\xff\xff\xff")  # ldc.i4.1; br back
        # Target 3
        code_flat.extend(b"\x18\x38\xca\xff\xff\xff")  # ldc.i4.2; br back
        # Target 4
        code_flat.extend(b"\x2a")  # ret

        score_flat, metrics_flat = CFGDiffer.compare_method_cfgs(code_linear, bytes(code_flat))
        self.assertTrue(metrics_flat["is_flattened"])
        self.assertLess(score_flat, 0.5)

    def test_ast_differ_opaque_predicates(self):
        """Verifies detection of injected opaque predicates and statement matching."""
        code_clean = b"\x16\x2a"  # ldc.i4.0; ret
        score_clean, m_clean = ASTDiffer.compare_method_ast(code_clean, code_clean)
        self.assertEqual(score_clean, 1.0)
        self.assertEqual(m_clean["opaque_predicates"], 0)

        # Code with injected tautology: ldc.i4.1; brtrue.s +0; ldc.i4.0; ret
        code_opaque = b"\x17\x2d\x00\x16\x2a"
        score_op, m_op = ASTDiffer.compare_method_ast(code_clean, code_opaque)
        self.assertGreaterEqual(m_op["opaque_predicates"], 1)
        self.assertLess(score_op, 1.0)

    def test_binary_diff_engine_identical_binaries(self):
        """Validates end-to-end BinaryDiffEngine on identical PE binaries."""
        res = BinaryDiffEngine.compare(
            self.baseline_pe,
            self.baseline_pe,
            name_a="baseline.exe",
            name_b="baseline.exe",
        )
        self.assertEqual(res.composite_similarity, 1.0)
        self.assertEqual(res.diff_category, DiffCategory.IDENTICAL)
        self.assertEqual(res.detected_impacts, [ObfuscationImpact.NONE])
        self.assertEqual(res.telemetry.identical_methods, len(res.method_diffs))
        self.assertEqual(res.telemetry.modified_methods, 0)
        self.assertEqual(res.telemetry.added_methods, 0)
        self.assertEqual(res.telemetry.removed_methods, 0)

    def test_binary_diff_engine_mutated_binaries(self):
        """Validates end-to-end BinaryDiffEngine on mutated PE binaries."""
        # Mutate baseline binary with high-entropy noise in trailing bytes
        mutated = bytearray(self.baseline_pe)
        mutated.extend(os.urandom(1024))

        res = BinaryDiffEngine.compare(
            self.baseline_pe,
            bytes(mutated),
            name_a="original.exe",
            name_b="mutated.exe",
        )
        self.assertLess(res.composite_similarity, 1.0)
        self.assertNotEqual(res.diff_category, DiffCategory.IDENTICAL)
        self.assertIsNotNone(res.telemetry.comparison_time_ms)

    def test_format_text_diff(self):
        """Verifies terminal text diff report formatting."""
        res = BinaryDiffEngine.compare(
            self.baseline_pe,
            self.baseline_pe,
            name_a="target_a.exe",
            name_b="target_b.exe",
        )
        text = BinaryDiffEngine.format_text_diff(res)
        self.assertIn("Multi-Engine Binary Diff Report", text)
        self.assertIn("Composite Similarity : 100.00%", text)
        self.assertIn("Metadata Layer", text)
        self.assertIn("Bytecode Layer", text)
        self.assertIn("CFG Graph", text)
        self.assertIn("AST Semantics", text)

    def test_html_diff_reporter_integrity(self):
        """Validates self-contained HTML visual report generation and zero CDN leaks."""
        res = BinaryDiffEngine.compare(
            self.baseline_pe,
            self.baseline_pe,
            name_a="test_a.exe",
            name_b="test_b.exe",
        )
        html_content = HTMLDiffReporter.generate(res)
        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("Multi-Engine Binary Forensic Diff", html_content)
        self.assertIn("Composite Similarity", html_content)
        # Ensure zero external web font or script leaks
        self.assertNotIn("http://", html_content)
        self.assertNotIn("https://", html_content)
        self.assertNotIn("<script src=", html_content)
        self.assertNotIn("<link rel=\"stylesheet\" href=\"http", html_content)

    def test_export_to_directory(self):
        """Validates file creation and structure when exporting diff reports."""
        res = BinaryDiffEngine.compare(
            self.baseline_pe,
            self.baseline_pe,
            name_a="source_a.exe",
            name_b="source_b.exe",
        )
        out_dir = os.path.join(self.temp_dir, "diff_export")
        export_meta = BinaryDiffEngine.export_to_directory(res, output_dir=out_dir)

        self.assertEqual(export_meta["files_count"], 4)
        self.assertTrue(os.path.exists(export_meta["exported_files"]["json"]))
        self.assertTrue(os.path.exists(export_meta["exported_files"]["csv"]))
        self.assertTrue(os.path.exists(export_meta["exported_files"]["txt"]))
        self.assertTrue(os.path.exists(export_meta["exported_files"]["html"]))

        # Check JSON integrity
        with open(export_meta["exported_files"]["json"], "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["composite_similarity"], 1.0)
            self.assertEqual(data["diff_category"], "identical")

    def test_core_facade_and_files(self):
        """Validates DotNetPackerCore.diff_binaries and export_diff_report."""
        file_a = os.path.join(self.temp_dir, "sample_a.exe")
        file_b = os.path.join(self.temp_dir, "sample_b.exe")
        with open(file_a, "wb") as f:
            f.write(self.baseline_pe)
        with open(file_b, "wb") as f:
            f.write(self.baseline_pe)

        res = DotNetPackerCore.diff_binaries(file_a, file_b)
        self.assertIsInstance(res, BinaryDiffResult)
        self.assertEqual(res.composite_similarity, 1.0)

        out_dir = os.path.join(self.temp_dir, "core_export")
        exp = DotNetPackerCore.export_diff_report(res, output_dir=out_dir)
        self.assertEqual(exp["files_count"], 4)

    def test_cli_diff_mode_text_and_json(self):
        """Validates CLI invocation with --diff / --diff-against across text and json formats."""
        file_a = os.path.join(self.temp_dir, "cli_a.exe")
        file_b = os.path.join(self.temp_dir, "cli_b.exe")
        with open(file_a, "wb") as f:
            f.write(self.baseline_pe)
        with open(file_b, "wb") as f:
            f.write(self.baseline_pe)

        # 1. Text diff format
        old_stdout = io.StringIO()
        try:
            import sys
            saved = sys.stdout
            sys.stdout = old_stdout
            ret = main([file_a, "--diff", file_b])
            output = old_stdout.getvalue()
        finally:
            sys.stdout = saved

        self.assertEqual(ret, 0)
        self.assertIn("Multi-Engine Binary Diff Report", output)
        self.assertIn("Composite Similarity", output)

        # 2. JSON diff format
        old_stdout_json = io.StringIO()
        try:
            saved = sys.stdout
            sys.stdout = old_stdout_json
            ret_json = main([file_a, "--diff", file_b, "--format", "json"])
            output_json = old_stdout_json.getvalue()
        finally:
            sys.stdout = saved

        self.assertEqual(ret_json, 0)
        parsed = json.loads(output_json)
        self.assertEqual(parsed["composite_similarity"], 1.0)
        self.assertEqual(parsed["diff_category"], "identical")

    def test_cli_diff_export_flags(self):
        """Validates CLI flags --diff-out, --diff-html, and --diff-json."""
        file_a = os.path.join(self.temp_dir, "exp_a.exe")
        file_b = os.path.join(self.temp_dir, "exp_b.exe")
        with open(file_a, "wb") as f:
            f.write(self.baseline_pe)
        with open(file_b, "wb") as f:
            f.write(self.baseline_pe)

        diff_out_dir = os.path.join(self.temp_dir, "cli_diff_out")
        html_out_file = os.path.join(self.temp_dir, "custom_report.html")
        json_out_file = os.path.join(self.temp_dir, "custom_summary.json")

        old_stdout = io.StringIO()
        try:
            import sys
            saved = sys.stdout
            sys.stdout = old_stdout
            ret = main([
                file_a,
                "--diff", file_b,
                "--diff-out", diff_out_dir,
                "--diff-html", html_out_file,
                "--diff-json", json_out_file,
            ])
        finally:
            sys.stdout = saved

        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(diff_out_dir, "diff_summary.json")))
        self.assertTrue(os.path.exists(os.path.join(diff_out_dir, "diff_report.html")))
        self.assertTrue(os.path.exists(html_out_file))
        self.assertTrue(os.path.exists(json_out_file))


if __name__ == "__main__":
    unittest.main()
