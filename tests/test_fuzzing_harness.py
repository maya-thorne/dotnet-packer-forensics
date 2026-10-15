"""
Comprehensive Unit & Integration Test Suite for Regression Fuzzing Harness & Synthetic Mutated Binary Generator.
Engineered & Audited by Maya Thorne.
"""

import io
import json
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator import (
    CrashSeverity,
    DotNetAnalyzer,
    DotNetPackerCore,
    FuzzCampaignResult,
    FuzzExecutionResult,
    FuzzTarget,
    MutationRecord,
    MutationStrategy,
    PayloadVerifier,
    RegressionFuzzingHarness,
    RegressionLedger,
    SyntheticMutatedBinaryGenerator,
)
from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.fuzzing.models import SecurityError, safe_path, zeroize_buffer
from dotnet_deobfuscator.mixed_mode.analyzer import MixedModeAnalyzer
from dotnet_deobfuscator.pe_rebuilder import PERebuilder
from dotnet_deobfuscator.unpackers.antidump_healer import AntiDumpHealer


class TestFuzzingHarness(unittest.TestCase):
    """Test suite for synthetic mutated binary generation and regression fuzzing harness."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="test_fuzz_")
        self.baseline_pe = SyntheticMutatedBinaryGenerator.generate_baseline_pe()

    def tearDown(self) -> None:
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. Baseline Synthetic PE Generation Tests
    def test_baseline_pe_generation_validity(self) -> None:
        """Verifies that generated baseline PE is structurally valid and recognized as .NET assembly."""
        self.assertGreaterEqual(len(self.baseline_pe), 0x600)
        self.assertTrue(self.baseline_pe.startswith(b"MZ"))

        # Verify through DotNetAnalyzer
        analysis = DotNetAnalyzer.inspect_assembly(self.baseline_pe)
        self.assertTrue(analysis["is_pe"])
        self.assertTrue(analysis["is_dotnet"])
        self.assertGreater(len(analysis["sections"]), 0)

        # Verify through PayloadVerifier
        pe_report, findings = PayloadVerifier.verify_pe_structure(self.baseline_pe, strict=False)
        self.assertTrue(pe_report.is_pe)
        self.assertTrue(pe_report.is_dotnet)
        self.assertTrue(pe_report.has_cor20_header)

    # 2. Mutation Strategy Tests
    def test_mutation_bit_flips(self) -> None:
        """Verifies bit flipping mutation operator."""
        import random
        prng = random.Random(1234)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_bit_flips(buf, prng, flip_count=3)
        self.assertEqual(len(records), 3)
        self.assertNotEqual(bytes(buf), self.baseline_pe)
        for r in records:
            self.assertEqual(r.strategy, MutationStrategy.BIT_FLIP)
            self.assertIn("Bit flip", r.description)

    def test_mutation_byte_noise(self) -> None:
        """Verifies byte noise replacement mutation operator."""
        import random
        prng = random.Random(5678)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_byte_noise(buf, prng, count=5)
        self.assertEqual(len(records), 5)
        for r in records:
            self.assertEqual(r.strategy, MutationStrategy.BYTE_NOISE)

    def test_mutation_dos_header(self) -> None:
        """Verifies DOS header and e_lfanew mangling."""
        import random
        prng = random.Random(100)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_dos_header(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.DOS_HEADER_MANGLE)

    def test_mutation_nt_header(self) -> None:
        """Verifies NT header signature and machine architecture mangling."""
        import random
        prng = random.Random(200)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_nt_header(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.NT_HEADER_MANGLE)

    def test_mutation_optional_header(self) -> None:
        """Verifies Optional Header magic, alignment, and data directory mangling."""
        import random
        prng = random.Random(300)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_optional_header(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.OPTIONAL_HEADER_MANGLE)

    def test_mutation_section_table(self) -> None:
        """Verifies section header names, raw offsets, and size mangling."""
        import random
        prng = random.Random(400)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_section_table(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.SECTION_TABLE_MANGLE)

    def test_mutation_cor20_descriptor(self) -> None:
        """Verifies Cor20Header COM descriptor mangling."""
        import random
        prng = random.Random(500)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_cor20_descriptor(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.COR20_DESCRIPTOR_MANGLE)

    def test_mutation_metadata_streams(self) -> None:
        """Verifies BSJB CLI metadata header and stream table mangling."""
        import random
        prng = random.Random(600)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_metadata_streams(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.METADATA_STREAM_MANGLE)

    def test_mutation_cil_instructions(self) -> None:
        """Verifies CIL instruction injection (invalid opcodes, branches, stack underflow)."""
        import random
        prng = random.Random(700)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_cil_instructions(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.CIL_BYTECODE_FUZZ)

    def test_mutation_overlay_slack(self) -> None:
        """Verifies overlay noise and fake signature injection."""
        import random
        prng = random.Random(800)
        buf = bytearray(self.baseline_pe)
        records = SyntheticMutatedBinaryGenerator.mutate_overlay_slack(buf, prng)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.OVERLAY_INJECTION)
        self.assertGreater(len(buf), len(self.baseline_pe))

    def test_mutation_truncation(self) -> None:
        """Verifies binary truncation at architectural boundaries."""
        import random
        prng = random.Random(900)
        buf = bytearray(self.baseline_pe)
        orig_len = len(buf)
        records = SyntheticMutatedBinaryGenerator.mutate_truncation(buf, prng)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].strategy, MutationStrategy.TRUNCATION)
        self.assertLess(len(buf), orig_len)

    # 3. Corpus Generation Tests
    def test_generate_corpus(self) -> None:
        """Verifies generating a corpus of synthetic mutants."""
        corpus = SyntheticMutatedBinaryGenerator.generate_corpus(
            base_binary=self.baseline_pe, count=5, seed=42
        )
        self.assertEqual(len(corpus), 5)
        for mutant_bytes, recs in corpus:
            self.assertGreater(len(mutant_bytes), 0)
            self.assertGreater(len(recs), 0)

    # 4. Harness Subsystem Target Execution Tests
    def test_harness_execute_target_clean_pass(self) -> None:
        """Verifies baseline PE executes cleanly across all individual forensic targets."""
        for tgt in [
            FuzzTarget.ANALYZE,
            FuzzTarget.REBUILD,
            FuzzTarget.VERIFY,
            FuzzTarget.CFG,
            FuzzTarget.BAML,
            FuzzTarget.MIXED_MODE,
            FuzzTarget.ANTIDUMP,
            FuzzTarget.ANTITAMPER,
            FuzzTarget.RULES,
        ]:
            sev, e_cls, e_msg, e_tb = RegressionFuzzingHarness.execute_target(tgt, self.baseline_pe)
            self.assertEqual(sev, CrashSeverity.CLEAN_PASS, f"Target {tgt.value} failed: {e_cls}: {e_msg}")

    def test_harness_execute_all_targets(self) -> None:
        """Verifies running the composite FuzzTarget.ALL target."""
        sev, e_cls, e_msg, _ = RegressionFuzzingHarness.execute_target(FuzzTarget.ALL, self.baseline_pe)
        self.assertEqual(sev, CrashSeverity.CLEAN_PASS)

    def test_harness_handled_error_on_corrupted_data(self) -> None:
        """Verifies harness captures graceful parser rejections without unhandled exceptions."""
        corrupted = b"MZ" + b"\x00" * 30 + b"\xFF" * 10
        sev, e_cls, _, _ = RegressionFuzzingHarness.execute_target(FuzzTarget.ALL, corrupted)
        self.assertIn(sev, (CrashSeverity.CLEAN_PASS, CrashSeverity.HANDLED_ERROR))

    def test_harness_timeout_detection(self) -> None:
        """Verifies timeout detection when per-iteration limit is exceeded."""
        # Use a near-zero timeout (0.0000001s) to trigger timeout hang
        sev, e_cls, _, _ = RegressionFuzzingHarness.execute_target(
            FuzzTarget.ALL, self.baseline_pe, timeout_sec=0.000001
        )
        self.assertEqual(sev, CrashSeverity.TIMEOUT_HANG)
        self.assertEqual(e_cls, "TimeoutError")

    # 5. End-to-End Campaign Tests
    def test_fuzzing_campaign_execution(self) -> None:
        """Executes a complete 10-iteration deterministic fuzzing campaign."""
        res = RegressionFuzzingHarness.run_campaign(
            base_binary=self.baseline_pe,
            iterations=10,
            seed=1337,
            targets=[FuzzTarget.ANALYZE, FuzzTarget.VERIFY],
            output_dir=self.tmp_dir,
        )
        self.assertIsInstance(res, FuzzCampaignResult)
        self.assertEqual(res.telemetry.total_iterations, 10)
        self.assertEqual(len(res.executions), 10)
        self.assertFalse(res.telemetry.has_regressions)

        # Check exported files
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, "campaign_report.json")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, "fuzzing_summary.txt")))

    # 6. Replay & Regression Ledger Tests
    def test_crash_replay_and_ledger(self) -> None:
        """Verifies regression crash recording and replaying."""
        ledger = RegressionLedger()
        mock_exec = FuzzExecutionResult(
            iteration=1,
            seed=999,
            target="all",
            strategies=["bit_flip"],
            severity=CrashSeverity.REGRESSION_CRASH,
            duration_ms=1.2,
            sample_sha256="0123456789abcdef",
            sample_size=1024,
            exception_class="SimulatedCrashError",
            exception_message="Synthetic parser failure",
        )
        entry = ledger.record_crash(mock_exec, b"dummy_crash_bytes", notes="Unit test entry")
        self.assertEqual(entry["exception_class"], "SimulatedCrashError")

        ledger_path = os.path.join(self.tmp_dir, "test_ledger.json")
        ledger.save_to_file(ledger_path)
        self.assertTrue(os.path.exists(ledger_path))

        new_ledger = RegressionLedger()
        count = new_ledger.load_from_file(ledger_path)
        self.assertEqual(count, 1)
        self.assertEqual(new_ledger.entries[0]["seed"], 999)

        # Replay crash
        replay_res = RegressionFuzzingHarness.replay_crash(FuzzTarget.ANALYZE, self.baseline_pe)
        self.assertEqual(replay_res.severity, CrashSeverity.CLEAN_PASS)

    # 7. Core Integration Methods Tests
    def test_core_fuzzing_methods(self) -> None:
        """Verifies DotNetPackerCore.run_fuzzing_campaign and generate_synthetic_corpus."""
        # Test campaign via core
        res = DotNetPackerCore.run_fuzzing_campaign(iterations=5, seed=42)
        self.assertEqual(res.telemetry.total_iterations, 5)

        # Test corpus generation via core
        corpus = DotNetPackerCore.generate_synthetic_corpus(count=3, seed=77, output_dir=self.tmp_dir)
        self.assertEqual(len(corpus), 3)
        self.assertTrue(os.path.exists(corpus[0]["path"]))

    # 8. CLI Command Integration Tests
    def test_cli_fuzz_flag(self) -> None:
        """Verifies CLI execution with --fuzz and text formatting."""
        code = main(["--fuzz", "--fuzz-iterations", "3", "--fuzz-seed", "123"])
        self.assertEqual(code, 0)

    def test_cli_fuzz_json_flag(self) -> None:
        """Verifies CLI execution with --fuzz and JSON output formatting."""
        code = main(["--fuzz", "--fuzz-iterations", "2", "--format", "json"])
        self.assertEqual(code, 0)

    def test_cli_gen_mutants_flag(self) -> None:
        """Verifies CLI execution with --gen-mutants."""
        out_dir = os.path.join(self.tmp_dir, "cli_mutants")
        code = main(["--gen-mutants", "--mutant-count", "2", "-o", out_dir])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_dir))
        self.assertEqual(len(os.listdir(out_dir)), 2)

    # 9. Security & Boundary Guardrail Tests
    def test_path_traversal_prevention(self) -> None:
        """Verifies safe_path rejects path traversal attempts."""
        with self.assertRaises(SecurityError):
            safe_path(self.tmp_dir, "../../secret_escape.bin")

    def test_zeroize_buffer_security(self) -> None:
        """Verifies zeroize_buffer zeroes out bytearray memory in-place."""
        buf = bytearray(b"SENSITIVE_KEY_AND_DEOBFUSCATOR_PAYLOAD")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(buf)))

    # 10. Adversarial Edge Case & Hardening Tests
    def test_baseline_pe64_generation_validity(self) -> None:
        """Verifies that generated 64-bit PE32+ baseline is structurally valid."""
        pe64 = SyntheticMutatedBinaryGenerator.generate_baseline_pe(is_64bit=True)
        self.assertGreaterEqual(len(pe64), 0x600)
        self.assertTrue(pe64.startswith(b"MZ"))

        # Verify through DotNetAnalyzer
        analysis = DotNetAnalyzer.inspect_assembly(pe64)
        self.assertTrue(analysis["is_pe"])
        self.assertTrue(analysis["is_dotnet"])

        # Verify through PayloadVerifier
        pe_report, _ = PayloadVerifier.verify_pe_structure(pe64, strict=False)
        self.assertTrue(pe_report.is_pe)
        self.assertTrue(pe_report.is_dotnet)
        self.assertTrue(pe_report.has_cor20_header)
        self.assertIn("AMD64", pe_report.machine)

    def test_regression_ledger_resilience_corrupted_json(self) -> None:
        """Verifies RegressionLedger.load_from_file gracefully handles corrupt/malformed files."""
        # 1. Non-existent file
        ledger = RegressionLedger()
        self.assertEqual(ledger.load_from_file(os.path.join(self.tmp_dir, "missing.json")), 0)

        # 2. 0-byte empty file
        empty_path = os.path.join(self.tmp_dir, "empty.json")
        with open(empty_path, "w", encoding="utf-8") as f:
            f.write("")
        self.assertEqual(ledger.load_from_file(empty_path), 0)

        # 3. Corrupted / truncated JSON
        corrupt_path = os.path.join(self.tmp_dir, "corrupt.json")
        with open(corrupt_path, "w", encoding="utf-8") as f:
            f.write('{"version": "1.0", "entries": [{"iteration": 1, "seed": 99')
        self.assertEqual(ledger.load_from_file(corrupt_path), 0)

        # 4. JSON root is list
        list_path = os.path.join(self.tmp_dir, "list.json")
        with open(list_path, "w", encoding="utf-8") as f:
            json.dump([{"iteration": 1, "seed": 101, "target": "analyze"}], f)
        self.assertEqual(ledger.load_from_file(list_path), 1)

        # 5. Invalid entries format (entries is integer)
        invalid_entries_path = os.path.join(self.tmp_dir, "invalid_entries.json")
        with open(invalid_entries_path, "w", encoding="utf-8") as f:
            json.dump({"entries": 12345}, f)
        self.assertEqual(ledger.load_from_file(invalid_entries_path), 0)

    def test_regression_ledger_crash_without_bytes(self) -> None:
        """Verifies record_crash preserves execution's sha256 and size when binary_bytes is None."""
        ledger = RegressionLedger()
        mock_exec = FuzzExecutionResult(
            iteration=5,
            seed=4242,
            target="rebuild",
            strategies=["truncation"],
            severity=CrashSeverity.REGRESSION_CRASH,
            duration_ms=0.5,
            sample_sha256="aabbccddeeff00112233445566778899",
            sample_size=2048,
            exception_class="MockCrash",
            exception_message="Synthetic failure",
        )
        entry = ledger.record_crash(mock_exec, None, notes="Testing None bytes")
        self.assertEqual(entry["sample_sha256"], "aabbccddeeff00112233445566778899")
        self.assertEqual(entry["sample_size"], 2048)

    def test_fuzz_target_aliases_and_normalization(self) -> None:
        """Verifies FuzzTarget.from_str supports alias mapping and case insensitivity."""
        self.assertEqual(FuzzTarget.from_str("overlay"), FuzzTarget.ANALYZE)
        self.assertEqual(FuzzTarget.from_str("entropy"), FuzzTarget.CFG)
        self.assertEqual(FuzzTarget.from_str("WPF"), FuzzTarget.BAML)
        self.assertEqual(FuzzTarget.from_str("mixed-mode"), FuzzTarget.MIXED_MODE)
        self.assertEqual(FuzzTarget.from_str("anti-tamper"), FuzzTarget.ANTITAMPER)
        self.assertEqual(FuzzTarget.from_str("threat"), FuzzTarget.RULES)

        with self.assertRaises(ValueError):
            FuzzTarget.from_str("completely_unknown_target_subsystem")

        # Verify passing string alias to execute_target
        sev, _, _, _ = RegressionFuzzingHarness.execute_target("overlay", self.baseline_pe)
        self.assertEqual(sev, CrashSeverity.CLEAN_PASS)

    def test_harness_active_watchdog_timeout(self) -> None:
        """Verifies active watchdog thread terminates stalling target without infinite hang."""
        import time

        def slow_worker(data: bytes) -> None:
            time.sleep(0.1)

        # Temporarily mock CFGAnalyzer.analyze with slow worker
        orig = DotNetAnalyzer.inspect_assembly
        try:
            DotNetAnalyzer.inspect_assembly = slow_worker
            sev, e_cls, _, _ = RegressionFuzzingHarness.execute_target(
                FuzzTarget.ANALYZE, self.baseline_pe, timeout_sec=0.01
            )
            self.assertEqual(sev, CrashSeverity.TIMEOUT_HANG)
            self.assertEqual(e_cls, "TimeoutError")
        finally:
            DotNetAnalyzer.inspect_assembly = orig

    def test_harness_subprocess_isolation(self) -> None:
        """Verifies execute_target in child OS subprocess mode."""
        sev, e_cls, e_msg, _ = RegressionFuzzingHarness.execute_target(
            FuzzTarget.ANALYZE, self.baseline_pe, timeout_sec=5.0, isolate_process=True
        )
        self.assertEqual(sev, CrashSeverity.CLEAN_PASS)

    def test_core_file_not_found_on_invalid_target(self) -> None:
        """Verifies DotNetPackerCore raises FileNotFoundError when target path is invalid."""
        with self.assertRaises(FileNotFoundError):
            DotNetPackerCore.run_fuzzing_campaign(target_path="nonexistent_target_12345.exe")
        with self.assertRaises(FileNotFoundError):
            DotNetPackerCore.generate_synthetic_corpus(base_path="nonexistent_base_12345.exe")

    def test_cli_fuzz_new_flags(self) -> None:
        """Verifies CLI execution with --fuzz-64, --fuzz-isolate, and target aliases."""
        code1 = main(["--fuzz", "--fuzz-64", "--fuzz-iterations", "2", "--fuzz-seed", "555"])
        self.assertEqual(code1, 0)

        code2 = main(["--fuzz", "--fuzz-isolate", "--fuzz-iterations", "1", "--fuzz-seed", "777"])
        self.assertEqual(code2, 0)

        code3 = main(["--fuzz", "--fuzz-targets", "overlay,entropy", "--fuzz-iterations", "2"])
        self.assertEqual(code3, 0)

        out_64 = os.path.join(self.tmp_dir, "cli_64_mutants")
        code4 = main(["--gen-mutants", "--fuzz-64", "--mutant-count", "2", "-o", out_64])
        self.assertEqual(code4, 0)
        self.assertTrue(os.path.exists(out_64))
        self.assertEqual(len(os.listdir(out_64)), 2)

    def test_large_binary_rejection_boundary(self) -> None:
        """Verifies harness rejects binaries exceeding MAX_BINARY_SIZE."""
        huge_binary = b"MZ" + b"\x00" * 10
        orig_max = RegressionFuzzingHarness.MAX_BINARY_SIZE
        try:
            RegressionFuzzingHarness.MAX_BINARY_SIZE = 5  # artificially lower limit to 5 bytes
            sev, e_cls, e_msg, _ = RegressionFuzzingHarness.execute_target(
                FuzzTarget.ANALYZE, huge_binary
            )
            self.assertEqual(sev, CrashSeverity.RESOURCE_EXHAUSTION)
            self.assertEqual(e_cls, "SecurityError")
        finally:
            RegressionFuzzingHarness.MAX_BINARY_SIZE = orig_max

    def test_harness_subprocess_hard_crash_preserves_traceback(self) -> None:
        """Verifies subprocess termination with non-zero exit code preserves stderr traceback snippet."""
        import subprocess
        from unittest.mock import patch, MagicMock

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Traceback (most recent call last):\n  File 'test.py', line 1\nAssertionError: hard crash")
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()

        with patch("subprocess.Popen", return_value=mock_proc):
            sev, e_cls, e_msg, tb = RegressionFuzzingHarness._execute_in_subprocess(
                FuzzTarget.ANALYZE, self.baseline_pe, timeout_sec=1.0
            )
            self.assertEqual(sev, CrashSeverity.REGRESSION_CRASH)
            self.assertEqual(e_cls, "ProcessAbortedError")
            self.assertIn("AssertionError: hard crash", e_msg)
            self.assertIsNotNone(tb)
            self.assertIn("Traceback (most recent call last)", tb)

    def test_harness_subprocess_polluted_stdout_resilience(self) -> None:
        """Verifies _extract_json_payload extracts result even when stdout contains warnings or prints."""
        polluted_stdout = (
            "RuntimeWarning: Some package warning on stdout\n"
            "Diagnostic: analyzing binary...\n"
            "__FUZZ_RESULT_JSON_START__\n"
            '{"severity": "clean_pass", "e_cls": null, "e_msg": null, "tb": null}\n'
            "__FUZZ_RESULT_JSON_END__\n"
            "Trailing line\n"
        )
        data = RegressionFuzzingHarness._extract_json_payload(polluted_stdout)
        self.assertIsNotNone(data)
        self.assertEqual(data["severity"], "clean_pass")

        # Test fallback reverse scanning
        polluted_no_markers = (
            "Some banner\n"
            '{"severity": "handled_error", "e_cls": "ValueError", "e_msg": "Bad input", "tb": null}\n'
        )
        data2 = RegressionFuzzingHarness._extract_json_payload(polluted_no_markers)
        self.assertIsNotNone(data2)
        self.assertEqual(data2["severity"], "handled_error")

    def test_regression_ledger_records_traceback_snippet(self) -> None:
        """Verifies record_crash persists traceback_snippet into entry['traceback']."""
        ledger = RegressionLedger()
        mock_exec = FuzzExecutionResult(
            iteration=1,
            seed=123,
            target="cfg",
            strategies=["bit_flip"],
            severity=CrashSeverity.REGRESSION_CRASH,
            duration_ms=1.2,
            sample_sha256="11223344",
            sample_size=1024,
            exception_class="KeyError",
            exception_message="'#Strings'",
            traceback_snippet="Traceback (most recent call last):\n  File 'cfg.py', line 42",
        )
        entry = ledger.record_crash(mock_exec, notes="Traceback recording test")
        self.assertEqual(entry["traceback"], "Traceback (most recent call last):\n  File 'cfg.py', line 42")

    def test_subprocess_worker_cli_stdin_dash_mode(self) -> None:
        """Verifies harness worker CLI reads binary from stdin when '-' is provided."""
        import subprocess
        import sys

        cmd = [sys.executable, "-m", "dotnet_deobfuscator.fuzzing.harness", "analyze", "-", "2.0"]
        res = subprocess.run(cmd, input=self.baseline_pe, capture_output=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn(b"__FUZZ_RESULT_JSON_START__", res.stdout)
        self.assertIn(b'"severity": "clean_pass"', res.stdout)

        # Verifies CLI usage failure on missing arguments
        res_fail = subprocess.run([sys.executable, "-m", "dotnet_deobfuscator.fuzzing.harness"], capture_output=True)
        self.assertEqual(res_fail.returncode, 1)
        self.assertIn(b"Usage:", res_fail.stderr)


    def test_adversarial_zero_length_and_sub_header_buffers(self) -> None:
        """Verifies generator and harness gracefully handle empty and sub-header buffers."""
        empty_buf = b""
        mut_empty, recs_empty = SyntheticMutatedBinaryGenerator.mutate_binary(empty_buf, seed=42, mutation_depth=3)
        self.assertEqual(len(mut_empty), 0)
        self.assertEqual(len(recs_empty), 0)

        # Execute harness against empty and minimal inputs
        for tgt in [FuzzTarget.ANALYZE, FuzzTarget.REBUILD, FuzzTarget.VERIFY, FuzzTarget.MIXED_MODE, FuzzTarget.ANTIDUMP]:
            sev, e_cls, e_msg, tb = RegressionFuzzingHarness.execute_target(tgt, empty_buf)
            self.assertIn(sev, (CrashSeverity.CLEAN_PASS, CrashSeverity.HANDLED_ERROR))

        # Single byte buffer
        single_byte = b"M"
        for tgt in [FuzzTarget.ANALYZE, FuzzTarget.REBUILD, FuzzTarget.VERIFY]:
            sev, _, _, _ = RegressionFuzzingHarness.execute_target(tgt, single_byte)
            self.assertIn(sev, (CrashSeverity.CLEAN_PASS, CrashSeverity.HANDLED_ERROR))

    def test_adversarial_extreme_entropy_and_boundary_depth(self) -> None:
        """Verifies generator and harness under extreme entropy and deep mutation depth."""
        # 1024 bytes of 0xFF (extreme entropy) and 0x00 (zero entropy)
        ff_buf = b"\xFF" * 1024
        zero_buf = b"\x00" * 1024

        mut_ff, recs_ff = SyntheticMutatedBinaryGenerator.mutate_binary(ff_buf, seed=999, mutation_depth=20)
        self.assertGreater(len(recs_ff), 0)

        mut_zero, recs_zero = SyntheticMutatedBinaryGenerator.mutate_binary(zero_buf, seed=888, mutation_depth=20)
        self.assertGreater(len(recs_zero), 0)

        for tgt in [FuzzTarget.ANALYZE, FuzzTarget.REBUILD, FuzzTarget.RULES]:
            sev, _, _, _ = RegressionFuzzingHarness.execute_target(tgt, mut_ff)
            self.assertIn(sev, (CrashSeverity.CLEAN_PASS, CrashSeverity.HANDLED_ERROR))

    def test_adversarial_rebuild_and_antidump_gigabyte_section_defense(self) -> None:
        """Verifies memory safety and bounds defense when sections declare 2GB sizes."""
        # Create a PE with a section claiming 0x7FFFFFFF raw/virtual size
        base = bytearray(self.baseline_pe)
        # Find .text section header in section table and corrupt size
        sec_idx = base.find(b".text\x00\x00\x00")
        if sec_idx != -1:
            struct.pack_into("<I", base, sec_idx + 8, 0x7FFFFFFF)   # VirtualSize
            struct.pack_into("<I", base, sec_idx + 16, 0x7FFFFFFF)  # SizeOfRawData
        mut_bytes = bytes(base)

        # PERebuilder and AntiDumpHealer must not allocate gigabytes or crash
        rebuilt, rep = PERebuilder.rebuild(mut_bytes)
        self.assertLess(len(rebuilt), 25 * 1024 * 1024)  # Must be capped under 25MB

        healed, h_rep = AntiDumpHealer.heal_dump(mut_bytes)
        self.assertLess(len(healed), 25 * 1024 * 1024)

    def test_adversarial_mixed_mode_truncated_optional_headers(self) -> None:
        """Verifies MixedModeAnalyzer handles truncated PE headers without struct.error."""
        # Truncated right at optional header boundaries
        truncated_pe = self.baseline_pe[:166]
        res = MixedModeAnalyzer.analyze(truncated_pe, file_name="truncated.exe")
        self.assertIsNotNone(res)
        self.assertFalse(res.telemetry.is_mixed_mode)


if __name__ == "__main__":
    unittest.main()

