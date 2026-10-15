"""
Regression Fuzzing Harness & Sandboxed Execution Engine for .NET Deobfuscation.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .generator import SyntheticMutatedBinaryGenerator
from .models import (
    CrashSeverity,
    FuzzCampaignResult,
    FuzzCampaignTelemetry,
    FuzzExecutionResult,
    FuzzTarget,
    MutationRecord,
    MutationStrategy,
    RegressionLedger,
    SecurityError,
    safe_path,
    zeroize_buffer,
)
from ..baml.decompiler import BamlDecompiler
from ..cfg.analyzer import CFGAnalyzer
from ..dotnet_analyzer import DotNetAnalyzer
from ..mixed_mode.analyzer import MixedModeAnalyzer
from ..payload_verifier import PayloadVerifier
from ..pe_overlay import PEOverlayParser
from ..pe_rebuilder import PERebuilder
from ..rules.rule_engine import ThreatRuleEngine
from ..signatures import ProtectorSignatures
from ..unpackers.antidump_healer import AntiDumpHealer
from ..unpackers.antitamper import AntiTamperUnpacker
from ..unpackers.confuserex import ConfuserExUnpacker
from ..unpackers.costura import CosturaUnpacker


class RegressionFuzzingHarness:
    """
    Sandboxed stress-testing fuzzing harness that evaluates deobfuscation and analysis
    subsystems against synthetically mutated PE and .NET binaries.
    """

    MAX_BINARY_SIZE = 100 * 1024 * 1024  # 100 MB bound

    @classmethod
    def execute_target(
        cls,
        target: Union[FuzzTarget, str],
        binary_data: bytes,
        timeout_sec: float = 3.0,
        isolate_process: bool = False,
    ) -> Tuple[CrashSeverity, Optional[str], Optional[str], Optional[str]]:
        """
        Executes a specific forensic subsystem against binary data in a sandboxed boundary.
        Returns (severity, exception_class, exception_message, traceback_snippet).
        """
        if isinstance(target, str):
            try:
                target = FuzzTarget.from_str(target)
            except ValueError as e:
                return (CrashSeverity.HANDLED_ERROR, type(e).__name__, str(e), None)

        if len(binary_data) > cls.MAX_BINARY_SIZE:
            return (
                CrashSeverity.RESOURCE_EXHAUSTION,
                "SecurityError",
                f"Binary size {len(binary_data)} exceeds {cls.MAX_BINARY_SIZE} bytes limit",
                None,
            )

        if isolate_process:
            return cls._execute_in_subprocess(target, binary_data, timeout_sec=timeout_sec)

        start_time = time.perf_counter()

        def _run_subsystem(t: FuzzTarget) -> None:
            if t == FuzzTarget.ANALYZE:
                DotNetAnalyzer.inspect_assembly(binary_data)
                ProtectorSignatures.identify(binary_data)
                PEOverlayParser.calculate_pe_size(binary_data)
                PEOverlayParser.extract_overlay(binary_data)
                CosturaUnpacker.detect(binary_data)
                ConfuserExUnpacker.detect(binary_data)
            elif t == FuzzTarget.REBUILD:
                PERebuilder.detect_anomalies(binary_data)
                if len(binary_data) >= 64:
                    PERebuilder.rebuild(binary_data)
            elif t == FuzzTarget.VERIFY:
                PayloadVerifier.verify_pe_structure(binary_data, strict=False)
            elif t == FuzzTarget.CFG:
                CFGAnalyzer.analyze(binary_data, file_name="fuzz_target.exe", max_methods=10)
            elif t == FuzzTarget.BAML:
                BamlDecompiler.decompile_assembly_data(binary_data, file_name="fuzz_target.exe")
            elif t == FuzzTarget.MIXED_MODE:
                MixedModeAnalyzer.analyze(binary_data, file_name="fuzz_target.exe")
            elif t == FuzzTarget.ANTIDUMP:
                AntiDumpHealer.detect(binary_data)
                if len(binary_data) >= 64:
                    AntiDumpHealer.heal_dump(binary_data)
            elif t == FuzzTarget.ANTITAMPER:
                AntiTamperUnpacker.detect(binary_data)
            elif t == FuzzTarget.RULES:
                ThreatRuleEngine.synthesize_from_bytes(binary_data, file_name="fuzz_target.exe")
            elif t == FuzzTarget.ALL:
                for sub in [
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
                    _run_subsystem(sub)
            else:
                raise ValueError(f"Unhandled fuzz target: {t}")

        exc: List[Optional[BaseException]] = [None]
        tb_str: List[Optional[str]] = [None]

        def _worker() -> None:
            try:
                _run_subsystem(target)
            except BaseException as e:
                exc[0] = e
                tb_str[0] = "".join(traceback.format_exception(e, limit=5))

        worker_thread = threading.Thread(target=_worker, daemon=True)
        worker_thread.start()
        worker_thread.join(timeout=timeout_sec)
        elapsed = time.perf_counter() - start_time

        if worker_thread.is_alive() or elapsed > timeout_sec:
            return (
                CrashSeverity.TIMEOUT_HANG,
                "TimeoutError",
                f"Execution exceeded timeout limit ({elapsed:.2f}s > {timeout_sec:.2f}s)",
                None,
            )

        if exc[0] is not None:
            e = exc[0]
            tb = tb_str[0]
            if isinstance(e, (MemoryError, RecursionError)):
                return (CrashSeverity.RESOURCE_EXHAUSTION, type(e).__name__, str(e), tb)
            elif isinstance(e, (ValueError, SecurityError, NotImplementedError, OSError, IOError)):
                return (CrashSeverity.HANDLED_ERROR, type(e).__name__, str(e), None)
            elif isinstance(e, (KeyError, IndexError, AttributeError, ZeroDivisionError, UnboundLocalError, AssertionError, TypeError)):
                return (CrashSeverity.REGRESSION_CRASH, type(e).__name__, str(e), tb)
            else:
                return (CrashSeverity.REGRESSION_CRASH, type(e).__name__, str(e), tb)

        return (CrashSeverity.CLEAN_PASS, None, None, None)

    @classmethod
    def _extract_json_payload(cls, output_text: str) -> Optional[Dict[str, Any]]:
        """Extracts JSON payload safely even if stdout is polluted with warnings or diagnostic logs."""
        start_tag = "__FUZZ_RESULT_JSON_START__"
        end_tag = "__FUZZ_RESULT_JSON_END__"
        if start_tag in output_text and end_tag in output_text:
            try:
                s_idx = output_text.index(start_tag) + len(start_tag)
                e_idx = output_text.index(end_tag, s_idx)
                return json.loads(output_text[s_idx:e_idx].strip())
            except (ValueError, json.JSONDecodeError):
                pass
        for line in reversed(output_text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    d = json.loads(line)
                    if isinstance(d, dict) and "severity" in d:
                        return d
                except json.JSONDecodeError:
                    pass
        return None

    @classmethod
    def _execute_in_subprocess(
        cls,
        target: FuzzTarget,
        binary_data: bytes,
        timeout_sec: float = 3.0,
    ) -> Tuple[CrashSeverity, Optional[str], Optional[str], Optional[str]]:
        """
        Executes target in an isolated child OS process via standard streams piping.
        Guarantees zero temporary file leaks, clean process termination, and pipe handle closure.
        """
        cmd = [
            sys.executable,
            "-W",
            "ignore",
            "-m",
            "dotnet_deobfuscator.fuzzing.harness",
            target.value,
            "-",
            str(timeout_sec),
        ]
        env = dict(os.environ)
        proj_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        curr_py_path = env.get("PYTHONPATH", "")
        if proj_root not in curr_py_path.split(os.pathsep):
            env["PYTHONPATH"] = f"{proj_root}{os.pathsep}{curr_py_path}".rstrip(os.pathsep)

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            stdout_bytes, stderr_bytes = proc.communicate(
                input=binary_data, timeout=timeout_sec + 3.0
            )
            out_text = stdout_bytes.decode("utf-8", errors="replace")
            err_text = stderr_bytes.decode("utf-8", errors="replace")

            data = cls._extract_json_payload(out_text)
            if proc.returncode == 0 and data is not None:
                return (
                    CrashSeverity(data["severity"]),
                    data.get("e_cls"),
                    data.get("e_msg"),
                    data.get("tb"),
                )
            else:
                err_preview = (err_text.strip() or out_text.strip())[:200]
                tb_snippet = err_text.strip() or None
                return (
                    CrashSeverity.REGRESSION_CRASH,
                    "ProcessAbortedError",
                    f"Subprocess terminated with exit code {proc.returncode}: {err_preview}",
                    tb_snippet,
                )
        except subprocess.TimeoutExpired:
            if proc is not None:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
            return (
                CrashSeverity.TIMEOUT_HANG,
                "TimeoutError",
                f"Subprocess execution exceeded timeout limit ({timeout_sec:.2f}s)",
                None,
            )
        except Exception as e:
            if proc is not None:
                try:
                    proc.kill()
                except OSError:
                    pass
            return (CrashSeverity.REGRESSION_CRASH, type(e).__name__, str(e), None)
        finally:
            if proc is not None:
                for pipe in (proc.stdin, proc.stdout, proc.stderr):
                    if pipe and not pipe.closed:
                        try:
                            pipe.close()
                        except OSError:
                            pass

    @classmethod
    def run_campaign(
        cls,
        base_binary: Optional[bytes] = None,
        iterations: int = 50,
        seed: int = 1337,
        targets: Optional[List[Union[FuzzTarget, str]]] = None,
        strategies: Optional[List[MutationStrategy]] = None,
        timeout_sec: float = 3.0,
        output_dir: Optional[str] = None,
        isolate_process: bool = False,
    ) -> FuzzCampaignResult:
        """
        Executes an end-to-end regression fuzzing campaign across target subsystems.
        Generates deterministic mutations, logs telemetry, captures crashes, and exports reports.
        """
        start_time = time.perf_counter()
        campaign_id = f"fuzz_cmp_{seed}_{int(start_time)}"
        fuzz_targets = [FuzzTarget.from_str(t) for t in targets] if targets else [FuzzTarget.ALL]
        target_name = ",".join(t.value for t in fuzz_targets)

        base = base_binary if base_binary is not None else SyntheticMutatedBinaryGenerator.generate_baseline_pe()

        telemetry = FuzzCampaignTelemetry(total_iterations=iterations)
        executions: List[FuzzExecutionResult] = []
        crashes: List[FuzzExecutionResult] = []

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        for i in range(iterations):
            iter_seed = (seed + (i * 10007)) & 0xFFFFFFFF
            mutated_bytes, mut_records = SyntheticMutatedBinaryGenerator.mutate_binary(
                base, strategies=strategies, seed=iter_seed, mutation_depth=2
            )

            # Record strategy usage
            for r in mut_records:
                s_name = r.strategy.value if hasattr(r.strategy, "value") else str(r.strategy)
                telemetry.strategies_used[s_name] = telemetry.strategies_used.get(s_name, 0) + 1

            sample_sha256 = hashlib.sha256(mutated_bytes).hexdigest()
            iter_start = time.perf_counter()

            # Execute targets
            worst_severity = CrashSeverity.CLEAN_PASS
            err_cls = None
            err_msg = None
            err_tb = None

            for tgt in fuzz_targets:
                sev, e_cls, e_msg, e_tb = cls.execute_target(
                    tgt, mutated_bytes, timeout_sec=timeout_sec, isolate_process=isolate_process
                )
                if sev == CrashSeverity.REGRESSION_CRASH:
                    worst_severity = sev
                    err_cls, err_msg, err_tb = e_cls, e_msg, e_tb
                    break
                elif sev == CrashSeverity.TIMEOUT_HANG and worst_severity != CrashSeverity.REGRESSION_CRASH:
                    worst_severity = sev
                    err_cls, err_msg, err_tb = e_cls, e_msg, e_tb
                elif sev == CrashSeverity.RESOURCE_EXHAUSTION and worst_severity == CrashSeverity.CLEAN_PASS:
                    worst_severity = sev
                    err_cls, err_msg, err_tb = e_cls, e_msg, e_tb
                elif sev == CrashSeverity.HANDLED_ERROR and worst_severity == CrashSeverity.CLEAN_PASS:
                    worst_severity = sev
                    err_cls, err_msg = e_cls, e_msg

            iter_duration_ms = (time.perf_counter() - iter_start) * 1000.0

            exec_res = FuzzExecutionResult(
                iteration=i + 1,
                seed=iter_seed,
                target=target_name,
                strategies=[r.strategy.value for r in mut_records],
                severity=worst_severity,
                duration_ms=iter_duration_ms,
                sample_sha256=sample_sha256,
                sample_size=len(mutated_bytes),
                exception_class=err_cls,
                exception_message=err_msg,
                traceback_snippet=err_tb,
                mutations=mut_records,
            )
            executions.append(exec_res)

            # Telemetry tracking
            if worst_severity == CrashSeverity.CLEAN_PASS:
                telemetry.clean_passes += 1
            elif worst_severity == CrashSeverity.HANDLED_ERROR:
                telemetry.handled_errors += 1
            elif worst_severity == CrashSeverity.TIMEOUT_HANG:
                telemetry.timeouts += 1
                telemetry.has_regressions = True
                crashes.append(exec_res)
            elif worst_severity in (CrashSeverity.REGRESSION_CRASH, CrashSeverity.RESOURCE_EXHAUSTION):
                telemetry.crashes += 1
                telemetry.has_regressions = True
                crashes.append(exec_res)
                sig = f"{err_cls}: {err_msg}"
                telemetry.unique_crash_signatures[sig] = (
                    telemetry.unique_crash_signatures.get(sig, 0) + 1
                )

                # Persist crash reproduction artifact
                if output_dir:
                    crash_bin_name = f"crash_iter{i+1:04d}_{sample_sha256[:8]}.bin"
                    crash_bin_path = safe_path(output_dir, crash_bin_name)
                    with open(crash_bin_path, "wb") as f_bin:
                        f_bin.write(mutated_bytes)

                    crash_json_name = f"crash_iter{i+1:04d}_{sample_sha256[:8]}.json"
                    crash_json_path = safe_path(output_dir, crash_json_name)
                    with open(crash_json_path, "w", encoding="utf-8") as f_json:
                        json.dump(exec_res.to_dict(), f_json, indent=2)

        total_elapsed = time.perf_counter() - start_time
        telemetry.total_duration_sec = total_elapsed

        campaign_res = FuzzCampaignResult(
            campaign_id=campaign_id,
            seed=seed,
            target=target_name,
            telemetry=telemetry,
            executions=executions,
            crashes=crashes,
        )

        if output_dir:
            cls.export_campaign_report(campaign_res, output_dir=output_dir)

        return campaign_res

    @classmethod
    def replay_crash(
        cls,
        target: Union[FuzzTarget, str],
        binary_bytes: bytes,
        timeout_sec: float = 3.0,
        isolate_process: bool = False,
    ) -> FuzzExecutionResult:
        """
        Replays a previously captured crash case to verify whether a fix successfully resolved it.
        """
        tgt = FuzzTarget.from_str(target)
        start = time.perf_counter()
        sev, e_cls, e_msg, e_tb = cls.execute_target(
            tgt, binary_bytes, timeout_sec=timeout_sec, isolate_process=isolate_process
        )
        dur = (time.perf_counter() - start) * 1000.0
        sha = hashlib.sha256(binary_bytes).hexdigest()

        return FuzzExecutionResult(
            iteration=0,
            seed=0,
            target=tgt.value,
            strategies=["replay"],
            severity=sev,
            duration_ms=dur,
            sample_sha256=sha,
            sample_size=len(binary_bytes),
            exception_class=e_cls,
            exception_message=e_msg,
            traceback_snippet=e_tb,
        )

    @classmethod
    def export_campaign_report(
        cls, result: FuzzCampaignResult, output_dir: str
    ) -> Dict[str, Any]:
        """
        Exports campaign JSON report, markdown summary, and regression ledger to disk.
        """
        os.makedirs(output_dir, exist_ok=True)
        report_path = safe_path(output_dir, "campaign_report.json")
        summary_path = safe_path(output_dir, "fuzzing_summary.txt")

        rep_dict = result.to_dict()
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(rep_dict, f, indent=2)

        summary_text = cls.format_campaign_summary(result)
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary_text)

        exported_files = [report_path, summary_path]

        # Also update / export regression ledger if crashes occurred
        if result.crashes:
            ledger = RegressionLedger()
            for c in result.crashes:
                ledger.record_crash(c, None, notes="Campaign automated crash export")
            ledger_path = safe_path(output_dir, "regression_ledger.json")
            ledger.save_to_file(ledger_path)
            exported_files.append(ledger_path)

        return {
            "output_dir": output_dir,
            "exported_files": exported_files,
            "total_iterations": result.telemetry.total_iterations,
            "crashes": result.telemetry.crashes,
        }

    @classmethod
    def format_campaign_summary(cls, result: FuzzCampaignResult) -> str:
        """Formats human-readable text summary of fuzzing campaign results."""
        t = result.telemetry
        lines = [
            "=" * 78,
            f"[dotnet-packer-re] Deobfuscation Regression Fuzzing Campaign Summary",
            "=" * 78,
            f"Campaign ID     : {result.campaign_id}",
            f"Target Scope    : {result.target.upper()}",
            f"PRNG Seed       : {result.seed}",
            f"Total Duration  : {t.total_duration_sec:.2f} seconds",
            f"Total Iterations: {t.total_iterations:,}",
            "",
            "--- [Outcome Breakdown] ---",
            f"  [+] Clean Passes       : {t.clean_passes:,} ({(t.clean_passes / max(1, t.total_iterations))*100:.1f}%)",
            f"  [+] Handled Rejections : {t.handled_errors:,} ({(t.handled_errors / max(1, t.total_iterations))*100:.1f}%)",
            f"  [-] Regression Crashes : {t.crashes:,}",
            f"  [-] Timeout Hangs      : {t.timeouts:,}",
            "",
            "--- [Mutations Evaluated] ---",
        ]

        for s_name, s_count in sorted(t.strategies_used.items()):
            lines.append(f"  * {s_name:<26} : {s_count:,} application(s)")

        if t.unique_crash_signatures:
            lines.append("")
            lines.append("--- [Unique Crash Signatures] ---")
            for sig, count in t.unique_crash_signatures.items():
                lines.append(f"  [!] {sig} ({count} occurrence(s))")
        else:
            lines.append("")
            lines.append("--- [Security & Stability Status] ---")
            lines.append("  [+] PASS: Zero regression crashes or hangs detected. All corrupt inputs handled gracefully.")

        lines.append("=" * 78)
        return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: python -m dotnet_deobfuscator.fuzzing.harness <TARGET> <FILE_OR_DASH> <TIMEOUT_SEC>\n")
        sys.stderr.flush()
        sys.exit(1)
    try:
        _tgt = FuzzTarget.from_str(sys.argv[1])
        _fpath = sys.argv[2]
        _timeout = float(sys.argv[3])
        if _fpath == "-":
            _bdata = sys.stdin.buffer.read()
        else:
            with open(_fpath, "rb") as _f:
                _bdata = _f.read()

        _sev, _e_cls, _e_msg, _tb = RegressionFuzzingHarness.execute_target(
            _tgt, _bdata, timeout_sec=_timeout, isolate_process=False
        )
        payload = json.dumps({
            "severity": _sev.value,
            "e_cls": _e_cls,
            "e_msg": _e_msg,
            "tb": _tb,
        })
        out_msg = f"__FUZZ_RESULT_JSON_START__\n{payload}\n__FUZZ_RESULT_JSON_END__\n"
        sys.stdout.buffer.write(out_msg.encode("utf-8"))
        sys.stdout.buffer.flush()
        sys.stderr.flush()
        sys.exit(0)
    except Exception as _ex:
        sys.stderr.write(f"HarnessWorkerError: {_ex}\n")
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        sys.exit(2)

