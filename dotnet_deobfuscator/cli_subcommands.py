"""
Subcommand Handlers for dotnet-packer-re CLI.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import sys
from typing import Optional

from .core import DotNetPackerCore


def handle_fuzz_mode(args) -> Optional[int]:
    """Handles automated regression fuzzing campaign mode."""
    if not getattr(args, "fuzz", False):
        return None
    try:
        targets = [t.strip() for t in args.fuzz_targets.split(",")] if args.fuzz_targets else None
        fuzz_res = DotNetPackerCore.run_fuzzing_campaign(
            target_path=args.target,
            iterations=args.fuzz_iterations,
            seed=args.fuzz_seed,
            targets=targets,
            timeout_sec=args.fuzz_timeout,
            output_dir=args.fuzz_out,
            is_64bit=args.fuzz_64,
            isolate_process=args.fuzz_isolate,
        )
        if args.format == "json":
            sys.stdout.write(json.dumps(fuzz_res.to_dict(), indent=2) + "\n")
        else:
            from .fuzzing import RegressionFuzzingHarness
            sys.stdout.write(RegressionFuzzingHarness.format_campaign_summary(fuzz_res) + "\n")
        return 1 if fuzz_res.telemetry.has_regressions else 0
    except Exception as e:
        sys.stderr.write(f"[-] Fuzzing campaign failed: {e}\n")
        return 1


def handle_mutants_mode(args) -> Optional[int]:
    """Handles synthetic mutated binary corpus generation mode."""
    if not getattr(args, "gen_mutants", False):
        return None
    try:
        mutants = DotNetPackerCore.generate_synthetic_corpus(
            base_path=args.target,
            count=args.mutant_count,
            output_dir=args.output or args.fuzz_out,
            is_64bit=args.fuzz_64,
        )
        if args.format == "json":
            sys.stdout.write(json.dumps(mutants, indent=2) + "\n")
        else:
            sys.stdout.write(f"[+] Generated {len(mutants)} synthetic mutated binaries.\n")
            for m in mutants:
                sys.stdout.write(f"    * [{m['index']:02d}] {m['file_name']} ({m['size_bytes']:,} bytes, {m['mutations_count']} mutations)\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"[-] Synthetic mutant generation failed: {e}\n")
        return 1


def handle_batch_mode(args) -> Optional[int]:
    """Handles batch directory forensic scanner mode."""
    if getattr(args, "batch", None) is None:
        return None
    try:
        target_dir = args.batch if (args.batch and args.batch != "") else args.target
        if not target_dir:
            sys.stderr.write("[-] Error: Target directory for batch scanning is required\n")
            return 2

        from .batch import BatchForensicEngine, BatchReporter, BatchScanOptions
        options = BatchScanOptions(
            target_dir=target_dir,
            recursive=args.batch_recursive,
            workers=args.batch_workers,
            pattern=args.batch_pattern,
            timeout_sec=args.batch_timeout,
            min_size_bytes=args.batch_min_size,
            max_size_bytes=args.batch_max_size,
            unpack_payloads=bool(args.output or args.unpack_dir),
            unpack_out_dir=args.output or args.unpack_dir,
            output_dir=args.batch_out,
            json_out=args.batch_json,
            csv_out=args.batch_csv,
            html_out=args.batch_html,
            master_key=args.key,
        )
        batch_report = BatchForensicEngine.run(options)
        if args.format == "json":
            sys.stdout.write(json.dumps(batch_report.to_dict(), indent=2, ensure_ascii=False) + "\n")
        else:
            sys.stdout.write(BatchReporter.format_console_table(batch_report) + "\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"[-] Batch forensic scan failed: {e}\n")
        return 1


def handle_diff_mode(args) -> Optional[int]:
    """Handles multi-engine binary diffing mode."""
    if not getattr(args, "diff_target", None):
        return None
    try:
        from .diffing import BinaryDiffEngine, BinaryDiffOptions, DiffEngine, HTMLDiffReporter
        opts = BinaryDiffOptions(engine=DiffEngine(args.diff_engine.lower()), min_similarity_threshold=args.diff_threshold)
        diff_res = DotNetPackerCore.diff_binaries(args.target, args.diff_target, options=opts)
        if args.format == "json":
            sys.stdout.write(json.dumps(diff_res.to_dict(), indent=2) + "\n")
        else:
            sys.stdout.write(BinaryDiffEngine.format_text_diff(diff_res) + "\n")
        if args.diff_out:
            exp_diff = DotNetPackerCore.export_diff_report(diff_res, output_dir=args.diff_out)
            sys.stdout.write(f"[+] Exported {exp_diff['files_count']} diff report files to -> {args.diff_out}\n")
        if args.diff_html:
            with open(args.diff_html, "w", encoding="utf-8") as f:
                f.write(HTMLDiffReporter.generate(diff_res))
            sys.stdout.write(f"[+] Exported visual HTML diff report to -> {args.diff_html}\n")
        if args.diff_json:
            with open(args.diff_json, "w", encoding="utf-8") as f:
                json.dump(diff_res.to_dict(), f, indent=2)
            sys.stdout.write(f"[+] Exported JSON diff summary to -> {args.diff_json}\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"[-] Binary diffing failed: {e}\n")
        return 1
