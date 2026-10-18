"""
Decompiler Bridge Engine & Forensic Export Facade.
Engineered & Audited by Maya Thorne.
"""

import csv
import json
import os
import time
from typing import Any, Dict, List, Optional

from .ghidra_bridge import GhidraBridgeGenerator
from .ida_bridge import IDABridgeGenerator
from .models import (
    DecompilerBridgeOptions,
    DecompilerBridgeResult,
    DecompilerBridgeTelemetry,
    DecompilerEngine,
    SecurityError,
    SymbolType,
    safe_path,
)
from .radare2_bridge import Radare2BridgeGenerator
from .symbol_sync import SymbolSynchronizer


class DecompilerBridgeEngine:
    """Facade orchestrating decompiler bridge script generation and safe artifact export."""

    @classmethod
    def analyze_file(
        cls,
        file_path: str,
        options: Optional[DecompilerBridgeOptions] = None,
        forensic_context: Optional[Dict[str, Any]] = None,
    ) -> DecompilerBridgeResult:
        """Analyzes target binary file and synthesizes decompiler bridge annotations."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target binary not found: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()
        return cls.analyze(
            data,
            options=options,
            file_name=os.path.basename(file_path),
            forensic_context=forensic_context,
        )

    @classmethod
    def analyze(
        cls,
        data: bytes,
        options: Optional[DecompilerBridgeOptions] = None,
        file_name: str = "target.exe",
        forensic_context: Optional[Dict[str, Any]] = None,
    ) -> DecompilerBridgeResult:
        """Synthesizes decompiler headless bridge scripts from in-memory binary data."""
        start_time = time.perf_counter()
        opts = options or DecompilerBridgeOptions()

        symbols, comments, bookmarks = SymbolSynchronizer.synchronize(
            data, options=opts, forensic_context=forensic_context
        )

        ghidra_script = None
        ida_script = None
        radare2_script = None
        runner_bat = None
        runner_sh = None

        target_engine = opts.engine

        if target_engine in (DecompilerEngine.GHIDRA, DecompilerEngine.ALL):
            ghidra_script = GhidraBridgeGenerator.generate_script(
                symbols, comments, bookmarks, base_addr=opts.base_addr, safe_labels=opts.safe_labels
            )
            runner_bat = GhidraBridgeGenerator.generate_runner_bat()
            runner_sh = GhidraBridgeGenerator.generate_runner_sh()

        if target_engine in (DecompilerEngine.IDA_PRO, DecompilerEngine.ALL):
            ida_script = IDABridgeGenerator.generate_script(
                symbols, comments, bookmarks, base_addr=opts.base_addr, safe_labels=opts.safe_labels
            )
            if target_engine == DecompilerEngine.IDA_PRO:
                runner_bat = IDABridgeGenerator.generate_runner_bat()
                runner_sh = IDABridgeGenerator.generate_runner_sh()

        if target_engine in (DecompilerEngine.RADARE2, DecompilerEngine.ALL):
            radare2_script = Radare2BridgeGenerator.generate_script(
                symbols, comments, bookmarks, base_addr=opts.base_addr, safe_labels=opts.safe_labels
            )
            if target_engine == DecompilerEngine.RADARE2:
                runner_bat = Radare2BridgeGenerator.generate_runner_bat()
                runner_sh = Radare2BridgeGenerator.generate_runner_sh()

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        distinct_tags = set()
        anomaly_count = 0
        rhp_count = 0
        conf_sum = 0.0

        for s in symbols:
            conf_sum += s.confidence
            distinct_tags.update(s.tags)
            if s.symbol_type == SymbolType.ANOMALY_BLOCK:
                anomaly_count += 1
            elif s.symbol_type == SymbolType.RUNTIME_HELPER:
                rhp_count += 1

        conf_avg = round(conf_sum / len(symbols), 4) if symbols else 0.0

        telemetry = DecompilerBridgeTelemetry(
            total_symbols=len(symbols),
            total_comments=len(comments),
            total_bookmarks=len(bookmarks),
            total_structs=0,
            engine=target_engine.value,
            generation_time_ms=elapsed_ms,
            confidence_avg=conf_avg,
            sources_count=len(distinct_tags),
            anomaly_blocks_count=anomaly_count,
            rhp_helpers_count=rhp_count,
        )

        return DecompilerBridgeResult(
            engine=target_engine,
            base_addr=opts.base_addr,
            symbols=symbols,
            comments=comments,
            bookmarks=bookmarks,
            structs=[],
            telemetry=telemetry,
            ghidra_script=ghidra_script,
            ida_script=ida_script,
            radare2_script=radare2_script,
            runner_batch=runner_bat,
            runner_sh=runner_sh,
        )

    @classmethod
    def export_to_directory(
        cls,
        result: DecompilerBridgeResult,
        output_dir: str,
        file_stem: str = "forensic_annotations",
    ) -> Dict[str, Any]:
        """Safely exports generated decompiler scripts and metadata to output directory."""
        if not output_dir:
            raise ValueError("output_dir must not be empty")

        abs_out = os.path.abspath(output_dir)
        os.makedirs(abs_out, exist_ok=True)
        exported_files: List[str] = []

        def _write(rel_name: str, content: str) -> None:
            dest = safe_path(abs_out, rel_name)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            exported_files.append(dest)

        if result.ghidra_script:
            _write(f"{file_stem}_ghidra.py", result.ghidra_script)
            _write("run_ghidra.bat", GhidraBridgeGenerator.generate_runner_bat(f"{file_stem}_ghidra.py"))
            _write("run_ghidra.sh", GhidraBridgeGenerator.generate_runner_sh(f"{file_stem}_ghidra.py"))

        if result.ida_script:
            _write(f"{file_stem}_ida.py", result.ida_script)
            _write("run_ida.bat", IDABridgeGenerator.generate_runner_bat(f"{file_stem}_ida.py"))
            _write("run_ida.sh", IDABridgeGenerator.generate_runner_sh(f"{file_stem}_ida.py"))

        if result.radare2_script:
            _write(f"{file_stem}_r2.r2", result.radare2_script)
            _write("run_r2.bat", Radare2BridgeGenerator.generate_runner_bat(f"{file_stem}_r2.r2"))
            _write("run_r2.sh", Radare2BridgeGenerator.generate_runner_sh(f"{file_stem}_r2.r2"))

        # Symbols JSON & CSV
        sym_dicts = [s.to_dict() for s in result.symbols]
        _write("symbols.json", json.dumps(sym_dicts, indent=2))

        csv_dest = safe_path(abs_out, "symbols.csv")
        with open(csv_dest, "w", encoding="utf-8", newline="") as f_csv:
            writer = csv.writer(f_csv)
            writer.writerow(["Name", "RVA", "Hex_RVA", "Size", "Type", "Is_Function", "Token", "Confidence", "Tags"])
            for s in result.symbols:
                writer.writerow([
                    s.name, s.rva, hex(s.rva), s.size, s.symbol_type.value,
                    s.is_function, hex(s.token) if s.token else "", s.confidence, ";".join(s.tags),
                ])
        exported_files.append(csv_dest)

        # Comments JSON
        cmt_dicts = [c.to_dict() for c in result.comments]
        _write("comments.json", json.dumps(cmt_dicts, indent=2))

        # Bookmarks JSON
        bm_dicts = [b.to_dict() for b in result.bookmarks]
        _write("bookmarks.json", json.dumps(bm_dicts, indent=2))

        # Telemetry JSON
        _write("telemetry.json", json.dumps(result.telemetry.to_dict(), indent=2))

        return {
            "output_dir": abs_out,
            "exported_files": exported_files,
            "exported_files_count": len(exported_files),
            "symbols_count": len(result.symbols),
            "comments_count": len(result.comments),
            "bookmarks_count": len(result.bookmarks),
            "telemetry": result.telemetry.to_dict(),
        }
