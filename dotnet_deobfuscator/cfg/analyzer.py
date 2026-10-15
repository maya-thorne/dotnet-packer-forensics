"""
High-Level CIL Control Flow Graph (CFG) Forensic Analyzer & Safe Exporter.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .builder import CFGBuilder
from .disassembler import CILDisassembler
from .models import (
    CFGAnalysisResult,
    CFGTelemetry,
    MethodCFG,
    SecurityError,
    calculate_entropy,
    zeroize_buffer,
)
from .visualizer import CFGVisualizer


def _safe_path(base_dir: str, file_name: str) -> str:
    """Enforces strict directory boundary containment preventing path traversal vulnerabilities."""
    resolved_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(resolved_base, file_name))
    if not (target_path == resolved_base or target_path.startswith(resolved_base + os.sep)):
        raise SecurityError(f"Path traversal detected: '{file_name}' attempts to escape destination '{base_dir}'")
    return target_path


class CFGAnalyzer:
    """Orchestrates static CFG disassembly, complexity scoring, and multi-format visualization exports."""

    MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB bound
    MAX_METHODS = 128

    @classmethod
    def analyze_bytecode(
        cls,
        bytecode: bytes,
        method_token: int = 0x06000001,
        method_name: str = "StandaloneMethod",
    ) -> MethodCFG:
        """Disassembles raw CIL bytecode and constructs a single MethodCFG."""
        insts = CILDisassembler.disassemble(bytecode)
        return CFGBuilder.build(insts, method_token=method_token, method_name=method_name)

    @classmethod
    def analyze_file(cls, file_path: str, max_methods: int = 50) -> CFGAnalysisResult:
        """Reads executable file from disk and performs full CFG forensic analysis."""
        file_size = os.path.getsize(file_path)
        if file_size > cls.MAX_FILE_SIZE:
            raise ValueError(f"File size {file_size} bytes exceeds maximum allowed limit ({cls.MAX_FILE_SIZE} bytes)")

        with open(file_path, "rb") as f:
            data = f.read()

        file_name = os.path.basename(file_path)
        return cls.analyze(data, file_name=file_name, max_methods=max_methods)

    @classmethod
    def analyze(
        cls, data: bytes, file_name: str = "target.exe", max_methods: int = 50
    ) -> CFGAnalysisResult:
        """Inspects binary buffer for CIL method bodies and generates comprehensive CFG telemetry."""
        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()

        # Extract method bytecode candidates
        method_candidates = cls._extract_methods(data, max_methods=max_methods)

        method_cfgs: List[MethodCFG] = []
        scratch_buffers: List[bytearray] = []

        try:
            for token, name, code_bytes in method_candidates:
                scratch = bytearray(code_bytes)
                scratch_buffers.append(scratch)
                m_cfg = cls.analyze_bytecode(bytes(scratch), method_token=token, method_name=name)
                method_cfgs.append(m_cfg)
        finally:
            # Cryptographic memory zeroization
            for s in scratch_buffers:
                zeroize_buffer(s)

        # Aggregate telemetry
        total_blocks = sum(len(m.blocks) for m in method_cfgs)
        total_edges = sum(len(m.edges) for m in method_cfgs)
        high_entropy_blocks_total = sum(m.high_entropy_block_count for m in method_cfgs)
        max_complexity = max((m.cyclomatic_complexity for m in method_cfgs), default=1)
        complex_count = sum(1 for m in method_cfgs if m.cyclomatic_complexity >= 10)
        dead_code_methods = sum(1 for m in method_cfgs if m.dead_block_count > 0)

        all_entropies = [m.average_entropy for m in method_cfgs if m.average_entropy > 0]
        avg_entropy = round(sum(all_entropies) / len(all_entropies), 4) if all_entropies else 0.0

        suspicious: List[str] = []
        for m in method_cfgs:
            reasons = []
            if m.high_entropy_block_count > 0:
                reasons.append(f"{m.high_entropy_block_count} high-entropy block(s)")
            if m.dead_block_count > 0:
                reasons.append(f"{m.dead_block_count} dead block(s)")
            if m.cyclomatic_complexity >= 15:
                reasons.append(f"cyclomatic={m.cyclomatic_complexity}")
            if m.anomalies_detected:
                reasons.append(f"{len(m.anomalies_detected)} anomaly flag(s)")

            if reasons:
                suspicious.append(f"0x{m.method_token:08X} ({m.method_name}): {', '.join(reasons)}")

        telemetry = CFGTelemetry(
            total_methods_analyzed=len(method_cfgs),
            total_blocks=total_blocks,
            total_edges=total_edges,
            high_entropy_blocks_total=high_entropy_blocks_total,
            max_cyclomatic_complexity=max_complexity,
            complex_methods_count=complex_count,
            methods_with_dead_code=dead_code_methods,
            average_method_entropy=avg_entropy,
            suspicious_methods=suspicious,
        )

        return CFGAnalysisResult(
            file_name=file_name,
            file_size=file_size,
            sha256=sha256,
            telemetry=telemetry,
            methods=method_cfgs,
        )

    @classmethod
    def export_to_directory(
        cls,
        result: CFGAnalysisResult,
        output_dir: str,
        formats: Optional[List[str]] = None,
        max_exported_methods: int = 15,
    ) -> Dict[str, Any]:
        """Safely exports CFG diagram files, structured JSON manifests, and telemetry reports."""
        os.makedirs(output_dir, exist_ok=True)
        chosen_formats = [f.lower() for f in (formats or ["mermaid", "dot", "svg", "ascii", "json"])]
        if "all" in chosen_formats:
            chosen_formats = ["mermaid", "dot", "svg", "ascii", "json"]

        manifest_path = _safe_path(output_dir, "cfg_manifest.json")
        exported_files: List[str] = [manifest_path]

        # Prioritize suspicious or complex methods for visual export
        sorted_methods = sorted(
            result.methods,
            key=lambda m: (m.high_entropy_block_count, m.cyclomatic_complexity, m.dead_block_count),
            reverse=True,
        )
        export_targets = sorted_methods[:max_exported_methods]

        method_export_records: List[Dict[str, Any]] = []

        for m in export_targets:
            token_hex = f"{m.method_token:08x}"
            clean_name = "".join(c if c.isalnum() or c in ("_", "-") else "_" for c in m.method_name)
            base_fname = f"method_{token_hex}_{clean_name}"
            m_record: Dict[str, Any] = {
                "token": f"0x{m.method_token:08X}",
                "name": m.method_name,
                "complexity": m.cyclomatic_complexity,
                "entropy": m.average_entropy,
                "files": {},
            }

            if "mermaid" in chosen_formats:
                mmd_path = _safe_path(output_dir, f"{base_fname}.mmd")
                with open(mmd_path, "w", encoding="utf-8") as f:
                    f.write(CFGVisualizer.export_mermaid(m))
                exported_files.append(mmd_path)
                m_record["files"]["mermaid"] = os.path.basename(mmd_path)

            if "dot" in chosen_formats:
                dot_path = _safe_path(output_dir, f"{base_fname}.dot")
                with open(dot_path, "w", encoding="utf-8") as f:
                    f.write(CFGVisualizer.export_dot(m))
                exported_files.append(dot_path)
                m_record["files"]["dot"] = os.path.basename(dot_path)

            if "svg" in chosen_formats:
                svg_path = _safe_path(output_dir, f"{base_fname}.svg")
                with open(svg_path, "w", encoding="utf-8") as f:
                    f.write(CFGVisualizer.export_svg(m))
                exported_files.append(svg_path)
                m_record["files"]["svg"] = os.path.basename(svg_path)

            if "ascii" in chosen_formats:
                txt_path = _safe_path(output_dir, f"{base_fname}.txt")
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(CFGVisualizer.export_ascii(m))
                exported_files.append(txt_path)
                m_record["files"]["ascii"] = os.path.basename(txt_path)

            if "json" in chosen_formats:
                json_path = _safe_path(output_dir, f"{base_fname}.json")
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(CFGVisualizer.export_json(m), f, indent=2)
                exported_files.append(json_path)
                m_record["files"]["json"] = os.path.basename(json_path)

            method_export_records.append(m_record)

        manifest = {
            "source_file": result.file_name,
            "source_size": result.file_size,
            "sha256": result.sha256,
            "telemetry": result.telemetry.to_dict(),
            "exported_methods_count": len(method_export_records),
            "exported_methods": method_export_records,
            "total_files_written": len(exported_files),
        }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return {
            "output_directory": output_dir,
            "manifest_path": manifest_path,
            "exported_files_count": len(exported_files),
            "exported_files": exported_files,
        }

    @classmethod
    def _extract_methods(
        cls, data: bytes, max_methods: int = 50
    ) -> List[Tuple[int, str, bytes]]:
        """Heuristically extracts CIL method bodies from ECMA-335 CorILMethod headers."""
        results: List[Tuple[int, str, bytes]] = []
        if len(data) < 64:
            return results

        token_counter = 0x06000001
        pos = 0
        total_len = len(data)

        # Scan for CorILMethod Tiny and Fat headers
        while pos < total_len - 4 and len(results) < max_methods:
            b0 = data[pos]

            # CorILMethod_TinyFormat: header byte has (b0 & 0x03) == 0x02
            if (b0 & 0x03) == 0x02:
                code_size = b0 >> 2
                if 2 <= code_size <= 64 and pos + 1 + code_size <= total_len:
                    code_slice = data[pos + 1 : pos + 1 + code_size]
                    # Heuristic validation: method typically terminates with ret (0x2A), throw (0x7A) or branch
                    if code_slice[-1] in (0x2A, 0x7A, 0x2B, 0x38, 0xDE):
                        results.append((token_counter, f"Method_{token_counter:08X}", code_slice))
                        token_counter += 1
                        pos += 1 + code_size
                        continue

            # CorILMethod_FatFormat: 12-byte header with (flags & 0x03) == 0x03
            if pos + 12 <= total_len:
                w0 = struct.unpack("<H", data[pos : pos + 2])[0]
                if (w0 & 0x03) == 0x03:
                    header_size_dwords = (w0 >> 12) & 0x0F
                    header_size = header_size_dwords * 4
                    if header_size >= 12 and pos + header_size + 4 <= total_len:
                        code_size = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
                        if 4 <= code_size <= 32768 and pos + header_size + code_size <= total_len:
                            code_slice = data[pos + header_size : pos + header_size + code_size]
                            if code_slice[-1] in (0x2A, 0x7A, 0x2B, 0x38, 0xDE):
                                results.append((token_counter, f"FatMethod_{token_counter:08X}", code_slice))
                                token_counter += 1
                                pos += header_size + code_size
                                continue

            pos += 1

        # Fallback: if no valid CorILMethod headers located, slice initial code or sample
        if not results:
            # Check for simple CIL sequence in data
            if total_len >= 8:
                results.append((0x06000001, "EntryMethod", data[: min(total_len, 256)]))

        return results
