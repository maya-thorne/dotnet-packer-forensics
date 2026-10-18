"""
Multi-Engine Binary Diffing Coordinator & Packing Similarity Measurer.
Engineered & Audited by Maya Thorne.
"""

import csv
import hashlib
import json
import os
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from .ast_differ import ASTDiffer
from .bytecode_differ import BytecodeDiffer
from .cfg_differ import CFGDiffer
from .html_reporter import HTMLDiffReporter
from .metadata_differ import MetadataDiffer
from .models import (
    ASTFlowDiff,
    BinaryDiffOptions,
    BinaryDiffResult,
    BinaryDiffTelemetry,
    BytecodeDiff,
    CFGGraphDiff,
    ChangeType,
    DiffCategory,
    DiffEngine,
    MetadataDiff,
    MethodDiff,
    ObfuscationImpact,
    safe_path,
    zeroize_buffer,
)


class BinaryDiffEngine:
    """Orchestrates multi-engine binary comparison across metadata, bytecode, CFG, and AST."""

    @classmethod
    def compare_files(
        cls, path_a: str, path_b: str, options: Optional[BinaryDiffOptions] = None
    ) -> BinaryDiffResult:
        """Reads two files safely from disk and executes binary comparison."""
        if not os.path.exists(path_a):
            raise FileNotFoundError(f"Source A binary not found: {path_a}")
        if not os.path.exists(path_b):
            raise FileNotFoundError(f"Source B binary not found: {path_b}")

        with open(path_a, "rb") as f_a:
            data_a = f_a.read()
        with open(path_b, "rb") as f_b:
            data_b = f_b.read()

        try:
            return cls.compare(
                data_a,
                data_b,
                name_a=os.path.basename(path_a),
                name_b=os.path.basename(path_b),
                options=options,
            )
        finally:
            # Audit zeroize
            pass

    @classmethod
    def compare(
        cls,
        data_a: bytes,
        data_b: bytes,
        name_a: str = "sample_a.exe",
        name_b: str = "sample_b.exe",
        options: Optional[BinaryDiffOptions] = None,
    ) -> BinaryDiffResult:
        """Compares two raw binaries across metadata, bytecode, CFG, and AST semantic layers."""
        start_time = time.perf_counter()
        opts = options or BinaryDiffOptions()

        sha256_a = hashlib.sha256(data_a).hexdigest()
        sha256_b = hashlib.sha256(data_b).hexdigest()

        # 1. Metadata Layer Comparison
        metadata_diff = MetadataDiffer.compare(data_a, data_b)

        # 2. Extract Methods from both samples
        methods_a = cls._extract_methods(data_a)
        methods_b = cls._extract_methods(data_b)

        # 3. Method Pairing and Multi-Engine Comparison
        method_diffs, byte_comps, cfg_comps, ast_comps = cls._compare_methods(
            methods_a, methods_b, opts
        )

        # 4. Aggregations
        bytecode_diff = BytecodeDiffer.aggregate_methods_bytecode(byte_comps)
        cfg_diff = CFGDiffer.aggregate_methods_cfg(cfg_comps)
        ast_diff = ASTDiffer.aggregate_methods_ast(ast_comps)

        # 5. Composite Similarity Computation
        w_meta = opts.weight_metadata
        w_byte = opts.weight_bytecode
        w_cfg = opts.weight_cfg
        w_ast = opts.weight_ast
        total_w = w_meta + w_byte + w_cfg + w_ast or 1.0

        if data_a == data_b:
            composite_score = 1.0
        else:
            composite_score = (
                (metadata_diff.similarity_score * w_meta)
                + (bytecode_diff.similarity_score * w_byte)
                + (cfg_diff.similarity_score * w_cfg)
                + (ast_diff.similarity_score * w_ast)
            ) / total_w
            composite_score = max(0.0, min(1.0, round(composite_score, 4)))

        # 6. Obfuscation & Packing Impact Signatures
        impacts = cls._evaluate_obfuscation_impacts(
            metadata_diff=metadata_diff,
            bytecode_diff=bytecode_diff,
            cfg_diff=cfg_diff,
            ast_diff=ast_diff,
            data_a=data_a,
            data_b=data_b,
        )

        # 7. Classification of Diff Category
        diff_cat = cls._classify_diff_category(composite_score, impacts)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Method statistics
        identical_m = sum(1 for m in method_diffs if m.change_type == ChangeType.UNCHANGED)
        modified_m = sum(1 for m in method_diffs if m.change_type == ChangeType.MODIFIED)
        added_m = sum(1 for m in method_diffs if m.change_type == ChangeType.ADDED)
        removed_m = sum(1 for m in method_diffs if m.change_type == ChangeType.REMOVED)

        telemetry = BinaryDiffTelemetry(
            comparison_time_ms=round(elapsed_ms, 2),
            total_methods_a=len(methods_a),
            total_methods_b=len(methods_b),
            matched_methods=len([m for m in method_diffs if m.token_a and m.token_b]),
            identical_methods=identical_m,
            modified_methods=modified_m,
            added_methods=added_m,
            removed_methods=removed_m,
            composite_similarity=composite_score,
            detected_impacts=[i.value for i in impacts],
        )

        return BinaryDiffResult(
            source_a=name_a,
            source_b=name_b,
            sha256_a=sha256_a,
            sha256_b=sha256_b,
            composite_similarity=composite_score,
            diff_category=diff_cat,
            metadata_diff=metadata_diff,
            bytecode_diff=bytecode_diff,
            cfg_diff=cfg_diff,
            ast_diff=ast_diff,
            method_diffs=method_diffs,
            detected_impacts=impacts,
            telemetry=telemetry,
        )

    @classmethod
    def _extract_methods(cls, data: bytes) -> Dict[int, Dict[str, Any]]:
        """Scans for Tiny and Fat CIL method bodies within executable buffers."""
        methods = {}
        if len(data) < 16:
            return methods

        # Fallback: scan for standard Tiny (0x02) and Fat (0x03) method headers
        token_counter = 0x06000001
        pos = 0
        limit = len(data)

        while pos < limit - 4:
            b0 = data[pos]
            header_type = b0 & 0x03

            # Tiny method header (0x02): (code_size << 2) | 0x02
            if header_type == 0x02:
                code_size = b0 >> 2
                if 2 <= code_size <= 63 and pos + 1 + code_size <= limit:
                    body = data[pos + 1 : pos + 1 + code_size]
                    # Verify standard terminal opcodes (ret=0x2A or throw=0x7A)
                    if body and (body[-1] in (0x2A, 0x7A) or b"\x2a" in body):
                        tok = token_counter
                        methods[tok] = {
                            "token": tok,
                            "name": f"Method_{tok:08X}",
                            "offset": pos,
                            "format": "tiny",
                            "code_size": code_size,
                            "bytecode": body,
                        }
                        token_counter += 1
                        pos += 1 + code_size
                        continue

            # Fat method header (0x03): 12 bytes header <HHII
            elif header_type == 0x03 and pos + 12 <= limit:
                flags_size = struct.unpack_from("<H", data, pos)[0]
                fat_size = (flags_size >> 12) * 4
                if fat_size == 12:
                    max_stack = struct.unpack_from("<H", data, pos + 2)[0]
                    code_size = struct.unpack_from("<I", data, pos + 4)[0]
                    local_sig = struct.unpack_from("<I", data, pos + 8)[0]
                    if 4 <= code_size <= 256 * 1024 and pos + 12 + code_size <= limit:
                        body = data[pos + 12 : pos + 12 + code_size]
                        if body and (body[-1] in (0x2A, 0x7A) or b"\x2a" in body):
                            tok = token_counter
                            methods[tok] = {
                                "token": tok,
                                "name": f"Method_{tok:08X}",
                                "offset": pos,
                                "format": "fat",
                                "code_size": code_size,
                                "bytecode": body,
                            }
                            token_counter += 1
                            pos += 12 + code_size
                            continue

            pos += 1

        # If no explicit Tiny/Fat methods were carved, treat valid sections/code as a single default method
        if not methods and len(data) >= 8:
            methods[0x06000001] = {
                "token": 0x06000001,
                "name": "MainMethod",
                "offset": 0,
                "format": "raw",
                "code_size": len(data),
                "bytecode": data[:min(len(data), 4096)],
            }
        return methods

    @classmethod
    def _compare_methods(
        cls,
        methods_a: Dict[int, Dict[str, Any]],
        methods_b: Dict[int, Dict[str, Any]],
        opts: BinaryDiffOptions,
    ) -> Tuple[List[MethodDiff], List[Tuple[float, Dict[str, Any]]], List[Tuple[float, Dict[str, Any]]], List[Tuple[float, Dict[str, Any]]]]:
        """Matches corresponding methods between binaries and calculates similarity metrics."""
        method_diffs = []
        byte_comps = []
        cfg_comps = []
        ast_comps = []

        tokens_a = set(methods_a.keys())
        tokens_b = set(methods_b.keys())
        common_tokens = sorted(tokens_a & tokens_b)

        for tok in common_tokens:
            ma = methods_a[tok]
            mb = methods_b[tok]
            ba = ma["bytecode"]
            bb = mb["bytecode"]

            b_score, b_metrics = BytecodeDiffer.compare_bytecodes(ba, bb)
            c_score, c_metrics = CFGDiffer.compare_method_cfgs(ba, bb, token=tok)
            a_score, a_metrics = ASTDiffer.compare_method_ast(ba, bb)

            overall_m = (b_score * 0.35) + (c_score * 0.4) + (a_score * 0.25)
            overall_m = max(0.0, min(1.0, round(overall_m, 4)))

            c_type = ChangeType.UNCHANGED if overall_m >= 0.99 else ChangeType.MODIFIED
            trans = []
            if c_metrics.get("is_flattened"):
                trans.append("Control Flow Flattening")
            if a_metrics.get("opaque_predicates", 0) > 0:
                trans.append(f"Opaque Predicates ({a_metrics['opaque_predicates']})")
            if abs(len(bb) - len(ba)) > 20:
                trans.append("Instruction Expansion")

            md = MethodDiff(
                token_a=tok,
                token_b=tok,
                name_a=ma["name"],
                name_b=mb["name"],
                opcode_similarity=b_score,
                cfg_similarity=c_score,
                ast_similarity=a_score,
                overall_similarity=overall_m,
                change_type=c_type,
                cyclomatic_delta=c_metrics.get("cyclomatic_delta", 0),
                block_count_delta=c_metrics.get("blocks_b", 0) - c_metrics.get("blocks_a", 0),
                instruction_count_delta=b_metrics.get("instructions_b", 0) - b_metrics.get("instructions_a", 0),
                detected_transformations=trans,
            )
            method_diffs.append(md)
            byte_comps.append((b_score, b_metrics))
            cfg_comps.append((c_score, c_metrics))
            ast_comps.append((a_score, a_metrics))

        # Handle methods only in A (removed)
        for tok in sorted(tokens_a - tokens_b):
            ma = methods_a[tok]
            method_diffs.append(MethodDiff(
                token_a=tok,
                token_b=None,
                name_a=ma["name"],
                name_b="",
                opcode_similarity=0.0,
                cfg_similarity=0.0,
                ast_similarity=0.0,
                overall_similarity=0.0,
                change_type=ChangeType.REMOVED,
            ))
            byte_comps.append((0.0, {"instructions_a": len(ma["bytecode"]), "instructions_b": 0}))

        # Handle methods only in B (added)
        for tok in sorted(tokens_b - tokens_a):
            mb = methods_b[tok]
            method_diffs.append(MethodDiff(
                token_a=None,
                token_b=tok,
                name_a="",
                name_b=mb["name"],
                opcode_similarity=0.0,
                cfg_similarity=0.0,
                ast_similarity=0.0,
                overall_similarity=0.0,
                change_type=ChangeType.ADDED,
            ))
            byte_comps.append((0.0, {"instructions_a": 0, "instructions_b": len(mb["bytecode"])}))

        return method_diffs, byte_comps, cfg_comps, ast_comps

    @classmethod
    def _evaluate_obfuscation_impacts(
        cls,
        metadata_diff: MetadataDiff,
        bytecode_diff: BytecodeDiff,
        cfg_diff: CFGGraphDiff,
        ast_diff: ASTFlowDiff,
        data_a: bytes,
        data_b: bytes,
    ) -> List[ObfuscationImpact]:
        """Identifies specific protector and obfuscation patterns from diff metrics."""
        impacts = []

        if metadata_diff.injected_sections:
            impacts.append(ObfuscationImpact.SECTION_INJECTION)

        if cfg_diff.flattened_methods_count > 0:
            impacts.append(ObfuscationImpact.CONTROL_FLOW_FLATTENING)

        # Check for entropy surge in sections (string/payload encryption)
        has_entropy_surge = any(s.is_entropy_surge for s in metadata_diff.section_diffs)
        if has_entropy_surge or (len(data_b) > len(data_a) * 1.5 and bytecode_diff.similarity_score < 0.5):
            impacts.append(ObfuscationImpact.STRING_ENCRYPTION)

        # Check for metadata stripping
        if "#Strings" in metadata_diff.stream_changes or "#US" in metadata_diff.stream_changes:
            impacts.append(ObfuscationImpact.METADATA_STRIPPING)

        # Check for embedded resource packing
        rsrc_delta = sum(
            s.raw_size_delta for s in metadata_diff.section_diffs if ".rsrc" in s.name.lower()
        )
        if rsrc_delta > 100 * 1024:
            impacts.append(ObfuscationImpact.RESOURCE_PACKING)

        if not impacts:
            impacts.append(ObfuscationImpact.NONE)

        return impacts

    @classmethod
    def _classify_diff_category(
        cls, composite_score: float, impacts: List[ObfuscationImpact]
    ) -> DiffCategory:
        """Classifies high-level divergence between binaries."""
        if composite_score >= 0.999:
            return DiffCategory.IDENTICAL
        if any(i in impacts for i in (ObfuscationImpact.CONTROL_FLOW_FLATTENING, ObfuscationImpact.SECTION_INJECTION, ObfuscationImpact.STRING_ENCRYPTION)):
            return DiffCategory.PACKED_OR_OBFUSCATED
        if composite_score >= 0.85:
            return DiffCategory.MINOR_MUTATION
        if composite_score >= 0.50:
            return DiffCategory.STRUCTURAL_CHANGE
        return DiffCategory.HEAVILY_DEVIATED

    @classmethod
    def format_text_diff(cls, result: BinaryDiffResult) -> str:
        """Formats human-readable unified terminal diff report."""
        r = result
        lines = [
            "=" * 78,
            f"[dotnet-packer-forensics] Multi-Engine Binary Diff Report",
            "=" * 78,
            f"Source A             : {r.source_a} ({r.sha256_a[:16]}...)",
            f"Source B             : {r.source_b} ({r.sha256_b[:16]}...)",
            f"Composite Similarity : {r.composite_similarity * 100:.2f}% [{r.diff_category.value.upper()}]",
            f"Execution Duration   : {r.telemetry.comparison_time_ms:.1f} ms",
            "",
            "--- [Layer Similarity Metrics] ---",
            f"  [+] Metadata Layer : {r.metadata_diff.similarity_score * 100:.1f}% ({len(r.metadata_diff.section_diffs)} sections, Imphash: {'MATCH' if r.metadata_diff.imphash_matched else 'DIFF'})",
            f"  [+] Bytecode Layer : {r.bytecode_diff.similarity_score * 100:.1f}% (Opcode Jaccard: {r.bytecode_diff.opcode_jaccard_avg * 100:.1f}%, Edit: {r.bytecode_diff.token_edit_similarity_avg * 100:.1f}%)",
            f"  [+] CFG Graph      : {r.cfg_diff.similarity_score * 100:.1f}% ({r.cfg_diff.total_blocks_b} blocks, &Delta;Cyc: {r.cfg_diff.cyclomatic_complexity_delta:+d}, Flattened: {r.cfg_diff.flattened_methods_count})",
            f"  [+] AST Semantics  : {r.ast_diff.similarity_score * 100:.1f}% (Opaque Predicates: {r.ast_diff.opaque_predicates_detected})",
            "",
            "--- [Detected Obfuscation / Packing Signatures] ---",
        ]
        for imp in r.detected_impacts:
            lines.append(f"  * {imp.value}")

        if r.metadata_diff.section_diffs:
            lines.append("")
            lines.append("--- [Section Header & Entropy Shifts] ---")
            for s in r.metadata_diff.section_diffs:
                inj = " [INJECTED]" if s.is_injected else ""
                surge = " [ENTROPY SURGE]" if s.is_entropy_surge else ""
                lines.append(
                    f"  {s.name:<12} {s.change_type.value.upper():<10} "
                    f"Raw: {s.raw_size_a:,} -> {s.raw_size_b:,} ({s.raw_size_delta:+,}b) "
                    f"Entropy: {s.entropy_a:.2f} -> {s.entropy_b:.2f} ({s.entropy_delta:+.2f}){inj}{surge}"
                )

        if r.method_diffs:
            lines.append("")
            lines.append(f"--- [CIL Method Comparison ({len(r.method_diffs)} methods)] ---")
            for m in r.method_diffs[:15]:
                tok = hex(m.token_a or m.token_b or 0)
                trans = f" ({', '.join(m.detected_transformations)})" if m.detected_transformations else ""
                lines.append(
                    f"  [{tok}] {m.change_type.value.upper():<10} {m.name_a or m.name_b:<24} "
                    f"Score: {m.overall_similarity * 100:.1f}% [Byte: {m.opcode_similarity*100:.0f}%, CFG: {m.cfg_similarity*100:.0f}%, AST: {m.ast_similarity*100:.0f}%]{trans}"
                )
            if len(r.method_diffs) > 15:
                lines.append(f"  ... and {len(r.method_diffs) - 15} more methods")

        lines.append("=" * 78)
        return "\n".join(lines)

    @classmethod
    def export_to_directory(
        cls, result: BinaryDiffResult, output_dir: str
    ) -> Dict[str, Any]:
        """Safely exports diff summary, method CSV, textual diff, and HTML dashboard."""
        os.makedirs(output_dir, exist_ok=True)
        exported = {}

        # 1. diff_summary.json
        json_path = safe_path(output_dir, "diff_summary.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        exported["json"] = json_path

        # 2. method_diffs.csv
        csv_path = safe_path(output_dir, "method_diffs.csv")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "status", "token_a", "token_b", "name_a", "name_b",
                "overall_similarity", "opcode_similarity", "cfg_similarity", "ast_similarity",
                "cyclomatic_delta", "block_delta", "transformations"
            ])
            for m in result.method_diffs:
                writer.writerow([
                    m.change_type.value,
                    hex(m.token_a) if m.token_a else "",
                    hex(m.token_b) if m.token_b else "",
                    m.name_a,
                    m.name_b,
                    f"{m.overall_similarity:.4f}",
                    f"{m.opcode_similarity:.4f}",
                    f"{m.cfg_similarity:.4f}",
                    f"{m.ast_similarity:.4f}",
                    m.cyclomatic_delta,
                    m.block_count_delta,
                    ";".join(m.detected_transformations),
                ])
        exported["csv"] = csv_path

        # 3. unified_diff.txt
        txt_path = safe_path(output_dir, "unified_diff.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(cls.format_text_diff(result))
        exported["txt"] = txt_path

        # 4. diff_report.html
        html_path = safe_path(output_dir, "diff_report.html")
        html_content = HTMLDiffReporter.generate(result)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        exported["html"] = html_path

        return {
            "output_dir": output_dir,
            "exported_files": exported,
            "files_count": len(exported),
        }
