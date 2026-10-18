"""
CIL Control Flow Graph (CFG) Topology & State Machine Differ.
Engineered & Audited by Maya Thorne.
"""

from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from ..cfg.builder import CFGBuilder
from ..cfg.disassembler import CILDisassembler
from ..cfg.models import CFGBlock, CFGEdgeType, MethodCFG
from .models import CFGGraphDiff


class CFGDiffer:
    """Compares control flow graphs, detects flattening, and matches basic blocks."""

    @classmethod
    def compare_method_cfgs(
        cls, code_a: bytes, code_b: bytes, token: int = 0x06000001
    ) -> Tuple[float, Dict[str, Any]]:
        """Builds and compares CFGs of two method bytecode streams."""
        ins_a = CILDisassembler.disassemble(code_a)
        ins_b = CILDisassembler.disassemble(code_b)

        if code_a == code_b:
            cfg = CFGBuilder.build(ins_a, method_token=token)
            return 1.0, {
                "blocks_a": len(cfg.blocks),
                "blocks_b": len(cfg.blocks),
                "edges_a": len(cfg.edges),
                "edges_b": len(cfg.edges),
                "cyclomatic_a": cfg.cyclomatic_complexity,
                "cyclomatic_b": cfg.cyclomatic_complexity,
                "cyclomatic_delta": 0,
                "block_jaccard": 1.0,
                "is_flattened": False,
                "anomalous_blocks_delta": 0,
            }

        cfg_a = CFGBuilder.build(ins_a, method_token=token)
        cfg_b = CFGBuilder.build(ins_b, method_token=token)

        blocks_a = list(cfg_a.blocks.values())
        blocks_b = list(cfg_b.blocks.values())

        if not blocks_a and not blocks_b:
            return 1.0, cls._empty_metrics()
        if not blocks_a or not blocks_b:
            return 0.0, {
                "blocks_a": len(blocks_a),
                "blocks_b": len(blocks_b),
                "edges_a": len(cfg_a.edges),
                "edges_b": len(cfg_b.edges),
                "cyclomatic_a": cfg_a.cyclomatic_complexity,
                "cyclomatic_b": cfg_b.cyclomatic_complexity,
                "cyclomatic_delta": cfg_b.cyclomatic_complexity - cfg_a.cyclomatic_complexity,
                "block_jaccard": 0.0,
                "is_flattened": False,
                "anomalous_blocks_delta": len(getattr(cfg_b, "anomalies_detected", [])) - len(getattr(cfg_a, "anomalies_detected", [])),
            }

        # Block count similarity
        b_max = max(len(blocks_a), len(blocks_b))
        b_ratio = min(len(blocks_a), len(blocks_b)) / b_max if b_max > 0 else 1.0

        # Edge count similarity
        e_max = max(len(cfg_a.edges), len(cfg_b.edges))
        e_ratio = min(len(cfg_a.edges), len(cfg_b.edges)) / e_max if e_max > 0 else 1.0

        # Cyclomatic complexity similarity
        c_max = max(cfg_a.cyclomatic_complexity, cfg_b.cyclomatic_complexity)
        c_ratio = min(cfg_a.cyclomatic_complexity, cfg_b.cyclomatic_complexity) / c_max if c_max > 0 else 1.0

        # Block signature matching
        sig_a = [cls._block_signature(blk) for blk in blocks_a]
        sig_b = [cls._block_signature(blk) for blk in blocks_b]
        ca = Counter(sig_a)
        cb = Counter(sig_b)
        intersection = sum((ca & cb).values())
        union = sum((ca | cb).values())
        block_jaccard = (intersection / union) if union > 0 else 1.0

        # Detection of Control Flow Flattening
        is_flattened = cls._detect_control_flow_flattening(cfg_a, cfg_b)

        # Composite CFG similarity score
        score = (b_ratio * 0.25) + (e_ratio * 0.25) + (c_ratio * 0.2) + (block_jaccard * 0.3)
        if is_flattened:
            score *= 0.4  # Steep penalty for control flow flattening
        score = max(0.0, min(1.0, round(score, 4)))

        metrics = {
            "blocks_a": len(blocks_a),
            "blocks_b": len(blocks_b),
            "edges_a": len(cfg_a.edges),
            "edges_b": len(cfg_b.edges),
            "cyclomatic_a": cfg_a.cyclomatic_complexity,
            "cyclomatic_b": cfg_b.cyclomatic_complexity,
            "cyclomatic_delta": cfg_b.cyclomatic_complexity - cfg_a.cyclomatic_complexity,
            "block_jaccard": round(block_jaccard, 4),
            "is_flattened": is_flattened,
            "anomalous_blocks_delta": len(getattr(cfg_b, "anomalies_detected", [])) - len(getattr(cfg_a, "anomalies_detected", [])),
        }
        return score, metrics

    @classmethod
    def _block_signature(cls, blk: CFGBlock) -> str:
        """Derives a resilient topological signature for a basic block."""
        first_op = getattr(blk.instructions[0], "name", getattr(blk.instructions[0], "mnemonic", "")).lower() if blk.instructions else "empty"
        last_op = getattr(blk.instructions[-1], "name", getattr(blk.instructions[-1], "mnemonic", "")).lower() if blk.instructions else "empty"
        ins_count = len(blk.instructions)
        # Quantize entropy to 0.5 buckets to absorb slight operand variances
        ent_bucket = round(blk.entropy * 2) / 2
        return f"{first_op}:{last_op}:{ins_count}:{ent_bucket}"

    @classmethod
    def _detect_control_flow_flattening(cls, cfg_a: MethodCFG, cfg_b: MethodCFG) -> bool:
        """Identifies hallmarks of state-machine control flow flattening transformation."""
        len_a = len(cfg_a.blocks)
        len_b = len(cfg_b.blocks)

        # 1. Block explosion heuristic: basic blocks doubled or more and >= 4
        block_surge = (len_b >= 4) and (len_b >= len_a * 2.0)

        # 2. Switch dispatcher presence in CFG B
        has_switch = any(
            any(getattr(i, "name", "") == "switch" for i in blk.instructions)
            for blk in cfg_b.blocks.values()
        )

        # 3. State dispatcher search in CFG B (high branching degree)
        has_central_dispatcher = False
        for blk in cfg_b.blocks.values():
            out_edges = [e for e in cfg_b.edges if getattr(e, "source_id", getattr(e, "source_block_id", -1)) == blk.block_id]
            if len(out_edges) >= 2:
                in_edges = [e for e in cfg_b.edges if getattr(e, "target_id", getattr(e, "target_block_id", -1)) == blk.block_id]
                if len(in_edges) >= 1 or len(out_edges) >= 3:
                    has_central_dispatcher = True
                    break

        # 4. Cyclomatic complexity surge
        c_delta = cfg_b.cyclomatic_complexity - cfg_a.cyclomatic_complexity
        complexity_surge = c_delta >= 3 and cfg_b.cyclomatic_complexity >= 4

        return (has_switch and (block_surge or has_central_dispatcher)) or (block_surge and has_central_dispatcher) or (has_central_dispatcher and complexity_surge)

    @classmethod
    def _empty_metrics(cls) -> Dict[str, Any]:
        return {
            "blocks_a": 0, "blocks_b": 0, "edges_a": 0, "edges_b": 0,
            "cyclomatic_a": 1, "cyclomatic_b": 1, "cyclomatic_delta": 0,
            "block_jaccard": 1.0, "is_flattened": False, "anomalous_blocks_delta": 0,
        }

    @classmethod
    def aggregate_methods_cfg(
        cls, method_comparisons: List[Tuple[float, Dict[str, Any]]]
    ) -> CFGGraphDiff:
        """Aggregates method-level CFG comparison metrics into CFGGraphDiff."""
        if not method_comparisons:
            return CFGGraphDiff(similarity_score=1.0)

        total_sim = sum(c[0] for c in method_comparisons)
        avg_sim = total_sim / len(method_comparisons)

        tot_b_a = sum(c[1].get("blocks_a", 0) for c in method_comparisons)
        tot_b_b = sum(c[1].get("blocks_b", 0) for c in method_comparisons)
        tot_e_a = sum(c[1].get("edges_a", 0) for c in method_comparisons)
        tot_e_b = sum(c[1].get("edges_b", 0) for c in method_comparisons)
        cyc_delta = sum(c[1].get("cyclomatic_delta", 0) for c in method_comparisons)
        flat_count = sum(1 for c in method_comparisons if c[1].get("is_flattened", False))
        anom_delta = sum(c[1].get("anomalous_blocks_delta", 0) for c in method_comparisons)

        return CFGGraphDiff(
            similarity_score=round(avg_sim, 4),
            total_blocks_a=tot_b_a,
            total_blocks_b=tot_b_b,
            total_edges_a=tot_e_a,
            total_edges_b=tot_e_b,
            cyclomatic_complexity_delta=cyc_delta,
            flattened_methods_count=flat_count,
            anomalous_blocks_delta=anom_delta,
        )
