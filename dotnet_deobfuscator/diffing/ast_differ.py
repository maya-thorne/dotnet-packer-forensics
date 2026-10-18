"""
AST Control Flow & Semantic Statement Differ for Binary Comparison.
Engineered & Audited by Maya Thorne.
"""

from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..cfg.disassembler import CILDisassembler
from ..cfg.models import CFGInstruction
from .models import ASTFlowDiff


class ASTDiffer:
    """Extracts statement-level flow representations and compares semantic AST structures."""

    @classmethod
    def compare_method_ast(cls, code_a: bytes, code_b: bytes) -> Tuple[float, Dict[str, Any]]:
        """Constructs and compares statement-level flow AST representations."""
        if code_a == code_b:
            stmts = cls._extract_statements(code_a)
            return 1.0, {
                "statements_a": len(stmts),
                "statements_b": len(stmts),
                "statement_similarity": 1.0,
                "loop_structure_similarity": 1.0,
                "opaque_predicates": 0,
            }

        stmts_a = cls._extract_statements(code_a)
        stmts_b = cls._extract_statements(code_b)

        if not stmts_a and not stmts_b:
            return 1.0, cls._empty_metrics()
        if not stmts_a or not stmts_b:
            return 0.0, {
                "statements_a": len(stmts_a),
                "statements_b": len(stmts_b),
                "statement_similarity": 0.0,
                "loop_structure_similarity": 0.0,
                "opaque_predicates": 0,
            }

        # Statement multiset Jaccard
        ca = Counter(stmts_a)
        cb = Counter(stmts_b)
        intersection = sum((ca & cb).values())
        union = sum((ca | cb).values())
        stmt_sim = (intersection / union) if union > 0 else 1.0

        # Loop / nesting structure estimation
        loop_sim = cls._compare_loop_structure(code_a, code_b)

        # Detect Opaque Predicates in Binary B
        opaque_count = cls._detect_opaque_predicates(code_b)

        score = (stmt_sim * 0.6) + (loop_sim * 0.4)
        if opaque_count > 0:
            score = max(0.0, score - min(0.3, opaque_count * 0.1))
        score = max(0.0, min(1.0, round(score, 4)))

        metrics = {
            "statements_a": len(stmts_a),
            "statements_b": len(stmts_b),
            "statement_similarity": round(stmt_sim, 4),
            "loop_structure_similarity": round(loop_sim, 4),
            "opaque_predicates": opaque_count,
        }
        return score, metrics

    @classmethod
    def _extract_statements(cls, code: bytes) -> List[str]:
        """Translates linear CIL instructions into high-level AST statement tokens."""
        instructions = CILDisassembler.disassemble(code)
        statements = []
        for ins in instructions:
            m = getattr(ins, "name", getattr(ins, "mnemonic", "")).lower()
            if m.startswith("stloc") or m.startswith("starg") or m.startswith("stfld") or m.startswith("stsfld"):
                statements.append("ASSIGNMENT")
            elif m in ("call", "callvirt", "newobj", "calli"):
                statements.append("INVOCATION")
            elif m in ("brtrue", "brtrue.s", "brfalse", "brfalse.s"):
                statements.append("COND_BRANCH")
            elif m.startswith("b") and (m.endswith(".s") or len(m) <= 4):
                statements.append("COMP_BRANCH")
            elif m in ("br", "br.s", "leave", "leave.s"):
                statements.append("UNCOND_BRANCH")
            elif m == "switch":
                statements.append("SWITCH_DISPATCH")
            elif m == "ret":
                statements.append("RETURN")
            elif m in ("throw", "rethrow"):
                statements.append("THROW")
            elif m in ("add", "sub", "mul", "div", "rem", "xor", "and", "or", "shl", "shr", "not", "neg"):
                statements.append("ARITHMETIC")
        return statements

    @classmethod
    def _compare_loop_structure(cls, code_a: bytes, code_b: bytes) -> float:
        """Compares backward-branch loop topologies between two bytecode sequences."""
        def count_backwards_branches(c: bytes) -> int:
            instructions = CILDisassembler.disassemble(c)
            count = 0
            for ins in instructions:
                m = getattr(ins, "name", getattr(ins, "mnemonic", "")).lower()
                target = getattr(ins, "branch_target", None)
                if (m.startswith("b") or m.startswith("br")) and target is not None:
                    if target < ins.offset:
                        count += 1
            return count

        loops_a = count_backwards_branches(code_a)
        loops_b = count_backwards_branches(code_b)

        if loops_a == loops_b:
            return 1.0
        m_max = max(loops_a, loops_b)
        return min(loops_a, loops_b) / m_max if m_max > 0 else 1.0

    @classmethod
    def _detect_opaque_predicates(cls, code: bytes) -> int:
        """Identifies injected trivial constant conditions (e.g., ldc.i4.1 followed by brtrue)."""
        instructions = CILDisassembler.disassemble(code)
        opaque_count = 0
        for i in range(len(instructions) - 1):
            curr_op = getattr(instructions[i], "name", getattr(instructions[i], "mnemonic", "")).lower()
            next_op = getattr(instructions[i + 1], "name", getattr(instructions[i + 1], "mnemonic", "")).lower()
            # Pattern: ldc.i4.1; brtrue -> always jumps (tautology)
            if curr_op in ("ldc.i4.1", "ldc.i4.m1") and next_op in ("brtrue", "brtrue.s"):
                opaque_count += 1
            # Pattern: ldc.i4.0; brfalse -> always jumps (tautology)
            elif curr_op == "ldc.i4.0" and next_op in ("brfalse", "brfalse.s"):
                opaque_count += 1
            # Pattern: ldc.i4.1; brfalse -> never jumps (dead branch)
            elif curr_op in ("ldc.i4.1", "ldc.i4.m1") and next_op in ("brfalse", "brfalse.s"):
                opaque_count += 1
            # Pattern: ldc.i4.0; brtrue -> never jumps (dead branch)
            elif curr_op == "ldc.i4.0" and next_op in ("brtrue", "brtrue.s"):
                opaque_count += 1
        return opaque_count

    @classmethod
    def _empty_metrics(cls) -> Dict[str, Any]:
        return {
            "statements_a": 0, "statements_b": 0, "statement_similarity": 1.0,
            "loop_structure_similarity": 1.0, "opaque_predicates": 0,
        }

    @classmethod
    def aggregate_methods_ast(
        cls, method_comparisons: List[Tuple[float, Dict[str, Any]]]
    ) -> ASTFlowDiff:
        """Aggregates method-level AST metrics into ASTFlowDiff."""
        if not method_comparisons:
            return ASTFlowDiff(similarity_score=1.0)

        total_sim = sum(c[0] for c in method_comparisons)
        avg_sim = total_sim / len(method_comparisons)

        avg_stmt = sum(c[1].get("statement_similarity", 0.0) for c in method_comparisons) / len(method_comparisons)
        avg_loop = sum(c[1].get("loop_structure_similarity", 0.0) for c in method_comparisons) / len(method_comparisons)
        tot_opaque = sum(c[1].get("opaque_predicates", 0) for c in method_comparisons)

        return ASTFlowDiff(
            similarity_score=round(avg_sim, 4),
            statement_similarity_avg=round(avg_stmt, 4),
            loop_structure_similarity=round(avg_loop, 4),
            opaque_predicates_detected=tot_opaque,
        )
