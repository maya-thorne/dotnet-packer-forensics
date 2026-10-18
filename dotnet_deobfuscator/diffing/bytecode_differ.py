"""
CIL Bytecode & Opcode Sequence Differ for Binary Comparison.
Engineered & Audited by Maya Thorne.
"""

from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..cfg.disassembler import CILDisassembler
from ..cfg.models import CFGInstruction
from .models import BytecodeDiff


class BytecodeDiffer:
    """Computes instruction-level similarity, edit distances, and opcode n-gram metrics."""

    @classmethod
    def compare_bytecodes(cls, code_a: bytes, code_b: bytes) -> Tuple[float, Dict[str, Any]]:
        """Compares two raw CIL method bytecode streams and yields similarity metrics."""
        if code_a == code_b:
            return 1.0, {
                "opcode_jaccard": 1.0,
                "token_edit_similarity": 1.0,
                "n_gram_similarity": 1.0,
                "instructions_a": len(code_a),
                "instructions_b": len(code_b),
                "identical_count": len(code_a),
            }

        instructions_a = CILDisassembler.disassemble(code_a)
        instructions_b = CILDisassembler.disassemble(code_b)

        if not instructions_a and not instructions_b:
            return 1.0, {
                "opcode_jaccard": 1.0,
                "token_edit_similarity": 1.0,
                "n_gram_similarity": 1.0,
                "instructions_a": 0,
                "instructions_b": 0,
                "identical_count": 0,
            }
        if not instructions_a or not instructions_b:
            return 0.0, {
                "opcode_jaccard": 0.0,
                "token_edit_similarity": 0.0,
                "n_gram_similarity": 0.0,
                "instructions_a": len(instructions_a),
                "instructions_b": len(instructions_b),
                "identical_count": 0,
            }

        norm_a = [cls.normalize_instruction(ins) for ins in instructions_a]
        norm_b = [cls.normalize_instruction(ins) for ins in instructions_b]

        jaccard = cls.calculate_jaccard(norm_a, norm_b)
        edit_sim = cls.calculate_edit_similarity(norm_a, norm_b)
        ngram_sim = cls.calculate_ngram_similarity(norm_a, norm_b, n=3)

        # Weighted combination of bytecode similarity metrics
        score = (jaccard * 0.3) + (edit_sim * 0.4) + (ngram_sim * 0.3)
        score = max(0.0, min(1.0, round(score, 4)))

        # Count matched opcodes
        c_a = Counter(norm_a)
        c_b = Counter(norm_b)
        shared_count = sum((c_a & c_b).values())

        metrics = {
            "opcode_jaccard": round(jaccard, 4),
            "token_edit_similarity": round(edit_sim, 4),
            "n_gram_similarity": round(ngram_sim, 4),
            "instructions_a": len(instructions_a),
            "instructions_b": len(instructions_b),
            "identical_count": shared_count,
        }
        return score, metrics

    @classmethod
    def normalize_instruction(cls, ins: CFGInstruction) -> str:
        """Normalizes opcode mnemonics and abstracts volatile operands."""
        m = getattr(ins, "name", getattr(ins, "mnemonic", "")).lower()
        # Normalize numeric constant loads
        if m.startswith("ldc.i4"):
            return "ldc.i4"
        if m.startswith("ldloc"):
            return "ldloc"
        if m.startswith("stloc"):
            return "stloc"
        if m.startswith("ldarg"):
            return "ldarg"
        if m.startswith("starg"):
            return "starg"
        # Normalize short vs long branch opcodes
        if m in ("br.s", "br"):
            return "branch_uncond"
        if m in ("brtrue.s", "brtrue", "brfalse.s", "brfalse"):
            return "branch_cond"
        if m.startswith("b") and (m.endswith(".s") or len(m) <= 4):
            return "branch_comp"
        return m

    @classmethod
    def calculate_jaccard(cls, seq_a: Sequence[str], seq_b: Sequence[str]) -> float:
        """Computes multiset Jaccard similarity between two token sequences."""
        if not seq_a and not seq_b:
            return 1.0
        if not seq_a or not seq_b:
            return 0.0
        ca = Counter(seq_a)
        cb = Counter(seq_b)
        intersection = sum((ca & cb).values())
        union = sum((ca | cb).values())
        if union == 0:
            return 1.0
        return intersection / union

    @classmethod
    def calculate_edit_similarity(cls, seq_a: Sequence[str], seq_b: Sequence[str]) -> float:
        """Computes normalized Levenshtein sequence alignment similarity."""
        len_a = len(seq_a)
        len_b = len(seq_b)
        if len_a == 0 and len_b == 0:
            return 1.0
        if len_a == 0 or len_b == 0:
            return 0.0

        # Memory-efficient Levenshtein distance using 2 rows
        # Limit comparison length to 1000 to maintain O(1) responsive execution
        limit = 1000
        sa = seq_a[:limit]
        sb = seq_b[:limit]
        la = len(sa)
        lb = len(sb)

        prev = list(range(lb + 1))
        curr = [0] * (lb + 1)

        for i in range(1, la + 1):
            curr[0] = i
            elem_a = sa[i - 1]
            for j in range(1, lb + 1):
                cost = 0 if elem_a == sb[j - 1] else 1
                curr[j] = min(
                    prev[j] + 1,       # deletion
                    curr[j - 1] + 1,   # insertion
                    prev[j - 1] + cost # substitution
                )
            prev, curr = curr, prev

        dist = prev[lb]
        max_len = max(la, lb)
        return max(0.0, 1.0 - (dist / max_len))

    @classmethod
    def calculate_ngram_similarity(cls, seq: Sequence[str], seq_target: Sequence[str], n: int = 3) -> float:
        """Computes n-gram multiset Dice/Jaccard similarity."""
        def extract_ngrams(s: Sequence[str]) -> Counter:
            if len(s) < n:
                return Counter([tuple(s)]) if s else Counter()
            return Counter(tuple(s[i:i+n]) for i in range(len(s) - n + 1))

        ng_a = extract_ngrams(seq)
        ng_b = extract_ngrams(seq_target)

        if not ng_a and not ng_b:
            return 1.0
        if not ng_a or not ng_b:
            return 0.0

        intersection = sum((ng_a & ng_b).values())
        total = sum(ng_a.values()) + sum(ng_b.values())
        if total == 0:
            return 1.0
        # Sorensen-Dice coefficient
        return (2.0 * intersection) / total

    @classmethod
    def aggregate_methods_bytecode(
        cls, method_comparisons: List[Tuple[float, Dict[str, Any]]]
    ) -> BytecodeDiff:
        """Aggregates individual method bytecode diff results into BytecodeDiff."""
        if not method_comparisons:
            return BytecodeDiff(similarity_score=1.0)

        total_sim = sum(c[0] for c in method_comparisons)
        avg_sim = total_sim / len(method_comparisons)

        avg_jaccard = sum(c[1].get("opcode_jaccard", 0.0) for c in method_comparisons) / len(method_comparisons)
        avg_edit = sum(c[1].get("token_edit_similarity", 0.0) for c in method_comparisons) / len(method_comparisons)
        avg_ngram = sum(c[1].get("n_gram_similarity", 0.0) for c in method_comparisons) / len(method_comparisons)
        tot_ins_a = sum(c[1].get("instructions_a", 0) for c in method_comparisons)
        tot_ins_b = sum(c[1].get("instructions_b", 0) for c in method_comparisons)
        ident_count = sum(c[1].get("identical_count", 0) for c in method_comparisons)

        return BytecodeDiff(
            similarity_score=round(avg_sim, 4),
            opcode_jaccard_avg=round(avg_jaccard, 4),
            token_edit_similarity_avg=round(avg_edit, 4),
            n_gram_similarity_avg=round(avg_ngram, 4),
            total_instructions_a=tot_ins_a,
            total_instructions_b=tot_ins_b,
            identical_opcodes_count=ident_count,
        )
