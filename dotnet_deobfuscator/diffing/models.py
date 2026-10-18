"""
Data Models, Enums & Security Primitives for Multi-Engine Binary Diffing.
Engineered & Audited by Maya Thorne.
"""

import ctypes
from dataclasses import asdict, dataclass, field
from enum import Enum
import math
import os
from typing import Any, Dict, List, Optional, Union


class SecurityError(Exception):
    """Raised when path traversal or security violation is detected."""


def safe_path(base_dir: str, target_path: str) -> str:
    """Resolves and validates that target_path resides safely within base_dir."""
    resolved_base = os.path.realpath(base_dir)
    normalized_segment = target_path.replace("\\", "/").replace("/", os.sep)
    abs_target = os.path.realpath(os.path.join(resolved_base, normalized_segment))
    base_prefix = resolved_base if resolved_base.endswith(os.sep) else resolved_base + os.sep

    valid = (abs_target == resolved_base or abs_target.startswith(base_prefix))
    if not valid and os.name == "nt":
        try:
            common = os.path.commonpath([resolved_base, abs_target])
            if common.lower() == resolved_base.lower():
                valid = True
        except ValueError as e:
            raise SecurityError(f"Cross-drive or invalid path access: {target_path}") from e

    if not valid:
        raise SecurityError(f"Directory traversal detected: {target_path}")
    return abs_target



def zeroize_buffer(buf: Union[bytearray, memoryview, ctypes.Array, bytes]) -> None:
    """Overwrites mutable memory buffers with zeroes to prevent memory leaks."""
    if not buf:
        return
    try:
        if isinstance(buf, (bytearray, memoryview)):
            c_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.byref(c_arr), 0, len(buf))
        elif hasattr(buf, "_length_") and hasattr(buf, "_type_"):
            ctypes.memset(ctypes.byref(buf), 0, ctypes.sizeof(buf))
    except Exception:
        if isinstance(buf, (bytearray, memoryview)):
            for i in range(len(buf)):
                buf[i] = 0


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy [0.0 - 8.0] for byte sequence."""
    if not data:
        return 0.0
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class DiffCategory(str, Enum):
    """High-level classification of divergence between two binaries."""
    IDENTICAL = "identical"
    MINOR_MUTATION = "minor_mutation"
    STRUCTURAL_CHANGE = "structural_change"
    PACKED_OR_OBFUSCATED = "packed_or_obfuscated"
    HEAVILY_DEVIATED = "heavily_deviated"


class ChangeType(str, Enum):
    """Categorization of individual item change."""
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    REMOVED = "removed"
    RENAMED = "renamed"


class DiffEngine(str, Enum):
    """Target comparison engines."""
    ALL = "all"
    METADATA = "metadata"
    BYTECODE = "bytecode"
    CFG = "cfg"
    AST = "ast"


class ObfuscationImpact(str, Enum):
    """Identified obfuscation or packing transformation signatures."""
    STRING_ENCRYPTION = "string_encryption"
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    METADATA_STRIPPING = "metadata_stripping"
    SECTION_INJECTION = "section_injection"
    BYTECODE_VIRTUALIZATION = "bytecode_virtualization"
    RESOURCE_PACKING = "resource_packing"
    ANOMALOUS_MUTATION = "anomalous_mutation"
    NONE = "none"


@dataclass
class SectionDiff:
    """Detailed structural difference between matching PE sections."""
    name: str
    raw_size_a: int
    raw_size_b: int
    raw_size_delta: int
    virtual_size_a: int
    virtual_size_b: int
    virtual_size_delta: int
    entropy_a: float
    entropy_b: float
    entropy_delta: float
    change_type: ChangeType
    is_injected: bool = False
    is_entropy_surge: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["change_type"] = self.change_type.value
        return d


@dataclass
class MethodDiff:
    """Fine-grained comparison between corresponding CIL methods."""
    token_a: Optional[int]
    token_b: Optional[int]
    name_a: str
    name_b: str
    opcode_similarity: float
    cfg_similarity: float
    ast_similarity: float
    overall_similarity: float
    change_type: ChangeType
    cyclomatic_delta: int = 0
    block_count_delta: int = 0
    instruction_count_delta: int = 0
    detected_transformations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["change_type"] = self.change_type.value
        d["token_a"] = hex(self.token_a) if self.token_a else None
        d["token_b"] = hex(self.token_b) if self.token_b else None
        return d


@dataclass
class MetadataDiff:
    """Header, section, stream, and PE descriptor comparison results."""
    similarity_score: float
    header_changes: Dict[str, Any] = field(default_factory=dict)
    stream_changes: Dict[str, Any] = field(default_factory=dict)
    section_diffs: List[SectionDiff] = field(default_factory=list)
    imphash_a: str = ""
    imphash_b: str = ""
    imphash_matched: bool = True
    injected_sections: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "similarity_score": round(self.similarity_score, 4),
            "header_changes": self.header_changes,
            "stream_changes": self.stream_changes,
            "section_diffs": [s.to_dict() for s in self.section_diffs],
            "imphash_a": self.imphash_a,
            "imphash_b": self.imphash_b,
            "imphash_matched": self.imphash_matched,
            "injected_sections": self.injected_sections,
        }


@dataclass
class BytecodeDiff:
    """Instruction-level opcode sequence, edit distance, and n-gram results."""
    similarity_score: float
    opcode_jaccard_avg: float = 0.0
    token_edit_similarity_avg: float = 0.0
    n_gram_similarity_avg: float = 0.0
    total_instructions_a: int = 0
    total_instructions_b: int = 0
    identical_opcodes_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "similarity_score": round(self.similarity_score, 4),
            "opcode_jaccard_avg": round(self.opcode_jaccard_avg, 4),
            "token_edit_similarity_avg": round(self.token_edit_similarity_avg, 4),
            "n_gram_similarity_avg": round(self.n_gram_similarity_avg, 4),
            "total_instructions_a": self.total_instructions_a,
            "total_instructions_b": self.total_instructions_b,
            "identical_opcodes_count": self.identical_opcodes_count,
        }


@dataclass
class CFGGraphDiff:
    """Control flow graph topology, block partitioning, and complexity delta."""
    similarity_score: float
    total_blocks_a: int = 0
    total_blocks_b: int = 0
    total_edges_a: int = 0
    total_edges_b: int = 0
    cyclomatic_complexity_delta: int = 0
    flattened_methods_count: int = 0
    anomalous_blocks_delta: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "similarity_score": round(self.similarity_score, 4),
            "total_blocks_a": self.total_blocks_a,
            "total_blocks_b": self.total_blocks_b,
            "total_edges_a": self.total_edges_a,
            "total_edges_b": self.total_edges_b,
            "cyclomatic_complexity_delta": self.cyclomatic_complexity_delta,
            "flattened_methods_count": self.flattened_methods_count,
            "anomalous_blocks_delta": self.anomalous_blocks_delta,
        }


@dataclass
class ASTFlowDiff:
    """Statement, loop hierarchy, and high-level structure comparison."""
    similarity_score: float
    statement_similarity_avg: float = 0.0
    loop_structure_similarity: float = 0.0
    opaque_predicates_detected: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "similarity_score": round(self.similarity_score, 4),
            "statement_similarity_avg": round(self.statement_similarity_avg, 4),
            "loop_structure_similarity": round(self.loop_structure_similarity, 4),
            "opaque_predicates_detected": self.opaque_predicates_detected,
        }


@dataclass
class BinaryDiffOptions:
    """Execution options governing multi-engine binary diffing."""
    engine: DiffEngine = DiffEngine.ALL
    min_similarity_threshold: float = 0.8
    weight_metadata: float = 0.15
    weight_bytecode: float = 0.25
    weight_cfg: float = 0.35
    weight_ast: float = 0.25
    output_dir: Optional[str] = None


@dataclass
class BinaryDiffTelemetry:
    """Operational telemetry summarizing diff performance and findings."""
    comparison_time_ms: float = 0.0
    total_methods_a: int = 0
    total_methods_b: int = 0
    matched_methods: int = 0
    identical_methods: int = 0
    modified_methods: int = 0
    added_methods: int = 0
    removed_methods: int = 0
    composite_similarity: float = 0.0
    detected_impacts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["composite_similarity"] = round(self.composite_similarity, 4)
        return d


@dataclass
class BinaryDiffResult:
    """Unified container storing all binary diffing telemetry and findings."""
    source_a: str
    source_b: str
    sha256_a: str
    sha256_b: str
    composite_similarity: float
    diff_category: DiffCategory
    metadata_diff: MetadataDiff
    bytecode_diff: BytecodeDiff
    cfg_diff: CFGGraphDiff
    ast_diff: ASTFlowDiff
    method_diffs: List[MethodDiff]
    detected_impacts: List[ObfuscationImpact]
    telemetry: BinaryDiffTelemetry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_a": self.source_a,
            "source_b": self.source_b,
            "sha256_a": self.sha256_a,
            "sha256_b": self.sha256_b,
            "composite_similarity": round(self.composite_similarity, 4),
            "diff_category": self.diff_category.value,
            "metadata_diff": self.metadata_diff.to_dict(),
            "bytecode_diff": self.bytecode_diff.to_dict(),
            "cfg_diff": self.cfg_diff.to_dict(),
            "ast_diff": self.ast_diff.to_dict(),
            "method_diffs": [m.to_dict() for m in self.method_diffs],
            "detected_impacts": [i.value for i in self.detected_impacts],
            "telemetry": self.telemetry.to_dict(),
        }
