"""
CIL Control Flow Graph (CFG) & High-Entropy Block Forensics Data Models.
Engineered & Audited by Maya Thorne.
"""

from enum import Enum, auto
import ctypes
import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class CFGEdgeType(Enum):
    """Classification of directed control flow transitions between basic blocks."""

    FALLTHROUGH = "fallthrough"
    UNCONDITIONAL_BRANCH = "unconditional"
    CONDITIONAL_TRUE = "cond_true"
    CONDITIONAL_FALSE = "cond_false"
    SWITCH_BRANCH = "switch"
    EXCEPTION_HANDLER = "exception"


class BlockEntropyLevel(Enum):
    """Categorization of Shannon entropy in basic block bytecode chunks."""

    LOW = "low"              # H < 3.0: Highly predictable boilerplate or nops
    NORMAL = "normal"        # 3.0 <= H < 5.5: Standard CIL instructions & operands
    SUSPICIOUS = "suspicious"# 5.5 <= H < 6.8: Packed constants or arithmetic mutation
    HIGH_ENTROPY = "high"    # H >= 6.8: Encrypted payload, native shellcode, or packer stub


class BlockAnomalyFlag(Enum):
    """Security and structural anomaly indicators detected within a basic block."""

    HIGH_ENTROPY_BLOCK = "high_entropy_bytes"
    OPAQUE_PREDICATE_SUSPECT = "opaque_predicate_suspect"
    UNREACHABLE_DEAD_CODE = "unreachable_dead_code"
    ABNORMAL_BRANCH_TARGET = "abnormal_branch_target"
    STATE_DISPATCHER = "state_dispatcher"
    STACK_UNDERFLOW_SUSPECT = "stack_underflow_suspect"


class DiagramFormat(Enum):
    """Supported visual flowchart and serialization export formats."""

    MERMAID = "mermaid"
    DOT = "dot"
    SVG = "svg"
    ASCII = "ascii"
    JSON = "json"


class FlowControl(Enum):
    """Instruction branch and termination characteristics."""

    NEXT = "next"
    BRANCH = "branch"
    COND_BRANCH = "cond_branch"
    SWITCH = "switch"
    RET = "ret"
    THROW = "throw"


class SecurityError(Exception):
    """Raised when an operation violates security boundaries or attempts path traversal."""
    pass


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0) for byte sequence."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def zeroize_buffer(buf: Union[bytearray, memoryview, ctypes.Array]) -> None:
    """Zeroizes in-memory buffers using ctypes.memset to eliminate residual cryptographic remnants."""
    if not buf:
        return
    try:
        if isinstance(buf, (bytearray, memoryview)):
            c_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.byref(c_arr), 0, len(buf))
        elif hasattr(buf, "_length_") and hasattr(buf, "_type_"):
            ctypes.memset(ctypes.byref(buf), 0, ctypes.sizeof(buf))
    except Exception:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0


class CFGInstruction:
    """Represents a decoded ECMA-335 CIL instruction within a control flow graph."""

    def __init__(
        self,
        offset: int,
        opcode: int,
        name: str,
        operand: Any = None,
        size: int = 1,
        raw_bytes: bytes = b"",
        branch_target: Optional[int] = None,
        switch_targets: Optional[List[int]] = None,
        flow_control: FlowControl = FlowControl.NEXT,
    ):
        self.offset = offset
        self.opcode = opcode
        self.name = name
        self.operand = operand
        self.size = size
        self.raw_bytes = raw_bytes
        self.branch_target = branch_target
        self.switch_targets = switch_targets or []
        self.flow_control = flow_control

    def is_branch(self) -> bool:
        return self.flow_control in (FlowControl.BRANCH, FlowControl.COND_BRANCH)

    def is_conditional(self) -> bool:
        return self.flow_control == FlowControl.COND_BRANCH

    def is_terminator(self) -> bool:
        return self.flow_control in (
            FlowControl.BRANCH,
            FlowControl.COND_BRANCH,
            FlowControl.SWITCH,
            FlowControl.RET,
            FlowControl.THROW,
        )

    def format(self) -> str:
        op_str = ""
        if self.branch_target is not None:
            op_str = f" IL_{self.branch_target:04X}"
        elif self.switch_targets:
            targets_str = ", ".join(f"IL_{t:04X}" for t in self.switch_targets)
            op_str = f" ({targets_str})"
        elif self.operand is not None:
            if isinstance(self.operand, int):
                op_str = f" 0x{self.operand:X}" if self.operand > 9 or self.operand < -9 else f" {self.operand}"
            else:
                op_str = f" {self.operand}"
        return f"IL_{self.offset:04X}: {self.name}{op_str}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "offset_hex": f"IL_{self.offset:04X}",
            "opcode": self.opcode,
            "opcode_hex": f"0x{self.opcode:04X}" if self.opcode > 0xFF else f"0x{self.opcode:02X}",
            "name": self.name,
            "operand": str(self.operand) if self.operand is not None else None,
            "size": self.size,
            "branch_target": self.branch_target,
            "branch_target_hex": f"IL_{self.branch_target:04X}" if self.branch_target is not None else None,
            "switch_targets": [f"IL_{t:04X}" for t in self.switch_targets],
            "flow_control": self.flow_control.value,
        }

    def __repr__(self) -> str:
        return self.format()


class CFGEdge:
    """Represents a directed edge between two basic blocks in a CFG."""

    def __init__(
        self,
        source_id: int,
        target_id: int,
        edge_type: CFGEdgeType,
        condition_label: Optional[str] = None,
    ):
        self.source_id = source_id
        self.target_id = target_id
        self.edge_type = edge_type
        self.condition_label = condition_label

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "condition_label": self.condition_label,
        }

    def __repr__(self) -> str:
        label = f" [{self.condition_label}]" if self.condition_label else ""
        return f"CFGEdge(B{self.source_id} -> B{self.target_id}, {self.edge_type.value}{label})"


class CFGBlock:
    """Represents a discrete basic block with Shannon entropy and anomaly telemetry."""

    def __init__(
        self,
        block_id: int,
        start_offset: int,
        end_offset: int,
        instructions: Optional[List[CFGInstruction]] = None,
        raw_bytes: bytes = b"",
        entropy: float = 0.0,
        entropy_level: BlockEntropyLevel = BlockEntropyLevel.NORMAL,
    ):
        self.block_id = block_id
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.instructions: List[CFGInstruction] = instructions or []
        self.raw_bytes = raw_bytes
        self.entropy = entropy
        self.entropy_level = entropy_level
        self.predecessors: Set[int] = set()
        self.successors: Set[int] = set()
        self.anomaly_flags: List[BlockAnomalyFlag] = []
        self.is_entry: bool = False
        self.is_exit: bool = False
        self.is_dead: bool = False
        self.is_loop_head: bool = False

    @property
    def last_instruction(self) -> Optional[CFGInstruction]:
        return self.instructions[-1] if self.instructions else None

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def byte_size(self) -> int:
        return len(self.raw_bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_id": self.block_id,
            "start_offset": self.start_offset,
            "start_offset_hex": f"IL_{self.start_offset:04X}",
            "end_offset": self.end_offset,
            "end_offset_hex": f"IL_{self.end_offset:04X}",
            "instruction_count": len(self.instructions),
            "byte_size": len(self.raw_bytes),
            "entropy": self.entropy,
            "entropy_level": self.entropy_level.value,
            "predecessors": sorted(list(self.predecessors)),
            "successors": sorted(list(self.successors)),
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
            "is_dead": self.is_dead,
            "is_loop_head": self.is_loop_head,
            "anomaly_flags": [f.value for f in self.anomaly_flags],
            "instructions": [i.to_dict() for i in self.instructions],
        }

    def __repr__(self) -> str:
        return (
            f"CFGBlock(id={self.block_id}, range=[IL_{self.start_offset:04X}..IL_{self.end_offset:04X}], "
            f"entropy={self.entropy} ({self.entropy_level.value}), insts={len(self.instructions)}, "
            f"succs={sorted(list(self.successors))})"
        )


class MethodCFG:
    """Represents a complete control flow graph for a single CIL method."""

    def __init__(
        self,
        method_token: int,
        method_name: str,
        entry_block_id: int = 0,
        blocks: Optional[Dict[int, CFGBlock]] = None,
        edges: Optional[List[CFGEdge]] = None,
        cyclomatic_complexity: int = 1,
        max_entropy: float = 0.0,
        average_entropy: float = 0.0,
        high_entropy_block_count: int = 0,
        dead_block_count: int = 0,
        loop_count: int = 0,
        anomalies_detected: Optional[List[str]] = None,
    ):
        self.method_token = method_token
        self.method_name = method_name
        self.entry_block_id = entry_block_id
        self.blocks: Dict[int, CFGBlock] = blocks or {}
        self.edges: List[CFGEdge] = edges or []
        self.cyclomatic_complexity = cyclomatic_complexity
        self.max_entropy = max_entropy
        self.average_entropy = average_entropy
        self.high_entropy_block_count = high_entropy_block_count
        self.dead_block_count = dead_block_count
        self.loop_count = loop_count
        self.anomalies_detected: List[str] = anomalies_detected or []

    def get_block(self, block_id: int) -> Optional[CFGBlock]:
        return self.blocks.get(block_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method_token": self.method_token,
            "method_token_hex": f"0x{self.method_token:08X}",
            "method_name": self.method_name,
            "entry_block_id": self.entry_block_id,
            "block_count": len(self.blocks),
            "edge_count": len(self.edges),
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "max_entropy": self.max_entropy,
            "average_entropy": self.average_entropy,
            "high_entropy_block_count": self.high_entropy_block_count,
            "dead_block_count": self.dead_block_count,
            "loop_count": self.loop_count,
            "anomalies_detected": self.anomalies_detected,
            "blocks": {bid: b.to_dict() for bid, b in sorted(self.blocks.items())},
            "edges": [e.to_dict() for e in self.edges],
        }


class CFGTelemetry:
    """Aggregate forensic telemetry across all analyzed methods in a binary."""

    def __init__(
        self,
        total_methods_analyzed: int = 0,
        total_blocks: int = 0,
        total_edges: int = 0,
        high_entropy_blocks_total: int = 0,
        max_cyclomatic_complexity: int = 1,
        complex_methods_count: int = 0,
        methods_with_dead_code: int = 0,
        average_method_entropy: float = 0.0,
        suspicious_methods: Optional[List[str]] = None,
    ):
        self.total_methods_analyzed = total_methods_analyzed
        self.total_blocks = total_blocks
        self.total_edges = total_edges
        self.high_entropy_blocks_total = high_entropy_blocks_total
        self.max_cyclomatic_complexity = max_cyclomatic_complexity
        self.complex_methods_count = complex_methods_count
        self.methods_with_dead_code = methods_with_dead_code
        self.average_method_entropy = average_method_entropy
        self.suspicious_methods: List[str] = suspicious_methods or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_methods_analyzed": self.total_methods_analyzed,
            "total_blocks": self.total_blocks,
            "total_edges": self.total_edges,
            "high_entropy_blocks_total": self.high_entropy_blocks_total,
            "max_cyclomatic_complexity": self.max_cyclomatic_complexity,
            "complex_methods_count": self.complex_methods_count,
            "methods_with_dead_code": self.methods_with_dead_code,
            "average_method_entropy": self.average_method_entropy,
            "suspicious_methods": self.suspicious_methods,
        }


class CFGAnalysisResult:
    """Complete forensic inspection result containing telemetry and method graphs."""

    def __init__(
        self,
        file_name: str,
        file_size: int,
        sha256: str,
        telemetry: CFGTelemetry,
        methods: Optional[List[MethodCFG]] = None,
    ):
        self.file_name = file_name
        self.file_size = file_size
        self.sha256 = sha256
        self.telemetry = telemetry
        self.methods: List[MethodCFG] = methods or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "telemetry": self.telemetry.to_dict(),
            "methods": [m.to_dict() for m in self.methods],
        }
