"""
CIL Control Flow Graph (CFG) & High-Entropy Block Forensics Module.
Engineered & Audited by Maya Thorne.
"""

from .analyzer import CFGAnalyzer
from .builder import CFGBuilder
from .disassembler import CILDisassembler
from .models import (
    BlockAnomalyFlag,
    BlockEntropyLevel,
    CFGAnalysisResult,
    CFGBlock,
    CFGEdge,
    CFGEdgeType,
    CFGInstruction,
    CFGTelemetry,
    DiagramFormat,
    FlowControl,
    MethodCFG,
    SecurityError,
    calculate_entropy,
    zeroize_buffer,
)
from .visualizer import CFGVisualizer

__all__ = [
    "CFGAnalyzer",
    "CFGBuilder",
    "CILDisassembler",
    "CFGVisualizer",
    "CFGBlock",
    "CFGEdge",
    "CFGEdgeType",
    "CFGInstruction",
    "BlockEntropyLevel",
    "BlockAnomalyFlag",
    "DiagramFormat",
    "FlowControl",
    "MethodCFG",
    "CFGTelemetry",
    "CFGAnalysisResult",
    "SecurityError",
    "calculate_entropy",
    "zeroize_buffer",
]
