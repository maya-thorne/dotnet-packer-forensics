"""
Multi-Engine Binary Diffing and AST Flow Graph Comparator Subpackage.
Engineered & Audited by Maya Thorne.
"""

from .ast_differ import ASTDiffer
from .bytecode_differ import BytecodeDiffer
from .cfg_differ import CFGDiffer
from .comparator import BinaryDiffEngine
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
    SectionDiff,
    SecurityError,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)

__all__ = [
    "ASTDiffer",
    "BytecodeDiffer",
    "CFGDiffer",
    "BinaryDiffEngine",
    "HTMLDiffReporter",
    "MetadataDiffer",
    "ASTFlowDiff",
    "BinaryDiffOptions",
    "BinaryDiffResult",
    "BinaryDiffTelemetry",
    "BytecodeDiff",
    "CFGGraphDiff",
    "ChangeType",
    "DiffCategory",
    "DiffEngine",
    "MetadataDiff",
    "MethodDiff",
    "ObfuscationImpact",
    "SectionDiff",
    "SecurityError",
    "calculate_entropy",
    "safe_path",
    "zeroize_buffer",
]
