"""
Native AOT & ReadyToRun (R2R) PE Forensic Analysis Package.
Engineered & Audited by Maya Thorne.
"""

from .analyzer import NativeAOTAnalyzer
from .aot_symbol_parser import AOTSymbolParser
from .disassembler import NativeDisassembler
from .models import (
    AOTVersion,
    CompilationType,
    DisassembledMethod,
    MethodDefEntry,
    NativeAOTAnalysisResult,
    NativeAOTTelemetry,
    NativeSymbol,
    R2RHeader,
    R2RInstruction,
    R2RSection,
    R2RSectionType,
    RuntimeFunctionEntry,
    SecurityError,
    TargetArchitecture,
    safe_path,
    zeroize_buffer,
)
from .r2r_parser import R2RParser

__all__ = [
    "AOTSymbolParser",
    "AOTVersion",
    "CompilationType",
    "DisassembledMethod",
    "MethodDefEntry",
    "NativeAOTAnalysisResult",
    "NativeAOTAnalyzer",
    "NativeAOTTelemetry",
    "NativeDisassembler",
    "NativeSymbol",
    "R2RHeader",
    "R2RInstruction",
    "R2RParser",
    "R2RSection",
    "R2RSectionType",
    "RuntimeFunctionEntry",
    "SecurityError",
    "TargetArchitecture",
    "safe_path",
    "zeroize_buffer",
]
