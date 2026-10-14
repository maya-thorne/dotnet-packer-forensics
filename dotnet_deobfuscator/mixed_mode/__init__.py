"""
Native Mixed-Mode PE & CIL-Native Transition Tracer Package.
Forensic analysis engine for C++/CLI (IJWH) binaries, VTableFixup tables, and unmanaged thunks.
Engineered & Audited by Maya Thorne.
"""

from .analyzer import MixedModeAnalyzer
from .models import (
    CILNativeTransition,
    Cor20Flag,
    MixedModeAnalysisResult,
    MixedModeTelemetry,
    MixedModeType,
    RiskSeverity,
    SecurityError,
    TLSCallbackInfo,
    TransitionDirection,
    TransitionType,
    UnmanagedExportBridge,
    VTFixupFlag,
    VTFixupSlot,
    VTFixupTable,
    VTFixupType,
)
from .transition_tracer import TransitionTracer
from .vtfixup_parser import VTFixupParser, zeroize_buffer

__all__ = [
    "MixedModeAnalyzer",
    "VTFixupParser",
    "TransitionTracer",
    "MixedModeAnalysisResult",
    "MixedModeTelemetry",
    "VTFixupTable",
    "VTFixupSlot",
    "CILNativeTransition",
    "UnmanagedExportBridge",
    "TLSCallbackInfo",
    "MixedModeType",
    "VTFixupType",
    "VTFixupFlag",
    "Cor20Flag",
    "TransitionDirection",
    "TransitionType",
    "RiskSeverity",
    "SecurityError",
    "zeroize_buffer",
]
