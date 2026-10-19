"""
JIT Compilation Tracing & Bytecode Capture Subsystem.
Engineered & Audited by Maya Thorne.
"""

from .analyzer import JITTracerEngine
from .assembly_restorer import JITAssemblyRestorer
from .emulator import VirtualJITCompiler
from .hook_detector import JITHookDetector
from .models import (
    CapturedMethod,
    CaptureSource,
    CipherFamily,
    CORINFO_METHOD_INFO,
    JITCaptureOptions,
    JITCaptureResult,
    JITCaptureTelemetry,
    JITExecutionState,
    JITHookSignature,
    JITHookType,
    OptimizationTier,
    SecurityError,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)
from .trace_parser import JITTraceParser

__all__ = [
    "JITTracerEngine",
    "JITAssemblyRestorer",
    "VirtualJITCompiler",
    "JITHookDetector",
    "JITTraceParser",
    "CapturedMethod",
    "CaptureSource",
    "CipherFamily",
    "CORINFO_METHOD_INFO",
    "JITCaptureOptions",
    "JITCaptureResult",
    "JITCaptureTelemetry",
    "JITExecutionState",
    "JITHookSignature",
    "JITHookType",
    "OptimizationTier",
    "SecurityError",
    "calculate_entropy",
    "safe_path",
    "zeroize_buffer",
]
