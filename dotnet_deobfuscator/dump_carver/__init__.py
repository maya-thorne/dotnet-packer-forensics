"""
Kernel Memory Dump Carving and Residual CIL Metadata Reconstructor Subpackage.
Engineered & Audited by Maya Thorne.
"""

from .analyzer import KernelDumpCarver
from .bsjb_carver import BSJBCarver
from .method_carver import MethodCarver
from .minidump_parser import MinidumpParser
from .models import (
    CarverAnomalyFlag,
    CarvedArtifactType,
    CarvedAssembly,
    CarvedMethod,
    CarvedString,
    CILMethodHeaderFormat,
    DumpCarverResult,
    DumpCarverTelemetry,
    DumpFormat,
    MemoryRange,
    SecurityError,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)
from .reconstructor import AssemblyReconstructor

__all__ = [
    "KernelDumpCarver",
    "MinidumpParser",
    "BSJBCarver",
    "MethodCarver",
    "AssemblyReconstructor",
    "DumpFormat",
    "CarvedArtifactType",
    "CILMethodHeaderFormat",
    "CarverAnomalyFlag",
    "MemoryRange",
    "CarvedString",
    "CarvedMethod",
    "CarvedAssembly",
    "DumpCarverTelemetry",
    "DumpCarverResult",
    "SecurityError",
    "safe_path",
    "zeroize_buffer",
    "calculate_entropy",
]
