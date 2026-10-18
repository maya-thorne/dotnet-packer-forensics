"""
Decompiler Headless Bridge Package for Ghidra, IDA Pro & Radare2.
Engineered & Audited by Maya Thorne.
"""

from .analyzer import DecompilerBridgeEngine
from .ghidra_bridge import GhidraBridgeGenerator
from .ida_bridge import IDABridgeGenerator
from .models import (
    CommentType,
    DecompilerBookmark,
    DecompilerBridgeOptions,
    DecompilerBridgeResult,
    DecompilerBridgeTelemetry,
    DecompilerComment,
    DecompilerEngine,
    DecompilerSymbol,
    DecompilerTypeStruct,
    SecurityError,
    SymbolType,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)
from .radare2_bridge import Radare2BridgeGenerator
from .symbol_sync import SymbolSynchronizer

__all__ = [
    "DecompilerBridgeEngine",
    "GhidraBridgeGenerator",
    "IDABridgeGenerator",
    "Radare2BridgeGenerator",
    "SymbolSynchronizer",
    "DecompilerEngine",
    "SymbolType",
    "CommentType",
    "DecompilerSymbol",
    "DecompilerComment",
    "DecompilerBookmark",
    "DecompilerTypeStruct",
    "DecompilerBridgeOptions",
    "DecompilerBridgeTelemetry",
    "DecompilerBridgeResult",
    "SecurityError",
    "safe_path",
    "zeroize_buffer",
    "calculate_entropy",
]
