"""
Data Models, Enums & Security Primitives for Decompiler Headless Bridges.
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
    abs_base = os.path.abspath(base_dir)
    if os.path.isabs(target_path):
        abs_target = os.path.abspath(target_path)
    else:
        abs_target = os.path.abspath(os.path.join(abs_base, target_path))
    try:
        common = os.path.commonpath([abs_base, abs_target])
    except ValueError as e:
        raise SecurityError(f"Cross-drive or invalid path access: {target_path}") from e
    if common != abs_base:
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


class DecompilerEngine(str, Enum):
    """Supported reverse engineering and decompiler targets."""
    GHIDRA = "ghidra"
    IDA_PRO = "ida_pro"
    RADARE2 = "radare2"
    ALL = "all"


class SymbolType(str, Enum):
    """Category of forensic symbol or recovered code point."""
    FUNCTION = "function"
    ENTRY_POINT = "entry_point"
    RUNTIME_HELPER = "runtime_helper"
    VM_DISPATCHER = "vm_dispatcher"
    DECRYPTOR = "decryptor"
    NATIVE_TRANSITION = "native_transition"
    METADATA_TOKEN = "metadata_token"
    ANOMALY_BLOCK = "anomaly_block"


class CommentType(str, Enum):
    """Target decompiler comment presentation placement."""
    PLATE = "plate"
    EOL = "eol"
    REPEATABLE = "repeatable"
    ANTERIOR = "anterior"
    POSTERIOR = "posterior"


@dataclass
class DecompilerSymbol:
    """Recovered symbol metadata to import into disassemblers."""
    name: str
    rva: int
    size: int = 0
    symbol_type: SymbolType = SymbolType.FUNCTION
    is_function: bool = True
    token: Optional[int] = None
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)
    demangled_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["symbol_type"] = self.symbol_type.value
        return d


@dataclass
class DecompilerComment:
    """Decompiler comment annotation positioned at a specific RVA."""
    rva: int
    text: str
    comment_type: CommentType = CommentType.PLATE
    is_repeatable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["comment_type"] = self.comment_type.value
        return d


@dataclass
class DecompilerBookmark:
    """Interactive navigation bookmark for rapid triage."""
    rva: int
    category: str = "Forensics"
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecompilerTypeStruct:
    """Forensic structure definition for decompiler Type Managers."""
    name: str
    size: int
    fields: List[Dict[str, Any]] = field(default_factory=list)
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecompilerBridgeOptions:
    """Options governing decompiler headless bridge script generation."""
    engine: DecompilerEngine = DecompilerEngine.ALL
    base_addr: int = 0x400000
    min_confidence: float = 0.5
    include_entropy_anomalies: bool = True
    include_runtime_helpers: bool = True
    include_vtfixups: bool = True
    include_demangled_symbols: bool = True
    safe_labels: bool = True
    output_dir: Optional[str] = None


@dataclass
class DecompilerBridgeTelemetry:
    """Operational telemetry summarizing bridge generation performance."""
    total_symbols: int = 0
    total_comments: int = 0
    total_bookmarks: int = 0
    total_structs: int = 0
    engine: str = "all"
    generation_time_ms: float = 0.0
    confidence_avg: float = 0.0
    sources_count: int = 0
    anomaly_blocks_count: int = 0
    rhp_helpers_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecompilerBridgeResult:
    """Unified container storing all generated bridge scripts and artifacts."""
    engine: DecompilerEngine
    base_addr: int
    symbols: List[DecompilerSymbol]
    comments: List[DecompilerComment]
    bookmarks: List[DecompilerBookmark]
    structs: List[DecompilerTypeStruct]
    telemetry: DecompilerBridgeTelemetry
    ghidra_script: Optional[str] = None
    ida_script: Optional[str] = None
    radare2_script: Optional[str] = None
    runner_batch: Optional[str] = None
    runner_sh: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine.value,
            "base_addr": hex(self.base_addr),
            "symbols_count": len(self.symbols),
            "comments_count": len(self.comments),
            "bookmarks_count": len(self.bookmarks),
            "structs_count": len(self.structs),
            "telemetry": self.telemetry.to_dict(),
            "has_ghidra_script": bool(self.ghidra_script),
            "has_ida_script": bool(self.ida_script),
            "has_radare2_script": bool(self.radare2_script),
        }
