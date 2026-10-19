"""
Data Models & Enums for JIT Compilation Tracing & Bytecode Capture.
Engineered & Audited by Maya Thorne.
"""

import ctypes
import math
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class SecurityError(Exception):
    """Raised when security boundaries or path constraints are violated."""
    pass


class JITHookType(str, Enum):
    """Classifies the CLR JIT hooking or method interception mechanism."""
    CORJIT_COMPILEMETHOD = "corjit_compilemethod"
    PRE_JIT_STUB = "pre_jit_stub"
    DYNAMIC_METHOD_EMIT = "dynamic_method_emit"
    TIERED_COMPILATION = "tiered_compilation"
    CUSTOM_CLR_HOOK = "custom_clr_hook"
    UNKNOWN = "unknown"


class JITExecutionState(str, Enum):
    """Tracks the lifecycle of a JIT-compiled or traced method."""
    PENDING = "pending"
    TRACED = "traced"
    CAPTURED = "captured"
    DECRYPTED = "decrypted"
    VALIDATED = "validated"
    CORRUPTED = "corrupted"
    FAULTED = "faulted"


class CaptureSource(str, Enum):
    """Source of the captured method bytecode."""
    EMULATED_JIT = "emulated_jit"
    TRACE_LOG = "trace_log"
    MEMORY_STREAM = "memory_stream"
    ETW_EVENT = "etw_event"
    SYNTHETIC = "synthetic"


class OptimizationTier(str, Enum):
    """Target .NET runtime JIT optimization tier."""
    TIER_0_MINOPT = "tier_0_minopt"
    TIER_0_QUICKJIT = "tier_0_quickjit"
    TIER_1_OPTIMIZED = "tier_1_optimized"
    READY_TO_RUN = "ready_to_run"
    UNKNOWN = "unknown"


class CipherFamily(str, Enum):
    """Cryptographic or transformation cipher detected on method stub."""
    NONE = "none"
    XOR_STREAM = "xor_stream"
    LCG_PRNG = "lcg_prng"
    RC4 = "rc4"
    AES_CBC = "aes_cbc"
    CUSTOM_BYTE_TABLE = "custom_byte_table"


@dataclass
class CORINFO_METHOD_INFO:
    """Represents method metadata passed to ICorJitCompiler::compileMethod."""
    ftn: int = 0
    scope: int = 0
    ILCode: int = 0
    ILCodeSize: int = 0
    maxStack: int = 8
    EHcount: int = 0
    options: int = 0
    sig: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ftn": hex(self.ftn),
            "scope": hex(self.scope),
            "ILCode": hex(self.ILCode),
            "ILCodeSize": self.ILCodeSize,
            "maxStack": self.maxStack,
            "EHcount": self.EHcount,
            "options": hex(self.options),
            "sig": hex(self.sig),
        }


@dataclass
class JITHookSignature:
    """Details of a detected JIT compilation hook in native or managed code."""
    hook_type: JITHookType
    target_module: str
    hook_pattern: str
    detected_rva: int
    confidence: float
    description: str
    protector_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hook_type": self.hook_type.value,
            "target_module": self.target_module,
            "hook_pattern": self.hook_pattern,
            "detected_rva": hex(self.detected_rva),
            "confidence": round(self.confidence, 3),
            "description": self.description,
            "protector_name": self.protector_name,
        }


@dataclass
class CapturedMethod:
    """Forensically extracted and validated CIL method body."""
    token: int
    name: str
    declaring_type: str
    rva: int
    il_bytes: bytes
    il_size: int
    header_format: str
    max_stack: int
    local_sig_token: int
    eh_clause_count: int
    cipher_detected: CipherFamily
    capture_source: CaptureSource
    state: JITExecutionState
    sha256: str
    disassembly_preview: List[str] = field(default_factory=list)
    entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": hex(self.token),
            "name": self.name,
            "declaring_type": self.declaring_type,
            "rva": hex(self.rva),
            "il_size": self.il_size,
            "il_hex": self.il_bytes.hex(),
            "header_format": self.header_format,
            "max_stack": self.max_stack,
            "local_sig_token": hex(self.local_sig_token),
            "eh_clause_count": self.eh_clause_count,
            "cipher_detected": self.cipher_detected.value,
            "capture_source": self.capture_source.value,
            "state": self.state.value,
            "sha256": self.sha256,
            "disassembly_preview": self.disassembly_preview,
            "entropy": round(self.entropy, 4),
        }


@dataclass
class JITCaptureTelemetry:
    """Quantitative performance and recovery metrics for JIT capture session."""
    methods_traced: int = 0
    methods_captured: int = 0
    methods_validated: int = 0
    total_bytes_captured: int = 0
    hooks_detected: int = 0
    duration_ms: float = 0.0
    average_entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "methods_traced": self.methods_traced,
            "methods_captured": self.methods_captured,
            "methods_validated": self.methods_validated,
            "total_bytes_captured": self.total_bytes_captured,
            "hooks_detected": self.hooks_detected,
            "duration_ms": round(self.duration_ms, 3),
            "average_entropy": round(self.average_entropy, 4),
        }


@dataclass
class JITCaptureOptions:
    """Configuration switches for JIT tracing and capture execution."""
    emulate_unpacker: bool = True
    min_confidence: float = 0.5
    max_methods: int = 100
    export_reconstructed_pe: bool = True
    zeroize_decrypted_scratch: bool = True
    target_tier: OptimizationTier = OptimizationTier.TIER_0_MINOPT


@dataclass
class JITCaptureResult:
    """Comprehensive output container for JIT tracing and capture harness."""
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    hooks: List[JITHookSignature]
    captured_methods: List[CapturedMethod]
    telemetry: JITCaptureTelemetry
    reconstructed_pe_bytes: Optional[bytes] = None
    is_hooked: bool = False
    primary_protector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "is_hooked": self.is_hooked,
            "primary_protector": self.primary_protector,
            "hooks": [h.to_dict() for h in self.hooks],
            "captured_methods": [m.to_dict() for m in self.captured_methods],
            "telemetry": self.telemetry.to_dict(),
            "has_reconstructed_pe": self.reconstructed_pe_bytes is not None,
            "reconstructed_pe_size": len(self.reconstructed_pe_bytes) if self.reconstructed_pe_bytes else 0,
        }


def safe_path(target_path: str, base_dir: str = "") -> str:
    """
    Sanitizes and bounds an output path within base_dir.
    Raises SecurityError on directory traversal or escape attempts.
    """
    if not target_path:
        raise SecurityError("Target path must be non-empty")

    # Handle inverted argument order if first arg is an existing directory
    if base_dir and os.path.isdir(target_path) and not os.path.isdir(base_dir):
        base_dir, target_path = target_path, base_dir

    if not base_dir:
        base_dir = os.getcwd()

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

    if not valid or ".." in target_path.split("/") or ".." in target_path.split("\\"):
        raise SecurityError(f"Directory traversal detected: {target_path}")
    return abs_target


def zeroize_buffer(buf: Union[bytearray, bytes, memoryview]) -> None:
    """Cryptographically overwrites buffer memory with zeros to eliminate memory leakage."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, memoryview):
        try:
            buf[:] = b"\x00" * len(buf)
        except (TypeError, ValueError):
            pass
    elif isinstance(buf, bytes):
        try:
            length = len(buf)
            offset = ctypes.sizeof(ctypes.c_size_t) * 4
            ctypes.memset(id(buf) + offset, 0, length)
        except Exception:
            pass


def calculate_entropy(data: bytes) -> float:
    """Computes Shannon entropy across byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    frequencies: Dict[int, int] = {}
    for b in data:
        frequencies[b] = frequencies.get(b, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
