"""
Data Models, Enums, and Security Primitives for Kernel Memory Dump Carving.
Engineered & Audited by Maya Thorne.
"""

import ctypes
import math
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class SecurityError(Exception):
    """Raised when path traversal or security boundary violation is detected."""
    pass


class DumpFormat(str, Enum):
    """Memory dump format classification."""
    MINIDUMP_MDMP = "minidump_mdmp"
    KERNEL_CRASH_DUMP = "kernel_crash_dump"
    RAW_MEMORY_BLOCK = "raw_memory_block"
    CORRUPTED_OR_UNKNOWN = "corrupted_or_unknown"


class CarvedArtifactType(str, Enum):
    """Type of artifact carved from memory."""
    PE_ASSEMBLY = "pe_assembly"
    RESIDUAL_METADATA_ROOT = "residual_metadata_root"
    RESIDUAL_CIL_METHOD = "residual_cil_method"
    USER_STRING_HEAP = "user_string_heap"
    STANDALONE_METADATA_STREAM = "standalone_metadata_stream"


class CILMethodHeaderFormat(str, Enum):
    """ECMA-335 CIL method header format."""
    TINY = "tiny"
    FAT = "fat"


class CarverAnomalyFlag(str, Enum):
    """Forensic anomalies and tampering indicators detected during dump carving."""
    CORRUPTED_PE_HEADER = "corrupted_pe_header"
    TRUNCATED_BSJB_STREAM = "truncated_bsjb_stream"
    ORPHANED_METHOD_BODIES = "orphaned_method_bodies"
    SUSPICIOUS_MEMORY_GAP = "suspicious_memory_gap"
    ANTI_FORENSIC_ZEROING = "anti_forensic_zeroing"
    UNALIGNED_SECTION_VIRTUALIZATION = "unaligned_section_virtualization"
    MISSING_COR20_DESCRIPTOR = "missing_cor20_descriptor"


def safe_path(base_dir: str, rel_path: str) -> str:
    """
    Validates and normalizes target file path, strictly preventing directory traversal.
    Raises SecurityError if resolved path attempts to escape base directory.
    """
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(os.path.join(base_real, rel_path))
    if not target_real.startswith(base_real + os.sep) and target_real != base_real:
        raise SecurityError(
            f"Path traversal detected: target '{target_real}' escapes base '{base_real}'"
        )
    return target_real


def zeroize_buffer(buf: Union[bytearray, memoryview, bytes]) -> None:
    """
    Cryptographically wipes memory buffer using ctypes.memset.
    """
    if isinstance(buf, (bytearray, memoryview)):
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte [0.0 - 8.0]."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


@dataclass
class MemoryRange:
    """Represents a virtual memory range extracted from minidump or raw dump."""
    start_va: int
    size: int
    file_offset: int
    flags: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_va": hex(self.start_va),
            "size": self.size,
            "file_offset": hex(self.file_offset),
            "flags": self.flags,
        }


@dataclass
class CarvedString:
    """Represents an extracted user string (#US) or identifier string (#Strings)."""
    heap: str
    offset: int
    value: str
    length: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CarvedMethod:
    """Represents a residual CIL method body recovered from memory."""
    token: int
    offset: int
    format: CILMethodHeaderFormat
    max_stack: int
    code_size: int
    local_sig_tok: int
    bytecode_hex: str
    entropy: float
    instructions_count: int
    has_valid_termination: bool

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["token"] = hex(self.token)
        d["offset"] = hex(self.offset)
        d["local_sig_tok"] = hex(self.local_sig_tok)
        d["format"] = self.format.value
        return d


@dataclass
class CarvedAssembly:
    """Represents an assembly identified or reconstructed from residual memory."""
    identifier: str
    offset: int
    size: int
    name: str
    version: str
    entry_point_token: int
    sha256: str
    is_pe_valid: bool
    is_reconstructed: bool
    confidence: float
    bsjb_offset: int
    streams_present: List[str] = field(default_factory=list)
    raw_data: bytes = field(default=b"", repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "offset": hex(self.offset),
            "size": self.size,
            "name": self.name,
            "version": self.version,
            "entry_point_token": hex(self.entry_point_token),
            "sha256": self.sha256,
            "is_pe_valid": self.is_pe_valid,
            "is_reconstructed": self.is_reconstructed,
            "confidence": round(self.confidence, 2),
            "bsjb_offset": hex(self.bsjb_offset),
            "streams_present": self.streams_present,
        }


@dataclass
class DumpCarverTelemetry:
    """Executive forensic telemetry for memory dump carving session."""
    dump_format: str
    dump_size: int
    memory_ranges_scanned: int
    modules_detected: int
    bsjb_roots_found: int
    assemblies_carved: int
    methods_recovered: int
    strings_recovered: int
    anomaly_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DumpCarverResult:
    """Top-level container for memory dump carving findings."""
    file_name: str
    telemetry: DumpCarverTelemetry
    carved_assemblies: List[CarvedAssembly] = field(default_factory=list)
    residual_methods: List[CarvedMethod] = field(default_factory=list)
    carved_strings: List[CarvedString] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "telemetry": self.telemetry.to_dict(),
            "carved_assemblies": [a.to_dict() for a in self.carved_assemblies],
            "residual_methods": [m.to_dict() for m in self.residual_methods],
            "carved_strings_count": len(self.carved_strings),
            "anomalies": self.anomalies,
        }
