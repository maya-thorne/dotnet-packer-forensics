"""
Data Models and Enums for Native Multi-Architecture Demuxer & Platform Router.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SecurityError(Exception):
    """Raised when bounds checks, sanitization, or path safety constraints are violated."""
    pass


class TargetArchitecture(str, Enum):
    """Hardware CPU architecture classifications."""
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"
    ARM = "arm"
    IA64 = "ia64"
    UNKNOWN = "unknown"


class TargetOS(str, Enum):
    """Operating system platform classifications."""
    WINDOWS = "windows"
    LINUX = "linux"
    OSX = "osx"
    ANY = "any"
    UNKNOWN = "unknown"


class BinaryFormat(str, Enum):
    """Executable binary formats."""
    PE32 = "PE32"
    PE32_PLUS = "PE32+"
    ELF32 = "ELF32"
    ELF64 = "ELF64"
    MACHO32 = "Mach-O 32"
    MACHO64 = "Mach-O 64"
    RAW_BINARY = "Raw Binary"


class DemuxSource(str, Enum):
    """Extraction origin or container source."""
    COSTURA_NATIVE = "COSTURA_NATIVE"
    RUNTIMES_CATALOG = "RUNTIMES_CATALOG"
    DIRECTORY_PREFIX = "DIRECTORY_PREFIX"
    PE_SECTION = "PE_SECTION"
    PE_RESOURCE = "PE_RESOURCE"
    OVERLAY_CARVED = "OVERLAY_CARVED"
    EMBEDDED_COMPRESSED = "EMBEDDED_COMPRESSED"
    STANDALONE_EMBED = "STANDALONE_EMBED"


@dataclass
class NativePayloadInfo:
    """Detailed telemetry and metadata for an extracted native binary payload."""
    name: str
    target_arch: TargetArchitecture
    target_os: TargetOS
    format: BinaryFormat
    source: DemuxSource
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    entropy: float
    is_pe: bool
    machine_code: int
    machine_hex: str
    declared_arch: Optional[TargetArchitecture] = None
    subsystem: Optional[str] = None
    export_name: Optional[str] = None
    compressed: bool = False
    compressed_size_bytes: int = 0
    compression_ratio: float = 1.0
    mismatch_detected: bool = False
    mismatch_details: Optional[str] = None
    raw_data: bytes = field(repr=False, default=b"")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "target_arch": self.target_arch.value,
            "declared_arch": self.declared_arch.value if self.declared_arch else None,
            "target_os": self.target_os.value,
            "format": self.format.value,
            "source": self.source.value,
            "size_bytes": self.size_bytes,
            "compressed": self.compressed,
            "compressed_size_bytes": self.compressed_size_bytes,
            "compression_ratio": round(self.compression_ratio, 4),
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "entropy": round(self.entropy, 4),
            "is_pe": self.is_pe,
            "machine_code": self.machine_code,
            "machine_hex": self.machine_hex,
            "subsystem": self.subsystem,
            "export_name": self.export_name,
            "mismatch_detected": self.mismatch_detected,
            "mismatch_details": self.mismatch_details,
        }


@dataclass
class PlatformRouteResult:
    """Evaluation result for platform-specific binary routing."""
    requested_os: TargetOS
    requested_arch: TargetArchitecture
    matched_payload: Optional[Dict[str, Any]]
    resolution_status: str
    fallback_chain: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_os": self.requested_os.value,
            "requested_arch": self.requested_arch.value,
            "matched_payload": self.matched_payload,
            "resolution_status": self.resolution_status,
            "fallback_chain": self.fallback_chain,
            "reason": self.reason,
        }


@dataclass
class NativeDemuxerTelemetry:
    """High-level telemetry aggregator for multi-architecture demuxer."""
    is_multi_arch: bool = False
    confidence: str = "NONE"
    total_payloads: int = 0
    architectures_found: List[str] = field(default_factory=list)
    platforms_found: List[str] = field(default_factory=list)
    sources_found: List[str] = field(default_factory=list)
    has_architecture_mismatch: bool = False
    mismatch_count: int = 0
    anomalies: List[str] = field(default_factory=list)
    payloads: List[NativePayloadInfo] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_multi_arch": self.is_multi_arch,
            "confidence": self.confidence,
            "total_payloads": self.total_payloads,
            "architectures_found": self.architectures_found,
            "platforms_found": self.platforms_found,
            "sources_found": self.sources_found,
            "has_architecture_mismatch": self.has_architecture_mismatch,
            "mismatch_count": self.mismatch_count,
            "anomalies": self.anomalies,
            "payloads": [p.to_dict() for p in self.payloads],
        }
