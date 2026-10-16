"""
Data Models, Enums & Security Sanitizers for Batch PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import ctypes
from dataclasses import asdict, dataclass, field
from enum import Enum
import os
import time
from typing import Any, Dict, List, Optional, Union


class SecurityError(Exception):
    """Raised when directory traversal or security boundary violations are detected."""
    pass


def zeroize_buffer(buf: Union[bytearray, memoryview, ctypes.Array]) -> None:
    """Zeroizes in-memory buffers using ctypes.memset to eliminate residual cryptographic remnants."""
    if not buf:
        return
    try:
        if isinstance(buf, (bytearray, memoryview)):
            c_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.byref(c_arr), 0, len(buf))
        elif hasattr(buf, "_length_") and hasattr(buf, "_type_"):
            ctypes.memset(ctypes.byref(buf), 0, ctypes.sizeof(buf))
    except Exception:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0


def safe_path(base_dir: str, file_name: str) -> str:
    """Enforces strict directory boundary containment preventing path traversal attacks."""
    resolved_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(resolved_base, file_name))
    base_prefix = resolved_base if resolved_base.endswith(os.sep) else resolved_base + os.sep

    valid = (target_path == resolved_base or target_path.startswith(base_prefix))
    if not valid and os.name == "nt":
        try:
            common = os.path.commonpath([resolved_base, target_path])
            if common.lower() == resolved_base.lower():
                valid = True
            elif os.path.exists(resolved_base) and os.path.exists(common):
                valid = os.path.samefile(resolved_base, common)
        except (ValueError, OSError):
            pass

    if not valid:
        raise SecurityError(
            f"Path traversal detected: '{file_name}' attempts to escape destination '{base_dir}'"
        )
    return target_path


class FileScanStatus(str, Enum):
    """Outcome status of single-file forensic scanning."""
    SCANNED = "scanned"
    PACKED = "packed"
    CLEAN = "clean"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"

    @classmethod
    def from_str(cls, val: Any) -> "FileScanStatus":
        """Converts string or enum value into corresponding FileScanStatus enum."""
        if isinstance(val, cls):
            return val
        cleaned = getattr(val, "value", str(val)).strip().lower()
        if "." in cleaned:
            cleaned = cleaned.split(".")[-1]
        for member in cls:
            if member.value == cleaned:
                return member
        return cls.ERROR


class ThreatLevel(str, Enum):
    """Assessed threat and obfuscation severity level."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, val: Any) -> "ThreatLevel":
        """Converts string or enum value into corresponding ThreatLevel enum."""
        if isinstance(val, cls):
            return val
        cleaned = getattr(val, "value", str(val)).strip().lower()
        if "." in cleaned:
            cleaned = cleaned.split(".")[-1]
        for member in cls:
            if member.value == cleaned:
                return member
        return cls.LOW

    @property
    def score(self) -> int:
        """Returns integer ranking value for threat sorting and comparison."""
        weights = {
            ThreatLevel.CLEAN: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }
        return weights.get(self, 0)

    def __lt__(self, other: "ThreatLevel") -> bool:
        if isinstance(other, ThreatLevel):
            return self.score < other.score
        return NotImplemented

    def __le__(self, other: "ThreatLevel") -> bool:
        if isinstance(other, ThreatLevel):
            return self.score <= other.score
        return NotImplemented

    def __gt__(self, other: "ThreatLevel") -> bool:
        if isinstance(other, ThreatLevel):
            return self.score > other.score
        return NotImplemented

    def __ge__(self, other: "ThreatLevel") -> bool:
        if isinstance(other, ThreatLevel):
            return self.score >= other.score
        return NotImplemented


@dataclass
class BatchScanOptions:
    """Configuration parameters controlling batch directory scanning."""
    target_dir: str
    recursive: bool = False
    workers: int = 4
    pattern: str = "*"
    timeout_sec: float = 30.0
    min_size_bytes: int = 0
    max_size_bytes: int = 100 * 1024 * 1024
    pe_only: bool = True
    unpack_payloads: bool = False
    unpack_out_dir: Optional[str] = None
    master_key: str = "randomkey"
    output_dir: Optional[str] = None
    json_out: Optional[str] = None
    csv_out: Optional[str] = None
    html_out: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes scan options to dictionary."""
        return asdict(self)


@dataclass
class SingleScanResult:
    """Forensic telemetry result for a single scanned binary."""
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    status: FileScanStatus
    threat_level: ThreatLevel
    is_pe: bool
    is_dotnet: bool
    protectors: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    overlay_size: int = 0
    scan_duration_ms: float = 0.0
    error_message: Optional[str] = None
    unpacked_count: int = 0
    unpacked_files: List[str] = field(default_factory=list)
    extra_telemetry: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Normalizes status and threat_level attributes into strict enum members."""
        self.status = FileScanStatus.from_str(self.status)
        self.threat_level = ThreatLevel.from_str(self.threat_level)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes single file scan result to dictionary."""
        res = asdict(self)
        res["status"] = self.status.value if hasattr(self.status, "value") else str(self.status)
        res["threat_level"] = self.threat_level.value if hasattr(self.threat_level, "value") else str(self.threat_level)
        return res


@dataclass
class BatchScanSummary:
    """Aggregated metrics across completed batch scan."""
    total_files_discovered: int = 0
    total_files_scanned: int = 0
    total_files_skipped: int = 0
    total_pe_files: int = 0
    total_dotnet_files: int = 0
    total_packed_files: int = 0
    total_clean_files: int = 0
    total_errors: int = 0
    total_timeouts: int = 0
    threat_counts: Dict[str, int] = field(
        default_factory=lambda: {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    )
    protector_counts: Dict[str, int] = field(default_factory=dict)
    total_bytes_scanned: int = 0
    elapsed_seconds: float = 0.0
    scan_rate_files_per_sec: float = 0.0
    scan_rate_mb_per_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes batch scan summary to dictionary."""
        return asdict(self)


@dataclass
class BatchScanReport:
    """Comprehensive batch forensic scan manifest report."""
    options: BatchScanOptions
    summary: BatchScanSummary
    results: List[SingleScanResult]
    timestamp_utc: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    scanner_version: str = "2.9.0"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes full report manifest to dictionary."""
        return {
            "scanner_version": self.scanner_version,
            "timestamp_utc": self.timestamp_utc,
            "options": self.options.to_dict(),
            "summary": self.summary.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }
