"""
Data Models, Enums & Telemetry Structures for Regression Fuzzing & Synthetic Binary Generation.
Engineered & Audited by Maya Thorne.
"""

import ctypes
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class SecurityError(Exception):
    """Raised when security boundaries, path traversal, or resource limits are breached."""
    pass


def zeroize_buffer(buf: bytearray) -> None:
    """Overwrites bytearray buffer with zero bytes in-place to prevent memory leaks."""
    if not isinstance(buf, bytearray):
        return
    length = len(buf)
    if length == 0:
        return
    c_buf = (ctypes.c_char * length).from_buffer(buf)
    ctypes.memset(c_buf, 0, length)


def safe_path(base_dir: str, file_name: str) -> str:
    """Enforces strict directory boundary containment preventing path traversal attacks."""
    resolved_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(resolved_base, file_name))
    if not (target_path == resolved_base or target_path.startswith(resolved_base + os.sep)):
        raise SecurityError(
            f"Path traversal detected: '{file_name}' attempts to escape destination '{base_dir}'"
        )
    return target_path


class MutationStrategy(str, Enum):
    """Categorized mutation strategies targeting specific PE and .NET structural layers."""
    BIT_FLIP = "bit_flip"
    BYTE_NOISE = "byte_noise"
    DOS_HEADER_MANGLE = "dos_header_mangle"
    NT_HEADER_MANGLE = "nt_header_mangle"
    OPTIONAL_HEADER_MANGLE = "optional_header_mangle"
    SECTION_TABLE_MANGLE = "section_table_mangle"
    COR20_DESCRIPTOR_MANGLE = "cor20_descriptor_mangle"
    METADATA_STREAM_MANGLE = "metadata_stream_mangle"
    CIL_BYTECODE_FUZZ = "cil_bytecode_fuzz"
    OVERLAY_INJECTION = "overlay_injection"
    TRUNCATION = "truncation"


class FuzzTarget(str, Enum):
    """Target subsystem in the deobfuscation and forensic pipeline to fuzz."""
    ALL = "all"
    ANALYZE = "analyze"
    REBUILD = "rebuild"
    VERIFY = "verify"
    CFG = "cfg"
    BAML = "baml"
    MIXED_MODE = "mixed_mode"
    ANTIDUMP = "antidump"
    ANTITAMPER = "antitamper"
    RULES = "rules"

    @classmethod
    def from_str(cls, val: Any) -> "FuzzTarget":
        """Resolves string or alias to canonical FuzzTarget enum member."""
        if isinstance(val, cls):
            return val
        norm = str(val).strip().lower().replace("-", "_")
        for member in cls:
            if member.value == norm:
                return member
        aliases: Dict[str, FuzzTarget] = {
            "pe": cls.ANALYZE, "overlay": cls.ANALYZE, "signatures": cls.ANALYZE,
            "costura": cls.ANALYZE, "confuserex": cls.ANALYZE,
            "pe_rebuilder": cls.REBUILD, "rebuilder": cls.REBUILD,
            "payload": cls.VERIFY, "verifier": cls.VERIFY, "payload_verifier": cls.VERIFY,
            "control_flow": cls.CFG, "flow": cls.CFG, "entropy": cls.CFG,
            "wpf": cls.BAML, "xaml": cls.BAML,
            "mixed": cls.MIXED_MODE, "native": cls.MIXED_MODE, "vtfixup": cls.MIXED_MODE, "mixedmode": cls.MIXED_MODE,
            "anti_dump": cls.ANTIDUMP, "dump": cls.ANTIDUMP, "healer": cls.ANTIDUMP,
            "anti_tamper": cls.ANTITAMPER, "tamper": cls.ANTITAMPER, "jit": cls.ANTITAMPER,
            "threat": cls.RULES, "yara": cls.RULES, "sigma": cls.RULES,
        }
        if norm in aliases:
            return aliases[norm]
        valid_targets = ", ".join(m.value for m in cls)
        raise ValueError(f"Unknown fuzz target '{val}'. Valid targets: {valid_targets}")



class CrashSeverity(str, Enum):
    """Classification of target execution outcome under mutated binary stress."""
    CLEAN_PASS = "clean_pass"                     # Target analyzed/unpacked successfully
    HANDLED_ERROR = "handled_error"               # Target gracefully caught and rejected invalid input
    REGRESSION_CRASH = "regression_crash"         # Uncaught fatal exception (KeyError, IndexError, ZeroDiv, etc.)
    TIMEOUT_HANG = "timeout_hang"                 # Target exceeded time threshold (infinite loop/stall)
    RESOURCE_EXHAUSTION = "resource_exhaustion"   # MemoryError, RecursionError, or DoS boundary hit


@dataclass
class MutationRecord:
    """Detailed audit entry for a single mutation applied to a binary buffer."""
    strategy: MutationStrategy
    offset: int
    original_hex: str
    mutated_hex: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy.value if isinstance(self.strategy, MutationStrategy) else str(self.strategy),
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:08X}",
            "original_hex": self.original_hex,
            "mutated_hex": self.mutated_hex,
            "description": self.description,
        }


@dataclass
class FuzzExecutionResult:
    """Telemetry report for a single fuzz iteration against a target subsystem."""
    iteration: int
    seed: int
    target: str
    strategies: List[str]
    severity: CrashSeverity
    duration_ms: float
    sample_sha256: str
    sample_size: int
    exception_class: Optional[str] = None
    exception_message: Optional[str] = None
    traceback_snippet: Optional[str] = None
    mutations: List[MutationRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iteration": self.iteration,
            "seed": self.seed,
            "target": self.target,
            "strategies": self.strategies,
            "severity": self.severity.value if isinstance(self.severity, CrashSeverity) else str(self.severity),
            "duration_ms": round(self.duration_ms, 3),
            "sample_sha256": self.sample_sha256,
            "sample_size": self.sample_size,
            "exception_class": self.exception_class,
            "exception_message": self.exception_message,
            "traceback_snippet": self.traceback_snippet,
            "mutation_count": len(self.mutations),
            "mutations": [m.to_dict() for m in self.mutations[:10]],  # Cap detailed mutations in JSON
        }


@dataclass
class FuzzCampaignTelemetry:
    """Aggregate statistical metrics from a fuzzing campaign."""
    total_iterations: int = 0
    clean_passes: int = 0
    handled_errors: int = 0
    crashes: int = 0
    timeouts: int = 0
    total_duration_sec: float = 0.0
    unique_crash_signatures: Dict[str, int] = field(default_factory=dict)
    strategies_used: Dict[str, int] = field(default_factory=dict)
    has_regressions: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_iterations": self.total_iterations,
            "clean_passes": self.clean_passes,
            "handled_errors": self.handled_errors,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "total_duration_sec": round(self.total_duration_sec, 3),
            "unique_crash_signatures": self.unique_crash_signatures,
            "strategies_used": self.strategies_used,
            "has_regressions": self.has_regressions,
        }


@dataclass
class FuzzCampaignResult:
    """Top-level container for complete fuzzing campaign execution and findings."""
    campaign_id: str
    seed: int
    target: str
    telemetry: FuzzCampaignTelemetry
    executions: List[FuzzExecutionResult] = field(default_factory=list)
    crashes: List[FuzzExecutionResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "seed": self.seed,
            "target": self.target,
            "telemetry": self.telemetry.to_dict(),
            "crash_count": len(self.crashes),
            "crashes": [c.to_dict() for c in self.crashes],
        }


class RegressionLedger:
    """Persistent storage and tracking ledger for regression crashes and historical replays."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    def record_crash(
        self,
        execution: FuzzExecutionResult,
        binary_bytes: Optional[bytes] = None,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Records a new crash case into the regression ledger."""
        if binary_bytes and len(binary_bytes) > 0:
            sha256 = hashlib.sha256(binary_bytes).hexdigest()
            size = len(binary_bytes)
        else:
            sha256 = execution.sample_sha256
            size = execution.sample_size
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
            "iteration": execution.iteration,
            "seed": execution.seed,
            "target": execution.target,
            "strategies": execution.strategies,
            "severity": execution.severity.value,
            "exception_class": execution.exception_class,
            "exception_message": execution.exception_message,
            "traceback": execution.traceback_snippet,
            "sample_sha256": sha256,
            "sample_size": size,
            "notes": notes,
        }
        self.entries.append(entry)
        return entry

    def save_to_file(self, file_path: str) -> None:
        """Saves regression ledger entries to a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump({"version": "1.0", "entries": self.entries}, f, indent=2)

    def load_from_file(self, file_path: str) -> int:
        """Loads regression ledger entries from a JSON file. Returns count loaded."""
        if not os.path.exists(file_path):
            return 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return 0
            data = json.loads(content)
            if isinstance(data, dict):
                raw_entries = data.get("entries", [])
            elif isinstance(data, list):
                raw_entries = data
            else:
                return 0
            if not isinstance(raw_entries, list):
                return 0
            valid_entries = [e for e in raw_entries if isinstance(e, dict)]
            self.entries.extend(valid_entries)
            return len(valid_entries)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return 0
