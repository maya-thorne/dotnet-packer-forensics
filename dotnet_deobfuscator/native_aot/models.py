"""
Native AOT & ReadyToRun (R2R) PE Forensic Data Models.
Defines data structures, enums, dataclasses, and security sanitizers for .NET 7/8/9 AOT analysis.
Engineered & Audited by Maya Thorne.
"""

import ctypes
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
import os
from typing import Any, Dict, List, Optional, Union


class SecurityError(Exception):
    """Raised when security boundaries or bounds checks are violated."""
    pass


class CompilationType(str, Enum):
    """Classification of PE executable regarding AOT / ReadyToRun compilation."""
    READYTORUN_R2R = "readytorun_r2r"
    NATIVE_AOT = "native_aot"
    HYBRID_AOT_MANAGED = "hybrid_aot_managed"
    STANDARD_MANAGED = "standard_managed"
    STANDARD_NATIVE = "standard_native"
    CORRUPTED_OR_ANOMALOUS = "corrupted_or_anomalous"


class R2RSectionType(IntEnum):
    """ReadyToRun section type identifiers defined in CoreCLR / Crossgen2 specifications."""
    COMPILER_IDENTIFIER = 100
    IMPORT_SECTIONS = 101
    RUNTIME_FUNCTIONS = 102
    METHODDEF_ENTRYPOINTS = 103
    EXCEPTION_INFO = 104
    DEBUG_INFO = 105
    DELAYLOAD_METHODCALL_THUNKS = 106
    AVAILABLE_TYPES = 107
    INSTANCE_METHOD_ENTRYPOINTS = 108
    INLINING_INFO = 109
    PROFILE_DATA = 110
    MANIFEST_METADATA = 111
    ATTRIBUTE_PRESENCE = 112
    INLINING_INFO2 = 113

    @classmethod
    def get_name(cls, value: int) -> str:
        """Returns human-readable name for section type ID."""
        try:
            return cls(value).name
        except ValueError:
            return f"UNKNOWN_SECTION_{value}"


class AOTVersion(str, Enum):
    """Inferred .NET Native AOT runtime generation."""
    DOTNET_7 = ".NET 7 Native AOT"
    DOTNET_8 = ".NET 8 Native AOT"
    DOTNET_9 = ".NET 9 Native AOT"
    UNKNOWN = "Unknown Native AOT"


class TargetArchitecture(str, Enum):
    """Underlying machine architecture targeted by precompiled native instructions."""
    X64 = "x64"
    X86 = "x86"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


@dataclass
class R2RHeader:
    """Header structure of ReadyToRun compilation block."""
    magic: int
    magic_str: str
    major_version: int
    minor_version: int
    flags: int
    num_sections: int
    entrypoint_rva: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class R2RSection:
    """Metadata describing an individual ReadyToRun section in the PE."""
    type_id: int
    type_name: str
    rva: int
    size: int
    raw_offset: Optional[int]
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeFunctionEntry:
    """Windows x64/ARM64 SEH RUNTIME_FUNCTION descriptor for native code methods."""
    index: int
    start_rva: int
    end_rva: int
    size_bytes: int
    unwind_info_rva: int
    method_token: Optional[int] = None
    symbol_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MethodDefEntry:
    """Entry point connecting an ECMA-335 MethodDef token to its precompiled native entry RVA."""
    token: int
    token_hex: str
    runtime_function_index: int
    entrypoint_rva: int
    method_name: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NativeSymbol:
    """Recovered or demangled symbol for an AOT/R2R native method or helper."""
    token: Optional[int]
    name: str
    demangled_name: str
    rva: int
    size_bytes: int
    symbol_type: str
    is_runtime_helper: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class R2RInstruction:
    """Disassembled native machine code instruction within a method body."""
    offset: int
    mnemonic: str
    operands: str
    raw_bytes: str
    size: int
    is_call: bool
    is_branch: bool
    target_rva: Optional[int] = None
    helper_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DisassembledMethod:
    """Collection of disassembled instructions representing an AOT / ReadyToRun method body."""
    name: str
    token: Optional[int]
    start_rva: int
    end_rva: int
    size_bytes: int
    instructions: List[R2RInstruction]
    blocks_count: int
    calls_count: int
    helpers_called: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "token": f"0x{self.token:08X}" if self.token else None,
            "start_rva": hex(self.start_rva),
            "end_rva": hex(self.end_rva),
            "size_bytes": self.size_bytes,
            "blocks_count": self.blocks_count,
            "calls_count": self.calls_count,
            "helpers_called": self.helpers_called,
            "instructions": [ins.to_dict() for ins in self.instructions],
        }


@dataclass
class NativeAOTTelemetry:
    """Forensic summary telemetry for Native AOT and ReadyToRun analysis."""
    compilation_type: str
    is_readytorun: bool
    is_native_aot: bool
    confidence: str
    target_arch: str
    r2r_version: Optional[str]
    inferred_dotnet_version: str
    compiler_identifier: Optional[str]
    r2r_sections_count: int
    runtime_functions_count: int
    method_entrypoints_count: int
    symbols_recovered_count: int
    rhp_helpers_detected: List[str]
    managed_code_sections: List[str]
    anomalies: List[str]
    risk_score: int
    risk_severity: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NativeAOTAnalysisResult:
    """Complete forensic inspection result for Native AOT and ReadyToRun binaries."""
    file_path: str
    file_size: int
    sha256: str
    telemetry: NativeAOTTelemetry
    r2r_header: Optional[R2RHeader]
    r2r_sections: List[R2RSection]
    runtime_functions: List[RuntimeFunctionEntry]
    method_entrypoints: List[MethodDefEntry]
    symbols: List[NativeSymbol]
    disassembled_methods: List[DisassembledMethod]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "telemetry": self.telemetry.to_dict(),
            "r2r_header": self.r2r_header.to_dict() if self.r2r_header else None,
            "r2r_sections": [s.to_dict() for s in self.r2r_sections],
            "runtime_functions_count": len(self.runtime_functions),
            "runtime_functions": [rf.to_dict() for rf in self.runtime_functions[:50]],
            "method_entrypoints_count": len(self.method_entrypoints),
            "method_entrypoints": [me.to_dict() for me in self.method_entrypoints[:50]],
            "symbols_count": len(self.symbols),
            "symbols": [s.to_dict() for s in self.symbols[:50]],
            "disassembled_methods_count": len(self.disassembled_methods),
            "disassembled_methods": [dm.to_dict() for dm in self.disassembled_methods[:20]],
        }


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


def safe_path(base_dir: str, rel_path: str) -> str:
    """Validates destination path to ensure no path traversal escape from base directory."""
    resolved_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(resolved_base, rel_path))
    if not (target_path == resolved_base or target_path.startswith(resolved_base + os.sep)):
        raise SecurityError(f"Path traversal detected: '{rel_path}' attempts to escape base directory '{base_dir}'")
    return target_path
