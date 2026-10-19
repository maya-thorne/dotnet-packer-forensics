"""
Data Models, Enums, and Security Primitives for .NET Single-File Host (AppHost / Bundle).
Engineered & Audited by Maya Thorne.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
import os
import re
from typing import Any, Dict, List, Optional


class SecurityError(Exception):
    """Raised when security boundaries (path traversal, bounds, corruption) are violated."""
    pass


class BundleFileType(str, Enum):
    """File type identifiers defined in the .NET Bundle specification."""
    UNKNOWN = "unknown"
    ASSEMBLY = "assembly"                      # 0x01: Managed .NET DLL or EXE
    NATIVE_BINARY = "native_binary"            # 0x02: Native DLL (.dll, .so, .dylib)
    PDB_FILE = "pdb_file"                      # 0x03: Debug symbols (.pdb)
    DEPS_JSON = "deps_json"                    # 0x04: .deps.json
    RUNTIME_CONFIG_JSON = "runtime_config_json" # 0x05: .runtimeconfig.json
    SYMBOLS = "symbols"                        # 0x06: Symbol files
    ICON = "icon"                              # 0x07: Embedded application icon
    CONTENT = "content"                        # 0x08: Arbitrary content file
    EXTRACT_TO_DISK = "extract_to_disk"        # 0x09: Native dependency extracted on run


class BundleVersion(str, Enum):
    """Single-File Host bundle specification version."""
    V1_NETCORE3 = "v1_netcore3"   # .NET Core 3.0 / 3.1
    V2_NET5 = "v2_net5"           # .NET 5.0
    V6_NET6_PLUS = "v6_net6_plus" # .NET 6.0, 7.0, 8.0, 9.0, 10.0
    UNKNOWN = "unknown"


class CompressionKind(str, Enum):
    """Compression algorithm applied to bundled streams."""
    NONE = "none"
    DEFLATE = "deflate"
    ZLIB = "zlib"
    BROTLI = "brotli"
    LZMA = "lzma"
    UNKNOWN = "unknown"


class SuperPackerKind(str, Enum):
    """High-level superpacker or bundle format classification."""
    NONE = "none"
    DOTNET_APPHOST = "dotnet_apphost" # Official Microsoft .NET Single-File Host
    WARP = "warp"                     # Warp Packer (dgiagio/warp)
    BOXEDAPP = "boxedapp"             # BoxedApp Packer (.bxapp)
    ENIGMA = "enigma"                 # Enigma Virtual Box
    COSTURA = "costura"               # Costura.Fody Embedded Assembly Packer


@dataclass
class BundleEntry:
    """Individual embedded file entry within the .NET single-file bundle."""
    offset: int
    size: int
    compressed_size: int
    file_type: BundleFileType
    relative_path: str
    sha256: str = ""
    entropy: float = 0.0
    is_compressed: bool = False
    is_pe: bool = False
    is_dotnet: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "file_type": self.file_type.value,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "entropy": round(self.entropy, 4),
            "is_compressed": self.is_compressed,
            "is_pe": self.is_pe,
            "is_dotnet": self.is_dotnet,
        }


@dataclass
class BundleHeader:
    """Parsed .NET Single-File bundle header metadata."""
    major_version: int
    minor_version: int
    file_count: int
    bundle_id: str
    deps_json_offset: int = 0
    deps_json_size: int = 0
    runtime_config_json_offset: int = 0
    runtime_config_json_size: int = 0
    flags: int = 0
    header_offset: int = 0
    marker_offset: int = 0
    is_compressed: bool = False
    entries: List[BundleEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "file_count": self.file_count,
            "bundle_id": self.bundle_id,
            "deps_json_offset": self.deps_json_offset,
            "deps_json_size": self.deps_json_size,
            "runtime_config_json_offset": self.runtime_config_json_offset,
            "runtime_config_json_size": self.runtime_config_json_size,
            "flags": self.flags,
            "header_offset": self.header_offset,
            "marker_offset": self.marker_offset,
            "is_compressed": self.is_compressed,
            "entries_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class BundleOptions:
    """Execution options for single-file bundle extraction and virtual volume mounting."""
    extract_dir: Optional[str] = None
    file_filter: str = "all"      # "all", "assemblies", "native", "symbols", "configs"
    decompress: bool = True
    verify_pe: bool = True
    min_confidence: float = 0.5


@dataclass
class BundleTelemetry:
    """Telemetry summary for bundle detection and carving."""
    is_bundle: bool = False
    packer_kind: SuperPackerKind = SuperPackerKind.NONE
    version: BundleVersion = BundleVersion.UNKNOWN
    bundle_id: str = ""
    total_files: int = 0
    assembly_count: int = 0
    native_count: int = 0
    pdb_count: int = 0
    config_count: int = 0
    total_uncompressed_bytes: int = 0
    total_compressed_bytes: int = 0
    overall_compression_ratio: float = 1.0
    has_compression: bool = False
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_bundle": self.is_bundle,
            "packer_kind": self.packer_kind.value,
            "version": self.version.value,
            "bundle_id": self.bundle_id,
            "total_files": self.total_files,
            "assembly_count": self.assembly_count,
            "native_count": self.native_count,
            "pdb_count": self.pdb_count,
            "config_count": self.config_count,
            "total_uncompressed_bytes": self.total_uncompressed_bytes,
            "total_compressed_bytes": self.total_compressed_bytes,
            "overall_compression_ratio": round(self.overall_compression_ratio, 4),
            "has_compression": self.has_compression,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class BundleExtractionResult:
    """Comprehensive result of bundle carving and virtual volume mounting."""
    file_name: str
    is_bundle: bool
    header: Optional[BundleHeader]
    entries: List[BundleEntry]
    telemetry: BundleTelemetry
    extracted_files: Dict[str, bytes] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "is_bundle": self.is_bundle,
            "header": self.header.to_dict() if self.header else None,
            "telemetry": self.telemetry.to_dict(),
            "extracted_count": len(self.extracted_files),
            "extracted_file_list": list(self.extracted_files.keys()),
            "errors": self.errors,
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

    # Disallow NTFS ADS (Alternate Data Streams)
    if ":" in target_path and not (len(target_path) > 1 and target_path[1] == ":" and ":" not in target_path[2:]):
        raise SecurityError(f"NTFS Alternate Data Stream detected in path: {target_path}")

    # Check for absolute path or root path
    if target_path.startswith("/") or target_path.startswith("\\") or (len(target_path) > 1 and target_path[1] == ":"):
        abs_target = os.path.realpath(target_path)
    else:
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
        raise SecurityError(f"Directory traversal attack detected in path: {target_path}")

    return abs_target


def zeroize_buffer(buf: Any) -> None:
    """Cryptographically overwrites mutable buffers in memory with zeros."""
    if buf is None:
        return
    try:
        import ctypes
        if isinstance(buf, (bytearray, memoryview)):
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, len(buf))
    except Exception:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte stream on a [0.0, 8.0] scale."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)
