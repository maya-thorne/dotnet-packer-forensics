"""
.NET Single-File Host (AppHost / Bundle) Extraction and Forensic Carving Module.
Engineered & Audited by Maya Thorne.
"""

from .decompressor import BundleDecompressor
from .header_parser import BundleHeaderParser, read_7bit_encoded_int, write_7bit_encoded_int
from .marker_scanner import (
    DOTNET_BUNDLE_MARKER,
    WARP_MAGIC,
    BundleMarkerScanner,
)
from .models import (
    BundleEntry,
    BundleExtractionResult,
    BundleFileType,
    BundleHeader,
    BundleOptions,
    BundleTelemetry,
    BundleVersion,
    CompressionKind,
    SecurityError,
    SuperPackerKind,
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)
from .unbundler import SingleFileBundleEngine
from .virtual_volume import VirtualBundleVolume, VirtualVolumeNode

__all__ = [
    "BundleDecompressor",
    "BundleHeaderParser",
    "read_7bit_encoded_int",
    "write_7bit_encoded_int",
    "DOTNET_BUNDLE_MARKER",
    "WARP_MAGIC",
    "BundleMarkerScanner",
    "BundleEntry",
    "BundleExtractionResult",
    "BundleFileType",
    "BundleHeader",
    "BundleOptions",
    "BundleTelemetry",
    "BundleVersion",
    "CompressionKind",
    "SecurityError",
    "SuperPackerKind",
    "calculate_entropy",
    "safe_path",
    "zeroize_buffer",
    "SingleFileBundleEngine",
    "VirtualBundleVolume",
    "VirtualVolumeNode",
]
