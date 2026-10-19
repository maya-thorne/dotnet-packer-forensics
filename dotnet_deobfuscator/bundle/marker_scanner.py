"""
Marker and Signature Scanner for .NET Single-File Host and Superpacker Formats.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import SuperPackerKind


# Official 32-byte Microsoft .NET Single-File Host Bundle Marker (SHA-256 of Bundle GUID)
# Used across .NET Core 3.x, .NET 5, 6, 7, 8, 9, 10
DOTNET_BUNDLE_MARKER = bytes([
    0x8b, 0x12, 0x02, 0x9f, 0x77, 0xc4, 0xd0, 0x45,
    0xa2, 0x7a, 0xd1, 0x97, 0x12, 0x70, 0x8f, 0xd3,
    0xc7, 0xa5, 0xd3, 0xfc, 0xb9, 0xde, 0xda, 0x4c,
    0x9a, 0x91, 0x62, 0x13, 0x46, 0xee, 0xcf, 0x84,
])

# Warp Packer footer signature (https://github.com/dgiagio/warp)
WARP_MAGIC = b"WARP\x00"

# BoxedApp Packer signatures
BOXEDAPP_SECTION = b".bxapp"
BOXEDAPP_MAGIC = b"BoxedApp"

# Enigma Virtual Box signatures
ENIGMA_MAGIC = b"EVB\x00"
ENIGMA_STRING = b"Enigma Virtual Box"


class BundleMarkerScanner:
    """Scans and locates single-file host bundle markers and superpacker signatures."""

    @classmethod
    def scan_dotnet_marker(cls, data: bytes) -> Optional[Tuple[int, int]]:
        """
        Scans data for the 32-byte .NET bundle marker and extracts the 64-bit bundle header offset.
        Returns: Tuple of (marker_offset, bundle_header_offset) or None if not found.
        """
        if len(data) < len(DOTNET_BUNDLE_MARKER) + 8:
            return None

        # Search from EOF backwards first (typical for single-file bundles with overlay payloads)
        marker_pos = data.rfind(DOTNET_BUNDLE_MARKER)
        while marker_pos != -1:
            if marker_pos >= 8:
                offset_bytes = data[marker_pos - 8 : marker_pos]
                header_offset = struct.unpack("<q", offset_bytes)[0]

                # Check if header_offset is a valid absolute offset
                if 0 <= header_offset < len(data):
                    return (marker_pos, header_offset)

                # Check if header_offset is relative to EOF (negative offset)
                if -len(data) <= header_offset < 0:
                    abs_offset = len(data) + header_offset
                    if 0 <= abs_offset < len(data):
                        return (marker_pos, abs_offset)

                # Check if header_offset is relative to marker position
                rel_marker_offset = marker_pos + header_offset
                if 0 <= rel_marker_offset < len(data):
                    return (marker_pos, rel_marker_offset)

            # If previous candidate didn't resolve to a valid offset, search earlier in binary
            marker_pos = data.rfind(DOTNET_BUNDLE_MARKER, 0, marker_pos)

        return None

    @classmethod
    def identify_packer(cls, data: bytes) -> Tuple[SuperPackerKind, Dict[str, Any]]:
        """
        Identifies whether binary is packed with official .NET Single-File Host or third-party superpacker.
        Returns: Tuple of (SuperPackerKind, metadata_dict).
        """
        meta: Dict[str, Any] = {
            "has_marker": False,
            "marker_offset": -1,
            "header_offset": -1,
            "matched_signatures": [],
        }

        # 1. Official .NET Single-File Host
        dotnet_marker = cls.scan_dotnet_marker(data)
        if dotnet_marker:
            marker_off, header_off = dotnet_marker
            meta["has_marker"] = True
            meta["marker_offset"] = marker_off
            meta["header_offset"] = header_off
            meta["matched_signatures"].append("DOTNET_BUNDLE_MARKER")
            return (SuperPackerKind.DOTNET_APPHOST, meta)

        # 2. Warp Packer
        if WARP_MAGIC in data:
            meta["matched_signatures"].append("WARP_MAGIC")
            warp_pos = data.rfind(WARP_MAGIC)
            meta["marker_offset"] = warp_pos
            return (SuperPackerKind.WARP, meta)

        # 3. BoxedApp Packer
        if BOXEDAPP_SECTION in data or BOXEDAPP_MAGIC in data:
            if BOXEDAPP_SECTION in data:
                meta["matched_signatures"].append("BOXEDAPP_SECTION")
            if BOXEDAPP_MAGIC in data:
                meta["matched_signatures"].append("BOXEDAPP_MAGIC")
            return (SuperPackerKind.BOXEDAPP, meta)

        # 4. Enigma Virtual Box
        if ENIGMA_MAGIC in data or ENIGMA_STRING in data:
            if ENIGMA_MAGIC in data:
                meta["matched_signatures"].append("ENIGMA_MAGIC")
            if ENIGMA_STRING in data:
                meta["matched_signatures"].append("ENIGMA_STRING")
            return (SuperPackerKind.ENIGMA, meta)

        # 5. Costura.Fody
        if b"costura." in data or b".dll.compressed" in data:
            meta["matched_signatures"].append("COSTURA_EMBEDDED")
            return (SuperPackerKind.COSTURA, meta)

        return (SuperPackerKind.NONE, meta)
