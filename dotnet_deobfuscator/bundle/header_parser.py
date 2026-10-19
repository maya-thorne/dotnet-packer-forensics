"""
BundleHeader Parser and Synthesizer for .NET Single-File Host Bundles.
Engineered & Audited by Maya Thorne.
"""

import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    BundleEntry,
    BundleFileType,
    BundleHeader,
    BundleVersion,
    SecurityError,
    calculate_entropy,
)


FILE_TYPE_MAP: Dict[int, BundleFileType] = {
    0x00: BundleFileType.UNKNOWN,
    0x01: BundleFileType.ASSEMBLY,
    0x02: BundleFileType.NATIVE_BINARY,
    0x03: BundleFileType.PDB_FILE,
    0x04: BundleFileType.DEPS_JSON,
    0x05: BundleFileType.RUNTIME_CONFIG_JSON,
    0x06: BundleFileType.SYMBOLS,
    0x07: BundleFileType.ICON,
    0x08: BundleFileType.CONTENT,
    0x09: BundleFileType.EXTRACT_TO_DISK,
}

REVERSE_FILE_TYPE_MAP: Dict[BundleFileType, int] = {v: k for k, v in FILE_TYPE_MAP.items()}


def read_7bit_encoded_int(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Reads a 7-bit encoded integer (LEB128 format used by .NET BinaryReader).
    Returns: Tuple of (decoded_value, bytes_consumed).
    """
    result = 0
    shift = 0
    consumed = 0
    while True:
        if offset + consumed >= len(data):
            raise SecurityError("Unexpected EOF while reading 7-bit encoded integer.")
        byte = data[offset + consumed]
        consumed += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift >= 35:
            raise SecurityError("7-bit encoded integer overflowed 32 bits.")
    return result, consumed


def write_7bit_encoded_int(value: int) -> bytes:
    """Encodes an integer into a 7-bit encoded integer (LEB128)."""
    out = bytearray()
    v = value
    while v >= 0x80:
        out.append((v | 0x80) & 0xFF)
        v >>= 7
    out.append(v & 0x7F)
    return bytes(out)


def read_dotnet_string(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Reads a length-prefixed UTF-8 string (.NET BinaryReader.ReadString format).
    Returns: Tuple of (string_value, bytes_consumed).
    """
    length, len_bytes = read_7bit_encoded_int(data, offset)
    cur = offset + len_bytes
    if cur + length > len(data):
        raise SecurityError(f"String length {length} exceeds buffer size at offset {offset}.")
    raw_str = data[cur : cur + length]
    try:
        decoded = raw_str.decode("utf-8")
    except UnicodeDecodeError:
        decoded = raw_str.decode("latin-1", errors="replace")
    return decoded, len_bytes + length


def write_dotnet_string(text: str) -> bytes:
    """Encodes a string using .NET BinaryReader.WriteString format."""
    encoded = text.encode("utf-8")
    return write_7bit_encoded_int(len(encoded)) + encoded


class BundleHeaderParser:
    """Parses and serializes .NET Single-File Host Bundle Headers."""

    @classmethod
    def parse_header(cls, data: bytes, header_offset: int, marker_offset: int = 0) -> BundleHeader:
        """
        Parses the BundleHeader at header_offset according to .NET Bundle specifications.
        """
        if header_offset < 0 or header_offset + 12 > len(data):
            raise SecurityError(f"Invalid bundle header offset {header_offset} for buffer size {len(data)}.")

        cur = header_offset
        major_version, minor_version, file_count = struct.unpack_from("<III", data, cur)
        cur += 12

        # Sanity check file count to prevent resource exhaustion attacks
        if file_count < 0 or file_count > 65536:
            raise SecurityError(f"Suspicious bundle file count {file_count} at offset {header_offset}.")

        # Read bundle ID string
        bundle_id, id_consumed = read_dotnet_string(data, cur)
        cur += id_consumed

        deps_json_offset = 0
        deps_json_size = 0
        runtime_config_json_offset = 0
        runtime_config_json_size = 0
        flags = 0
        is_compressed = False

        # In v2 (.NET 5) and v6 (.NET 6/7/8/9/10), additional header fields exist
        if major_version >= 2:
            if cur + 40 > len(data):
                raise SecurityError(f"Truncated v{major_version} bundle header at offset {cur}.")
            (
                deps_json_offset,
                deps_json_size,
                runtime_config_json_offset,
                runtime_config_json_size,
                flags,
            ) = struct.unpack_from("<qqqqQ", data, cur)
            cur += 40
            # Flag bit 0 indicates bundle compression enabled in .NET 6+
            is_compressed = bool(flags & 0x01)

        # Parse file entries
        entries: List[BundleEntry] = []
        for _ in range(file_count):
            if cur >= len(data):
                raise SecurityError(f"Unexpected EOF while reading bundle file entries at offset {cur}.")

            if major_version >= 6:
                # v6+: offset (8), size (8), compressed_size (8), file_type (1)
                if cur + 25 > len(data):
                    raise SecurityError(f"Truncated v6 file entry at offset {cur}.")
                offset, size, compressed_size, type_val = struct.unpack_from("<qqqB", data, cur)
                cur += 25
            else:
                # v1 & v2: offset (8), size (8), file_type (1)
                if cur + 17 > len(data):
                    raise SecurityError(f"Truncated v1/v2 file entry at offset {cur}.")
                offset, size, type_val = struct.unpack_from("<qqB", data, cur)
                compressed_size = 0
                cur += 17

            # Read entry relative path
            path_str, path_consumed = read_dotnet_string(data, cur)
            cur += path_consumed

            # Resolve file type
            file_type = FILE_TYPE_MAP.get(type_val, BundleFileType.UNKNOWN)

            # Heuristics for compression check
            entry_compressed = (compressed_size > 0 and compressed_size != size) or (is_compressed and compressed_size > 0)

            # Quick PE header check if within bounds
            is_pe = False
            is_dotnet = False
            entropy_val = 0.0
            if 0 <= offset < len(data):
                sample_len = min(size if not entry_compressed else compressed_size, 512)
                sample = data[offset : offset + sample_len]
                if sample.startswith(b"MZ"):
                    is_pe = True
                    if b"BSJB" in sample or b".text" in sample:
                        is_dotnet = True
                entropy_val = calculate_entropy(sample)

            entries.append(
                BundleEntry(
                    offset=offset,
                    size=size,
                    compressed_size=compressed_size,
                    file_type=file_type,
                    relative_path=path_str,
                    entropy=entropy_val,
                    is_compressed=entry_compressed,
                    is_pe=is_pe,
                    is_dotnet=is_dotnet,
                )
            )

        return BundleHeader(
            major_version=major_version,
            minor_version=minor_version,
            file_count=file_count,
            bundle_id=bundle_id,
            deps_json_offset=deps_json_offset,
            deps_json_size=deps_json_size,
            runtime_config_json_offset=runtime_config_json_offset,
            runtime_config_json_size=runtime_config_json_size,
            flags=flags,
            header_offset=header_offset,
            marker_offset=marker_offset,
            is_compressed=is_compressed,
            entries=entries,
        )

    @classmethod
    def serialize_header(cls, header: BundleHeader) -> bytes:
        """
        Serializes a BundleHeader object into compliant binary format.
        """
        buf = bytearray()
        buf.extend(struct.pack("<III", header.major_version, header.minor_version, len(header.entries)))
        buf.extend(write_dotnet_string(header.bundle_id))

        if header.major_version >= 2:
            buf.extend(
                struct.pack(
                    "<qqqqQ",
                    header.deps_json_offset,
                    header.deps_json_size,
                    header.runtime_config_json_offset,
                    header.runtime_config_json_size,
                    header.flags,
                )
            )

        for e in header.entries:
            type_val = REVERSE_FILE_TYPE_MAP.get(e.file_type, 0x00)
            if header.major_version >= 6:
                buf.extend(struct.pack("<qqqB", e.offset, e.size, e.compressed_size, type_val))
            else:
                buf.extend(struct.pack("<qqB", e.offset, e.size, type_val))
            buf.extend(write_dotnet_string(e.relative_path))

        return bytes(buf)
