"""
ECMA-335 BSJB Metadata Header Scanner and Metadata Stream Carver.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import CarverAnomalyFlag, CarvedString


class BSJBCarver:
    """
    Scans memory buffers for ECMA-335 BSJB signatures, extracts stream descriptors,
    parses string heaps (#US / #Strings), and recovers metadata tables (#~ / #-).
    """

    BSJB_MAGIC = b"BSJB"

    @classmethod
    def scan_bsjb_roots(cls, data: bytes) -> List[int]:
        """Scans buffer and returns list of file offsets where BSJB header begins."""
        offsets: List[int] = []
        start = 0
        while True:
            idx = data.find(cls.BSJB_MAGIC, start)
            if idx == -1:
                break
            # Sanity check: must have at least 16 bytes following BSJB
            if idx + 16 <= len(data):
                offsets.append(idx)
            start = idx + 4
        return offsets

    @classmethod
    def parse_bsjb_header(
        cls, data: bytes, bsjb_offset: int
    ) -> Optional[Dict[str, Any]]:
        """
        Parses ECMA-335 BSJB header and stream table descriptors at given offset.
        """
        data_len = len(data)
        if bsjb_offset + 16 > data_len:
            return None

        # Verify magic
        if data[bsjb_offset : bsjb_offset + 4] != cls.BSJB_MAGIC:
            return None

        major, minor, _reserved, ver_len = struct.unpack_from(
            "<HHII", data, bsjb_offset + 4
        )
        if bsjb_offset + 16 + ver_len > data_len or ver_len > 256:
            return None

        ver_bytes = data[bsjb_offset + 16 : bsjb_offset + 16 + ver_len]
        ver_str = ver_bytes.split(b"\x00")[0].decode("ascii", errors="ignore")

        # Offset to Flags and Streams count
        after_ver = bsjb_offset + 16 + ver_len
        if after_ver + 4 > data_len:
            return None

        _flags, num_streams = struct.unpack_from("<HH", data, after_ver)
        if num_streams > 16:  # Standard ECMA-335 has at most 5-6 streams
            return None

        streams: Dict[str, Dict[str, int]] = {}
        curr_offset = after_ver + 4

        for _ in range(num_streams):
            if curr_offset + 8 > data_len:
                break
            s_offset, s_size = struct.unpack_from("<II", data, curr_offset)
            curr_offset += 8

            # Read null-terminated stream name (padded to 4-byte boundary)
            name_chars: List[int] = []
            while curr_offset < data_len:
                b = data[curr_offset]
                curr_offset += 1
                if b == 0:
                    # Pad to 4-byte boundary
                    while curr_offset % 4 != 0 and curr_offset < data_len:
                        curr_offset += 1
                    break
                name_chars.append(b)
                if len(name_chars) > 32:
                    break

            stream_name = bytes(name_chars).decode("ascii", errors="ignore")
            if stream_name:
                streams[stream_name] = {
                    "offset": bsjb_offset + s_offset,
                    "size": s_size,
                    "rel_offset": s_offset,
                }

        return {
            "bsjb_offset": bsjb_offset,
            "version": ver_str,
            "major": major,
            "minor": minor,
            "streams_count": num_streams,
            "streams": streams,
        }

    @classmethod
    def extract_user_strings(
        cls, data: bytes, us_stream_offset: int, us_stream_size: int, max_strings: int = 100
    ) -> List[CarvedString]:
        """
        Parses the #US (User String) heap extracting UTF-16LE string literals.
        """
        results: List[CarvedString] = []
        data_len = len(data)
        limit = min(us_stream_offset + us_stream_size, data_len)

        # First byte in #US is always 0x00 (empty string)
        curr = us_stream_offset + 1
        while curr < limit and len(results) < max_strings:
            # Decode compressed 7-bit length
            b0 = data[curr]
            curr += 1
            if b0 == 0:
                continue

            if (b0 & 0x80) == 0:
                str_byte_len = b0
            elif (b0 & 0xC0) == 0x80:
                if curr >= limit:
                    break
                b1 = data[curr]
                curr += 1
                str_byte_len = ((b0 & 0x3F) << 8) | b1
            else:
                if curr + 2 >= limit:
                    break
                b1, b2, b3 = data[curr : curr + 3]
                curr += 3
                str_byte_len = ((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3

            if str_byte_len < 1 or curr + str_byte_len > limit:
                break

            # The last byte is trailing flag byte (0x00 or 0x01), string chars are str_byte_len - 1
            char_bytes_len = str_byte_len - 1
            if char_bytes_len > 0 and char_bytes_len % 2 == 0:
                raw_chars = data[curr : curr + char_bytes_len]
                try:
                    val = raw_chars.decode("utf-16le", errors="ignore")
                    # Filter out non-printable or trivial whitespace
                    if val.strip() and any(c.isalnum() for c in val):
                        results.append(
                            CarvedString(
                                heap="#US",
                                offset=curr,
                                value=val.strip(),
                                length=len(val),
                            )
                        )
                except Exception:
                    pass

            curr += str_byte_len

        return results

    @classmethod
    def extract_identifier_strings(
        cls, data: bytes, strings_offset: int, strings_size: int, max_strings: int = 100
    ) -> List[CarvedString]:
        """
        Parses the #Strings heap extracting null-terminated UTF-8 identifier tokens.
        """
        results: List[CarvedString] = []
        data_len = len(data)
        limit = min(strings_offset + strings_size, data_len)

        curr = strings_offset + 1  # 0x00 is empty string
        while curr < limit and len(results) < max_strings:
            null_pos = data.find(b"\x00", curr, limit)
            if null_pos == -1:
                null_pos = limit

            token_bytes = data[curr:null_pos]
            if len(token_bytes) >= 3:
                try:
                    val = token_bytes.decode("utf-8", errors="ignore")
                    if val.isascii() and any(c.isalpha() for c in val):
                        results.append(
                            CarvedString(
                                heap="#Strings",
                                offset=curr,
                                value=val,
                                length=len(val),
                            )
                        )
                except Exception:
                    pass

            curr = null_pos + 1
        return results

    @classmethod
    def parse_metadata_tables(
        cls, data: bytes, table_stream_offset: int, table_stream_size: int
    ) -> Dict[str, Any]:
        """
        Parses ECMA-335 #~ or #- metadata table stream header and table row counts.
        """
        data_len = len(data)
        if table_stream_offset + 24 > data_len:
            return {"valid_tables": 0, "table_row_counts": {}}

        _reserved, major, minor, heap_sizes, _res2, valid_mask, sorted_mask = (
            struct.unpack_from("<IBBBBQQ", data, table_stream_offset)
        )

        table_names = [
            "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef",
            "ParamPtr", "Param", "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute",
            "FieldMarshal", "DeclSecurity", "ClassLayout", "FieldLayout", "StandAloneSig",
            "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
            "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA",
            "ENCLog", "ENCMap", "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef",
            "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType", "ManifestResource",
            "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint",
        ]

        table_row_counts: Dict[str, int] = {}
        curr = table_stream_offset + 24

        for table_idx in range(64):
            if (valid_mask & (1 << table_idx)) != 0:
                if curr + 4 > data_len:
                    break
                rows = struct.unpack_from("<I", data, curr)[0]
                curr += 4
                name = (
                    table_names[table_idx]
                    if table_idx < len(table_names)
                    else f"Table_{table_idx:02X}"
                )
                table_row_counts[name] = rows

        return {
            "major": major,
            "minor": minor,
            "heap_sizes": heap_sizes,
            "valid_mask": hex(valid_mask),
            "sorted_mask": hex(sorted_mask),
            "table_row_counts": table_row_counts,
        }
