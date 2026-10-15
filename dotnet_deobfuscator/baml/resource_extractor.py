"""
Managed Resource Container (.resources) Parser & BAML Stream Carving Engine.
Engineered & Audited by Maya Thorne.
"""

import math
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    BamlAnomalyFlag,
    BamlElement,
    BamlError,
    BamlRecordType,
    ResourceSourceType,
)


def _calc_entropy(data_str: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not data_str:
        return 0.0
    length = len(data_str)
    counts: Dict[str, int] = {}
    for ch in data_str:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class BamlResourceExtractor:
    """Extracts BAML binary streams from .NET .resources containers and raw PE sections."""

    MANAGED_RESOURCES_MAGIC = 0xBEEFCACE  # Little-endian: 0xCE, 0xCA, 0xEF, 0xBE
    MAX_RESOURCE_SIZE = 100 * 1024 * 1024  # 100 MB safety limit

    SUSPICIOUS_HANDLER_KEYWORDS = (
        "shell", "payload", "exec", "inject", "stager", "drop",
        "hollow", "powershell", "cmd", "beacon", "c2", "download",
    )

    @classmethod
    def extract_from_resources(cls, data: bytes) -> List[Tuple[str, bytes]]:
        """Parses standard .NET ResourceManager binary containers (0xBEEFCACE) for .baml entries."""
        if len(data) < 24:
            return []

        # Check magic
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != cls.MANAGED_RESOURCES_MAGIC:
            return []

        items: List[Tuple[str, bytes]] = []
        pos = 4

        try:
            # Header info
            num_res_header = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            header_skip = struct.unpack_from("<I", data, pos)[0]
            pos += 4

            if header_skip > len(data) - pos:
                return []
            pos += header_skip

            if pos + 12 > len(data):
                return []

            version = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            num_resources = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            num_types = struct.unpack_from("<I", data, pos)[0]
            pos += 4

            if num_resources == 0 or num_resources > 10000:
                return []

            # Skip type descriptions
            for _ in range(num_types):
                str_len, pos = cls._read_7bit_int(data, pos)
                pos += str_len

            # Align to 8-byte boundary if version == 1
            # Hash values table (4 bytes * num_resources)
            pos += 4 * num_resources
            if pos > len(data):
                return []

            # Virtual offsets for names (4 bytes * num_resources)
            name_offsets = []
            for _ in range(num_resources):
                name_offsets.append(struct.unpack_from("<I", data, pos)[0])
                pos += 4

            if pos + 4 > len(data):
                return []
            data_section_offset = struct.unpack_from("<I", data, pos)[0]
            pos += 4

            name_section_base = pos

            for name_rel_offset in name_offsets:
                cur_name_pos = name_section_base + name_rel_offset
                if cur_name_pos >= len(data):
                    continue

                # Read name string (UTF-16LE in standard .resources)
                name_byte_len, cur_name_pos = cls._read_7bit_int(data, cur_name_pos)
                if cur_name_pos + name_byte_len + 4 > len(data):
                    continue

                raw_name_bytes = data[cur_name_pos : cur_name_pos + name_byte_len]
                cur_name_pos += name_byte_len
                resource_name = raw_name_bytes.decode("utf-16le", errors="replace")

                data_rel_offset = struct.unpack_from("<I", data, cur_name_pos)[0]
                item_data_pos = data_section_offset + data_rel_offset

                if item_data_pos >= len(data):
                    continue

                # Read type code and data
                type_code, item_data_pos = cls._read_7bit_int(data, item_data_pos)
                # Read payload length
                payload_len, item_data_pos = cls._read_7bit_int(data, item_data_pos)

                if payload_len <= 0 or payload_len > cls.MAX_RESOURCE_SIZE:
                    continue
                if item_data_pos + payload_len > len(data):
                    continue

                payload_bytes = data[item_data_pos : item_data_pos + payload_len]

                # Check if name ends with .baml or data starts with BAML signature
                if resource_name.lower().endswith(".baml") or cls._is_baml_payload(payload_bytes):
                    items.append((resource_name, payload_bytes))

        except Exception:
            # Fall back safely on partial parses
            pass

        return items

    @classmethod
    def carve_baml_streams(cls, data: bytes) -> List[Tuple[str, bytes]]:
        """Heuristically carves standalone BAML byte streams from arbitrary buffers."""
        carved: List[Tuple[str, bytes]] = []
        if len(data) < 16:
            return carved

        # Search for BAML version signature: 0x00600000 or DocumentStart sequences
        target_seqs = [
            b"\x00\x60\x00\x00",
            b"\x00\x00\x00\x00\x60\x00\x00\x00",
        ]

        found_offsets: Set[int] = set()
        for seq in target_seqs:
            start = 0
            while True:
                idx = data.find(seq, start)
                if idx == -1:
                    break
                found_offsets.add(idx)
                start = idx + 1

        # Also search for DocumentStart opcode (0x01) followed by AssemblyInfo (0x1D) or TypeInfo (0x1E)
        doc_start_pat = re.compile(b"\x01[\x00\x01]?[\x1D\x1E\x20\x03]")
        for m in doc_start_pat.finditer(data):
            found_offsets.add(m.start())

        stream_idx = 1
        for offset in sorted(found_offsets):
            sub_data = data[offset : min(offset + 500000, len(data))]
            if cls._is_baml_payload(sub_data):
                # Search for DocumentEnd opcode (0x02)
                end_idx = sub_data.find(b"\x02", 4)
                if end_idx != -1:
                    stream_bytes = sub_data[: end_idx + 1]
                else:
                    stream_bytes = sub_data[: min(4096, len(sub_data))]

                carved.append((f"carved_stream_{stream_idx}.baml", stream_bytes))
                stream_idx += 1

        return carved

    @classmethod
    def extract_all(
        cls, data: bytes, source_name: str = "binary.exe"
    ) -> List[Tuple[str, bytes, ResourceSourceType]]:
        """Extracts all BAML streams from data using multi-stage container parsing and carving."""
        results: List[Tuple[str, bytes, ResourceSourceType]] = []

        # 1. Managed Resources parsing
        managed_items = cls.extract_from_resources(data)
        for name, b_data in managed_items:
            results.append((name, b_data, ResourceSourceType.MANAGED_RESOURCES))

        # 2. If no managed resources or if pure BAML, test entire buffer
        if not results:
            if cls._is_baml_payload(data):
                results.append((source_name, data, ResourceSourceType.RAW_BAML_STREAM))

        # 3. If still empty, attempt heuristic carving
        if not results:
            carved_items = cls.carve_baml_streams(data)
            for name, b_data in carved_items:
                results.append((name, b_data, ResourceSourceType.PE_SECTION_CARVED))

        return results

    @classmethod
    def detect_anomalies(cls, root: Optional[BamlElement], raw_bytes: bytes) -> List[str]:
        """Performs deep static forensic analysis on BAML element trees and raw streams."""
        anomalies: List[str] = []
        if root is None:
            return anomalies

        # URL regex
        url_pattern = re.compile(r"(https?://[^\s\"'>]+|ftp://[^\s\"'>]+|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)")
        base64_pattern = re.compile(r"^[A-Za-z0-9+/]{64,}={0,2}$")

        def _scan_element(elem: BamlElement) -> None:
            # 1. Suspicious Event Handlers
            for k, v in elem.attributes.items():
                lower_v = v.lower()
                for kw in cls.SUSPICIOUS_HANDLER_KEYWORDS:
                    if kw in lower_v:
                        anomalies.append(
                            f"{BamlAnomalyFlag.SUSPICIOUS_EVENT_HANDLER.value}: Element '{elem.tag_name}' bound to suspicious handler/value '{v}'"
                        )
                        elem.anomalies.append(BamlAnomalyFlag.SUSPICIOUS_EVENT_HANDLER.value)
                        break

            # 2. Suspicious URIs in attributes
            for k, v in elem.attributes.items():
                match = url_pattern.search(v)
                if match:
                    anomalies.append(
                        f"{BamlAnomalyFlag.SUSPICIOUS_URI.value}: Element '{elem.tag_name}' attribute '{k}' contains URI '{match.group(0)}'"
                    )
                    elem.anomalies.append(BamlAnomalyFlag.SUSPICIOUS_URI.value)

            # 3. Hidden UI Elements with clandestine payloads
            vis = elem.attributes.get("Visibility", "")
            opacity = elem.attributes.get("Opacity", "")
            is_hidden = vis in ("Collapsed", "Hidden") or opacity in ("0", "0.0")
            if is_hidden and (elem.children or elem.text or len(elem.attributes) > 2):
                anomalies.append(
                    f"{BamlAnomalyFlag.HIDDEN_UI_ELEMENT.value}: Concealed UI element '{elem.tag_name}' (Visibility={vis or opacity}) contains active nodes/attributes"
                )
                elem.anomalies.append(BamlAnomalyFlag.HIDDEN_UI_ELEMENT.value)

            # 4. Large Base64 Blobs
            for k, v in elem.attributes.items():
                if len(v) >= 64 and base64_pattern.match(v):
                    entropy = _calc_entropy(v)
                    if entropy >= 4.5:
                        anomalies.append(
                            f"{BamlAnomalyFlag.SUSPICIOUS_BASE64_PAYLOAD.value}: High-entropy Base64 payload in '{elem.tag_name}.{k}' (len={len(v)}, entropy={entropy})"
                        )
                        elem.anomalies.append(BamlAnomalyFlag.SUSPICIOUS_BASE64_PAYLOAD.value)

            # 5. Obfuscated Identifiers
            for text_to_check in [elem.tag_name, elem.attributes.get("x:Class", "")]:
                if text_to_check:
                    non_ascii_count = sum(1 for ch in text_to_check if ord(ch) > 127)
                    if non_ascii_count > 3:
                        anomalies.append(
                            f"{BamlAnomalyFlag.OBFUSCATED_IDENTIFIER.value}: Obfuscated Unicode identifier detected in '{text_to_check}'"
                        )
                        elem.anomalies.append(BamlAnomalyFlag.OBFUSCATED_IDENTIFIER.value)

            # Recurse children
            for child in elem.children:
                _scan_element(child)

        _scan_element(root)
        return list(dict.fromkeys(anomalies))

    @classmethod
    def _is_baml_payload(cls, data: bytes) -> bool:
        """Determines if byte slice begins with valid BAML records or version signatures."""
        if len(data) < 2:
            return False
        # Version 0.96 prefix
        if len(data) >= 4 and data[:4] in (b"\x00\x60\x00\x00", b"\x60\x00\x00\x00"):
            return True
        # DocumentStart opcode (0x01)
        if data[0] == 0x01 and len(data) >= 3:
            second_byte = data[1]
            if second_byte in (0x00, 0x01, 0x1D, 0x1E, 0x20, 0x03, 0x14):
                return True
        return False

    @staticmethod
    def _read_7bit_int(data: bytes, offset: int) -> Tuple[int, int]:
        """Helper to read 7-bit encoded integer from data at offset."""
        count = 0
        shift = 0
        pos = offset
        while True:
            if pos >= len(data):
                raise BamlError("Unexpected EOF reading 7-bit int")
            b = data[pos]
            pos += 1
            count |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                break
            if shift >= 35:
                raise BamlError("Malformed 7-bit int")
        return count, pos
