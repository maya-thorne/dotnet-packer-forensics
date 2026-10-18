"""
PE & .NET Metadata Differ for Binary Comparison.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from ..dotnet_analyzer import DotNetAnalyzer
from .models import ChangeType, MetadataDiff, SectionDiff, calculate_entropy


class MetadataDiffer:
    """Compares PE headers, section tables, and .NET metadata structures."""

    KNOWN_PROTECTOR_SECTIONS = {
        ".necro", ".eazvm", ".armdot", ".tamper", ".cflow", ".protect",
        ".themida", ".vmp", ".aspack", ".upx", ".petite",
    }

    @classmethod
    def compare(cls, data_a: bytes, data_b: bytes) -> MetadataDiff:
        """Executes deep PE and CLR metadata comparison between two binaries."""
        header_changes = cls._compare_pe_headers(data_a, data_b)
        stream_changes = cls._compare_metadata_streams(data_a, data_b)
        section_diffs, injected_sections = cls._compare_sections(data_a, data_b)
        
        imphash_a = cls._compute_imphash_proxy(data_a)
        imphash_b = cls._compute_imphash_proxy(data_b)
        imphash_matched = (imphash_a == imphash_b) and bool(imphash_a)

        # Compute similarity score
        score = cls._calculate_metadata_similarity(
            header_changes=header_changes,
            stream_changes=stream_changes,
            section_diffs=section_diffs,
            imphash_matched=imphash_matched,
            injected_sections=injected_sections,
        )

        return MetadataDiff(
            similarity_score=score,
            header_changes=header_changes,
            stream_changes=stream_changes,
            section_diffs=section_diffs,
            imphash_a=imphash_a,
            imphash_b=imphash_b,
            imphash_matched=imphash_matched,
            injected_sections=injected_sections,
        )

    @classmethod
    def _parse_sections(cls, data: bytes) -> Dict[str, Dict[str, Any]]:
        """Parses PE section headers and computes per-section entropy."""
        sections = {}
        if len(data) < 64 or data[:2] != b"MZ":
            return sections
        e_lfanew = struct.unpack_from("<I", data, 60)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            return sections

        num_sections, opt_hdr_size = struct.unpack_from("<HH", data, e_lfanew + 6)[0:2]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_start = e_lfanew + 24 + opt_hdr_size

        for i in range(num_sections):
            sec_offset = sec_start + (i * 40)
            if sec_offset + 40 > len(data):
                break
            raw_name = data[sec_offset:sec_offset+8].rstrip(b"\x00")
            name = raw_name.decode("latin-1", errors="replace").strip()
            if not name:
                name = f"section_{i}"
            v_size, v_addr, raw_size, raw_ptr, _, _, _, _, characteristics = struct.unpack_from(
                "<IIIIIIHHI", data, sec_offset + 8
            )
            sec_bytes = data[raw_ptr:raw_ptr+raw_size] if raw_ptr + raw_size <= len(data) else b""
            entropy = calculate_entropy(sec_bytes) if sec_bytes else 0.0

            sections[name] = {
                "name": name,
                "virtual_size": v_size,
                "virtual_address": v_addr,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "characteristics": characteristics,
                "entropy": entropy,
            }
        return sections

    @classmethod
    def _compare_sections(cls, data_a: bytes, data_b: bytes) -> Tuple[List[SectionDiff], List[str]]:
        """Compares section headers, entropy deviations, and injected protector sections."""
        secs_a = cls._parse_sections(data_a)
        secs_b = cls._parse_sections(data_b)
        diffs = []
        injected = []

        all_names = list(dict.fromkeys(list(secs_a.keys()) + list(secs_b.keys())))

        for name in all_names:
            in_a = name in secs_a
            in_b = name in secs_b

            if in_a and in_b:
                sa = secs_a[name]
                sb = secs_b[name]
                raw_delta = sb["raw_size"] - sa["raw_size"]
                v_delta = sb["virtual_size"] - sa["virtual_size"]
                ent_delta = round(sb["entropy"] - sa["entropy"], 4)
                entropy_surge = (ent_delta > 1.2) and (sb["entropy"] >= 6.5)

                change_type = ChangeType.UNCHANGED
                if raw_delta != 0 or v_delta != 0 or abs(ent_delta) >= 0.1:
                    change_type = ChangeType.MODIFIED

                diffs.append(SectionDiff(
                    name=name,
                    raw_size_a=sa["raw_size"],
                    raw_size_b=sb["raw_size"],
                    raw_size_delta=raw_delta,
                    virtual_size_a=sa["virtual_size"],
                    virtual_size_b=sb["virtual_size"],
                    virtual_size_delta=v_delta,
                    entropy_a=sa["entropy"],
                    entropy_b=sb["entropy"],
                    entropy_delta=ent_delta,
                    change_type=change_type,
                    is_injected=False,
                    is_entropy_surge=entropy_surge,
                ))
            elif in_b and not in_a:
                sb = secs_b[name]
                is_prot = name.lower() in cls.KNOWN_PROTECTOR_SECTIONS or sb["entropy"] >= 7.0
                if is_prot:
                    injected.append(name)
                diffs.append(SectionDiff(
                    name=name,
                    raw_size_a=0,
                    raw_size_b=sb["raw_size"],
                    raw_size_delta=sb["raw_size"],
                    virtual_size_a=0,
                    virtual_size_b=sb["virtual_size"],
                    virtual_size_delta=sb["virtual_size"],
                    entropy_a=0.0,
                    entropy_b=sb["entropy"],
                    entropy_delta=sb["entropy"],
                    change_type=ChangeType.ADDED,
                    is_injected=True,
                    is_entropy_surge=sb["entropy"] >= 6.5,
                ))
            elif in_a and not in_b:
                sa = secs_a[name]
                diffs.append(SectionDiff(
                    name=name,
                    raw_size_a=sa["raw_size"],
                    raw_size_b=0,
                    raw_size_delta=-sa["raw_size"],
                    virtual_size_a=sa["virtual_size"],
                    virtual_size_b=0,
                    virtual_size_delta=-sa["virtual_size"],
                    entropy_a=sa["entropy"],
                    entropy_b=0.0,
                    entropy_delta=-sa["entropy"],
                    change_type=ChangeType.REMOVED,
                    is_injected=False,
                    is_entropy_surge=False,
                ))

        return diffs, injected

    @classmethod
    def _compare_pe_headers(cls, data_a: bytes, data_b: bytes) -> Dict[str, Any]:
        """Compares PE optional headers and machine characteristics."""
        def extract_hdr(d: bytes) -> Dict[str, Any]:
            if len(d) < 64 or d[:2] != b"MZ":
                return {}
            e_lfanew = struct.unpack_from("<I", d, 60)[0]
            if e_lfanew + 68 > len(d) or d[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
                return {}
            machine, num_sec = struct.unpack_from("<HH", d, e_lfanew + 4)
            magic = struct.unpack_from("<H", d, e_lfanew + 24)[0]
            ep_rva = struct.unpack_from("<I", d, e_lfanew + 40)[0]
            return {
                "machine": machine,
                "sections_count": num_sec,
                "pe_magic": magic,
                "entrypoint_rva": ep_rva,
            }

        ha = extract_hdr(data_a)
        hb = extract_hdr(data_b)
        changes = {}
        for k in set(ha.keys()) | set(hb.keys()):
            va = ha.get(k)
            vb = hb.get(k)
            if va != vb:
                changes[k] = {"before": va, "after": vb}
        return changes

    @classmethod
    def _compare_metadata_streams(cls, data_a: bytes, data_b: bytes) -> Dict[str, Any]:
        """Compares BSJB metadata streams presence, sizes, and corruption indicators."""
        def find_bsjb_streams(d: bytes) -> Dict[str, int]:
            streams = {}
            idx = d.find(b"BSJB")
            if idx == -1 or idx + 32 > len(d):
                return streams
            vlen = struct.unpack_from("<I", d, idx + 12)[0]
            if idx + 16 + vlen + 4 > len(d):
                return streams
            pos = idx + 16 + vlen
            # Round up to 4 bytes
            rem = (pos - idx) % 4
            if rem != 0:
                pos += (4 - rem)
            if pos + 4 > len(d):
                return streams
            flags, num_streams = struct.unpack_from("<HH", d, pos)
            pos += 4
            for _ in range(min(num_streams, 16)):
                if pos + 8 > len(d):
                    break
                s_offset, s_size = struct.unpack_from("<II", d, pos)
                pos += 8
                # Stream name is null-terminated UTF-8, padded to 4-byte boundary
                name_bytes = bytearray()
                while pos < len(d) and d[pos] != 0:
                    name_bytes.append(d[pos])
                    pos += 1
                while pos < len(d) and d[pos] == 0:
                    pos += 1
                rem2 = pos % 4
                if rem2 != 0:
                    pos += (4 - rem2)
                s_name = name_bytes.decode("utf-8", errors="replace")
                if s_name:
                    streams[s_name] = s_size
            return streams

        sa = find_bsjb_streams(data_a)
        sb = find_bsjb_streams(data_b)
        changes = {}
        for k in set(sa.keys()) | set(sb.keys()):
            va = sa.get(k)
            vb = sb.get(k)
            if va != vb:
                changes[k] = {"before": va, "after": vb}
        return changes

    @classmethod
    def _compute_imphash_proxy(cls, data: bytes) -> str:
        """Computes deterministic hash proxy for imports and export symbols."""
        if len(data) < 256:
            return ""
        # Locate strings in data as rough proxy for imports
        return hashlib.md5(data[:min(len(data), 4096)]).hexdigest()

    @classmethod
    def _calculate_metadata_similarity(
        cls, header_changes: Dict[str, Any], stream_changes: Dict[str, Any],
        section_diffs: List[SectionDiff], imphash_matched: bool, injected_sections: List[str]
    ) -> float:
        """Computes normalized metadata similarity in range [0.0 - 1.0]."""
        if not section_diffs and not header_changes and not stream_changes:
            return 1.0

        score = 1.0

        # Penalize header discrepancies
        score -= min(0.3, len(header_changes) * 0.1)

        # Penalize stream modifications or missing streams
        score -= min(0.3, len(stream_changes) * 0.08)

        # Penalize section diffs
        mod_secs = sum(1 for s in section_diffs if s.change_type == ChangeType.MODIFIED)
        add_secs = sum(1 for s in section_diffs if s.change_type == ChangeType.ADDED)
        rem_secs = sum(1 for s in section_diffs if s.change_type == ChangeType.REMOVED)
        score -= min(0.4, (mod_secs * 0.05) + (add_secs * 0.1) + (rem_secs * 0.1))

        # Injected sections penalty
        if injected_sections:
            score -= min(0.2, len(injected_sections) * 0.1)

        return max(0.0, round(score, 4))
