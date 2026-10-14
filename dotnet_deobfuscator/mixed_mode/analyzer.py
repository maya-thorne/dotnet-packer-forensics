"""
Mixed-Mode PE Forensic Analyzer & Engine.
Performs static analysis of C++/CLI assemblies, parses Cor20Header, and orchestrates boundary tracing.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Cor20Flag,
    MixedModeAnalysisResult,
    MixedModeTelemetry,
    MixedModeType,
    RiskSeverity,
    SecurityError,
    VTFixupTable,
)
from .transition_tracer import TransitionTracer
from .vtfixup_parser import VTFixupParser, zeroize_buffer


def _safe_path(base_dir: str, file_name: str) -> str:
    """Validates that destination path does not escape base directory via path traversal."""
    resolved_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(resolved_base, file_name))
    if not (target_path == resolved_base or target_path.startswith(resolved_base + os.sep)):
        raise SecurityError(f"Path traversal detected: {file_name} attempts to escape {base_dir}")
    return target_path


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0) for byte slice."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class MixedModeAnalyzer:
    """Forensic engine for analyzing mixed-mode C++/CLI binaries and CIL/native transitions."""

    @staticmethod
    def _rva_to_offset(rva: int, sec_rva_map: List[Tuple[int, int, int, int]]) -> Optional[int]:
        """Translates Relative Virtual Address (RVA) to raw file offset."""
        if rva <= 0:
            return None
        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            span = max(v_size, raw_size)
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size:
                    return raw_ptr + delta
        return None

    @classmethod
    def analyze_file(cls, file_path: str) -> MixedModeAnalysisResult:
        """Analyzes a binary file on disk."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()
        return cls.analyze(data, file_name=os.path.basename(file_path))

    @classmethod
    def analyze(cls, data: bytes, file_name: str = "binary.exe") -> MixedModeAnalysisResult:
        """Performs static forensic inspection of PE binary for mixed-mode traits."""
        sha256 = hashlib.sha256(data).hexdigest()
        file_size = len(data)

        # 1. DOS & NT Header Validation
        if len(data) < 64 or data[:2] != b"MZ":
            telemetry = MixedModeTelemetry(
                is_mixed_mode=False,
                mixed_mode_type=MixedModeType.PURE_NATIVE.value,
                confidence="NONE",
                cor20_flags=[],
                has_native_entrypoint=False,
                native_entrypoint_rva=None,
                entrypoint_token_or_rva_hex=None,
                vtfixup_tables_count=0,
                total_vtfixup_slots=0,
                from_unmanaged_slots_count=0,
                unmanaged_exports_count=0,
                bridged_exports_count=0,
                tls_callbacks_count=0,
                transitions_count=0,
                anomalies=["Not a valid PE executable (missing MZ magic)"],
                risk_score=0,
                risk_severity=RiskSeverity.INFORMATIONAL.value,
            )
            return MixedModeAnalysisResult(
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                telemetry=telemetry,
            )

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            telemetry = MixedModeTelemetry(
                is_mixed_mode=False,
                mixed_mode_type=MixedModeType.PURE_NATIVE.value,
                confidence="NONE",
                cor20_flags=[],
                has_native_entrypoint=False,
                native_entrypoint_rva=None,
                entrypoint_token_or_rva_hex=None,
                vtfixup_tables_count=0,
                total_vtfixup_slots=0,
                from_unmanaged_slots_count=0,
                unmanaged_exports_count=0,
                bridged_exports_count=0,
                tls_callbacks_count=0,
                transitions_count=0,
                anomalies=["Corrupted PE signature or invalid e_lfanew pointer"],
                risk_score=0,
                risk_severity=RiskSeverity.INFORMATIONAL.value,
            )
            return MixedModeAnalysisResult(
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                telemetry=telemetry,
            )

        # 2. NT Optional Header & Data Directories
        file_hdr_off = e_lfanew + 4
        machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, file_hdr_off
        )

        opt_hdr_off = file_hdr_off + 20
        magic = struct.unpack_from("<H", data, opt_hdr_off)[0] if opt_hdr_size >= 2 else 0
        is_pe32_plus = (magic == 0x020B)

        entry_point_rva = 0
        image_base = 0x400000
        if opt_hdr_size >= 24:
            entry_point_rva = struct.unpack_from("<I", data, opt_hdr_off + 16)[0]
        if is_pe32_plus and opt_hdr_size >= 32:
            image_base = struct.unpack_from("<Q", data, opt_hdr_off + 24)[0]
        elif not is_pe32_plus and opt_hdr_size >= 32:
            image_base = struct.unpack_from("<I", data, opt_hdr_off + 28)[0]

        # Data Directory indices:
        # 0: Export Table
        # 1: Import Table
        # 9: TLS Directory
        # 14: CLR Header (Cor20)
        dir_base = opt_hdr_off + (112 if is_pe32_plus else 96)
        export_rva, export_size = 0, 0
        tls_rva, tls_size = 0, 0
        clr_rva, clr_size = 0, 0

        if opt_hdr_size >= (112 if is_pe32_plus else 96) + 16:
            # Export (dir 0)
            export_rva, export_size = struct.unpack_from("<II", data, dir_base)
        if opt_hdr_size >= (112 if is_pe32_plus else 96) + 80:
            # TLS (dir 9)
            tls_rva, tls_size = struct.unpack_from("<II", data, dir_base + (9 * 8))
        if opt_hdr_size >= (112 if is_pe32_plus else 96) + 120:
            # CLR Cor20 (dir 14)
            clr_rva, clr_size = struct.unpack_from("<II", data, dir_base + (14 * 8))

        # 3. Parse Sections
        sections_off = opt_hdr_off + opt_hdr_size
        sec_rva_map: List[Tuple[int, int, int, int]] = []
        sections_summary: List[Dict[str, Any]] = []

        for i in range(num_sections):
            sec_entry = sections_off + (i * 40)
            if sec_entry + 40 > len(data):
                break
            raw_name = data[sec_entry : sec_entry + 8]
            sec_name = raw_name.split(b"\x00")[0].decode("latin1", errors="ignore")
            v_size, v_addr, raw_size, raw_ptr, _, _, _, _, sec_chars = struct.unpack_from(
                "<IIIIIIHHI", data, sec_entry + 8
            )
            sec_rva_map.append((v_addr, v_size, raw_ptr, raw_size))

            sec_bytes = data[raw_ptr : raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
            ent = calculate_entropy(sec_bytes)

            is_executable = bool(sec_chars & 0x20000000)
            sections_summary.append({
                "name": sec_name,
                "virtual_address": hex(v_addr),
                "virtual_size": v_size,
                "raw_size": raw_size,
                "entropy": ent,
                "is_executable": is_executable,
            })

        pe_info = {
            "is_pe32_plus": is_pe32_plus,
            "entry_point_rva": entry_point_rva,
            "image_base": image_base,
            "export_rva": export_rva,
            "export_size": export_size,
            "tls_rva": tls_rva,
            "tls_size": tls_size,
        }

        # 4. Check if CLR header exists
        if clr_rva == 0 or clr_size < 72:
            telemetry = MixedModeTelemetry(
                is_mixed_mode=False,
                mixed_mode_type=MixedModeType.PURE_NATIVE.value,
                confidence="HIGH",
                cor20_flags=[],
                has_native_entrypoint=True,
                native_entrypoint_rva=entry_point_rva,
                entrypoint_token_or_rva_hex=hex(entry_point_rva),
                vtfixup_tables_count=0,
                total_vtfixup_slots=0,
                from_unmanaged_slots_count=0,
                unmanaged_exports_count=0,
                bridged_exports_count=0,
                tls_callbacks_count=0,
                transitions_count=0,
                anomalies=["Standard native PE binary (no CLR Cor20Header)"],
                risk_score=10,
                risk_severity=RiskSeverity.INFORMATIONAL.value,
            )
            return MixedModeAnalysisResult(
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                telemetry=telemetry,
                sections_summary=sections_summary,
            )

        # 5. Parse Cor20Header (IMAGE_COR20_HEADER)
        clr_off = cls._rva_to_offset(clr_rva, sec_rva_map)
        if clr_off is None or clr_off + 72 > len(data):
            telemetry = MixedModeTelemetry(
                is_mixed_mode=False,
                mixed_mode_type=MixedModeType.CORRUPTED_OR_ANOMALOUS.value,
                confidence="LOW",
                cor20_flags=[],
                has_native_entrypoint=False,
                native_entrypoint_rva=None,
                entrypoint_token_or_rva_hex=None,
                vtfixup_tables_count=0,
                total_vtfixup_slots=0,
                from_unmanaged_slots_count=0,
                unmanaged_exports_count=0,
                bridged_exports_count=0,
                tls_callbacks_count=0,
                transitions_count=0,
                anomalies=["Cor20Header RVA points outside file bounds or corrupted"],
                risk_score=50,
                risk_severity=RiskSeverity.MEDIUM.value,
            )
            return MixedModeAnalysisResult(
                file_name=file_name,
                file_size=file_size,
                sha256=sha256,
                telemetry=telemetry,
                sections_summary=sections_summary,
            )

        (
            cb,
            major_ver,
            minor_ver,
            meta_rva,
            meta_size,
            cor_flags,
            entry_token,
            rsrc_rva,
            rsrc_size,
            sn_rva,
            sn_size,
            cm_rva,
            cm_size,
            vtfixup_rva,
            vtfixup_size,
            eat_rva,
            eat_size,
            mnh_rva,
            mnh_size,
        ) = struct.unpack_from("<IHHIIIIIIIIIIIIIIII", data, clr_off)

        # Decode Flags
        cor20_flags_list: List[str] = []
        is_ilonly = bool(cor_flags & Cor20Flag.COMIMAGE_FLAGS_ILONLY)
        if is_ilonly:
            cor20_flags_list.append("COMIMAGE_FLAGS_ILONLY")
        if cor_flags & Cor20Flag.COMIMAGE_FLAGS_32BITREQUIRED:
            cor20_flags_list.append("COMIMAGE_FLAGS_32BITREQUIRED")
        if cor_flags & Cor20Flag.COMIMAGE_FLAGS_IL_LIBRARY:
            cor20_flags_list.append("COMIMAGE_FLAGS_IL_LIBRARY")
        if cor_flags & Cor20Flag.COMIMAGE_FLAGS_STRONGNAMESIGNED:
            cor20_flags_list.append("COMIMAGE_FLAGS_STRONGNAMESIGNED")
        has_native_ep = bool(cor_flags & Cor20Flag.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
        if has_native_ep:
            cor20_flags_list.append("COMIMAGE_FLAGS_NATIVE_ENTRYPOINT")
        if cor_flags & Cor20Flag.COMIMAGE_FLAGS_TRACKDEBUGDATA:
            cor20_flags_list.append("COMIMAGE_FLAGS_TRACKDEBUGDATA")

        # 6. Parse VTFixup Tables
        vtfixup_tables: List[VTFixupTable] = []
        if vtfixup_rva > 0 and vtfixup_size >= 8:
            vtfixup_tables = VTFixupParser.parse_vtfixups(data, vtfixup_rva, vtfixup_size, sec_rva_map)

        # 7. Trace Execution Transitions
        cor20_info = {
            "has_native_entrypoint": has_native_ep,
            "native_entrypoint_rva": entry_token if has_native_ep else None,
            "entry_token": entry_token,
            "cor_flags": cor_flags,
        }

        transitions, export_bridges, tls_callbacks = TransitionTracer.trace_transitions(
            data=data,
            cor20_info=cor20_info,
            vtfixup_tables=vtfixup_tables,
            sec_rva_map=sec_rva_map,
            pe_info=pe_info,
            sections=sections_summary,
        )

        # 8. Classify Mixed-Mode Status
        has_vtfixup_entries = len(vtfixup_tables) > 0 and any(t.slot_count > 0 for t in vtfixup_tables)
        is_mixed_mode = False
        mixed_mode_type = MixedModeType.PURE_MANAGED
        confidence = "HIGH"
        anomalies: List[str] = []

        if not is_ilonly or has_native_ep or has_vtfixup_entries:
            is_mixed_mode = True
            mixed_mode_type = MixedModeType.MIXED_MODE_IJWH
            confidence = "HIGH"

            if not is_ilonly:
                anomalies.append("COMIMAGE_FLAGS_ILONLY cleared (0x0): binary executes native machine code directly")
            if has_native_ep:
                anomalies.append(f"COMIMAGE_FLAGS_NATIVE_ENTRYPOINT active: EntryPointToken holds native RVA 0x{entry_token:08X}")
            if has_vtfixup_entries:
                anomalies.append(f"VTableFixup table present ({len(vtfixup_tables)} tables): bridges native code to managed CIL methods")
        else:
            is_mixed_mode = False
            mixed_mode_type = MixedModeType.PURE_MANAGED
            confidence = "HIGH"

        if tls_callbacks:
            anomalies.append(f"Native TLS Callbacks identified ({len(tls_callbacks)} callbacks): executes native code before CLR initialization")

        bridged_count = sum(1 for b in export_bridges if b.is_vtfixup_thunk)
        if bridged_count > 0:
            anomalies.append(f"Unmanaged PE export symbols bridging to CIL tokens ({bridged_count} bridged exports)")

        total_slots = sum(t.slot_count for t in vtfixup_tables)
        from_unmanaged_slots = sum(
            sum(1 for s in t.slots if s.is_from_unmanaged) for t in vtfixup_tables
        )

        # 9. Compute Forensic Risk Score (0-100)
        risk_score = 0
        if is_mixed_mode:
            risk_score += 30
        if has_native_ep:
            risk_score += 20
        if tls_callbacks:
            risk_score += 25
        if bridged_count > 0:
            risk_score += 15
        if from_unmanaged_slots > 0:
            risk_score += 10

        # Check for executable section with high entropy
        for s in sections_summary:
            if s.get("is_executable") and s.get("entropy", 0) >= 6.8:
                risk_score += 10
                anomalies.append(f"High-entropy executable section '{s.get('name')}' ({s.get('entropy')}): potential encrypted native shellcode or packer stub")
                break

        risk_score = min(risk_score, 100)

        if risk_score >= 75:
            risk_severity = RiskSeverity.CRITICAL.value
        elif risk_score >= 50:
            risk_severity = RiskSeverity.HIGH.value
        elif risk_score >= 25:
            risk_severity = RiskSeverity.MEDIUM.value
        elif risk_score > 0:
            risk_severity = RiskSeverity.LOW.value
        else:
            risk_severity = RiskSeverity.INFORMATIONAL.value

        entry_repr = hex(entry_token) if entry_token else None

        telemetry = MixedModeTelemetry(
            is_mixed_mode=is_mixed_mode,
            mixed_mode_type=mixed_mode_type.value,
            confidence=confidence,
            cor20_flags=cor20_flags_list,
            has_native_entrypoint=has_native_ep,
            native_entrypoint_rva=entry_token if has_native_ep else None,
            entrypoint_token_or_rva_hex=entry_repr,
            vtfixup_tables_count=len(vtfixup_tables),
            total_vtfixup_slots=total_slots,
            from_unmanaged_slots_count=from_unmanaged_slots,
            unmanaged_exports_count=len(export_bridges),
            bridged_exports_count=bridged_count,
            tls_callbacks_count=len(tls_callbacks),
            transitions_count=len(transitions),
            anomalies=anomalies,
            risk_score=risk_score,
            risk_severity=risk_severity,
        )

        return MixedModeAnalysisResult(
            file_name=file_name,
            file_size=file_size,
            sha256=sha256,
            telemetry=telemetry,
            vtfixup_tables=vtfixup_tables,
            transitions=transitions,
            export_bridges=export_bridges,
            tls_callbacks=tls_callbacks,
            sections_summary=sections_summary,
        )

    @classmethod
    def export_to_directory(
        cls, result: MixedModeAnalysisResult, output_dir: str
    ) -> Dict[str, Any]:
        """Exports forensic reports, JSON manifests, and VTFixup tables to destination directory."""
        os.makedirs(output_dir, exist_ok=True)
        manifest_path = _safe_path(output_dir, "mixed_mode_manifest.json")
        transitions_path = _safe_path(output_dir, "transitions.json")
        vtfixups_path = _safe_path(output_dir, "vtfixups_report.txt")

        exported_files: List[str] = []

        # 1. Full Manifest JSON
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        exported_files.append(manifest_path)

        # 2. Transitions JSON
        transitions_dict = [t.to_dict() for t in result.transitions]
        with open(transitions_path, "w", encoding="utf-8") as f:
            json.dump(transitions_dict, f, indent=2)
        exported_files.append(transitions_path)

        # 3. VTFixups Human-Readable Text Report
        lines = [
            f"=== Mixed-Mode VTableFixup Forensic Report: {result.file_name} ===",
            f"SHA-256: {result.sha256}",
            f"Classification: {result.telemetry.mixed_mode_type} (Risk: {result.telemetry.risk_severity.upper()}, Score: {result.telemetry.risk_score}/100)",
            f"VTableFixup Tables: {result.telemetry.vtfixup_tables_count} | Total Slots: {result.telemetry.total_vtfixup_slots}",
            "",
        ]

        for tbl in result.vtfixup_tables:
            lines.append(f"[Table #{tbl.table_index}] RVA: {hex(tbl.table_rva)} | Slots: {tbl.slot_count} | Type: {tbl.fixup_type.value} | Flags: {', '.join(tbl.flags_names)}")
            for s in tbl.slots:
                lines.append(f"  - Slot {s.slot_index:03d} (RVA: {hex(s.slot_rva)}): Token {s.target_token_hex} [{s.token_type_name}] -> {s.description}")
            lines.append("")

        if result.export_bridges:
            lines.append("=== Unmanaged Export Bridges ===")
            for eb in result.export_bridges:
                thunk_tag = f" -> Bridged Token: {eb.linked_token_hex}" if eb.is_vtfixup_thunk else ""
                lines.append(f"  - Export '{eb.export_name}' (Ord {eb.ordinal}, RVA: {hex(eb.function_rva)}, Sec: {eb.section_name}){thunk_tag}")
            lines.append("")

        if result.tls_callbacks:
            lines.append("=== Native TLS Callbacks ===")
            for tc in result.tls_callbacks:
                lines.append(f"  - TLS Callback RVA: {hex(tc.callback_rva)} (Sec: {tc.section_name}, InCode: {tc.is_in_code_section})")
            lines.append("")

        with open(vtfixups_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        exported_files.append(vtfixups_path)

        return {
            "output_dir": output_dir,
            "exported_files": exported_files,
            "manifest_file": manifest_path,
            "transitions_file": transitions_path,
            "vtfixups_file": vtfixups_path,
        }
