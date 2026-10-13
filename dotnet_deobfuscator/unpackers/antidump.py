"""
Forensic Anti-Dump Unpacker & Safe Directory Exporter.
Engineered & Audited by Maya Thorne.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .antidump_healer import AntiDumpHealer
from .antidump_models import (
    AntiDumpHealOptions,
    AntiDumpHealResult,
    AntiDumpTelemetry,
    SecurityError,
)


class AntiDumpUnpacker:
    """
    High-level forensic unpacker facade for detecting and neutralizing anti-dump
    protections and exporting normalized binaries to disk.
    """

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """Runs heuristic anti-dump and process memory dump detection."""
        telemetry = AntiDumpHealer.detect(data)
        return {
            "is_anti_dump": telemetry.is_anti_dump_detected,
            "confidence": telemetry.confidence,
            "dump_source": telemetry.dump_source.value,
            "detected_techniques": [t.value for t in telemetry.detected_techniques],
            "original_header_intact": telemetry.original_header_intact,
            "bsjb_found": telemetry.bsjb_metadata_found,
            "bsjb_rva": f"0x{telemetry.bsjb_rva:X}" if telemetry.bsjb_rva is not None else None,
            "cor20_recovered": telemetry.cor20_recovered,
            "anomalies": telemetry.anomalies,
        }

    @classmethod
    def heal_dump(
        cls, data: bytes, options: Optional[AntiDumpHealOptions] = None
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Restores and normalizes damaged memory dump into clean standalone PE executable."""
        healed_bytes, result = AntiDumpHealer.heal_dump(data, options=options)
        return healed_bytes, result.to_dict()

    @classmethod
    def _safe_path(cls, base_dir: str, subpath: str) -> str:
        """Resolves target path and enforces strict confinement within base_dir."""
        real_base = os.path.realpath(base_dir)
        target = os.path.realpath(os.path.join(real_base, subpath))
        if not target.startswith(real_base + os.sep) and target != real_base:
            raise SecurityError(f"Path traversal detected: {target} escapes {real_base}")
        return target

    @classmethod
    def unpack_to_directory(
        cls,
        data: bytes,
        output_dir: str,
        options: Optional[AntiDumpHealOptions] = None,
    ) -> Dict[str, Any]:
        """
        Heals process dump and safely exports restored binary, carved sections,
        telemetry, and import maps to disk.
        """
        # Strict directory path traversal defense
        real_target_dir = os.path.realpath(output_dir)
        os.makedirs(real_target_dir, exist_ok=True)

        healed_bytes, result = AntiDumpHealer.heal_dump(data, options=options)
        exported_files: List[str] = []

        # 1. Write healed binary
        ext = ".dll" if any(s.name == ".reloc" for s in result.sections) and b"_CorDllMain" in healed_bytes else ".exe"
        bin_name = f"healed_dump{ext}"
        bin_path = cls._safe_path(real_target_dir, bin_name)

        with open(bin_path, "wb") as f:
            f.write(healed_bytes)
        exported_files.append(bin_name)
        result.output_path = bin_path

        # 2. Export individual sections for deep inspection
        sections_dir = cls._safe_path(real_target_dir, "sections")
        os.makedirs(sections_dir, exist_ok=True)

        for sec in result.sections:
            clean_sec_name = "".join(c for c in sec.name if c.isalnum() or c in (".", "_", "-")).strip()
            if not clean_sec_name:
                clean_sec_name = "section"
            sec_file = f"{clean_sec_name}.bin"
            sec_path = cls._safe_path(sections_dir, sec_file)

            if sec.raw_ptr + sec.raw_size <= len(healed_bytes):
                chunk = healed_bytes[sec.raw_ptr : sec.raw_ptr + sec.raw_size]
                with open(sec_path, "wb") as f:
                    f.write(chunk)
                exported_files.append(f"sections/{sec_file}")

        # 3. Export telemetry manifest
        manifest_path = cls._safe_path(real_target_dir, "antidump_telemetry.json")

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        exported_files.append("antidump_telemetry.json")

        # 4. Export synthesized import report if applicable
        if result.synthesized_import:
            import_path = cls._safe_path(real_target_dir, "scylla_import_report.json")

            with open(import_path, "w", encoding="utf-8") as f:
                json.dump(result.synthesized_import.to_dict(), f, indent=2)
            exported_files.append("scylla_import_report.json")


        return {
            "output_dir": real_target_dir,
            "exported_files": exported_files,
            "result": result.to_dict(),
        }
