"""
High-Level Forensic Orchestrator and Safe Artifact Exporter for Kernel Memory Dump Carving.
Engineered & Audited by Maya Thorne.
"""

import json
import os
from typing import Any, Dict, List, Optional

from .bsjb_carver import BSJBCarver
from .method_carver import MethodCarver
from .minidump_parser import MinidumpParser
from .models import (
    CarverAnomalyFlag,
    CarvedAssembly,
    CarvedMethod,
    CarvedString,
    DumpCarverResult,
    DumpCarverTelemetry,
    DumpFormat,
    MemoryRange,
    SecurityError,
    safe_path,
    zeroize_buffer,
)
from .reconstructor import AssemblyReconstructor


class KernelDumpCarver:
    """
    High-level forensic analyzer for Windows Minidumps (MDMP), kernel crash dumps,
    and process memory snapshots. Carves residual CIL metadata, assemblies, and strings.
    """

    @classmethod
    def analyze_file(
        cls,
        file_path: str,
        min_confidence: float = 0.5,
        max_methods: int = 100,
    ) -> DumpCarverResult:
        """Reads dump file from disk and performs full forensic carving."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target dump file not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        file_name = os.path.basename(file_path)
        return cls.analyze(
            data,
            file_name=file_name,
            min_confidence=min_confidence,
            max_methods=max_methods,
        )

    @classmethod
    def analyze(
        cls,
        data: bytes,
        file_name: str = "memory.dmp",
        min_confidence: float = 0.5,
        max_methods: int = 100,
    ) -> DumpCarverResult:
        """
        Executes forensic carving across in-memory dump buffer.
        """
        dump_size = len(data)
        fmt = MinidumpParser.identify_format(data)

        memory_ranges: List[MemoryRange] = []
        modules: List[Dict[str, Any]] = []
        system_info: Dict[str, Any] = {}

        if fmt == DumpFormat.MINIDUMP_MDMP:
            memory_ranges, modules, system_info = MinidumpParser.parse_minidump(data)
        else:
            memory_ranges = MinidumpParser.extract_linear_ranges(data)

        # Scan for BSJB metadata roots across memory
        bsjb_offsets = BSJBCarver.scan_bsjb_roots(data)

        carved_assemblies: List[CarvedAssembly] = []
        all_methods: List[CarvedMethod] = []
        all_strings: List[CarvedString] = []
        anomalies: List[str] = []

        # If no BSJB found in minidump
        if not bsjb_offsets:
            anomalies.append("No ECMA-335 BSJB metadata signatures found in memory dump")
        else:
            for b_off in bsjb_offsets:
                bsjb_info = BSJBCarver.parse_bsjb_header(data, b_off)
                if not bsjb_info:
                    anomalies.append(f"{CarverAnomalyFlag.TRUNCATED_BSJB_STREAM.value}: at offset {hex(b_off)}")
                    continue

                streams = bsjb_info.get("streams", {})

                # Extract #US strings
                if "#US" in streams:
                    us_desc = streams["#US"]
                    us_strings = BSJBCarver.extract_user_strings(
                        data, us_desc["offset"], us_desc["size"]
                    )
                    all_strings.extend(us_strings)

                # Extract #Strings identifiers
                if "#Strings" in streams:
                    str_desc = streams["#Strings"]
                    id_strings = BSJBCarver.extract_identifier_strings(
                        data, str_desc["offset"], str_desc["size"]
                    )
                    all_strings.extend(id_strings)

                # Carve residual CIL methods around BSJB or within memory range
                methods_near = MethodCarver.scan_methods(
                    data,
                    search_start=max(0, b_off - 65536),
                    search_end=min(len(data), b_off + 256 * 1024),
                    max_methods=max_methods - len(all_methods),
                )
                all_methods.extend(methods_near)

                # Reconstruct viable assembly
                assembly = AssemblyReconstructor.reconstruct_from_memory(
                    dump_data=data,
                    bsjb_offset=b_off,
                    bsjb_info=bsjb_info,
                    methods=methods_near,
                )
                if assembly and assembly.confidence >= min_confidence:
                    carved_assemblies.append(assembly)

        # General anomaly checks
        if fmt == DumpFormat.MINIDUMP_MDMP and len(memory_ranges) > 1:
            for i in range(len(memory_ranges) - 1):
                gap = memory_ranges[i + 1].start_va - (memory_ranges[i].start_va + memory_ranges[i].size)
                if gap > 100 * 1024 * 1024:  # > 100MB gap
                    anomalies.append(
                        f"{CarverAnomalyFlag.SUSPICIOUS_MEMORY_GAP.value}: {gap // (1024 * 1024)}MB gap between descriptors"
                    )
                    break

        if bsjb_offsets and not carved_assemblies:
            anomalies.append(CarverAnomalyFlag.ORPHANED_METHOD_BODIES.value)

        telemetry = DumpCarverTelemetry(
            dump_format=fmt.value,
            dump_size=dump_size,
            memory_ranges_scanned=len(memory_ranges),
            modules_detected=len(modules),
            bsjb_roots_found=len(bsjb_offsets),
            assemblies_carved=len(carved_assemblies),
            methods_recovered=len(all_methods),
            strings_recovered=len(all_strings),
            anomaly_flags=anomalies,
        )

        return DumpCarverResult(
            file_name=file_name,
            telemetry=telemetry,
            carved_assemblies=carved_assemblies,
            residual_methods=all_methods,
            carved_strings=all_strings,
            anomalies=anomalies,
        )

    @classmethod
    def export_to_directory(
        cls, result: DumpCarverResult, output_dir: str
    ) -> Dict[str, Any]:
        """
        Safely exports carved assemblies, residual method JSON, strings, and telemetry
        to output directory with path traversal defenses.
        """
        os.makedirs(output_dir, exist_ok=True)
        exported_files: List[str] = []

        # 1. summary.json
        summary_path = safe_path(output_dir, "summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        exported_files.append(summary_path)

        # 2. carved_assemblies/
        if result.carved_assemblies:
            assemblies_dir = safe_path(output_dir, "carved_assemblies")
            os.makedirs(assemblies_dir, exist_ok=True)
            for idx, asm in enumerate(result.carved_assemblies):
                fn = f"{asm.identifier}.exe" if asm.is_pe_valid else f"{asm.identifier}.bin"
                asm_path = safe_path(assemblies_dir, fn)
                with open(asm_path, "wb") as f:
                    f.write(asm.raw_data)
                exported_files.append(asm_path)

        # 3. residual_methods.json
        if result.residual_methods:
            methods_path = safe_path(output_dir, "residual_methods.json")
            with open(methods_path, "w", encoding="utf-8") as f:
                json.dump([m.to_dict() for m in result.residual_methods], f, indent=2)
            exported_files.append(methods_path)

        # 4. extracted_strings.txt
        if result.carved_strings:
            strings_path = safe_path(output_dir, "extracted_strings.txt")
            with open(strings_path, "w", encoding="utf-8") as f:
                for s in result.carved_strings:
                    f.write(f"[{s.heap} @ {hex(s.offset)}] {s.value}\n")
            exported_files.append(strings_path)

        return {
            "output_directory": output_dir,
            "exported_files": exported_files,
            "assemblies_exported": len(result.carved_assemblies),
            "methods_exported": len(result.residual_methods),
            "strings_exported": len(result.carved_strings),
        }
