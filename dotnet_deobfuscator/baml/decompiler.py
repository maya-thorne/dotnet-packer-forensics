"""
High-Level WPF BAML Decompiler & Safe Multi-Stream Exporter.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    BamlDecompileStatus,
    BamlElement,
    BamlError,
    BamlExtractionResult,
    BamlTelemetry,
    DecompiledXaml,
    ResourceSourceType,
    SecurityError,
    zeroize_buffer,
)
from .reader import BamlBinaryReader
from .resource_extractor import BamlResourceExtractor
from .xml_emitter import XamlEmitter


def _safe_path(base_dir: str, file_name: str) -> str:
    """Enforces strict directory boundary containment preventing path traversal vulnerabilities."""
    resolved_base = os.path.realpath(base_dir)
    target_path = os.path.realpath(os.path.join(resolved_base, file_name))
    if not (target_path == resolved_base or target_path.startswith(resolved_base + os.sep)):
        raise SecurityError(
            f"Path traversal detected: '{file_name}' attempts to escape destination '{base_dir}'"
        )
    return target_path


class BamlDecompiler:
    """Forensic orchestrator for extracting BAML UI streams and decompiling to clean XAML."""

    MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB maximum safety limit

    @classmethod
    def decompile_stream(
        cls,
        data: bytes,
        resource_name: str = "resource.baml",
    ) -> DecompiledXaml:
        """Decompiles a single BAML byte buffer to valid, formatted XAML markup."""
        sha256 = hashlib.sha256(data).hexdigest()
        raw_size = len(data)

        reader = BamlBinaryReader(data)
        root, status = reader.parse()

        # Anomaly detection
        anomalies = BamlResourceExtractor.detect_anomalies(root, data)
        for warn in reader.parse_warnings:
            anomalies.append(f"parser_warning: {warn}")

        # XAML emission
        emitter = XamlEmitter(indent_size=2)
        xaml_content = emitter.emit(root) if root else "<UserControl />\n"
        is_valid_xml = emitter.validate_xml(xaml_content)

        element_count = root.count_nodes() if root else 0
        property_count = len(root.attributes) if root else 0
        root_tag = root.tag_name if root else "Unknown"

        return DecompiledXaml(
            resource_name=resource_name,
            xaml_content=xaml_content,
            status=status,
            root_tag=root_tag,
            element_count=element_count,
            property_count=property_count,
            anomalies=anomalies,
            raw_size=raw_size,
            decompiled_size=len(xaml_content.encode("utf-8")),
            sha256=sha256,
            is_valid_xml=is_valid_xml,
        )

    @classmethod
    def decompile_assembly_data(
        cls,
        data: bytes,
        file_name: str = "assembly.exe",
    ) -> BamlExtractionResult:
        """Extracts and decompiles all embedded BAML streams within an assembly buffer."""
        start_time = time.perf_counter()
        file_size = len(data)

        # 1. Extract all BAML streams
        streams = BamlResourceExtractor.extract_all(data, source_name=file_name)
        source_type = ResourceSourceType.RAW_BAML_STREAM
        if streams:
            source_type = streams[0][2]

        decompiled_items: List[DecompiledXaml] = []
        telemetry = BamlTelemetry()
        suspicious_findings: List[str] = []

        telemetry.total_baml_streams = len(streams)

        # 2. Decompile each extracted stream
        for stream_name, stream_bytes, _ in streams:
            try:
                dec = cls.decompile_stream(stream_bytes, resource_name=stream_name)
                decompiled_items.append(dec)

                if dec.status == BamlDecompileStatus.SUCCESS:
                    telemetry.successful_decompiles += 1
                elif dec.status == BamlDecompileStatus.PARTIAL:
                    telemetry.partial_decompiles += 1
                else:
                    telemetry.failed_decompiles += 1

                telemetry.total_elements += dec.element_count
                telemetry.total_attributes += dec.property_count

                if dec.anomalies:
                    telemetry.total_anomalies += len(dec.anomalies)
                    for anom in dec.anomalies:
                        suspicious_findings.append(f"[{stream_name}] {anom}")
                        anom_key = anom.split(":")[0].strip()
                        telemetry.anomaly_types[anom_key] = (
                            telemetry.anomaly_types.get(anom_key, 0) + 1
                        )

            except Exception as e:
                telemetry.failed_decompiles += 1
                suspicious_findings.append(
                    f"[{stream_name}] Decompile exception: {str(e)}"
                )

        telemetry.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return BamlExtractionResult(
            file_name=file_name,
            file_size=file_size,
            source_type=source_type,
            decompiled_items=decompiled_items,
            telemetry=telemetry,
            suspicious_findings=suspicious_findings,
        )

    @classmethod
    def decompile_file(cls, file_path: str) -> BamlExtractionResult:
        """Reads executable file from disk and executes full BAML UI forensic extraction."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target binary not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size > cls.MAX_FILE_SIZE:
            raise ValueError(
                f"File size {file_size} exceeds maximum limit ({cls.MAX_FILE_SIZE} bytes)"
            )

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.decompile_assembly_data(data, file_name=os.path.basename(file_path))

    @classmethod
    def export_to_directory(
        cls,
        result: BamlExtractionResult,
        output_dir: str,
        export_raw_baml: bool = False,
    ) -> Dict[str, Any]:
        """Safely exports decompiled XAML documents and structured forensic manifests to disk."""
        os.makedirs(output_dir, exist_ok=True)
        exported_files: List[str] = []

        manifest: Dict[str, Any] = {
            "source_file": result.file_name,
            "file_size": result.file_size,
            "source_type": result.source_type.value,
            "telemetry": result.telemetry.to_dict(),
            "suspicious_findings": result.suspicious_findings,
            "documents": [],
        }

        for item in result.decompiled_items:
            # Generate clean output filename: e.g. mainwindow.baml -> mainwindow.xaml
            base_name = os.path.basename(item.resource_name)
            if base_name.lower().endswith(".baml"):
                base_name = base_name[:-5]
            if not base_name.endswith(".xaml"):
                base_name += ".xaml"

            xaml_file_path = _safe_path(output_dir, base_name)
            with open(xaml_file_path, "w", encoding="utf-8") as f:
                f.write(item.xaml_content)
            exported_files.append(xaml_file_path)

            doc_entry = item.to_dict()
            doc_entry["exported_xaml_path"] = xaml_file_path
            manifest["documents"].append(doc_entry)

        # Write manifest JSON
        manifest_path = _safe_path(output_dir, "baml_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        exported_files.append(manifest_path)

        return {
            "success": True,
            "output_dir": output_dir,
            "exported_files": exported_files,
            "total_documents": len(result.decompiled_items),
            "manifest_file": manifest_path,
        }
