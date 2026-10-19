"""
Single-File Host (AppHost) Unbundling Engine & Forensic Carving Orchestrator.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import struct
import time
import zlib
from typing import Any, Dict, List, Optional, Tuple

from .header_parser import BundleHeaderParser, write_dotnet_string
from .marker_scanner import BundleMarkerScanner, DOTNET_BUNDLE_MARKER
from .models import (
    BundleEntry,
    BundleExtractionResult,
    BundleFileType,
    BundleHeader,
    BundleOptions,
    BundleTelemetry,
    BundleVersion,
    SecurityError,
    SuperPackerKind,
    safe_path,
    zeroize_buffer,
)
from .virtual_volume import VirtualBundleVolume


class SingleFileBundleEngine:
    """Orchestrates detection, virtual volume mounting, carving, and safe unbundling."""

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """
        Fast inspection to determine whether data contains an AppHost bundle or superpacker.
        """
        packer_kind, meta = BundleMarkerScanner.identify_packer(data)
        is_bundle = (packer_kind == SuperPackerKind.DOTNET_APPHOST)

        version = BundleVersion.UNKNOWN
        file_count = 0
        bundle_id = ""
        is_compressed = False
        assembly_count = 0
        native_count = 0
        pdb_count = 0
        config_count = 0
        total_raw = 0
        total_comp = 0

        if is_bundle and meta["header_offset"] >= 0:
            try:
                hdr = BundleHeaderParser.parse_header(data, meta["header_offset"], meta["marker_offset"])
                file_count = hdr.file_count
                bundle_id = hdr.bundle_id
                is_compressed = hdr.is_compressed
                if hdr.major_version == 1:
                    version = BundleVersion.V1_NETCORE3
                elif hdr.major_version == 2:
                    version = BundleVersion.V2_NET5
                elif hdr.major_version >= 6:
                    version = BundleVersion.V6_NET6_PLUS

                for e in hdr.entries:
                    if e.file_type == BundleFileType.ASSEMBLY:
                        assembly_count += 1
                    elif e.file_type in (BundleFileType.NATIVE_BINARY, BundleFileType.EXTRACT_TO_DISK):
                        native_count += 1
                    elif e.file_type in (BundleFileType.PDB_FILE, BundleFileType.SYMBOLS):
                        pdb_count += 1
                    elif e.file_type in (BundleFileType.DEPS_JSON, BundleFileType.RUNTIME_CONFIG_JSON):
                        config_count += 1
                    total_raw += e.size
                    total_comp += e.compressed_size if e.is_compressed and e.compressed_size > 0 else e.size
            except Exception:
                pass

        ratio = (total_comp / total_raw) if total_raw > 0 else 1.0

        return {
            "is_bundle": is_bundle,
            "packer_kind": packer_kind.value,
            "version": version.value,
            "has_marker": meta["has_marker"],
            "marker_offset": meta["marker_offset"],
            "header_offset": meta["header_offset"],
            "file_count": file_count,
            "total_files": file_count,
            "assembly_count": assembly_count,
            "native_count": native_count,
            "pdb_count": pdb_count,
            "config_count": config_count,
            "total_uncompressed_bytes": total_raw,
            "total_compressed_bytes": total_comp,
            "overall_compression_ratio": round(ratio, 4),
            "bundle_id": bundle_id,
            "is_compressed": is_compressed,
            "has_compression": is_compressed,
            "matched_signatures": meta["matched_signatures"],
        }

    @classmethod
    def mount(cls, data: bytes, file_name: str = "app.exe") -> Optional[VirtualBundleVolume]:
        """
        Mounts the bundle as an in-memory virtual filesystem volume.
        """
        marker_info = BundleMarkerScanner.scan_dotnet_marker(data)
        if not marker_info:
            return None
        marker_off, header_off = marker_info
        hdr = BundleHeaderParser.parse_header(data, header_off, marker_off)
        return VirtualBundleVolume(header=hdr, binary_data=data)

    @classmethod
    def unbundle_bytes(
        cls,
        data: bytes,
        options: Optional[BundleOptions] = None,
        file_name: str = "app.exe",
    ) -> BundleExtractionResult:
        """
        Performs full forensic unbundling and carving on in-memory binary data.
        """
        start_time = time.perf_counter()
        opts = options or BundleOptions()
        errors: List[str] = []
        extracted_files: Dict[str, bytes] = {}

        packer_kind, meta = BundleMarkerScanner.identify_packer(data)
        if not meta["has_marker"] or meta["header_offset"] < 0:
            elapsed = round((time.perf_counter() - start_time) * 1000, 3)
            return BundleExtractionResult(
                file_name=file_name,
                is_bundle=False,
                header=None,
                entries=[],
                telemetry=BundleTelemetry(
                    is_bundle=False,
                    packer_kind=packer_kind,
                    elapsed_ms=elapsed,
                ),
                extracted_files={},
                errors=["No valid .NET bundle marker found."],
            )

        try:
            hdr = BundleHeaderParser.parse_header(data, meta["header_offset"], meta["marker_offset"])
        except Exception as e:
            elapsed = round((time.perf_counter() - start_time) * 1000, 3)
            return BundleExtractionResult(
                file_name=file_name,
                is_bundle=True,
                header=None,
                entries=[],
                telemetry=BundleTelemetry(
                    is_bundle=True,
                    packer_kind=packer_kind,
                    elapsed_ms=elapsed,
                ),
                extracted_files={},
                errors=[f"Failed to parse bundle header: {e}"],
            )

        volume = VirtualBundleVolume(header=hdr, binary_data=data)
        filtered_entries = volume.filter_entries(opts.file_filter)

        for entry in filtered_entries:
            try:
                file_bytes = volume.read_file_bytes(entry.relative_path)
                extracted_files[entry.relative_path] = file_bytes
            except Exception as e:
                errors.append(f"Failed to extract '{entry.relative_path}': {e}")

        # Compute telemetry
        summary = volume.get_summary()
        ver = BundleVersion.UNKNOWN
        if hdr.major_version == 1:
            ver = BundleVersion.V1_NETCORE3
        elif hdr.major_version == 2:
            ver = BundleVersion.V2_NET5
        elif hdr.major_version >= 6:
            ver = BundleVersion.V6_NET6_PLUS

        elapsed = round((time.perf_counter() - start_time) * 1000, 3)
        telemetry = BundleTelemetry(
            is_bundle=True,
            packer_kind=SuperPackerKind.DOTNET_APPHOST,
            version=ver,
            bundle_id=hdr.bundle_id,
            total_files=summary["total_files"],
            assembly_count=summary["assembly_count"],
            native_count=summary["native_count"],
            pdb_count=summary["pdb_count"],
            config_count=summary["config_count"],
            total_uncompressed_bytes=summary["total_uncompressed_bytes"],
            total_compressed_bytes=summary["total_compressed_bytes"],
            overall_compression_ratio=summary["compression_ratio"],
            has_compression=summary["has_compressed_files"],
            elapsed_ms=elapsed,
        )

        return BundleExtractionResult(
            file_name=file_name,
            is_bundle=True,
            header=hdr,
            entries=hdr.entries,
            telemetry=telemetry,
            extracted_files=extracted_files,
            errors=errors,
        )

    @classmethod
    def unbundle_file(
        cls,
        file_path: str,
        options: Optional[BundleOptions] = None,
    ) -> BundleExtractionResult:
        """Loads target file and unbundles contents."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Bundle file not found: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()
        return cls.unbundle_bytes(data, options=options, file_name=os.path.basename(file_path))

    @classmethod
    def export_to_directory(
        cls,
        result: BundleExtractionResult,
        output_dir: str,
    ) -> Dict[str, Any]:
        """
        Safely writes extracted bundle files and manifest to the destination directory.
        Strictly applies safe_path to defend against directory traversal.
        """
        os.makedirs(output_dir, exist_ok=True)
        written_files: List[str] = []

        for rel_path, file_data in result.extracted_files.items():
            dest = safe_path(output_dir, rel_path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(file_data)
            written_files.append(dest)

        # Write manifest file
        manifest_data = {
            "file_name": result.file_name,
            "is_bundle": result.is_bundle,
            "telemetry": result.telemetry.to_dict(),
            "extracted_count": len(written_files),
            "files": [e.to_dict() for e in result.entries],
            "errors": result.errors,
        }
        manifest_path = safe_path(output_dir, "bundle_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        written_files.append(manifest_path)

        return {
            "output_dir": output_dir,
            "extracted_count": len(result.extracted_files),
            "manifest_file": manifest_path,
            "exported_files": written_files,
            "telemetry": result.telemetry.to_dict(),
        }

    @classmethod
    def synthesize_test_bundle(
        cls,
        files: Dict[str, Tuple[bytes, BundleFileType]],
        major_version: int = 6,
        compress: bool = False,
        bundle_id: str = "test-bundle-id-12345",
        host_stub_size: int = 1024,
    ) -> bytes:
        """
        Synthesizes a realistic .NET Single-File Host executable for unit testing and fuzzing.
        """
        buf = bytearray()
        # 1. Host executable PE stub
        buf.extend(b"MZ" + b"\x00" * (host_stub_size - 2))

        # 2. File payloads
        entries: List[BundleEntry] = []
        for rel_path, (raw_data, ftype) in files.items():
            offset = len(buf)
            raw_len = len(raw_data)
            comp_len = 0
            is_comp = False

            if compress and raw_len > 0:
                compressed = zlib.compress(raw_data, level=6)
                comp_len = len(compressed)
                is_comp = True
                buf.extend(compressed)
            else:
                buf.extend(raw_data)

            entries.append(
                BundleEntry(
                    offset=offset,
                    size=raw_len,
                    compressed_size=comp_len,
                    file_type=ftype,
                    relative_path=rel_path,
                    is_compressed=is_comp,
                )
            )

        # 3. Header
        header_offset = len(buf)
        header = BundleHeader(
            major_version=major_version,
            minor_version=0,
            file_count=len(entries),
            bundle_id=bundle_id,
            deps_json_offset=0,
            deps_json_size=0,
            runtime_config_json_offset=0,
            runtime_config_json_size=0,
            flags=1 if compress else 0,
            header_offset=header_offset,
            is_compressed=compress,
            entries=entries,
        )
        serialized_hdr = BundleHeaderParser.serialize_header(header)
        buf.extend(serialized_hdr)

        # 4. 8-byte Bundle Header Offset + 32-byte Bundle Marker
        marker_offset = len(buf) + 8
        buf.extend(struct.pack("<q", header_offset))
        buf.extend(DOTNET_BUNDLE_MARKER)

        return bytes(buf)
