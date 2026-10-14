"""
Forensic Native Multi-Architecture Demuxer & Safe Directory Exporter.
Engineered & Audited by Maya Thorne.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .native_demuxer_engine import NativeDemuxerEngine, zeroize_buffer
from .native_demuxer_models import (
    NativeDemuxerTelemetry,
    NativePayloadInfo,
    PlatformRouteResult,
    SecurityError,
    TargetArchitecture,
    TargetOS,
)


class NativeDemuxerUnpacker:
    """
    High-level forensic facade for discovering, extracting, and routing
    multi-architecture native binaries (x86, x64, ARM64) bundled within .NET assemblies.
    """

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """Runs fast static heuristic inspection for embedded multi-architecture native artifacts."""
        telemetry = NativeDemuxerEngine.scan_and_demux(data)
        return {
            "is_multi_arch": telemetry.is_multi_arch,
            "confidence": telemetry.confidence,
            "total_payloads": telemetry.total_payloads,
            "architectures_found": telemetry.architectures_found,
            "platforms_found": telemetry.platforms_found,
            "sources_found": telemetry.sources_found,
            "has_architecture_mismatch": telemetry.has_architecture_mismatch,
            "mismatch_count": telemetry.mismatch_count,
            "anomalies": telemetry.anomalies,
        }

    @classmethod
    def demux(cls, data: bytes) -> Tuple[NativeDemuxerTelemetry, List[NativePayloadInfo]]:
        """Extracts and verifies all embedded multi-architecture native payloads."""
        telemetry = NativeDemuxerEngine.scan_and_demux(data)
        return telemetry, telemetry.payloads

    @classmethod
    def route(
        cls,
        data: bytes,
        target_os: str = "windows",
        target_arch: str = "x64",
    ) -> Dict[str, Any]:
        """Simulates dynamic loader routing and platform resolution for given OS and architecture."""
        telemetry = NativeDemuxerEngine.scan_and_demux(data)
        route_result = NativeDemuxerEngine.route_for_platform(
            telemetry.payloads, requested_os=target_os, requested_arch=target_arch
        )
        return route_result.to_dict()

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
        target_arch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Demuxes all native multi-architecture binaries and exports them into
        organized architecture directories with a complete routing manifest.
        """
        real_target_dir = os.path.realpath(output_dir)
        os.makedirs(real_target_dir, exist_ok=True)

        telemetry, payloads = cls.demux(data)

        # Filter by requested architecture if specified
        if target_arch:
            target_arch_lower = target_arch.lower()
            payloads = [p for p in payloads if p.target_arch.value.lower() == target_arch_lower]

        extracted_files: List[Dict[str, Any]] = []

        for p in payloads:
            arch_dir_name = p.target_arch.value if p.target_arch != TargetArchitecture.UNKNOWN else "other"
            arch_dir = cls._safe_path(real_target_dir, arch_dir_name)
            os.makedirs(arch_dir, exist_ok=True)

            # Sanitize filename
            clean_filename = os.path.basename(p.name).replace("..", "_").replace("/", "_").replace("\\", "_")
            if not clean_filename:
                clean_filename = f"payload_{p.sha256[:8]}.bin"

            # Ensure proper extension
            if p.is_pe and not clean_filename.lower().endswith((".dll", ".exe")):
                clean_filename += ".dll"
            elif p.target_os == TargetOS.LINUX and not clean_filename.lower().endswith((".so", "")):
                clean_filename += ".so"

            dest_path = cls._safe_path(arch_dir, clean_filename)

            # Write carved binary
            raw_bytes = p.raw_data
            if raw_bytes:
                with open(dest_path, "wb") as f:
                    f.write(raw_bytes)
                extracted_files.append({
                    "name": clean_filename,
                    "architecture": p.target_arch.value,
                    "os": p.target_os.value,
                    "format": p.format.value,
                    "path": dest_path,
                    "size_bytes": len(raw_bytes),
                    "sha256": p.sha256,
                    "mismatch_detected": p.mismatch_detected,
                })

        # Generate routing manifest simulation for common platform targets
        routing_simulation = {
            "win-x86": NativeDemuxerEngine.route_for_platform(payloads, TargetOS.WINDOWS, TargetArchitecture.X86).to_dict(),
            "win-x64": NativeDemuxerEngine.route_for_platform(payloads, TargetOS.WINDOWS, TargetArchitecture.X64).to_dict(),
            "win-arm64": NativeDemuxerEngine.route_for_platform(payloads, TargetOS.WINDOWS, TargetArchitecture.ARM64).to_dict(),
            "linux-x64": NativeDemuxerEngine.route_for_platform(payloads, TargetOS.LINUX, TargetArchitecture.X64).to_dict(),
            "linux-arm64": NativeDemuxerEngine.route_for_platform(payloads, TargetOS.LINUX, TargetArchitecture.ARM64).to_dict(),
            "osx-arm64": NativeDemuxerEngine.route_for_platform(payloads, TargetOS.OSX, TargetArchitecture.ARM64).to_dict(),
        }

        manifest = {
            "demuxer_version": "2.3.0",
            "is_multi_arch": telemetry.is_multi_arch,
            "confidence": telemetry.confidence,
            "total_extracted": len(extracted_files),
            "architectures_present": telemetry.architectures_found,
            "platforms_present": telemetry.platforms_found,
            "anomalies": telemetry.anomalies,
            "extracted_payloads": extracted_files,
            "routing_simulation": routing_simulation,
        }

        manifest_path = cls._safe_path(real_target_dir, "routing_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return {
            "output_dir": real_target_dir,
            "total_extracted": len(extracted_files),
            "extracted_files": extracted_files,
            "manifest_path": manifest_path,
            "telemetry": telemetry.to_dict(),
        }
