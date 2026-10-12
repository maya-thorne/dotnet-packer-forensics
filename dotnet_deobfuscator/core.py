"""
Core Orchestrator for .NET Packer & PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import os
import time
from typing import Dict, List, Optional

from .dotnet_analyzer import DotNetAnalyzer
from .pe_overlay import PEOverlayParser
from .signatures import ProtectorSignatures
from .unpackers.costura import CosturaUnpacker


class DotNetPackerCore:
    """High-level forensic orchestrator for .NET and PE packer analysis."""

    @staticmethod
    def analyze_file(file_path: str, master_key: str = "randomkey") -> Dict[str, any]:
        """Runs full static analysis on binary file and attempts automatic unpacking."""
        start_time = time.perf_counter()
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target binary not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
        file_size = len(data)

        # 1. Structural Assembly Analysis
        assembly_info = DotNetAnalyzer.inspect_assembly(data)

        # 2. Protector Signature Matching
        detected_protectors = ProtectorSignatures.identify(data)

        # 3. PE Overlay Detection & xorPacker Decryption
        pe_size = PEOverlayParser.calculate_pe_size(data)
        overlay_bytes = PEOverlayParser.extract_overlay(data)
        xor_result = PEOverlayParser.decrypt_xor_packer(data, master_key=master_key)

        # 4. Costura Embedded Assembly Inspection
        costura_detect = CosturaUnpacker.detect(data)
        costura_payloads = CosturaUnpacker.unpack(data)

        return {
            "file": file_path,
            "size_bytes": file_size,
            "elapsed_ms": elapsed_ms,
            "is_pe": assembly_info["is_pe"],
            "is_dotnet": assembly_info["is_dotnet"],
            "entropy": assembly_info["entropy"],
            "sections": assembly_info["sections"],
            "metadata_streams": assembly_info["metadata_streams"],
            "suspicious_indicators": assembly_info["suspicious_indicators"],
            "detected_protectors": detected_protectors,
            "overlay": {
                "has_overlay": len(overlay_bytes) > 0,
                "overlay_size_bytes": len(overlay_bytes),
                "pe_virtual_size": pe_size,
            },
            "unpacked_payload": {
                "success": xor_result is not None,
                "details": (
                    {
                        "sentinel_offset": xor_result["sentinel_offset"],
                        "dynamic_key": xor_result["dynamic_key_recovered"],
                        "payload_size": len(xor_result["decrypted_payload_bytes"]),
                        "is_valid_pe": xor_result["is_valid_pe"],
                    }
                    if xor_result
                    else None
                ),
            },
            "costura": {
                "detected": costura_detect["is_costura"],
                "confidence": costura_detect["confidence"],
                "payloads_count": len(costura_payloads),
                "payloads": [
                    {
                        "original_name": p["original_name"],
                        "output_filename": p["output_filename"],
                        "compressed_size_bytes": p["compressed_size_bytes"],
                        "size_bytes": p["size_bytes"],
                        "sha256": p["sha256"],
                        "is_pe": p["is_pe"],
                        "is_pdb": p["is_pdb"],
                        "entropy": p["entropy"],
                    }
                    for p in costura_payloads
                ],
            },
        }

    @classmethod
    def unpack_to_file(
        cls, input_path: str, output_path: str, master_key: str = "randomkey"
    ) -> bool:
        """Extracts and writes decrypted payload to disk."""
        with open(input_path, "rb") as f:
            data = f.read()

        xor_result = PEOverlayParser.decrypt_xor_packer(data, master_key=master_key)
        if xor_result:
            with open(output_path, "wb") as f:
                f.write(xor_result["decrypted_payload_bytes"])
            return True

        # Check if single Costura payload exists
        costura_payloads = CosturaUnpacker.unpack(data)
        if len(costura_payloads) == 1:
            with open(output_path, "wb") as f:
                f.write(costura_payloads[0]["payload_bytes"])
            return True

        return False

    @classmethod
    def unpack_to_dir(cls, input_path: str, output_dir: str) -> List[Dict[str, any]]:
        """Extracts all embedded Costura assemblies into target directory."""
        with open(input_path, "rb") as f:
            data = f.read()
        return CosturaUnpacker.unpack_to_directory(data, output_dir)
