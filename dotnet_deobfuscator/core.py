"""
Core Orchestrator for .NET Packer & PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import os
import struct
import time
from typing import Dict, List, Optional, Tuple

from .dotnet_analyzer import DotNetAnalyzer
from .pe_overlay import PEOverlayParser
from .pe_rebuilder import PERebuilder, PERebuildOptions, PERebuildReport
from .signatures import ProtectorSignatures
from .unpackers.confuserex import ConfuserExUnpacker
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

        # 5. ConfuserEx Modular Protector Inspection & String / Resource Forensics
        confuser_detect = ConfuserExUnpacker.detect(data)
        confuser_payloads = ConfuserExUnpacker.unpack(data)

        # Extract decrypted strings across CLI resources and raw streams
        confuser_strings_list: List[str] = []
        if confuser_detect["is_confuserex"]:
            res_info = ConfuserExUnpacker.parse_cli_resources_directory(data)
            if res_info is not None:
                res_offset, res_size = res_info
                curr = 0
                while curr + 4 <= res_size:
                    length = struct.unpack_from("<I", data, res_offset + curr)[0]
                    curr += 4
                    if length == 0 or curr + length > res_size:
                        break
                    chunk = data[res_offset + curr : res_offset + curr + length]
                    curr += length
                    dec_res = ConfuserExUnpacker.decrypt_constants(chunk, mode="auto")
                    if dec_res["success"] and len(dec_res["strings"]) > 0:
                        confuser_strings_list.extend(dec_res["strings"])
            if not confuser_strings_list:
                dec_res = ConfuserExUnpacker.decrypt_constants(data, mode="auto")
                confuser_strings_list = dec_res.get("strings", [])
            confuser_strings_list = list(dict.fromkeys(confuser_strings_list))

        # 6. PE Structural Health & Section Rebuilder Diagnostics
        pe_diag = PERebuilder.detect_anomalies(data)

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
            "pe_rebuilder": {
                "is_valid_pe": assembly_info["is_pe"],
                "is_memory_dump": pe_diag["is_memory_dump"],
                "anomalies_detected": pe_diag["anomalies"],
                "anomalies_count": len(pe_diag["anomalies"]),
                "repair_recommended": len(pe_diag["anomalies"]) > 0,
            },
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
            "confuserex": {
                "detected": confuser_detect["is_confuserex"],
                "confidence": confuser_detect["confidence"],
                "detected_protections": confuser_detect["detected_protections"],
                "markers_found": confuser_detect["markers_found"],
                "obfuscated_names_count": confuser_detect["obfuscated_names_count"],
                "has_antidump": confuser_detect["has_antidump"],
                "has_antitamper": confuser_detect["has_antitamper"],
                "has_constants": confuser_detect["has_constants"],
                "has_resources": confuser_detect["has_resources"],
                "decrypted_strings_count": len(confuser_strings_list),
                "decrypted_strings": confuser_strings_list[:100],
                "resources_count": len(confuser_payloads),
                "resources": [
                    {
                        "original_name": r["original_name"],
                        "output_filename": r["output_filename"],
                        "size_bytes": r["size_bytes"],
                        "sha256": r["sha256"],
                        "is_pe": r["is_pe"],
                        "resource_type": r.get("resource_type", "Binary Resource"),
                        "entropy": r["entropy"],
                    }
                    for r in confuser_payloads
                ],
            },
        }

    @classmethod
    def rebuild_pe(
        cls,
        input_path: str,
        output_path: str,
        options: Optional[PERebuildOptions] = None,
    ) -> PERebuildReport:
        """Rebuilds and repairs damaged PE headers and sections, saving output to file."""
        with open(input_path, "rb") as f:
            data = f.read()
        rebuilt_bytes, report = PERebuilder.rebuild(data, options=options)
        with open(output_path, "wb") as f:
            f.write(rebuilt_bytes)
        return report

    @classmethod
    def rebuild_pe_buffer(
        cls,
        data: bytes,
        options: Optional[PERebuildOptions] = None,
    ) -> Tuple[bytes, PERebuildReport]:
        """Rebuilds and repairs damaged PE headers and sections from byte buffer."""
        return PERebuilder.rebuild(data, options=options)

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

        # Check if single ConfuserEx payload exists
        confuser_payloads = ConfuserExUnpacker.unpack(data)
        if len(confuser_payloads) == 1:
            with open(output_path, "wb") as f:
                f.write(confuser_payloads[0]["payload_bytes"])
            return True

        return False

    @classmethod
    def unpack_to_dir(cls, input_path: str, output_dir: str) -> List[Dict[str, any]]:
        """Extracts all embedded Costura and ConfuserEx assemblies into target directory."""
        with open(input_path, "rb") as f:
            data = f.read()
        written = []
        written.extend(CosturaUnpacker.unpack_to_directory(data, output_dir))
        written.extend(ConfuserExUnpacker.unpack_to_directory(data, output_dir))
        return written

    @classmethod
    def dump_strings(cls, input_path: str) -> List[str]:
        """Extracts and decrypts all embedded ConfuserEx constants and literal strings."""
        with open(input_path, "rb") as f:
            data = f.read()

        strings: List[str] = []
        res_info = ConfuserExUnpacker.parse_cli_resources_directory(data)
        if res_info is not None:
            res_offset, res_size = res_info
            curr = 0
            while curr + 4 <= res_size:
                length = struct.unpack_from("<I", data, res_offset + curr)[0]
                curr += 4
                if length == 0 or curr + length > res_size:
                    break
                chunk = data[res_offset + curr : res_offset + curr + length]
                curr += length
                res = ConfuserExUnpacker.decrypt_constants(chunk, mode="auto")
                if res["success"] and len(res["strings"]) > 0:
                    strings.extend(res["strings"])

        if not strings:
            res = ConfuserExUnpacker.decrypt_constants(data, mode="auto")
            strings = res.get("strings", [])

        return list(dict.fromkeys(strings))
