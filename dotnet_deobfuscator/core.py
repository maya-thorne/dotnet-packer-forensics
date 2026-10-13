"""
Core Orchestrator for .NET Packer & PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import os
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .dotnet_analyzer import DotNetAnalyzer
from .payload_verifier import (
    PayloadVerificationResult,
    PayloadVerifier,
)
from .pe_overlay import PEOverlayParser
from .pe_rebuilder import PERebuilder, PERebuildOptions, PERebuildReport
from .signatures import ProtectorSignatures
from .unpackers.armdot import (
    ArmDotOpcodeTable,
    ArmDotUnpacker,
    ArmDotVMDisassembler,
)
from .unpackers.babel import BabelUnpacker
from .unpackers.confuserex import ConfuserExUnpacker
from .unpackers.costura import CosturaUnpacker
from .unpackers.eazfuscator import EazfuscatorUnpacker
from .unpackers.eazfuscator_vm import EazfuscatorVMDisassembler, VMOpcodeTable
from .unpackers.deepsea import DeepSeaUnpacker
from .unpackers.intellilock import IntelliLockUnpacker
from .unpackers.intellilock_models import HardwareProfile, VirtualLicense
from .unpackers.reactor import DotNetReactorUnpacker


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

        # 6. .NET Reactor & NecroBit / Native Stub Envelope Forensics
        reactor_detect = DotNetReactorUnpacker.detect(data)
        reactor_payloads = DotNetReactorUnpacker.unpack(data)
        reactor_methods = DotNetReactorUnpacker.extract_necrobit_methods(data)

        # 7. Eazfuscator.NET VM Forensics & Virtualized Method Containers
        eaz_detect = EazfuscatorUnpacker.detect(data)
        eaz_containers = EazfuscatorUnpacker.extract_vm_containers(data)

        # 8. Babel Obfuscator Cross-Assembly Forensics & Merged Assemblies
        babel_detect = BabelUnpacker.detect(data)
        babel_merged = BabelUnpacker.extract_merged_assemblies(data)

        # 9. ArmDot Method-Level Virtual Machine Forensics & Containers
        armdot_detect = ArmDotUnpacker.detect(data)
        armdot_containers = ArmDotUnpacker.extract_vm_containers(data)

        # 10. IntelliLock License Management Envelope & Hardware Locking Forensics
        intellilock_detect = IntelliLockUnpacker.detect(data)

        # 11. DeepSea Obfuscator Control Flow Flattening Forensics
        deepsea_detect = DeepSeaUnpacker.detect(data)

        # 12. PE Structural Health & Section Rebuilder Diagnostics
        pe_diag = PERebuilder.detect_anomalies(data)

        # 13. Cryptographic Hashes & Integrity Baselines
        hashes = PayloadVerifier.compute_hashes(data)

        return {
            "file": file_path,
            "size_bytes": file_size,
            "elapsed_ms": elapsed_ms,
            "sha256": hashes["sha256"],
            "hashes": hashes,
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
            "reactor": {
                "detected": reactor_detect["is_reactor"],
                "confidence": reactor_detect["confidence"],
                "is_native_envelope": reactor_detect["is_native_envelope"],
                "has_necrobit": reactor_detect["has_necrobit"],
                "markers_found": reactor_detect["markers_found"],
                "methods_count": len(reactor_methods),
                "restored_methods": [
                    {
                        "token": m["token"],
                        "header_format": m["header_format"],
                        "code_size": m["code_size"],
                        "is_valid_cil": m["is_valid_cil"],
                    }
                    for m in reactor_methods.values()
                ][:50],
                "payloads_count": len(reactor_payloads),
                "payloads": [
                    {
                        "output_filename": p["output_filename"],
                        "size_bytes": p["size_bytes"],
                        "sha256": p["sha256"],
                        "artifact_type": p["artifact_type"],
                    }
                    for p in reactor_payloads
                ],
            },
            "eazfuscator": {
                "detected": eaz_detect["is_eazfuscator"],
                "confidence": eaz_detect["confidence"],
                "has_virtual_machine": eaz_detect["has_virtual_machine"],
                "vm_method_count": eaz_detect["vm_method_count"],
                "vm_containers_count": eaz_detect["vm_containers_count"],
                "matched_markers": eaz_detect["matched_markers"],
                "containers": [
                    {
                        "offset": f"0x{c['offset']:X}",
                        "magic": c["magic"],
                        "version": c["version"],
                        "method_count": c["method_count"],
                        "tokens": [m["token_hex"] for m in c.get("methods", [])],
                    }
                    for c in eaz_containers
                ],
            },
            "babel": {
                "detected": babel_detect["is_babel"],
                "confidence": babel_detect["confidence"],
                "has_merged_assemblies": babel_detect["has_merged_assemblies"],
                "merged_assemblies_count": babel_detect["merged_assemblies_count"],
                "has_embedded_map": babel_detect["has_embedded_map"],
                "obfuscated_symbols_count": babel_detect["obfuscated_symbols_count"],
                "markers_found": babel_detect["markers_found"],
                "merged_assemblies": [
                    {
                        "original_name": m["original_name"],
                        "output_filename": m["output_filename"],
                        "size_bytes": m["size_bytes"],
                        "sha256": m["sha256"],
                        "is_pe": m["is_pe"],
                        "compression": m["compression"],
                        "entropy": m["entropy"],
                    }
                    for m in babel_merged
                ],
            },
            "armdot": {
                "detected": armdot_detect["is_armdot"],
                "confidence": armdot_detect["confidence"],
                "has_virtual_machine": armdot_detect["has_virtual_machine"],
                "vm_method_count": armdot_detect["vm_method_count"],
                "vm_containers_count": armdot_detect["vm_containers_count"],
                "matched_markers": armdot_detect["matched_markers"],
                "containers": [
                    {
                        "offset": f"0x{c['offset']:X}",
                        "magic": c["magic"],
                        "version": c["version"],
                        "method_count": c["method_count"],
                        "tokens": [m["token_hex"] for m in c.get("methods", [])],
                    }
                    for c in armdot_containers
                ],
            },
            "intellilock": {
                "detected": intellilock_detect["is_intellilock"],
                "confidence": intellilock_detect["confidence"],
                "is_enveloped": intellilock_detect["is_enveloped"],
                "has_hardware_lock": intellilock_detect["has_hardware_lock"],
                "has_trial_expiration": intellilock_detect["has_trial_expiration"],
                "markers_found": intellilock_detect["markers_found"],
                "sections_matched": intellilock_detect["sections_matched"],
            },
            "deepsea": {
                "detected": deepsea_detect["is_deepsea"],
                "confidence": deepsea_detect["confidence"],
                "matched_markers": deepsea_detect["matched_markers"],
                "switch_density": deepsea_detect["switch_density"],
                "state_var_density": deepsea_detect["state_var_density"],
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

        # Check if single .NET Reactor payload exists
        reactor_payloads = DotNetReactorUnpacker.unpack(data)
        if len(reactor_payloads) == 1:
            with open(output_path, "wb") as f:
                f.write(reactor_payloads[0]["payload_bytes"])
            return True

        # Check if Eazfuscator VM containers exist
        eaz_containers = EazfuscatorUnpacker.extract_vm_containers(data)
        if eaz_containers:
            rebuilt_pe, rep = EazfuscatorUnpacker.devirtualize_assembly(data)
            if rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0:
                with open(output_path, "wb") as f:
                    f.write(rebuilt_pe)
                return True

        # Check if single Babel merged assembly exists
        babel_merged = BabelUnpacker.extract_merged_assemblies(data)
        if len(babel_merged) == 1:
            with open(output_path, "wb") as f:
                f.write(babel_merged[0]["payload_bytes"])
            return True

        # Check if ArmDot VM containers exist
        armdot_containers = ArmDotUnpacker.extract_vm_containers(data)
        if armdot_containers:
            rebuilt_pe, rep = ArmDotUnpacker.devirtualize_assembly(data)
            if rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0:
                with open(output_path, "wb") as f:
                    f.write(rebuilt_pe)
                return True

        # Check if DeepSea flattened methods exist
        deepsea_detect = DeepSeaUnpacker.detect(data)
        if deepsea_detect["is_deepsea"]:
            rebuilt_pe, rep = DeepSeaUnpacker.deflatten_assembly(data)
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
            return True

        return False

    @classmethod
    def unpack_to_dir(cls, input_path: str, output_dir: str) -> List[Dict[str, any]]:
        """Extracts all embedded Costura, ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, and DeepSea assemblies into target directory."""
        with open(input_path, "rb") as f:
            data = f.read()
        written = []
        written.extend(CosturaUnpacker.unpack_to_directory(data, output_dir))
        written.extend(ConfuserExUnpacker.unpack_to_directory(data, output_dir))
        written.extend(DotNetReactorUnpacker.unpack_to_directory(data, output_dir))
        written.extend(EazfuscatorUnpacker.unpack_to_directory(data, output_dir))
        written.extend(BabelUnpacker.unpack_to_directory(data, output_dir))
        written.extend(ArmDotUnpacker.unpack_to_directory(data, output_dir))
        if DeepSeaUnpacker.detect(data)["is_deepsea"]:
            DeepSeaUnpacker.unpack_to_directory(data, output_dir)
        return written

    @classmethod
    def demangle_babel(
        cls,
        input_path: str,
        output_path: Optional[str] = None,
        custom_map: Optional[Union[Dict[str, str], str]] = None,
    ) -> Tuple[bytes, Dict[str, any]]:
        """Demangles Babel Obfuscator symbols and reconstructs cross-assembly dependency graph."""
        with open(input_path, "rb") as f:
            data = f.read()
        demangled_pe, rep = BabelUnpacker.demangle_assembly(data, custom_map=custom_map)
        if output_path and rep.get("success"):
            with open(output_path, "wb") as f:
                f.write(demangled_pe)
        return demangled_pe, rep

    @classmethod
    def extract_babel_assemblies(cls, input_path: str) -> List[Dict[str, any]]:
        """Carves all merged satellite assemblies embedded within Babel binary."""
        with open(input_path, "rb") as f:
            data = f.read()
        return BabelUnpacker.extract_merged_assemblies(data)

    @classmethod
    def strip_reactor_envelope(cls, input_path: str, output_path: str) -> bool:
        """Strips native wrapper envelope and writes carved managed .NET assembly to file."""
        with open(input_path, "rb") as f:
            data = f.read()
        stripped_pe, rep = DotNetReactorUnpacker.strip_native_envelope(data)
        if stripped_pe and rep.get("is_valid_managed_pe"):
            with open(output_path, "wb") as f:
                f.write(stripped_pe)
            return True
        return False

    @classmethod
    def restore_necrobit(
        cls, input_path: str, output_path: str, seed: int = 0x14725836
    ) -> Dict[str, any]:
        """Restores encrypted NecroBit CIL method bodies and writes patched assembly to file."""
        with open(input_path, "rb") as f:
            data = f.read()
        restored_pe, rep = DotNetReactorUnpacker.restore_necrobit_assembly(data, seed=seed)
        if rep.get("success") or rep.get("methods_restored_count", 0) > 0:
            with open(output_path, "wb") as f:
                f.write(restored_pe)
        return rep

    @classmethod
    def devirtualize_eazfuscator(
        cls,
        input_path: str,
        output_path: Optional[str] = None,
        custom_table: Optional[VMOpcodeTable] = None,
    ) -> Tuple[bytes, Dict[str, any]]:
        """De-virtualizes Eazfuscator.NET virtual machine methods and optionally writes restored PE to file."""
        with open(input_path, "rb") as f:
            data = f.read()
        rebuilt_pe, rep = EazfuscatorUnpacker.devirtualize_assembly(data, custom_table=custom_table)
        if output_path and (rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0):
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
        return rebuilt_pe, rep

    @classmethod
    def disassemble_eazfuscator_vm(
        cls, input_path: str, custom_table: Optional[VMOpcodeTable] = None
    ) -> List[Dict[str, any]]:
        """Disassembles all embedded Eazfuscator VM method containers to formatted assembly."""
        with open(input_path, "rb") as f:
            data = f.read()
        containers = EazfuscatorUnpacker.extract_vm_containers(data)
        disassembler = EazfuscatorVMDisassembler(opcode_table=custom_table or VMOpcodeTable())
        disassembled_methods: List[Dict[str, any]] = []
        for c in containers:
            for m in c.get("methods", []):
                instructions = disassembler.disassemble(m["bytecode"])
                disassembled_methods.append({
                    "token": m["token_hex"],
                    "instruction_count": len(instructions),
                    "disassembly": "\n".join(inst.format() for inst in instructions),
                })
        return disassembled_methods

    @classmethod
    def devirtualize_armdot(
        cls,
        input_path: str,
        output_path: Optional[str] = None,
        custom_table: Optional[ArmDotOpcodeTable] = None,
    ) -> Tuple[bytes, Dict[str, any]]:
        """De-virtualizes ArmDot virtual machine methods and optionally writes restored PE to file."""
        with open(input_path, "rb") as f:
            data = f.read()
        rebuilt_pe, rep = ArmDotUnpacker.devirtualize_assembly(data, custom_table=custom_table)
        if output_path and (rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0):
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
        return rebuilt_pe, rep

    @classmethod
    def disassemble_armdot_vm(
        cls, input_path: str, custom_table: Optional[ArmDotOpcodeTable] = None
    ) -> List[Dict[str, any]]:
        """Disassembles all embedded ArmDot VM method containers to formatted assembly."""
        with open(input_path, "rb") as f:
            data = f.read()
        containers = ArmDotUnpacker.extract_vm_containers(data)
        disassembler = ArmDotVMDisassembler(opcode_table=custom_table or ArmDotOpcodeTable())
        disassembled_methods: List[Dict[str, any]] = []
        for c in containers:
            for m in c.get("methods", []):
                instructions = disassembler.disassemble(m["bytecode"])
                disassembled_methods.append({
                    "token": m["token_hex"],
                    "instruction_count": len(instructions),
                    "disassembly": "\n".join(inst.format() for inst in instructions),
                })
        return disassembled_methods

    @classmethod
    def extract_armdot_containers(cls, input_path: str) -> List[Dict[str, any]]:
        """Carves all ArmDot virtual machine method containers embedded in the binary."""
        with open(input_path, "rb") as f:
            data = f.read()
        return ArmDotUnpacker.extract_vm_containers(data)

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

    @classmethod
    def verify_payload(
        cls,
        target_path: str,
        reference_path: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        strict_pe: bool = False,
    ) -> PayloadVerificationResult:
        """Verifies payload cryptographic hashes, bitwise parity, and PE/CLR structure."""
        return PayloadVerifier.verify_payload_file(
            target_path=target_path,
            reference_path=reference_path,
            expected_sha256=expected_sha256,
            strict_pe=strict_pe,
        )

    @classmethod
    def verify_payload_buffer(
        cls,
        data: bytes,
        reference_data: Optional[bytes] = None,
        expected_sha256: Optional[str] = None,
        strict_pe: bool = False,
    ) -> PayloadVerificationResult:
        """Verifies byte buffer cryptographic hashes, bitwise parity, and PE/CLR structure."""
        return PayloadVerifier.verify_payload_buffer(
            payload_data=data,
            reference_data=reference_data,
            expected_sha256=expected_sha256,
            strict_pe=strict_pe,
        )

    @classmethod
    def verify_directory(
        cls,
        target_dir: str,
        golden_hashes: Optional[Dict[str, str]] = None,
        strict_pe: bool = False,
    ) -> List[PayloadVerificationResult]:
        """Audits all binary payloads in a directory against hash baselines and PE constraints."""
        return PayloadVerifier.verify_directory(
            target_dir=target_dir,
            golden_hashes=golden_hashes,
            strict_pe=strict_pe,
        )

    @classmethod
    def strip_intellilock(
        cls,
        input_path: str,
        output_path: str,
        master_seed: int = 0x14725836,
    ) -> Dict[str, Any]:
        """Neutralizes IntelliLock license envelope, restoring clean assembly."""
        with open(input_path, "rb") as f:
            data = f.read()
        unlocked_bin, meta, lic = IntelliLockUnpacker.neutralize_license_envelope(
            data, master_seed=master_seed
        )
        with open(output_path, "wb") as f:
            f.write(unlocked_bin)
        return {
            "unlocked_file": output_path,
            "size_bytes": len(unlocked_bin),
            "metadata": meta.to_dict(),
            "license": lic.to_dict(),
        }

    @classmethod
    def bypass_intellilock_hwlock(
        cls, hardware_id: str = "*"
    ) -> VirtualLicense:
        """Synthesizes matching VirtualLicense to bypass hardware locking."""
        return VirtualLicense.generate_unlimited_license(hardware_id=hardware_id)

    @classmethod
    def unpack_intellilock_dir(
        cls,
        input_path: str,
        output_dir: str,
        master_seed: int = 0x14725836,
    ) -> Dict[str, Any]:
        """Unpacks neutralized binary, synthetic license, and manifest to directory."""
        with open(input_path, "rb") as f:
            data = f.read()
        return IntelliLockUnpacker.unpack_to_directory(
            data, output_dir=output_dir, master_seed=master_seed
        )

    @classmethod
    def deflatten_deepsea(
        cls,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """De-flattens DeepSea obfuscated assembly and writes output PE if specified."""
        with open(input_path, "rb") as f:
            data = f.read()
        rebuilt_pe, rep = DeepSeaUnpacker.deflatten_assembly(data)
        if output_path:
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
        return rebuilt_pe, rep

    @classmethod
    def deflatten_deepsea_method(
        cls, bytecode: bytes, method_name: str = "Method"
    ) -> Dict[str, Any]:
        """De-flattens a single CIL method bytecode stream and reconstructs AST."""
        return DeepSeaUnpacker.deflatten_method(bytecode, method_name=method_name)

    @classmethod
    def unpack_deepsea_dir(
        cls, input_path: str, output_dir: str
    ) -> Dict[str, Any]:
        """Unpacks de-flattened binary, AST JSON, and CFG diagrams to directory."""
        with open(input_path, "rb") as f:
            data = f.read()
        return DeepSeaUnpacker.unpack_to_directory(data, output_dir=output_dir)

