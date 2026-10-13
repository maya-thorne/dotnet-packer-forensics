"""
Core Orchestrator for .NET Packer & PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import os
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .analysis_collector import build_analysis_report
from .dotnet_analyzer import DotNetAnalyzer
from .payload_verifier import (
    PayloadVerificationResult,
    PayloadVerifier,
)
from .pe_overlay import PEOverlayParser
from .pe_rebuilder import PERebuilder, PERebuildOptions, PERebuildReport
from .signatures import ProtectorSignatures
from .unpackers.antidump import AntiDumpUnpacker
from .unpackers.antidump_models import AntiDumpHealOptions, AntiDumpHealResult
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
from .unpackers.antitamper import AntiTamperUnpacker
from .unpackers.antitamper_jit import JITDumperInterface
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
            confuser_strings_list = DotNetPackerCore._extract_confuser_strings(data)

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

        # 12. CLI Metadata Anti-Tamper & JIT Dumper Forensics
        antitamper_detect = AntiTamperUnpacker.detect(data)

        # 13. Anti-Dump Memory PE Header & Scylla Dump Forensics
        antidump_detect = AntiDumpUnpacker.detect(data)

        # 14. PE Structural Health & Section Rebuilder Diagnostics
        pe_diag = PERebuilder.detect_anomalies(data)

        # 15. Cryptographic Hashes & Integrity Baselines
        hashes = PayloadVerifier.compute_hashes(data)

        return build_analysis_report(
            file_path=file_path,
            file_size=file_size,
            elapsed_ms=elapsed_ms,
            hashes=hashes,
            assembly_info=assembly_info,
            detected_protectors=detected_protectors,
            pe_diag=pe_diag,
            overlay_bytes=overlay_bytes,
            pe_size=pe_size,
            xor_result=xor_result,
            costura_detect=costura_detect,
            costura_payloads=costura_payloads,
            confuser_detect=confuser_detect,
            confuser_payloads=confuser_payloads,
            confuser_strings_list=confuser_strings_list,
            reactor_detect=reactor_detect,
            reactor_payloads=reactor_payloads,
            reactor_methods=reactor_methods,
            eaz_detect=eaz_detect,
            eaz_containers=eaz_containers,
            babel_detect=babel_detect,
            babel_merged=babel_merged,
            armdot_detect=armdot_detect,
            armdot_containers=armdot_containers,
            intellilock_detect=intellilock_detect,
            deepsea_detect=deepsea_detect,
            antitamper_detect=antitamper_detect,
            antidump_detect=antidump_detect,
        )


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

        # Check if AntiDump memory dump needs healing
        antidump_detect = AntiDumpUnpacker.detect(data)
        if antidump_detect["is_anti_dump"]:
            healed_pe, rep = AntiDumpUnpacker.heal_dump(data)
            if rep.get("is_healed"):
                with open(output_path, "wb") as f:
                    f.write(healed_pe)
                return True

        return False

    @classmethod
    def unpack_to_dir(cls, input_path: str, output_dir: str) -> List[Dict[str, any]]:
        """Extracts all embedded Costura, ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, DeepSea, AntiTamper, and AntiDump assemblies into target directory."""
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
        if AntiTamperUnpacker.detect(data)["is_tampered"]:
            AntiTamperUnpacker.unpack_to_directory(data, output_dir)
        if AntiDumpUnpacker.detect(data)["is_anti_dump"]:
            AntiDumpUnpacker.unpack_to_directory(data, output_dir)
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
    def _extract_confuser_strings(cls, data: bytes) -> List[str]:
        """Helper to extract and decrypt embedded ConfuserEx string constants."""
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
    def dump_strings(cls, input_path: str) -> List[str]:
        """Extracts and decrypts all embedded ConfuserEx constants and literal strings."""
        with open(input_path, "rb") as f:
            data = f.read()
        return cls._extract_confuser_strings(data)

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
    def unpack_deepsea_dir(cls, input_path: str, output_dir: str) -> Dict[str, Any]:
        """Unpacks de-flattened binary, AST JSON, and CFG diagrams to directory."""
        with open(input_path, "rb") as f:
            return DeepSeaUnpacker.unpack_to_directory(f.read(), output_dir=output_dir)

    @classmethod
    def restore_antitamper(
        cls,
        input_path: str,
        output_path: Optional[str] = None,
        jit_dump_path: Optional[str] = None,
        master_seed: int = 0x5A5A5A5A,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Restores anti-tampered assembly, repairing CIL method bodies."""
        with open(input_path, "rb") as f:
            data = f.read()
        jit_records = None
        if jit_dump_path and os.path.exists(jit_dump_path):
            with open(jit_dump_path, "r", encoding="utf-8") as f:
                jit_records = JITDumperInterface.ingest_json_dump(f.read())
        restored = AntiTamperUnpacker.decrypt_and_restore_methods(
            data, jit_records=jit_records, master_seed=master_seed
        )
        rebuilt_pe, rep = AntiTamperUnpacker.restore_assembly(data, restored)
        if output_path:
            with open(output_path, "wb") as f:
                f.write(rebuilt_pe)
        return rebuilt_pe, rep

    @classmethod
    def unpack_antitamper_dir(
        cls,
        input_path: str,
        output_dir: str,
        jit_dump_path: Optional[str] = None,
        master_seed: int = 0x5A5A5A5A,
    ) -> Dict[str, Any]:
        """Unpacks anti-tampered binary, dumped methods, and CIL files to directory."""
        with open(input_path, "rb") as f:
            return AntiTamperUnpacker.unpack_to_directory(
                f.read(), output_dir=output_dir, jit_dump_file=jit_dump_path, master_seed=master_seed
            )

    @classmethod
    def heal_anti_dump(
        cls,
        input_path: str,
        output_path: Optional[str] = None,
        options: Optional[AntiDumpHealOptions] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Heals anti-dump memory corruptions, reconstructing PE headers and CLR metadata."""
        with open(input_path, "rb") as f:
            data = f.read()
        healed_pe, rep = AntiDumpUnpacker.heal_dump(data, options=options)
        if output_path and rep.get("is_healed"):
            with open(output_path, "wb") as f:
                f.write(healed_pe)
        return healed_pe, rep

    @classmethod
    def detect_anti_dump(cls, input_path: str) -> Dict[str, Any]:
        """Detects anti-dump memory corruptions and dump layout characteristics."""
        with open(input_path, "rb") as f:
            return AntiDumpUnpacker.detect(f.read())

    @classmethod
    def unpack_anti_dump_dir(
        cls,
        input_path: str,
        output_dir: str,
        options: Optional[AntiDumpHealOptions] = None,
    ) -> Dict[str, Any]:
        """Heals dump and exports normalized binary, carved sections, and telemetry to directory."""
        with open(input_path, "rb") as f:
            return AntiDumpUnpacker.unpack_to_directory(
                f.read(), output_dir=output_dir, options=options
            )



