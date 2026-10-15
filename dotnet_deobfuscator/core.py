"""
Core Orchestrator for .NET Packer & PE Forensics.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import os
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .fuzzing import (
    FuzzCampaignResult,
    FuzzTarget,
    MutationStrategy,
    RegressionFuzzingHarness,
    SyntheticMutatedBinaryGenerator,
)
from .analysis_collector import build_analysis_report
from .dotnet_analyzer import DotNetAnalyzer
from .payload_verifier import PayloadVerificationResult, PayloadVerifier
from .pe_overlay import PEOverlayParser
from .pe_rebuilder import PERebuilder, PERebuildOptions, PERebuildReport
from .signatures import ProtectorSignatures
from .unpackers.antidump import AntiDumpUnpacker
from .unpackers.antidump_models import AntiDumpHealOptions, AntiDumpHealResult
from .unpackers.native_demuxer import NativeDemuxerUnpacker
from .rules import RuleFormat, RuleGranularity, RuleGenerationResult, ThreatRuleEngine
from .mixed_mode import MixedModeAnalyzer, MixedModeAnalysisResult
from .cfg import CFGAnalyzer, CFGAnalysisResult, MethodCFG
from .baml import BamlDecompiler, BamlExtractionResult
from .unpacker_dispatcher import unpack_payload_to_file, unpack_all_to_dir
from .unpackers.armdot import ArmDotOpcodeTable, ArmDotUnpacker, ArmDotVMDisassembler
from .unpackers.babel import BabelUnpacker
from .unpackers.confuserex import ConfuserExUnpacker
from .unpackers.costura import CosturaUnpacker
from .unpackers.eazfuscator import EazfuscatorUnpacker, EazfuscatorVMDisassembler, VMOpcodeTable
from .unpackers.antitamper import AntiTamperUnpacker, JITDumperInterface
from .unpackers.deepsea import DeepSeaUnpacker
from .unpackers.intellilock import IntelliLockUnpacker, HardwareProfile, VirtualLicense
from .unpackers.reactor import DotNetReactorUnpacker


class DotNetPackerCore:
    """High-level forensic orchestrator for .NET and PE packer analysis."""

    @classmethod
    def analyze_file(cls, file_path: str, master_key: str = "randomkey") -> Dict[str, Any]:
        """Runs full static analysis on binary file and attempts automatic unpacking."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target binary not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.analyze_bytes(data, master_key=master_key, file_name=os.path.basename(file_path))

    @classmethod
    def analyze_bytes(
        cls,
        data: bytes,
        master_key: str = "randomkey",
        file_name: str = "target.exe",
    ) -> Dict[str, Any]:
        """Runs full static analysis on in-memory binary buffer and attempts automatic unpacking."""
        start_time = time.perf_counter()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
        file_size = len(data)

        # 1. Structural Assembly Analysis & Protector Signatures
        assembly_info = DotNetAnalyzer.inspect_assembly(data)
        detected_protectors = ProtectorSignatures.identify(data)

        # 2. PE Overlay Detection & xorPacker Decryption
        pe_size = PEOverlayParser.calculate_pe_size(data)
        overlay_bytes = PEOverlayParser.extract_overlay(data)
        xor_result = PEOverlayParser.decrypt_xor_packer(data, master_key=master_key)

        # 3. Costura & ConfuserEx Forensics
        costura_detect = CosturaUnpacker.detect(data)
        costura_payloads = CosturaUnpacker.unpack(data)
        confuser_detect = ConfuserExUnpacker.detect(data)
        confuser_payloads = ConfuserExUnpacker.unpack(data)
        confuser_strings_list: List[str] = []
        if confuser_detect["is_confuserex"]:
            confuser_strings_list = DotNetPackerCore._extract_confuser_strings(data)

        # 4. .NET Reactor, Eazfuscator, Babel & ArmDot Virtual Machine Forensics
        reactor_detect = DotNetReactorUnpacker.detect(data)
        reactor_payloads = DotNetReactorUnpacker.unpack(data)
        reactor_methods = DotNetReactorUnpacker.extract_necrobit_methods(data)
        eaz_detect = EazfuscatorUnpacker.detect(data)
        eaz_containers = EazfuscatorUnpacker.extract_vm_containers(data)
        babel_detect = BabelUnpacker.detect(data)
        babel_merged = BabelUnpacker.extract_merged_assemblies(data)
        armdot_detect = ArmDotUnpacker.detect(data)
        armdot_containers = ArmDotUnpacker.extract_vm_containers(data)

        # 5. IntelliLock, DeepSea, Anti-Tamper, Anti-Dump & Native Demuxer
        intellilock_detect = IntelliLockUnpacker.detect(data)
        deepsea_detect = DeepSeaUnpacker.detect(data)
        antitamper_detect = AntiTamperUnpacker.detect(data)
        antidump_detect = AntiDumpUnpacker.detect(data)
        native_demux_detect = NativeDemuxerUnpacker.detect(data)
        _, native_demux_payload_objs = NativeDemuxerUnpacker.demux(data)
        native_demux_payloads = [p.to_dict() for p in native_demux_payload_objs]

        # 6. PE Structural Health & Integrity Baselines
        pe_diag = PERebuilder.detect_anomalies(data)
        hashes = PayloadVerifier.compute_hashes(data)

        # 17. Automated Threat Hunting Rule Synthesis (Behavioral Baseline)
        threat_rules_res = ThreatRuleEngine.synthesize_from_bytes(
            data, file_name=file_name, granularity=RuleGranularity.BEHAVIORAL
        )
        threat_rules_telemetry = {
            "synthesized": True,
            "granularity": threat_rules_res.granularity.value,
            "yara_count": len(threat_rules_res.yara_rules),
            "sigma_count": len(threat_rules_res.sigma_rules),
            "yara_rules": [r.rule_name for r in threat_rules_res.yara_rules],
            "sigma_rules": [s.title for s in threat_rules_res.sigma_rules],
        }

        # 18. Native Mixed-Mode PE Forensics & CIL-Native Transition Tracer
        mixed_mode_res = MixedModeAnalyzer.analyze(data, file_name=file_name)
        mixed_mode_telemetry = mixed_mode_res.telemetry.to_dict()

        # 19. CIL Control Flow Graph (CFG) & High-Entropy Block Diagnostics
        cfg_res = CFGAnalyzer.analyze(data, file_name=file_name)
        cfg_telemetry = cfg_res.telemetry.to_dict()

        # 20. WPF BAML & Embedded UI Resource Forensics
        baml_res = BamlDecompiler.decompile_assembly_data(data, file_name=file_name)
        baml_telemetry = baml_res.telemetry.to_dict()

        return build_analysis_report(
            file_path=file_name, file_size=file_size, elapsed_ms=elapsed_ms,
            hashes=hashes, assembly_info=assembly_info, detected_protectors=detected_protectors,
            pe_diag=pe_diag, overlay_bytes=overlay_bytes, pe_size=pe_size, xor_result=xor_result,
            costura_detect=costura_detect, costura_payloads=costura_payloads,
            confuser_detect=confuser_detect, confuser_payloads=confuser_payloads,
            confuser_strings_list=confuser_strings_list,
            reactor_detect=reactor_detect, reactor_payloads=reactor_payloads, reactor_methods=reactor_methods,
            eaz_detect=eaz_detect, eaz_containers=eaz_containers,
            babel_detect=babel_detect, babel_merged=babel_merged,
            armdot_detect=armdot_detect, armdot_containers=armdot_containers,
            intellilock_detect=intellilock_detect, deepsea_detect=deepsea_detect,
            antitamper_detect=antitamper_detect, antidump_detect=antidump_detect,
            native_demux_detect=native_demux_detect, native_demux_payloads=native_demux_payloads,
            threat_rules_telemetry=threat_rules_telemetry, mixed_mode_telemetry=mixed_mode_telemetry,
            cfg_telemetry=cfg_telemetry, baml_telemetry=baml_telemetry,
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
        """Extracts and writes decrypted payload to disk across all supported protector types."""
        with open(input_path, "rb") as f:
            data = f.read()
        return unpack_payload_to_file(data, output_path=output_path, master_key=master_key)

    @classmethod
    def unpack_to_dir(cls, input_path: str, output_dir: str) -> List[Dict[str, any]]:
        """Extracts all embedded Costura, ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, DeepSea, AntiTamper, and AntiDump assemblies into target directory."""
        with open(input_path, "rb") as f:
            data = f.read()
        return unpack_all_to_dir(data, output_dir=output_dir)


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

    @classmethod
    def demux_native(cls, input_path: str) -> Dict[str, Any]:
        """Scans and demuxes embedded multi-architecture native binaries."""
        with open(input_path, "rb") as f:
            data = f.read()
        telemetry, payloads = NativeDemuxerUnpacker.demux(data)
        return {
            "telemetry": telemetry.to_dict(),
            "payloads": [p.to_dict() for p in payloads],
        }

    @classmethod
    def route_native(cls, input_path: str, target_os: str = "windows", target_arch: str = "x64") -> Dict[str, Any]:
        """Simulates dynamic loader routing and platform resolution for given OS and architecture."""
        with open(input_path, "rb") as f:
            return NativeDemuxerUnpacker.route(f.read(), target_os=target_os, target_arch=target_arch)

    @classmethod
    def unpack_native_dir(cls, input_path: str, output_dir: str, target_arch: Optional[str] = None) -> Dict[str, Any]:
        """Demuxes native multi-architecture binaries and exports to architecture-organized directory."""
        with open(input_path, "rb") as f:
            return NativeDemuxerUnpacker.unpack_to_directory(f.read(), output_dir=output_dir, target_arch=target_arch)

    @classmethod
    def generate_threat_rules(
        cls, input_path: str, granularity: str = "behavioral", rule_format: str = "combined", options: Optional[Dict[str, Any]] = None
    ) -> RuleGenerationResult:
        """Synthesizes dynamic YARA and Sigma rules from input binary."""
        return ThreatRuleEngine.synthesize_from_file(
            input_path, granularity=RuleGranularity(granularity.lower()), rule_format=RuleFormat(rule_format.lower()), options=options
        )

    @classmethod
    def export_threat_rules(
        cls, input_path: str, output_dir: str, granularity: str = "behavioral", rule_format: str = "combined", options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Synthesizes and exports detection rules and JSON manifest to target directory."""
        res = cls.generate_threat_rules(input_path, granularity=granularity, rule_format=rule_format, options=options)
        return ThreatRuleEngine.export_to_directory(res, output_dir=output_dir)

    @classmethod
    def analyze_mixed_mode(cls, input_path: str) -> MixedModeAnalysisResult:
        """Performs static forensic inspection of PE binary for mixed-mode traits."""
        return MixedModeAnalyzer.analyze_file(input_path)

    @classmethod
    def export_mixed_mode(cls, input_path: str, output_dir: str) -> Dict[str, Any]:
        """Analyzes mixed-mode PE and exports manifests, transitions, and VTFixup tables."""
        return MixedModeAnalyzer.export_to_directory(cls.analyze_mixed_mode(input_path), output_dir=output_dir)

    @classmethod
    def analyze_cfg(cls, input_path: str, max_methods: int = 50) -> CFGAnalysisResult:
        """Performs static CIL control flow graph and entropy analysis on binary."""
        return CFGAnalyzer.analyze_file(input_path, max_methods=max_methods)

    @classmethod
    def export_cfg(
        cls, input_path: str, output_dir: str, formats: Optional[List[str]] = None, max_exported_methods: int = 15
    ) -> Dict[str, Any]:
        """Analyzes binary CFG and exports visual diagrams, JSON manifests, and telemetry reports."""
        return CFGAnalyzer.export_to_directory(
            cls.analyze_cfg(input_path), output_dir=output_dir, formats=formats, max_exported_methods=max_exported_methods
        )

    @classmethod
    def analyze_baml(cls, input_path: str) -> BamlExtractionResult:
        """Performs static BAML UI forensics and XAML decompiler analysis on binary."""
        return BamlDecompiler.decompile_file(input_path)

    @classmethod
    def export_baml(cls, input_path: str, output_dir: str, export_raw_baml: bool = False) -> Dict[str, Any]:
        """Extracts and decompiles BAML streams and exports XAML documents to disk."""
        return BamlDecompiler.export_to_directory(
            cls.analyze_baml(input_path), output_dir=output_dir, export_raw_baml=export_raw_baml
        )

    @classmethod
    def run_fuzzing_campaign(
        cls, target_path: Optional[str] = None, iterations: int = 50, seed: int = 1337,
        targets: Optional[List[str]] = None, timeout_sec: float = 3.0, output_dir: Optional[str] = None,
        is_64bit: bool = False, isolate_process: bool = False,
    ) -> FuzzCampaignResult:
        """Executes automated regression fuzzing campaign across forensic targets."""
        base_binary = None
        if target_path:
            if not os.path.exists(target_path):
                raise FileNotFoundError(f"Fuzzing target file not found: {target_path}")
            with open(target_path, "rb") as f:
                base_binary = f.read()
        elif is_64bit:
            base_binary = SyntheticMutatedBinaryGenerator.generate_baseline_pe(is_64bit=True)
        parsed_targets = [FuzzTarget.from_str(t) for t in targets] if targets else None
        return RegressionFuzzingHarness.run_campaign(
            base_binary=base_binary, iterations=iterations, seed=seed,
            targets=parsed_targets, timeout_sec=timeout_sec, output_dir=output_dir,
            isolate_process=isolate_process,
        )

    @classmethod
    def generate_synthetic_corpus(
        cls, base_path: Optional[str] = None, count: int = 10, seed: int = 42,
        output_dir: Optional[str] = None, is_64bit: bool = False,
    ) -> List[Dict[str, Any]]:
        """Generates and optionally exports a corpus of synthetic mutated binaries."""
        base_binary = None
        if base_path:
            if not os.path.exists(base_path):
                raise FileNotFoundError(f"Base binary file not found: {base_path}")
            with open(base_path, "rb") as f:
                base_binary = f.read()
        elif is_64bit:
            base_binary = SyntheticMutatedBinaryGenerator.generate_baseline_pe(is_64bit=True)
        corpus = SyntheticMutatedBinaryGenerator.generate_corpus(base_binary=base_binary, count=count, seed=seed)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        results = []
        for i, (m_bytes, recs) in enumerate(corpus):
            sha = hashlib.sha256(m_bytes).hexdigest()
            fname = f"synthetic_mutant_{i+1:03d}_{sha[:8]}.bin"
            item = {"index": i + 1, "file_name": fname, "sha256": sha, "size_bytes": len(m_bytes), "mutations_count": len(recs)}
            if output_dir:
                p = os.path.join(output_dir, fname)
                with open(p, "wb") as f_out:
                    f_out.write(m_bytes)
                item["path"] = p
            results.append(item)
        return results





