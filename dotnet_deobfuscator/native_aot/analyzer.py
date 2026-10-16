"""
Native AOT & ReadyToRun (R2R) PE Forensic Analyzer & Engine.
Orchestrates PE structure inspection, R2R parsing, Native AOT symbol recovery, and disassembly export.
Engineered & Audited by Maya Thorne.
"""

import csv
import hashlib
import json
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from .aot_symbol_parser import AOTSymbolParser
from .disassembler import NativeDisassembler
from .models import (
    AOTVersion,
    CompilationType,
    DisassembledMethod,
    MethodDefEntry,
    NativeAOTAnalysisResult,
    NativeAOTTelemetry,
    NativeSymbol,
    R2RHeader,
    R2RSection,
    RuntimeFunctionEntry,
    SecurityError,
    TargetArchitecture,
    safe_path,
    zeroize_buffer,
)
from .r2r_parser import R2RParser


class NativeAOTAnalyzer:
    """Forensic engine for analyzing ReadyToRun (R2R) and Native AOT (.NET 7/8/9) PE binaries."""

    @staticmethod
    def _rva_to_offset(rva: int, sec_rva_map: List[Tuple[int, int, int, int]]) -> Optional[int]:
        """Translates Relative Virtual Address (RVA) to raw file offset."""
        if rva <= 0:
            return None
        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            span = max(v_size, raw_size)
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size:
                    return raw_ptr + delta
        return None

    @classmethod
    def analyze_file(cls, file_path: str, max_methods: int = 50) -> NativeAOTAnalysisResult:
        """Analyzes a binary file on disk for Native AOT and ReadyToRun characteristics."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target binary file not found: {file_path}")
        with open(file_path, "rb") as f:
            data = f.read()
        return cls.analyze(data, file_name=os.path.basename(file_path), max_methods=max_methods)

    @classmethod
    def analyze(
        cls,
        data: bytes,
        file_name: str = "binary.exe",
        max_methods: int = 50,
    ) -> NativeAOTAnalysisResult:
        """Performs static forensic inspection of binary byte buffer for AOT and R2R metadata."""
        sha256 = hashlib.sha256(data).hexdigest()
        file_size = len(data)
        anomalies: List[str] = []

        # 1. DOS & NT Header Validation
        if len(data) < 64 or data[:2] != b"MZ":
            telemetry = cls._create_corrupted_telemetry(
                "Not a valid PE executable (missing MZ magic)", anomalies
            )
            return NativeAOTAnalysisResult(
                file_name, file_size, sha256, telemetry, None, [], [], [], [], []
            )

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            telemetry = cls._create_corrupted_telemetry(
                "Corrupted PE signature or truncated headers", anomalies
            )
            return NativeAOTAnalysisResult(
                file_name, file_size, sha256, telemetry, None, [], [], [], [], []
            )

        # 2. Machine & Architecture Classification
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt_hdr_start = e_lfanew + 24

        arch = TargetArchitecture.UNKNOWN
        if machine == 0x8664:
            arch = TargetArchitecture.X64
        elif machine == 0x014C:
            arch = TargetArchitecture.X86
        elif machine == 0xAA64:
            arch = TargetArchitecture.ARM64

        if opt_hdr_start + 2 > len(data):
            telemetry = cls._create_corrupted_telemetry("Truncated Optional Header", anomalies)
            return NativeAOTAnalysisResult(
                file_name, file_size, sha256, telemetry, None, [], [], [], [], []
            )

        magic = struct.unpack_from("<H", data, opt_hdr_start)[0]
        is_64bit = magic == 0x20B

        # 3. Data Directory extraction
        export_rva = 0
        export_size = 0
        cor20_rva = 0
        cor20_size = 0
        managed_native_rva = 0

        # Export directory is at opt_hdr_start + (112 if 64-bit else 96)
        exp_dir_off = opt_hdr_start + (112 if is_64bit else 96)
        if exp_dir_off + 8 <= len(data):
            export_rva, export_size = struct.unpack_from("<II", data, exp_dir_off)

        # CLR Cor20Header Directory is at index 14: opt_hdr_start + (224 if 64-bit else 208)
        clr_dir_off = opt_hdr_start + (224 if is_64bit else 208)
        if clr_dir_off + 8 <= len(data):
            cor20_rva, cor20_size = struct.unpack_from("<II", data, clr_dir_off)

        # 4. Section headers extraction
        sec_hdr_start = opt_hdr_start + opt_hdr_size
        sec_rva_map: List[Tuple[int, int, int, int]] = []
        section_names: List[str] = []
        aot_managed_sections: List[str] = []

        for i in range(min(num_sections, 96)):
            sec_off = sec_hdr_start + (i * 40)
            if sec_off + 40 > len(data):
                break
            name = (
                data[sec_off : sec_off + 8]
                .decode("latin1", errors="ignore")
                .strip("\x00")
            )
            v_size, v_addr, r_size, r_ptr = struct.unpack_from("<IIII", data, sec_off + 8)
            sec_rva_map.append((v_addr, v_size, r_ptr, r_size))
            section_names.append(name)
            if any(name.lower().startswith(s) or s.startswith(name.lower()) for s in AOTSymbolParser.AOT_SECTIONS):
                aot_managed_sections.append(name)

        # 5. Extract ManagedNativeHeader if Cor20Header is present
        if cor20_rva > 0 and cor20_size >= 72:
            cor_off = cls._rva_to_offset(cor20_rva, sec_rva_map)
            if cor_off is not None and cor_off + 72 <= len(data):
                # ManagedNativeHeader is at offset 0x40 in IMAGE_COR20_HEADER (64 bytes in)
                managed_native_rva, _ = struct.unpack_from("<II", data, cor_off + 0x40)

        # 6. Parse ReadyToRun (R2R) structures
        r2r_hdr, r2r_secs, runtime_funcs, method_eps, compiler_id = R2RParser.parse(
            data, sec_rva_map, managed_native_rva
        )

        # 7. Redhawk Helpers & Symbol Parsing
        detected_helpers = AOTSymbolParser.scan_for_helpers(data)
        inferred_ver = AOTSymbolParser.infer_aot_version(
            data, detected_helpers, compiler_id, section_names
        )

        symbols: List[NativeSymbol] = []
        if export_rva > 0 and export_size > 0:
            exp_symbols = AOTSymbolParser.parse_pe_exports(
                data, export_rva, export_size, sec_rva_map
            )
            symbols.extend(exp_symbols)

        reflection_symbols = AOTSymbolParser.scan_embedded_reflection_symbols(data, sec_rva_map)
        symbols.extend(reflection_symbols)

        # Build helper map for disassembler
        known_helpers: Dict[int, str] = {}
        for s in symbols:
            if s.rva > 0:
                known_helpers[s.rva] = s.demangled_name or s.name

        # 8. Determine CompilationType & Confidence
        is_r2r = r2r_hdr is not None
        is_aot = len(aot_managed_sections) > 0 or len(detected_helpers) >= 2 or (
            cor20_rva == 0 and len(detected_helpers) > 0
        )

        comp_type = CompilationType.STANDARD_NATIVE
        confidence = "NONE"

        if is_r2r and is_aot:
            comp_type = CompilationType.HYBRID_AOT_MANAGED
            confidence = "HIGH"
        elif is_r2r:
            comp_type = CompilationType.READYTORUN_R2R
            confidence = "HIGH"
        elif is_aot:
            comp_type = CompilationType.NATIVE_AOT
            confidence = "HIGH" if len(detected_helpers) >= 2 else "MEDIUM"
        elif cor20_rva > 0:
            comp_type = CompilationType.STANDARD_MANAGED
            confidence = "HIGH"

        # 9. Disassemble methods
        disassembled: List[DisassembledMethod] = []
        methods_to_disasm = runtime_funcs[:max_methods]

        # If no runtime functions were extracted, fall back to disassembling entrypoint or symbols
        if not methods_to_disasm and (is_r2r or is_aot):
            for sym in symbols[:max_methods]:
                if sym.rva > 0 and not sym.is_runtime_helper:
                    raw_off = cls._rva_to_offset(sym.rva, sec_rva_map)
                    if raw_off and raw_off < len(data):
                        code_slice = data[raw_off : min(raw_off + 128, len(data))]
                        dm = NativeDisassembler.disassemble_method(
                            code_slice, sym.rva, name=sym.demangled_name, arch=arch, known_helpers=known_helpers
                        )
                        disassembled.append(dm)
        else:
            for rf in methods_to_disasm:
                raw_off = cls._rva_to_offset(rf.start_rva, sec_rva_map)
                if raw_off and raw_off < len(data):
                    code_len = min(rf.size_bytes if rf.size_bytes > 0 else 64, 512)
                    code_slice = data[raw_off : min(raw_off + code_len, len(data))]
                    m_name = rf.symbol_name or f"R2RMethod_0x{rf.start_rva:08X}"
                    dm = NativeDisassembler.disassemble_method(
                        code_slice,
                        rf.start_rva,
                        name=m_name,
                        token=rf.method_token,
                        arch=arch,
                        known_helpers=known_helpers,
                    )
                    disassembled.append(dm)

        # 10. Anomalies & Risk Scoring
        risk_score = 0
        if is_r2r and not compiler_id:
            anomalies.append("ReadyToRun header present but compiler identifier string is absent")
            risk_score += 15

        if is_r2r and len(runtime_funcs) == 0:
            anomalies.append("ReadyToRun binary contains 0 RUNTIME_FUNCTION entries (possible anti-analysis or stripped)")
            risk_score += 25

        if is_aot and len(symbols) == 0:
            anomalies.append("Native AOT binary has all reflection symbols and exports stripped")
            risk_score += 20

        if any(sec == ".corrupted" for sec in section_names):
            anomalies.append("Anomalous section name detected in PE headers")
            risk_score += 30

        risk_severity = "clean"
        if risk_score >= 50:
            risk_severity = "high"
        elif risk_score >= 25:
            risk_severity = "medium"
        elif risk_score > 0:
            risk_severity = "informational"

        r2r_ver_str = f"v{r2r_hdr.major_version}.{r2r_hdr.minor_version}" if r2r_hdr else None

        telemetry = NativeAOTTelemetry(
            compilation_type=comp_type.value,
            is_readytorun=is_r2r,
            is_native_aot=is_aot,
            confidence=confidence,
            target_arch=arch.value,
            r2r_version=r2r_ver_str,
            inferred_dotnet_version=inferred_ver.value,
            compiler_identifier=compiler_id,
            r2r_sections_count=len(r2r_secs),
            runtime_functions_count=len(runtime_funcs),
            method_entrypoints_count=len(method_eps),
            symbols_recovered_count=len(symbols),
            rhp_helpers_detected=detected_helpers,
            managed_code_sections=aot_managed_sections,
            anomalies=anomalies,
            risk_score=risk_score,
            risk_severity=risk_severity,
        )

        return NativeAOTAnalysisResult(
            file_path=file_name,
            file_size=file_size,
            sha256=sha256,
            telemetry=telemetry,
            r2r_header=r2r_hdr,
            r2r_sections=r2r_secs,
            runtime_functions=runtime_funcs,
            method_entrypoints=method_eps,
            symbols=symbols,
            disassembled_methods=disassembled,
        )

    @classmethod
    def export_to_directory(
        cls,
        result: NativeAOTAnalysisResult,
        output_dir: str,
        max_exported_methods: int = 25,
    ) -> Dict[str, Any]:
        """
        Safely exports forensic analysis artifacts (summary, sections, symbols, disassembly)
        into the specified output directory. Uses safe_path to guarantee zero directory traversal.
        """
        os.makedirs(output_dir, exist_ok=True)
        exported_files: Dict[str, str] = {}

        # 1. Summary JSON
        summary_path = safe_path(output_dir, "summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        exported_files["summary_json"] = summary_path

        # 2. R2R Sections JSON
        if result.r2r_sections:
            sec_path = safe_path(output_dir, "r2r_sections.json")
            with open(sec_path, "w", encoding="utf-8") as f:
                json.dump([s.to_dict() for s in result.r2r_sections], f, indent=2)
            exported_files["sections_json"] = sec_path

        # 3. Symbols CSV
        if result.symbols:
            sym_path = safe_path(output_dir, "symbols.csv")
            with open(sym_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Token", "Name", "DemangledName", "RVA", "SizeBytes", "Type", "IsHelper"])
                for s in result.symbols:
                    tok_str = f"0x{s.token:08X}" if s.token else ""
                    writer.writerow([
                        tok_str, s.name, s.demangled_name, hex(s.rva), s.size_bytes, s.symbol_type, s.is_runtime_helper
                    ])
            exported_files["symbols_csv"] = sym_path

        # 4. Disassembly TXT
        if result.disassembled_methods:
            disasm_path = safe_path(output_dir, "disassembly.txt")
            with open(disasm_path, "w", encoding="utf-8") as f:
                f.write(f"; Native AOT / ReadyToRun Disassembly for {result.file_path}\n")
                f.write(f"; Architecture: {result.telemetry.target_arch} | SHA-256: {result.sha256}\n\n")
                for dm in result.disassembled_methods[:max_exported_methods]:
                    f.write(f"=== Method: {dm.name} (RVA: {hex(dm.start_rva)} - {hex(dm.end_rva)}) ===\n")
                    if dm.token:
                        f.write(f"; Token: 0x{dm.token:08X}\n")
                    if dm.helpers_called:
                        f.write(f"; Helpers called: {', '.join(dm.helpers_called)}\n")
                    for ins in dm.instructions:
                        target = f" -> {hex(ins.target_rva)}" if ins.target_rva else ""
                        helper = f" <{ins.helper_name}>" if ins.helper_name else ""
                        f.write(
                            f"  0x{ins.offset:08X}:  {ins.raw_bytes:<14}  {ins.mnemonic:<6} {ins.operands}{target}{helper}\n"
                        )
                    f.write("\n")
            exported_files["disassembly_txt"] = disasm_path

        # 5. Disassembly JSON
        if result.disassembled_methods:
            disasm_json_path = safe_path(output_dir, "disassembly.json")
            with open(disasm_json_path, "w", encoding="utf-8") as f:
                json.dump(
                    [dm.to_dict() for dm in result.disassembled_methods[:max_exported_methods]],
                    f,
                    indent=2,
                )
            exported_files["disassembly_json"] = disasm_json_path

        return {
            "success": True,
            "output_dir": output_dir,
            "exported_files": exported_files,
            "methods_count": len(result.disassembled_methods),
            "symbols_count": len(result.symbols),
            "r2r_sections_count": len(result.r2r_sections),
        }

    @staticmethod
    def _create_corrupted_telemetry(reason: str, anomalies: List[str]) -> NativeAOTTelemetry:
        """Constructs telemetry for invalid or corrupted PE inputs."""
        anomalies.append(reason)
        return NativeAOTTelemetry(
            compilation_type=CompilationType.CORRUPTED_OR_ANOMALOUS.value,
            is_readytorun=False,
            is_native_aot=False,
            confidence="NONE",
            target_arch=TargetArchitecture.UNKNOWN.value,
            r2r_version=None,
            inferred_dotnet_version=AOTVersion.UNKNOWN.value,
            compiler_identifier=None,
            r2r_sections_count=0,
            runtime_functions_count=0,
            method_entrypoints_count=0,
            symbols_recovered_count=0,
            rhp_helpers_detected=[],
            managed_code_sections=[],
            anomalies=anomalies,
            risk_score=100,
            risk_severity="high",
        )
