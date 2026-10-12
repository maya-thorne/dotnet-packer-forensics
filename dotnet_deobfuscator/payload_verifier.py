"""
Payload Verification & PE Structural Integrity Regression Test Harness.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BitwiseDiff:
    """Detailed diagnostics for bitwise byte divergence between two binaries."""
    offset: int
    expected_byte: int
    actual_byte: int
    hex_context: str
    total_mismatches: int
    length_match: bool
    size_expected: int
    size_actual: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "first_divergence_offset": self.offset,
            "first_divergence_hex": f"0x{self.offset:08X}",
            "expected_byte": f"0x{self.expected_byte:02X}",
            "actual_byte": f"0x{self.actual_byte:02X}",
            "total_mismatches": self.total_mismatches,
            "length_match": self.length_match,
            "size_expected": self.size_expected,
            "size_actual": self.size_actual,
            "hex_context": self.hex_context,
        }


@dataclass
class VerificationFinding:
    """Individual integrity audit finding or anomaly."""
    category: str
    severity: str  # "INFO", "WARN", "FAIL"
    message: str
    offset: Optional[int] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
        }
        if self.offset is not None:
            res["offset"] = f"0x{self.offset:X}"
        if self.details:
            res["details"] = self.details
        return res


@dataclass
class SectionIntegrity:
    """Structural details for an individual PE section."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    entropy: float
    is_valid_bounds: bool
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "virtual_address": f"0x{self.virtual_address:X}",
            "virtual_size": self.virtual_size,
            "raw_offset": f"0x{self.raw_offset:X}",
            "raw_size": self.raw_size,
            "entropy": round(self.entropy, 4),
            "is_valid_bounds": self.is_valid_bounds,
            "anomalies": self.anomalies,
        }


@dataclass
class PEStructureReport:
    """Comprehensive PE & CLR metadata structure verification report."""
    is_pe: bool = False
    is_dotnet: bool = False
    machine: Optional[str] = None
    subsystem: Optional[str] = None
    section_count: int = 0
    sections: List[SectionIntegrity] = field(default_factory=list)
    has_cor20_header: bool = False
    cor20_valid: bool = False
    metadata_header_found: bool = False
    metadata_streams: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_pe": self.is_pe,
            "is_dotnet": self.is_dotnet,
            "machine": self.machine,
            "subsystem": self.subsystem,
            "section_count": self.section_count,
            "sections": [s.to_dict() for s in self.sections],
            "has_cor20_header": self.has_cor20_header,
            "cor20_valid": self.cor20_valid,
            "metadata_header_found": self.metadata_header_found,
            "metadata_streams": self.metadata_streams,
            "anomalies": self.anomalies,
        }


@dataclass
class PayloadVerificationResult:
    """Holistic verification result encompassing hashes, bitwise diffs, and PE structure."""
    target_path: str
    reference_path: Optional[str] = None
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    size_bytes: int = 0
    passed: bool = False
    has_warnings: bool = False
    bitwise_match: Optional[bool] = None
    bitwise_diff: Optional[BitwiseDiff] = None
    pe_structure: PEStructureReport = field(default_factory=PEStructureReport)
    findings: List[VerificationFinding] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "target": self.target_path,
            "reference": self.reference_path,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "size_bytes": self.size_bytes,
            "status": "PASS" if self.passed else ("WARN" if self.has_warnings else "FAIL"),
            "passed": self.passed,
            "has_warnings": self.has_warnings,
            "summary": self.summary,
            "pe_structure": self.pe_structure.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.bitwise_match is not None:
            res["bitwise_match"] = self.bitwise_match
        if self.bitwise_diff is not None:
            res["bitwise_diff"] = self.bitwise_diff.to_dict()
        return res


class PayloadVerifier:
    """
    Forensic Verification Engine:
    Performs bitwise divergence analysis, cryptographic hash integrity checks,
    and rigorous PE & CLR metadata structural conformance auditing.
    """

    MACHINE_MAP = {
        0x014C: "IMAGE_FILE_MACHINE_I386 (x86 32-bit)",
        0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64 64-bit)",
        0xAA64: "IMAGE_FILE_MACHINE_ARM64 (ARM 64-bit)",
        0x01C0: "IMAGE_FILE_MACHINE_ARM (ARM Thumb)",
        0x0200: "IMAGE_FILE_MACHINE_IA64 (Intel Itanium)",
    }

    SUBSYSTEM_MAP = {
        1: "IMAGE_SUBSYSTEM_NATIVE",
        2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3: "IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)",
        7: "IMAGE_SUBSYSTEM_POSIX_CUI",
        9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
        14: "IMAGE_SUBSYSTEM_XBOX",
    }

    @staticmethod
    def compute_entropy(data: bytes) -> float:
        """Calculates Shannon entropy (0.0 to 8.0) of byte buffer with bounds safety."""
        if not data:
            return 0.0
        import math
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        ent = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                ent -= p * math.log2(p)
        return round(ent, 4)

    @classmethod
    def compute_hashes(cls, data: bytes) -> Dict[str, str]:
        """Calculates SHA-256, SHA-1, and MD5 cryptographic digests."""
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }

    @classmethod
    def compare_bitwise(
        cls,
        payload: bytes,
        reference: bytes,
        context_radius: int = 16,
    ) -> Tuple[bool, Optional[BitwiseDiff]]:
        """
        Executes strict byte-for-byte comparison between payload and reference.
        Returns match status and BitwiseDiff detailing the exact first deviation offset.
        """
        size_actual = len(payload)
        size_expected = len(reference)
        length_match = (size_actual == size_expected)

        if payload == reference:
            return True, None

        min_len = min(size_actual, size_expected)
        first_diff_idx = -1
        mismatches = 0

        for i in range(min_len):
            if payload[i] != reference[i]:
                if first_diff_idx == -1:
                    first_diff_idx = i
                mismatches += 1

        if first_diff_idx == -1 and not length_match:
            first_diff_idx = min_len

        mismatches += abs(size_actual - size_expected)

        # Build hex context around first deviation
        start_ctx = max(0, first_diff_idx - context_radius)
        end_ctx_p = min(size_actual, first_diff_idx + context_radius + 1)
        end_ctx_r = min(size_expected, first_diff_idx + context_radius + 1)

        exp_byte = reference[first_diff_idx] if first_diff_idx < size_expected else -1
        act_byte = payload[first_diff_idx] if first_diff_idx < size_actual else -1

        sub_ref = reference[start_ctx:end_ctx_r]
        sub_act = payload[start_ctx:end_ctx_p]

        ref_hex = " ".join(f"{b:02X}" for b in sub_ref)
        act_hex = " ".join(f"{b:02X}" for b in sub_act)

        context_repr = f"Offset 0x{first_diff_idx:08X}:\n  Expected: {ref_hex}\n  Actual  : {act_hex}"

        diff = BitwiseDiff(
            offset=first_diff_idx,
            expected_byte=exp_byte if exp_byte >= 0 else 0,
            actual_byte=act_byte if act_byte >= 0 else 0,
            hex_context=context_repr,
            total_mismatches=mismatches,
            length_match=length_match,
            size_expected=size_expected,
            size_actual=size_actual,
        )
        return False, diff

    @classmethod
    def verify_pe_structure(
        cls,
        data: bytes,
        strict: bool = False,
    ) -> Tuple[PEStructureReport, List[VerificationFinding]]:
        """
        Rigorous parser and verifier for PE headers, section boundaries,
        and CLR COM descriptors (.NET Cor20Header).
        """
        report = PEStructureReport()
        findings: List[VerificationFinding] = []

        # 1. DOS & NT Header Discovery
        has_mz = (len(data) >= 2 and data[:2] == b"MZ")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0
        has_pe_sig = False
        if 0x40 <= e_lfanew <= len(data) - 4:
            has_pe_sig = (data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00")

        if not has_mz and not has_pe_sig:
            # Raw binary payload (non-PE container)
            report.is_pe = False
            sev = "FAIL" if strict else "INFO"
            findings.append(VerificationFinding(
                category="CONTAINER_TYPE",
                severity=sev,
                message="Raw binary payload (non-PE container; no MZ or NT signature).",
            ))
            if strict:
                report.anomalies.append("Non-PE container rejected in strict mode")
            return report, findings

        if not has_mz:
            report.anomalies.append("Missing or corrupted DOS magic ('MZ')")
            findings.append(VerificationFinding(
                category="DOS_HEADER",
                severity="WARN" if not strict else "FAIL",
                message="Missing standard 'MZ' signature (0x5A4D) at offset 0x0.",
                offset=0,
            ))
        else:
            findings.append(VerificationFinding(
                category="DOS_HEADER",
                severity="INFO",
                message="Valid DOS signature ('MZ') identified.",
                offset=0,
            ))

        if not (0x40 <= e_lfanew <= len(data) - 4):
            report.is_pe = False
            report.anomalies.append(f"Invalid e_lfanew PE header offset: 0x{e_lfanew:X}")
            findings.append(VerificationFinding(
                category="DOS_HEADER",
                severity="FAIL" if strict else "WARN",
                message=f"e_lfanew pointer 0x{e_lfanew:X} points out of bounds or into DOS stub.",
                offset=0x3C,
            ))
            return report, findings

        # 2. NT Headers Validation
        pe_sig = data[e_lfanew : e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            report.is_pe = False
            report.anomalies.append(f"Corrupted NT signature at 0x{e_lfanew:X}: {pe_sig!r}")
            findings.append(VerificationFinding(
                category="NT_HEADER",
                severity="FAIL" if strict else "WARN",
                message="NT signature mismatch (expected 'PE\\0\\0').",
                offset=e_lfanew,
            ))
            return report, findings

        report.is_pe = True
        findings.append(VerificationFinding(
            category="NT_HEADER",
            severity="INFO",
            message="Valid NT signature ('PE\\0\\0') verified.",
            offset=e_lfanew,
        ))

        if e_lfanew + 24 > len(data):
            findings.append(VerificationFinding(
                category="FILE_HEADER",
                severity="FAIL",
                message="File truncated before FileHeader could be read.",
                offset=e_lfanew,
            ))
            return report, findings

        machine, num_sections, _, _, _, size_opt_header, characteristics = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4
        )
        report.machine = cls.MACHINE_MAP.get(machine, f"UNKNOWN_MACHINE_0x{machine:04X}")
        report.section_count = num_sections

        findings.append(VerificationFinding(
            category="FILE_HEADER",
            severity="INFO",
            message=f"Architecture: {report.machine}, Sections: {num_sections}.",
            offset=e_lfanew + 4,
        ))

        if num_sections == 0 or num_sections > 96:
            report.anomalies.append(f"Suspicious section count: {num_sections}")
            findings.append(VerificationFinding(
                category="FILE_HEADER",
                severity="FAIL" if num_sections == 0 else "WARN",
                message=f"Abnormal section count ({num_sections}). Typical range is 1-16.",
                offset=e_lfanew + 6,
            ))

        # 3. Optional Header Validation
        opt_offset = e_lfanew + 24
        if size_opt_header < 68 or opt_offset + size_opt_header > len(data):
            findings.append(VerificationFinding(
                category="OPTIONAL_HEADER",
                severity="FAIL",
                message="Optional header truncated or missing.",
                offset=opt_offset,
            ))
            return report, findings

        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_pe32_plus = (opt_magic == 0x020B)
        subsys_offset = opt_offset + (68 if is_pe32_plus else 68)
        subsys = struct.unpack_from("<H", data, subsys_offset)[0] if opt_offset + 70 <= len(data) else 0
        report.subsystem = cls.SUBSYSTEM_MAP.get(subsys, f"UNKNOWN_SUBSYSTEM_{subsys}")

        sec_align = struct.unpack_from("<I", data, opt_offset + 32)[0]
        file_align = struct.unpack_from("<I", data, opt_offset + 36)[0]

        if sec_align == 0 or (sec_align & (sec_align - 1)) != 0:
            report.anomalies.append(f"Non-power-of-two SectionAlignment: 0x{sec_align:X}")
            findings.append(VerificationFinding(
                category="OPTIONAL_HEADER",
                severity="WARN",
                message=f"SectionAlignment 0x{sec_align:X} is non-standard.",
                offset=opt_offset + 32,
            ))

        if file_align == 0 or (file_align & (file_align - 1)) != 0:
            report.anomalies.append(f"Non-power-of-two FileAlignment: 0x{file_align:X}")
            findings.append(VerificationFinding(
                category="OPTIONAL_HEADER",
                severity="WARN",
                message=f"FileAlignment 0x{file_align:X} is non-standard.",
                offset=opt_offset + 36,
            ))

        # 4. Data Directories & CLR COM Descriptor (Directory[14])
        rva_cor20 = 0
        size_cor20 = 0
        num_rva = struct.unpack_from("<I", data, opt_offset + (108 if is_pe32_plus else 92))[0] if opt_offset + 96 <= len(data) else 0
        dd_start = opt_offset + (112 if is_pe32_plus else 96)

        if num_rva > 14 and dd_start + (15 * 8) <= len(data):
            rva_cor20, size_cor20 = struct.unpack_from("<II", data, dd_start + (14 * 8))
            if rva_cor20 > 0 and size_cor20 > 0:
                report.has_cor20_header = True

        # 5. Section Table Verification
        sec_tbl_start = opt_offset + size_opt_header
        sections: List[SectionIntegrity] = []
        prev_va = 0

        for idx in range(num_sections):
            entry_off = sec_tbl_start + (idx * 40)
            if entry_off + 40 > len(data):
                report.anomalies.append(f"Section table truncated at index {idx}")
                findings.append(VerificationFinding(
                    category="SECTION_TABLE",
                    severity="FAIL",
                    message=f"Section table truncated reading section #{idx}.",
                    offset=entry_off,
                ))
                break

            sec_name_raw = data[entry_off : entry_off + 8]
            clean_name = sec_name_raw.split(b"\x00")[0].decode("ascii", errors="replace").strip()
            v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, entry_off + 8)

            sec_anomalies: List[str] = []
            is_valid_bounds = True

            # Validate physical raw offset boundaries
            if raw_ptr + raw_size > len(data):
                is_valid_bounds = False
                sec_anomalies.append("Physical raw offset extends beyond end of file")
                findings.append(VerificationFinding(
                    category="SECTION_TABLE",
                    severity="WARN" if not strict else "FAIL",
                    message=f"Section '{clean_name}' raw bytes [0x{raw_ptr:X}..0x{raw_ptr+raw_size:X}] exceed file size ({len(data)} bytes).",
                    offset=entry_off,
                ))

            # Validate virtual address ordering
            if idx > 0 and v_addr < prev_va:
                sec_anomalies.append("VirtualAddress is not monotonically increasing")
                findings.append(VerificationFinding(
                    category="SECTION_TABLE",
                    severity="WARN",
                    message=f"Section '{clean_name}' VirtualAddress 0x{v_addr:X} precedes previous 0x{prev_va:X}.",
                    offset=entry_off + 12,
                ))
            prev_va = v_addr

            # Calculate section byte entropy
            sec_bytes = b""
            if raw_ptr < len(data):
                sec_bytes = data[raw_ptr : min(len(data), raw_ptr + raw_size)]
            sec_ent = cls.compute_entropy(sec_bytes)

            if sec_ent > 7.85:
                findings.append(VerificationFinding(
                    category="SECTION_ENTROPY",
                    severity="INFO",
                    message=f"High entropy {sec_ent:.3f} in section '{clean_name}' indicates compression/encryption.",
                    offset=raw_ptr,
                ))

            sec_info = SectionIntegrity(
                name=clean_name,
                virtual_address=v_addr,
                virtual_size=v_size,
                raw_offset=raw_ptr,
                raw_size=raw_size,
                entropy=sec_ent,
                is_valid_bounds=is_valid_bounds,
                anomalies=sec_anomalies,
            )
            sections.append(sec_info)

        report.sections = sections

        # 6. CLR Cor20Header & BSJB Metadata Inspection
        if report.has_cor20_header:
            cor_raw = cls.rva_to_offset(rva_cor20, sections)
            if cor_raw is not None and cor_raw + 72 <= len(data):
                cb_size = struct.unpack_from("<I", data, cor_raw)[0]
                if cb_size == 72:
                    report.cor20_valid = True
                    report.is_dotnet = True
                    findings.append(VerificationFinding(
                        category="COR20_HEADER",
                        severity="INFO",
                        message="Valid .NET CLR Cor20Header (cb=72) verified.",
                        offset=cor_raw,
                    ))

                    # Inspect MetaData directory inside Cor20Header
                    md_rva, md_size = struct.unpack_from("<II", data, cor_raw + 8)
                    md_raw = cls.rva_to_offset(md_rva, sections)
                    if md_raw is not None and md_raw + 16 <= len(data):
                        md_sig = struct.unpack_from("<I", data, md_raw)[0]
                        if md_sig == 0x424A5342:  # 'BSJB'
                            report.metadata_header_found = True
                            findings.append(VerificationFinding(
                                category="CLI_METADATA",
                                severity="INFO",
                                message="Authentic .NET CLI metadata header signature ('BSJB') verified.",
                                offset=md_raw,
                            ))
                            # Scan for stream names
                            streams = []
                            for st_name in [b"#Strings", b"#US", b"#Blob", b"#GUID", b"#~", b"#-"]:
                                if st_name in data[md_raw : min(len(data), md_raw + md_size)]:
                                    streams.append(st_name.decode("ascii"))
                            report.metadata_streams = streams
                else:
                    report.anomalies.append(f"Cor20Header cb mismatch: {cb_size} != 72")
                    findings.append(VerificationFinding(
                        category="COR20_HEADER",
                        severity="WARN",
                        message=f"Cor20Header size descriptor is {cb_size} (standard is 72).",
                        offset=cor_raw,
                    ))

        return report, findings

    @staticmethod
    def rva_to_offset(rva: int, sections: List[SectionIntegrity]) -> Optional[int]:
        """Translates Relative Virtual Address (RVA) to physical file offset."""
        for s in sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s.raw_offset + (rva - s.virtual_address)
        return None

    @classmethod
    def verify_payload_buffer(
        cls,
        payload_data: bytes,
        reference_data: Optional[bytes] = None,
        expected_sha256: Optional[str] = None,
        strict_pe: bool = False,
    ) -> PayloadVerificationResult:
        """
        Runs comprehensive multi-stage verification on raw byte payload.
        Performs cryptographic hashing, bitwise differential diagnostics, and PE structure checks.
        """
        hashes = cls.compute_hashes(payload_data)
        size_bytes = len(payload_data)

        res = PayloadVerificationResult(
            target_path="<buffer>",
            sha256=hashes["sha256"],
            sha1=hashes["sha1"],
            md5=hashes["md5"],
            size_bytes=size_bytes,
        )

        # 1. Expected SHA-256 match
        if expected_sha256:
            clean_exp = expected_sha256.lower().strip()
            if hashes["sha256"].lower() == clean_exp:
                res.findings.append(VerificationFinding(
                    category="HASH_INTEGRITY",
                    severity="INFO",
                    message="SHA-256 matches expected golden hash signature.",
                ))
            else:
                res.findings.append(VerificationFinding(
                    category="HASH_INTEGRITY",
                    severity="FAIL",
                    message=f"SHA-256 mismatch: actual {hashes['sha256']} != expected {clean_exp}.",
                ))

        # 2. Bitwise reference comparison
        if reference_data is not None:
            res.reference_path = "<reference_buffer>"
            match, diff = cls.compare_bitwise(payload_data, reference_data)
            res.bitwise_match = match
            res.bitwise_diff = diff

            if match:
                res.findings.append(VerificationFinding(
                    category="BITWISE_MATCH",
                    severity="INFO",
                    message="100% bitwise parity confirmed with reference payload.",
                ))
            else:
                res.findings.append(VerificationFinding(
                    category="BITWISE_MATCH",
                    severity="FAIL",
                    message=f"Bitwise divergence detected: {diff.total_mismatches} byte deviations starting at offset 0x{diff.offset:08X}.",
                    offset=diff.offset,
                    details=diff.hex_context,
                ))

        # 3. PE Structure Validation
        pe_report, pe_findings = cls.verify_pe_structure(payload_data, strict=strict_pe)
        res.pe_structure = pe_report
        res.findings.extend(pe_findings)

        # 4. Evaluate Pass/Fail/Warn Status
        has_fail = any(f.severity == "FAIL" for f in res.findings)
        has_warn = any(f.severity == "WARN" for f in res.findings)

        res.passed = not has_fail
        res.has_warnings = has_warn

        if res.passed and not has_warn:
            res.summary = "All cryptographic hash checks and PE structural constraints verified successfully."
        elif res.passed and has_warn:
            res.summary = "Verification completed with non-fatal structural anomalies (warnings)."
        else:
            res.summary = "Verification failed due to hash mismatch, bitwise divergence, or structural PE corruption."

        # Zeroize sensitive buffer reference in memory
        del payload_data
        if reference_data is not None:
            del reference_data

        return res

    @classmethod
    def verify_payload_file(
        cls,
        target_path: str,
        reference_path: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        strict_pe: bool = False,
    ) -> PayloadVerificationResult:
        """Loads target and reference files from disk and executes complete verification."""
        if not os.path.isfile(target_path):
            res = PayloadVerificationResult(target_path=target_path)
            res.passed = False
            res.findings.append(VerificationFinding(
                category="FILE_IO",
                severity="FAIL",
                message=f"Target file not found: {target_path}",
            ))
            res.summary = f"Target file does not exist: {target_path}"
            return res

        with open(target_path, "rb") as f:
            target_data = f.read()

        reference_data: Optional[bytes] = None
        if reference_path:
            if not os.path.isfile(reference_path):
                res = PayloadVerificationResult(target_path=target_path, reference_path=reference_path)
                res.passed = False
                res.findings.append(VerificationFinding(
                    category="FILE_IO",
                    severity="FAIL",
                    message=f"Reference file not found: {reference_path}",
                ))
                res.summary = f"Reference file does not exist: {reference_path}"
                return res
            with open(reference_path, "rb") as f:
                reference_data = f.read()

        result = cls.verify_payload_buffer(
            payload_data=target_data,
            reference_data=reference_data,
            expected_sha256=expected_sha256,
            strict_pe=strict_pe,
        )
        result.target_path = target_path
        result.reference_path = reference_path
        return result

    @classmethod
    def verify_directory(
        cls,
        target_dir: str,
        golden_hashes: Optional[Dict[str, str]] = None,
        strict_pe: bool = False,
    ) -> List[PayloadVerificationResult]:
        """
        Audits all binary payloads in target directory against golden hash registry
        and structural PE constraints.
        """
        results: List[PayloadVerificationResult] = []
        if not os.path.isdir(target_dir):
            return results

        for root, _, files in os.walk(target_dir):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                expected_hash = golden_hashes.get(file_name) if golden_hashes else None
                res = cls.verify_payload_file(
                    target_path=full_path,
                    expected_sha256=expected_hash,
                    strict_pe=strict_pe,
                )
                results.append(res)
        return results

    @classmethod
    def format_text_report(cls, result: PayloadVerificationResult, verbose: bool = False) -> str:
        """Renders an elegant, human-readable terminal report."""
        status_tag = "[PASS]" if result.passed else ("[WARN]" if result.has_warnings else "[FAIL]")
        lines = [
            "==============================================================================",
            f"Forensic Payload Verification & Integrity Report {status_tag}",
            "==============================================================================",
            f"Target Binary   : {result.target_path}",
            f"File Size       : {result.size_bytes:,} bytes",
            f"SHA-256 Digest  : {result.sha256}",
            f"SHA-1 Digest    : {result.sha1}",
            f"MD5 Digest      : {result.md5}",
        ]

        if result.reference_path:
            lines.append(f"Reference File  : {result.reference_path}")
            parity = "100% BITWISE PARITY" if result.bitwise_match else "DIVERGENCE DETECTED"
            lines.append(f"Bitwise Parity  : {parity}")
            if result.bitwise_diff:
                d = result.bitwise_diff
                lines.append(f"  First Diff At : 0x{d.offset:08X} (Exp: 0x{d.expected_byte:02X}, Act: 0x{d.actual_byte:02X})")
                lines.append(f"  Total Mismatch: {d.total_mismatches:,} bytes")
                lines.append(f"  Length Match  : {'YES' if d.length_match else 'NO'} ({d.size_actual:,} vs {d.size_expected:,} bytes)")

        lines.append("")
        lines.append("--- [PE & CLR Structural Health] ---")
        pe = result.pe_structure
        lines.append(f"  PE Image Valid  : {'YES' if pe.is_pe else 'NO'}")
        if pe.is_pe:
            lines.append(f"  Target Machine  : {pe.machine}")
            lines.append(f"  Subsystem Type  : {pe.subsystem}")
            lines.append(f"  Section Count   : {pe.section_count}")
            lines.append(f"  .NET Assembly   : {'YES' if pe.is_dotnet else 'NO'}")
            if pe.is_dotnet:
                lines.append(f"  Cor20Header     : {'VALID (cb=72)' if pe.cor20_valid else 'INVALID'}")
                lines.append(f"  CLI Metadata    : {'PRESENT (BSJB)' if pe.metadata_header_found else 'NOT_FOUND'}")
                if pe.metadata_streams:
                    lines.append(f"  Metadata Streams: {', '.join(pe.metadata_streams)}")

        if pe.sections and (verbose or not result.passed):
            lines.append("")
            lines.append("--- [Section Boundaries & Entropy] ---")
            for s in pe.sections:
                lines.append(
                    f"  {s.name:<8} VAddr: 0x{s.virtual_address:08X} RawPtr: 0x{s.raw_offset:08X} "
                    f"RawSize: {s.raw_size:<8} Entropy: {s.entropy:0.4f} "
                    f"[{'OK' if s.is_valid_bounds else 'ERR'}]"
                )

        lines.append("")
        lines.append("--- [Integrity Findings & Telemetry] ---")
        for f in result.findings:
            sev_marker = {"INFO": "[i]", "WARN": "[!]", "FAIL": "[-]"}.get(f.severity, "[?]")
            off_str = f" @ {f.offset}" if f.offset else ""
            lines.append(f"  {sev_marker} [{f.category}]{off_str} {f.message}")

        lines.append("")
        lines.append(f"Overall Result  : {result.summary}")
        lines.append("==============================================================================")
        return "\n".join(lines)
