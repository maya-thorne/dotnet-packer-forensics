"""
Data Models and Enums for Anti-Dump Forensics & Memory Healer.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SecurityError(Exception):
    """Raised when bounds checks, sanitization, or path safety constraints are violated."""
    pass


class AntiDumpTechnique(str, Enum):
    """Categorization of detected anti-dump memory corruption techniques."""
    ERASED_DOS_HEADER = "ERASED_DOS_HEADER"
    ERASED_NT_HEADER = "ERASED_NT_HEADER"
    STRIPPED_SECTION_TABLE = "STRIPPED_SECTION_TABLE"
    CORRUPTED_COR20_DESCRIPTOR = "CORRUPTED_COR20_DESCRIPTOR"
    MISSING_CLR_IMPORTS = "MISSING_CLR_IMPORTS"
    VIRTUAL_MEMORY_LAYOUT = "VIRTUAL_MEMORY_LAYOUT"
    ZEROED_OPTIONAL_HEADER = "ZEROED_OPTIONAL_HEADER"
    ANOMALOUS_CHARACTERISTICS = "ANOMALOUS_CHARACTERISTICS"
    CONFUSEREX_ANTIDUMP = "CONFUSEREX_ANTIDUMP"
    REACTOR_ANTIDUMP = "REACTOR_ANTIDUMP"


class DumpSource(str, Enum):
    """Source classification for dumped memory images."""
    UNKNOWN = "UNKNOWN"
    SCYLLA_DUMP = "SCYLLA_DUMP"
    MEGADUMPER = "MEGADUMPER"
    PROCESS_HACKER = "PROCESS_HACKER"
    RAW_VIRTUAL_MEM = "RAW_VIRTUAL_MEM"
    CORRUPTED_DISK_PE = "CORRUPTED_DISK_PE"


class SectionType(str, Enum):
    """Heuristic classification of PE section semantics."""
    CODE_AND_CLR = "CODE_AND_CLR"
    METADATA_BSJB = "METADATA_BSJB"
    IMPORT_TABLE = "IMPORT_TABLE"
    WIN32_RESOURCES = "WIN32_RESOURCES"
    RELOCATIONS = "RELOCATIONS"
    GENERIC_DATA = "GENERIC_DATA"


@dataclass
class HealedSectionInfo:
    """Represents a sanitized and normalized PE section header."""
    name: str
    original_name: bytes
    virtual_address: int
    virtual_size: int
    raw_ptr: int
    raw_size: int
    characteristics: int
    section_type: SectionType = SectionType.GENERIC_DATA
    entropy: float = 0.0
    contains_bsjb: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "virtual_address": f"0x{self.virtual_address:X}",
            "virtual_size": self.virtual_size,
            "raw_ptr": f"0x{self.raw_ptr:X}",
            "raw_size": self.raw_size,
            "characteristics": f"0x{self.characteristics:X}",
            "section_type": self.section_type.value,
            "entropy": round(self.entropy, 4),
            "contains_bsjb": self.contains_bsjb,
        }


@dataclass
class SynthesizedImportInfo:
    """Details of reconstructed CLR mscoree.dll bootstrap imports."""
    dll_name: str = "mscoree.dll"
    symbol_name: str = "_CorExeMain"
    iat_rva: int = 0
    int_rva: int = 0
    descriptor_rva: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dll_name": self.dll_name,
            "symbol_name": self.symbol_name,
            "iat_rva": f"0x{self.iat_rva:X}",
            "int_rva": f"0x{self.int_rva:X}",
            "descriptor_rva": f"0x{self.descriptor_rva:X}",
        }


@dataclass
class AntiDumpTelemetry:
    """Telemetry and diagnostic metrics identified during anti-dump analysis."""
    is_anti_dump_detected: bool = False
    confidence: str = "NONE"
    dump_source: DumpSource = DumpSource.UNKNOWN
    detected_techniques: List[AntiDumpTechnique] = field(default_factory=list)
    original_header_intact: bool = True
    bsjb_metadata_found: bool = False
    bsjb_rva: Optional[int] = None
    cor20_recovered: bool = False
    cor20_synthesized: bool = False
    cor20_rva: Optional[int] = None
    iat_reconstructed: bool = False
    sections_healed_count: int = 0
    anomalies: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anti_dump_detected": self.is_anti_dump_detected,
            "confidence": self.confidence,
            "dump_source": self.dump_source.value,
            "detected_techniques": [t.value for t in self.detected_techniques],
            "original_header_intact": self.original_header_intact,
            "bsjb_metadata_found": self.bsjb_metadata_found,
            "bsjb_rva": f"0x{self.bsjb_rva:X}" if self.bsjb_rva is not None else None,
            "cor20_recovered": self.cor20_recovered,
            "cor20_synthesized": self.cor20_synthesized,
            "cor20_rva": f"0x{self.cor20_rva:X}" if self.cor20_rva is not None else None,
            "iat_reconstructed": self.iat_reconstructed,
            "sections_healed_count": self.sections_healed_count,
            "anomalies": self.anomalies,
            "actions": self.actions,
        }


@dataclass
class AntiDumpHealOptions:
    """Configuration knobs governing PE header and section healing."""
    target_file_alignment: int = 0x200
    target_section_alignment: int = 0x2000
    fix_dos_header: bool = True
    fix_nt_headers: bool = True
    normalize_sections: bool = True
    unmap_virtual_memory: bool = True
    reconstruct_cor20: bool = True
    reconstruct_iat: bool = True
    zeroize_security_dir: bool = True
    sanitize_section_names: bool = True
    infer_missing_sections: bool = True


@dataclass
class AntiDumpHealResult:
    """Final output report of the memory dump healing operation."""
    is_healed: bool = False
    original_size: int = 0
    healed_size: int = 0
    sha256: str = ""
    telemetry: AntiDumpTelemetry = field(default_factory=AntiDumpTelemetry)
    sections: List[HealedSectionInfo] = field(default_factory=list)
    synthesized_import: Optional[SynthesizedImportInfo] = None
    output_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_healed": self.is_healed,
            "original_size": self.original_size,
            "healed_size": self.healed_size,
            "sha256": self.sha256,
            "telemetry": self.telemetry.to_dict(),
            "sections": [s.to_dict() for s in self.sections],
            "synthesized_import": self.synthesized_import.to_dict() if self.synthesized_import else None,
            "output_path": self.output_path,
        }
