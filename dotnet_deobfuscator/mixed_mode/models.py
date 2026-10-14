"""
Native Mixed-Mode PE & CIL-Native Transition Models.
Defines data structures, enums, and telemetry models for C++/CLI (IJWH) forensic analysis.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum, IntFlag
import os
from typing import Any, Dict, List, Optional


class SecurityError(Exception):
    """Raised when security boundaries or bounds checks are violated."""
    pass


class MixedModeType(str, Enum):
    """Classification of PE executable regarding managed and native code composition."""
    PURE_MANAGED = "pure_managed"
    MIXED_MODE_IJWH = "mixed_mode_ijwh"
    PURE_NATIVE = "pure_native"
    CORRUPTED_OR_ANOMALOUS = "corrupted_or_anomalous"


class VTFixupType(str, Enum):
    """VTable Fixup slot width type."""
    SLOT_32BIT = "slot_32bit"
    SLOT_64BIT = "slot_64bit"


class VTFixupFlag(IntFlag):
    """COR_VTABLE fixup flags from ECMA-335 and CorHdr.h."""
    COR_VTABLE_32BIT = 0x01
    COR_VTABLE_64BIT = 0x02
    COR_VTABLE_FROM_UNMANAGED = 0x04
    COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN = 0x08
    COR_VTABLE_CALL_MOST_DERIVED = 0x10


class Cor20Flag(IntFlag):
    """CLR Cor20Header.Flags bitmask values."""
    COMIMAGE_FLAGS_ILONLY = 0x00000001
    COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000


class TransitionDirection(str, Enum):
    """Direction of execution flow across managed / native boundary."""
    NATIVE_TO_MANAGED = "native_to_managed"
    MANAGED_TO_NATIVE = "managed_to_native"
    BIDIRECTIONAL = "bidirectional"
    INTERNAL_NATIVE = "internal_native"


class TransitionType(str, Enum):
    """Mechanism facilitating execution transition."""
    VTFIXUP_THUNK = "vtfixup_thunk"
    UNMANAGED_EXPORT = "unmanaged_export"
    NATIVE_ENTRYPOINT = "native_entrypoint"
    TLS_CALLBACK = "tls_callback"
    PINVOKE_CALL = "pinvoke_call"
    REVERSE_PINVOKE = "reverse_pinvoke"


class RiskSeverity(str, Enum):
    """Severity of mixed-mode security and obfuscation risk."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VTFixupSlot:
    """Individual VTable fixup entry referencing a CLR token or function pointer."""
    slot_index: int
    slot_rva: int
    slot_offset: Optional[int]
    target_token_hex: str
    target_token_int: int
    token_type_name: str
    flags_int: int
    is_from_unmanaged: bool
    is_call_most_derived: bool
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_index": self.slot_index,
            "slot_rva": hex(self.slot_rva),
            "slot_offset": hex(self.slot_offset) if self.slot_offset is not None else None,
            "target_token": self.target_token_hex,
            "target_token_int": self.target_token_int,
            "token_type": self.token_type_name,
            "flags": hex(self.flags_int),
            "is_from_unmanaged": self.is_from_unmanaged,
            "is_call_most_derived": self.is_call_most_derived,
            "description": self.description,
        }


@dataclass
class VTFixupTable:
    """A contiguous array of VTable fixup slots governed by a single header."""
    table_index: int
    table_rva: int
    table_offset: Optional[int]
    slot_count: int
    fixup_type: VTFixupType
    flags_int: int
    flags_names: List[str]
    slots: List[VTFixupSlot] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "table_index": self.table_index,
            "table_rva": hex(self.table_rva),
            "table_offset": hex(self.table_offset) if self.table_offset is not None else None,
            "slot_count": self.slot_count,
            "fixup_type": self.fixup_type.value,
            "flags_int": hex(self.flags_int),
            "flags_names": self.flags_names,
            "slots": [s.to_dict() for s in self.slots],
        }


@dataclass
class UnmanagedExportBridge:
    """Exported PE function that bridges unmanaged callers into managed methods."""
    export_name: str
    ordinal: int
    function_rva: int
    function_offset: Optional[int]
    is_vtfixup_thunk: bool
    linked_token_hex: Optional[str]
    section_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "export_name": self.export_name,
            "ordinal": self.ordinal,
            "function_rva": hex(self.function_rva),
            "function_offset": hex(self.function_offset) if self.function_offset is not None else None,
            "is_vtfixup_thunk": self.is_vtfixup_thunk,
            "linked_token": self.linked_token_hex,
            "section_name": self.section_name,
        }


@dataclass
class TLSCallbackInfo:
    """Native TLS (Thread Local Storage) callback pre-execution hook."""
    callback_rva: int
    callback_offset: Optional[int]
    section_name: str
    is_in_code_section: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "callback_rva": hex(self.callback_rva),
            "callback_offset": hex(self.callback_offset) if self.callback_offset is not None else None,
            "section_name": self.section_name,
            "is_in_code_section": self.is_in_code_section,
        }


@dataclass
class CILNativeTransition:
    """Traced boundary transition between managed CIL and native machine code."""
    transition_id: str
    direction: TransitionDirection
    transition_type: TransitionType
    source_location: str
    target_location: str
    description: str
    is_suspicious: bool
    risk_factor: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "direction": self.direction.value,
            "transition_type": self.transition_type.value,
            "source_location": self.source_location,
            "target_location": self.target_location,
            "description": self.description,
            "is_suspicious": self.is_suspicious,
            "risk_factor": self.risk_factor,
        }


@dataclass
class MixedModeTelemetry:
    """Summary metrics, flags, and risk assessments for mixed-mode binary."""
    is_mixed_mode: bool
    mixed_mode_type: str
    confidence: str
    cor20_flags: List[str]
    has_native_entrypoint: bool
    native_entrypoint_rva: Optional[int]
    entrypoint_token_or_rva_hex: Optional[str]
    vtfixup_tables_count: int
    total_vtfixup_slots: int
    from_unmanaged_slots_count: int
    unmanaged_exports_count: int
    bridged_exports_count: int
    tls_callbacks_count: int
    transitions_count: int
    anomalies: List[str]
    risk_score: int
    risk_severity: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_mixed_mode": self.is_mixed_mode,
            "mixed_mode_type": self.mixed_mode_type,
            "confidence": self.confidence,
            "cor20_flags": self.cor20_flags,
            "has_native_entrypoint": self.has_native_entrypoint,
            "native_entrypoint_rva": hex(self.native_entrypoint_rva) if self.native_entrypoint_rva is not None else None,
            "entrypoint_token_or_rva": self.entrypoint_token_or_rva_hex,
            "vtfixup_tables_count": self.vtfixup_tables_count,
            "total_vtfixup_slots": self.total_vtfixup_slots,
            "from_unmanaged_slots_count": self.from_unmanaged_slots_count,
            "unmanaged_exports_count": self.unmanaged_exports_count,
            "bridged_exports_count": self.bridged_exports_count,
            "tls_callbacks_count": self.tls_callbacks_count,
            "transitions_count": self.transitions_count,
            "anomalies": self.anomalies,
            "risk_score": self.risk_score,
            "risk_severity": self.risk_severity,
        }


@dataclass
class MixedModeAnalysisResult:
    """Full forensic analysis package for native mixed-mode PE binary."""
    file_name: str
    file_size: int
    sha256: str
    telemetry: MixedModeTelemetry
    vtfixup_tables: List[VTFixupTable] = field(default_factory=list)
    transitions: List[CILNativeTransition] = field(default_factory=list)
    export_bridges: List[UnmanagedExportBridge] = field(default_factory=list)
    tls_callbacks: List[TLSCallbackInfo] = field(default_factory=list)
    sections_summary: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "telemetry": self.telemetry.to_dict(),
            "vtfixup_tables": [t.to_dict() for t in self.vtfixup_tables],
            "transitions": [tr.to_dict() for tr in self.transitions],
            "export_bridges": [eb.to_dict() for eb in self.export_bridges],
            "tls_callbacks": [tc.to_dict() for tc in self.tls_callbacks],
            "sections_summary": self.sections_summary,
        }
