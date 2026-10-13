"""
CLI Metadata Anti-Tamper & In-Memory JIT Dumper Data Models.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple


class SecurityError(Exception):
    """Raised when security boundaries or bounds limits are violated."""
    pass


class AntiTamperType(Enum):
    """Identified category of .NET anti-tampering protection."""
    NONE = "None"
    CONFUSEREX_JIT = "ConfuserEx JIT Hook AntiTamper"
    CONFUSEREX_NORMAL = "ConfuserEx Normal AntiTamper"
    JIT_HOOK = "Generic CLR JIT Hook"
    CORRUPTED_METADATA = "Corrupted CLI Metadata Stream"
    ENCRYPTED_METHODS = "Encrypted CIL Method Bodies"
    CUSTOM_SECTION = "Custom Anti-Tamper PE Section"


class CorILMethodFormat(Enum):
    """ECMA-335 CIL Method Header format types."""
    TINY = "Tiny"
    FAT = "Fat"


@dataclass
class CorILMethodHeader:
    """Parsed ECMA-335 CorILMethod header structure."""
    format: CorILMethodFormat
    header_size: int
    code_size: int
    max_stack: int
    local_var_sig_tok: int
    flags: int
    code_bytes: bytes
    raw_header_bytes: bytes
    extra_sections: bytes = b""

    @property
    def total_size(self) -> int:
        return self.header_size + self.code_size + len(self.extra_sections)

    @property
    def raw_body(self) -> bytes:
        return self.raw_header_bytes + self.code_bytes + self.extra_sections

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format.value,
            "header_size": self.header_size,
            "code_size": self.code_size,
            "max_stack": self.max_stack,
            "local_var_sig_tok": f"0x{self.local_var_sig_tok:08X}" if self.local_var_sig_tok else "0x00000000",
            "flags": f"0x{self.flags:04X}",
            "extra_sections_size": len(self.extra_sections),
            "total_size": self.total_size,
        }


@dataclass
class JITMethodRecord:
    """Decrypted or in-memory dumped CIL method record."""
    token: int
    rid: int
    name: str
    rva: int
    format: str
    code_size: int
    max_stack: int
    local_var_sig_tok: int
    cil_bytes: bytes
    raw_method_body: bytes
    sha256: str = ""
    verified_cil: bool = True

    def __post_init__(self) -> None:
        if not self.sha256 and self.raw_method_body:
            self.sha256 = hashlib.sha256(self.raw_method_body).hexdigest()

    @property
    def token_hex(self) -> str:
        return f"0x{self.token:08X}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token_hex,
            "rid": self.rid,
            "name": self.name,
            "rva": f"0x{self.rva:08X}",
            "format": self.format,
            "code_size": self.code_size,
            "max_stack": self.max_stack,
            "local_var_sig_tok": f"0x{self.local_var_sig_tok:08X}" if self.local_var_sig_tok else "0x00000000",
            "cil_hex": self.cil_bytes.hex(),
            "sha256": self.sha256,
            "verified_cil": self.verified_cil,
            "body_size": len(self.raw_method_body),
        }


@dataclass
class AntiTamperSectionInfo:
    """Forensic details of PE sections associated with anti-tamper mechanisms."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    entropy: float
    is_encrypted: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "virtual_address": f"0x{self.virtual_address:08X}",
            "virtual_size": self.virtual_size,
            "raw_pointer": f"0x{self.raw_pointer:08X}",
            "raw_size": self.raw_size,
            "entropy": round(self.entropy, 4),
            "is_encrypted": self.is_encrypted,
        }


@dataclass
class AntiTamperDetectionResult:
    """Detection findings and confidence evaluation for Anti-Tamper protections."""
    is_tampered: bool
    confidence: str
    detected_types: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    encrypted_methods_count: int = 0
    corrupted_streams: List[str] = field(default_factory=list)
    jit_signatures: List[str] = field(default_factory=list)
    anti_tamper_sections: List[str] = field(default_factory=list)
    entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_tampered": self.is_tampered,
            "confidence": self.confidence,
            "detected_types": self.detected_types,
            "indicators": self.indicators,
            "encrypted_methods_count": self.encrypted_methods_count,
            "corrupted_streams": self.corrupted_streams,
            "jit_signatures": self.jit_signatures,
            "anti_tamper_sections": self.anti_tamper_sections,
            "entropy": round(self.entropy, 4),
        }


def token_to_hex(token: int) -> str:
    """Formats 32-bit metadata token as hexadecimal string."""
    return f"0x{token:08X}"


def hex_to_token(val: str) -> int:
    """Parses hexadecimal or decimal string to 32-bit metadata token."""
    s = val.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)
