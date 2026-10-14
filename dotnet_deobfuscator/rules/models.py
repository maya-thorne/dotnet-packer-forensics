"""
Data Models and Enums for Automated Threat Hunting YARA & Sigma Rule Synthesizer.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SecurityError(Exception):
    """Raised when bounds checks, sanitization, or path safety constraints are violated."""
    pass


class RuleFormat(str, Enum):
    """Target detection rule format."""
    YARA = "yara"
    SIGMA = "sigma"
    COMBINED = "combined"


class RuleGranularity(str, Enum):
    """Granularity and strictness level for synthesized rules."""
    SPECIFIC = "specific"
    BEHAVIORAL = "behavioral"
    HUNT = "hunt"


class RuleSeverity(str, Enum):
    """Severity or alert level for detection rules."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class YARARule:
    """Represents a syntactically valid, production-ready YARA rule."""
    rule_name: str
    meta: Dict[str, Any]
    strings: List[Tuple[str, str, str]]  # (identifier e.g. "$s1", value/modifier, comment)
    condition: str
    imports: List[str] = field(default_factory=lambda: ["pe"])
    tags: List[str] = field(default_factory=list)

    def to_yara_string(self) -> str:
        """Serializes the rule into pristine, formatted YARA v4+ text."""
        lines: List[str] = []

        # 1. Imports
        for imp in sorted(set(self.imports)):
            lines.append(f'import "{imp}"')
        if self.imports:
            lines.append("")

        # 2. Rule declaration & tags
        tag_str = (" : " + " ".join(self.tags)) if self.tags else ""
        lines.append(f"rule {self.rule_name}{tag_str} {{")

        # 3. Meta block
        lines.append("    meta:")
        for k, v in self.meta.items():
            if isinstance(v, bool):
                val_str = "true" if v else "false"
            elif isinstance(v, (int, float)):
                val_str = str(v)
            else:
                escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
                val_str = f'"{escaped}"'
            lines.append(f"        {k} = {val_str}")

        # 4. Strings block
        if self.strings:
            lines.append("    strings:")
            for ident, val, comment in self.strings:
                comment_str = f" // {comment}" if comment else ""
                lines.append(f"        {ident} = {val}{comment_str}")

        # 5. Condition block
        lines.append("    condition:")
        cond_lines = self.condition.strip().split("\n")
        for cline in cond_lines:
            lines.append(f"        {cline.strip()}")

        lines.append("}")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "tags": self.tags,
            "imports": self.imports,
            "meta": self.meta,
            "strings_count": len(self.strings),
            "condition": self.condition,
            "raw_rule": self.to_yara_string(),
        }


@dataclass
class SigmaRule:
    """Represents a valid, production-ready Sigma detection rule (Sigma Spec v2)."""
    title: str
    id: str
    status: str
    description: str
    references: List[str]
    author: str
    date: str
    tags: List[str]
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    level: RuleSeverity
    modified: Optional[str] = None
    falsepositives: List[str] = field(default_factory=lambda: ["Administrative activity", "Legitimate internal software"])

    def to_sigma_yaml(self) -> str:
        """Serializes the rule into standard Sigma YAML representation without external dependencies."""
        lines: List[str] = []
        lines.append(f"title: {self.title}")
        lines.append(f"id: {self.id}")
        lines.append(f"status: {self.status}")
        lines.append(f"description: {self.description}")
        if self.references:
            lines.append("references:")
            for ref in self.references:
                lines.append(f"    - {ref}")
        lines.append(f"author: {self.author}")
        lines.append(f"date: {self.date}")
        if self.modified:
            lines.append(f"modified: {self.modified}")
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"    - {tag}")

        lines.append("logsource:")
        for k, v in self.logsource.items():
            lines.append(f"    {k}: {v}")

        lines.append("detection:")
        for sel_name, sel_val in self.detection.items():
            if sel_name == "condition":
                continue
            lines.append(f"    {sel_name}:")
            if isinstance(sel_val, dict):
                for k, v in sel_val.items():
                    if isinstance(v, list):
                        lines.append(f"        {k}:")
                        for item in v:
                            lines.append(f"            - '{item}'")
                    else:
                        lines.append(f"        {k}: '{v}'")
            elif isinstance(sel_val, list):
                for item in sel_val:
                    lines.append(f"        - '{item}'")
            else:
                lines.append(f"        '{sel_val}'")

        cond = self.detection.get("condition", "selection")
        lines.append(f"    condition: {cond}")

        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"    - {fp}")

        lines.append(f"level: {self.level.value}")
        return "\n".join(lines) + "\n"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "tags": self.tags,
            "logsource": self.logsource,
            "level": self.level.value,
            "raw_yaml": self.to_sigma_yaml(),
        }


@dataclass
class ExtractedThreatFeatures:
    """Forensic threat markers and structural features extracted from binary."""
    file_name: str
    file_size: int
    sha256: str
    sha1: str
    md5: str
    imphash: Optional[str]
    is_pe: bool
    is_dotnet: bool
    machine_type: str
    subsystem: str
    section_count: int
    section_names: List[str]
    section_entropies: List[Tuple[str, float]]
    high_entropy_sections: List[Tuple[str, float]]
    suspicious_indicators: List[str]
    detected_protectors: List[Dict[str, Any]]
    has_overlay: bool
    overlay_size: int
    overlay_entropy: float
    has_xor_packer: bool
    xor_key: Optional[str]
    cor20_entry_point: Optional[int]
    metadata_streams: List[str]
    bytecode_patterns: List[Tuple[str, bytes, str]] = field(default_factory=list)
    string_markers: List[str] = field(default_factory=list)
    native_architectures: List[str] = field(default_factory=list)
    anti_dump_active: bool = False
    anti_tamper_active: bool = False
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "imphash": self.imphash,
            "is_pe": self.is_pe,
            "is_dotnet": self.is_dotnet,
            "machine_type": self.machine_type,
            "subsystem": self.subsystem,
            "section_count": self.section_count,
            "section_names": self.section_names,
            "high_entropy_sections": self.high_entropy_sections,
            "suspicious_indicators": self.suspicious_indicators,
            "detected_protectors": self.detected_protectors,
            "has_overlay": self.has_overlay,
            "overlay_size": self.overlay_size,
            "overlay_entropy": round(self.overlay_entropy, 4),
            "has_xor_packer": self.has_xor_packer,
            "xor_key": self.xor_key,
            "cor20_entry_point": self.cor20_entry_point,
            "metadata_streams": self.metadata_streams,
            "string_markers": self.string_markers,
            "native_architectures": self.native_architectures,
            "anti_dump_active": self.anti_dump_active,
            "anti_tamper_active": self.anti_tamper_active,
            "anomalies": self.anomalies,
        }


@dataclass
class RuleGenerationResult:
    """Complete collection of generated YARA and Sigma rules along with telemetry."""
    target_file: str
    granularity: RuleGranularity
    features: ExtractedThreatFeatures
    yara_rules: List[YARARule] = field(default_factory=list)
    sigma_rules: List[SigmaRule] = field(default_factory=list)
    generation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_file": self.target_file,
            "granularity": self.granularity.value,
            "generation_time_ms": round(self.generation_time_ms, 3),
            "yara_rules_count": len(self.yara_rules),
            "sigma_rules_count": len(self.sigma_rules),
            "yara_rules": [r.to_dict() for r in self.yara_rules],
            "sigma_rules": [r.to_dict() for r in self.sigma_rules],
            "features": self.features.to_dict(),
        }
