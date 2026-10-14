"""
Dynamic Sigma Rule Synthesizer for .NET & PE Threat Hunting.
Engineered & Audited by Maya Thorne.
"""

import uuid
from typing import Any, Dict, List, Optional

from .models import ExtractedThreatFeatures, RuleGranularity, RuleSeverity, SigmaRule


class SigmaSynthesizer:
    """Synthesizes high-fidelity, spec-compliant Sigma detection rules (YAML format)."""

    NAMESPACE_UUID = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

    @classmethod
    def generate_rules(
        cls,
        features: ExtractedThreatFeatures,
        granularity: RuleGranularity = RuleGranularity.BEHAVIORAL,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[SigmaRule]:
        """Generates Sigma rules based on requested granularity level."""
        options = options or {}
        rules: List[SigmaRule] = []

        if granularity == RuleGranularity.SPECIFIC:
            rules.append(cls._synthesize_specific_process_creation(features, options))
            rules.append(cls._synthesize_specific_file_drop(features, options))
        elif granularity == RuleGranularity.BEHAVIORAL:
            rules.extend(cls._synthesize_behavioral_rules(features, options))
        elif granularity == RuleGranularity.HUNT:
            rules.extend(cls._synthesize_hunting_rules(features, options))

        return rules

    @classmethod
    def _generate_rule_id(cls, seed: str) -> str:
        """Generates a deterministic UUID v5 from a seed string."""
        return str(uuid.uuid5(cls.NAMESPACE_UUID, f"dotnet.packer.{seed}"))

    @classmethod
    def _synthesize_specific_process_creation(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> SigmaRule:
        """Synthesizes a specific process creation Sigma rule targeting the exact binary hash and name."""
        author = options.get("author", "Maya Thorne")
        date = options.get("date", "2026-10-14")
        short_hash = features.sha256[:12]
        title = f"Execution of Packed .NET Binary - {features.file_name} ({short_hash})"
        rule_id = cls._generate_rule_id(f"specific.process.{features.sha256}")

        selection: Dict[str, Any] = {
            "Hashes|contains": [
                f"SHA256={features.sha256.upper()}",
                f"SHA256={features.sha256.lower()}",
            ]
        }
        if features.imphash:
            selection["Imphash"] = features.imphash.lower()

        detection = {
            "selection": selection,
            "condition": "selection",
        }

        return SigmaRule(
            title=title,
            id=rule_id,
            status="test",
            description=f"Detects execution of specific packed or obfuscated .NET binary {features.file_name} via SHA-256 / Imphash.",
            references=["https://github.com/maya-thorne/dotnet-packer-forensics"],
            author=author,
            date=date,
            tags=[
                "attack.defense_evasion",
                "attack.t1027",
                "attack.t1027.002",
                "attack.execution",
            ],
            logsource={
                "category": "process_creation",
                "product": "windows",
            },
            detection=detection,
            level=RuleSeverity.HIGH,
            falsepositives=["Legitimate software verified with valid digital signature"],
        )

    @classmethod
    def _synthesize_specific_file_drop(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> SigmaRule:
        """Synthesizes a file event Sigma rule targeting binary drop or creation."""
        author = options.get("author", "Maya Thorne")
        date = options.get("date", "2026-10-14")
        short_hash = features.sha256[:12]
        title = f"Packed .NET Binary Dropped on Disk - {features.file_name} ({short_hash})"
        rule_id = cls._generate_rule_id(f"specific.file.{features.sha256}")

        detection = {
            "selection": {
                "TargetFilename|endswith": [
                    f"\\{features.file_name}",
                    f"\\Temp\\{features.file_name}",
                ],
                "Hashes|contains": f"SHA256={features.sha256.upper()}",
            },
            "condition": "selection",
        }

        return SigmaRule(
            title=title,
            id=rule_id,
            status="test",
            description=f"Detects creation or drop of specific packed .NET binary {features.file_name} in filesystem.",
            references=["https://github.com/maya-thorne/dotnet-packer-forensics"],
            author=author,
            date=date,
            tags=[
                "attack.defense_evasion",
                "attack.t1027",
                "attack.t1027.002",
            ],
            logsource={
                "category": "file_event",
                "product": "windows",
            },
            detection=detection,
            level=RuleSeverity.HIGH,
            falsepositives=["Installation or build pipelines in developer workstations"],
        )

    @classmethod
    def _synthesize_behavioral_rules(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> List[SigmaRule]:
        """Synthesizes behavioral detection rules targeting protector execution behaviors."""
        rules: List[SigmaRule] = []
        author = options.get("author", "Maya Thorne")
        date = options.get("date", "2026-10-14")

        # 1. Suspicious Process Execution from Temp / AppData
        rule_id = cls._generate_rule_id(f"behavioral.suspicious_path.{features.sha256[:16]}")
        detection = {
            "selection_paths": {
                "Image|contains": [
                    "\\AppData\\Local\\Temp\\",
                    "\\AppData\\Roaming\\",
                    "\\Windows\\Temp\\",
                    "\\ProgramData\\",
                ]
            },
            "selection_modules": {
                "CommandLine|contains": [
                    "costura",
                    "confuser",
                    "reactor",
                    "eazfuscator",
                    "babel",
                    "armdot",
                ]
            },
            "condition": "selection_paths and selection_modules",
        }

        rules.append(
            SigmaRule(
                title="Execution of Packed .NET Assembly from Staging Directory",
                id=rule_id,
                status="experimental",
                description="Detects suspicious execution of packed .NET binaries containing obfuscator artifacts from temporary directories.",
                references=["https://github.com/maya-thorne/dotnet-packer-forensics"],
                author=author,
                date=date,
                tags=[
                    "attack.defense_evasion",
                    "attack.t1027.002",
                    "attack.execution",
                ],
                logsource={
                    "category": "process_creation",
                    "product": "windows",
                },
                detection=detection,
                level=RuleSeverity.MEDIUM,
                falsepositives=["Legitimate software updaters and installers executing from Temp"],
            )
        )

        # 2. xorPacker or Overlay Payload Execution
        if features.has_xor_packer or features.has_overlay:
            overlay_id = cls._generate_rule_id(f"behavioral.overlay_exec.{features.sha256[:16]}")
            overlay_detection = {
                "selection": {
                    "CommandLine|contains": [
                        "***randomkey",
                        "xorStub",
                        "-unpack",
                        "--deobfuscate",
                    ]
                },
                "condition": "selection",
            }
            rules.append(
                SigmaRule(
                    title="Suspicious xorPacker Overlay Command-Line Execution",
                    id=overlay_id,
                    status="test",
                    description="Detects execution or invocation of binaries passing dynamic xorPacker overlay tokens via command-line arguments.",
                    references=["https://github.com/maya-thorne/dotnet-packer-forensics"],
                    author=author,
                    date=date,
                    tags=[
                        "attack.defense_evasion",
                        "attack.t1027",
                    ],
                    logsource={
                        "category": "process_creation",
                        "product": "windows",
                    },
                    detection=overlay_detection,
                    level=RuleSeverity.HIGH,
                )
            )

        return rules

    @classmethod
    def _synthesize_hunting_rules(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> List[SigmaRule]:
        """Synthesizes broad threat hunting Sigma rules for SIEM telemetry correlation."""
        rules: List[SigmaRule] = []
        author = options.get("author", "Maya Thorne")
        date = options.get("date", "2026-10-14")

        # 1. Image Load Rule: CLR Bootstrap with Untrusted Image
        img_id = cls._generate_rule_id(f"hunt.image_load_clr.{features.sha256[:16]}")
        detection = {
            "selection_clr": {
                "ImageLoaded|endswith": [
                    "\\mscoree.dll",
                    "\\clr.dll",
                    "\\coreclr.dll",
                ]
            },
            "selection_untrusted": {
                "Image|contains": [
                    "\\AppData\\Local\\Temp\\",
                    "\\Users\\Public\\",
                    "\\PerfLogs\\",
                ]
            },
            "condition": "selection_clr and selection_untrusted",
        }

        rules.append(
            SigmaRule(
                title="Suspicious CLR Runtime Library Load from Untrusted Path",
                id=img_id,
                status="experimental",
                description="Hunts for image load events where mscoree.dll or CLR runtime is loaded by executables running from writable public or temp directories.",
                references=["https://github.com/maya-thorne/dotnet-packer-forensics"],
                author=author,
                date=date,
                tags=[
                    "attack.defense_evasion",
                    "attack.t1027",
                    "attack.t1055",
                ],
                logsource={
                    "category": "image_load",
                    "product": "windows",
                },
                detection=detection,
                level=RuleSeverity.MEDIUM,
                falsepositives=["Portable standalone .NET tools executed by administrators"],
            )
        )

        return rules
