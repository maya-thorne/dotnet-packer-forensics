"""
Dynamic YARA Rule Synthesizer for .NET & PE Threat Hunting.
Engineered & Audited by Maya Thorne.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from .models import ExtractedThreatFeatures, RuleGranularity, RuleSeverity, YARARule


class YARASynthesizer:
    """Synthesizes high-fidelity, syntactically pristine YARA rules from extracted binary features."""

    @classmethod
    def generate_rules(
        cls,
        features: ExtractedThreatFeatures,
        granularity: RuleGranularity = RuleGranularity.BEHAVIORAL,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[YARARule]:
        """Generates YARA rules based on requested granularity level."""
        options = options or {}
        rules: List[YARARule] = []

        if granularity == RuleGranularity.SPECIFIC:
            rules.append(cls._synthesize_specific_rule(features, options))
        elif granularity == RuleGranularity.BEHAVIORAL:
            rules.extend(cls._synthesize_behavioral_rules(features, options))
        elif granularity == RuleGranularity.HUNT:
            rules.extend(cls._synthesize_hunting_rules(features, options))

        return rules

    @classmethod
    def _sanitize_identifier(cls, name: str) -> str:
        """Sanitizes strings to produce valid YARA rule identifiers."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_")
        if not clean or clean[0].isdigit():
            clean = "rule_" + clean
        return clean.lower()

    @classmethod
    def _escape_string(cls, s: str) -> str:
        """Safely escapes backslashes and double quotes in YARA string literals."""
        return s.replace("\\", "\\\\").replace('"', '\\"')

    @classmethod
    def _synthesize_specific_rule(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> YARARule:
        """Synthesizes a tightly bound rule targeting an exact binary sample."""
        short_hash = features.sha256[:12]
        rule_name = f"dotnet_sample_{cls._sanitize_identifier(features.file_name)}_{short_hash}"

        meta = {
            "description": f"Specific detection rule for {features.file_name}",
            "author": options.get("author", "Maya Thorne"),
            "date": options.get("date", "2026-10-14"),
            "severity": RuleSeverity.HIGH.value,
            "target_file": features.file_name,
            "hash_sha256": features.sha256,
            "hash_sha1": features.sha1,
            "hash_md5": features.md5,
            "file_size": features.file_size,
        }
        if features.imphash:
            meta["imphash"] = features.imphash

        strings: List[Tuple[str, str, str]] = []
        cond_parts: List[str] = ["uint16(0) == 0x5A4D", "pe.is_pe"]

        # String markers
        idx = 1
        for marker in features.string_markers[:8]:
            escaped = cls._escape_string(marker)
            strings.append((f"$s{idx}", f'"{escaped}" ascii wide', f"Marker: {marker}"))
            idx += 1

        # Hex bytecode patterns
        b_idx = 1
        for p_name, p_bytes, p_desc in features.bytecode_patterns[:3]:
            hex_str = " ".join(f"{b:02X}" for b in p_bytes)
            strings.append((f"$code{b_idx}", f"{{ {hex_str} }}", f"Bytecode: {p_desc}"))
            b_idx += 1

        # Conditions
        cond_parts.append(f"filesize >= {max(1, features.file_size - 4096)} and filesize <= {features.file_size + 4096}")
        if features.section_count > 0:
            cond_parts.append(f"pe.number_of_sections == {features.section_count}")

        if strings:
            if len(strings) > 2:
                cond_parts.append(f"{min(3, len(strings))} of them")
            else:
                cond_parts.append("all of them")

        condition = " and\n".join(cond_parts)
        imports = ["pe"]
        tags = ["specific", "sample_iocs", "dotnet_packer"]

        return YARARule(
            rule_name=rule_name,
            meta=meta,
            strings=strings,
            condition=condition,
            imports=imports,
            tags=tags,
        )

    @classmethod
    def _synthesize_behavioral_rules(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> List[YARARule]:
        """Synthesizes behavioral detection rules targeting detected protector families and evasion traits."""
        rules: List[YARARule] = []
        author = options.get("author", "Maya Thorne")
        date = options.get("date", "2026-10-14")

        # 1. Rules per detected protector
        if features.detected_protectors:
            for prot in features.detected_protectors:
                p_name = prot.get("protector", "Generic")
                p_slug = cls._sanitize_identifier(p_name)
                rule_name = f"dotnet_protector_{p_slug}_behavioral"

                meta = {
                    "description": f"Behavioral signature for .NET protector {p_name}",
                    "author": author,
                    "date": date,
                    "severity": RuleSeverity.HIGH.value,
                    "protector_type": prot.get("type", "Obfuscator"),
                    "confidence": prot.get("confidence", "HIGH"),
                }

                strings: List[Tuple[str, str, str]] = []
                s_idx = 1
                for tok in prot.get("matched_tokens", []):
                    strings.append((f"$token{s_idx}", f'"{cls._escape_string(tok)}" ascii wide', f"Signature token: {tok}"))
                    s_idx += 1

                # Include section names if relevant
                sec_idx = 1
                for sname in features.section_names:
                    if sname.lower() in [".necro", ".eazvm", ".armdot", ".deepsea", ".tamper", ".cfs", ".reactor"]:
                        strings.append((f"$sec{sec_idx}", f'"{cls._escape_string(sname)}" ascii', f"Section marker: {sname}"))
                        sec_idx += 1

                cond_parts = ["uint16(0) == 0x5A4D", "pe.is_pe"]
                if strings:
                    cond_parts.append("any of them")
                else:
                    cond_parts.append("pe.is_dotnet")

                rules.append(
                    YARARule(
                        rule_name=rule_name,
                        meta=meta,
                        strings=strings,
                        condition=" and\n".join(cond_parts),
                        imports=["pe"],
                        tags=["behavioral", p_slug, "threat_hunting"],
                    )
                )

        # 2. xorPacker PE Overlay rule if present
        if features.has_xor_packer or features.has_overlay:
            rule_name = f"dotnet_packer_xorpacker_overlay_heuristic"
            meta = {
                "description": "Detects two-stage xorPacker overlay or appended encrypted PE payload",
                "author": author,
                "date": date,
                "severity": RuleSeverity.HIGH.value,
            }
            strings = [
                ("$sentinel", '"***" ascii', "xorPacker delimiter sentinel"),
                ("$key_marker", '"randomkey" ascii', "xorPacker default secret token"),
                ("$stub_marker", '"xorStub" ascii', "xorPacker decryption stub"),
            ]
            cond_parts = [
                "uint16(0) == 0x5A4D",
                "pe.is_pe",
                f"pe.overlay.size >= {max(16, features.overlay_size // 2 if features.has_overlay else 16)}",
                "any of ($sentinel, $key_marker, $stub_marker)",
            ]
            rules.append(
                YARARule(
                    rule_name=rule_name,
                    meta=meta,
                    strings=strings,
                    condition=" and\n".join(cond_parts),
                    imports=["pe"],
                    tags=["behavioral", "xorpacker", "overlay"],
                )
            )

        # 3. Fallback generic packed heuristic rule if nothing specific matched
        if not rules:
            rule_name = "dotnet_packer_generic_packed_heuristic"
            meta = {
                "description": "Heuristic detection for anomalous or packed .NET PE binaries",
                "author": author,
                "date": date,
                "severity": RuleSeverity.MEDIUM.value,
            }
            strings = [
                ("$mscoree", '"mscoree.dll" ascii wide nocase', "CLR runtime import"),
                ("$corexe", '"_CorExeMain" ascii wide', "CLR executable entrypoint"),
                ("$cordll", '"_CorDllMain" ascii wide', "CLR DLL entrypoint"),
            ]
            cond_parts = [
                "uint16(0) == 0x5A4D",
                "pe.is_pe",
                "($mscoree and ($corexe or $cordll))",
            ]
            if features.high_entropy_sections:
                cond_parts.append(f"pe.number_of_sections >= {max(1, features.section_count)}")
            rules.append(
                YARARule(
                    rule_name=rule_name,
                    meta=meta,
                    strings=strings,
                    condition=" and\n".join(cond_parts),
                    imports=["pe"],
                    tags=["heuristic", "generic_packer", "dotnet"],
                )
            )

        return rules

    @classmethod
    def _synthesize_hunting_rules(
        cls, features: ExtractedThreatFeatures, options: Dict[str, Any]
    ) -> List[YARARule]:
        """Synthesizes broad threat hunting rules for proactive SOC / DFIR scanning."""
        rules: List[YARARule] = []
        author = options.get("author", "Maya Thorne")
        date = options.get("date", "2026-10-14")

        # 1. High-Entropy Packed Section Hunting Rule
        rules.append(
            YARARule(
                rule_name="dotnet_hunt_high_entropy_packed_section",
                meta={
                    "description": "Broad hunting rule for .NET assemblies with high-entropy non-resource sections",
                    "author": author,
                    "date": date,
                    "severity": RuleSeverity.MEDIUM.value,
                    "mitre_technique": "T1027.002",
                },
                strings=[
                    ("$cor1", '"_CorExeMain" ascii wide', "CLR execution stub"),
                    ("$cor2", '"_CorDllMain" ascii wide', "CLR library stub"),
                    ("$mscoree", '"mscoree.dll" ascii wide nocase', "CLR bootstrap DLL"),
                ],
                condition=(
                    "uint16(0) == 0x5A4D and\n"
                    "pe.is_pe and\n"
                    "($mscoree and ($cor1 or $cor2)) and\n"
                    "for any section in pe.sections :\n"
                    '    (section.name != ".rsrc" and math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.2)'
                ),
                imports=["pe", "math"],
                tags=["hunting", "high_entropy", "packed_dotnet"],
            )
        )

        # 2. Anti-Dump Erased Header Hunting Rule
        if features.anti_dump_active or "Missing or corrupted DOS magic ('MZ')" in features.anomalies:
            rules.append(
                YARARule(
                    rule_name="dotnet_hunt_antidump_erased_pe_header",
                    meta={
                        "description": "Threat hunting rule for memory dumps with erased DOS/NT headers and BSJB metadata",
                        "author": author,
                        "date": date,
                        "severity": RuleSeverity.HIGH.value,
                        "mitre_technique": "T1497 / T1027",
                    },
                    strings=[
                        ("$bsjb", '"BSJB" ascii', "CLR Metadata Root Signature"),
                        ("$antidump", '"AntiDump" ascii wide', "Anti-dump indicator"),
                    ],
                    condition=(
                        "($bsjb and ($antidump or uint16(0) != 0x5A4D)) or\n"
                        "(uint32(uint32(0x3C)) == 0x00004550 and uint16(0) != 0x5A4D)"
                    ),
                    imports=["pe"],
                    tags=["hunting", "antidump", "memory_dump"],
                )
            )

        # 3. Multi-Architecture Native Demuxer Carrier Hunting Rule
        if features.native_architectures or any("costura" in m.lower() for m in features.string_markers):
            rules.append(
                YARARule(
                    rule_name="dotnet_hunt_native_multiarch_carrier",
                    meta={
                        "description": "Hunting rule for .NET carrier assemblies embedding multi-architecture native binaries",
                        "author": author,
                        "date": date,
                        "severity": RuleSeverity.MEDIUM.value,
                        "mitre_technique": "T1027.001",
                    },
                    strings=[
                        ("$costura32", '"costura32." ascii wide', "32-bit embedded payload prefix"),
                        ("$costura64", '"costura64." ascii wide', "64-bit embedded payload prefix"),
                        ("$runtimes_rid", '"runtimes/win-x64/native" ascii wide', "NuGet native runtime catalog"),
                        ("$runtimes_arm", '"runtimes/win-arm64/native" ascii wide', "ARM64 runtime catalog"),
                    ],
                    condition=(
                        "uint16(0) == 0x5A4D and\n"
                        "pe.is_pe and\n"
                        "(any of ($costura*) or any of ($runtimes*))"
                    ),
                    imports=["pe"],
                    tags=["hunting", "native_demuxer", "multi_arch"],
                )
            )

        return rules
