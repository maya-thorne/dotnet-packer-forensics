"""
Unified Threat Hunting Rule Synthesizer Engine & Exporter.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

from .feature_extractor import ThreatFeatureExtractor
from .models import (
    ExtractedThreatFeatures,
    RuleFormat,
    RuleGranularity,
    RuleGenerationResult,
    SecurityError,
)
from .sigma_synthesizer import SigmaSynthesizer
from .yara_synthesizer import YARASynthesizer


class ThreatRuleEngine:
    """Orchestrates feature extraction, YARA/Sigma synthesis, and safe disk export."""

    @classmethod
    def synthesize_from_bytes(
        cls,
        data: bytes,
        file_name: str = "target.exe",
        granularity: RuleGranularity = RuleGranularity.BEHAVIORAL,
        rule_format: RuleFormat = RuleFormat.COMBINED,
        options: Optional[Dict[str, Any]] = None,
    ) -> RuleGenerationResult:
        """Synthesizes detection rules from in-memory binary data."""
        start_time = time.perf_counter()
        options = options or {}

        # 1. Extract structural and behavioral features
        features = ThreatFeatureExtractor.extract_from_bytes(data, file_name=file_name)

        # 2. Synthesize YARA rules if requested
        yara_rules = []
        if rule_format in (RuleFormat.YARA, RuleFormat.COMBINED):
            yara_rules = YARASynthesizer.generate_rules(features, granularity=granularity, options=options)

        # 3. Synthesize Sigma rules if requested
        sigma_rules = []
        if rule_format in (RuleFormat.SIGMA, RuleFormat.COMBINED):
            sigma_rules = SigmaSynthesizer.generate_rules(features, granularity=granularity, options=options)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return RuleGenerationResult(
            target_file=file_name,
            granularity=granularity,
            features=features,
            yara_rules=yara_rules,
            sigma_rules=sigma_rules,
            generation_time_ms=elapsed_ms,
        )

    @classmethod
    def synthesize_from_file(
        cls,
        file_path: str,
        granularity: RuleGranularity = RuleGranularity.BEHAVIORAL,
        rule_format: RuleFormat = RuleFormat.COMBINED,
        options: Optional[Dict[str, Any]] = None,
    ) -> RuleGenerationResult:
        """Synthesizes detection rules from a binary file on disk."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary file not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size > 200 * 1024 * 1024:
            raise SecurityError(f"Target binary exceeds 200MB limit: {file_size} bytes")

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.synthesize_from_bytes(
            data=data,
            file_name=os.path.basename(file_path),
            granularity=granularity,
            rule_format=rule_format,
            options=options,
        )

    @classmethod
    def export_to_directory(
        cls, result: RuleGenerationResult, output_dir: str
    ) -> Dict[str, Any]:
        """Safely exports synthesized YARA and Sigma rules along with a JSON manifest to disk."""
        real_out = os.path.realpath(output_dir)
        os.makedirs(real_out, exist_ok=True)

        written_files: List[str] = []

        # 1. Export YARA rules
        if result.yara_rules:
            yara_path = cls._safe_path(real_out, "yara_rules.yar")
            with open(yara_path, "w", encoding="utf-8") as f:
                f.write("// ==============================================================================\n")
                f.write(f"// YARA Rules Synthesized for {result.target_file} ({result.granularity.value})\n")
                f.write("// Engineered & Audited by Maya Thorne\n")
                f.write("// ==============================================================================\n\n")
                for r in result.yara_rules:
                    f.write(r.to_yara_string())
                    f.write("\n")
            written_files.append(yara_path)

        # 2. Export individual Sigma rules
        for idx, s in enumerate(result.sigma_rules):
            sig_name = f"sigma_{idx + 1}_{s.id[:8]}.yml"
            sig_path = cls._safe_path(real_out, sig_name)
            with open(sig_path, "w", encoding="utf-8") as f:
                f.write(s.to_sigma_yaml())
            written_files.append(sig_path)

        # 3. Export Manifest
        manifest_path = cls._safe_path(real_out, "rules_manifest.json")
        manifest_data = {
            "target_file": result.target_file,
            "granularity": result.granularity.value,
            "generation_time_ms": round(result.generation_time_ms, 3),
            "yara_rules_count": len(result.yara_rules),
            "sigma_rules_count": len(result.sigma_rules),
            "yara_rule_names": [r.rule_name for r in result.yara_rules],
            "sigma_rule_titles": [s.title for s in result.sigma_rules],
            "target_hashes": {
                "sha256": result.features.sha256,
                "sha1": result.features.sha1,
                "md5": result.features.md5,
                "imphash": result.features.imphash,
            },
            "exported_files": [os.path.basename(p) for p in written_files] + ["rules_manifest.json"],
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        written_files.append(manifest_path)

        return {
            "success": True,
            "output_directory": real_out,
            "yara_rules_count": len(result.yara_rules),
            "sigma_rules_count": len(result.sigma_rules),
            "exported_files": written_files,
            "manifest": manifest_data,
        }

    @classmethod
    def _safe_path(cls, base_dir: str, rel_path: str) -> str:
        """Validates that candidate path remains strictly inside the target base directory."""
        clean_rel = os.path.normpath(rel_path).lstrip(os.path.sep).lstrip("/")
        if ".." in clean_rel.split(os.path.sep):
            raise SecurityError(f"Directory traversal attack detected in path: {rel_path}")
        target = os.path.realpath(os.path.join(base_dir, clean_rel))
        if not (target == base_dir or target.startswith(base_dir + os.path.sep)):
            raise SecurityError(f"Path escape outside base directory: {target}")
        return target
