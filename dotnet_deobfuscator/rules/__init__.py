"""
Threat Hunting Rule Generation & Synthesis Package.
Engineered & Audited by Maya Thorne.
"""

from .feature_extractor import ThreatFeatureExtractor, calculate_entropy, zeroize_buffer
from .models import (
    ExtractedThreatFeatures,
    RuleFormat,
    RuleGranularity,
    RuleGenerationResult,
    RuleSeverity,
    SecurityError,
    SigmaRule,
    YARARule,
)
from .rule_engine import ThreatRuleEngine
from .sigma_synthesizer import SigmaSynthesizer
from .yara_synthesizer import YARASynthesizer

__all__ = [
    "ThreatRuleEngine",
    "ThreatFeatureExtractor",
    "YARASynthesizer",
    "SigmaSynthesizer",
    "ExtractedThreatFeatures",
    "RuleFormat",
    "RuleGranularity",
    "RuleSeverity",
    "RuleGenerationResult",
    "YARARule",
    "SigmaRule",
    "SecurityError",
    "zeroize_buffer",
    "calculate_entropy",
]
