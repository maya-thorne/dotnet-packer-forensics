"""
Deobfuscation Regression Fuzzing Harness & Synthetic Mutated Binary Generator Subpackage.
Engineered & Audited by Maya Thorne.
"""

from .generator import SyntheticMutatedBinaryGenerator
from .harness import RegressionFuzzingHarness
from .models import (
    CrashSeverity,
    FuzzCampaignResult,
    FuzzCampaignTelemetry,
    FuzzExecutionResult,
    FuzzTarget,
    MutationRecord,
    MutationStrategy,
    RegressionLedger,
    SecurityError,
    safe_path,
    zeroize_buffer,
)

__all__ = [
    "CrashSeverity",
    "FuzzCampaignResult",
    "FuzzCampaignTelemetry",
    "FuzzExecutionResult",
    "FuzzTarget",
    "MutationRecord",
    "MutationStrategy",
    "RegressionFuzzingHarness",
    "RegressionLedger",
    "SecurityError",
    "SyntheticMutatedBinaryGenerator",
    "safe_path",
    "zeroize_buffer",
]
