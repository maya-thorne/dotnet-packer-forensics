"""
dotnet-packer-forensics Python Toolchain.
Engineered & Audited by Maya Thorne.
"""

from .core import DotNetPackerCore
from .dotnet_analyzer import DotNetAnalyzer
from .payload_verifier import (
    BitwiseDiff,
    PayloadVerificationResult,
    PayloadVerifier,
    PEStructureReport,
    SectionIntegrity,
    VerificationFinding,
)
from .pe_overlay import PEOverlayParser
from .pe_rebuilder import PERebuilder, PERebuildOptions, PERebuildReport
from .signatures import ProtectorSignatures
from .unpackers.confuserex import ConfuserExUnpacker
from .unpackers.costura import CosturaUnpacker
from .unpackers.eazfuscator import EazfuscatorUnpacker
from .unpackers.eazfuscator_vm import (
    EazfuscatorDevirtualizer,
    EazfuscatorVMDisassembler,
    VMInstruction,
    VMOpcode,
    VMOpcodeTable,
)
from .unpackers.reactor import DotNetReactorUnpacker

__version__ = "1.6.0"
__author__ = "Maya Thorne"

__all__ = [
    "DotNetPackerCore",
    "DotNetAnalyzer",
    "PEOverlayParser",
    "PERebuilder",
    "PERebuildOptions",
    "PERebuildReport",
    "PayloadVerifier",
    "PayloadVerificationResult",
    "PEStructureReport",
    "SectionIntegrity",
    "BitwiseDiff",
    "VerificationFinding",
    "ProtectorSignatures",
    "CosturaUnpacker",
    "ConfuserExUnpacker",
    "DotNetReactorUnpacker",
    "EazfuscatorUnpacker",
    "VMOpcode",
    "VMOpcodeTable",
    "VMInstruction",
    "EazfuscatorVMDisassembler",
    "EazfuscatorDevirtualizer",
    "__version__",
]

