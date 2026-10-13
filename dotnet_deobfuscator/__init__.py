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
from .unpackers.armdot import (
    ArmDotDevirtualizer,
    ArmDotInstruction,
    ArmDotOpcode,
    ArmDotOpcodeTable,
    ArmDotUnpacker,
    ArmDotVMDisassembler,
)
from .unpackers.babel import BabelUnpacker
from .unpackers.babel_demangler import (
    AssemblyNode,
    BabelDemangler,
    DemangleRule,
    DemangledSymbol,
    DependencyGraph,
)
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
from .unpackers.deepsea import DeepSeaUnpacker
from .unpackers.deepsea_deflattener import (
    ASTReconstructor,
    CILDisassembler,
    CILEmitter,
    DeepSeaDeflattener,
    OpaquePredicateEliminator,
)
from .unpackers.deepsea_models import (
    ASTBlock,
    ASTIf,
    ASTMethod,
    ASTNode,
    ASTStatement,
    ASTWhile,
    BasicBlock,
    CILInstruction,
    CILOpcode,
    ControlFlowGraph,
)
from .unpackers.intellilock import IntelliLockUnpacker
from .unpackers.intellilock_models import (
    HardwareProfile,
    IntelliLockMetadata,
    LicenseStatus,
    LockType,
    SecurityError,
    VirtualLicense,
)
from .unpackers.reactor import DotNetReactorUnpacker

__version__ = "2.0.0"
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
    "BabelUnpacker",
    "BabelDemangler",
    "DemangleRule",
    "DemangledSymbol",
    "AssemblyNode",
    "DependencyGraph",
    "ArmDotUnpacker",
    "ArmDotOpcode",
    "ArmDotOpcodeTable",
    "ArmDotInstruction",
    "ArmDotVMDisassembler",
    "ArmDotDevirtualizer",
    "IntelliLockUnpacker",
    "IntelliLockMetadata",
    "HardwareProfile",
    "VirtualLicense",
    "LockType",
    "LicenseStatus",
    "SecurityError",
    "DeepSeaUnpacker",
    "DeepSeaDeflattener",
    "CILDisassembler",
    "CILEmitter",
    "OpaquePredicateEliminator",
    "ASTReconstructor",
    "CILOpcode",
    "CILInstruction",
    "BasicBlock",
    "ControlFlowGraph",
    "ASTNode",
    "ASTMethod",
    "ASTBlock",
    "ASTStatement",
    "ASTIf",
    "ASTWhile",
    "__version__",
]
