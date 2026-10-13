"""
Unpacker Engines for .NET Protectors & Assembly Bundlers.
Engineered & Audited by Maya Thorne.
"""

from .armdot import (
    ArmDotDevirtualizer,
    ArmDotInstruction,
    ArmDotOpcode,
    ArmDotOpcodeTable,
    ArmDotUnpacker,
    ArmDotVMDisassembler,
)
from .babel import BabelUnpacker
from .babel_demangler import (
    AssemblyNode,
    BabelDemangler,
    DemangleRule,
    DemangledSymbol,
    DependencyGraph,
)
from .confuserex import ConfuserExUnpacker
from .confuserex_constants import ConfuserExConstantsDecryptor
from .costura import CosturaUnpacker
from .eazfuscator import EazfuscatorUnpacker
from .eazfuscator_vm import (
    EazfuscatorDevirtualizer,
    EazfuscatorVMDisassembler,
    VMInstruction,
    VMOpcode,
    VMOpcodeTable,
)
from .deepsea import DeepSeaUnpacker
from .deepsea_deflattener import (
    ASTReconstructor,
    CILDisassembler,
    CILEmitter,
    DeepSeaDeflattener,
    OpaquePredicateEliminator,
)
from .deepsea_models import (
    ASTBlock,
    ASTIf,
    ASTMethod,
    ASTNode,
    ASTStatement,
    ASTWhile,
    BasicBlock,
    CILInstruction,
    CILOpcode,
    CILOperandType,
    ControlFlowGraph,
    FlowControl,
)
from .antitamper import AntiTamperUnpacker
from .antitamper_jit import (
    AntiTamperDecrypter,
    CorILMethodParser,
    JITDumperInterface,
)
from .antitamper_models import (
    AntiTamperDetectionResult,
    AntiTamperSectionInfo,
    AntiTamperType,
    CorILMethodFormat,
    CorILMethodHeader,
    JITMethodRecord,
)
from .intellilock import IntelliLockUnpacker
from .intellilock_models import (
    HardwareProfile,
    IntelliLockMetadata,
    LicenseStatus,
    LockType,
    SecurityError,
    VirtualLicense,
)
from .reactor import DotNetReactorUnpacker

from .antidump import AntiDumpUnpacker
from .antidump_healer import AntiDumpHealer
from .antidump_models import (
    AntiDumpHealOptions,
    AntiDumpHealResult,
    AntiDumpTechnique,
    AntiDumpTelemetry,
    DumpSource,
    HealedSectionInfo,
    SectionType,
    SynthesizedImportInfo,
)

__all__ = [
    "CosturaUnpacker",
    "ConfuserExUnpacker",
    "ConfuserExConstantsDecryptor",
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
    "AntiTamperUnpacker",
    "AntiTamperDecrypter",
    "CorILMethodParser",
    "JITDumperInterface",
    "AntiTamperType",
    "CorILMethodFormat",
    "CorILMethodHeader",
    "JITMethodRecord",
    "AntiTamperDetectionResult",
    "AntiTamperSectionInfo",
    "AntiDumpUnpacker",
    "AntiDumpHealer",
    "AntiDumpHealOptions",
    "AntiDumpHealResult",
    "AntiDumpTechnique",
    "AntiDumpTelemetry",
    "DumpSource",
    "HealedSectionInfo",
    "SectionType",
    "SynthesizedImportInfo",
]

