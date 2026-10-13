"""
Unpacker Engines for .NET Protectors & Assembly Bundlers.
Engineered & Audited by Maya Thorne.
"""

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
from .reactor import DotNetReactorUnpacker

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
]
