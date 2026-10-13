"""
Unpacker Engines for .NET Protectors & Assembly Bundlers.
Engineered & Audited by Maya Thorne.
"""

from .confuserex import ConfuserExUnpacker
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
    "DotNetReactorUnpacker",
    "EazfuscatorUnpacker",
    "VMOpcode",
    "VMOpcodeTable",
    "VMInstruction",
    "EazfuscatorVMDisassembler",
    "EazfuscatorDevirtualizer",
]

