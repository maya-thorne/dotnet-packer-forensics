"""
dotnet-packer-forensics Python Toolchain.
Engineered & Audited by Maya Thorne.
"""

from .core import DotNetPackerCore
from .dotnet_analyzer import DotNetAnalyzer
from .pe_overlay import PEOverlayParser
from .pe_rebuilder import PERebuilder, PERebuildOptions, PERebuildReport
from .signatures import ProtectorSignatures
from .unpackers.confuserex import ConfuserExUnpacker
from .unpackers.costura import CosturaUnpacker

__version__ = "1.3.0"
__author__ = "Maya Thorne"

__all__ = [
    "DotNetPackerCore",
    "DotNetAnalyzer",
    "PEOverlayParser",
    "PERebuilder",
    "PERebuildOptions",
    "PERebuildReport",
    "ProtectorSignatures",
    "CosturaUnpacker",
    "ConfuserExUnpacker",
    "__version__",
]
