"""
WPF BAML & Embedded UI Resource Decompiler & XML Restorer Package.
Engineered & Audited by Maya Thorne.
"""

from .decompiler import BamlDecompiler
from .models import (
    BamlAnomalyFlag,
    BamlDecompileStatus,
    BamlElement,
    BamlError,
    BamlExtractionResult,
    BamlRecordType,
    BamlTelemetry,
    DecompiledXaml,
    ResourceSourceType,
    SecurityError,
    UIElementType,
    zeroize_buffer,
)
from .reader import BamlBinaryReader
from .resource_extractor import BamlResourceExtractor
from .tokens import (
    DESIGN_XMLNS,
    KNOWN_BAML_ATTRIBUTES,
    KNOWN_BAML_TYPES,
    MC_XMLNS,
    PRESENTATION_XMLNS,
    XAML_XMLNS,
    resolve_attribute_name,
    resolve_type_name,
)
from .xml_emitter import XamlEmitter

__all__ = [
    "BamlDecompiler",
    "BamlBinaryReader",
    "BamlResourceExtractor",
    "XamlEmitter",
    "BamlRecordType",
    "BamlDecompileStatus",
    "UIElementType",
    "ResourceSourceType",
    "BamlAnomalyFlag",
    "BamlElement",
    "DecompiledXaml",
    "BamlTelemetry",
    "BamlExtractionResult",
    "SecurityError",
    "BamlError",
    "zeroize_buffer",
    "PRESENTATION_XMLNS",
    "XAML_XMLNS",
    "DESIGN_XMLNS",
    "MC_XMLNS",
    "KNOWN_BAML_TYPES",
    "KNOWN_BAML_ATTRIBUTES",
    "resolve_type_name",
    "resolve_attribute_name",
]
