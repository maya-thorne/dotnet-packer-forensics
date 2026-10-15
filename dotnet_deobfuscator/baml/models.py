"""
BAML (Binary Application Markup Language) & XAML UI Forensics Data Models.
Engineered & Audited by Maya Thorne.
"""

from dataclasses import dataclass, field
from enum import Enum, IntEnum
import ctypes
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class SecurityError(Exception):
    """Raised when security boundaries, path traversal guards, or bounds are violated."""
    pass


class BamlError(Exception):
    """Raised when BAML parsing or XAML reconstruction encounters an unrecoverable format error."""
    pass


def zeroize_buffer(buf: Union[bytearray, memoryview, ctypes.Array]) -> None:
    """Zeroizes in-memory buffers using ctypes.memset to eliminate residual cryptographic remnants."""
    if not buf:
        return
    try:
        if isinstance(buf, (bytearray, memoryview)):
            c_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.byref(c_arr), 0, len(buf))
        elif hasattr(buf, "_length_") and hasattr(buf, "_type_"):
            ctypes.memset(ctypes.byref(buf), 0, ctypes.sizeof(buf))
    except Exception:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0


class BamlRecordType(IntEnum):
    """MS-BAML Specification Record Type Codes."""

    DOCUMENT_START = 1
    DOCUMENT_END = 2
    ELEMENT_START = 3
    ELEMENT_END = 4
    PROPERTY = 5
    PROPERTY_CUSTOM = 6
    PROPERTY_COMPLEX_START = 7
    PROPERTY_COMPLEX_END = 8
    PROPERTY_ARRAY_START = 9
    PROPERTY_ARRAY_END = 10
    PROPERTY_ILIST_START = 11
    PROPERTY_ILIST_END = 12
    PROPERTY_IDICTIONARY_START = 13
    PROPERTY_IDICTIONARY_END = 14
    LITERAL_CONTENT = 15
    TEXT = 16
    TEXT_WITH_CONVERTER = 17
    ROUTED_EVENT = 18
    CLR_EVENT = 19
    XMLNS_PROPERTY = 20
    XML_ATTRIBUTE = 21
    PROCESSING_INSTRUCTION = 22
    COMMENT = 23
    DEF_ATTRIBUTE = 24
    DEF_ATTRIBUTE_KEY_STRING = 25
    DEF_ATTRIBUTE_KEY_TYPE = 26
    END_ATTRIBUTES = 27
    PI_MAPPING = 28
    ASSEMBLY_INFO = 29
    TYPE_INFO = 30
    TYPE_SERIALIZER_INFO = 31
    ATTRIBUTE_INFO = 32
    STRING_INFO = 33
    PROPERTY_STRING_REFERENCE = 34
    PROPERTY_TYPE_REFERENCE = 35
    PROPERTY_WITH_EXTENSION = 36
    PROPERTY_WITH_CONVERTER = 37
    MODIFY_KEY_VALUE = 38
    CONNECTION_ID = 39
    CONTENT_PROPERTY = 40
    NAMED_ELEMENT_START = 41
    STATIC_RESOURCE = 42
    STATIC_RESOURCE_ID = 43
    TEXT_WITH_ID = 44
    PRESENTATION_OPTIONS_ATTRIBUTE = 45
    LINE_NUMBER_AND_POSITION = 46
    LINE_POSITION = 47


class BamlDecompileStatus(Enum):
    """Execution status for individual BAML-to-XAML decompile tasks."""

    SUCCESS = "success"
    PARTIAL = "partial"
    MALFORMED = "malformed"
    CORRUPTED = "corrupted"


class UIElementType(Enum):
    """Categorization of primary WPF UI root structures."""

    WINDOW = "Window"
    USER_CONTROL = "UserControl"
    PAGE = "Page"
    APPLICATION = "Application"
    RESOURCE_DICTIONARY = "ResourceDictionary"
    DATA_TEMPLATE = "DataTemplate"
    GENERIC_ELEMENT = "GenericElement"


class ResourceSourceType(Enum):
    """Origin of carved BAML streams within compiled PE binaries."""

    MANAGED_RESOURCES = "managed_resources"  # Standard .NET .g.resources (0xBEEFCACE)
    RAW_BAML_STREAM = "raw_baml_stream"      # Standalone .baml file
    PE_SECTION_CARVED = "pe_section_carved"  # Carved from PE section payload
    EMBEDDED_RESOURCE = "embedded_resource"  # Embedded CLI manifest stream


class BamlAnomalyFlag(Enum):
    """Security and forensic anomaly indicators discovered during BAML inspection."""

    SUSPICIOUS_URI = "suspicious_uri"
    SUSPICIOUS_EVENT_HANDLER = "suspicious_event_handler"
    HIDDEN_UI_ELEMENT = "hidden_ui_element"
    SUSPICIOUS_BASE64_PAYLOAD = "suspicious_base64_payload"
    OBFUSCATED_IDENTIFIER = "obfuscated_identifier"
    RESOURCE_DICTIONARY_PAYLOAD = "resource_dictionary_payload"


@dataclass
class BamlAssemblyInfo:
    """Represents a BAML AssemblyInfo record mapping an ID to an assembly name."""
    assembly_id: int
    name: str


@dataclass
class BamlTypeInfo:
    """Represents a BAML TypeInfo record mapping a Type ID to a CLR type name."""
    type_id: int
    assembly_id: int
    name: str
    is_known: bool = False


@dataclass
class BamlAttributeInfo:
    """Represents a BAML AttributeInfo record mapping an Attribute ID to an attribute name."""
    attribute_id: int
    owner_type_id: int
    usage: int
    name: str


@dataclass
class BamlStringInfo:
    """Represents a BAML StringInfo record mapping a String ID to a literal string."""
    string_id: int
    value: str


@dataclass
class BamlElement:
    """AST node representing a reconstructed XAML/BAML UI element."""

    tag_name: str
    type_id: int = 0
    attributes: Dict[str, str] = field(default_factory=dict)
    children: List["BamlElement"] = field(default_factory=list)
    text: Optional[str] = None
    comments: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    is_root: bool = False
    line_number: Optional[int] = None
    line_position: Optional[int] = None

    def add_child(self, child: "BamlElement") -> None:
        """Appends a child node to element."""
        self.children.append(child)

    def add_attribute(self, key: str, value: str) -> None:
        """Sets an attribute value on element."""
        self.attributes[key] = value

    def count_nodes(self) -> int:
        """Recursively calculates total number of descendant elements."""
        total = 1
        for c in self.children:
            total += c.count_nodes()
        return total

    def to_dict(self) -> Dict[str, Any]:
        """Serializes element AST node to dictionary structure."""
        return {
            "tag": self.tag_name,
            "type_id": self.type_id,
            "attributes": dict(self.attributes),
            "text": self.text,
            "comments": list(self.comments),
            "anomalies": list(self.anomalies),
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class DecompiledXaml:
    """Decompiled XAML document and associated forensic metrics."""

    resource_name: str
    xaml_content: str
    status: BamlDecompileStatus
    root_tag: str
    element_count: int
    property_count: int
    anomalies: List[str]
    raw_size: int
    decompiled_size: int
    sha256: str
    is_valid_xml: bool

    def to_dict(self) -> Dict[str, Any]:
        """Converts decompiled XAML record to dictionary representation."""
        return {
            "resource_name": self.resource_name,
            "status": self.status.value,
            "root_tag": self.root_tag,
            "element_count": self.element_count,
            "property_count": self.property_count,
            "anomalies": list(self.anomalies),
            "raw_size": self.raw_size,
            "decompiled_size": self.decompiled_size,
            "sha256": self.sha256,
            "is_valid_xml": self.is_valid_xml,
            "xaml_snippet": (
                self.xaml_content[:500] + "..." if len(self.xaml_content) > 500 else self.xaml_content
            ),
        }


@dataclass
class BamlTelemetry:
    """Forensic telemetry across all extracted and decompiled BAML streams."""

    total_baml_streams: int = 0
    successful_decompiles: int = 0
    partial_decompiles: int = 0
    failed_decompiles: int = 0
    total_elements: int = 0
    total_attributes: int = 0
    total_anomalies: int = 0
    execution_time_ms: float = 0.0
    anomaly_types: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts telemetry metrics to dictionary."""
        return {
            "total_baml_streams": self.total_baml_streams,
            "successful_decompiles": self.successful_decompiles,
            "partial_decompiles": self.partial_decompiles,
            "failed_decompiles": self.failed_decompiles,
            "total_elements": self.total_elements,
            "total_attributes": self.total_attributes,
            "total_anomalies": self.total_anomalies,
            "execution_time_ms": self.execution_time_ms,
            "anomaly_types": dict(self.anomaly_types),
        }


@dataclass
class BamlExtractionResult:
    """Complete results for BAML extraction and XAML decompiler pipeline."""

    file_name: str
    file_size: int
    source_type: ResourceSourceType
    decompiled_items: List[DecompiledXaml]
    telemetry: BamlTelemetry
    suspicious_findings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes full extraction result to dictionary."""
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "source_type": self.source_type.value,
            "decompiled_items": [item.to_dict() for item in self.decompiled_items],
            "telemetry": self.telemetry.to_dict(),
            "suspicious_findings": list(self.suspicious_findings),
        }
