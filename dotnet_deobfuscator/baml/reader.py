"""
MS-BAML Binary Stream Reader & AST Parser.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    BamlAnomalyFlag,
    BamlAssemblyInfo,
    BamlAttributeInfo,
    BamlDecompileStatus,
    BamlElement,
    BamlError,
    BamlRecordType,
    BamlStringInfo,
    BamlTypeInfo,
)
from .tokens import (
    PRESENTATION_XMLNS,
    XAML_XMLNS,
    resolve_attribute_name,
    resolve_type_name,
)


class BamlBinaryReader:
    """Decodes low-level binary BAML record streams into structured BamlElement ASTs."""

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)
        self.pos = 0

        # Lookup tables populated during parsing
        self.assemblies: Dict[int, BamlAssemblyInfo] = {}
        self.types: Dict[int, BamlTypeInfo] = {}
        self.attributes: Dict[int, BamlAttributeInfo] = {}
        self.strings: Dict[int, BamlStringInfo] = {}
        self.xmlns_map: Dict[str, str] = {}
        self.pi_mappings: List[Tuple[str, str, int]] = []

        # Parser state
        self.element_stack: List[BamlElement] = []
        self.root_element: Optional[BamlElement] = None
        self.status = BamlDecompileStatus.SUCCESS
        self.parse_warnings: List[str] = []

    # -------------------------------------------------------------------------
    # Primitive Binary Reader Methods (with bounds enforcement)
    # -------------------------------------------------------------------------

    def read_byte(self) -> int:
        """Reads a single unsigned byte."""
        if self.pos >= self.length:
            raise BamlError(f"Unexpected EOF reading byte at offset {self.pos}")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_int16(self) -> int:
        """Reads a 16-bit signed integer (little-endian)."""
        if self.pos + 2 > self.length:
            raise BamlError(f"Unexpected EOF reading int16 at offset {self.pos}")
        val = struct.unpack_from("<h", self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_uint16(self) -> int:
        """Reads a 16-bit unsigned integer (little-endian)."""
        if self.pos + 2 > self.length:
            raise BamlError(f"Unexpected EOF reading uint16 at offset {self.pos}")
        val = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_int32(self) -> int:
        """Reads a 32-bit signed integer (little-endian)."""
        if self.pos + 4 > self.length:
            raise BamlError(f"Unexpected EOF reading int32 at offset {self.pos}")
        val = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_uint32(self) -> int:
        """Reads a 32-bit unsigned integer (little-endian)."""
        if self.pos + 4 > self.length:
            raise BamlError(f"Unexpected EOF reading uint32 at offset {self.pos}")
        val = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_7bit_int(self) -> int:
        """Reads a variable-length 7-bit encoded integer."""
        count = 0
        shift = 0
        while True:
            if self.pos >= self.length:
                raise BamlError(f"Unexpected EOF reading 7-bit encoded int at offset {self.pos}")
            b = self.data[self.pos]
            self.pos += 1
            count |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                break
            if shift >= 35:
                raise BamlError(f"Malformed 7-bit encoded int exceeded 35 bits at offset {self.pos}")
        return count

    def read_string(self) -> str:
        """Reads a 7-bit length-prefixed UTF-8 string."""
        length = self.read_7bit_int()
        if length == 0:
            return ""
        if self.pos + length > self.length:
            raise BamlError(f"Unexpected EOF reading string of length {length} at offset {self.pos}")
        raw = self.data[self.pos : self.pos + length]
        self.pos += length
        return raw.decode("utf-8", errors="replace")

    def read_bytes(self, length: int) -> bytes:
        """Reads raw byte chunk."""
        if self.pos + length > self.length:
            raise BamlError(f"Unexpected EOF reading {length} bytes at offset {self.pos}")
        b = self.data[self.pos : self.pos + length]
        self.pos += length
        return b

    # -------------------------------------------------------------------------
    # Main Stream Parsing Loop
    # -------------------------------------------------------------------------

    def parse(self) -> Tuple[Optional[BamlElement], BamlDecompileStatus]:
        """Parses entire BAML stream into an AST element hierarchy."""
        if not self.data:
            return None, BamlDecompileStatus.CORRUPTED

        # Detect optional BAML version prefix
        self._check_version_header()

        try:
            while self.pos < self.length:
                record_type_code = self.read_byte()
                try:
                    record_type = BamlRecordType(record_type_code)
                except ValueError:
                    self.parse_warnings.append(
                        f"Unrecognized BAML record opcode 0x{record_type_code:02X} at offset 0x{self.pos-1:X}"
                    )
                    self.status = BamlDecompileStatus.PARTIAL
                    break

                if record_type == BamlRecordType.DOCUMENT_END:
                    break

                self._process_record(record_type)

        except Exception as e:
            self.parse_warnings.append(f"Parsing terminated early due to exception: {str(e)}")
            self.status = BamlDecompileStatus.PARTIAL

        # If elements remain unclosed on the stack, safely finalize them
        while self.element_stack:
            self.element_stack.pop()

        if self.root_element is None:
            # If no root element was created, build a synthetic container with collected properties
            self.root_element = BamlElement(tag_name="UserControl", is_root=True)
            self.status = BamlDecompileStatus.PARTIAL

        # Inject standard namespace declarations if not already present
        if PRESENTATION_XMLNS not in self.root_element.attributes.values():
            self.root_element.add_attribute("xmlns", PRESENTATION_XMLNS)
        if XAML_XMLNS not in self.root_element.attributes.values():
            self.root_element.add_attribute("xmlns:x", XAML_XMLNS)

        for prefix, uri in self.xmlns_map.items():
            attr_name = f"xmlns:{prefix}" if prefix else "xmlns"
            if attr_name not in self.root_element.attributes:
                self.root_element.add_attribute(attr_name, uri)

        return self.root_element, self.status

    def _check_version_header(self) -> None:
        """Inspects and consumes optional BAML version or signature blocks."""
        if self.length >= 8:
            first_dword = struct.unpack_from("<I", self.data, 0)[0]
            # Signature check: 0x00600000 or MS-BAML version (0.96)
            if first_dword == 0x00600000 or first_dword == 0x00006000:
                self.pos = 8
            elif first_dword == 0x00000000 and self.length >= 8:
                second_dword = struct.unpack_from("<I", self.data, 4)[0]
                if second_dword in (0x00600000, 0x00000060, 0x00006000):
                    self.pos = 8

    def _process_record(self, record_type: BamlRecordType) -> None:
        """Dispatches record parsing according to BamlRecordType."""
        if record_type == BamlRecordType.DOCUMENT_START:
            # DocumentStart record
            pass

        elif record_type == BamlRecordType.ASSEMBLY_INFO:
            asm_id = self.read_int16()
            asm_name = self.read_string()
            self.assemblies[asm_id] = BamlAssemblyInfo(assembly_id=asm_id, name=asm_name)

        elif record_type == BamlRecordType.TYPE_INFO:
            type_id = self.read_int16()
            asm_id = self.read_int16()
            type_name = self.read_string()
            self.types[type_id] = BamlTypeInfo(type_id=type_id, assembly_id=asm_id, name=type_name)

        elif record_type == BamlRecordType.ATTRIBUTE_INFO:
            attr_id = self.read_int16()
            owner_type_id = self.read_int16()
            usage = self.read_byte()
            attr_name = self.read_string()
            self.attributes[attr_id] = BamlAttributeInfo(
                attribute_id=attr_id, owner_type_id=owner_type_id, usage=usage, name=attr_name
            )

        elif record_type == BamlRecordType.STRING_INFO:
            str_id = self.read_int16()
            val = self.read_string()
            self.strings[str_id] = BamlStringInfo(string_id=str_id, value=val)

        elif record_type == BamlRecordType.XMLNS_PROPERTY:
            prefix = self.read_string()
            xml_ns = self.read_string()
            # Assemblies list
            asm_count = self.read_int16()
            for _ in range(asm_count):
                self.read_int16()
            self.xmlns_map[prefix] = xml_ns

        elif record_type == BamlRecordType.PI_MAPPING:
            xml_ns = self.read_string()
            clr_ns = self.read_string()
            asm_id = self.read_int16()
            self.pi_mappings.append((xml_ns, clr_ns, asm_id))

        elif record_type == BamlRecordType.DEF_ATTRIBUTE:
            value = self.read_string()
            name_str_id = self.read_int16()
            # Resolve name from strings table or standard names
            attr_name = "Key"
            if name_str_id in self.strings:
                attr_name = self.strings[name_str_id].value
            elif name_str_id == 1:
                attr_name = "Name"
            elif name_str_id == 2:
                attr_name = "Class"
            elif name_str_id == 3:
                attr_name = "Key"

            target_attr = f"x:{attr_name}"
            if self.element_stack:
                self.element_stack[-1].add_attribute(target_attr, value)
            elif self.root_element:
                self.root_element.add_attribute(target_attr, value)

        elif record_type == BamlRecordType.ELEMENT_START:
            type_id = self.read_int16()
            flags = self.read_byte()

            custom_types = {k: v.name for k, v in self.types.items()}
            tag_name = resolve_type_name(type_id, custom_types)

            element = BamlElement(tag_name=tag_name, type_id=type_id)
            if self.root_element is None:
                self.root_element = element
                element.is_root = True

            if self.element_stack:
                self.element_stack[-1].add_child(element)

            self.element_stack.append(element)

        elif record_type == BamlRecordType.NAMED_ELEMENT_START:
            type_id = self.read_int16()
            name = self.read_string()
            custom_types = {k: v.name for k, v in self.types.items()}
            tag_name = resolve_type_name(type_id, custom_types)

            element = BamlElement(tag_name=tag_name, type_id=type_id)
            element.add_attribute("x:Name", name)

            if self.root_element is None:
                self.root_element = element
                element.is_root = True

            if self.element_stack:
                self.element_stack[-1].add_child(element)

            self.element_stack.append(element)

        elif record_type == BamlRecordType.ELEMENT_END:
            if self.element_stack:
                self.element_stack.pop()

        elif record_type == BamlRecordType.PROPERTY:
            attr_id = self.read_int16()
            value = self.read_string()
            custom_attrs = {k: v.name for k, v in self.attributes.items()}
            attr_name = resolve_attribute_name(attr_id, custom_attrs)

            if self.element_stack:
                self.element_stack[-1].add_attribute(attr_name, value)
            elif self.root_element:
                self.root_element.add_attribute(attr_name, value)

        elif record_type == BamlRecordType.PROPERTY_CUSTOM:
            attr_id = self.read_int16()
            serializer_id = self.read_int16()
            data_len = self.read_7bit_int()
            custom_bytes = self.read_bytes(data_len)

            custom_attrs = {k: v.name for k, v in self.attributes.items()}
            attr_name = resolve_attribute_name(attr_id, custom_attrs)

            # Try to decode string or format as hex
            val_str = custom_bytes.decode("utf-8", errors="replace")
            if not val_str.isprintable() or len(val_str) == 0:
                val_str = custom_bytes.hex()

            if self.element_stack:
                self.element_stack[-1].add_attribute(attr_name, val_str)

        elif record_type == BamlRecordType.TEXT:
            text_val = self.read_string()
            if self.element_stack:
                self.element_stack[-1].text = text_val

        elif record_type == BamlRecordType.COMMENT:
            comment_val = self.read_string()
            if self.element_stack:
                self.element_stack[-1].comments.append(comment_val)

        elif record_type == BamlRecordType.LITERAL_CONTENT:
            val = self.read_string()
            # Consume reserved line/col coordinates
            self.read_int32()
            self.read_int32()
            if self.element_stack:
                self.element_stack[-1].text = val

        elif record_type == BamlRecordType.LINE_NUMBER_AND_POSITION:
            line_num = self.read_int32()
            line_pos = self.read_int32()
            if self.element_stack:
                self.element_stack[-1].line_number = line_num
                self.element_stack[-1].line_position = line_pos

        elif record_type == BamlRecordType.LINE_POSITION:
            line_pos = self.read_int32()
            if self.element_stack:
                self.element_stack[-1].line_position = line_pos

        elif record_type == BamlRecordType.CONNECTION_ID:
            # Connection ID for compiled event wireup (x:ConnectionId)
            conn_id = self.read_int32()
            if self.element_stack:
                self.element_stack[-1].add_attribute("x:ConnectionId", str(conn_id))

        elif record_type == BamlRecordType.STATIC_RESOURCE:
            type_id = self.read_int16()
            flags = self.read_byte()

        elif record_type == BamlRecordType.ROUTED_EVENT:
            attr_id = self.read_int16()
            handler_name = self.read_string()
            custom_attrs = {k: v.name for k, v in self.attributes.items()}
            event_name = resolve_attribute_name(attr_id, custom_attrs)
            if self.element_stack:
                self.element_stack[-1].add_attribute(event_name, handler_name)

        elif record_type == BamlRecordType.CLR_EVENT:
            attr_id = self.read_int16()
            handler_name = self.read_string()
            custom_attrs = {k: v.name for k, v in self.attributes.items()}
            event_name = resolve_attribute_name(attr_id, custom_attrs)
            if self.element_stack:
                self.element_stack[-1].add_attribute(event_name, handler_name)

        elif record_type in (
            BamlRecordType.PROPERTY_COMPLEX_START,
            BamlRecordType.PROPERTY_ARRAY_START,
            BamlRecordType.PROPERTY_ILIST_START,
            BamlRecordType.PROPERTY_IDICTIONARY_START,
        ):
            # Complex property wrappers: read attribute ID
            attr_id = self.read_int16()
            custom_attrs = {k: v.name for k, v in self.attributes.items()}
            attr_name = resolve_attribute_name(attr_id, custom_attrs)
            # Create a synthetic property element tag (e.g., <Window.Resources>)
            owner_tag = self.element_stack[-1].tag_name if self.element_stack else "Root"
            prop_elem = BamlElement(tag_name=f"{owner_tag}.{attr_name}")
            if self.element_stack:
                self.element_stack[-1].add_child(prop_elem)
            self.element_stack.append(prop_elem)

        elif record_type in (
            BamlRecordType.PROPERTY_COMPLEX_END,
            BamlRecordType.PROPERTY_ARRAY_END,
            BamlRecordType.PROPERTY_ILIST_END,
            BamlRecordType.PROPERTY_IDICTIONARY_END,
        ):
            if self.element_stack:
                self.element_stack.pop()
