"""
XAML (XML) Generator & Validator from BamlElement AST.
Engineered & Audited by Maya Thorne.
"""

import xml.etree.ElementTree as ET
from typing import List, Optional
import re

from .models import BamlElement


def _escape_xml_attr(val: str) -> str:
    """Escapes XML special characters inside attribute values."""
    if not val:
        return ""
    val = val.replace("&", "&amp;")
    val = val.replace("<", "&lt;")
    val = val.replace(">", "&gt;")
    val = val.replace('"', "&quot;")
    val = val.replace("'", "&apos;")
    return val


def _escape_xml_text(val: str) -> str:
    """Escapes XML special characters within text content."""
    if not val:
        return ""
    val = val.replace("&", "&amp;")
    val = val.replace("<", "&lt;")
    val = val.replace(">", "&gt;")
    return val


def _sanitize_tag_name(tag: str) -> str:
    """Sanitizes element tag name to ensure standard XML compliance."""
    if not tag:
        return "Element"
    # Allow alphanumeric, underscores, dots, and colons
    cleaned = re.sub(r"[^a-zA-Z0-9_\.:]", "_", tag)
    if cleaned[0].isdigit() or cleaned[0] in ".-":
        cleaned = "_" + cleaned
    return cleaned


class XamlEmitter:
    """Emits human-readable, well-indented XAML markup from BAML AST trees."""

    def __init__(self, indent_size: int = 2):
        self.indent_size = indent_size

    def emit(self, root: BamlElement) -> str:
        """Converts BamlElement hierarchy to a complete XAML document string."""
        lines = ['<?xml version="1.0" encoding="utf-8"?>']
        self._emit_element(root, depth=0, lines=lines)
        return "\n".join(lines) + "\n"

    def _emit_element(self, elem: BamlElement, depth: int, lines: List[str]) -> None:
        """Recursively formats and appends an element and its children."""
        indent = " " * (depth * self.indent_size)
        tag = _sanitize_tag_name(elem.tag_name)

        # Emit any preceding comments
        for c in elem.comments:
            lines.append(f"{indent}<!-- {c.strip()} -->")

        # Format attributes
        attr_strs = []
        if elem.is_root:
            # Order root attributes for clean readability
            primary_keys = ["xmlns", "xmlns:x", "x:Class", "Title", "Width", "Height"]
            sorted_keys = []
            for k in primary_keys:
                if k in elem.attributes:
                    sorted_keys.append(k)
            for k in sorted(elem.attributes.keys()):
                if k not in sorted_keys:
                    sorted_keys.append(k)
            for k in sorted_keys:
                v = elem.attributes[k]
                clean_k = _sanitize_tag_name(k)
                attr_strs.append(f'{clean_k}="{_escape_xml_attr(v)}"')
        else:
            for k, v in sorted(elem.attributes.items()):
                clean_k = _sanitize_tag_name(k)
                attr_strs.append(f'{clean_k}="{_escape_xml_attr(v)}"')

        attr_part = (" " + " ".join(attr_strs)) if attr_strs else ""

        has_children = len(elem.children) > 0
        has_text = elem.text is not None and len(elem.text.strip()) > 0

        if not has_children and not has_text:
            lines.append(f"{indent}<{tag}{attr_part} />")
            return

        if not has_children and has_text:
            text_val = _escape_xml_text(elem.text.strip())
            if len(text_val) < 60 and "\n" not in text_val:
                lines.append(f"{indent}<{tag}{attr_part}>{text_val}</{tag}>")
            else:
                lines.append(f"{indent}<{tag}{attr_part}>")
                child_indent = " " * ((depth + 1) * self.indent_size)
                for tline in text_val.splitlines():
                    lines.append(f"{child_indent}{tline}")
                lines.append(f"{indent}</{tag}>")
            return

        # Element has children (and optional text)
        lines.append(f"{indent}<{tag}{attr_part}>")
        if has_text:
            child_indent = " " * ((depth + 1) * self.indent_size)
            lines.append(f"{child_indent}{_escape_xml_text(elem.text.strip())}")

        for child in elem.children:
            self._emit_element(child, depth=depth + 1, lines=lines)

        lines.append(f"{indent}</{tag}>")

    @staticmethod
    def validate_xml(xaml_str: str) -> bool:
        """Validates that the emitted XAML string is 100% well-formed XML."""
        if not xaml_str or not xaml_str.strip():
            return False
        try:
            ET.fromstring(xaml_str.encode("utf-8"))
            return True
        except ET.ParseError:
            return False
