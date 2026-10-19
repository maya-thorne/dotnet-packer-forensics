"""
Ingestion & Normalization of JIT Trace Logs, ETW Streams & Frida Hook Dumps.
Engineered & Audited by Maya Thorne.
"""

import csv
import io
import json
import re
import struct
from typing import List, Optional

from .emulator import VirtualJITCompiler
from .models import CapturedMethod, CaptureSource


class JITTraceParser:
    """Parses diverse external JIT compilation traces into standardized forensic models."""

    # Regex pattern for Frida / x64dbg text trace logs
    PATTERN_TEXT_TRACE = re.compile(
        r"(?:token|methoddef|md)?\s*[:=]?\s*(0x[0-9a-fA-F]+|[0-9]+).*?(?:il|bytes|code)\s*[:=]?\s*([0-9a-fA-F\s\-]+)",
        re.IGNORECASE,
    )

    @classmethod
    def parse_trace_data(cls, data: bytes, source: CaptureSource = CaptureSource.TRACE_LOG) -> List[CapturedMethod]:
        """Auto-detects format (JSON, CSV, Binary JITD, Text) and parses trace into CapturedMethods."""
        if not data:
            return []

        # 1. Check Binary JITD format
        if data.startswith(b"JITD"):
            return cls._parse_binary_jitd(data)

        # 2. Try JSON format
        try:
            text = data.decode("utf-8", errors="replace").strip()
            if text.startswith("{") or text.startswith("["):
                parsed = json.loads(text)
                return cls._parse_json(parsed, source)
        except Exception:
            pass

        # 3. Try CSV format (first line must be a CSV header with comma/tab)
        text = data.decode("utf-8", errors="replace").strip()
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        first_line = lines[0].lower() if lines else ""
        if ("," in first_line or "\t" in first_line) and "token" in first_line and any(k in first_line for k in ("name", "il", "rva", "type", "hex")):
            try:
                csv_methods = cls._parse_csv(text, source)
                if csv_methods:
                    return csv_methods
            except Exception:
                pass

        # 4. Fallback to Line-by-Line Regex text parsing
        return cls._parse_text_log(text, source)

    @classmethod
    def _parse_binary_jitd(cls, data: bytes) -> List[CapturedMethod]:
        """Parses custom binary JITD stream: JITD + uint32 count + records."""
        methods: List[CapturedMethod] = []
        if len(data) < 8:
            return methods

        count = struct.unpack("<I", data[4:8])[0]
        offset = 8
        total = len(data)

        for _ in range(count):
            if offset + 12 > total:
                break
            token, rva, il_size = struct.unpack("<III", data[offset : offset + 12])
            offset += 12
            if offset + il_size > total:
                break
            il_bytes = data[offset : offset + il_size]
            offset += il_size

            method = VirtualJITCompiler.compile_method(
                token=token,
                raw_body_bytes=il_bytes,
                rva=rva,
                source=CaptureSource.MEMORY_STREAM,
            )
            methods.append(method)

        return methods

    @classmethod
    def _parse_json(cls, obj: object, source: CaptureSource) -> List[CapturedMethod]:
        """Parses structured JSON trace lists or telemetry events."""
        methods: List[CapturedMethod] = []
        items = []

        if isinstance(obj, list):
            items = obj
        elif isinstance(obj, dict):
            items = obj.get("methods") or obj.get("events") or obj.get("captured") or [obj]

        for item in items:
            if not isinstance(item, dict):
                continue
            token_raw = item.get("token") or item.get("MethodToken") or 0
            token = int(str(token_raw), 16) if str(token_raw).startswith("0x") else int(token_raw)
            name = str(item.get("name") or item.get("MethodName") or f"Method_{token:08X}")
            declaring_type = str(item.get("declaring_type") or item.get("TypeName") or "Type")
            rva_raw = item.get("rva") or item.get("RVA") or 0
            rva = int(str(rva_raw), 16) if str(rva_raw).startswith("0x") else int(rva_raw)

            il_hex = str(item.get("il_hex") or item.get("ILCode") or item.get("bytes") or "").replace(" ", "").replace("\n", "")
            try:
                il_bytes = bytes.fromhex(il_hex) if il_hex else b""
            except ValueError:
                il_bytes = b""

            method = VirtualJITCompiler.compile_method(
                token=token,
                raw_body_bytes=il_bytes,
                rva=rva,
                name=name,
                declaring_type=declaring_type,
                source=source,
            )
            methods.append(method)

        return methods

    @classmethod
    def _parse_csv(cls, text: str, source: CaptureSource) -> List[CapturedMethod]:
        """Parses CSV formatted JIT log files."""
        methods: List[CapturedMethod] = []
        reader = csv.DictReader(io.StringIO(text))

        for row in reader:
            token_str = (row.get("token") or row.get("Token") or "").strip()
            if not token_str:
                continue
            token = int(token_str, 16) if token_str.startswith("0x") else int(token_str)
            name = (row.get("name") or row.get("Name") or f"Method_{token:08X}").strip()
            declaring_type = (row.get("declaring_type") or row.get("Type") or "Type").strip()
            rva_str = (row.get("rva") or row.get("RVA") or "0").strip()
            rva = int(rva_str, 16) if rva_str.startswith("0x") else int(rva_str)

            il_hex = (row.get("il_hex") or row.get("IL") or row.get("bytes") or "").replace(" ", "").strip()
            try:
                il_bytes = bytes.fromhex(il_hex) if il_hex else b""
            except ValueError:
                il_bytes = b""

            method = VirtualJITCompiler.compile_method(
                token=token,
                raw_body_bytes=il_bytes,
                rva=rva,
                name=name,
                declaring_type=declaring_type,
                source=source,
            )
            methods.append(method)

        return methods

    @classmethod
    def _parse_text_log(cls, text: str, source: CaptureSource) -> List[CapturedMethod]:
        """Extracts token and hex bytes from freeform debugger or Frida console logs."""
        methods: List[CapturedMethod] = []
        lines = text.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            match = cls.PATTERN_TEXT_TRACE.search(line)
            if match:
                token_str, hex_str = match.groups()
                token = int(token_str, 16) if token_str.startswith("0x") else int(token_str)
                clean_hex = hex_str.replace(" ", "").replace("-", "")
                try:
                    il_bytes = bytes.fromhex(clean_hex)
                except ValueError:
                    continue

                method = VirtualJITCompiler.compile_method(
                    token=token,
                    raw_body_bytes=il_bytes,
                    source=source,
                )
                methods.append(method)

        return methods
