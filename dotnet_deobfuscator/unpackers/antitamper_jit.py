"""
In-Memory CLR JIT Dumper Interface & Decrypted CIL Bytecode Engine.
Engineered & Audited by Maya Thorne.
"""

import json
import math
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .antitamper_models import (
    CorILMethodFormat,
    CorILMethodHeader,
    JITMethodRecord,
    SecurityError,
    hex_to_token,
    token_to_hex,
)


class CorILMethodParser:
    """Parser, builder, and validator for ECMA-335 CorILMethod headers."""

    # Set of valid single-byte CIL opcodes (ECMA-335 Partition III)
    VALID_SINGLE_BYTE_OPCODES: Set[int] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x25, 0x26, 0x28, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40, 0x45, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x80, 0x81, 0x8D,
        0x8E, 0x8F, 0x90, 0x91, 0xA3, 0xA4, 0xA5, 0xC2, 0xC3, 0xC6, 0xD0, 0xD1, 0xD2, 0xD3,
        0xD4, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
    }

    @classmethod
    def parse_method_header(cls, data: bytes, offset: int = 0) -> Optional[CorILMethodHeader]:
        """Parses CorILMethod Tiny or Fat header from byte stream at specified offset."""
        if offset >= len(data):
            return None

        first_byte = data[offset]
        fmt_bits = first_byte & 0x03

        # Tiny Format: bits 0-1 are 0x02, code size is bits 2-7 (up to 63 bytes)
        if fmt_bits == 0x02:
            code_size = first_byte >> 2
            if offset + 1 + code_size > len(data):
                return None
            code_bytes = data[offset + 1 : offset + 1 + code_size]
            return CorILMethodHeader(
                format=CorILMethodFormat.TINY,
                header_size=1,
                code_size=code_size,
                max_stack=8,
                local_var_sig_tok=0,
                flags=first_byte,
                code_bytes=code_bytes,
                raw_header_bytes=data[offset : offset + 1],
                extra_sections=b"",
            )

        # Fat Format: bits 0-1 are 0x03, header size is (flags >> 12) * 4 (usually 12)
        if fmt_bits == 0x03:
            if offset + 12 > len(data):
                return None
            flags, max_stack, code_size, local_sig = struct.unpack_from("<HHII", data, offset)
            hdr_dwords = (flags >> 12) & 0x0F
            header_size = max(12, hdr_dwords * 4)

            if offset + header_size + code_size > len(data):
                return None

            code_bytes = data[offset + header_size : offset + header_size + code_size]
            raw_header = data[offset : offset + header_size]

            extra_sections = b""
            if (flags & 0x08) != 0:  # CorILMethod_MoreSects
                sect_start = offset + header_size + code_size
                # Align to 4-byte boundary
                aligned_start = (sect_start + 3) & ~3
                if aligned_start + 4 <= len(data):
                    sect_flags = data[aligned_start]
                    sect_size = struct.unpack_from("<I", data, aligned_start)[0] >> 8
                    if sect_size > 0 and aligned_start + sect_size <= len(data):
                        extra_sections = data[aligned_start : aligned_start + sect_size]

            return CorILMethodHeader(
                format=CorILMethodFormat.FAT,
                header_size=header_size,
                code_size=code_size,
                max_stack=max_stack,
                local_var_sig_tok=local_sig,
                flags=flags,
                code_bytes=code_bytes,
                raw_header_bytes=raw_header,
                extra_sections=extra_sections,
            )

        return None

    @classmethod
    def build_tiny_method(cls, code_bytes: bytes) -> bytes:
        """Constructs an ECMA-335 Tiny format method body (for code under 64 bytes)."""
        if len(code_bytes) >= 64:
            return cls.build_fat_method(code_bytes, max_stack=8)
        header_byte = (len(code_bytes) << 2) | 0x02
        return bytes([header_byte]) + code_bytes

    @classmethod
    def build_fat_method(
        cls,
        code_bytes: bytes,
        max_stack: int = 8,
        local_sig: int = 0,
        extra_sections: bytes = b"",
    ) -> bytes:
        """Constructs an ECMA-335 Fat format method body (12-byte header + CIL + extra sections)."""
        has_more_sects = len(extra_sections) > 0
        # Flags: 0x3003 = Size: 3 DWORDS (12 bytes), Format: Fat (0x03)
        flags = 0x3003 | (0x08 if has_more_sects else 0)
        header = struct.pack("<HHII", flags, max_stack, len(code_bytes), local_sig)
        body = bytearray(header + code_bytes)

        if has_more_sects:
            # 4-byte align before extra sections
            while len(body) % 4 != 0:
                body.append(0)
            body.extend(extra_sections)

        return bytes(body)

    @classmethod
    def validate_cil_instructions(cls, cil_bytes: bytes) -> Tuple[bool, List[str]]:
        """Verifies if byte buffer contains valid ECMA-335 CIL opcode sequences."""
        if not cil_bytes:
            return False, []

        opcodes_found: List[str] = []
        i = 0
        valid_count = 0
        total_count = 0

        while i < len(cil_bytes):
            op = cil_bytes[i]
            total_count += 1

            if op == 0xFE:  # Two-byte opcode prefix
                if i + 1 < len(cil_bytes):
                    sub = cil_bytes[i + 1]
                    opcodes_found.append(f"0xFE{sub:02X}")
                    valid_count += 1
                    i += 2
                    continue
                else:
                    break

            if op in cls.VALID_SINGLE_BYTE_OPCODES:
                valid_count += 1
                opcodes_found.append(f"0x{op:02X}")
            i += 1

        if total_count == 0:
            return False, []

        valid_ratio = valid_count / total_count
        # High confidence CIL if > 65% of traversed bytes match CIL opcode set
        return valid_ratio >= 0.65, opcodes_found


class AntiTamperDecrypter:
    """Cryptographic stream decrypters for anti-tampered method bodies."""

    @staticmethod
    def decrypt_lcg_stream(
        ciphertext: bytes, seed: int, a: int = 1664525, c: int = 1013904223
    ) -> bytes:
        """Decrypts ciphertext using Linear Congruential Generator (LCG) PRNG stream cipher."""
        state = seed & 0xFFFFFFFF
        res = bytearray(len(ciphertext))
        for i in range(len(ciphertext)):
            state = (state * a + c) & 0xFFFFFFFF
            keystream_byte = (state >> 24) & 0xFF
            res[i] = ciphertext[i] ^ keystream_byte
        return bytes(res)

    @staticmethod
    def decrypt_token_keyed_xor(
        ciphertext: bytes, token: int, salt: int = 0x5A5A5A5A
    ) -> bytes:
        """Decrypts method bytecode using token-hash derived 4-byte key."""
        key_val = (token ^ salt) & 0xFFFFFFFF
        key_bytes = struct.pack("<I", key_val)
        res = bytearray(len(ciphertext))
        for i in range(len(ciphertext)):
            res[i] = ciphertext[i] ^ key_bytes[i % 4]
        return bytes(res)

    @staticmethod
    def decrypt_rolling_xor(ciphertext: bytes, key: bytes) -> bytes:
        """Decrypts ciphertext using a rolling multi-byte XOR cipher."""
        if not key:
            return ciphertext
        res = bytearray(len(ciphertext))
        key_len = len(key)
        state = 0
        for i in range(len(ciphertext)):
            k = (key[i % key_len] + state) & 0xFF
            res[i] = ciphertext[i] ^ k
            state = (state + res[i]) & 0xFF
        return bytes(res)

    @staticmethod
    def zeroize_buffer(buf: bytearray) -> None:
        """Securely wipes memory buffer to prevent residual key leakage."""
        for i in range(len(buf)):
            buf[i] = 0


class JITDumperInterface:
    """Interface for capturing and processing in-memory CLR JIT dumped methods."""

    MAX_DUMP_SIZE = 50 * 1024 * 1024  # 50 MB safety ceiling
    MAGIC_JIT_BINARY = b"JITD"

    @classmethod
    def ingest_json_dump(cls, json_data: Union[str, dict, list]) -> List[JITMethodRecord]:
        """Ingests structured JIT dump telemetry from JSON string or dict/list."""
        if isinstance(json_data, str):
            if len(json_data) > cls.MAX_DUMP_SIZE:
                raise SecurityError(f"JSON dump size ({len(json_data)} bytes) exceeds limit")
            parsed = json.loads(json_data)
        else:
            parsed = json_data

        items: List[Dict[str, Any]] = []
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            items = parsed.get("methods", parsed.get("dumped_methods", []))

        records: List[JITMethodRecord] = []
        for idx, item in enumerate(items):
            token_val = item.get("token", 0x06000001 + idx)
            token = hex_to_token(str(token_val)) if isinstance(token_val, str) else int(token_val)
            rid = token & 0x00FFFFFF
            name = str(item.get("name", f"Method_{rid:04X}"))
            rva = int(item.get("rva", 0))

            cil_hex = item.get("cil_hex", item.get("cil", item.get("bytecode", "")))
            body_hex = item.get("body_hex", item.get("raw_body", ""))

            cil_bytes = bytes.fromhex(cil_hex) if cil_hex else b""
            raw_body = bytes.fromhex(body_hex) if body_hex else b""

            if raw_body and not cil_bytes:
                hdr = CorILMethodParser.parse_method_header(raw_body)
                if hdr:
                    cil_bytes = hdr.code_bytes
                    fmt_str = hdr.format.value
                    code_sz = hdr.code_size
                    m_stack = hdr.max_stack
                    l_sig = hdr.local_var_sig_tok
                else:
                    cil_bytes = raw_body[1:] if len(raw_body) > 1 else raw_body
                    fmt_str = "Tiny"
                    code_sz = len(cil_bytes)
                    m_stack = 8
                    l_sig = 0
            else:
                fmt_str = item.get("format", "Tiny" if len(cil_bytes) < 64 else "Fat")
                code_sz = int(item.get("code_size", len(cil_bytes)))
                m_stack = int(item.get("max_stack", 8))
                l_sig = int(item.get("local_var_sig_tok", 0))
                if not raw_body:
                    if fmt_str == "Tiny" and len(cil_bytes) < 64:
                        raw_body = CorILMethodParser.build_tiny_method(cil_bytes)
                    else:
                        raw_body = CorILMethodParser.build_fat_method(
                            cil_bytes, max_stack=m_stack, local_sig=l_sig
                        )

            is_valid, _ = CorILMethodParser.validate_cil_instructions(cil_bytes)

            records.append(
                JITMethodRecord(
                    token=token,
                    rid=rid,
                    name=name,
                    rva=rva,
                    format=fmt_str,
                    code_size=code_sz,
                    max_stack=m_stack,
                    local_var_sig_tok=l_sig,
                    cil_bytes=cil_bytes,
                    raw_method_body=raw_body,
                    verified_cil=is_valid,
                )
            )

        return records

    @classmethod
    def ingest_raw_jit_stream(cls, stream_bytes: bytes) -> List[JITMethodRecord]:
        """Ingests compact binary JIT dump stream ([JITD magic, count, records...])."""
        if len(stream_bytes) < 8:
            return []
        if len(stream_bytes) > cls.MAX_DUMP_SIZE:
            raise SecurityError("Raw JIT stream exceeds memory bounds")

        magic = stream_bytes[:4]
        if magic != cls.MAGIC_JIT_BINARY:
            return []

        count = struct.unpack_from("<I", stream_bytes, 4)[0]
        offset = 8
        records: List[JITMethodRecord] = []

        for idx in range(count):
            if offset + 20 > len(stream_bytes):
                break
            token, rva, code_sz, m_stack, l_sig = struct.unpack_from("<IIHHII", stream_bytes, offset)[:5]
            # Unpack: token (4), rva (4), code_sz (4), m_stack (2), flags (2), l_sig (4) -> 20 bytes
            token, rva, code_sz = struct.unpack_from("<III", stream_bytes, offset)
            m_stack, flags = struct.unpack_from("<HH", stream_bytes, offset + 12)
            l_sig = struct.unpack_from("<I", stream_bytes, offset + 16)[0]
            offset += 20

            if offset + code_sz > len(stream_bytes):
                break
            cil_bytes = stream_bytes[offset : offset + code_sz]
            offset += code_sz

            fmt_str = "Tiny" if (flags & 0x03) == 0x02 else "Fat"
            if fmt_str == "Tiny" and len(cil_bytes) < 64:
                raw_body = CorILMethodParser.build_tiny_method(cil_bytes)
            else:
                raw_body = CorILMethodParser.build_fat_method(
                    cil_bytes, max_stack=m_stack, local_sig=l_sig
                )

            is_valid, _ = CorILMethodParser.validate_cil_instructions(cil_bytes)
            rid = token & 0x00FFFFFF

            records.append(
                JITMethodRecord(
                    token=token,
                    rid=rid,
                    name=f"Method_{rid:04X}",
                    rva=rva,
                    format=fmt_str,
                    code_size=code_sz,
                    max_stack=m_stack,
                    local_var_sig_tok=l_sig,
                    cil_bytes=cil_bytes,
                    raw_method_body=raw_body,
                    verified_cil=is_valid,
                )
            )

        return records

    @classmethod
    def ingest_memory_dump(
        cls, dump_bytes: bytes, base_address: int = 0
    ) -> List[JITMethodRecord]:
        """Scans process memory dump for embedded ECMA-335 CorILMethod headers."""
        if len(dump_bytes) > cls.MAX_DUMP_SIZE:
            raise SecurityError("Memory dump buffer exceeds safety limits")

        records: List[JITMethodRecord] = []
        offset = 0
        method_idx = 1

        while offset < len(dump_bytes) - 4:
            first = dump_bytes[offset]
            fmt = first & 0x03

            if fmt in (0x02, 0x03):
                hdr = CorILMethodParser.parse_method_header(dump_bytes, offset)
                if hdr and hdr.code_size > 0 and hdr.code_size <= 65536:
                    is_valid, _ = CorILMethodParser.validate_cil_instructions(hdr.code_bytes)
                    if is_valid and len(hdr.code_bytes) >= 1:
                        # Ensure last byte is ret (0x2A) or valid control flow
                        if hdr.code_bytes[-1] in (0x2A, 0x7A, 0x2B, 0x38, 0x00):
                            token = 0x06000000 | method_idx
                            records.append(
                                JITMethodRecord(
                                    token=token,
                                    rid=method_idx,
                                    name=f"DumpedMethod_{method_idx:04X}",
                                    rva=base_address + offset,
                                    format=hdr.format.value,
                                    code_size=hdr.code_size,
                                    max_stack=hdr.max_stack,
                                    local_var_sig_tok=hdr.local_var_sig_tok,
                                    cil_bytes=hdr.code_bytes,
                                    raw_method_body=hdr.raw_body,
                                    verified_cil=True,
                                )
                            )
                            method_idx += 1
                            offset += hdr.total_size
                            continue
            offset += 1

        return records

    @classmethod
    def export_jit_json(cls, records: List[JITMethodRecord], indent: int = 2) -> str:
        """Exports list of JIT method records to formatted JSON."""
        data = {
            "method_count": len(records),
            "methods": [r.to_dict() for r in records],
        }
        return json.dumps(data, indent=indent)
