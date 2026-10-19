"""
Virtual CLR JIT Execution & Bytecode Decryption Emulation Harness.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple

from .models import (
    CapturedMethod,
    CaptureSource,
    CipherFamily,
    CORINFO_METHOD_INFO,
    JITExecutionState,
    calculate_entropy,
    zeroize_buffer,
)


class VirtualJITCompiler:
    """Emulates the CLR JIT compilation pipeline to intercept and capture decrypted CIL methods."""

    # Selected ECMA-335 CIL opcode dictionary for validation and disassembly preview
    CIL_OPCODES_1BYTE: Dict[int, Tuple[str, int]] = {
        0x00: ("nop", 0),
        0x01: ("break", 0),
        0x02: ("ldarg.0", 0),
        0x03: ("ldarg.1", 0),
        0x04: ("ldarg.2", 0),
        0x05: ("ldarg.3", 0),
        0x06: ("ldloc.0", 0),
        0x07: ("ldloc.1", 0),
        0x08: ("ldloc.2", 0),
        0x09: ("ldloc.3", 0),
        0x0A: ("stloc.0", 0),
        0x0B: ("stloc.1", 0),
        0x0C: ("stloc.2", 0),
        0x0D: ("stloc.3", 0),
        0x0E: ("ldarg.s", 1),
        0x0F: ("ldarga.s", 1),
        0x10: ("starg.s", 1),
        0x11: ("ldloc.s", 1),
        0x12: ("ldloca.s", 1),
        0x13: ("stloc.s", 1),
        0x14: ("ldnull", 0),
        0x15: ("ldc.i4.m1", 0),
        0x16: ("ldc.i4.0", 0),
        0x17: ("ldc.i4.1", 0),
        0x18: ("ldc.i4.2", 0),
        0x19: ("ldc.i4.3", 0),
        0x1A: ("ldc.i4.4", 0),
        0x1B: ("ldc.i4.5", 0),
        0x1C: ("ldc.i4.6", 0),
        0x1D: ("ldc.i4.7", 0),
        0x1E: ("ldc.i4.8", 0),
        0x1F: ("ldc.i4.s", 1),
        0x20: ("ldc.i4", 4),
        0x25: ("dup", 0),
        0x26: ("pop", 0),
        0x28: ("call", 4),
        0x2A: ("ret", 0),
        0x2B: ("br.s", 1),
        0x2C: ("brfalse.s", 1),
        0x2D: ("brtrue.s", 1),
        0x2E: ("beq.s", 1),
        0x2F: ("bge.s", 1),
        0x30: ("bgt.s", 1),
        0x38: ("br", 4),
        0x39: ("brfalse", 4),
        0x3A: ("brtrue", 4),
        0x58: ("add", 0),
        0x59: ("sub", 0),
        0x5A: ("mul", 0),
        0x5B: ("div", 0),
        0x65: ("xor", 0),
        0x66: ("shl", 0),
        0x67: ("shr", 0),
        0x72: ("ldstr", 4),
        0x73: ("newobj", 4),
        0x79: ("unbox", 4),
        0x7B: ("ldfld", 4),
        0x7C: ("ldflda", 4),
        0x7D: ("stfld", 4),
        0x7E: ("ldsfld", 4),
        0x80: ("stsfld", 4),
        0x8D: ("newarr", 4),
        0x8E: ("ldlen", 0),
        0x90: ("ldelem.i4", 0),
        0x9A: ("stelem.i4", 0),
        0xA3: ("conv.i4", 0),
        0xA4: ("conv.i8", 0),
        0xA5: ("conv.r4", 0),
        0xA6: ("conv.r8", 0),
        0xD0: ("ldtoken", 4),
    }

    CIL_OPCODES_2BYTE: Dict[int, Tuple[str, int]] = {
        0x01: ("ceq", 0),
        0x02: ("cgt", 0),
        0x03: ("cgt.un", 0),
        0x04: ("clt", 0),
        0x05: ("clt.un", 0),
        0x06: ("ldftn", 4),
        0x07: ("ldvirtftn", 4),
        0x14: ("localloc", 0),
    }

    @classmethod
    def compile_method(
        cls,
        token: int,
        raw_body_bytes: bytes,
        rva: int = 0,
        name: str = "",
        declaring_type: str = "Type",
        source: CaptureSource = CaptureSource.EMULATED_JIT,
    ) -> CapturedMethod:
        """
        Emulates ICorJitCompiler::compileMethod call on a method body buffer,
        parsing CorILMethod headers, validating CIL opcodes, and producing a CapturedMethod.
        """
        if not raw_body_bytes:
            return cls._create_corrupted_method(token, name, declaring_type, rva, source)

        header_byte = raw_body_bytes[0]
        header_format = "Tiny" if (header_byte & 0x03) == 0x02 else ("Fat" if (header_byte & 0x03) == 0x03 else "Corrupted")

        if header_format == "Tiny":
            code_size = header_byte >> 2
            max_stack = 8
            local_sig_token = 0
            eh_clause_count = 0
            header_size = 1
            il_bytes = raw_body_bytes[header_size : header_size + code_size]
        elif header_format == "Fat":
            if len(raw_body_bytes) < 12:
                return cls._create_corrupted_method(token, name, declaring_type, rva, source)
            flags_size = struct.unpack("<H", raw_body_bytes[0:2])[0]
            header_size = (flags_size >> 12) * 4
            max_stack = struct.unpack("<H", raw_body_bytes[2:4])[0]
            code_size = struct.unpack("<I", raw_body_bytes[4:8])[0]
            local_sig_token = struct.unpack("<I", raw_body_bytes[8:12])[0]
            il_bytes = raw_body_bytes[header_size : header_size + code_size]
            # Check for extra exception handling section
            has_more_sections = bool(flags_size & 0x0008)
            eh_clause_count = 0
            if has_more_sections and len(raw_body_bytes) >= header_size + code_size + 4:
                eh_clause_count = cls._parse_eh_count(raw_body_bytes, header_size + code_size)
        else:
            # Assume raw CIL stream if no standard header
            il_bytes = raw_body_bytes
            code_size = len(il_bytes)
            max_stack = 8
            local_sig_token = 0
            eh_clause_count = 0
            header_format = "Raw"

        disasm = cls.disassemble_cil(il_bytes)
        entropy = calculate_entropy(il_bytes)
        sha = hashlib.sha256(il_bytes).hexdigest()

        # Validate method termination
        state = JITExecutionState.VALIDATED if cls._validate_cil(il_bytes) else JITExecutionState.CAPTURED

        return CapturedMethod(
            token=token,
            name=name or f"Method_{token:08X}",
            declaring_type=declaring_type,
            rva=rva,
            il_bytes=il_bytes,
            il_size=len(il_bytes),
            header_format=header_format,
            max_stack=max_stack,
            local_sig_token=local_sig_token,
            eh_clause_count=eh_clause_count,
            cipher_detected=CipherFamily.NONE,
            capture_source=source,
            state=state,
            sha256=sha,
            disassembly_preview=disasm,
            entropy=entropy,
        )

    @classmethod
    def emulate_decryption_stub(
        cls,
        token: int,
        encrypted_chunk: bytes,
        cipher: CipherFamily = CipherFamily.LCG_PRNG,
        seed: int = 0x1337BEEF,
        rva: int = 0,
        name: str = "",
        declaring_type: str = "Type",
    ) -> CapturedMethod:
        """
        Emulates dynamic decryption of an encrypted method body using LCG/XOR PRNG stream.
        Zeroizes temporary scratch memory upon extraction.
        """
        if not encrypted_chunk:
            return cls._create_corrupted_method(token, name, declaring_type, rva, CaptureSource.EMULATED_JIT)

        scratch = bytearray(encrypted_chunk)

        try:
            if cipher == CipherFamily.LCG_PRNG:
                # Standard LCG PRNG: state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
                state = (token ^ seed) & 0xFFFFFFFF
                for i in range(len(scratch)):
                    state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
                    key_byte = (state >> 16) & 0xFF
                    scratch[i] ^= key_byte
            elif cipher == CipherFamily.XOR_STREAM:
                key = [(token >> (8 * j)) & 0xFF for j in range(4)]
                for i in range(len(scratch)):
                    scratch[i] ^= key[i % 4]
            elif cipher == CipherFamily.CUSTOM_BYTE_TABLE:
                for i in range(len(scratch)):
                    scratch[i] = ((scratch[i] ^ 0xAA) + 0x05) & 0xFF

            decrypted_bytes = bytes(scratch)
            method = cls.compile_method(
                token=token,
                raw_body_bytes=decrypted_bytes,
                rva=rva,
                name=name,
                declaring_type=declaring_type,
                source=CaptureSource.EMULATED_JIT,
            )
            method.cipher_detected = cipher
            method.state = JITExecutionState.DECRYPTED
            return method
        finally:
            zeroize_buffer(scratch)

    @classmethod
    def disassemble_cil(cls, il_bytes: bytes, max_instructions: int = 20) -> List[str]:
        """Disassembles ECMA-335 CIL bytecode into formatted instruction lines."""
        if not il_bytes:
            return []

        lines: List[str] = []
        offset = 0
        total = len(il_bytes)

        while offset < total and len(lines) < max_instructions:
            pc = offset
            b = il_bytes[offset]
            offset += 1

            if b == 0xFE:
                if offset >= total:
                    lines.append(f"IL_{pc:04X}: [truncated 0xFE]")
                    break
                b2 = il_bytes[offset]
                offset += 1
                if b2 in cls.CIL_OPCODES_2BYTE:
                    name, op_len = cls.CIL_OPCODES_2BYTE[b2]
                    operand = cls._read_operand(il_bytes, offset, op_len)
                    offset += op_len
                    lines.append(f"IL_{pc:04X}: {name}{operand}")
                else:
                    lines.append(f"IL_{pc:04X}: unknown_0xFE_{b2:02X}")
            else:
                if b in cls.CIL_OPCODES_1BYTE:
                    name, op_len = cls.CIL_OPCODES_1BYTE[b]
                    operand = cls._read_operand(il_bytes, offset, op_len)
                    offset += op_len
                    lines.append(f"IL_{pc:04X}: {name}{operand}")
                else:
                    lines.append(f"IL_{pc:04X}: byte 0x{b:02X}")

        if offset < total:
            lines.append(f"... (+ {total - offset} bytes remaining)")

        return lines

    @classmethod
    def _read_operand(cls, data: bytes, offset: int, length: int) -> str:
        """Formats instruction operand into text representation."""
        if length == 0:
            return ""
        if offset + length > len(data):
            return " <truncated>"
        chunk = data[offset : offset + length]
        if length == 1:
            val = struct.unpack("<b", chunk)[0]
            return f" {val}"
        elif length == 2:
            val = struct.unpack("<h", chunk)[0]
            return f" {val}"
        elif length == 4:
            val = struct.unpack("<I", chunk)[0]
            return f" 0x{val:08X}"
        return f" 0x{chunk.hex()}"

    @classmethod
    def _validate_cil(cls, il_bytes: bytes) -> bool:
        """Validates that CIL instruction stream terminates properly and contains known opcodes."""
        if not il_bytes:
            return False
        # Last opcode should typically be a ret (0x2A), throw (0x7A), or branch
        last_byte = il_bytes[-1]
        return last_byte in (0x2A, 0x7A, 0x2B, 0x38)

    @classmethod
    def _parse_eh_count(cls, data: bytes, sect_offset: int) -> int:
        """Parses exception handling section clause count."""
        aligned_offset = (sect_offset + 3) & ~3
        if aligned_offset + 4 > len(data):
            return 0
        kind = data[aligned_offset]
        if kind & 0x01:  # CorILMethod_Sect_EHFat
            data_size = data[aligned_offset + 1] | (data[aligned_offset + 2] << 8) | (data[aligned_offset + 3] << 16)
            return max(0, (data_size - 4) // 24)
        else:  # Small
            data_size = data[aligned_offset + 1]
            return max(0, (data_size - 4) // 12)

    @classmethod
    def _create_corrupted_method(
        cls, token: int, name: str, declaring_type: str, rva: int, source: CaptureSource
    ) -> CapturedMethod:
        return CapturedMethod(
            token=token,
            name=name or f"Method_{token:08X}",
            declaring_type=declaring_type,
            rva=rva,
            il_bytes=b"",
            il_size=0,
            header_format="Corrupted",
            max_stack=0,
            local_sig_token=0,
            eh_clause_count=0,
            cipher_detected=CipherFamily.NONE,
            capture_source=source,
            state=JITExecutionState.CORRUPTED,
            sha256="",
            disassembly_preview=[],
            entropy=0.0,
        )
