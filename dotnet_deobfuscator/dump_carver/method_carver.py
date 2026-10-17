"""
Residual CIL Method Body Scanner and Instruction Validator.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import List, Optional, Tuple

from .models import CILMethodHeaderFormat, CarvedMethod, calculate_entropy


class MethodCarver:
    """
    Scans memory pages for residual Tiny and Fat ECMA-335 CIL method bodies,
    verifying bytecode integrity, opcodes, and termination invariants.
    """

    KNOWN_ONE_BYTE_OPCODES = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x25, 0x26, 0x28, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
        0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7A, 0x7B, 0x7C,
        0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94,
        0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2,
        0xD0, 0xD1, 0xD2, 0xD3, 0xDC, 0xDD, 0xDE,
    }

    # Opcode immediate payload lengths (in bytes)
    OPCODE_OPERAND_SIZES = {
        0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 1,  # ldarg.s, etc.
        0x1F: 1,  # ldc.i4.s
        0x20: 4, 0x21: 8, 0x22: 4, 0x23: 8,  # ldc.i4, ldc.i8, ldc.r4, ldc.r8
        0x28: 4, 0x6F: 4, 0x72: 4, 0x73: 4, 0x74: 4, 0x75: 4,  # call, callvirt, ldstr, newobj, etc.
        0x7B: 4, 0x7C: 4, 0x7D: 4, 0x7E: 4, 0x7F: 4, 0x80: 4,  # ldfld, stfld, etc.
        0x2B: 1, 0x2C: 1, 0x2D: 1, 0x2E: 1, 0x2F: 1, 0x30: 1, 0x31: 1, 0x32: 1,  # short branches
        0x38: 4, 0x39: 4, 0x3A: 4, 0x3B: 4, 0x3C: 4, 0x3D: 4, 0x3E: 4, 0x3F: 4,  # 32-bit branches
        0x8C: 4, 0x8D: 4,  # box, newarr
        0xD0: 4,  # ldtoken
    }

    @classmethod
    def scan_methods(
        cls, data: bytes, search_start: int = 0, search_end: Optional[int] = None, max_methods: int = 100
    ) -> List[CarvedMethod]:
        """
        Scans data range for residual Tiny and Fat CIL method bodies.
        """
        results: List[CarvedMethod] = []
        data_len = len(data)
        end = min(search_end or data_len, data_len)
        curr = search_start

        while curr < end and len(results) < max_methods:
            # 1. Try parsing Fat header (requires 12 bytes aligned to 4)
            if curr % 4 == 0 and curr + 12 <= end:
                fat_res = cls._try_parse_fat_header(data, curr, end)
                if fat_res is not None:
                    method_obj, consumed = fat_res
                    method_obj.token = 0x06000000 + len(results) + 1
                    results.append(method_obj)
                    curr += consumed
                    continue

            # 2. Try parsing Tiny header (1 byte header)
            tiny_res = cls._try_parse_tiny_header(data, curr, end)
            if tiny_res is not None:
                method_obj, consumed = tiny_res
                method_obj.token = 0x06000000 + len(results) + 1
                results.append(method_obj)
                curr += consumed
                continue

            curr += 1

        return results

    @classmethod
    def _try_parse_fat_header(
        cls, data: bytes, offset: int, limit: int
    ) -> Optional[Tuple[CarvedMethod, int]]:
        """Attempts to parse a 12-byte Fat CIL method header."""
        flags_and_size = struct.unpack_from("<H", data, offset)[0]
        flags = flags_and_size & 0x0F
        if flags != 0x03:
            return None

        header_size = (flags_and_size >> 12) * 4
        if header_size < 12 or offset + header_size > limit:
            return None

        max_stack, code_size, local_sig = struct.unpack_from("<HII", data, offset + 2)
        if code_size < 1 or code_size > 65536 or offset + header_size + code_size > limit:
            return None

        bytecode = data[offset + header_size : offset + header_size + code_size]
        is_valid, ins_count, has_term = cls._validate_bytecode(bytecode)
        if not is_valid:
            return None

        entropy = calculate_entropy(bytecode)
        # Avoid all zeroes or extreme noise
        if entropy == 0.0 and code_size > 4:
            return None

        method = CarvedMethod(
            token=0,
            offset=offset,
            format=CILMethodHeaderFormat.FAT,
            max_stack=max_stack,
            code_size=code_size,
            local_sig_tok=local_sig,
            bytecode_hex=bytecode.hex().upper(),
            entropy=entropy,
            instructions_count=ins_count,
            has_valid_termination=has_term,
        )
        return method, header_size + code_size

    @classmethod
    def _try_parse_tiny_header(
        cls, data: bytes, offset: int, limit: int
    ) -> Optional[Tuple[CarvedMethod, int]]:
        """Attempts to parse a 1-byte Tiny CIL method header."""
        b0 = data[offset]
        if (b0 & 0x03) != 0x02:
            return None

        code_size = b0 >> 2
        if code_size < 1 or code_size > 63 or offset + 1 + code_size > limit:
            return None

        bytecode = data[offset + 1 : offset + 1 + code_size]
        is_valid, ins_count, has_term = cls._validate_bytecode(bytecode)
        if not is_valid or not has_term:
            return None

        entropy = calculate_entropy(bytecode)
        if entropy == 0.0 and code_size > 2:
            return None

        method = CarvedMethod(
            token=0,
            offset=offset,
            format=CILMethodHeaderFormat.TINY,
            max_stack=8,
            code_size=code_size,
            local_sig_tok=0,
            bytecode_hex=bytecode.hex().upper(),
            entropy=entropy,
            instructions_count=ins_count,
            has_valid_termination=has_term,
        )
        return method, 1 + code_size

    @classmethod
    def _validate_bytecode(cls, bytecode: bytes) -> Tuple[bool, int, bool]:
        """
        Validates instruction sequence, counts valid opcodes, and checks termination.
        """
        b_len = len(bytecode)
        if b_len == 0:
            return False, 0, False

        curr = 0
        ins_count = 0
        has_termination = False

        while curr < b_len:
            op = bytecode[curr]
            curr += 1
            ins_count += 1

            if op == 0x2A:  # ret
                has_termination = True
            elif op == 0x7A:  # throw
                has_termination = True

            # Two-byte opcode prefix
            if op == 0xFE:
                if curr >= b_len:
                    return False, ins_count, False
                _sub_op = bytecode[curr]
                curr += 1
                continue

            if op not in cls.KNOWN_ONE_BYTE_OPCODES:
                # If unknown opcode encountered in first 2 instructions, reject
                if ins_count <= 2:
                    return False, ins_count, False
                # Skip 1 byte and continue checking
                continue

            # Advance immediate operand size if known
            op_size = cls.OPCODE_OPERAND_SIZES.get(op, 0)
            if curr + op_size > b_len:
                return False, ins_count, False
            curr += op_size

        return ins_count > 0, ins_count, has_termination
