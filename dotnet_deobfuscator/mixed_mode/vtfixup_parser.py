"""
VTableFixup Parser for Mixed-Mode .NET Assemblies.
Parses IMAGE_COR_VTABLEFIXUPS entries, decodes slot tokens, and maps transition targets.
Engineered & Audited by Maya Thorne.
"""

import ctypes
import struct
from typing import Any, List, Optional, Tuple, Union

from .models import (
    SecurityError,
    VTFixupFlag,
    VTFixupSlot,
    VTFixupTable,
    VTFixupType,
)


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
        # Fallback manual zeroization
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0


class VTFixupParser:
    """Parses ECMA-335 / Win32 VTableFixup tables and resolves slot tokens."""

    MAX_TABLES = 1024
    MAX_SLOTS_PER_TABLE = 16384

    TOKEN_TYPE_MAP = {
        0x01: "TypeRef",
        0x02: "TypeDef",
        0x04: "FieldDef",
        0x06: "MethodDef",
        0x08: "ParamDef",
        0x0A: "MemberRef",
        0x11: "StandAloneSig",
        0x14: "Event",
        0x17: "Property",
        0x20: "Permission",
        0x23: "Assembly",
        0x2B: "MethodSpec",
    }

    @staticmethod
    def _rva_to_offset(rva: int, sec_rva_map: List[Tuple[int, int, int, int]]) -> Optional[int]:
        """Translates Relative Virtual Address (RVA) to raw file offset."""
        if rva <= 0:
            return None
        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            span = max(v_size, raw_size)
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size:
                    return raw_ptr + delta
        return None

    @classmethod
    def parse_vtfixups(
        cls,
        data: bytes,
        vtfixup_rva: int,
        vtfixup_size: int,
        sec_rva_map: List[Tuple[int, int, int, int]],
    ) -> List[VTFixupTable]:
        """
        Parses all IMAGE_COR_VTABLEFIXUP headers and iterates their slots.

        Layout of each IMAGE_COR_VTABLEFIXUP (8 bytes):
          RVA:   uint32 (vtable slot array location)
          Count: uint16 (number of slots)
          Type:  uint16 (flags)
        """
        tables: List[VTFixupTable] = []
        if vtfixup_rva <= 0 or vtfixup_size < 8:
            return tables

        base_offset = cls._rva_to_offset(vtfixup_rva, sec_rva_map)
        if base_offset is None or base_offset + 8 > len(data):
            return tables

        num_headers = min(vtfixup_size // 8, cls.MAX_TABLES)
        curr_offset = base_offset

        for table_idx in range(num_headers):
            if curr_offset + 8 > len(data) or curr_offset + 8 > base_offset + vtfixup_size:
                break

            tbl_rva, slot_count, type_flags = struct.unpack_from("<IHH", data, curr_offset)
            curr_offset += 8

            if slot_count == 0 or slot_count > cls.MAX_SLOTS_PER_TABLE:
                continue

            is_64bit = bool(type_flags & VTFixupFlag.COR_VTABLE_64BIT)
            slot_width = 8 if is_64bit else 4
            fixup_type = VTFixupType.SLOT_64BIT if is_64bit else VTFixupType.SLOT_32BIT

            flags_names: List[str] = []
            if type_flags & VTFixupFlag.COR_VTABLE_32BIT:
                flags_names.append("COR_VTABLE_32BIT")
            if type_flags & VTFixupFlag.COR_VTABLE_64BIT:
                flags_names.append("COR_VTABLE_64BIT")
            if type_flags & VTFixupFlag.COR_VTABLE_FROM_UNMANAGED:
                flags_names.append("COR_VTABLE_FROM_UNMANAGED")
            if type_flags & VTFixupFlag.COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN:
                flags_names.append("COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN")
            if type_flags & VTFixupFlag.COR_VTABLE_CALL_MOST_DERIVED:
                flags_names.append("COR_VTABLE_CALL_MOST_DERIVED")

            tbl_offset = cls._rva_to_offset(tbl_rva, sec_rva_map)
            slots: List[VTFixupSlot] = []

            if tbl_offset is not None and tbl_offset < len(data):
                for s_idx in range(slot_count):
                    s_rva = tbl_rva + (s_idx * slot_width)
                    s_off = cls._rva_to_offset(s_rva, sec_rva_map)
                    if s_off is None or s_off + slot_width > len(data):
                        break

                    if is_64bit:
                        token_val = struct.unpack_from("<Q", data, s_off)[0]
                        # In .NET 64-bit VTFixup slots on disk, the low 32 bits hold the MethodDef token
                        token_int = token_val & 0xFFFFFFFF
                    else:
                        token_int = struct.unpack_from("<I", data, s_off)[0]

                    table_id = (token_int >> 24) & 0xFF
                    token_type_name = cls.TOKEN_TYPE_MAP.get(table_id, "UnknownToken")
                    token_hex = f"0x{token_int:08X}"

                    is_from_unmanaged = bool(type_flags & VTFixupFlag.COR_VTABLE_FROM_UNMANAGED)
                    is_call_most = bool(type_flags & VTFixupFlag.COR_VTABLE_CALL_MOST_DERIVED)

                    desc_parts = []
                    if is_from_unmanaged:
                        desc_parts.append("Native-to-Managed Call Thunk")
                    if is_call_most:
                        desc_parts.append("Virtual Call Most Derived")
                    desc_parts.append(f"Target: {token_type_name} {token_hex}")
                    description = " | ".join(desc_parts)

                    slots.append(
                        VTFixupSlot(
                            slot_index=s_idx,
                            slot_rva=s_rva,
                            slot_offset=s_off,
                            target_token_hex=token_hex,
                            target_token_int=token_int,
                            token_type_name=token_type_name,
                            flags_int=type_flags,
                            is_from_unmanaged=is_from_unmanaged,
                            is_call_most_derived=is_call_most,
                            description=description,
                        )
                    )

            tables.append(
                VTFixupTable(
                    table_index=table_idx,
                    table_rva=tbl_rva,
                    table_offset=tbl_offset,
                    slot_count=slot_count,
                    fixup_type=fixup_type,
                    flags_int=type_flags,
                    flags_names=flags_names,
                    slots=slots,
                )
            )

        return tables
