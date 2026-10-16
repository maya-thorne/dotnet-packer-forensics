"""
ReadyToRun (R2R) PE Header & Section Parser.
Parses ECMA-335 ManagedNativeHeader, READYTORUN_HEADER, sections, and RUNTIME_FUNCTION entries.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    MethodDefEntry,
    R2RHeader,
    R2RSection,
    R2RSectionType,
    RuntimeFunctionEntry,
    SecurityError,
)


class R2RParser:
    """Parses ReadyToRun (R2R) metadata structures and section tables."""

    RTR_MAGIC = 0x00525452  # 'RTR\0' in little-endian
    MAX_SECTIONS = 128
    MAX_RUNTIME_FUNCTIONS = 65536
    MAX_ENTRYPOINTS = 65536

    SECTION_DESCRIPTIONS: Dict[int, str] = {
        R2RSectionType.COMPILER_IDENTIFIER: "Compiler Identification String (Crossgen2 / CoreCLR)",
        R2RSectionType.IMPORT_SECTIONS: "Module Import Sections (Eager & Lazy Thunk Tables)",
        R2RSectionType.RUNTIME_FUNCTIONS: "Windows SEH RUNTIME_FUNCTION Array (Native Code Range)",
        R2RSectionType.METHODDEF_ENTRYPOINTS: "MethodDef Token to Native EntryPoint Map",
        R2RSectionType.EXCEPTION_INFO: "Native Exception Handling & Clause Directory",
        R2RSectionType.DEBUG_INFO: "Native Machine Code to IL Debug Sequence Map",
        R2RSectionType.DELAYLOAD_METHODCALL_THUNKS: "Delay-load Method Call Thunk Table",
        R2RSectionType.AVAILABLE_TYPES: "Exported & Available Types Hash Table",
        R2RSectionType.INSTANCE_METHOD_ENTRYPOINTS: "Generic Instance Method EntryPoints",
        R2RSectionType.INLINING_INFO: "JIT Inlining Metadata & Method Boundaries",
        R2RSectionType.PROFILE_DATA: "Profile-Guided Optimization (PGO) Instrumentation",
        R2RSectionType.MANIFEST_METADATA: "Embedded ReadyToRun ECMA-335 Manifest Metadata",
        R2RSectionType.ATTRIBUTE_PRESENCE: "Custom Attribute Presence Bitmask Filter",
        R2RSectionType.INLINING_INFO2: "Enhanced Inlining Information & Inlinee Graphs",
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
    def find_r2r_header(
        cls,
        data: bytes,
        sec_rva_map: List[Tuple[int, int, int, int]],
        managed_native_rva: int = 0,
    ) -> Optional[Tuple[int, int]]:
        """
        Locates the READYTORUN_HEADER offset and RVA.
        First tries managed_native_rva from Cor20Header.
        Falls back to scanning section buffers for 'RTR\0' magic with valid structure.
        """
        if managed_native_rva > 0:
            offset = cls._rva_to_offset(managed_native_rva, sec_rva_map)
            if offset is not None and offset + 16 <= len(data):
                magic = struct.unpack_from("<I", data, offset)[0]
                if magic == cls.RTR_MAGIC:
                    return offset, managed_native_rva

        # Fallback scan across PE sections for RTR magic
        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            sec_end = min(raw_ptr + raw_size, len(data))
            if raw_ptr >= sec_end:
                continue
            pos = raw_ptr
            while pos + 16 <= sec_end:
                idx = data.find(b"RTR\x00", pos, sec_end)
                if idx == -1 or idx + 16 > sec_end:
                    break
                # Validate candidate header
                magic, maj_ver, min_ver, flags, num_secs = struct.unpack_from("<IHHII", data, idx)
                if magic == cls.RTR_MAGIC and 1 <= maj_ver <= 32 and num_secs <= cls.MAX_SECTIONS:
                    candidate_rva = v_addr + (idx - raw_ptr)
                    return idx, candidate_rva
                pos = idx + 4

        return None

    @classmethod
    def parse(
        cls,
        data: bytes,
        sec_rva_map: List[Tuple[int, int, int, int]],
        managed_native_rva: int = 0,
    ) -> Tuple[
        Optional[R2RHeader],
        List[R2RSection],
        List[RuntimeFunctionEntry],
        List[MethodDefEntry],
        Optional[str],
    ]:
        """
        Parses ReadyToRun header and all contained sections.
        Returns: (header, sections, runtime_functions, method_entrypoints, compiler_id)
        """
        loc = cls.find_r2r_header(data, sec_rva_map, managed_native_rva)
        if not loc:
            return None, [], [], [], None

        hdr_offset, hdr_rva = loc
        if hdr_offset + 16 > len(data):
            return None, [], [], [], None

        magic, maj_ver, min_ver, flags, num_sections = struct.unpack_from("<IHHII", data, hdr_offset)
        if magic != cls.RTR_MAGIC:
            return None, [], [], [], None

        num_sections = min(num_sections, cls.MAX_SECTIONS)
        header = R2RHeader(
            magic=magic,
            magic_str="RTR",
            major_version=maj_ver,
            minor_version=min_ver,
            flags=flags,
            num_sections=num_sections,
            entrypoint_rva=hdr_rva,
        )

        sections: List[R2RSection] = []
        runtime_functions: List[RuntimeFunctionEntry] = []
        method_entrypoints: List[MethodDefEntry] = []
        compiler_id: Optional[str] = None

        # Each section entry in the header:
        # struct READYTORUN_SECTION {
        #     uint32_t Type;
        #     IMAGE_DATA_DIRECTORY Section; // RVA: uint32, Size: uint32
        # }; -> 12 bytes per section
        curr_offset = hdr_offset + 16
        for sec_idx in range(num_sections):
            if curr_offset + 12 > len(data):
                break
            sec_type, sec_rva, sec_size = struct.unpack_from("<III", data, curr_offset)
            curr_offset += 12

            raw_off = cls._rva_to_offset(sec_rva, sec_rva_map)
            type_name = R2RSectionType.get_name(sec_type)
            desc = cls.SECTION_DESCRIPTIONS.get(sec_type, f"ReadyToRun Section {sec_type}")

            section_obj = R2RSection(
                type_id=sec_type,
                type_name=type_name,
                rva=sec_rva,
                size=sec_size,
                raw_offset=raw_off,
                description=desc,
            )
            sections.append(section_obj)

            if raw_off is None or raw_off >= len(data):
                continue

            # Process individual section contents
            valid_size = min(sec_size, len(data) - raw_off)
            if sec_type == R2RSectionType.COMPILER_IDENTIFIER:
                compiler_id = cls._parse_compiler_identifier(data, raw_off, valid_size)

            elif sec_type == R2RSectionType.RUNTIME_FUNCTIONS:
                runtime_functions = cls._parse_runtime_functions(data, raw_off, valid_size)

            elif sec_type == R2RSectionType.METHODDEF_ENTRYPOINTS:
                method_entrypoints = cls._parse_methoddef_entrypoints(
                    data, raw_off, valid_size, runtime_functions, sec_rva_map
                )

        # Cross-reference method entrypoints with runtime functions
        if method_entrypoints and runtime_functions:
            for ep in method_entrypoints:
                if 0 <= ep.runtime_function_index < len(runtime_functions):
                    rf = runtime_functions[ep.runtime_function_index]
                    rf.method_token = ep.token
                    rf.symbol_name = ep.method_name

        return header, sections, runtime_functions, method_entrypoints, compiler_id

    @classmethod
    def _parse_compiler_identifier(cls, data: bytes, raw_offset: int, size: int) -> Optional[str]:
        """Extracts compiler identification string (e.g. Crossgen2 version)."""
        if size <= 0:
            return None
        chunk = data[raw_offset : raw_offset + size]
        # Null-terminated or raw ASCII
        null_idx = chunk.find(b"\x00")
        if null_idx != -1:
            chunk = chunk[:null_idx]
        try:
            val = chunk.decode("utf-8", errors="replace").strip()
            return val if val else None
        except Exception:
            return None

    @classmethod
    def _parse_runtime_functions(
        cls, data: bytes, raw_offset: int, size: int
    ) -> List[RuntimeFunctionEntry]:
        """
        Parses array of RUNTIME_FUNCTION structures.
        Each structure is 12 bytes on x64/ARM64:
          BeginAddress:     uint32
          EndAddress:       uint32
          UnwindDataAddress: uint32
        """
        entries: List[RuntimeFunctionEntry] = []
        num_entries = min(size // 12, cls.MAX_RUNTIME_FUNCTIONS)
        curr = raw_offset
        for i in range(num_entries):
            if curr + 12 > len(data):
                break
            begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", data, curr)
            curr += 12
            size_bytes = end_rva - begin_rva if end_rva >= begin_rva else 0
            entry = RuntimeFunctionEntry(
                index=i,
                start_rva=begin_rva,
                end_rva=end_rva,
                size_bytes=size_bytes,
                unwind_info_rva=unwind_rva,
                method_token=None,
                symbol_name=None,
            )
            entries.append(entry)
        return entries

    @classmethod
    def _parse_methoddef_entrypoints(
        cls,
        data: bytes,
        raw_offset: int,
        size: int,
        runtime_functions: List[RuntimeFunctionEntry],
        sec_rva_map: List[Tuple[int, int, int, int]],
    ) -> List[MethodDefEntry]:
        """
        Parses ReadyToRun MethodDef EntryPoints section.
        Supports:
          1) Table of uint32 tokens / function indices
          2) Array of uint32 RVAs indexed by Method RID (1-based)
          3) Token-Function index pairs
        """
        entrypoints: List[MethodDefEntry] = []
        if size < 4:
            return entrypoints

        # Format detection: inspect first entry
        first_val = struct.unpack_from("<I", data, raw_offset)[0]

        # Case A: Format is (Token: uint32, FuncIndex: uint32) pairs
        if (first_val & 0xFF000000) == 0x06000000 and size >= 8:
            pair_count = min(size // 8, cls.MAX_ENTRYPOINTS)
            for i in range(pair_count):
                off = raw_offset + (i * 8)
                if off + 8 > len(data):
                    break
                tok, func_idx = struct.unpack_from("<II", data, off)
                entry_rva = 0
                if 0 <= func_idx < len(runtime_functions):
                    entry_rva = runtime_functions[func_idx].start_rva
                entrypoints.append(
                    MethodDefEntry(
                        token=tok,
                        token_hex=f"0x{tok:08X}",
                        runtime_function_index=func_idx,
                        entrypoint_rva=entry_rva,
                        method_name=f"Method_{tok:08X}",
                    )
                )
            return entrypoints

        # Case B: Array of runtime function indices (or RVAs), indexed by MethodDef RID (1-based)
        num_slots = min(size // 4, cls.MAX_ENTRYPOINTS)
        for rid in range(1, num_slots + 1):
            off = raw_offset + ((rid - 1) * 4)
            if off + 4 > len(data):
                break
            val = struct.unpack_from("<I", data, off)[0]
            if val == 0 or val == 0xFFFFFFFF:
                continue

            token = 0x06000000 | rid
            func_idx = val
            entry_rva = val
            if 0 <= val < len(runtime_functions):
                func_idx = val
                entry_rva = runtime_functions[val].start_rva
            else:
                func_idx = rid - 1

            entrypoints.append(
                MethodDefEntry(
                    token=token,
                    token_hex=f"0x{token:08X}",
                    runtime_function_index=func_idx,
                    entrypoint_rva=entry_rva,
                    method_name=f"Method_{token:08X}",
                )
            )

        return entrypoints
