"""
Parser for Windows Minidump (MDMP) and Memory Dump Container Structures.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import DumpFormat, MemoryRange


class MinidumpParser:
    """
    Parses Windows Minidump (MDMP), 32/64-bit memory list streams,
    and fallback raw memory dump structures.
    """

    MINIDUMP_SIGNATURE = b"MDMP"
    STREAM_THREAD_LIST = 3
    STREAM_MODULE_LIST = 4
    STREAM_MEMORY_LIST = 5
    STREAM_SYSTEM_INFO = 7
    STREAM_MEMORY64_LIST = 9
    STREAM_MEMORY_INFO_LIST = 16

    @classmethod
    def identify_format(cls, data: bytes) -> DumpFormat:
        """Determines the container format of the memory dump."""
        if not data or len(data) < 16:
            return DumpFormat.CORRUPTED_OR_UNKNOWN

        if data.startswith(cls.MINIDUMP_SIGNATURE):
            return DumpFormat.MINIDUMP_MDMP

        if data.startswith(b"PAGE"):
            return DumpFormat.KERNEL_CRASH_DUMP

        return DumpFormat.RAW_MEMORY_BLOCK

    @classmethod
    def parse_minidump(
        cls, data: bytes
    ) -> Tuple[List[MemoryRange], List[Dict[str, Any]], Dict[str, Any]]:
        """
        Parses Windows Minidump streams, returning memory ranges, modules, and system info.
        """
        if len(data) < 32 or not data.startswith(cls.MINIDUMP_SIGNATURE):
            return [], [], {}

        num_streams, stream_dir_rva = struct.unpack_from("<II", data, 8)
        memory_ranges: List[MemoryRange] = []
        modules: List[Dict[str, Any]] = []
        system_info: Dict[str, Any] = {}

        data_len = len(data)
        if stream_dir_rva >= data_len:
            return [], [], {}

        for i in range(num_streams):
            entry_offset = stream_dir_rva + (i * 12)
            if entry_offset + 12 > data_len:
                break
            stream_type, data_size, rva = struct.unpack_from("<III", data, entry_offset)
            if rva + data_size > data_len:
                continue

            stream_bytes = data[rva : rva + data_size]

            # 1. Standard 32-bit MemoryListStream
            if stream_type == cls.STREAM_MEMORY_LIST:
                ranges = cls._parse_memory_list_stream(stream_bytes, data_len)
                memory_ranges.extend(ranges)

            # 2. 64-bit Memory64ListStream
            elif stream_type == cls.STREAM_MEMORY64_LIST:
                ranges = cls._parse_memory64_list_stream(stream_bytes, data_len)
                memory_ranges.extend(ranges)

            # 3. ModuleListStream
            elif stream_type == cls.STREAM_MODULE_LIST:
                mod_list = cls._parse_module_list_stream(stream_bytes, data)
                modules.extend(mod_list)

            # 4. SystemInfoStream
            elif stream_type == cls.STREAM_SYSTEM_INFO:
                system_info = cls._parse_system_info_stream(stream_bytes)

        # Sort and deduplicate ranges
        memory_ranges.sort(key=lambda r: r.start_va)
        return memory_ranges, modules, system_info

    @classmethod
    def _parse_memory_list_stream(
        cls, stream_bytes: bytes, dump_len: int
    ) -> List[MemoryRange]:
        """Parses MINIDUMP_MEMORY_LIST stream containing 32-bit VA descriptors."""
        if len(stream_bytes) < 4:
            return []
        num_ranges = struct.unpack_from("<I", stream_bytes, 0)[0]
        results: List[MemoryRange] = []

        offset = 4
        for _ in range(num_ranges):
            if offset + 16 > len(stream_bytes):
                break
            start_va, data_size, rva = struct.unpack_from("<QII", stream_bytes, offset)
            offset += 16
            if rva + data_size <= dump_len and data_size > 0:
                results.append(
                    MemoryRange(start_va=start_va, size=data_size, file_offset=rva)
                )
        return results

    @classmethod
    def _parse_memory64_list_stream(
        cls, stream_bytes: bytes, dump_len: int
    ) -> List[MemoryRange]:
        """Parses MINIDUMP_MEMORY64_LIST stream containing contiguous 64-bit ranges."""
        if len(stream_bytes) < 16:
            return []
        num_ranges, base_rva = struct.unpack_from("<QQ", stream_bytes, 0)
        results: List[MemoryRange] = []

        offset = 16
        curr_rva = base_rva
        for _ in range(num_ranges):
            if offset + 16 > len(stream_bytes):
                break
            start_va, data_size = struct.unpack_from("<QQ", stream_bytes, offset)
            offset += 16
            if curr_rva + data_size <= dump_len and data_size > 0:
                results.append(
                    MemoryRange(start_va=start_va, size=data_size, file_offset=curr_rva)
                )
            curr_rva += data_size
        return results

    @classmethod
    def _parse_module_list_stream(
        cls, stream_bytes: bytes, full_dump: bytes
    ) -> List[Dict[str, Any]]:
        """Parses MINIDUMP_MODULE_LIST stream extracting loaded modules."""
        if len(stream_bytes) < 4:
            return []
        num_modules = struct.unpack_from("<I", stream_bytes, 0)[0]
        modules: List[Dict[str, Any]] = []

        offset = 4
        module_entry_size = 108
        dump_len = len(full_dump)

        for _ in range(num_modules):
            if offset + module_entry_size > len(stream_bytes):
                break
            base_of_image, size_of_image, checksum, timestamp, name_rva = (
                struct.unpack_from("<QIIII", stream_bytes, offset)
            )
            offset += module_entry_size

            name = "unknown"
            if name_rva + 4 <= dump_len:
                str_len = struct.unpack_from("<I", full_dump, name_rva)[0]
                str_start = name_rva + 4
                if str_start + str_len <= dump_len:
                    try:
                        name = full_dump[str_start : str_start + str_len].decode("utf-16le", errors="ignore")
                    except Exception:
                        name = "unparseable"

            modules.append({
                "name": name,
                "base_address": hex(base_of_image),
                "size": size_of_image,
                "timestamp": timestamp,
                "checksum": hex(checksum),
            })
        return modules

    @classmethod
    def _parse_system_info_stream(cls, stream_bytes: bytes) -> Dict[str, Any]:
        """Parses MINIDUMP_SYSTEM_INFO stream."""
        if len(stream_bytes) < 16:
            return {}
        arch_code = struct.unpack_from("<H", stream_bytes, 0)[0]
        arch_map = {0: "x86", 5: "ARM", 6: "IA64", 9: "x64", 12: "ARM64"}
        return {
            "processor_architecture": arch_map.get(arch_code, f"unknown_{arch_code}"),
            "raw_arch_code": arch_code,
        }

    @classmethod
    def extract_linear_ranges(
        cls, data: bytes, chunk_size: int = 1024 * 1024
    ) -> List[MemoryRange]:
        """
        Partitions raw memory dump or contiguous memory block into linear MemoryRanges.
        """
        ranges: List[MemoryRange] = []
        data_len = len(data)
        if data_len == 0:
            return []

        # If data is small (< 16 MB), return single range
        if data_len <= 16 * 1024 * 1024:
            return [MemoryRange(start_va=0x10000000, size=data_len, file_offset=0)]

        # Chunk into contiguous slices
        curr = 0
        va_base = 0x10000000
        while curr < data_len:
            curr_size = min(chunk_size, data_len - curr)
            ranges.append(
                MemoryRange(start_va=va_base + curr, size=curr_size, file_offset=curr)
            )
            curr += curr_size
        return ranges
