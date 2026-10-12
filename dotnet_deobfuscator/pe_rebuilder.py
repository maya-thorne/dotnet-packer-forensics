"""
PE Header & Section Table Rebuilder and Integrity Restorer.
Engineered & Audited by Maya Thorne.
"""

import math
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SectionHeader:
    """Represents a reconstructed PE section header."""
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int


@dataclass
class PERebuildOptions:
    """Configurable options for PE rebuilding operations."""
    fix_dos_header: bool = True
    fix_nt_headers: bool = True
    fix_section_alignments: bool = True
    unmap_memory_dump: bool = True
    sanitize_section_names: bool = True
    fix_cor20_descriptor: bool = True
    strip_invalid_security: bool = True
    recalculate_image_size: bool = True
    target_file_alignment: int = 0x200
    target_section_alignment: int = 0x2000


@dataclass
class PERebuildReport:
    """Detailed summary of repairs, realignments, and integrity status."""
    is_repaired: bool = False
    original_size: int = 0
    rebuilt_size: int = 0
    anomalies_detected: List[str] = field(default_factory=list)
    actions_applied: List[str] = field(default_factory=list)
    sections_count: int = 0
    is_memory_dump: bool = False
    is_dotnet: bool = False
    cor20_recovered: bool = False
    new_size_of_image: int = 0
    sha256_rebuilt: str = ""


class PERebuilder:
    """
    Forensic engine to analyze, repair, realign, and reconstruct damaged PE headers,
    section tables, and .NET CLR metadata descriptors.
    """

    DOS_MAGIC = 0x5A4D  # "MZ"
    PE_SIGNATURE = 0x00004550  # "PE\0\0"
    PE32_MAGIC = 0x10B
    PE32_PLUS_MAGIC = 0x20B
    COR20_HEADER_SIZE = 72

    # Standard minimal MS-DOS stub with "This program cannot be run in DOS mode."
    STANDARD_DOS_STUB = bytes([
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
        0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63,
        0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
        0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    @staticmethod
    def align_up(value: int, alignment: int) -> int:
        """Rounds a value up to the nearest multiple of alignment."""
        if alignment <= 0:
            return value
        remainder = value % alignment
        return value if remainder == 0 else value + (alignment - remainder)

    @classmethod
    def detect_anomalies(cls, data: bytes) -> Dict[str, Any]:
        """
        Scans a binary buffer and identifies PE header corruptions, memory dump traits,
        section misalignments, and damaged CLR descriptors.
        """
        anomalies: List[str] = []
        is_mem_dump = False
        is_pe = False
        is_dotnet = False

        if len(data) < 64:
            anomalies.append("Buffer too small for PE executable (< 64 bytes)")
            return {
                "is_pe": False,
                "is_memory_dump": False,
                "is_dotnet": False,
                "anomalies": anomalies,
            }

        # 1. DOS Header Checks
        if data[:2] != b"MZ":
            anomalies.append("Missing or corrupted DOS magic ('MZ')")
        else:
            is_pe = True

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            anomalies.append(f"Corrupted e_lfanew pointer (0x{e_lfanew:X})")
            pe_offset = data.find(b"PE\x00\x00")
            if pe_offset != -1:
                anomalies.append(f"Found orphaned PE signature at offset 0x{pe_offset:X}")
                e_lfanew = pe_offset
            else:
                return {
                    "is_pe": is_pe,
                    "is_memory_dump": False,
                    "is_dotnet": False,
                    "anomalies": anomalies,
                }
        elif data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            anomalies.append(f"Invalid PE signature at e_lfanew (0x{e_lfanew:X})")
            pe_offset = data.find(b"PE\x00\x00")
            if pe_offset != -1:
                anomalies.append(f"Relocated PE signature detected at 0x{pe_offset:X}")
                e_lfanew = pe_offset

        # 2. NT & Optional Headers
        if e_lfanew + 24 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]

            if opt_size < 28 or e_lfanew + 24 + opt_size > len(data):
                anomalies.append(f"Abnormal Optional Header size: {opt_size} bytes")

            magic = struct.unpack_from("<H", data, e_lfanew + 24)[0] if e_lfanew + 26 <= len(data) else 0
            if magic not in (cls.PE32_MAGIC, cls.PE32_PLUS_MAGIC):
                anomalies.append(f"Unknown Optional Header magic: 0x{magic:X}")

            sec_align = 0x2000
            file_align = 0x200
            size_of_image = 0
            size_of_headers = 0

            if magic in (cls.PE32_MAGIC, cls.PE32_PLUS_MAGIC) and e_lfanew + 24 + 68 <= len(data):
                sec_align = struct.unpack_from("<I", data, e_lfanew + 56)[0]
                file_align = struct.unpack_from("<I", data, e_lfanew + 60)[0]
                size_of_image = struct.unpack_from("<I", data, e_lfanew + 80)[0]
                size_of_headers = struct.unpack_from("<I", data, e_lfanew + 84)[0]

                if sec_align == 0 or (sec_align & (sec_align - 1)) != 0:
                    anomalies.append(f"Non-power-of-two SectionAlignment: 0x{sec_align:X}")
                if file_align == 0 or (file_align & (file_align - 1)) != 0:
                    anomalies.append(f"Non-power-of-two FileAlignment: 0x{file_align:X}")

            # 3. Section Table Checks & Memory Dump Diagnostics
            sec_start = e_lfanew + 24 + opt_size
            matching_va_ptrs = 0
            zero_ptrs = 0

            for i in range(num_sections):
                entry = sec_start + (i * 40)
                if entry + 40 > len(data):
                    anomalies.append("Section table truncated before declared section count")
                    break

                vsize = struct.unpack_from("<I", data, entry + 8)[0]
                vaddr = struct.unpack_from("<I", data, entry + 12)[0]
                rsize = struct.unpack_from("<I", data, entry + 16)[0]
                rptr = struct.unpack_from("<I", data, entry + 20)[0]

                if vaddr == rptr and vaddr > 0:
                    matching_va_ptrs += 1
                if rptr == 0 and vsize > 0:
                    zero_ptrs += 1
                if rptr + rsize > len(data):
                    anomalies.append(f"Section {i} raw data overflows file bounds (0x{rptr+rsize:X} > 0x{len(data):X})")

            if num_sections > 0 and (matching_va_ptrs >= (num_sections // 2 + 1) or zero_ptrs == num_sections):
                is_mem_dump = True
                anomalies.append("Process memory dump layout detected (VirtualAddress mapped to raw pointers)")

            # 4. CLR Cor20Header Directory Checks
            data_dirs_offset = e_lfanew + 24 + (96 if magic == cls.PE32_MAGIC else 112)
            cor20_dir_offset = data_dirs_offset + (14 * 8)
            if cor20_dir_offset + 8 <= len(data):
                clr_rva, clr_size = struct.unpack_from("<II", data, cor20_dir_offset)
                if clr_rva > 0 and clr_size > 0:
                    is_dotnet = True
                elif b"BSJB" in data:
                    is_dotnet = True
                    anomalies.append("CLR Metadata '#~'/'BSJB' present but COM Descriptor directory is zeroed (Anti-Dump)")

        return {
            "is_pe": is_pe,
            "is_memory_dump": is_mem_dump,
            "is_dotnet": is_dotnet,
            "anomalies": anomalies,
        }

    @classmethod
    def find_pe_offset(cls, data: bytes) -> int:
        """Locates the PE signature offset within the binary."""
        if len(data) >= 0x40 and data[:2] == b"MZ":
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                return e_lfanew
        pos = data.find(b"PE\x00\x00")
        return pos if pos != -1 else 0x80

    @classmethod
    def sanitize_name(cls, raw_bytes: bytes, index: int) -> str:
        """Produces a clean 8-byte alphanumeric section name."""
        clean = ""
        for b in raw_bytes:
            if 0x20 <= b <= 0x7E:
                clean += chr(b)
            elif b == 0:
                break
        clean = clean.strip()
        if not clean:
            return f".sec{index}"
        return clean[:8]

    @classmethod
    def rebuild(
        cls, data: bytes, options: Optional[PERebuildOptions] = None
    ) -> Tuple[bytes, PERebuildReport]:
        """
        Reconstructs, normalizes, and realigns damaged PE headers, section tables,
        and CLR directories into a clean standalone PE binary.
        """
        if options is None:
            options = PERebuildOptions()

        report = PERebuildReport(original_size=len(data))
        diag = cls.detect_anomalies(data)
        report.anomalies_detected = diag["anomalies"]
        report.is_memory_dump = diag["is_memory_dump"]
        report.is_dotnet = diag["is_dotnet"]

        if len(data) < 64:
            report.is_repaired = False
            return data, report

        buf = bytearray(data)

        # ---------------------------------------------------------
        # Step 1: Repair DOS Header & e_lfanew
        # ---------------------------------------------------------
        pe_offset = cls.find_pe_offset(data)
        if pe_offset == -1 or pe_offset + 24 > len(buf):
            # No PE signature anywhere; create fresh DOS & minimal NT stub
            pe_offset = 0x80
            buf = bytearray(pe_offset + 248) + buf
            report.actions_applied.append("Synthesized clean DOS and NT header base")

        if options.fix_dos_header:
            # Fix DOS magic
            if buf[:2] != b"MZ":
                buf[0:2] = b"MZ"
                report.actions_applied.append("Restored DOS magic signature (0x5A4D)")

            # Set e_lfanew pointer
            struct.pack_into("<I", buf, 0x3C, pe_offset)
            report.actions_applied.append(f"Realigned e_lfanew pointer -> 0x{pe_offset:X}")

            # Ensure minimal DOS stub presence if area between 0x40 and pe_offset is blank
            if pe_offset >= 0x80 and buf[0x40 : 0x40 + len(cls.STANDARD_DOS_STUB)] == b"\x00" * len(cls.STANDARD_DOS_STUB):
                stub_len = min(len(cls.STANDARD_DOS_STUB), pe_offset - 0x40)
                buf[0x40 : 0x40 + stub_len] = cls.STANDARD_DOS_STUB[:stub_len]
                report.actions_applied.append("Restored standard MS-DOS compatibility stub")

        # ---------------------------------------------------------
        # Step 2: Validate & Fix NT File Header
        # ---------------------------------------------------------
        if buf[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"
            report.actions_applied.append(f"Injected PE\\0\\0 signature at offset 0x{pe_offset:X}")

        machine = struct.unpack_from("<H", buf, pe_offset + 4)[0]
        if machine not in (0x014C, 0x8664, 0xAA64):
            # Default to I386 if invalid
            struct.pack_into("<H", buf, pe_offset + 4, 0x014C)
            machine = 0x014C
            report.actions_applied.append("Normalized Machine architecture to IMAGE_FILE_MACHINE_I386 (0x014C)")

        num_sections = struct.unpack_from("<H", buf, pe_offset + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", buf, pe_offset + 20)[0]
        characteristics = struct.unpack_from("<H", buf, pe_offset + 22)[0]

        # Ensure executable flag in characteristics
        if (characteristics & 0x0002) == 0:
            characteristics |= 0x0002  # IMAGE_FILE_EXECUTABLE_IMAGE
            struct.pack_into("<H", buf, pe_offset + 22, characteristics)
            report.actions_applied.append("Set IMAGE_FILE_EXECUTABLE_IMAGE characteristic flag")

        # ---------------------------------------------------------
        # Step 3: Optional Header Normalization
        # ---------------------------------------------------------
        magic = struct.unpack_from("<H", buf, pe_offset + 24)[0] if pe_offset + 26 <= len(buf) else 0
        if magic not in (cls.PE32_MAGIC, cls.PE32_PLUS_MAGIC):
            magic = cls.PE32_MAGIC
            struct.pack_into("<H", buf, pe_offset + 24, magic)
            report.actions_applied.append("Restored PE32 Optional Header magic (0x10B)")

        expected_opt_size = 0xE0 if magic == cls.PE32_MAGIC else 0xF0
        if opt_hdr_size != expected_opt_size:
            struct.pack_into("<H", buf, pe_offset + 20, expected_opt_size)
            opt_hdr_size = expected_opt_size
            report.actions_applied.append(f"Normalized SizeOfOptionalHeader -> 0x{expected_opt_size:X}")

        sec_align = struct.unpack_from("<I", buf, pe_offset + 56)[0]
        file_align = struct.unpack_from("<I", buf, pe_offset + 60)[0]

        if sec_align < 0x1000 or (sec_align & (sec_align - 1)) != 0:
            sec_align = options.target_section_alignment
            struct.pack_into("<I", buf, pe_offset + 56, sec_align)
            report.actions_applied.append(f"Normalized SectionAlignment -> 0x{sec_align:X}")

        if file_align < 0x200 or (file_align & (file_align - 1)) != 0:
            file_align = options.target_file_alignment
            struct.pack_into("<I", buf, pe_offset + 60, file_align)
            report.actions_applied.append(f"Normalized FileAlignment -> 0x{file_align:X}")

        # Subsystem: Ensure GUI or CUI
        subsystem = struct.unpack_from("<H", buf, pe_offset + 68)[0]
        if subsystem not in (2, 3):
            struct.pack_into("<H", buf, pe_offset + 68, 3)  # Windows CUI
            report.actions_applied.append("Restored Subsystem to IMAGE_SUBSYSTEM_WINDOWS_CUI (3)")

        # ---------------------------------------------------------
        # Step 4: Parse & Reconstruct Section Headers
        # ---------------------------------------------------------
        sec_hdr_start = pe_offset + 24 + opt_hdr_size
        max_possible_sections = min(num_sections, (len(buf) - sec_hdr_start) // 40)
        sections: List[SectionHeader] = []

        for i in range(max_possible_sections):
            entry = sec_hdr_start + (i * 40)
            raw_name = bytes(buf[entry : entry + 8])
            vsize = struct.unpack_from("<I", buf, entry + 8)[0]
            vaddr = struct.unpack_from("<I", buf, entry + 12)[0]
            rsize = struct.unpack_from("<I", buf, entry + 16)[0]
            rptr = struct.unpack_from("<I", buf, entry + 20)[0]
            charact = struct.unpack_from("<I", buf, entry + 36)[0]

            name = cls.sanitize_name(raw_name, i) if options.sanitize_section_names else raw_name.decode("latin1", errors="ignore")

            sections.append(SectionHeader(
                name=name,
                virtual_size=vsize,
                virtual_address=vaddr,
                raw_size=rsize,
                raw_ptr=rptr,
                characteristics=charact,
            ))

        report.sections_count = len(sections)

        # ---------------------------------------------------------
        # Step 5: Memory Dump Unmapping & Raw Section Rebuilding
        # ---------------------------------------------------------
        # Header size alignment
        headers_end = sec_hdr_start + (len(sections) * 40)
        aligned_headers_size = cls.align_up(headers_end, file_align)
        struct.pack_into("<I", buf, pe_offset + 84, aligned_headers_size)

        # Build clean output file buffer
        rebuilt = bytearray(buf[:aligned_headers_size])
        if len(rebuilt) < aligned_headers_size:
            rebuilt.extend(b"\x00" * (aligned_headers_size - len(rebuilt)))

        current_file_offset = aligned_headers_size

        for i, sec in enumerate(sections):
            # Extract section content
            sec_bytes = b""
            if report.is_memory_dump and options.unmap_memory_dump:
                # In memory dumps, data is mapped at VirtualAddress
                src_offset = sec.virtual_address
                src_size = sec.virtual_size if sec.virtual_size > 0 else sec.raw_size
                if src_offset < len(buf):
                    sec_bytes = bytes(buf[src_offset : min(src_offset + src_size, len(buf))])
            else:
                # Disk raw offset
                if sec.raw_ptr < len(buf):
                    src_size = sec.raw_size if sec.raw_size > 0 else sec.virtual_size
                    sec_bytes = bytes(buf[sec.raw_ptr : min(sec.raw_ptr + src_size, len(buf))])

            # Align raw size
            actual_content_len = len(sec_bytes)
            aligned_raw_size = cls.align_up(actual_content_len, file_align)
            if aligned_raw_size == 0 and sec.virtual_size > 0:
                aligned_raw_size = cls.align_up(sec.virtual_size, file_align)

            sec.raw_ptr = current_file_offset
            sec.raw_size = aligned_raw_size
            if sec.virtual_size == 0:
                sec.virtual_size = actual_content_len

            # Append padded data to rebuilt buffer
            rebuilt.extend(sec_bytes)
            if len(sec_bytes) < aligned_raw_size:
                rebuilt.extend(b"\x00" * (aligned_raw_size - len(sec_bytes)))

            current_file_offset += aligned_raw_size

            # Update section header in rebuilt binary
            entry = sec_hdr_start + (i * 40)
            name_bytes = sec.name.encode("latin1")[:8].ljust(8, b"\x00")
            rebuilt[entry : entry + 8] = name_bytes
            struct.pack_into("<I", rebuilt, entry + 8, sec.virtual_size)
            struct.pack_into("<I", rebuilt, entry + 12, sec.virtual_address)
            struct.pack_into("<I", rebuilt, entry + 16, sec.raw_size)
            struct.pack_into("<I", rebuilt, entry + 20, sec.raw_ptr)
            struct.pack_into("<I", rebuilt, entry + 36, sec.characteristics)

        report.actions_applied.append(f"Realigned {len(sections)} sections and recalculated file offsets")

        # ---------------------------------------------------------
        # Step 6: Recalculate SizeOfImage
        # ---------------------------------------------------------
        if sections:
            highest_sec = max(sections, key=lambda s: s.virtual_address + s.virtual_size)
            new_size_of_image = cls.align_up(highest_sec.virtual_address + highest_sec.virtual_size, sec_align)
            struct.pack_into("<I", rebuilt, pe_offset + 80, new_size_of_image)
            report.new_size_of_image = new_size_of_image
            report.actions_applied.append(f"Updated SizeOfImage -> 0x{new_size_of_image:X}")

        # ---------------------------------------------------------
        # Step 7: Data Directories & Cor20Header Recovery
        # ---------------------------------------------------------
        data_dirs_offset = pe_offset + 24 + (96 if magic == cls.PE32_MAGIC else 112)
        cor20_dir_offset = data_dirs_offset + (14 * 8)
        security_dir_offset = data_dirs_offset + (4 * 8)

        # Clear invalid Authenticode security directory
        if options.strip_invalid_security and security_dir_offset + 8 <= len(rebuilt):
            struct.pack_into("<II", rebuilt, security_dir_offset, 0, 0)
            report.actions_applied.append("Zeroed out invalid Certificate/Security directory table")

        # Recover Cor20Header directory if .NET metadata is present
        if options.fix_cor20_descriptor and cor20_dir_offset + 8 <= len(rebuilt):
            clr_rva, clr_size = struct.unpack_from("<II", rebuilt, cor20_dir_offset)
            if clr_rva == 0 or clr_size == 0:
                recovered_rva = cls._locate_cor20_header_rva(rebuilt, sections)
                if recovered_rva is not None:
                    struct.pack_into("<II", rebuilt, cor20_dir_offset, recovered_rva, cls.COR20_HEADER_SIZE)
                    report.cor20_recovered = True
                    report.is_dotnet = True
                    report.actions_applied.append(f"Recovered .NET Cor20Header COM Descriptor at RVA 0x{recovered_rva:X}")

        # Zeroize sensitive temporary staging buffer
        for idx in range(len(buf)):
            buf[idx] = 0

        final_bytes = bytes(rebuilt)
        report.rebuilt_size = len(final_bytes)
        report.is_repaired = True

        # Calculate SHA-256 hash of rebuilt binary
        import hashlib
        report.sha256_rebuilt = hashlib.sha256(final_bytes).hexdigest()

        return final_bytes, report

    @classmethod
    def _locate_cor20_header_rva(cls, data: bytearray, sections: List[SectionHeader]) -> Optional[int]:
        """
        Locates the Cor20Header (cb=72) within executable or initialized data sections
        and validates that its MetaData directory points to a valid 'BSJB' signature.
        """
        for sec in sections:
            rptr = sec.raw_ptr
            rsize = sec.raw_size
            if rptr + rsize > len(data):
                continue

            sec_data = data[rptr : rptr + rsize]
            idx = 0
            while True:
                idx = sec_data.find(b"\x48\x00\x00\x00", idx)
                if idx == -1 or idx + 72 > len(sec_data):
                    break

                # Inspect candidates
                cb = struct.unpack_from("<I", sec_data, idx)[0]
                major = struct.unpack_from("<H", sec_data, idx + 4)[0]
                if cb == 72 and major in (2, 0):
                    meta_rva = struct.unpack_from("<I", sec_data, idx + 8)[0]
                    meta_size = struct.unpack_from("<I", sec_data, idx + 12)[0]
                    if meta_rva > 0 and meta_size > 0:
                        # Convert meta_rva to raw pointer
                        meta_ptr = cls.rva_to_raw(meta_rva, sections)
                        if meta_ptr and meta_ptr + 4 <= len(data) and data[meta_ptr : meta_ptr + 4] == b"BSJB":
                            return sec.virtual_address + idx
                idx += 4
        return None

    @staticmethod
    def rva_to_raw(rva: int, sections: List[SectionHeader]) -> Optional[int]:
        """Translates a Relative Virtual Address (RVA) to a file raw offset."""
        for sec in sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
                return sec.raw_ptr + (rva - sec.virtual_address)
        return None
