"""
Anti-Dump Memory PE Header Healer & Scylla-Compatible Dump Normalizer.
Engineered & Audited by Maya Thorne.
"""

import ctypes
import hashlib
import math
import struct
from typing import Any, Dict, List, Optional, Tuple

from .antidump_models import (
    AntiDumpHealOptions,
    AntiDumpHealResult,
    AntiDumpTechnique,
    AntiDumpTelemetry,
    DumpSource,
    HealedSectionInfo,
    SectionType,
    SecurityError,
    SynthesizedImportInfo,
)


class AntiDumpHealer:
    """
    Forensic engine to detect anti-dump memory corruptions, reconstruct erased PE headers,
    synthesize missing CLR Cor20Header and IAT imports, and unmap Scylla/Process memory dumps.
    """

    DOS_MAGIC = 0x5A4D  # "MZ"
    PE_SIGNATURE = 0x00004550  # "PE\0\0"
    PE32_MAGIC = 0x10B
    PE32_PLUS_MAGIC = 0x20B
    COR20_HEADER_SIZE = 72
    BSJB_MAGIC = 0x424A5342  # "BSJB"
    MAX_BUFFER_SIZE = 256 * 1024 * 1024  # 256 MB safety limit
    MAX_SECTIONS = 96

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
        rem = value % alignment
        return value if rem == 0 else value + (alignment - rem)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Computes Shannon entropy (0.0 to 8.0) across byte buffer."""
        if not data:
            return 0.0
        frequencies = [0] * 256
        for b in data:
            frequencies[b] += 1
        length = len(data)
        entropy = 0.0
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def detect(cls, data: bytes) -> AntiDumpTelemetry:
        """
        Scans a binary or memory dump buffer to identify active anti-dump corruptions
        and classify dump format characteristics.
        """
        if len(data) > cls.MAX_BUFFER_SIZE:
            raise SecurityError(f"Buffer size {len(data)} exceeds maximum threshold of {cls.MAX_BUFFER_SIZE} bytes.")

        telemetry = AntiDumpTelemetry()
        if len(data) < 64:
            telemetry.anomalies.append("Buffer too small for executable inspection (< 64 bytes)")
            return telemetry

        # 1. DOS Header Integrity Check
        has_mz = data[:2] == b"MZ"
        if not has_mz:
            telemetry.original_header_intact = False
            telemetry.detected_techniques.append(AntiDumpTechnique.ERASED_DOS_HEADER)
            telemetry.anomalies.append("Missing or erased DOS magic ('MZ' signature zeroed)")

        # 2. Locate PE Offset and NT Headers
        pe_offset = -1
        if has_mz and len(data) >= 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                pe_offset = e_lfanew

        if pe_offset == -1:
            raw_pe = data.find(b"PE\x00\x00")
            if raw_pe != -1:
                pe_offset = raw_pe
                telemetry.anomalies.append(f"Orphaned PE signature found at offset 0x{pe_offset:X}")
            else:
                telemetry.original_header_intact = False
                telemetry.detected_techniques.append(AntiDumpTechnique.ERASED_NT_HEADER)
                telemetry.anomalies.append("Complete absence of PE signature in header region (Anti-Dump Erase)")

        # 3. Check for BSJB Metadata presence
        bsjb_info = cls.scan_bsjb_metadata(data)
        if bsjb_info is not None:
            telemetry.bsjb_metadata_found = True
            telemetry.bsjb_rva = bsjb_info[0]

        # 4. Check Section Table and Virtual Address Mappings
        num_sections = 0
        is_mem_dump = False
        matching_va_count = 0
        stripped_names_count = 0

        if pe_offset != -1 and pe_offset + 24 <= len(data):
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            sec_start = pe_offset + 24 + opt_size

            for i in range(min(num_sections, cls.MAX_SECTIONS)):
                entry = sec_start + (i * 40)
                if entry + 40 > len(data):
                    break
                sec_name = data[entry : entry + 8]
                vaddr = struct.unpack_from("<I", data, entry + 12)[0]
                rptr = struct.unpack_from("<I", data, entry + 20)[0]

                if vaddr > 0 and vaddr == rptr:
                    matching_va_count += 1
                if sec_name.strip(b"\x00") == b"" or not any(0x20 <= b <= 0x7E for b in sec_name):
                    stripped_names_count += 1

            if num_sections > 0:
                if matching_va_count >= (num_sections // 2 + 1):
                    is_mem_dump = True
                    telemetry.detected_techniques.append(AntiDumpTechnique.VIRTUAL_MEMORY_LAYOUT)
                    telemetry.anomalies.append("Memory-mapped section layout detected (VirtualAddress == PointerToRawData)")
                if stripped_names_count >= max(1, num_sections // 2):
                    telemetry.detected_techniques.append(AntiDumpTechnique.STRIPPED_SECTION_TABLE)
                    telemetry.anomalies.append("Stripped or zeroed section names identified (Anti-Dump evasion)")

            # Check Data Directories for CLR and Imports
            magic = struct.unpack_from("<H", data, pe_offset + 24)[0] if pe_offset + 26 <= len(data) else 0
            if magic in (cls.PE32_MAGIC, cls.PE32_PLUS_MAGIC):
                dd_offset = pe_offset + 24 + (96 if magic == cls.PE32_MAGIC else 112)
                import_dir = dd_offset + 8
                cor20_dir = dd_offset + (14 * 8)

                if import_dir + 8 <= len(data) and (telemetry.bsjb_metadata_found or is_mem_dump):
                    imp_rva, imp_size = struct.unpack_from("<II", data, import_dir)
                    if imp_rva == 0 or imp_size == 0:
                        telemetry.detected_techniques.append(AntiDumpTechnique.MISSING_CLR_IMPORTS)
                        telemetry.anomalies.append("Missing or zeroed Import Directory table")

                if cor20_dir + 8 <= len(data):
                    cor_rva, cor_size = struct.unpack_from("<II", data, cor20_dir)
                    if cor_rva > 0 and cor_size > 0:
                        telemetry.cor20_recovered = True
                        telemetry.cor20_rva = cor_rva
                    elif telemetry.bsjb_metadata_found:
                        telemetry.detected_techniques.append(AntiDumpTechnique.CORRUPTED_COR20_DESCRIPTOR)
                        telemetry.anomalies.append("CLR Metadata (BSJB) exists but Cor20Header descriptor is stripped")

        # 5. Classifier: Scylla / MegaDumper / ConfuserEx / Reactor heuristics
        if b"Scylla" in data or b"scylla" in data:
            telemetry.dump_source = DumpSource.SCYLLA_DUMP
        elif b"MegaDumper" in data or (is_mem_dump and b"mscoree.dll" in data):
            telemetry.dump_source = DumpSource.MEGADUMPER
        elif is_mem_dump:
            telemetry.dump_source = DumpSource.RAW_VIRTUAL_MEM
        elif not has_mz and telemetry.bsjb_metadata_found:
            telemetry.dump_source = DumpSource.CORRUPTED_DISK_PE

        if b"Confuser.Runtime.AntiDump" in data or (not has_mz and telemetry.bsjb_metadata_found and num_sections == 0):
            telemetry.detected_techniques.append(AntiDumpTechnique.CONFUSEREX_ANTIDUMP)
            telemetry.anomalies.append("ConfuserEx Anti-Dump runtime pattern identified")

        if b".reactor" in data and is_mem_dump:
            telemetry.detected_techniques.append(AntiDumpTechnique.REACTOR_ANTIDUMP)
            telemetry.anomalies.append(".NET Reactor Anti-Dump protection signature detected")

        # Confidence Scoring: distinguish true corruptions from standard clean binaries
        technique_count = len(telemetry.detected_techniques)
        has_primary_anti_dump = (
            not telemetry.original_header_intact
            or is_mem_dump
            or AntiDumpTechnique.STRIPPED_SECTION_TABLE in telemetry.detected_techniques
            or AntiDumpTechnique.CORRUPTED_COR20_DESCRIPTOR in telemetry.detected_techniques
            or AntiDumpTechnique.CONFUSEREX_ANTIDUMP in telemetry.detected_techniques
            or AntiDumpTechnique.REACTOR_ANTIDUMP in telemetry.detected_techniques
        )
        if has_primary_anti_dump and (technique_count >= 2 or not has_mz):
            telemetry.is_anti_dump_detected = True
            telemetry.confidence = "HIGH"
        elif has_primary_anti_dump:
            telemetry.is_anti_dump_detected = True
            telemetry.confidence = "MEDIUM"
        else:
            telemetry.is_anti_dump_detected = False
            telemetry.confidence = "LOW"


        return telemetry

    @classmethod
    def scan_bsjb_metadata(cls, data: bytes) -> Optional[Tuple[int, int, str]]:
        """
        Scans binary buffer for ECMA-335 BSJB CLR metadata header.
        Returns (bsjb_offset, estimated_metadata_size, version_string).
        """
        idx = 0
        while True:
            idx = data.find(b"BSJB", idx)
            if idx == -1 or idx + 16 > len(data):
                break

            magic = struct.unpack_from("<I", data, idx)[0]
            if magic == cls.BSJB_MAGIC:
                major_ver, minor_ver = struct.unpack_from("<HH", data, idx + 4)
                ver_len = struct.unpack_from("<I", data, idx + 12)[0]
                if 0 < ver_len <= 256 and idx + 16 + ver_len + 4 <= len(data):
                    raw_ver = data[idx + 16 : idx + 16 + ver_len]
                    version_str = raw_ver.rstrip(b"\x00").decode("latin1", errors="ignore")
                    stream_offset = idx + 16 + ver_len
                    if stream_offset + 4 <= len(data):
                        flags, streams_count = struct.unpack_from("<HH", data, stream_offset)
                        if 1 <= streams_count <= 16:
                            # Estimate metadata size: at least 4096 or distance to next section
                            est_size = max(4096, min(len(data) - idx, 2 * 1024 * 1024))
                            return idx, est_size, version_str
            idx += 4
        return None

    @classmethod
    def build_clr_import_table(
        cls, image_base: int, target_rva: int, is_dll: bool = False
    ) -> Tuple[bytes, int, int, SynthesizedImportInfo]:
        """
        Synthesizes a standard Windows PE CLR bootstrap import table for mscoree.dll.
        Returns (import_section_bytes, import_dir_rva, iat_rva, info).
        """
        dll_name = b"mscoree.dll\x00"
        symbol_name = b"_CorDllMain\x00" if is_dll else b"_CorExeMain\x00"

        # Layout inside import block:
        # [0x00] EntryPoint jump thunk: FF 25 [IAT RVA + ImageBase] (6 bytes) + 2 bytes pad
        # [0x08] IMAGE_IMPORT_DESCRIPTOR (20 bytes): INT, TimeDateStamp, Forwarder, Name, IAT
        # [0x1C] Null Terminator IMAGE_IMPORT_DESCRIPTOR (20 bytes)
        # [0x30] INT Thunk (4 bytes): RVA of IMAGE_IMPORT_BY_NAME + null thunk (4 bytes)
        # [0x38] IAT Thunk (4 bytes): RVA of IMAGE_IMPORT_BY_NAME + null thunk (4 bytes)
        # [0x40] IMAGE_IMPORT_BY_NAME: Hint (2 bytes: 0) + Name string
        # [aligned] DllName string: "mscoree.dll\0"

        thunk_len = 8
        import_desc_len = 40  # 1 descriptor + 1 null terminator
        int_thunk_offset = thunk_len + import_desc_len  # 0x30
        iat_thunk_offset = int_thunk_offset + 8         # 0x38
        import_by_name_offset = iat_thunk_offset + 8    # 0x40
        dll_name_offset = import_by_name_offset + 2 + len(symbol_name) + (1 if len(symbol_name) % 2 != 0 else 0)

        total_size = cls.align_up(dll_name_offset + len(dll_name) + 16, 16)
        blob = bytearray(total_size)

        iat_rva = target_rva + iat_thunk_offset
        int_rva = target_rva + int_thunk_offset
        name_rva = target_rva + dll_name_offset
        ibn_rva = target_rva + import_by_name_offset

        # 1. Entry point jump: FF 25 <absolute VA of IAT>
        blob[0:2] = b"\xFF\x25"
        struct.pack_into("<I", blob, 2, image_base + iat_rva)

        # 2. IMAGE_IMPORT_DESCRIPTOR
        desc_offset = thunk_len
        struct.pack_into("<IIIII", blob, desc_offset, int_rva, 0, 0, name_rva, iat_rva)

        # 3. INT and IAT Thunks
        struct.pack_into("<I", blob, int_thunk_offset, ibn_rva)
        struct.pack_into("<I", blob, iat_thunk_offset, ibn_rva)


        # 4. IMAGE_IMPORT_BY_NAME
        struct.pack_into("<H", blob, import_by_name_offset, 0)  # Hint = 0
        blob[import_by_name_offset + 2 : import_by_name_offset + 2 + len(symbol_name)] = symbol_name

        # 5. Dll name
        blob[dll_name_offset : dll_name_offset + len(dll_name)] = dll_name

        info = SynthesizedImportInfo(
            dll_name="mscoree.dll",
            symbol_name=symbol_name.rstrip(b"\x00").decode("ascii"),
            iat_rva=iat_rva,
            int_rva=int_rva,
            descriptor_rva=target_rva + desc_offset,
        )
        return bytes(blob), target_rva + desc_offset, iat_rva, info

    @classmethod
    def sanitize_section_name(cls, raw: bytes, idx: int) -> str:
        """Sanitizes or restores a valid 8-byte ASCII section name."""
        clean = ""
        for b in raw:
            if 0x20 <= b <= 0x7E:
                clean += chr(b)
            elif b == 0:
                break
        clean = clean.strip()
        if not clean or clean.startswith("?"):
            return f".sec{idx}"
        return clean[:8]

    @classmethod
    def heal_dump(
        cls, data: bytes, options: Optional[AntiDumpHealOptions] = None
    ) -> Tuple[bytes, AntiDumpHealResult]:
        """
        Executes full forensic normalization and header reconstruction on memory dumps.
        """
        if options is None:
            options = AntiDumpHealOptions()

        result = AntiDumpHealResult(original_size=len(data))
        telemetry = cls.detect(data)
        result.telemetry = telemetry

        if len(data) < 64:
            return data, result

        buf = bytearray(data)
        file_align = options.target_file_alignment
        sec_align = options.target_section_alignment
        image_base = 0x00400000

        # Determine architecture and PE offset
        pe_offset = -1
        if buf[:2] == b"MZ" and len(buf) >= 0x40:
            e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
            if 0 < e_lfanew < len(buf) - 4 and buf[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                pe_offset = e_lfanew

        if pe_offset == -1:
            raw_pe = buf.find(b"PE\x00\x00")
            if raw_pe != -1 and raw_pe < 0x1000:
                pe_offset = raw_pe
            else:
                pe_offset = 0x80
                telemetry.actions.append(f"Synthesized fresh PE header base at offset 0x{pe_offset:X}")

        # -------------------------------------------------------------
        # Step 1: Repair DOS Header & e_lfanew
        # -------------------------------------------------------------
        if options.fix_dos_header:
            if buf[:2] != b"MZ":
                buf[0:2] = b"MZ"
                telemetry.actions.append("Restored DOS magic signature (0x5A4D)")
            struct.pack_into("<I", buf, 0x3C, pe_offset)
            telemetry.actions.append(f"Realigned e_lfanew -> 0x{pe_offset:X}")

            if pe_offset >= 0x80 and buf[0x40 : 0x40 + len(cls.STANDARD_DOS_STUB)] == b"\x00" * len(cls.STANDARD_DOS_STUB):
                stub_len = min(len(cls.STANDARD_DOS_STUB), pe_offset - 0x40)
                buf[0x40 : 0x40 + stub_len] = cls.STANDARD_DOS_STUB[:stub_len]
                telemetry.actions.append("Injected standard MS-DOS compatibility stub")

        # -------------------------------------------------------------
        # Step 2: Ensure NT Headers & Optional Header Base
        # -------------------------------------------------------------
        if len(buf) < pe_offset + 248:
            buf.extend(b"\x00" * (pe_offset + 248 - len(buf)))

        if buf[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"
            telemetry.actions.append(f"Injected PE\\0\\0 signature at 0x{pe_offset:X}")

        machine = struct.unpack_from("<H", buf, pe_offset + 4)[0]
        if machine not in (0x014C, 0x8664):
            machine = 0x014C
            struct.pack_into("<H", buf, pe_offset + 4, machine)
            telemetry.actions.append("Normalized Machine architecture to IMAGE_FILE_MACHINE_I386")

        num_sections = struct.unpack_from("<H", buf, pe_offset + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", buf, pe_offset + 20)[0]
        characteristics = struct.unpack_from("<H", buf, pe_offset + 22)[0]

        is_dll = (characteristics & 0x2000) != 0
        expected_opt_size = 0xE0 if machine == 0x014C else 0xF0
        if opt_hdr_size != expected_opt_size:
            struct.pack_into("<H", buf, pe_offset + 20, expected_opt_size)
            opt_hdr_size = expected_opt_size

        magic = cls.PE32_MAGIC if machine == 0x014C else cls.PE32_PLUS_MAGIC
        struct.pack_into("<H", buf, pe_offset + 24, magic)

        # Ensure executable flag
        characteristics |= 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
        struct.pack_into("<H", buf, pe_offset + 22, characteristics)

        # Standard Optional Header fields
        struct.pack_into("<I", buf, pe_offset + 56, sec_align)
        struct.pack_into("<I", buf, pe_offset + 60, file_align)
        struct.pack_into("<H", buf, pe_offset + 68, 3)  # Subsystem: Windows CUI
        struct.pack_into("<I", buf, pe_offset + 116, 16)  # NumberOfRvaAndSizes

        # -------------------------------------------------------------
        # Step 3: Parse or Synthesize Section Table
        # -------------------------------------------------------------
        sec_start = pe_offset + 24 + opt_hdr_size
        raw_sections: List[HealedSectionInfo] = []

        if num_sections > 0 and sec_start + (num_sections * 40) <= len(buf):
            for i in range(min(num_sections, cls.MAX_SECTIONS)):
                entry = sec_start + (i * 40)
                raw_name = bytes(buf[entry : entry + 8])
                vsize = struct.unpack_from("<I", buf, entry + 8)[0]
                vaddr = struct.unpack_from("<I", buf, entry + 12)[0]
                rsize = struct.unpack_from("<I", buf, entry + 16)[0]
                rptr = struct.unpack_from("<I", buf, entry + 20)[0]
                charact = struct.unpack_from("<I", buf, entry + 36)[0]

                name = cls.sanitize_section_name(raw_name, i) if options.sanitize_section_names else raw_name.decode("latin1", errors="ignore")
                raw_sections.append(HealedSectionInfo(
                    name=name,
                    original_name=raw_name,
                    virtual_address=vaddr,
                    virtual_size=vsize,
                    raw_ptr=rptr,
                    raw_size=rsize,
                    characteristics=charact if charact != 0 else 0x60000020,
                ))

        # If section table was completely stripped (e.g. ConfuserEx Anti-Dump), synthesize sections
        if not raw_sections and options.infer_missing_sections:
            telemetry.actions.append("Synthesizing baseline .text section from memory contents")
            text_vaddr = 0x2000
            text_size = max(4096, len(buf) - text_vaddr if len(buf) > text_vaddr else len(buf))
            raw_sections.append(HealedSectionInfo(
                name=".text",
                original_name=b".text\x00\x00\x00",
                virtual_address=text_vaddr,
                virtual_size=text_size,
                raw_ptr=text_vaddr,
                raw_size=text_size,
                characteristics=0x60000020,  # CODE | EXECUTE | READ
                section_type=SectionType.CODE_AND_CLR,
            ))

        # -------------------------------------------------------------
        # Step 4: Reconstruct Import Directory & IAT
        # -------------------------------------------------------------
        synthesized_import = None
        import_block = b""
        if options.reconstruct_iat:
            # Place import section after the highest current section
            highest_va = max((s.virtual_address + cls.align_up(s.virtual_size, sec_align) for s in raw_sections), default=0x2000)
            import_va = cls.align_up(highest_va, sec_align)
            import_block, import_desc_rva, iat_rva, synthesized_import = cls.build_clr_import_table(
                image_base=image_base, target_rva=import_va, is_dll=is_dll
            )
            # Add synthetic .rdata / import section
            raw_sections.append(HealedSectionInfo(
                name=".rdata",
                original_name=b".rdata\x00\x00",
                virtual_address=import_va,
                virtual_size=len(import_block),
                raw_ptr=import_va,
                raw_size=cls.align_up(len(import_block), file_align),
                characteristics=0x40000040,  # INITIALIZED_DATA | READ
                section_type=SectionType.IMPORT_TABLE,
            ))
            result.synthesized_import = synthesized_import
            telemetry.iat_reconstructed = True
            telemetry.actions.append(f"Reconstructed mscoree.dll CLR import table (IAT at 0x{iat_rva:X})")

            # Update Optional Header Data Directories
            dd_offset = pe_offset + 24 + (96 if magic == cls.PE32_MAGIC else 112)
            struct.pack_into("<II", buf, dd_offset + 8, import_desc_rva, 40)  # Import Directory
            struct.pack_into("<II", buf, dd_offset + (12 * 8), iat_rva, 8)     # IAT Directory

            # Point AddressOfEntryPoint to the import jump stub
            struct.pack_into("<I", buf, pe_offset + 40, import_va)
            telemetry.actions.append(f"Set AddressOfEntryPoint -> 0x{import_va:X}")

        # -------------------------------------------------------------
        # Step 5: Unmap Memory Dump & Rebuild Sequential File Layout
        # -------------------------------------------------------------
        # Update number of sections in NT Header
        struct.pack_into("<H", buf, pe_offset + 6, len(raw_sections))

        headers_end = sec_start + (len(raw_sections) * 40)
        aligned_headers_size = cls.align_up(headers_end, file_align)
        struct.pack_into("<I", buf, pe_offset + 84, aligned_headers_size)

        rebuilt = bytearray(buf[:aligned_headers_size])
        if len(rebuilt) < aligned_headers_size:
            rebuilt.extend(b"\x00" * (aligned_headers_size - len(rebuilt)))

        current_file_offset = aligned_headers_size

        for i, sec in enumerate(raw_sections):
            if sec.section_type == SectionType.IMPORT_TABLE:
                sec_bytes = import_block
            elif telemetry.detected_techniques and AntiDumpTechnique.VIRTUAL_MEMORY_LAYOUT in telemetry.detected_techniques and options.unmap_virtual_memory:
                # Memory dump unmapping: read from virtual address
                src_off = sec.virtual_address
                src_sz = sec.virtual_size if sec.virtual_size > 0 else sec.raw_size
                sec_bytes = bytes(buf[src_off : min(src_off + src_sz, len(buf))]) if src_off < len(buf) else b""
            else:
                # Disk raw pointer
                src_off = sec.raw_ptr
                src_sz = sec.raw_size if sec.raw_size > 0 else sec.virtual_size
                sec_bytes = bytes(buf[src_off : min(src_off + src_sz, len(buf))]) if src_off < len(buf) else b""

            content_len = len(sec_bytes)
            aligned_raw_size = cls.align_up(content_len, file_align)
            if aligned_raw_size == 0 and sec.virtual_size > 0:
                aligned_raw_size = cls.align_up(sec.virtual_size, file_align)

            sec.raw_ptr = current_file_offset
            sec.raw_size = aligned_raw_size
            if sec.virtual_size == 0:
                sec.virtual_size = content_len

            sec.entropy = cls.calculate_entropy(sec_bytes)
            if b"BSJB" in sec_bytes:
                sec.contains_bsjb = True
                sec.section_type = SectionType.METADATA_BSJB

            rebuilt.extend(sec_bytes)
            if len(sec_bytes) < aligned_raw_size:
                rebuilt.extend(b"\x00" * (aligned_raw_size - len(sec_bytes)))

            current_file_offset += aligned_raw_size

            # Update section header in rebuilt binary
            entry = sec_start + (i * 40)
            name_bytes = sec.name.encode("latin1")[:8].ljust(8, b"\x00")
            rebuilt[entry : entry + 8] = name_bytes
            struct.pack_into("<I", rebuilt, entry + 8, sec.virtual_size)
            struct.pack_into("<I", rebuilt, entry + 12, sec.virtual_address)
            struct.pack_into("<I", rebuilt, entry + 16, sec.raw_size)
            struct.pack_into("<I", rebuilt, entry + 20, sec.raw_ptr)
            struct.pack_into("<I", rebuilt, entry + 36, sec.characteristics)

        telemetry.sections_healed_count = len(raw_sections)
        result.sections = raw_sections
        telemetry.actions.append(f"Normalized and unmapped {len(raw_sections)} sections to disk file layout")

        # -------------------------------------------------------------
        # Step 6: Recalculate SizeOfImage
        # -------------------------------------------------------------
        highest_extent = max((s.virtual_address + cls.align_up(s.virtual_size, sec_align) for s in raw_sections), default=0x4000)
        struct.pack_into("<I", rebuilt, pe_offset + 80, highest_extent)
        telemetry.actions.append(f"Updated SizeOfImage -> 0x{highest_extent:X}")

        # -------------------------------------------------------------
        # Step 7: Synthesize or Reconnect Cor20Header Descriptor
        # -------------------------------------------------------------
        dd_offset = pe_offset + 24 + (96 if magic == cls.PE32_MAGIC else 112)
        cor20_dd_offset = dd_offset + (14 * 8)
        sec_dd_offset = dd_offset + (4 * 8)

        if options.zeroize_security_dir and sec_dd_offset + 8 <= len(rebuilt):
            struct.pack_into("<II", rebuilt, sec_dd_offset, 0, 0)
            telemetry.actions.append("Zeroed out invalid Authenticode security directory")

        if options.reconstruct_cor20 and telemetry.bsjb_metadata_found:
            bsjb_rva = telemetry.bsjb_rva or 0x2000
            # Look for existing Cor20Header in the binary
            cor_rva = None
            for s in raw_sections:
                if s.raw_ptr + s.raw_size <= len(rebuilt):
                    sec_chunk = rebuilt[s.raw_ptr : s.raw_ptr + s.raw_size]
                    found_idx = sec_chunk.find(b"\x48\x00\x00\x00\x02\x00")
                    if found_idx != -1 and found_idx + 72 <= len(sec_chunk):
                        cor_rva = s.virtual_address + found_idx
                        break

            if cor_rva is not None:
                struct.pack_into("<II", rebuilt, cor20_dd_offset, cor_rva, cls.COR20_HEADER_SIZE)
                telemetry.cor20_recovered = True
                telemetry.cor20_rva = cor_rva
                telemetry.actions.append(f"Reconnected existing Cor20Header at RVA 0x{cor_rva:X}")
            else:
                # Synthesize standard Cor20Header at the end of the text/metadata section
                target_sec = next((s for s in raw_sections if s.contains_bsjb or s.name == ".text"), raw_sections[0])
                cor20_offset = target_sec.raw_ptr + min(target_sec.raw_size - cls.COR20_HEADER_SIZE, 0x100)
                if cor20_offset + cls.COR20_HEADER_SIZE <= len(rebuilt):
                    # cb=72, major=2, minor=5, MetaData=(bsjb_rva, 4096), Flags=1, EntryPointToken=0x06000001
                    struct.pack_into("<IHHI", rebuilt, cor20_offset, 72, 2, 5, bsjb_rva)
                    struct.pack_into("<III", rebuilt, cor20_offset + 12, 4096, 1, 0x06000001)
                    cor20_synth_rva = target_sec.virtual_address + (cor20_offset - target_sec.raw_ptr)
                    struct.pack_into("<II", rebuilt, cor20_dd_offset, cor20_synth_rva, cls.COR20_HEADER_SIZE)
                    telemetry.cor20_synthesized = True
                    telemetry.cor20_rva = cor20_synth_rva
                    telemetry.actions.append(f"Synthesized standard Cor20Header at RVA 0x{cor20_synth_rva:X}")

        # Zeroize sensitive scratchpad buffer
        try:
            ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
        except Exception:
            for i in range(len(buf)):
                buf[i] = 0

        final_bytes = bytes(rebuilt)
        result.healed_size = len(final_bytes)
        result.is_healed = True
        result.sha256 = hashlib.sha256(final_bytes).hexdigest()
        return final_bytes, result
