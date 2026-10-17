"""
PE Assembly Reconstructor and Minimal PE32 Container Synthesizer.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

from ..payload_verifier import PayloadVerifier
from ..pe_rebuilder import PERebuilder
from .models import CarvedAssembly, CarvedMethod


class AssemblyReconstructor:
    """
    Reconstructs valid PE assemblies from carved memory segments by either
    unmapping virtual memory layouts or synthesizing a compliant PE32/CLR wrapper.
    """

    @classmethod
    def reconstruct_from_memory(
        cls,
        dump_data: bytes,
        bsjb_offset: int,
        bsjb_info: Dict[str, Any],
        methods: List[CarvedMethod],
        search_window: int = 1024 * 1024,
    ) -> Optional[CarvedAssembly]:
        """
        Attempts to locate a surrounding PE header to unmap and reconstruct the assembly,
        or synthesizes a minimal compliant PE32 container around the carved BSJB metadata.
        """
        # 1. Search backwards for an MZ header
        start_search = max(0, bsjb_offset - search_window)
        mz_offset = cls._find_nearest_mz(dump_data, start_search, bsjb_offset)

        if mz_offset is not None:
            rebuilt_pe = cls._try_unmap_existing_pe(dump_data, mz_offset, bsjb_offset)
            if rebuilt_pe is not None:
                sha = hashlib.sha256(rebuilt_pe).hexdigest()
                return CarvedAssembly(
                    identifier=f"carved_pe_{sha[:8]}",
                    offset=mz_offset,
                    size=len(rebuilt_pe),
                    name=bsjb_info.get("version", "DotNetAssembly"),
                    version=bsjb_info.get("version", "v4.0.30319"),
                    entry_point_token=0x06000001,
                    sha256=sha,
                    is_pe_valid=True,
                    is_reconstructed=True,
                    confidence=0.95,
                    bsjb_offset=bsjb_offset,
                    streams_present=list(bsjb_info.get("streams", {}).keys()),
                    raw_data=rebuilt_pe,
                )

        # 2. If no MZ header found, synthesize a compliant PE32 container
        synthesized_pe = cls.synthesize_pe_wrapper(dump_data, bsjb_offset, bsjb_info, methods)
        if synthesized_pe is not None:
            sha = hashlib.sha256(synthesized_pe).hexdigest()
            return CarvedAssembly(
                identifier=f"synthesized_{sha[:8]}",
                offset=bsjb_offset,
                size=len(synthesized_pe),
                name=f"Synthesized_{sha[:8]}",
                version=bsjb_info.get("version", "v4.0.30319"),
                entry_point_token=0x06000001,
                sha256=sha,
                is_pe_valid=True,
                is_reconstructed=True,
                confidence=0.85,
                bsjb_offset=bsjb_offset,
                streams_present=list(bsjb_info.get("streams", {}).keys()),
                raw_data=synthesized_pe,
            )

        return None

    @classmethod
    def _find_nearest_mz(cls, data: bytes, start: int, end: int) -> Optional[int]:
        """Finds the last valid MZ header preceding the BSJB offset."""
        last_mz = None
        curr = start
        while curr < end:
            idx = data.find(b"MZ", curr, end)
            if idx == -1:
                break
            # Validate PE signature pointer at 0x3C
            if idx + 0x40 <= len(data):
                pe_ptr = struct.unpack_from("<I", data, idx + 0x3C)[0]
                if 0x40 <= pe_ptr <= 0x1000 and idx + pe_ptr + 4 <= len(data):
                    if data[idx + pe_ptr : idx + pe_ptr + 4] == b"PE\x00\x00":
                        last_mz = idx
            curr = idx + 2
        return last_mz

    @classmethod
    def _try_unmap_existing_pe(
        cls, data: bytes, mz_offset: int, bsjb_offset: int
    ) -> Optional[bytes]:
        """
        Unmaps virtual memory section layout back to physical file offsets.
        """
        data_len = len(data)
        if mz_offset + 0x40 > data_len:
            return None

        pe_ptr = struct.unpack_from("<I", data, mz_offset + 0x3C)[0]
        nt_offset = mz_offset + pe_ptr
        if nt_offset + 24 > data_len or data[nt_offset : nt_offset + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack_from("<H", data, nt_offset + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, nt_offset + 20)[0]
        opt_hdr_offset = nt_offset + 24
        if opt_hdr_offset + opt_hdr_size > data_len or opt_hdr_size < 68:
            return None

        file_alignment = struct.unpack_from("<I", data, opt_hdr_offset + 36)[0]
        if file_alignment == 0 or (file_alignment & (file_alignment - 1)) != 0:
            file_alignment = 0x200

        sec_hdr_offset = opt_hdr_offset + opt_hdr_size
        sections: List[Tuple[int, int, int, int]] = []  # (vaddr, vsize, raddr, rsize)

        max_raw_end = 0
        for i in range(num_sections):
            entry = sec_hdr_offset + (i * 40)
            if entry + 40 > data_len:
                break
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, entry + 8)
            sections.append((vaddr, vsize, raddr, rsize))
            max_raw_end = max(max_raw_end, raddr + rsize)

        if max_raw_end == 0 or max_raw_end > 50 * 1024 * 1024:
            return None

        # Assemble file buffer
        rebuilt = bytearray(max_raw_end)
        # Copy header region
        hdr_size = min(sec_hdr_offset + (num_sections * 40), data_len - mz_offset)
        rebuilt[:hdr_size] = data[mz_offset : mz_offset + hdr_size]

        # Copy sections from their virtual offsets
        for vaddr, vsize, raddr, rsize in sections:
            src_start = mz_offset + vaddr
            src_size = min(vsize, rsize, data_len - src_start) if src_start < data_len else 0
            if src_size > 0 and raddr + src_size <= len(rebuilt):
                rebuilt[raddr : raddr + src_size] = data[src_start : src_start + src_size]

        return bytes(rebuilt)

    @classmethod
    def synthesize_pe_wrapper(
        cls,
        data: bytes,
        bsjb_offset: int,
        bsjb_info: Dict[str, Any],
        methods: List[CarvedMethod],
    ) -> Optional[bytes]:
        """
        Synthesizes a minimal compliant PE32/CLR container hosting the carved BSJB metadata.
        """
        # Determine total size of BSJB metadata block
        streams = bsjb_info.get("streams", {})
        max_stream_end = 0
        for s in streams.values():
            s_end = s.get("rel_offset", 0) + s.get("size", 0)
            max_stream_end = max(max_stream_end, s_end)

        metadata_size = max(max_stream_end, 256)
        # Align metadata size to 4
        metadata_size = (metadata_size + 3) & ~3

        data_len = len(data)
        if bsjb_offset + metadata_size > data_len:
            metadata_size = data_len - bsjb_offset
        if metadata_size <= 0:
            return None

        metadata_bytes = data[bsjb_offset : bsjb_offset + metadata_size]

        # Structure .text section:
        # Offset 0x00: Native stub (6 bytes: JMP [0x00402000])
        # Offset 0x08: IMAGE_COR20_HEADER (72 bytes)
        # Offset 0x50: Cor20 Method Bodies & BSJB Metadata
        cor20_hdr_offset = 8
        metadata_rel_in_text = 80

        text_content = bytearray(metadata_rel_in_text + len(metadata_bytes))
        # Native stub: FF 25 00 20 40 00
        text_content[0:6] = b"\xFF\x25\x00\x20\x40\x00"

        # IMAGE_COR20_HEADER (72 bytes)
        # cb (4), MajorVer(2), MinorVer(2), MetaData RVA (4), MetaData Size (4), Flags (4), EntryPoint (4)
        entry_point = methods[0].token if methods else 0x06000001
        cor20_hdr = struct.pack(
            "<IIHHIIII",
            72,  # cb
            2,   # MajorRuntimeVersion
            5,   # MinorRuntimeVersion
            0x2000 + metadata_rel_in_text,  # MetaData RVA
            len(metadata_bytes),            # MetaData Size
            0x00000001,                     # COMIMAGE_FLAGS_ILONLY
            entry_point,                    # EntryPointToken
            0,                              # Resources RVA
        )
        text_content[cor20_hdr_offset : cor20_hdr_offset + len(cor20_hdr)] = cor20_hdr
        text_content[metadata_rel_in_text : metadata_rel_in_text + len(metadata_bytes)] = metadata_bytes

        # PE Sections
        file_align = 0x200
        sec_align = 0x2000

        text_raw_size = ((len(text_content) + file_align - 1) // file_align) * file_align
        text_virt_size = len(text_content)
        padded_text = bytearray(text_raw_size)
        padded_text[: len(text_content)] = text_content

        # Minimal .reloc section
        reloc_raw_size = file_align
        padded_reloc = bytearray(reloc_raw_size)
        # Relocation for the native stub jump target
        reloc_hdr = struct.pack("<II", 0x2000, 12)  # Page RVA, Block Size
        padded_reloc[:8] = reloc_hdr
        padded_reloc[8:10] = struct.pack("<H", 0x3002)  # HIGHLOW at offset 2

        # Headers
        hdr_raw_size = file_align
        pe_buf = bytearray(hdr_raw_size + text_raw_size + reloc_raw_size)

        # 1. DOS Header
        pe_buf[0:2] = b"MZ"
        struct.pack_into("<I", pe_buf, 0x3C, 0x80)  # e_lfanew = 0x80

        # 2. NT Headers at 0x80
        nt_start = 0x80
        pe_buf[nt_start : nt_start + 4] = b"PE\x00\x00"

        # FileHeader (20 bytes)
        struct.pack_into(
            "<HHIIIHH",
            pe_buf,
            nt_start + 4,
            0x014C,      # Machine (i386)
            2,           # NumberOfSections
            0x65000000,  # TimeDateStamp
            0,           # PointerToSymbolTable
            0,           # NumberOfSymbols
            224,         # SizeOfOptionalHeader
            0x210E,      # Characteristics (EXECUTABLE_IMAGE | 32BIT | DLL)
        )

        # OptionalHeader (224 bytes)
        opt_start = nt_start + 24
        struct.pack_into(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            pe_buf,
            opt_start,
            0x010B,      # Magic (PE32)
            11,          # MajorLinkerVersion
            0,           # MinorLinkerVersion
            text_raw_size,  # SizeOfCode
            reloc_raw_size, # SizeOfInitializedData
            0,           # SizeOfUninitializedData
            0x2000,      # AddressOfEntryPoint
            0x2000,      # BaseOfCode
            0x4000,      # BaseOfData
            0x00400000,  # ImageBase
            sec_align,   # SectionAlignment
            file_align,  # FileAlignment
            4, 0, 0, 0, 4, 0,  # OS/Image/Subsystem Versions
            0,           # Win32VersionValue
            0x6000,      # SizeOfImage
            hdr_raw_size,# SizeOfHeaders
            0,           # CheckSum
            3,           # Subsystem (WINDOWS_CUI)
            0x8540,      # DllCharacteristics
            0x100000,    # SizeOfStackReserve
            0x1000,      # SizeOfStackCommit
            0x100000,    # SizeOfHeapReserve
            0x1000,      # SizeOfHeapCommit
            0,           # LoaderFlags
            16,          # NumberOfRvaAndSizes
        )

        # DataDirectory[14] = CLR Runtime Header (RVA 0x2008, Size 72)
        clr_dir_offset = opt_start + 96 + (14 * 8)
        struct.pack_into("<II", pe_buf, clr_dir_offset, 0x2000 + cor20_hdr_offset, 72)

        # DataDirectory[5] = Base Relocation Table (RVA 0x4000, Size 12)
        reloc_dir_offset = opt_start + 96 + (5 * 8)
        struct.pack_into("<II", pe_buf, reloc_dir_offset, 0x4000, 12)

        # Section Headers (at opt_start + 224)
        sec_start = opt_start + 224

        # Section 1: .text
        pe_buf[sec_start : sec_start + 8] = b".text\x00\x00\x00"
        struct.pack_into(
            "<IIIIIIHHI",
            pe_buf,
            sec_start + 8,
            text_virt_size,  # VirtualSize
            0x2000,          # VirtualAddress
            text_raw_size,   # SizeOfRawData
            hdr_raw_size,    # PointerToRawData
            0, 0, 0, 0,
            0x60000020,      # Characteristics (CODE | EXECUTE | READ)
        )

        # Section 2: .reloc
        reloc_sec_start = sec_start + 40
        pe_buf[reloc_sec_start : reloc_sec_start + 8] = b".reloc\x00\x00"
        struct.pack_into(
            "<IIIIIIHHI",
            pe_buf,
            reloc_sec_start + 8,
            12,              # VirtualSize
            0x4000,          # VirtualAddress
            reloc_raw_size,  # SizeOfRawData
            hdr_raw_size + text_raw_size,  # PointerToRawData
            0, 0, 0, 0,
            0x42000040,      # Characteristics (INITIALIZED_DATA | DISCARDABLE | READ)
        )

        # Copy section bodies
        pe_buf[hdr_raw_size : hdr_raw_size + text_raw_size] = padded_text
        pe_buf[hdr_raw_size + text_raw_size : hdr_raw_size + text_raw_size + reloc_raw_size] = padded_reloc

        return bytes(pe_buf)
