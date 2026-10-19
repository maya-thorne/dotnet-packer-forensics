"""
PE Assembly Reconstructor & CIL Method Body Injector for Captured JIT Methods.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import List, Optional

from .models import CapturedMethod


class JITAssemblyRestorer:
    """Injects captured and decrypted CIL method bodies into a target PE binary or synthesizes a wrapper."""

    @classmethod
    def reconstruct_pe(
        cls,
        base_pe_bytes: Optional[bytes],
        methods: List[CapturedMethod],
        section_name: str = ".jitcapt",
    ) -> bytes:
        """
        Injects captured methods into base PE via a new section (.jitcapt),
        or synthesizes a minimal compliant PE container if base binary is unavailable.
        """
        if not methods:
            return base_pe_bytes or b""

        # Pack all captured method bodies into a single aligned payload block
        payload_block, method_offsets = cls._pack_method_bodies(methods)

        if base_pe_bytes and len(base_pe_bytes) >= 0x200 and base_pe_bytes[:2] == b"MZ":
            try:
                return cls._inject_section(base_pe_bytes, payload_block, section_name)
            except Exception:
                pass

        # Fallback: Synthesize minimal valid PE32 container
        return cls._synthesize_minimal_pe(payload_block, section_name)

    @classmethod
    def _pack_method_bodies(cls, methods: List[CapturedMethod]) -> tuple[bytes, List[int]]:
        """Packs CIL method bodies with 4-byte alignment, tracking offsets."""
        buf = bytearray()
        offsets: List[int] = []

        for m in methods:
            # 4-byte alignment
            pad = (4 - (len(buf) % 4)) % 4
            buf.extend(b"\x00" * pad)
            offsets.append(len(buf))

            if m.header_format == "Tiny":
                header_byte = (m.il_size << 2) | 0x02
                buf.append(header_byte)
                buf.extend(m.il_bytes)
            elif m.header_format == "Fat":
                flags_size = 0x3003  # Fat header (0x03) + size 3 dwords (0x3000)
                fat_hdr = struct.pack("<HHII", flags_size, m.max_stack, m.il_size, m.local_sig_token)
                buf.extend(fat_hdr)
                buf.extend(m.il_bytes)
            else:
                buf.extend(m.il_bytes)

        return bytes(buf), offsets

    @classmethod
    def _inject_section(cls, pe_data: bytes, section_data: bytes, name: str) -> bytes:
        """Appends a new section header and data to an existing PE binary."""
        e_lfanew = struct.unpack("<I", pe_data[0x3C:0x40])[0]
        if e_lfanew + 0xF8 > len(pe_data):
            raise ValueError("Corrupted PE header")

        pe_buf = bytearray(pe_data)
        num_sections = struct.unpack("<H", pe_buf[e_lfanew + 6 : e_lfanew + 8])[0]
        opt_hdr_size = struct.unpack("<H", pe_buf[e_lfanew + 20 : e_lfanew + 22])[0]
        sect_table_offset = e_lfanew + 24 + opt_hdr_size

        # Find highest RVA and raw offset
        max_rva = 0x1000
        max_raw = len(pe_data)

        for i in range(num_sections):
            hdr_off = sect_table_offset + (i * 40)
            if hdr_off + 40 <= len(pe_buf):
                vsize, vrva, rsize, roff = struct.unpack("<IIII", pe_buf[hdr_off + 8 : hdr_off + 24])
                aligned_vsize = (vsize + 0xFFF) & ~0xFFF
                max_rva = max(max_rva, vrva + aligned_vsize)
                max_raw = max(max_raw, roff + rsize)

        new_rva = (max_rva + 0xFFF) & ~0xFFF
        new_raw_offset = (max_raw + 0x1FF) & ~0x1FF

        # Pad file to new_raw_offset
        if len(pe_buf) < new_raw_offset:
            pe_buf.extend(b"\x00" * (new_raw_offset - len(pe_buf)))

        # Build section header (40 bytes)
        sec_name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
        vsize = len(section_data)
        rsize = (vsize + 0x1FF) & ~0x1FF
        chars = 0x60000020  # MEM_EXECUTE | MEM_READ | CNT_CODE

        new_sect_hdr = struct.pack(
            "<8sIIIIIIHHI",
            sec_name_bytes,
            vsize,
            new_rva,
            rsize,
            new_raw_offset,
            0,
            0,
            0,
            0,
            chars,
        )

        new_hdr_offset = sect_table_offset + (num_sections * 40)
        # Check space for new header before the first section's raw data
        first_section_raw = struct.unpack("<I", pe_buf[sect_table_offset + 20 : sect_table_offset + 24])[0]
        if new_hdr_offset + 40 > first_section_raw:
            # Not enough header slack space, return original
            return pe_data

        pe_buf[new_hdr_offset : new_hdr_offset + 40] = new_sect_hdr

        # Update NumberOfSections
        pe_buf[e_lfanew + 6 : e_lfanew + 8] = struct.pack("<H", num_sections + 1)

        # Update SizeOfImage
        new_image_size = (new_rva + vsize + 0xFFF) & ~0xFFF
        pe_buf[e_lfanew + 0x38 : e_lfanew + 0x3C] = struct.pack("<I", new_image_size)

        # Append section payload
        pe_buf.extend(section_data)
        pad_size = rsize - vsize
        if pad_size > 0:
            pe_buf.extend(b"\x00" * pad_size)

        return bytes(pe_buf)

    @classmethod
    def _synthesize_minimal_pe(cls, payload: bytes, section_name: str) -> bytes:
        """Synthesizes a minimal valid PE32 container holding the captured methods."""
        buf = bytearray(0x400)  # Headers block (1024 bytes)

        # DOS Header
        buf[0:2] = b"MZ"
        buf[0x3C:0x40] = struct.pack("<I", 0x80)  # e_lfanew

        # NT Headers at 0x80
        nt_off = 0x80
        buf[nt_off : nt_off + 4] = b"PE\x00\x00"
        # FileHeader: Machine=0x014C (x86), Sections=1, OptHdrSize=0xE0, Chars=0x0102
        buf[nt_off + 4 : nt_off + 24] = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)

        # Optional Header (PE32)
        opt_off = nt_off + 24
        buf[opt_off : opt_off + 2] = struct.pack("<H", 0x010B)  # Magic PE32
        buf[opt_off + 16 : opt_off + 20] = struct.pack("<I", 0x2000)  # AddressOfEntryPoint
        buf[opt_off + 28 : opt_off + 32] = struct.pack("<I", 0x00400000)  # ImageBase
        buf[opt_off + 32 : opt_off + 36] = struct.pack("<I", 0x1000)  # SectionAlignment
        buf[opt_off + 36 : opt_off + 40] = struct.pack("<I", 0x200)  # FileAlignment
        buf[opt_off + 56 : opt_off + 60] = struct.pack("<I", 0x4000)  # SizeOfImage
        buf[opt_off + 60 : opt_off + 64] = struct.pack("<I", 0x400)  # SizeOfHeaders
        buf[opt_off + 68 : opt_off + 70] = struct.pack("<H", 0x0003)  # Subsystem=CONSOLE
        buf[opt_off + 92 : opt_off + 96] = struct.pack("<I", 16)  # NumberOfRvaAndSizes

        # Section Header at nt_off + 24 + 0xE0 = 0x80 + 24 + 224 = 0x178
        sec_off = opt_off + 0xE0
        vsize = len(payload)
        rsize = (vsize + 0x1FF) & ~0x1FF
        sec_name = section_name.encode("ascii")[:8].ljust(8, b"\x00")
        buf[sec_off : sec_off + 40] = struct.pack(
            "<8sIIIIIIHHI",
            sec_name,
            vsize,
            0x2000,
            rsize,
            0x400,
            0,
            0,
            0,
            0,
            0x60000020,
        )

        # Section raw data at 0x400
        buf.extend(payload)
        pad = rsize - vsize
        if pad > 0:
            buf.extend(b"\x00" * pad)

        return bytes(buf)

    @classmethod
    def generate_disassembly_listing(cls, methods: List[CapturedMethod]) -> str:
        """Emits human-readable ECMA-335 CIL assembly listing for all captured methods."""
        lines: List[str] = [
            "// ==========================================================================",
            "// JIT-Captured .NET Assembly CIL Disassembly Listing",
            f"// Total Captured Methods: {len(methods)}",
            "// Generated by dotnet-packer-forensics JIT Tracer Engine",
            "// ==========================================================================",
            "",
            ".assembly extern mscorlib { .ver 4:0:0:0 }",
            '.assembly CapturedAssembly { .hash algorithm 0x00008004 .ver 1:0:0:0 }',
            '.module CapturedAssembly.dll',
            "",
        ]

        # Group by declaring type
        types_map: dict[str, List[CapturedMethod]] = {}
        for m in methods:
            t = m.declaring_type or "Global"
            types_map.setdefault(t, []).append(m)

        for type_name, type_methods in types_map.items():
            lines.append(f".class public auto ansi beforefieldinit {type_name}")
            lines.append("{")
            for m in type_methods:
                lines.append(f"  // Token: {hex(m.token)} | RVA: {hex(m.rva)} | Header: {m.header_format} | Size: {m.il_size} bytes")
                lines.append(f"  // SHA-256: {m.sha256[:16]}... | State: {m.state.value} | Source: {m.capture_source.value}")
                lines.append(f"  .method public hidebysig instance void {m.name}() cil managed")
                lines.append("  {")
                lines.append(f"    .maxstack {m.max_stack}")
                if m.local_sig_token:
                    lines.append(f"    // LocalVarSig: {hex(m.local_sig_token)}")
                for dis_line in m.disassembly_preview:
                    lines.append(f"    {dis_line}")
                lines.append("  }")
                lines.append("")
            lines.append("}")
            lines.append("")

        return "\n".join(lines)
