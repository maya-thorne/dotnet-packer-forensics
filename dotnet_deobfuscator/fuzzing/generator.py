"""
Synthetic Mutated Binary Generator for .NET & PE Deobfuscator Regression Fuzzing.
Engineered & Audited by Maya Thorne.
"""

import os
import random
import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import MutationRecord, MutationStrategy, SecurityError, zeroize_buffer


class SyntheticMutatedBinaryGenerator:
    """
    Generates structurally valid baseline .NET PE binaries and applies targeted,
    multi-layer structural and bytecode mutations to stress-test forensic engines.
    """

    PE32_MAGIC = 0x010B
    PE32_PLUS_MAGIC = 0x020B
    MACHINE_I386 = 0x014C
    MACHINE_AMD64 = 0x8664
    COR20_HEADER_SIZE = 72

    @classmethod
    def generate_baseline_pe(
        cls,
        is_dotnet: bool = True,
        is_64bit: bool = False,
        method_name: str = "FuzzTargetMethod",
        entrypoint_token: int = 0x06000001,
        overlay_payload: Optional[bytes] = None,
    ) -> bytes:
        """
        Constructs a valid, minimal PE32 or PE32+ executable containing standard .NET CLI metadata,
        Cor20Header, metadata stream tables (#Strings, #US, #~), and a valid CIL method body.
        """
        # 1. DOS Header (0x80 bytes)
        dos = bytearray(0x80)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x80)

        # 2. NT File Header & Optional Header
        machine = cls.MACHINE_AMD64 if is_64bit else cls.MACHINE_I386
        opt_magic = cls.PE32_PLUS_MAGIC if is_64bit else cls.PE32_MAGIC
        opt_size = 0xF0 if is_64bit else 0xE0
        charact = 0x0022 if is_64bit else 0x0102

        file_hdr = bytearray(24)
        file_hdr[0:4] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", file_hdr, 4, machine, 2, 0x66B00000, 0, 0, opt_size, charact)

        # 3. Optional Header (0xE0 for 32-bit, 0xF0 for 64-bit)
        opt_hdr = bytearray(opt_size)
        struct.pack_into("<HBB", opt_hdr, 0, opt_magic, 11, 0)
        struct.pack_into("<III", opt_hdr, 4, 0x400, 0x400, 0)
        struct.pack_into("<II", opt_hdr, 16, 0x2000, 0x2000)
        if is_64bit:
            struct.pack_into("<Q", opt_hdr, 24, 0x0000000140000000)  # 64-bit ImageBase
            struct.pack_into("<IIHHHHII", opt_hdr, 32, 0x2000, 0x200, 4, 0, 0, 0, 4, 0)
            struct.pack_into("<IIHH", opt_hdr, 56, 0x6000, 0x200, 3, 0x8540)
            struct.pack_into("<QQQQII", opt_hdr, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
            if is_dotnet:
                struct.pack_into("<II", opt_hdr, 112 + (14 * 8), 0x2000, cls.COR20_HEADER_SIZE)
        else:
            struct.pack_into("<II", opt_hdr, 24, 0x4000, 0x00400000)  # BaseOfData, 32-bit ImageBase
            struct.pack_into("<IIHHHHII", opt_hdr, 32, 0x2000, 0x200, 4, 0, 0, 0, 4, 0)
            struct.pack_into("<IIHH", opt_hdr, 56, 0x6000, 0x200, 3, 0x8540)
            struct.pack_into("<IIIIII", opt_hdr, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
            if is_dotnet:
                struct.pack_into("<II", opt_hdr, 96 + (14 * 8), 0x2000, cls.COR20_HEADER_SIZE)

        # 4. Section Table (.text @ 0x200, .rsrc @ 0x600)
        sec_table = bytearray(80)
        sec_table[0:8] = b".text\x00\x00\x00"
        struct.pack_into("<IIIIIIHHI", sec_table, 8, 0x1000, 0x2000, 0x400, 0x200, 0, 0, 0, 0, 0x60000020)
        sec_table[40:48] = b".rsrc\x00\x00\x00"
        struct.pack_into("<IIIIIIHHI", sec_table, 48, 0x1000, 0x4000, 0x200, 0x600, 0, 0, 0, 0, 0x40000040)

        raw_headers = dos + file_hdr + opt_hdr + sec_table
        if len(raw_headers) < 0x200:
            raw_headers += b"\x00" * (0x200 - len(raw_headers))

        # 5. .text Section Payload (0x400 bytes)
        text_payload = bytearray(0x400)
        if is_dotnet:
            struct.pack_into("<IHHI", text_payload, 0, cls.COR20_HEADER_SIZE, 2, 5, 0x2050)
            struct.pack_into("<III", text_payload, 12, 0x120, 0x00000001, entrypoint_token)

            # BSJB Metadata Root & Streams (#Strings, #US, #~)
            meta_offset = 0x50
            struct.pack_into("<IHHII", text_payload, meta_offset, 0x424A5342, 1, 1, 0, 12)
            text_payload[meta_offset + 16 : meta_offset + 28] = b"v4.0.30319\x00\x00"
            s_start = meta_offset + 28
            struct.pack_into("<HH", text_payload, s_start, 0, 3)

            s1 = s_start + 4
            struct.pack_into("<II", text_payload, s1, 0x50, 0x30)
            text_payload[s1 + 8 : s1 + 17] = b"#Strings\x00"
            s2 = s1 + 20
            struct.pack_into("<II", text_payload, s2, 0x80, 0x20)
            text_payload[s2 + 8 : s2 + 12] = b"#US\x00\x00"
            s3 = s2 + 12
            struct.pack_into("<II", text_payload, s3, 0xA0, 0x40)
            text_payload[s3 + 8 : s3 + 12] = b"#~\x00\x00"

            str_offset = meta_offset + 0x50
            sample_strings = b"\x00Main\x00" + method_name.encode("utf-8") + b"\x00System\x00Object\x00"
            text_payload[str_offset : str_offset + len(sample_strings)] = sample_strings

            # CIL Method Body: TinyHeader 0x0A, nop (0x00), ret (0x2A)
            text_payload[0x180:0x183] = b"\x0A\x00\x2A"

        # 6. .rsrc Section Payload (0x200 bytes)
        rsrc_payload = bytearray(0x200)
        rsrc_payload[0:16] = b"\x00" * 12 + b"\x01\x00\x00\x00"

        binary = bytes(raw_headers) + bytes(text_payload) + bytes(rsrc_payload)
        if overlay_payload:
            binary += overlay_payload
        return binary

    @classmethod
    def mutate_bit_flips(
        cls, data: bytearray, prng: random.Random, flip_count: int = 2
    ) -> List[MutationRecord]:
        """Flips individual bits at pseudorandom offsets."""
        records: List[MutationRecord] = []
        if len(data) == 0:
            return records
        for _ in range(max(1, flip_count)):
            idx = prng.randint(0, len(data) - 1)
            bit = prng.randint(0, 7)
            orig = data[idx]
            mut = orig ^ (1 << bit)
            data[idx] = mut
            records.append(MutationRecord(
                strategy=MutationStrategy.BIT_FLIP,
                offset=idx,
                original_hex=f"{orig:02X}",
                mutated_hex=f"{mut:02X}",
                description=f"Bit flip at bit {bit} (0x{orig:02X} -> 0x{mut:02X})",
            ))
        return records

    @classmethod
    def mutate_byte_noise(
        cls, data: bytearray, prng: random.Random, count: int = 4
    ) -> List[MutationRecord]:
        """Substitutes random byte sequences with arbitrary garbage, zeros, or edge integers."""
        records: List[MutationRecord] = []
        if len(data) == 0:
            return records
        edge_bytes = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE]
        for _ in range(max(1, count)):
            idx = prng.randint(0, len(data) - 1)
            orig = data[idx]
            mut = prng.choice(edge_bytes) if prng.random() < 0.5 else prng.randint(0, 255)
            data[idx] = mut
            records.append(MutationRecord(
                strategy=MutationStrategy.BYTE_NOISE,
                offset=idx,
                original_hex=f"{orig:02X}",
                mutated_hex=f"{mut:02X}",
                description=f"Byte noise mutation (0x{orig:02X} -> 0x{mut:02X})",
            ))
        return records

    @classmethod
    def mutate_dos_header(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Corrupts DOS magic or e_lfanew offset pointer."""
        records: List[MutationRecord] = []
        if len(data) < 0x40:
            return records
        choice = prng.randint(0, 2)
        if choice == 0:
            # Corrupt MZ magic
            orig = bytes(data[0:2]).hex().upper()
            data[0:2] = b"XX" if prng.random() < 0.5 else b"\x00\x00"
            records.append(MutationRecord(
                strategy=MutationStrategy.DOS_HEADER_MANGLE,
                offset=0,
                original_hex=orig,
                mutated_hex=bytes(data[0:2]).hex().upper(),
                description="Corrupted DOS header magic signature",
            ))
        elif choice == 1:
            # Corrupt e_lfanew to out-of-bounds offset
            orig = bytes(data[0x3C:0x40]).hex().upper()
            bogus_offsets = [0, 0xFFFFFFFF, len(data) + 0x1000, 0x00000010]
            bogus = prng.choice(bogus_offsets)
            struct.pack_into("<I", data, 0x3C, bogus)
            records.append(MutationRecord(
                strategy=MutationStrategy.DOS_HEADER_MANGLE,
                offset=0x3C,
                original_hex=orig,
                mutated_hex=bytes(data[0x3C:0x40]).hex().upper(),
                description=f"Corrupted e_lfanew pointer to 0x{bogus:08X}",
            ))
        else:
            # Wipe DOS stub table
            orig = bytes(data[0x10:0x3C]).hex().upper()
            for i in range(0x10, 0x3C):
                data[i] = 0xFF
            records.append(MutationRecord(
                strategy=MutationStrategy.DOS_HEADER_MANGLE,
                offset=0x10,
                original_hex=orig[:8] + "...",
                mutated_hex="FFFFFFFF...",
                description="Flooded DOS stub reserved fields with 0xFF",
            ))
        return records

    @classmethod
    def mutate_nt_header(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Corrupts PE signature, Machine architecture, or NumberOfSections."""
        records: List[MutationRecord] = []
        if len(data) < 0x40:
            return records
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return records

        choice = prng.randint(0, 2)
        if choice == 0:
            # Corrupt PE\0\0
            orig = bytes(data[e_lfanew : e_lfanew + 4]).hex().upper()
            data[e_lfanew : e_lfanew + 4] = b"NE\x00\x00" if prng.random() < 0.5 else b"\xFF\xFF\xFF\xFF"
            records.append(MutationRecord(
                strategy=MutationStrategy.NT_HEADER_MANGLE,
                offset=e_lfanew,
                original_hex=orig,
                mutated_hex=bytes(data[e_lfanew : e_lfanew + 4]).hex().upper(),
                description="Corrupted PE\\0\\0 signature at e_lfanew",
            ))
        elif choice == 1:
            # Machine field
            orig = bytes(data[e_lfanew + 4 : e_lfanew + 6]).hex().upper()
            struct.pack_into("<H", data, e_lfanew + 4, prng.choice([0, 0x9999, 0xFFFF]))
            records.append(MutationRecord(
                strategy=MutationStrategy.NT_HEADER_MANGLE,
                offset=e_lfanew + 4,
                original_hex=orig,
                mutated_hex=bytes(data[e_lfanew + 4 : e_lfanew + 6]).hex().upper(),
                description="Mutated Machine architecture identifier",
            ))
        else:
            # NumberOfSections
            orig = bytes(data[e_lfanew + 6 : e_lfanew + 8]).hex().upper()
            bogus_sec = prng.choice([0, 96, 65535])
            struct.pack_into("<H", data, e_lfanew + 6, bogus_sec)
            records.append(MutationRecord(
                strategy=MutationStrategy.NT_HEADER_MANGLE,
                offset=e_lfanew + 6,
                original_hex=orig,
                mutated_hex=bytes(data[e_lfanew + 6 : e_lfanew + 8]).hex().upper(),
                description=f"Corrupted NumberOfSections to {bogus_sec}",
            ))
        return records

    @classmethod
    def mutate_optional_header(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Mangles Optional Header fields (Magic, SectionAlignment, DataDirectories)."""
        records: List[MutationRecord] = []
        if len(data) < 0x40:
            return records
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt_start = e_lfanew + 24
        if opt_start + 120 > len(data):
            return records

        choice = prng.randint(0, 2)
        if choice == 0:
            # Magic
            orig = bytes(data[opt_start : opt_start + 2]).hex().upper()
            struct.pack_into("<H", data, opt_start, prng.choice([0x0000, 0x020B, 0xFFFF]))
            records.append(MutationRecord(
                strategy=MutationStrategy.OPTIONAL_HEADER_MANGLE,
                offset=opt_start,
                original_hex=orig,
                mutated_hex=bytes(data[opt_start : opt_start + 2]).hex().upper(),
                description="Corrupted OptionalHeader Magic word",
            ))
        elif choice == 1:
            # SectionAlignment / FileAlignment conflict
            orig = bytes(data[opt_start + 32 : opt_start + 40]).hex().upper()
            struct.pack_into("<I", data, opt_start + 32, 0x100)   # SectionAlignment < FileAlignment
            struct.pack_into("<I", data, opt_start + 36, 0x1000)  # FileAlignment
            records.append(MutationRecord(
                strategy=MutationStrategy.OPTIONAL_HEADER_MANGLE,
                offset=opt_start + 32,
                original_hex=orig,
                mutated_hex=bytes(data[opt_start + 32 : opt_start + 40]).hex().upper(),
                description="Inverted SectionAlignment < FileAlignment anomaly",
            ))
        else:
            # Data Directory 14 (CLR) - offset 96 for PE32, 112 for PE32+
            opt_magic = struct.unpack_from("<H", data, opt_start)[0] if opt_start + 2 <= len(data) else 0x010B
            dd_offset = 112 if opt_magic == 0x020B else 96
            clr_dir_off = opt_start + dd_offset + (14 * 8)
            if clr_dir_off + 8 <= len(data):
                orig = bytes(data[clr_dir_off : clr_dir_off + 8]).hex().upper()
                struct.pack_into("<II", data, clr_dir_off, 0xFFFFFFFF, 0x00000000)
                records.append(MutationRecord(
                    strategy=MutationStrategy.OPTIONAL_HEADER_MANGLE,
                    offset=clr_dir_off,
                    original_hex=orig,
                    mutated_hex=bytes(data[clr_dir_off : clr_dir_off + 8]).hex().upper(),
                    description="Zeroed or corrupted DataDirectory[14] CLR descriptor",
                ))
        return records

    @classmethod
    def mutate_section_table(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Corrupts section headers, overlapping pointers, and invalid raw boundaries."""
        records: List[MutationRecord] = []
        if len(data) < 0x40:
            return records
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return records
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_start = e_lfanew + 24 + opt_size
        if sec_start + 40 > len(data) or num_sections == 0:
            return records

        target_sec = prng.randint(0, min(num_sections - 1, 3))
        off = sec_start + (target_sec * 40)
        if off + 40 > len(data):
            return records

        choice = prng.randint(0, 2)
        if choice == 0:
            # Corrupt section name to non-printable binary or empty nulls
            orig = bytes(data[off : off + 8]).hex().upper()
            data[off : off + 8] = b"\xFF\xFE\x00\x01\x80\x90\xAA\xBB" if prng.random() < 0.5 else b"\x00" * 8
            records.append(MutationRecord(
                strategy=MutationStrategy.SECTION_TABLE_MANGLE,
                offset=off,
                original_hex=orig,
                mutated_hex=bytes(data[off : off + 8]).hex().upper(),
                description=f"Corrupted Section {target_sec} name to unprintable bytes",
            ))
        elif choice == 1:
            # PointerToRawData out-of-bounds
            orig = bytes(data[off + 20 : off + 24]).hex().upper()
            bogus_ptr = len(data) + 0x20000
            struct.pack_into("<I", data, off + 20, bogus_ptr)
            records.append(MutationRecord(
                strategy=MutationStrategy.SECTION_TABLE_MANGLE,
                offset=off + 20,
                original_hex=orig,
                mutated_hex=bytes(data[off + 20 : off + 24]).hex().upper(),
                description=f"Section {target_sec} PointerToRawData displaced past EOF",
            ))
        else:
            # SizeOfRawData massive integer overflow candidate
            orig = bytes(data[off + 16 : off + 20]).hex().upper()
            struct.pack_into("<I", data, off + 16, 0x7FFFFFFF)
            records.append(MutationRecord(
                strategy=MutationStrategy.SECTION_TABLE_MANGLE,
                offset=off + 16,
                original_hex=orig,
                mutated_hex=bytes(data[off + 16 : off + 20]).hex().upper(),
                description=f"Section {target_sec} SizeOfRawData integer overflow",
            ))
        return records

    @classmethod
    def mutate_cor20_descriptor(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Corrupts IMAGE_COR20_HEADER fields (cb, MetaData RVA/Size, Flags)."""
        records: List[MutationRecord] = []
        # Find Cor20Header candidate (cb == 72)
        cor_idx = -1
        for i in range(0x200, min(len(data) - 72, 0x1000)):
            if struct.unpack_from("<I", data, i)[0] == 72:
                cor_idx = i
                break
        if cor_idx == -1:
            return records

        choice = prng.randint(0, 2)
        if choice == 0:
            # Corrupt cb size
            orig = bytes(data[cor_idx : cor_idx + 4]).hex().upper()
            struct.pack_into("<I", data, cor_idx, prng.choice([0, 16, 0xFFFFFFFF]))
            records.append(MutationRecord(
                strategy=MutationStrategy.COR20_DESCRIPTOR_MANGLE,
                offset=cor_idx,
                original_hex=orig,
                mutated_hex=bytes(data[cor_idx : cor_idx + 4]).hex().upper(),
                description="Corrupted Cor20Header cb field",
            ))
        elif choice == 1:
            # Corrupt MetaData RVA/Size
            orig = bytes(data[cor_idx + 8 : cor_idx + 16]).hex().upper()
            struct.pack_into("<II", data, cor_idx + 8, 0xFFFFFFFF, 0x00000000)
            records.append(MutationRecord(
                strategy=MutationStrategy.COR20_DESCRIPTOR_MANGLE,
                offset=cor_idx + 8,
                original_hex=orig,
                mutated_hex=bytes(data[cor_idx + 8 : cor_idx + 16]).hex().upper(),
                description="Corrupted Cor20Header MetaData RVA/Size directory",
            ))
        else:
            # Corrupt EntryPointToken
            orig = bytes(data[cor_idx + 20 : cor_idx + 24]).hex().upper()
            struct.pack_into("<I", data, cor_idx + 20, 0x02000000)  # TypeDef token instead of MethodDef
            records.append(MutationRecord(
                strategy=MutationStrategy.COR20_DESCRIPTOR_MANGLE,
                offset=cor_idx + 20,
                original_hex=orig,
                mutated_hex=bytes(data[cor_idx + 20 : cor_idx + 24]).hex().upper(),
                description="Mutated Cor20 EntryPointToken to invalid table RID",
            ))
        return records

    @classmethod
    def mutate_metadata_streams(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Corrupts BSJB signature, version string lengths, or stream table counts/offsets."""
        records: List[MutationRecord] = []
        bsjb_pos = data.find(b"BSJB")
        if bsjb_pos == -1 or bsjb_pos + 32 > len(data):
            return records

        choice = prng.randint(0, 2)
        if choice == 0:
            # Corrupt BSJB signature
            orig = bytes(data[bsjb_pos : bsjb_pos + 4]).hex().upper()
            data[bsjb_pos : bsjb_pos + 4] = b"BSXX" if prng.random() < 0.5 else b"\x00\x00\x00\x00"
            records.append(MutationRecord(
                strategy=MutationStrategy.METADATA_STREAM_MANGLE,
                offset=bsjb_pos,
                original_hex=orig,
                mutated_hex=bytes(data[bsjb_pos : bsjb_pos + 4]).hex().upper(),
                description="Corrupted BSJB CLI metadata magic signature",
            ))
        elif choice == 1:
            # Corrupt Version string length
            orig = bytes(data[bsjb_pos + 12 : bsjb_pos + 16]).hex().upper()
            struct.pack_into("<I", data, bsjb_pos + 12, 0x10000)  # Claim 64KB version string
            records.append(MutationRecord(
                strategy=MutationStrategy.METADATA_STREAM_MANGLE,
                offset=bsjb_pos + 12,
                original_hex=orig,
                mutated_hex=bytes(data[bsjb_pos + 12 : bsjb_pos + 16]).hex().upper(),
                description="Bloated CLI metadata VersionLength field",
            ))
        else:
            # Corrupt stream count
            ver_len = struct.unpack_from("<I", data, bsjb_pos + 12)[0]
            stream_count_pos = bsjb_pos + 16 + ver_len + 2
            if stream_count_pos + 2 <= len(data):
                orig = bytes(data[stream_count_pos : stream_count_pos + 2]).hex().upper()
                struct.pack_into("<H", data, stream_count_pos, 0x0500)  # 1280 streams claimed
                records.append(MutationRecord(
                    strategy=MutationStrategy.METADATA_STREAM_MANGLE,
                    offset=stream_count_pos,
                    original_hex=orig,
                    mutated_hex=bytes(data[stream_count_pos : stream_count_pos + 2]).hex().upper(),
                    description="Corrupted stream count to extreme value (1280 streams)",
                ))
        return records

    @classmethod
    def mutate_cil_instructions(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Injects invalid CIL opcodes (0xFE 0xFF), out-of-bounds branches, and stack hazards."""
        records: List[MutationRecord] = []
        # Search for CIL method indicator: 0x00 0x2A (nop, ret) or TinyHeader 0x0A
        idx = data.find(b"\x00\x2A")
        if idx == -1:
            idx = prng.randint(0x200, len(data) - 8) if len(data) > 0x220 else -1
        if idx == -1:
            return records

        choice = prng.randint(0, 2)
        if choice == 0:
            # Inject invalid 2-byte CIL opcode 0xFE 0xFF
            orig = bytes(data[idx : idx + 2]).hex().upper()
            data[idx : idx + 2] = b"\xFE\xFF"
            records.append(MutationRecord(
                strategy=MutationStrategy.CIL_BYTECODE_FUZZ,
                offset=idx,
                original_hex=orig,
                mutated_hex="FEFF",
                description="Injected invalid 2-byte CIL opcode 0xFE 0xFF",
            ))
        elif choice == 1:
            # Inject branch out of bounds (br.s -100 or br +0x10000)
            orig = bytes(data[idx : idx + 2]).hex().upper()
            data[idx : idx + 2] = b"\x2B\x80"  # br.s -128
            records.append(MutationRecord(
                strategy=MutationStrategy.CIL_BYTECODE_FUZZ,
                offset=idx,
                original_hex=orig,
                mutated_hex="2B80",
                description="Injected negative out-of-bounds CIL branch target",
            ))
        else:
            # Inject stack underflow sequence: pop, pop, ret
            orig = bytes(data[idx : idx + 3]).hex().upper()
            data[idx : idx + 3] = b"\x26\x26\x2A"
            records.append(MutationRecord(
                strategy=MutationStrategy.CIL_BYTECODE_FUZZ,
                offset=idx,
                original_hex=orig,
                mutated_hex="26262A",
                description="Injected stack-underflow CIL bytecode sequence (pop pop ret)",
            ))
        return records

    @classmethod
    def mutate_overlay_slack(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Appends random noise, pseudo-protector markers, or corrupted archive headers to overlay."""
        records: List[MutationRecord] = []
        orig_len = len(data)
        choice = prng.randint(0, 2)
        if choice == 0:
            # Append high-entropy random bytes
            noise = bytearray(prng.randbytes(prng.randint(64, 512)))
            data.extend(noise)
            records.append(MutationRecord(
                strategy=MutationStrategy.OVERLAY_INJECTION,
                offset=orig_len,
                original_hex="EOF",
                mutated_hex=bytes(noise[:8]).hex().upper() + "...",
                description=f"Appended {len(noise)} bytes of random high-entropy overlay noise",
            ))
        elif choice == 1:
            # Append pseudo-protector signature markers
            markers = [b"ConfusedByAttribute\x00", b".reactor\x00", b"Costura\x00", b"SmartAssembly\x00"]
            chosen = prng.choice(markers)
            data.extend(chosen)
            records.append(MutationRecord(
                strategy=MutationStrategy.OVERLAY_INJECTION,
                offset=orig_len,
                original_hex="EOF",
                mutated_hex=bytes(chosen).hex().upper(),
                description=f"Injected fake protector marker in overlay slack: {chosen.decode('ascii', errors='ignore')}",
            ))
        else:
            # Append corrupted ZIP / Deflate stream magic
            fake_zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\xFF" * 32
            data.extend(fake_zip)
            records.append(MutationRecord(
                strategy=MutationStrategy.OVERLAY_INJECTION,
                offset=orig_len,
                original_hex="EOF",
                mutated_hex=bytes(fake_zip[:8]).hex().upper(),
                description="Appended corrupt PKZIP container header to overlay",
            ))
        return records

    @classmethod
    def mutate_truncation(
        cls, data: bytearray, prng: random.Random
    ) -> List[MutationRecord]:
        """Truncates binary at arbitrary architectural boundaries."""
        records: List[MutationRecord] = []
        if len(data) <= 64:
            return records
        orig_len = len(data)
        # Select boundary: 64, 128, 256, 512, or random ratio strictly below orig_len
        candidates = [64, 128, 256, 512, prng.randint(32, max(33, orig_len - 16))]
        valid_cuts = [p for p in candidates if p < orig_len]
        cut = prng.choice(valid_cuts) if valid_cuts else prng.randint(1, orig_len - 1)
        del data[cut:]
        records.append(MutationRecord(
            strategy=MutationStrategy.TRUNCATION,
            offset=cut,
            original_hex=f"len:{orig_len}",
            mutated_hex=f"len:{len(data)}",
            description=f"Truncated file from {orig_len} bytes to {len(data)} bytes",
        ))
        return records

    @classmethod
    def mutate_binary(
        cls,
        base_data: bytes,
        strategies: Optional[List[MutationStrategy]] = None,
        seed: Optional[int] = None,
        mutation_depth: int = 2,
    ) -> Tuple[bytes, List[MutationRecord]]:
        """
        Applies a sequence of configured mutation strategies to input binary buffer.
        Returns the mutated binary bytes and an audit log of all applied mutations.
        """
        prng = random.Random(seed)
        buf = bytearray(base_data)
        all_records: List[MutationRecord] = []

        strategy_map = {
            MutationStrategy.BIT_FLIP: cls.mutate_bit_flips, MutationStrategy.BYTE_NOISE: cls.mutate_byte_noise,
            MutationStrategy.DOS_HEADER_MANGLE: cls.mutate_dos_header, MutationStrategy.NT_HEADER_MANGLE: cls.mutate_nt_header,
            MutationStrategy.OPTIONAL_HEADER_MANGLE: cls.mutate_optional_header, MutationStrategy.SECTION_TABLE_MANGLE: cls.mutate_section_table,
            MutationStrategy.COR20_DESCRIPTOR_MANGLE: cls.mutate_cor20_descriptor, MutationStrategy.METADATA_STREAM_MANGLE: cls.mutate_metadata_streams,
            MutationStrategy.CIL_BYTECODE_FUZZ: cls.mutate_cil_instructions, MutationStrategy.OVERLAY_INJECTION: cls.mutate_overlay_slack,
            MutationStrategy.TRUNCATION: cls.mutate_truncation,
        }

        available_strategies = strategies or list(MutationStrategy)

        depth = max(1, mutation_depth)
        for _ in range(depth):
            strat = prng.choice(available_strategies)
            handler = strategy_map.get(strat)
            if handler:
                recs = handler(buf, prng)
                all_records.extend(recs)

        res_bytes = bytes(buf)
        zeroize_buffer(buf)
        return res_bytes, all_records

    @classmethod
    def generate_corpus(
        cls,
        base_binary: Optional[bytes] = None,
        count: int = 10,
        seed: int = 42,
        strategies: Optional[List[MutationStrategy]] = None,
        mutation_depth: int = 2,
    ) -> List[Tuple[bytes, List[MutationRecord]]]:
        """
        Generates a diverse synthetic mutated corpus with comprehensive mutation coverage.
        """
        base = base_binary if base_binary is not None else cls.generate_baseline_pe()
        corpus: List[Tuple[bytes, List[MutationRecord]]] = []

        for i in range(count):
            iter_seed = (seed + (i * 31337)) & 0xFFFFFFFF
            mutated_bytes, records = cls.mutate_binary(
                base, strategies=strategies, seed=iter_seed, mutation_depth=mutation_depth
            )
            corpus.append((mutated_bytes, records))

        return corpus
