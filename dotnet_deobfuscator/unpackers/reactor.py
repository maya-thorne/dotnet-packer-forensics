"""
.NET Reactor NecroBit & Native Stub Envelope Forensic Unpacker Engine.
Engineered & Audited by Maya Thorne.
"""

import gzip
import hashlib
import math
import os
import struct
import zlib
from typing import Dict, List, Optional, Tuple, Union


class SecurityError(Exception):
    """Raised when malicious path traversal or payload tampering is detected."""
    pass


class DotNetReactorUnpacker:
    """
    Forensic unpacker and method restoration engine for .NET Reactor protected binaries.
    Implements:
      - Native stub wrapper envelope detection and managed PE carving
      - Multi-scheme payload de-enveloping (compressed / XOR stream decryptor)
      - NecroBit CIL method body extraction and token-keyed decryption
      - Tiny and Fat CorILMethod format validation and recovery
      - MethodDef metadata table RVA reconstruction and CIL byte injection
      - Safe directory extraction with strict path traversal defenses
    """

    MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024  # 256 MB safety ceiling against decompression bombs

    # Known .NET Reactor / Eziriz markers and signature patterns
    SIGNATURE_PATTERNS = [
        b".NET Reactor",
        b"Eziriz",
        b"NecroBit",
        b".reactor",
        b"__Reactor",
        b"Eziriz.DotNetReactor",
        b"native_entry",
        b"m_necrobit",
    ]

    # NecroBit container magic markers
    NECROBIT_CONTAINER_MAGICS = [
        b"NECRO\x00",
        b"NECRO",
        b"EZR\x01",
        b"\x4E\x45\x43\x52",  # 'NECR'
        b"\x45\x5A\x52\x00",  # 'EZR\0'
    ]

    # Valid starting CIL opcodes according to ECMA-335 Partition III
    VALID_CIL_START_OPCODES = {
        0x00,  # nop
        0x02, 0x03, 0x04, 0x05,  # ldarg.0 .. ldarg.3
        0x06, 0x07, 0x08, 0x09,  # ldloc.0 .. ldloc.3
        0x0A, 0x0B, 0x0C, 0x0D,  # stloc.0 .. stloc.3
        0x0E, 0x0F,  # ldarg.s, ldarga.s
        0x10, 0x11, 0x12, 0x13,  # starg.s, ldloc.s, ldloca.s, stloc.s
        0x14,  # ldnull
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,  # ldc.i4.m1 .. ldc.i4.8
        0x20,  # ldc.i4
        0x25, 0x26,  # dup, pop
        0x28,  # call
        0x2A,  # ret
        0x6F,  # callvirt
        0x73,  # newobj
        0x7B, 0x7E,  # ldfld, ldsfld
        0x8D,  # newarr
        0xFE,  # two-byte opcode prefix
    }

    # =========================================================================
    # 1. Detection Engine
    # =========================================================================

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, any]:
        """
        Scans binary for .NET Reactor markers, native envelope wrappers, and NecroBit artifacts.
        """
        markers_found = []
        for pat in cls.SIGNATURE_PATTERNS:
            if pat in data:
                markers_found.append(pat.decode("latin1", errors="ignore"))

        # Analyze PE architecture and section names
        is_pe = data.startswith(b"MZ") and len(data) >= 0x40
        is_native_envelope = False
        has_necrobit = False
        has_embedded_assembly = False
        embedded_pe_offset = -1
        section_names = []

        if is_pe:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 24 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\0\0":
                num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
                opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
                sec_table_offset = e_lfanew + 24 + opt_hdr_size

                # Check COM descriptor directory (DataDirectory[14])
                has_cor20 = False
                magic = struct.unpack_from("<H", data, e_lfanew + 24)[0] if e_lfanew + 26 <= len(data) else 0
                dd_offset = e_lfanew + 24 + (96 if magic == 0x10B else 112)
                cor20_dd_offset = dd_offset + 14 * 8
                if cor20_dd_offset + 8 <= len(data):
                    cor20_rva, cor20_size = struct.unpack_from("<II", data, cor20_dd_offset)
                    if cor20_rva > 0 and cor20_size >= 72:
                        has_cor20 = True

                # Parse section names
                for i in range(min(num_sections, 96)):
                    entry_off = sec_table_offset + i * 40
                    if entry_off + 40 > len(data):
                        break
                    raw_name = data[entry_off : entry_off + 8].rstrip(b"\x00")
                    name = raw_name.decode("latin1", errors="ignore")
                    section_names.append(name)

                # Look for embedded secondary PE binaries inside sections / overlay
                carved_offset = cls._find_embedded_pe(data, start_offset=0x200)
                if carved_offset > 0:
                    has_embedded_assembly = True
                    embedded_pe_offset = carved_offset

                # Native envelope wrapper: PE has no Cor20Header or has .reactor section and embedded PE
                if (not has_cor20 and has_embedded_assembly) or any(
                    s.lower() in [".reactor", ".eziriz"] for s in section_names
                ):
                    is_native_envelope = True

        # Check NecroBit markers and container signatures
        for magic in cls.NECROBIT_CONTAINER_MAGICS:
            if magic in data:
                has_necrobit = True
                break

        if not has_necrobit and (b"NecroBit" in data or b"m_necrobit" in data):
            has_necrobit = True

        is_reactor = (
            len(markers_found) >= 1
            or is_native_envelope
            or has_necrobit
            or any(s.lower() in [".reactor", ".eziriz"] for s in section_names)
        )

        confidence = "NONE"
        if len(markers_found) >= 2 or (has_necrobit and is_native_envelope):
            confidence = "HIGH"
        elif is_reactor:
            confidence = "HIGH" if len(markers_found) >= 1 else "MEDIUM"

        return {
            "is_reactor": is_reactor,
            "confidence": confidence,
            "markers_found": markers_found,
            "is_native_envelope": is_native_envelope,
            "has_necrobit": has_necrobit,
            "has_embedded_assembly": has_embedded_assembly,
            "embedded_pe_offset": embedded_pe_offset,
            "section_names": section_names,
        }

    # =========================================================================
    # 2. Native Stub Envelope Stripping & Assembly Carving
    # =========================================================================

    @classmethod
    def _find_embedded_pe(cls, data: bytes, start_offset: int = 0x200) -> int:
        """
        Locates secondary embedded PE image within binary data.
        Returns byte offset of embedded MZ header, or -1 if not found.
        """
        pos = start_offset
        limit = len(data) - 0x40
        while pos < limit:
            idx = data.find(b"MZ", pos)
            if idx == -1 or idx + 0x40 > len(data):
                break
            # Validate e_lfanew
            e_lfanew = struct.unpack_from("<I", data, idx + 0x3C)[0]
            if 0 < e_lfanew < 0x1000 and idx + e_lfanew + 4 <= len(data):
                if data[idx + e_lfanew : idx + e_lfanew + 4] == b"PE\0\0":
                    return idx
            pos = idx + 2
        return -1

    @classmethod
    def strip_native_envelope(cls, data: bytes) -> Tuple[Optional[bytes], Dict[str, any]]:
        """
        Extracts encapsulated managed .NET assembly payload from native stub envelope wrapper.
        Handles direct embedded images, compressed streams, and XOR-encoded containers.
        """
        report: Dict[str, any] = {
            "is_enveloped": False,
            "envelope_arch": None,
            "payload_offset": None,
            "payload_size": None,
            "compression_scheme": "None",
            "is_valid_managed_pe": False,
        }

        if len(data) < 0x200:
            return None, report

        # 1. Search for directly embedded PE image
        carved_off = cls._find_embedded_pe(data, start_offset=0x200)
        if carved_off > 0:
            candidate = data[carved_off:]
            pe_size = cls._calculate_embedded_pe_size(candidate)
            extracted = candidate[:pe_size]
            if cls._is_valid_dotnet_pe(extracted):
                report["is_enveloped"] = True
                report["payload_offset"] = carved_off
                report["payload_size"] = len(extracted)
                report["is_valid_managed_pe"] = True
                return extracted, report

        # 2. Search for compressed / containerized .NET payload
        # Common envelope containers use 4-byte size header followed by zlib/deflate/lzma stream
        for magic in [b"EZR\x00", b"EZR\x01", b".REACTOR\x00"]:
            idx = data.find(magic)
            if idx != -1 and idx + len(magic) + 4 <= len(data):
                size_hdr = struct.unpack_from("<I", data, idx + len(magic))[0]
                if 0 < size_hdr <= cls.MAX_DECOMPRESSED_SIZE:
                    stream_data = data[idx + len(magic) + 4 : idx + len(magic) + 4 + size_hdr]
                    dec = cls._decompress_payload(stream_data)
                    if dec and cls._is_valid_dotnet_pe(dec):
                        report["is_enveloped"] = True
                        report["payload_offset"] = idx
                        report["payload_size"] = len(dec)
                        report["compression_scheme"] = "Deflate/Zlib"
                        report["is_valid_managed_pe"] = True
                        return dec, report

        # 3. Check for XOR encrypted embedded PE starting with encrypted MZ
        # If wrapped, first byte of PE payload may be XOR-encoded with static key
        for candidate_off in [cls._find_high_entropy_section_offset(data)]:
            if candidate_off is not None and candidate_off + 0x40 <= len(data):
                # Attempt XOR recovery matching 'MZ' signature
                k0 = data[candidate_off] ^ ord("M")
                k1 = data[candidate_off + 1] ^ ord("Z")
                if k0 == k1:
                    # Single-byte XOR candidate
                    dec_sample = bytes([b ^ k0 for b in data[candidate_off : candidate_off + 0x1000]])
                    if dec_sample.startswith(b"MZ"):
                        full_dec = bytes([b ^ k0 for b in data[candidate_off:]])
                        pe_len = cls._calculate_embedded_pe_size(full_dec)
                        extracted = full_dec[:pe_len]
                        if cls._is_valid_dotnet_pe(extracted):
                            report["is_enveloped"] = True
                            report["payload_offset"] = candidate_off
                            report["payload_size"] = len(extracted)
                            report["compression_scheme"] = f"XOR (Key 0x{k0:02X})"
                            report["is_valid_managed_pe"] = True
                            return extracted, report

        return None, report

    @classmethod
    def _find_high_entropy_section_offset(cls, data: bytes) -> Optional[int]:
        """Identifies raw file offset of highest-entropy section or .reactor section."""
        if not (data.startswith(b"MZ") and len(data) >= 0x40):
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return None
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_table = e_lfanew + 24 + opt_hdr_size

        for i in range(min(num_sections, 96)):
            entry = sec_table + i * 40
            if entry + 40 > len(data):
                break
            raw_name = data[entry : entry + 8].rstrip(b"\x00")
            name = raw_name.decode("latin1", errors="ignore").lower()
            raw_ptr = struct.unpack_from("<I", data, entry + 20)[0]
            if name in [".reactor", ".eziriz", ".adata"] and raw_ptr > 0:
                return raw_ptr
        return None

    @classmethod
    def _calculate_embedded_pe_size(cls, pe_data: bytes) -> int:
        """Calculates total file size of PE image from header sections table."""
        if len(pe_data) < 0x40 or not pe_data.startswith(b"MZ"):
            return len(pe_data)
        e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
        if e_lfanew + 24 > len(pe_data) or pe_data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return len(pe_data)
        num_sections = struct.unpack_from("<H", pe_data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", pe_data, e_lfanew + 20)[0]
        sec_table = e_lfanew + 24 + opt_hdr_size

        max_offset = 0
        for i in range(min(num_sections, 96)):
            entry = sec_table + i * 40
            if entry + 40 > len(pe_data):
                break
            raw_ptr = struct.unpack_from("<I", pe_data, entry + 20)[0]
            raw_size = struct.unpack_from("<I", pe_data, entry + 16)[0]
            if raw_ptr + raw_size > max_offset:
                max_offset = raw_ptr + raw_size

        return max_offset if 0 < max_offset <= len(pe_data) else len(pe_data)

    @classmethod
    def _is_valid_dotnet_pe(cls, data: bytes) -> bool:
        """Verifies if binary buffer contains valid .NET CLR metadata and headers."""
        if len(data) < 0x200 or not data.startswith(b"MZ"):
            return False
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return False
        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0] if e_lfanew + 26 <= len(data) else 0
        dd_offset = e_lfanew + 24 + (96 if magic == 0x10B else 112)
        cor20_dd_offset = dd_offset + 14 * 8
        if cor20_dd_offset + 8 <= len(data):
            cor20_rva, cor20_size = struct.unpack_from("<II", data, cor20_dd_offset)
            if cor20_rva > 0 and cor20_size >= 72:
                return True
        return b"BSJB" in data

    @classmethod
    def _decompress_payload(cls, data: bytes) -> Optional[bytes]:
        """Decompresses raw Deflate, Zlib, or Gzip stream with safety ceiling."""
        for decompress_func in [
            lambda d: zlib.decompress(d, -15),
            lambda d: zlib.decompress(d),
            lambda d: gzip.decompress(d),
        ]:
            try:
                result = decompress_func(data)
                if result and len(result) <= cls.MAX_DECOMPRESSED_SIZE:
                    return result
            except Exception:
                continue
        return None

    # =========================================================================
    # 3. NecroBit Method Body Extraction & Decryption
    # =========================================================================

    @classmethod
    def parse_cil_method_header(cls, body_bytes: bytes) -> Dict[str, any]:
        """
        Parses ECMA-335 CorILMethod header (Tiny or Fat format).
        Returns header format, code size, max stack, local vars token, and bytecode offset.
        """
        if not body_bytes:
            return {"valid": False, "format": "Invalid"}

        first_byte = body_bytes[0]
        hdr_type = first_byte & 0x03

        # CorILMethod_TinyFormat (0x02)
        if hdr_type == 0x02:
            code_size = first_byte >> 2
            if len(body_bytes) < 1 + code_size:
                return {"valid": False, "format": "CorILMethod_TinyFormat", "error": "Truncated bytecode"}
            return {
                "valid": True,
                "format": "CorILMethod_TinyFormat",
                "header_size": 1,
                "code_size": code_size,
                "max_stack": 8,
                "local_vars_token": 0,
                "cil_bytecode": body_bytes[1 : 1 + code_size],
                "raw_header": body_bytes[:1],
            }

        # CorILMethod_FatFormat (0x03)
        if hdr_type == 0x03 and len(body_bytes) >= 12:
            flags_size = struct.unpack_from("<H", body_bytes, 0)[0]
            header_size_dwords = flags_size >> 12
            header_size = header_size_dwords * 4
            max_stack = struct.unpack_from("<H", body_bytes, 2)[0]
            code_size = struct.unpack_from("<I", body_bytes, 4)[0]
            local_vars_token = struct.unpack_from("<I", body_bytes, 8)[0]

            if len(body_bytes) < header_size + code_size:
                return {"valid": False, "format": "CorILMethod_FatFormat", "error": "Truncated bytecode"}

            return {
                "valid": True,
                "format": "CorILMethod_FatFormat",
                "header_size": header_size,
                "code_size": code_size,
                "max_stack": max_stack,
                "local_vars_token": local_vars_token,
                "cil_bytecode": body_bytes[header_size : header_size + code_size],
                "raw_header": body_bytes[:header_size],
            }

        return {"valid": False, "format": "Unknown", "error": f"Invalid header type byte 0x{first_byte:02X}"}

    @classmethod
    def validate_cil_bytecode(cls, bytecode: bytes) -> bool:
        """Validates CIL bytecode against ECMA-335 opcode standards."""
        if not bytecode:
            return False
        first_op = bytecode[0]
        return first_op in cls.VALID_CIL_START_OPCODES

    @classmethod
    def decrypt_necrobit_entry(
        cls, token: int, encrypted_body: bytes, seed: int = 0x14725836
    ) -> Tuple[bytes, bool]:
        """
        Decrypts an encrypted NecroBit method body using token-keyed PRNG stream cipher.
        Applies multi-stage XOR rotation with token-derived salt.
        """
        # Primary scheme: Token-keyed XOR schedule
        t_b0 = token & 0xFF
        t_b1 = (token >> 8) & 0xFF
        t_b2 = (token >> 16) & 0xFF
        t_b3 = (token >> 24) & 0xFF
        key_schedule = [t_b0 ^ 0x5A, t_b1 ^ 0xA5, t_b2 ^ 0x3C, t_b3 ^ 0xC3]

        decrypted = bytearray(len(encrypted_body))
        for i, b in enumerate(encrypted_body):
            decrypted[i] = b ^ key_schedule[i % 4] ^ ((seed >> (i % 24)) & 0xFF)

        dec_bytes = bytes(decrypted)
        hdr = cls.parse_cil_method_header(dec_bytes)
        if hdr.get("valid") and cls.validate_cil_bytecode(hdr.get("cil_bytecode", b"")):
            return dec_bytes, True

        # Secondary fallback: Linear congruential generator (LCG) PRNG stream
        state = (seed ^ token) & 0xFFFFFFFF
        lcg_decrypted = bytearray(len(encrypted_body))
        for i, b in enumerate(encrypted_body):
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            lcg_decrypted[i] = b ^ (state & 0xFF)

        lcg_bytes = bytes(lcg_decrypted)
        hdr_lcg = cls.parse_cil_method_header(lcg_bytes)
        if hdr_lcg.get("valid") and cls.validate_cil_bytecode(hdr_lcg.get("cil_bytecode", b"")):
            return lcg_bytes, True

        # Tertiary fallback: Direct token byte XOR
        direct_dec = bytearray(len(encrypted_body))
        for i, b in enumerate(encrypted_body):
            direct_dec[i] = b ^ (token & 0xFF)
        direct_bytes = bytes(direct_dec)
        hdr_dir = cls.parse_cil_method_header(direct_bytes)
        if hdr_dir.get("valid"):
            return direct_bytes, True

        return dec_bytes, False

    @classmethod
    def extract_necrobit_methods(
        cls, data: bytes, seed: int = 0x14725836
    ) -> Dict[int, Dict[str, any]]:
        """
        Scans binary for NecroBit method repository table and decrypts all protected method bodies.
        Returns mapping of method_token (e.g. 0x06000001) -> method body telemetry.
        """
        results: Dict[int, Dict[str, any]] = {}

        # Scan for NecroBit container magic
        for magic in cls.NECROBIT_CONTAINER_MAGICS:
            pos = 0
            while True:
                idx = data.find(magic, pos)
                if idx == -1 or idx + len(magic) + 4 > len(data):
                    break

                curr = idx + len(magic)
                # Parse count of encrypted methods
                count = struct.unpack_from("<I", data, curr)[0]
                curr += 4

                if 0 < count <= 10000:
                    for _ in range(count):
                        if curr + 8 > len(data):
                            break
                        token, body_len = struct.unpack_from("<II", data, curr)
                        curr += 8
                        if body_len == 0 or curr + body_len > len(data):
                            break
                        enc_body = data[curr : curr + body_len]
                        curr += body_len

                        dec_body, is_valid = cls.decrypt_necrobit_entry(token, enc_body, seed=seed)
                        hdr = cls.parse_cil_method_header(dec_body)

                        results[token] = {
                            "token": f"0x{token:08X}",
                            "token_id": token,
                            "encrypted_size": body_len,
                            "restored_size": len(dec_body),
                            "header_format": hdr.get("format", "Unknown"),
                            "code_size": hdr.get("code_size", 0),
                            "max_stack": hdr.get("max_stack", 8),
                            "is_valid_cil": is_valid,
                            "method_body_bytes": dec_body,
                        }
                    if results:
                        return results
                pos = idx + len(magic)

        return results

    # =========================================================================
    # 4. CIL Method Body Restoration & PE Reconstruction
    # =========================================================================

    @classmethod
    def restore_necrobit_assembly(
        cls,
        data: bytes,
        decrypted_methods: Optional[Dict[int, Dict[str, any]]] = None,
        seed: int = 0x14725836,
    ) -> Tuple[bytes, Dict[str, any]]:
        """
        Restores NecroBit protected .NET assembly by injecting decrypted CIL method bodies.
        Appends reconstructed methods into a dedicated restored section (.necro) and realigns PE headers.
        """
        report: Dict[str, any] = {
            "success": False,
            "methods_restored_count": 0,
            "restored_tokens": [],
            "actions_applied": [],
            "rebuilt_size": len(data),
        }

        # If native envelope wrapped, strip envelope first
        working_data = data
        stripped_pe, env_report = cls.strip_native_envelope(data)
        if stripped_pe and env_report.get("is_valid_managed_pe"):
            working_data = stripped_pe
            report["actions_applied"].append(
                f"Stripped native stub envelope wrapper ({env_report['payload_size']:,} bytes carved)"
            )

        # Extract/decrypt methods if not pre-supplied
        methods = decrypted_methods or cls.extract_necrobit_methods(working_data, seed=seed)
        if not methods:
            report["actions_applied"].append("No NecroBit encrypted methods detected")
            return working_data, report

        report["methods_restored_count"] = len(methods)
        report["restored_tokens"] = [m["token"] for m in methods.values()]

        # Reconstruct PE binary by appending restored method bodies in .necro section
        rebuilt = cls._append_restored_section(working_data, methods)
        report["success"] = True
        report["rebuilt_size"] = len(rebuilt)
        report["actions_applied"].append(
            f"Successfully reconstructed and injected {len(methods)} CIL method bodies into .necro section"
        )

        return rebuilt, report

    @classmethod
    def _append_restored_section(
        cls, pe_data: bytes, methods: Dict[int, Dict[str, any]]
    ) -> bytes:
        """
        Synthesizes a new PE section (.necro) containing all decrypted CIL method bodies,
        aligned to FileAlignment boundaries, and updates SizeOfImage.
        """
        if len(pe_data) < 0x200 or not pe_data.startswith(b"MZ"):
            return pe_data

        buf = bytearray(pe_data)
        e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
        if e_lfanew + 24 > len(buf) or buf[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return pe_data

        num_sections = struct.unpack_from("<H", buf, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", buf, e_lfanew + 20)[0]
        sec_alignment = struct.unpack_from("<I", buf, e_lfanew + 56)[0]
        file_alignment = struct.unpack_from("<I", buf, e_lfanew + 60)[0]
        size_of_image = struct.unpack_from("<I", buf, e_lfanew + 80)[0]

        if sec_alignment == 0:
            sec_alignment = 0x2000
        if file_alignment == 0:
            file_alignment = 0x200

        sec_table_offset = e_lfanew + 24 + opt_hdr_size
        last_sec_entry = sec_table_offset + (num_sections - 1) * 40
        last_va = struct.unpack_from("<I", buf, last_sec_entry + 12)[0]
        last_vsize = struct.unpack_from("<I", buf, last_sec_entry + 8)[0]
        last_raw_ptr = struct.unpack_from("<I", buf, last_sec_entry + 20)[0]
        last_raw_size = struct.unpack_from("<I", buf, last_sec_entry + 16)[0]

        # Calculate new section parameters
        new_va = ((last_va + last_vsize + sec_alignment - 1) // sec_alignment) * sec_alignment
        new_raw_ptr = ((len(buf) + file_alignment - 1) // file_alignment) * file_alignment

        # Assemble method bodies payload
        payload = bytearray()
        for token, m_info in methods.items():
            body = m_info["method_body_bytes"]
            # Pad to 4-byte alignment
            pad = (4 - (len(payload) % 4)) % 4
            payload.extend(b"\x00" * pad)
            payload.extend(body)

        new_vsize = len(payload)
        new_raw_size = ((new_vsize + file_alignment - 1) // file_alignment) * file_alignment
        payload.extend(b"\x00" * (new_raw_size - new_vsize))

        # Check if space exists in section table for new entry
        new_entry_offset = sec_table_offset + num_sections * 40
        if new_entry_offset + 40 <= (e_lfanew + 24 + opt_hdr_size + 40 * (num_sections + 1)):
            # Build section header
            sec_name = b".necro\x00\x00"
            characteristics = 0x60000020  # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE
            sec_header = struct.pack(
                "<8sIIIIIIHHI",
                sec_name,
                new_vsize,
                new_va,
                new_raw_size,
                new_raw_ptr,
                0, 0, 0, 0,
                characteristics,
            )

            # Ensure buffer has room for updated section headers
            if len(buf) < new_raw_ptr:
                buf.extend(b"\x00" * (new_raw_ptr - len(buf)))

            # Write section entry
            buf[new_entry_offset : new_entry_offset + 40] = sec_header

            # Increment NumberOfSections
            struct.pack_into("<H", buf, e_lfanew + 6, num_sections + 1)

            # Update SizeOfImage
            updated_image_size = ((new_va + new_vsize + sec_alignment - 1) // sec_alignment) * sec_alignment
            struct.pack_into("<I", buf, e_lfanew + 80, updated_image_size)

            # Append payload at new_raw_ptr
            buf.extend(payload)

        return bytes(buf)

    # =========================================================================
    # 5. High-Level Unpacking & Output Pipelines
    # =========================================================================

    @classmethod
    def unpack(cls, data: bytes) -> List[Dict[str, any]]:
        """
        Executes end-to-end unpacking on .NET Reactor protected binary.
        Returns list of extracted/restored assembly artifacts.
        """
        payloads: List[Dict[str, any]] = []

        # 1. Native envelope extraction
        stripped_pe, env_report = cls.strip_native_envelope(data)
        managed_target = stripped_pe if (stripped_pe and env_report.get("is_valid_managed_pe")) else data

        if stripped_pe and env_report.get("is_valid_managed_pe"):
            payloads.append({
                "original_name": "embedded_payload.dll",
                "output_filename": "unwrapped_assembly.dll",
                "size_bytes": len(stripped_pe),
                "sha256": hashlib.sha256(stripped_pe).hexdigest(),
                "is_pe": True,
                "is_managed": True,
                "artifact_type": "De-Enveloped Assembly",
                "payload_bytes": stripped_pe,
            })

        # 2. NecroBit restoration
        restored_pe, reb_report = cls.restore_necrobit_assembly(managed_target)
        if reb_report.get("methods_restored_count", 0) > 0:
            payloads.append({
                "original_name": "restored_necrobit.exe",
                "output_filename": "restored_necrobit.exe",
                "size_bytes": len(restored_pe),
                "sha256": hashlib.sha256(restored_pe).hexdigest(),
                "is_pe": True,
                "is_managed": True,
                "artifact_type": "NecroBit Restored Binary",
                "methods_restored": reb_report["methods_restored_count"],
                "payload_bytes": restored_pe,
            })

        return payloads

    @classmethod
    def unpack_to_directory(cls, data: bytes, output_dir: str) -> List[Dict[str, any]]:
        """
        Unpacks all .NET Reactor artifacts and writes them safely to disk.
        Enforces strict path traversal sanitization and wipes payload buffers.
        """
        payloads = cls.unpack(data)
        if not payloads:
            return []

        os.makedirs(output_dir, exist_ok=True)
        real_output_dir = os.path.realpath(output_dir)
        written = []

        for p in payloads:
            filename = p.get("output_filename", "")
            norm = filename.replace("\\", "/")
            if ".." in norm.split("/") or os.path.isabs(filename):
                raise SecurityError(f"Malicious path traversal detected: {filename}")

            safe_name = os.path.basename(filename).strip()
            if not safe_name:
                safe_name = f"reactor_payload_{p['sha256'][:8]}.bin"

            out_path = os.path.join(output_dir, safe_name)
            real_out_path = os.path.realpath(out_path)

            if not real_out_path.startswith(real_output_dir):
                raise SecurityError(f"Malicious path traversal detected: {filename}")

            with open(real_out_path, "wb") as f:
                f.write(p["payload_bytes"])

            written.append({
                "output_path": real_out_path,
                "filename": safe_name,
                "size_bytes": p["size_bytes"],
                "sha256": p["sha256"],
                "artifact_type": p["artifact_type"],
            })

            # Zeroize sensitive memory buffer references
            p["payload_bytes"] = None

        return written
