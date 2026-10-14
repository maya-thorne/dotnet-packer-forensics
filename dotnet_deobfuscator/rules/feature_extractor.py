"""
Threat Feature Extractor for .NET & PE Binaries.
Engineered & Audited by Maya Thorne.
"""

import ctypes
import hashlib
import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from ..dotnet_analyzer import DotNetAnalyzer
from ..pe_overlay import PEOverlayParser
from ..pe_rebuilder import PERebuilder
from ..signatures import ProtectorSignatures
from .models import ExtractedThreatFeatures, SecurityError


def zeroize_buffer(buf: bytearray) -> None:
    """Cryptographically zeroes out an in-memory mutable byte buffer."""
    if not isinstance(buf, (bytearray, memoryview)):
        return
    length = len(buf)
    if length == 0:
        return
    c_arr = (ctypes.c_char * length).from_buffer(buf)
    ctypes.memset(c_arr, 0, length)


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy for given byte sequence (0.00 to 8.00)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / total
        ent -= p * math.log2(p)
    return ent


class ThreatFeatureExtractor:
    """Extracts low-level structural, cryptographic, and behavioral markers for rule generation."""

    @classmethod
    def extract_from_file(cls, file_path: str) -> ExtractedThreatFeatures:
        """Extracts features directly from a binary file on disk."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        file_size = os.path.getsize(file_path)
        if file_size > 200 * 1024 * 1024:
            raise SecurityError(f"Target binary exceeds 200MB limit: {file_size} bytes")

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.extract_from_bytes(data, file_name=os.path.basename(file_path))

    @classmethod
    def extract_from_bytes(cls, data: bytes, file_name: str = "binary.exe") -> ExtractedThreatFeatures:
        """Extracts comprehensive threat features from a raw byte buffer."""
        # 1. Cryptographic hashes
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()

        # 2. Basic PE Structure & Imphash
        is_pe, machine_code, subsystem_code, section_hdrs, imphash, anomalies = cls._parse_pe_headers(data)

        machine_map = {
            0x014C: "IMAGE_FILE_MACHINE_I386 (x86)",
            0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64)",
            0xAA64: "IMAGE_FILE_MACHINE_ARM64 (ARM64)",
            0x01C0: "IMAGE_FILE_MACHINE_ARMNT (ARM)",
        }
        machine_type = machine_map.get(machine_code, f"UNKNOWN (0x{machine_code:04X})")

        subsystem_map = {
            2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
        }
        subsystem = subsystem_map.get(subsystem_code, f"UNKNOWN ({subsystem_code})")

        # 3. Section Entropies & Names
        section_names: List[str] = []
        section_entropies: List[Tuple[str, float]] = []
        high_entropy_sections: List[Tuple[str, float]] = []

        for s_name, raw_ptr, raw_sz in section_hdrs:
            section_names.append(s_name)
            if raw_ptr < len(data) and raw_sz > 0:
                chunk = data[raw_ptr : raw_ptr + raw_sz]
                ent = calculate_entropy(chunk)
                section_entropies.append((s_name, round(ent, 4)))
                if ent >= 7.0 and s_name.lower() not in [".rsrc"]:
                    high_entropy_sections.append((s_name, round(ent, 4)))
            else:
                section_entropies.append((s_name, 0.0))

        # 4. .NET Cor20 & Metadata Inspection
        assembly_info = DotNetAnalyzer.inspect_assembly(data)
        is_dotnet = assembly_info.get("is_dotnet", False)
        metadata_streams = assembly_info.get("metadata_streams", [])
        suspicious_indicators = assembly_info.get("suspicious_indicators", [])

        cor20_entry_point = None
        cor20_header = assembly_info.get("cor20_header")
        if cor20_header and isinstance(cor20_header, dict):
            cor20_entry_point = cor20_header.get("entry_point_token")

        # 5. Overlay & xorPacker
        pe_size = PEOverlayParser.calculate_pe_size(data) or len(data)
        overlay_bytes = PEOverlayParser.extract_overlay(data)
        has_overlay = len(overlay_bytes) > 0
        overlay_size = len(overlay_bytes)
        overlay_entropy = calculate_entropy(overlay_bytes) if has_overlay else 0.0

        has_xor_packer = False
        xor_key = None
        if has_overlay:
            xor_res = PEOverlayParser.decrypt_xor_packer(data)
            if xor_res:
                has_xor_packer = True
                xor_key = xor_res.get("dynamic_key_recovered")

        # 6. Protector Signatures
        detected_protectors = ProtectorSignatures.identify(data)

        # 7. Bytecode patterns and characteristic string markers
        bytecode_patterns = cls._scan_bytecode_patterns(data)
        string_markers = cls._extract_distinct_markers(data, detected_protectors)

        # 8. Anti-dump and anti-tamper heuristics
        anti_dump_active = (
            b"AntiDump" in data
            or any(a in anomalies for a in ["Missing or corrupted DOS magic ('MZ')", "VirtualAddress mapped directly"])
            or ".antidump" in [s.lower() for s in section_names]
        )
        anti_tamper_active = (
            b"AntiTamper" in data
            or ".tamper" in [s.lower() for s in section_names]
            or (is_dotnet and ("#Strings" not in metadata_streams or "#US" not in metadata_streams))
        )

        # 9. Native architectures present
        native_architectures: List[str] = []
        if b"costura32" in data or b"x86" in data:
            native_architectures.append("x86")
        if b"costura64" in data or b"x64" in data:
            native_architectures.append("x64")
        if b"arm64" in data:
            native_architectures.append("arm64")

        return ExtractedThreatFeatures(
            file_name=file_name,
            file_size=len(data),
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            imphash=imphash,
            is_pe=is_pe,
            is_dotnet=is_dotnet,
            machine_type=machine_type,
            subsystem=subsystem,
            section_count=len(section_hdrs),
            section_names=section_names,
            section_entropies=section_entropies,
            high_entropy_sections=high_entropy_sections,
            suspicious_indicators=suspicious_indicators,
            detected_protectors=detected_protectors,
            has_overlay=has_overlay,
            overlay_size=overlay_size,
            overlay_entropy=overlay_entropy,
            has_xor_packer=has_xor_packer,
            xor_key=xor_key,
            cor20_entry_point=cor20_entry_point,
            metadata_streams=metadata_streams,
            bytecode_patterns=bytecode_patterns,
            string_markers=string_markers,
            native_architectures=native_architectures,
            anti_dump_active=anti_dump_active,
            anti_tamper_active=anti_tamper_active,
            anomalies=anomalies,
        )

    @classmethod
    def _parse_pe_headers(
        cls, data: bytes
    ) -> Tuple[bool, int, int, List[Tuple[str, int, int]], Optional[str], List[str]]:
        """Parses DOS/NT/Section headers, calculates imphash, and checks for structural anomalies."""
        anomalies: List[str] = []
        if len(data) < 64:
            return False, 0, 0, [], None, ["File size smaller than minimum DOS header"]

        if data[:2] != b"MZ":
            anomalies.append("Missing or corrupted DOS magic ('MZ')")

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0
        if e_lfanew + 24 > len(data):
            return False, 0, 0, [], None, anomalies + ["Corrupted or out-of-bounds e_lfanew pointer"]

        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return False, 0, 0, [], None, anomalies + ["Missing PE signature"]

        file_hdr_offset = e_lfanew + 4
        machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, file_hdr_offset
        )

        opt_hdr_offset = file_hdr_offset + 20
        magic = struct.unpack_from("<H", data, opt_hdr_offset)[0] if opt_hdr_size >= 2 else 0
        is_pe32_plus = (magic == 0x020B)

        subsystem = 0
        import_rva = 0
        import_size = 0

        if opt_hdr_size >= 70:
            subsystem_offset = opt_hdr_offset + 68
            if subsystem_offset + 2 <= len(data):
                subsystem = struct.unpack_from("<H", data, subsystem_offset)[0]

        # Data directory for Imports is Directory[1]
        data_dir_offset = opt_hdr_offset + (112 if is_pe32_plus else 96)
        if opt_hdr_size >= (112 if is_pe32_plus else 96) + 16:
            import_entry_offset = data_dir_offset + 8  # index 1 * 8 bytes
            if import_entry_offset + 8 <= len(data):
                import_rva, import_size = struct.unpack_from("<II", data, import_entry_offset)

        # Parse Section Headers
        sections_offset = opt_hdr_offset + opt_hdr_size
        section_hdrs: List[Tuple[str, int, int]] = []
        sec_rva_map: List[Tuple[int, int, int, int]] = []

        for i in range(num_sections):
            sec_offset = sections_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break
            raw_name = data[sec_offset : sec_offset + 8]
            sec_name = raw_name.split(b"\x00")[0].decode("latin1", errors="ignore")
            v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec_offset + 8)
            section_hdrs.append((sec_name, raw_ptr, raw_size))
            sec_rva_map.append((v_addr, v_size, raw_ptr, raw_size))

        # Compute Imphash
        imphash = cls._calculate_imphash(data, import_rva, import_size, sec_rva_map)

        return True, machine, subsystem, section_hdrs, imphash, anomalies

    @classmethod
    def _rva_to_offset(cls, rva: int, sec_rva_map: List[Tuple[int, int, int, int]]) -> Optional[int]:
        """Translates RVA to raw file offset."""
        for v_addr, v_size, raw_ptr, raw_size in sec_rva_map:
            span = max(v_size, raw_size)
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size:
                    return raw_ptr + delta
        return None

    @classmethod
    def _calculate_imphash(
        cls,
        data: bytes,
        import_rva: int,
        import_size: int,
        sec_rva_map: List[Tuple[int, int, int, int]],
    ) -> Optional[str]:
        """Calculates standard PE imphash (MD5 of sorted, lowercased DLL.API names)."""
        if import_rva == 0 or import_size == 0:
            return None

        import_offset = cls._rva_to_offset(import_rva, sec_rva_map)
        if not import_offset or import_offset + 20 > len(data):
            return None

        imports_list: List[str] = []
        curr_desc = import_offset

        while curr_desc + 20 <= len(data):
            orig_ft, time_stamp, forwarder, name_rva, ft = struct.unpack_from("<IIIII", data, curr_desc)
            if orig_ft == 0 and name_rva == 0 and ft == 0:
                break

            dll_name_offset = cls._rva_to_offset(name_rva, sec_rva_map)
            if dll_name_offset and dll_name_offset < len(data):
                end_idx = data.find(b"\x00", dll_name_offset)
                if end_idx != -1:
                    dll_raw = data[dll_name_offset:end_idx].decode("latin1", errors="ignore").lower()
                    dll_stem = dll_raw[:-4] if (dll_raw.endswith(".dll") or dll_raw.endswith(".sys")) else dll_raw

                    thunk_rva = orig_ft if orig_ft != 0 else ft
                    thunk_offset = cls._rva_to_offset(thunk_rva, sec_rva_map)
                    if thunk_offset:
                        curr_thunk = thunk_offset
                        while curr_thunk + 4 <= len(data):
                            val = struct.unpack_from("<I", data, curr_thunk)[0]
                            if val == 0:
                                break
                            if val & 0x80000000:
                                # Ordinal import
                                ord_num = val & 0xFFFF
                                imports_list.append(f"{dll_stem}.ord{ord_num}")
                            else:
                                func_offset = cls._rva_to_offset(val, sec_rva_map)
                                if func_offset and func_offset + 2 < len(data):
                                    f_end = data.find(b"\x00", func_offset + 2)
                                    if f_end != -1:
                                        func_name = data[func_offset + 2 : f_end].decode("latin1", errors="ignore").lower()
                                        imports_list.append(f"{dll_stem}.{func_name}")
                            curr_thunk += 4

            curr_desc += 20

        if not imports_list:
            return None

        raw_imphash_str = ",".join(imports_list)
        return hashlib.md5(raw_imphash_str.encode("utf-8")).hexdigest()

    @classmethod
    def _scan_bytecode_patterns(cls, data: bytes) -> List[Tuple[str, bytes, str]]:
        """Identifies signature bytecode sequences for common protectors and obfuscators."""
        patterns: List[Tuple[str, bytes, str]] = []

        # 1. NecroBit CorILMethod Tiny stub (72 [ldstr] ... 28 [call] ... 2A [ret])
        if b"\x72" in data and b"\x28" in data and b"\x2A" in data:
            necro_idx = data.find(b"\x28")
            if necro_idx != -1 and necro_idx + 5 <= len(data) and data[necro_idx + 5 : necro_idx + 6] == b"\x2A":
                patterns.append(("necrobit_call_ret", data[necro_idx : necro_idx + 6], "CIL method call and return stub"))

        # 2. ConfuserEx Anti-Tamper LCG seed loop (FE 01 [xor] ... 61 [mul] ... 62 [sub])
        if b"\xFE\x01" in data:
            patterns.append(("confuser_xor_stub", b"\xFE\x01", "CIL CEIL/XOR opcode pattern"))

        # 3. Standard XOR loop (00 ... 5A ... 73 ... 2A)
        if b"***" in data and b"randomkey" in data:
            patterns.append(("xorpacker_sentinel", b"***", "xorPacker overlay sentinel delimiter"))

        return patterns

    @classmethod
    def _extract_distinct_markers(cls, data: bytes, detected_protectors: List[Dict[str, Any]]) -> List[str]:
        """Extracts unique ASCII and Unicode string markers for rule string definitions."""
        markers: List[str] = []
        known_tokens = [
            "ConfuserEx",
            "ConfusedByAttribute",
            ".NET Reactor",
            "Eziriz",
            "NecroBit",
            "Eazfuscator.NET",
            "BabelObfuscator",
            "BabelAttribute",
            "ArmDot",
            "ArmDotAttribute",
            "DeepSeaObfuscator",
            "IntelliLock",
            "TrialAttribute",
            "costura.",
            "costura32.",
            "costura64.",
            "AntiTamper",
            "AntiDump",
            "randomkey",
            "mscoree.dll",
            "_CorExeMain",
            "_CorDllMain",
        ]

        for token in known_tokens:
            token_b = token.encode("latin1")
            token_w = token.encode("utf-16le")
            if token_b in data or token_w in data:
                markers.append(token)

        for p in detected_protectors:
            for t in p.get("matched_tokens", []):
                if t not in markers:
                    markers.append(t)

        return sorted(set(markers))
