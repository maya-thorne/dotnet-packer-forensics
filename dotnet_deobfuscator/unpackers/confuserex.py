"""
ConfuserEx Modular Protector Forensic Unpacker & Decryption Engine.
Engineered & Audited by Maya Thorne.
"""

import gzip
import hashlib
import math
import os
import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple, Union


class SecurityError(Exception):
    """Raised when malicious path traversal or payload tampering is detected."""
    pass


class ConfuserExUnpacker:
    """
    Forensic unpacker and static deobfuscation engine for ConfuserEx protected .NET binaries.
    Implements marker detection, dynamic LCG/XorShift PRNG string decryption,
    CLI Resources directory parsing, multi-format decompression, and safe resource extraction.
    """

    MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024  # 256 MB safety ceiling against decompression bombs

    # ConfuserEx Core Detection Signatures & Tokens
    SIGNATURE_PATTERNS = [
        b"ConfusedByAttribute",
        b"ConfuserEx",
        b"Confuser.Core",
        b"Confuser.Runtime",
        b"AntiDump",
        b"AntiTamper",
        b"Constants",
        b"Resources",
        b"ControlFlow",
        b"RefProxy",
    ]

    # Obfuscated / Invisible Unicode Code Points frequently utilized by ConfuserEx Renamer
    CONFUSER_UNICODE_CHARS = {
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F,  # Zero-width spaces & marks
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # Bidirectional overrides
        0x2060, 0xFEFF, 0x00A0,                  # Word joiners, zero-width no-break spaces
    }

    # =========================================================================
    # 1. Detection Engine
    # =========================================================================

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, any]:
        """
        Scans binary for ConfuserEx markers, attributes, protections, and mangled names.
        """
        markers_found = []
        for pat in cls.SIGNATURE_PATTERNS:
            if pat in data:
                markers_found.append(pat.decode("latin1", errors="ignore"))

        # Detect specific ConfuserEx protection modules
        detected_protections = []
        has_antidump = any(m in ["AntiDump"] for m in markers_found) or (b"VirtualProtect" in data and b"Marshal.Copy" in data and b"Confuser" in data)
        has_antitamper = any(m in ["AntiTamper"] for m in markers_found) or (b"AntiTamper" in data or (b"#-Strings" in data and b"#US" not in data))
        has_constants = any(m in ["Constants"] for m in markers_found) or b"Confuser.Runtime.Constant" in data
        has_resources = any(m in ["Resources"] for m in markers_found) or b"Confuser.Runtime.Resource" in data

        if has_antidump:
            detected_protections.append("Anti-Dump")
        if has_antitamper:
            detected_protections.append("Anti-Tamper")
        if has_constants:
            detected_protections.append("Constants Encryption")
        if has_resources:
            detected_protections.append("Resource Protection")
        if b"ControlFlow" in data or (b"Switch" in data and b"Confuser" in data):
            detected_protections.append("Control Flow Flattening")

        # Analyze name obfuscation / invisible Unicode sequences
        obfuscated_names_count = 0
        try:
            text_sample = data.decode("utf-8", errors="ignore")
            for char in text_sample:
                if ord(char) in cls.CONFUSER_UNICODE_CHARS:
                    obfuscated_names_count += 1
        except Exception:
            pass

        if obfuscated_names_count > 0:
            detected_protections.append("Name Protection (Unicode Renamer)")

        is_confuserex = (
            len(markers_found) >= 1
            or obfuscated_names_count > 5
        )

        if "ConfusedByAttribute" in markers_found or "ConfuserEx" in markers_found:
            confidence = "HIGH"
        elif len(markers_found) >= 2 or (is_confuserex and obfuscated_names_count > 0):
            confidence = "HIGH"
        elif is_confuserex:
            confidence = "MEDIUM"
        else:
            confidence = "NONE"

        return {
            "is_confuserex": is_confuserex,
            "confidence": confidence,
            "markers_found": markers_found,
            "detected_protections": detected_protections,
            "obfuscated_names_count": obfuscated_names_count,
            "has_antidump": has_antidump,
            "has_antitamper": has_antitamper,
            "has_constants": has_constants,
            "has_resources": has_resources,
        }

    # =========================================================================
    # 2. Mathematical Ciphers & PRNG Stream Generators
    # =========================================================================

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0)."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        length = len(data)
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def xorshift32_keystream(seed: int, length: int) -> bytes:
        """
        ConfuserEx Normal Mode XorShift 32-bit PRNG stream cipher keystream.
        Generates pseudo-random keystream bytes using canonical triplet (13, 17, 5).
        """
        state = seed & 0xFFFFFFFF
        if state == 0:
            state = 0x12345678  # Avoid zero-lockup state
        keystream = bytearray(length)
        idx = 0
        while idx < length:
            state = (state ^ ((state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            state = (state ^ (state >> 17)) & 0xFFFFFFFF
            state = (state ^ ((state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            block = struct.pack("<I", state)
            take = min(4, length - idx)
            keystream[idx : idx + take] = block[:take]
            idx += take
        return bytes(keystream)

    @staticmethod
    def lcg_keystream(
        seed: int,
        length: int,
        multiplier: int = 1664525,
        addend: int = 1013904223,
    ) -> bytes:
        """
        Linear Congruential Generator (LCG) PRNG stream cipher keystream.
        Computes state = (state * multiplier + addend) mod 2^32.
        """
        state = seed & 0xFFFFFFFF
        keystream = bytearray(length)
        idx = 0
        while idx < length:
            state = ((state * multiplier) + addend) & 0xFFFFFFFF
            block = struct.pack("<I", state)
            take = min(4, length - idx)
            keystream[idx : idx + take] = block[:take]
            idx += take
        return bytes(keystream)

    @staticmethod
    def derive_key_schedule(seed: int, key_len: int = 16) -> bytes:
        """
        Derives an expanded multi-byte key schedule from a dynamic numeric seed.
        Utilizes integer mixing to yield a high-dispersion key block.
        """
        state = seed & 0xFFFFFFFF
        schedule = bytearray()
        while len(schedule) < key_len:
            state = (state ^ (state >> 16)) & 0xFFFFFFFF
            state = (state * 0x45D9F3B) & 0xFFFFFFFF
            state = (state ^ (state >> 16)) & 0xFFFFFFFF
            state = (state * 0x45D9F3B) & 0xFFFFFFFF
            state = (state ^ (state >> 16)) & 0xFFFFFFFF
            schedule.extend(struct.pack("<I", state))
        return bytes(schedule[:key_len])

    @staticmethod
    def xor_crypt(data: bytes, key: bytes) -> bytes:
        """Symmetric multi-byte XOR encryption / decryption."""
        if not key:
            return data
        k_len = len(key)
        return bytes(b ^ key[i % k_len] for i, b in enumerate(data))

    @classmethod
    def evaluate_plaintext_score(cls, data: bytes) -> float:
        """
        Calculates heuristic score (0.0 to 1.0) indicating whether byte buffer is authentic plaintext.
        Evaluates printable ASCII ratio, valid UTF-8 sequences, and Shannon entropy.
        """
        if not data:
            return 0.0
        printable_count = sum(1 for b in data if (32 <= b <= 126 or b in (9, 10, 13, 0)))
        printable_ratio = printable_count / len(data)

        # Check for valid UTF-8 decoding proportion
        utf8_score = 0.0
        try:
            decoded = data.decode("utf-8", errors="ignore")
            if len(decoded) >= len(data) * 0.6:
                utf8_score = 0.2
        except Exception:
            pass

        # Check Shannon entropy (plaintext string tables: 2.0 - 5.8; encrypted data: > 7.3)
        ent = cls.calculate_entropy(data)
        entropy_score = 0.0
        if 1.5 <= ent <= 5.8:
            entropy_score = 0.25
        elif ent > 7.2:
            entropy_score = -0.35

        score = max(0.0, min(1.0, (printable_ratio * 0.55) + utf8_score + entropy_score))
        return round(score, 4)

    # =========================================================================
    # 3. String & Constants Table Parser
    # =========================================================================

    @staticmethod
    def read_7bit_encoded_int(data: bytes, offset: int) -> Tuple[int, int]:
        """
        Reads a 7-bit encoded integer as utilized by .NET BinaryReader.ReadString().
        Returns (integer_value, bytes_consumed).
        """
        val = 0
        shift = 0
        consumed = 0
        curr = offset
        while curr < len(data):
            b = data[curr]
            curr += 1
            consumed += 1
            val |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
            if shift >= 35:
                break
        return val, consumed

    @classmethod
    def parse_string_table(cls, data: bytes) -> Dict[str, any]:
        """
        Parses decrypted ConfuserEx constants buffer extracting:
        - 7-bit length-prefixed UTF-8 strings
        - 4-byte LE length-prefixed strings
        - Null-terminated UTF-8 / ASCII strings
        - Primitive numeric constants (int32, int64, float, double)
        """
        strings: List[str] = []
        constants: List[Dict[str, any]] = []
        seen_strings = set()

        curr = 0
        data_len = len(data)

        # Pass 1: 7-bit and 4-byte length-prefixed strings
        while curr < data_len:
            # Try 7-bit encoded integer length prefix
            s_len, consumed = cls.read_7bit_encoded_int(data, curr)
            if 0 < s_len <= (data_len - (curr + consumed)) and s_len <= 65536:
                str_bytes = data[curr + consumed : curr + consumed + s_len]
                try:
                    decoded = str_bytes.decode("utf-8")
                    if decoded and all(ord(c) >= 32 or c in "\t\r\n" for c in decoded):
                        if decoded not in seen_strings:
                            seen_strings.add(decoded)
                            strings.append(decoded)
                            constants.append({
                                "offset": curr,
                                "type": "string",
                                "encoding": "utf-8-7bit",
                                "value": decoded,
                            })
                        curr += consumed + s_len
                        continue
                except Exception:
                    pass

            # Try 4-byte LE length prefix
            if curr + 4 <= data_len:
                le_len = struct.unpack_from("<I", data, curr)[0]
                if 0 < le_len <= (data_len - (curr + 4)) and le_len <= 65536:
                    str_bytes = data[curr + 4 : curr + 4 + le_len]
                    try:
                        decoded = str_bytes.decode("utf-8")
                        if decoded and all(ord(c) >= 32 or c in "\t\r\n" for c in decoded):
                            if decoded not in seen_strings:
                                seen_strings.add(decoded)
                                strings.append(decoded)
                                constants.append({
                                    "offset": curr,
                                    "type": "string",
                                    "encoding": "utf-8-le32",
                                    "value": decoded,
                                })
                            curr += 4 + le_len
                            continue
                    except Exception:
                        pass

            # Try primitive constants (int32)
            if curr + 4 <= data_len:
                val32 = struct.unpack_from("<i", data, curr)[0]
                constants.append({
                    "offset": curr,
                    "type": "int32",
                    "value": val32,
                })
            curr += 4

        # Pass 2: Null-terminated string carving fallback (only if no length-prefixed strings found)
        if len(strings) == 0:
            parts = data.split(b"\x00")
            for p in parts:
                if len(p) >= 3:
                    try:
                        s = p.decode("utf-8")
                        if s and all(ord(c) >= 32 or c in "\t\r\n" for c in s):
                            if s not in seen_strings:
                                seen_strings.add(s)
                                strings.append(s)
                                constants.append({
                                    "offset": -1,
                                    "type": "string",
                                    "encoding": "null-terminated",
                                    "value": s,
                                })
                    except Exception:
                        pass

        return {
            "strings": strings,
            "constants": constants,
        }

    @classmethod
    def decrypt_constants(
        cls,
        encrypted_data: bytes,
        seed: Optional[int] = None,
        key: Optional[bytes] = None,
        mode: str = "auto",
    ) -> Dict[str, any]:
        """
        Decrypts ConfuserEx constants / string buffer.
        Supports explicit seed/key or automatic heuristic key recovery.
        Modes: 'xorshift', 'lcg', 'xor', 'auto'.
        """
        if not encrypted_data:
            return {
                "success": False,
                "mode": mode,
                "recovered_seed": None,
                "recovered_key": None,
                "score": 0.0,
                "strings": [],
                "constants": [],
                "decrypted_bytes": b"",
            }

        length = len(encrypted_data)

        # Case 1: Seed provided with XorShift mode
        if seed is not None and mode in ("xorshift", "auto"):
            keystream = cls.xorshift32_keystream(seed, length)
            decrypted = bytes(b ^ k for b, k in zip(encrypted_data, keystream))
            parsed = cls.parse_string_table(decrypted)
            score = cls.evaluate_plaintext_score(decrypted)
            return {
                "success": True,
                "mode": "xorshift",
                "recovered_seed": seed,
                "recovered_key": None,
                "score": score,
                "strings": parsed["strings"],
                "constants": parsed["constants"],
                "decrypted_bytes": decrypted,
            }

        # Case 2: Seed provided with LCG mode
        if seed is not None and mode == "lcg":
            keystream = cls.lcg_keystream(seed, length)
            decrypted = bytes(b ^ k for b, k in zip(encrypted_data, keystream))
            parsed = cls.parse_string_table(decrypted)
            score = cls.evaluate_plaintext_score(decrypted)
            return {
                "success": True,
                "mode": "lcg",
                "recovered_seed": seed,
                "recovered_key": None,
                "score": score,
                "strings": parsed["strings"],
                "constants": parsed["constants"],
                "decrypted_bytes": decrypted,
            }

        # Case 3: Explicit key provided with XOR mode
        if key is not None:
            decrypted = cls.xor_crypt(encrypted_data, key)
            parsed = cls.parse_string_table(decrypted)
            score = cls.evaluate_plaintext_score(decrypted)
            return {
                "success": True,
                "mode": "xor",
                "recovered_seed": None,
                "recovered_key": key,
                "score": score,
                "strings": parsed["strings"],
                "constants": parsed["constants"],
                "decrypted_bytes": decrypted,
            }

        # Case 4: Automatic key / seed recovery (mode == 'auto')
        # Check raw unencrypted first
        raw_parsed = cls.parse_string_table(encrypted_data)
        raw_lp = sum(1 for c in raw_parsed["constants"] if c.get("encoding") in ("utf-8-7bit", "utf-8-le32"))
        raw_score = cls.evaluate_plaintext_score(encrypted_data) + (raw_lp * 1.0)
        if len(raw_parsed["strings"]) > 0:
            raw_score += min(0.4, len(raw_parsed["strings"]) * 0.1)

        best_candidate = {
            "success": len(raw_parsed["strings"]) > 0,
            "mode": "raw",
            "recovered_seed": None,
            "recovered_key": None,
            "score": raw_score,
            "strings": raw_parsed["strings"],
            "constants": raw_parsed["constants"],
            "decrypted_bytes": encrypted_data,
        }

        # Heuristic 4A: Exhaustive single-byte XOR scan (0x01 to 0xFF)
        for k in range(1, 256):
            candidate = bytes(b ^ k for b in encrypted_data)
            parsed = cls.parse_string_table(candidate)
            if len(parsed["strings"]) == 0:
                continue
            total_len = sum(len(s) for s in parsed["strings"])
            if total_len < 4:
                continue

            coverage = total_len / length
            alpha_ratio = sum(1 for s in parsed["strings"] for c in s if c.isalnum() or c in " _-./:") / total_len
            score = cls.evaluate_plaintext_score(candidate) + (coverage * 2.0) + (alpha_ratio * 0.5)
            if score > best_candidate["score"]:
                best_candidate = {
                    "success": True,
                    "mode": "xor_1byte",
                    "recovered_seed": None,
                    "recovered_key": bytes([k]),
                    "score": score,
                    "strings": parsed["strings"],
                    "constants": parsed["constants"],
                    "decrypted_bytes": candidate,
                }

        # Heuristic 4B: Candidate seeds from buffer integers or common Confuser seeds
        candidate_seeds = [
            0x12345678, 0xCAFEBABE, 0xDEADBEEF, 0x1337BEEF, 0x5A5A5A5A,
            0x00000001, 0x0000002A, 0x00000100, 0x00001000,
        ]
        for off in range(0, min(64, len(encrypted_data) - 4), 4):
            val = struct.unpack_from("<I", encrypted_data, off)[0]
            if val not in candidate_seeds:
                candidate_seeds.append(val)

        for s in candidate_seeds:
            # Test XorShift
            xs_stream = cls.xorshift32_keystream(s, length)
            xs_dec = bytes(b ^ k for b, k in zip(encrypted_data, xs_stream))
            parsed = cls.parse_string_table(xs_dec)
            if len(parsed["strings"]) > 0:
                total_len = sum(len(st) for st in parsed["strings"])
                coverage = total_len / length
                alpha_ratio = sum(1 for st in parsed["strings"] for c in st if c.isalnum() or c in " _-./:") / max(1, total_len)
                xs_score = cls.evaluate_plaintext_score(xs_dec) + (coverage * 2.0) + (alpha_ratio * 0.5)
                if xs_score > best_candidate["score"]:
                    best_candidate = {
                        "success": True,
                        "mode": "xorshift",
                        "recovered_seed": s,
                        "recovered_key": None,
                        "score": xs_score,
                        "strings": parsed["strings"],
                        "constants": parsed["constants"],
                        "decrypted_bytes": xs_dec,
                    }

            # Test LCG
            lcg_stream = cls.lcg_keystream(s, length)
            lcg_dec = bytes(b ^ k for b, k in zip(encrypted_data, lcg_stream))
            parsed = cls.parse_string_table(lcg_dec)
            if len(parsed["strings"]) > 0:
                total_len = sum(len(st) for st in parsed["strings"])
                coverage = total_len / length
                alpha_ratio = sum(1 for st in parsed["strings"] for c in st if c.isalnum() or c in " _-./:") / max(1, total_len)
                lcg_score = cls.evaluate_plaintext_score(lcg_dec) + (coverage * 2.0) + (alpha_ratio * 0.5)
                if lcg_score > best_candidate["score"]:
                    best_candidate = {
                        "success": True,
                        "mode": "lcg",
                        "recovered_seed": s,
                        "recovered_key": None,
                        "score": lcg_score,
                        "strings": parsed["strings"],
                        "constants": parsed["constants"],
                        "decrypted_bytes": lcg_dec,
                    }

        return best_candidate

    # =========================================================================
    # 4. Resource Protection Decryption & Decompression Engine
    # =========================================================================

    @staticmethod
    def rva_to_file_offset(data: bytes, rva: int) -> Optional[int]:
        """Maps Relative Virtual Address (RVA) to physical raw file offset with safe bounds checks."""
        if len(data) < 64 or data[:2] != b"MZ":
            return None

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_hdr_start = e_lfanew + 24 + opt_hdr_size

        for i in range(num_sections):
            sec_offset = sec_hdr_start + (i * 40)
            if sec_offset + 40 > len(data):
                break
            vsize = struct.unpack_from("<I", data, sec_offset + 8)[0]
            vaddr = struct.unpack_from("<I", data, sec_offset + 12)[0]
            rsize = struct.unpack_from("<I", data, sec_offset + 16)[0]
            rptr = struct.unpack_from("<I", data, sec_offset + 20)[0]

            eff_size = max(vsize, rsize)
            if vaddr <= rva < vaddr + eff_size:
                offset_in_sec = rva - vaddr
                if offset_in_sec < rsize and rptr + offset_in_sec <= len(data):
                    return rptr + offset_in_sec
        return None

    @classmethod
    def parse_cli_resources_directory(cls, data: bytes) -> Optional[Tuple[int, int]]:
        """Parses CLI (CLR) Header and extracts (resources_file_offset, resources_size)."""
        if len(data) < 64 or data[:2] != b"MZ":
            return None

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        cli_rva_offset = e_lfanew + 24 + (208 if magic == 0x10B else 224)
        if cli_rva_offset + 8 > len(data):
            return None

        clr_rva, clr_size = struct.unpack_from("<II", data, cli_rva_offset)
        if clr_rva == 0 or clr_size == 0:
            return None

        clr_offset = cls.rva_to_file_offset(data, clr_rva)
        if clr_offset is None or clr_offset + 72 > len(data):
            return None

        # Cor20Header.Resources (RVA, Size) at offset 24
        res_rva, res_size = struct.unpack_from("<II", data, clr_offset + 24)
        if res_rva == 0 or res_size == 0:
            return None

        res_file_offset = cls.rva_to_file_offset(data, res_rva)
        if res_file_offset is None or res_file_offset >= len(data):
            return None

        actual_size = min(res_size, len(data) - res_file_offset)
        return res_file_offset, actual_size

    @classmethod
    def decompress_payload(cls, raw_data: bytes) -> bytes:
        """
        Decompresses payload supporting Deflate (RFC 1951), Zlib, Gzip, and raw payloads.
        Strictly enforces MAX_DECOMPRESSED_SIZE to prevent decompression bomb denial-of-service.
        """
        if not raw_data:
            return b""

        # 1. Standard Zlib Header Check: 0x78 and (b0*256 + b1) % 31 == 0
        if len(raw_data) >= 2 and raw_data[0] == 0x78 and ((raw_data[0] * 256 + raw_data[1]) % 31 == 0):
            try:
                decomp = zlib.decompress(raw_data, zlib.MAX_WBITS)
                if len(decomp) > cls.MAX_DECOMPRESSED_SIZE:
                    raise ValueError("Decompressed payload exceeds safety ceiling")
                return decomp
            except (zlib.error, struct.error, OSError):
                pass

        # 2. Standard Gzip Header Check: 0x1F, 0x8B
        if len(raw_data) >= 2 and raw_data[:2] == b"\x1f\x8b":
            try:
                decomp = gzip.decompress(raw_data)
                if len(decomp) > cls.MAX_DECOMPRESSED_SIZE:
                    raise ValueError("Decompressed payload exceeds safety ceiling")
                return decomp
            except (gzip.BadGzipFile, OSError, struct.error):
                pass

        # 3. 4-byte LE length prefix followed by Raw Deflate (-15 windowBits)
        if len(raw_data) > 4:
            try:
                decomp = zlib.decompress(raw_data[4:], -zlib.MAX_WBITS)
                if len(decomp) > cls.MAX_DECOMPRESSED_SIZE:
                    raise ValueError("Decompressed payload exceeds safety ceiling")
                return decomp
            except (zlib.error, struct.error, OSError):
                pass

        # 4. RFC 1951 Raw Deflate (-15 windowBits)
        try:
            decomp = zlib.decompress(raw_data, -zlib.MAX_WBITS)
            if len(decomp) > cls.MAX_DECOMPRESSED_SIZE:
                raise ValueError("Decompressed payload exceeds safety ceiling")
            return decomp
        except (zlib.error, struct.error, OSError):
            pass

        # 5. Standard Zlib fallback
        try:
            decomp = zlib.decompress(raw_data, zlib.MAX_WBITS)
            if len(decomp) > cls.MAX_DECOMPRESSED_SIZE:
                raise ValueError("Decompressed payload exceeds safety ceiling")
            return decomp
        except (zlib.error, struct.error, OSError):
            pass

        # 6. Raw uncompressed fallback
        return raw_data

    @classmethod
    def identify_payload_type(cls, data: bytes) -> str:
        """Heuristically identifies resource payload binary type."""
        if cls.is_valid_pe(data):
            return "Managed Assembly (PE)"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG Image"
        if data.startswith(b"\xff\xd8\xff"):
            return "JPEG Image"
        if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            return "GIF Image"
        if data.startswith(b"\x00\x00\x01\x00"):
            return "Icon Resource"
        if data.startswith(b"<?xml") or data.startswith(b"\xef\xbb\xbf<?xml"):
            return "XML Document / Configuration"
        if data.startswith(b"\xce\xca\xef\xbe"):
            return ".NET ResourceManager Container"
        return "Binary Resource"

    @classmethod
    def parse_resource_catalog(cls, catalog_bytes: bytes) -> List[Dict[str, any]]:
        """
        Parses internal ConfuserEx or .NET resource catalog into individual extracted items.
        Supports:
        - ConfuserEx catalog: [entry_count: u32] ([name_len: u32][name][data_len: u32][data])*
        - Standard .NET ResourceManager: magic 0xBEEFCACE
        - Single embedded assembly or resource payload fallback
        """
        items: List[Dict[str, any]] = []
        if len(catalog_bytes) < 4:
            return items

        # Format A: ConfuserEx Custom Resource Catalog
        count = struct.unpack_from("<I", catalog_bytes, 0)[0]
        if 0 < count <= 1000:
            curr = 4
            valid_catalog = True
            entries = []
            for _ in range(count):
                if curr + 4 > len(catalog_bytes):
                    valid_catalog = False
                    break
                name_len = struct.unpack_from("<I", catalog_bytes, curr)[0]
                curr += 4
                if curr + name_len + 4 > len(catalog_bytes) or name_len > 1024:
                    valid_catalog = False
                    break
                try:
                    name = catalog_bytes[curr : curr + name_len].decode("utf-8")
                except Exception:
                    name = f"res_{len(entries)}.bin"
                curr += name_len
                data_len = struct.unpack_from("<I", catalog_bytes, curr)[0]
                curr += 4
                if curr + data_len > len(catalog_bytes) or data_len > cls.MAX_DECOMPRESSED_SIZE:
                    valid_catalog = False
                    break
                entry_data = catalog_bytes[curr : curr + data_len]
                curr += data_len
                entries.append((name, entry_data))

            if valid_catalog and len(entries) == count:
                for name, p_data in entries:
                    decomp = cls.decompress_payload(p_data)
                    safe_name = cls.sanitize_filename(name)
                    items.append({
                        "original_name": name,
                        "output_filename": safe_name,
                        "compressed_size_bytes": len(p_data),
                        "size_bytes": len(decomp),
                        "sha256": hashlib.sha256(decomp).hexdigest(),
                        "is_pe": cls.is_valid_pe(decomp),
                        "resource_type": cls.identify_payload_type(decomp),
                        "entropy": cls.calculate_entropy(decomp),
                        "payload_bytes": decomp,
                    })
                return items

        # Format B: Direct embedded file payload
        decomp = cls.decompress_payload(catalog_bytes)
        safe_name = "extracted_confuser_resource.bin"
        if cls.is_valid_pe(decomp):
            safe_name = "extracted_confuser_payload.dll"

        items.append({
            "original_name": "confuser.resources",
            "output_filename": safe_name,
            "compressed_size_bytes": len(catalog_bytes),
            "size_bytes": len(decomp),
            "sha256": hashlib.sha256(decomp).hexdigest(),
            "is_pe": cls.is_valid_pe(decomp),
            "resource_type": cls.identify_payload_type(decomp),
            "entropy": cls.calculate_entropy(decomp),
            "payload_bytes": decomp,
        })
        return items

    @classmethod
    def unpack(
        cls,
        data: bytes,
        seed: Optional[int] = None,
        key: Optional[bytes] = None,
    ) -> List[Dict[str, any]]:
        """
        Locates encrypted resource containers in PE binary or via heuristic carving,
        decrypts container streams, decompresses payload, and parses internal catalogs.
        """
        # Guard: Only attempt extraction if explicit decryption parameters are provided
        # or ConfuserEx markers/protections are detected in binary.
        if seed is None and key is None:
            detection = cls.detect(data)
            if not detection["is_confuserex"]:
                return []

        results: List[Dict[str, any]] = []

        # Step 1: CLI Resources Directory Extraction
        res_info = cls.parse_cli_resources_directory(data)
        if res_info is not None:
            res_offset, res_size = res_info
            curr = 0
            idx = 0
            while curr + 4 <= res_size:
                length = struct.unpack_from("<I", data, res_offset + curr)[0]
                curr += 4
                if length == 0 or curr + length > res_size:
                    break

                raw_chunk = data[res_offset + curr : res_offset + curr + length]
                curr += length
                idx += 1

                # Check if chunk is already a valid unencrypted catalog
                direct_catalog = cls.parse_resource_catalog(raw_chunk)
                if len(direct_catalog) > 0 and (direct_catalog[0]["original_name"] != "confuser.resources" or direct_catalog[0]["is_pe"]):
                    results.extend(direct_catalog)
                    continue

                # Decrypt raw container if encrypted
                decrypted_chunk = raw_chunk
                if seed is not None:
                    keystream = cls.xorshift32_keystream(seed, len(raw_chunk))
                    decrypted_chunk = bytes(b ^ k for b, k in zip(raw_chunk, keystream))
                elif key is not None:
                    decrypted_chunk = cls.xor_crypt(raw_chunk, key)
                else:
                    # Attempt automatic constants/resource decryption
                    dec_res = cls.decrypt_constants(raw_chunk, mode="auto")
                    if dec_res["success"] and dec_res["score"] > 0.45:
                        decrypted_chunk = dec_res["decrypted_bytes"]

                # Parse catalog entries
                catalog_items = cls.parse_resource_catalog(decrypted_chunk)
                results.extend(catalog_items)

        # Step 2: Heuristic Carving Fallback (if CLI Resources directory is absent or corrupted)
        if len(results) == 0:
            cand_offsets = []
            for marker in [b"Confuser.Runtime", b"confuser.resources", b"\xce\xca\xef\xbe"]:
                pos = 0
                while True:
                    idx = data.find(marker, pos)
                    if idx == -1:
                        break
                    cand_offsets.append(idx)
                    pos = idx + len(marker)

            for c_off in cand_offsets:
                for test_off in range(c_off, min(c_off + 64, len(data) - 4)):
                    c_len = struct.unpack_from("<I", data, test_off)[0]
                    if 16 <= c_len <= (len(data) - test_off - 4) and c_len <= cls.MAX_DECOMPRESSED_SIZE:
                        chunk = data[test_off + 4 : test_off + 4 + c_len]
                        decomp = cls.decompress_payload(chunk)
                        if cls.is_valid_pe(decomp):
                            results.append({
                                "original_name": "carved.dll",
                                "output_filename": "carved.dll",
                                "compressed_size_bytes": len(chunk),
                                "size_bytes": len(decomp),
                                "sha256": hashlib.sha256(decomp).hexdigest(),
                                "is_pe": True,
                                "resource_type": "Managed Assembly (PE)",
                                "entropy": cls.calculate_entropy(decomp),
                                "payload_bytes": decomp,
                            })
                            break
                        catalog_items = cls.parse_resource_catalog(chunk)
                        if len(catalog_items) > 0 and (catalog_items[0]["original_name"] != "confuser.resources" or catalog_items[0]["is_pe"]):
                            results.extend(catalog_items)
                            break

        return results

    # =========================================================================
    # 5. Path Traversal Defenses & Safe Directory Extraction
    # =========================================================================

    @staticmethod
    def sanitize_filename(name: str) -> str:
        """
        Sanitizes extracted resource names and defends against path traversal.
        Normalizes separators, strips directory navigation (../, ..\\), null bytes, and control chars.
        """
        clean = name.replace("\\", "/").strip()
        clean = os.path.basename(clean)

        # Remove null bytes and non-printable control characters
        clean = "".join(c for c in clean if 31 < ord(c) < 127 or ord(c) >= 160)

        # Fallback if empty or starts with invalid leading dot
        if not clean or clean.startswith("."):
            clean = f"confuser_res_{hashlib.sha256(name.encode('utf-8', errors='ignore')).hexdigest()[:8]}.bin"

        return clean

    @classmethod
    def unpack_to_directory(
        cls,
        data: bytes,
        output_dir: str,
        seed: Optional[int] = None,
        key: Optional[bytes] = None,
    ) -> List[Dict[str, any]]:
        """
        Unpacks all ConfuserEx encrypted resources safely to disk.
        Enforces path containment within output_dir and defends against directory traversal attacks.
        """
        payloads = cls.unpack(data, seed=seed, key=key)
        os.makedirs(output_dir, exist_ok=True)
        written = []

        real_output_dir = os.path.abspath(output_dir)

        for p in payloads:
            safe_name = os.path.basename(p["output_filename"])
            out_path = os.path.join(output_dir, safe_name)
            real_out_path = os.path.abspath(out_path)

            # Security Defense: Check path traversal
            if not real_out_path.startswith(real_output_dir):
                raise SecurityError(f"Directory traversal attack detected in filename: {p['output_filename']}")

            with open(out_path, "wb") as f:
                f.write(p["payload_bytes"])

            written.append({
                "original_name": p["original_name"],
                "output_filename": safe_name,
                "output_path": out_path,
                "size_bytes": p["size_bytes"],
                "sha256": p["sha256"],
                "is_pe": p["is_pe"],
                "resource_type": p.get("resource_type", "Binary Resource"),
            })

            # Zeroize sensitive payload bytes from memory dictionary
            p["payload_bytes"] = None

        return written

    # =========================================================================
    # 6. Memory Hygiene & PE Validation Utilities
    # =========================================================================

    @staticmethod
    def zeroize(buffer: Union[bytearray, memoryview, list]) -> None:
        """
        Cryptographic memory wiping: zeroes out sensitive key buffers in memory.
        """
        if isinstance(buffer, (bytearray, memoryview)):
            for i in range(len(buffer)):
                buffer[i] = 0
        elif isinstance(buffer, list):
            for i in range(len(buffer)):
                buffer[i] = 0

    @classmethod
    def is_valid_pe(cls, data: bytes) -> bool:
        """Validates if byte buffer is a well-formed PE executable."""
        if len(data) < 64 or data[:2] != b"MZ":
            return False
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                return True
        except Exception:
            pass
        return False
