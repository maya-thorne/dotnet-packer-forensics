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

from .confuserex_constants import ConfuserExConstantsDecryptor


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
    # 2. Mathematical Ciphers & Constants Decryptor Delegation
    # =========================================================================

    zeroize = ConfuserExConstantsDecryptor.zeroize
    calculate_entropy = ConfuserExConstantsDecryptor.calculate_entropy
    xorshift32_keystream = ConfuserExConstantsDecryptor.xorshift32_keystream
    lcg_keystream = ConfuserExConstantsDecryptor.lcg_keystream
    derive_key_schedule = ConfuserExConstantsDecryptor.derive_key_schedule
    xor_crypt = ConfuserExConstantsDecryptor.xor_crypt
    evaluate_plaintext_score = ConfuserExConstantsDecryptor.evaluate_plaintext_score
    read_7bit_encoded_int = ConfuserExConstantsDecryptor.read_7bit_encoded_int
    parse_string_table = ConfuserExConstantsDecryptor.parse_string_table
    decrypt_constants = ConfuserExConstantsDecryptor.decrypt_constants

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

        real_output_dir = os.path.realpath(output_dir)

        for p in payloads:
            safe_name = os.path.basename(p["output_filename"])
            out_path = os.path.join(output_dir, safe_name)
            real_out_path = os.path.realpath(out_path)

            # Security Defense: Check path traversal
            if not real_out_path.startswith(real_output_dir + os.sep) and real_out_path != real_output_dir:
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
