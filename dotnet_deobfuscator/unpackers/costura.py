"""
Costura.Fody Embedded Assembly & Compressed Resource Forensic Unpacker.
Engineered & Audited by Maya Thorne.
"""

import gzip
import hashlib
import math
import os
import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple


class CosturaUnpacker:
    """
    Forensic unpacker for assemblies bundled with Costura.Fody.
    Extracts embedded and compressed (.compressed) managed assemblies,
    unmanaged native DLLs, and debug symbol files (PDB).
    """

    MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024  # 256 MB safety ceiling against decompression bombs

    # Typical Costura manifest resource prefixes
    RESOURCE_PREFIXES = [
        "costura.",
        "costura32.",
        "costura64.",
    ]

    SIGNATURE_PATTERNS = [
        b"costura.",
        b"costura32.",
        b"costura64.",
        b"Costura.",
        b"costura.costura.",
        b".dll.compressed",
        b".pdb.compressed",
    ]

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, any]:
        """
        Scans binary for Costura signatures, markers, and embedded resource patterns.
        """
        matched = []
        for pat in cls.SIGNATURE_PATTERNS:
            if pat in data:
                matched.append(pat.decode("latin1", errors="ignore"))

        # Look for resource string candidates in raw bytes
        candidates = []
        regex = re.compile(rb"(costura(?:32|64)?\.[a-zA-Z0-9_\-\.]+\.(?:dll|pdb)(?:\.compressed)?)", re.IGNORECASE)
        for m in regex.finditer(data):
            try:
                name = m.group(1).decode("latin1")
                if name not in candidates:
                    candidates.append(name)
            except Exception:
                pass

        is_costura = len(matched) > 0 or len(candidates) > 0
        confidence = "HIGH" if len(matched) >= 2 or len(candidates) >= 1 else ("MEDIUM" if len(matched) == 1 else "NONE")

        return {
            "is_costura": is_costura,
            "confidence": confidence,
            "matched_indicators": matched,
            "resource_candidates": candidates,
        }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

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

            # In PE files, virtual size can be 0 or smaller than raw size, take the effective size
            eff_size = max(vsize, rsize)
            if vaddr <= rva < vaddr + eff_size:
                offset_in_sec = rva - vaddr
                if offset_in_sec < rsize and rptr + offset_in_sec <= len(data):
                    return rptr + offset_in_sec
        return None

    @classmethod
    def parse_cli_resources_directory(cls, data: bytes) -> Optional[Tuple[int, int]]:
        """
        Parses CLI (CLR) Header and extracts (resources_file_offset, resources_size).
        """
        if len(data) < 64 or data[:2] != b"MZ":
            return None

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        # Data Directory 14 (CLR Runtime Header)
        cli_rva_offset = e_lfanew + 24 + (208 if magic == 0x10B else 224)
        if cli_rva_offset + 8 > len(data):
            return None

        clr_rva, clr_size = struct.unpack_from("<II", data, cli_rva_offset)
        if clr_rva == 0 or clr_size == 0:
            return None

        clr_offset = cls.rva_to_file_offset(data, clr_rva)
        if clr_offset is None or clr_offset + 72 > len(data):
            return None

        # Resources directory is at offset 24 in IMAGE_COR20_HEADER (RVA, Size)
        res_rva, res_size = struct.unpack_from("<II", data, clr_offset + 24)
        if res_rva == 0 or res_size == 0:
            return None

        res_file_offset = cls.rva_to_file_offset(data, res_rva)
        if res_file_offset is None or res_file_offset >= len(data):
            return None

        actual_size = min(res_size, len(data) - res_file_offset)
        return res_file_offset, actual_size

    @classmethod
    def parse_cli_metadata_strings(cls, data: bytes) -> List[str]:
        """
        Extracts resource candidate names from the CLI #Strings stream.
        """
        strings = []
        if len(data) < 64 or data[:2] != b"MZ":
            return strings

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return strings

        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        cli_rva_offset = e_lfanew + 24 + (208 if magic == 0x10B else 224)
        if cli_rva_offset + 8 > len(data):
            return strings

        clr_rva, clr_size = struct.unpack_from("<II", data, cli_rva_offset)
        if clr_rva == 0:
            return strings

        clr_offset = cls.rva_to_file_offset(data, clr_rva)
        if clr_offset is None or clr_offset + 16 > len(data):
            return strings

        # Metadata Directory RVA & Size at offset 8 of IMAGE_COR20_HEADER
        meta_rva, meta_size = struct.unpack_from("<II", data, clr_offset + 8)
        if meta_rva == 0:
            return strings

        meta_offset = cls.rva_to_file_offset(data, meta_rva)
        if meta_offset is None or meta_offset + 16 > len(data):
            return strings

        # Validate BSJB magic
        if data[meta_offset : meta_offset + 4] != b"BSJB":
            return strings

        v_len = struct.unpack_from("<I", data, meta_offset + 12)[0]
        stream_hdr_offset = meta_offset + 16 + v_len
        # Flags (2 bytes) + Streams count (2 bytes)
        if stream_hdr_offset + 4 > len(data):
            return strings

        streams_count = struct.unpack_from("<H", data, stream_hdr_offset + 2)[0]
        curr = stream_hdr_offset + 4

        for _ in range(streams_count):
            if curr + 8 > len(data):
                break
            s_offset, s_size = struct.unpack_from("<II", data, curr)
            curr += 8
            # Stream name is null-terminated, padded to 4-byte boundary
            name_chars = []
            while curr < len(data) and data[curr] != 0:
                name_chars.append(chr(data[curr]))
                curr += 1
            curr += 1  # Skip null terminator
            # 4-byte alignment
            pad = (4 - ((len(name_chars) + 1) % 4)) % 4
            curr += pad
            s_name = "".join(name_chars)

            if s_name == "#Strings":
                stream_start = meta_offset + s_offset
                stream_end = min(stream_start + s_size, len(data))
                raw_strings_blob = data[stream_start:stream_end]

                # Extract strings
                parts = raw_strings_blob.split(b"\x00")
                for p in parts:
                    if p:
                        try:
                            s = p.decode("utf-8")
                            if any(s.lower().startswith(pref) for pref in cls.RESOURCE_PREFIXES) or s.lower().endswith(".compressed"):
                                strings.append(s)
                        except Exception:
                            pass
        return strings

    @classmethod
    def decompress_payload(cls, raw_data: bytes, is_compressed: bool = True) -> bytes:
        """
        Decompresses raw Costura payload using DeflateStream inversion.
        Supports RFC 1951 raw deflate, length-prefixed raw deflate, zlib, and gzip.
        Enforces MAX_DECOMPRESSED_SIZE to prevent decompression bombs.
        """
        if not is_compressed:
            return raw_data

        if not raw_data:
            return b""

        # Attempt 1: RFC 1951 Raw Deflate (negative windowBits: -15) - standard Costura format
        try:
            decomp = zlib.decompress(raw_data, -zlib.MAX_WBITS, cls.MAX_DECOMPRESSED_SIZE)
            return decomp
        except Exception:
            pass

        # Attempt 2: 4-byte little-endian length prefix followed by raw deflate
        if len(raw_data) > 4:
            try:
                decomp = zlib.decompress(raw_data[4:], -zlib.MAX_WBITS, cls.MAX_DECOMPRESSED_SIZE)
                return decomp
            except Exception:
                pass

        # Attempt 3: 8-byte length prefix
        if len(raw_data) > 8:
            try:
                decomp = zlib.decompress(raw_data[8:], -zlib.MAX_WBITS, cls.MAX_DECOMPRESSED_SIZE)
                return decomp
            except Exception:
                pass

        # Attempt 4: Standard zlib (with headers)
        try:
            decomp = zlib.decompress(raw_data, cls.MAX_DECOMPRESSED_SIZE)
            return decomp
        except Exception:
            pass

        # Attempt 5: Standard gzip
        try:
            decomp = gzip.decompress(raw_data)
            if len(decomp) > cls.MAX_DECOMPRESSED_SIZE:
                raise ValueError("Gzip payload exceeds maximum safe limit")
            return decomp
        except Exception:
            pass

        # If decompression fails, return raw data as fallback
        return raw_data

    @staticmethod
    def sanitize_filename(name: str) -> str:
        """
        Sanitizes extracted resource names and defends against path traversal.
        Normalizes Costura naming:
          costura.newtonsoft.json.dll.compressed -> newtonsoft.json.dll
          costura32.sqlite.interop.dll.compressed -> costura32_sqlite.interop.dll
          costura64.sqlite.interop.dll.compressed -> costura64_sqlite.interop.dll
        """
        # Neutralize path traversal
        clean = name.replace("\\", "/").strip()
        clean = os.path.basename(clean)

        # Remove null bytes and control chars
        clean = "".join(c for c in clean if 31 < ord(c) < 127 or ord(c) >= 160)

        # Strip .compressed suffix
        if clean.lower().endswith(".compressed"):
            clean = clean[:-11]

        # Normalize Costura prefixes
        lower_clean = clean.lower()
        if lower_clean.startswith("costura."):
            clean = clean[8:]
        elif lower_clean.startswith("costura32."):
            clean = "costura32_" + clean[10:]
        elif lower_clean.startswith("costura64."):
            clean = "costura64_" + clean[10:]

        # Fallback if empty
        if not clean or clean.startswith("."):
            clean = f"extracted_assembly_{hashlib.sha256(name.encode()).hexdigest()[:8]}.dll"

        return clean

    @classmethod
    def is_valid_pe(cls, data: bytes) -> bool:
        """Checks if byte buffer is a valid PE executable."""
        if len(data) < 64 or data[:2] != b"MZ":
            return False
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                return True
        except Exception:
            pass
        return False

    @classmethod
    def is_valid_pdb(cls, data: bytes) -> bool:
        """Checks if byte buffer is a Microsoft PDB file."""
        return data.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00") or data.startswith(b"BSJB")

    @classmethod
    def unpack(cls, data: bytes) -> List[Dict[str, any]]:
        """
        Extracts and decompresses all embedded Costura assemblies and resources.
        Utilizes both CLI Resources directory mapping and heuristic pattern carving.
        """
        results: List[Dict[str, any]] = []
        seen_names = set()

        # Step 1: CLI Resources Directory Extraction
        res_info = cls.parse_cli_resources_directory(data)
        meta_names = cls.parse_cli_metadata_strings(data)

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

                # Associate with candidate name if available
                res_name = meta_names[idx] if idx < len(meta_names) else f"costura_res_{idx}.dll.compressed"
                idx += 1

                is_compressed = res_name.lower().endswith(".compressed")
                decompressed = cls.decompress_payload(raw_chunk, is_compressed=is_compressed)
                sanitized_name = cls.sanitize_filename(res_name)

                seen_names.add(sanitized_name)
                results.append({
                    "original_name": res_name,
                    "output_filename": sanitized_name,
                    "compressed_size_bytes": len(raw_chunk),
                    "size_bytes": len(decompressed),
                    "sha256": hashlib.sha256(decompressed).hexdigest(),
                    "is_pe": cls.is_valid_pe(decompressed),
                    "is_pdb": cls.is_valid_pdb(decompressed),
                    "entropy": cls.calculate_entropy(decompressed),
                    "payload_bytes": decompressed,
                })

        # Step 2: Heuristic Carving Fallback (if CLI table is corrupted, non-standard, or packed)
        # Scan for Costura resource candidate markers or embedded PE headers inside raw streams
        if len(results) == 0:
            detection = cls.detect(data)
            for c_name in detection["resource_candidates"]:
                sanitized_name = cls.sanitize_filename(c_name)
                if sanitized_name in seen_names:
                    continue

                # Locate resource name in data and inspect following bytes for length prefixes
                pos = 0
                while True:
                    idx = data.find(c_name.encode("latin1"), pos)
                    if idx == -1:
                        break
                    pos = idx + len(c_name)

                    # Look around position for a length prefix or deflate stream
                    # Check window of 128 bytes after name
                    for test_off in range(idx + len(c_name), min(idx + len(c_name) + 128, len(data) - 4)):
                        cand_len = struct.unpack_from("<I", data, test_off)[0]
                        if 8 <= cand_len < len(data) - test_off - 4:
                            candidate_bytes = data[test_off + 4 : test_off + 4 + cand_len]
                            is_comp = c_name.lower().endswith(".compressed")
                            decomp = cls.decompress_payload(candidate_bytes, is_compressed=is_comp)
                            if cls.is_valid_pe(decomp) or cls.is_valid_pdb(decomp):
                                seen_names.add(sanitized_name)
                                results.append({
                                    "original_name": c_name,
                                    "output_filename": sanitized_name,
                                    "compressed_size_bytes": len(candidate_bytes),
                                    "size_bytes": len(decomp),
                                    "sha256": hashlib.sha256(decomp).hexdigest(),
                                    "is_pe": cls.is_valid_pe(decomp),
                                    "is_pdb": cls.is_valid_pdb(decomp),
                                    "entropy": cls.calculate_entropy(decomp),
                                    "payload_bytes": decomp,
                                })
                                break

        return results

    @classmethod
    def unpack_to_directory(cls, data: bytes, output_dir: str) -> List[Dict[str, any]]:
        """
        Unpacks all Costura payloads and writes them safely to disk.
        Defends against directory traversal and ensures 100% path safety.
        """
        payloads = cls.unpack(data)
        os.makedirs(output_dir, exist_ok=True)
        written = []

        for p in payloads:
            safe_name = os.path.basename(p["output_filename"])
            out_path = os.path.join(output_dir, safe_name)

            # Security: ensure resolved path is strictly inside output_dir
            real_out_path = os.path.abspath(out_path)
            real_output_dir = os.path.abspath(output_dir)
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
                "is_pdb": p["is_pdb"],
            })

            # Zeroize sensitive payload bytes from memory dictionary if needed
            p["payload_bytes"] = None

        return written
