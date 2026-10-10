"""
PE Overlay & xorPacker Dual-XOR Forensic Deobfuscation Module.
Engineered & Audited by Maya Thorne.
"""

import base64
import struct
from typing import Dict, Optional


class PEOverlayParser:
    """Parses PE Section headers and extracts/decrypts xorPacker overlay structures."""

    SENTINEL = b"***"
    DEFAULT_MASTER_KEY = "randomkey"

    @staticmethod
    def calculate_pe_size(data: bytes) -> Optional[int]:
        """Calculates the end of mapped PE raw sections."""
        if len(data) < 64 or data[:2] != b"MZ":
            return None

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return None

        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        section_hdr_offset = e_lfanew + 24 + opt_hdr_size

        max_raw_end = 0
        for i in range(num_sections):
            sec_offset = section_hdr_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break
            raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, sec_offset + 20)[0]
            sec_end = raw_ptr + raw_size
            if sec_end > max_raw_end:
                max_raw_end = sec_end

        return max_raw_end if max_raw_end > 0 else None

    @classmethod
    def extract_overlay(cls, data: bytes) -> bytes:
        """Extracts unmapped overlay bytes beyond calculated PE sections."""
        pe_size = cls.calculate_pe_size(data)
        if pe_size is not None and len(data) > pe_size:
            return data[pe_size:]
        return b""

    @staticmethod
    def xor_cipher(data: str, key: str) -> str:
        """Inverts the repetitive XOR cipher used by xorStub."""
        if not key:
            return data
        res = []
        key_len = len(key)
        for i, char in enumerate(data):
            res.append(chr(ord(char) ^ ord(key[i % key_len])))
        return "".join(res)

    @classmethod
    def decrypt_xor_packer(
        cls, data: bytes, master_key: str = DEFAULT_MASTER_KEY
    ) -> Optional[Dict[str, any]]:
        """
        Locates xorPacker '***' sentinel, derives dynamic key, and extracts payload.
        Handles the exact C# pipeline:
        bytesBack = Convert.FromBase64String(ROT13Encode(Encoding.UTF8.GetString(Convert.FromBase64String(cipheredFile)), randomKey))
        """
        idx = data.find(cls.SENTINEL)
        if idx == -1:
            return None

        raw_payload_chunk = data[idx + len(cls.SENTINEL) :]
        try:
            settings_str = raw_payload_chunk.decode("ascii", errors="ignore")
        except Exception:
            return None

        if "|" not in settings_str:
            return None

        parts = settings_str.split("|", 1)
        ciphered_payload = parts[0].strip()
        encoded_key = parts[1].strip()

        try:
            # 1. Base64 decode dynamic key chunk
            xor_dyn_key_bytes = base64.b64decode(encoded_key)
            xor_dyn_key_str = xor_dyn_key_bytes.decode("utf-8", errors="ignore")
            # 2. Derive dynamic session key via master key XOR
            dynamic_key = cls.xor_cipher(xor_dyn_key_str, master_key)

            # 3. Decrypt payload following exact C# xorStub flow
            # Step A: FromBase64String(cipheredFile)
            stage1_bytes = base64.b64decode(ciphered_payload)
            stage1_str = stage1_bytes.decode("utf-8", errors="ignore")
            # Step B: ROT13Encode(..., randomKey)
            stage2_b64 = cls.xor_cipher(stage1_str, dynamic_key)
            # Step C: Convert.FromBase64String(...)
            decrypted_bytes = base64.b64decode(stage2_b64)

            return {
                "sentinel_offset": idx,
                "master_key_used": master_key,
                "dynamic_key_recovered": dynamic_key,
                "ciphered_payload_len": len(ciphered_payload),
                "decrypted_payload_bytes": decrypted_bytes,
                "is_valid_pe": decrypted_bytes.startswith(b"MZ"),
            }
        except Exception:
            return None
