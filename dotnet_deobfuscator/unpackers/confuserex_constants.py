"""
ConfuserEx Mathematical Ciphers, PRNG Keystream Generators & Constants Table Decryptor.
Engineered & Audited by Maya Thorne.
"""

import math
import struct
from typing import Dict, List, Optional, Tuple, Union


class ConfuserExConstantsDecryptor:
    """
    Cryptographic decryptor and heuristics engine for ConfuserEx constants protection.
    Implements XorShift 32-bit PRNG, Linear Congruential Generators (LCG),
    dynamic key scheduling, 7-bit encoded integer string tables, and auto key recovery.
    """

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

    @classmethod
    def xorshift32_keystream(cls, seed: int, length: int) -> bytes:
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
        res = bytes(keystream)
        cls.zeroize(keystream)
        return res

    @classmethod
    def lcg_keystream(
        cls,
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
        res = bytes(keystream)
        cls.zeroize(keystream)
        return res

    @classmethod
    def derive_key_schedule(cls, seed: int, key_len: int = 16) -> bytes:
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
        res = bytes(schedule[:key_len])
        cls.zeroize(schedule)
        return res

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
