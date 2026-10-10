"""
.NET CLI Metadata & Bytecode Entropy Analyzer.
Engineered & Audited by Maya Thorne.
"""

import math
import struct
from typing import Dict, List, Optional


class DotNetAnalyzer:
    """Performs static parsing of .NET PE headers, CLI metadata, and entropy."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy of a byte buffer (0.0 to 8.0)."""
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

    @classmethod
    def inspect_assembly(cls, data: bytes) -> Dict[str, any]:
        """Inspects PE executable for .NET CLR headers and metadata signatures."""
        res = {
            "is_pe": False,
            "is_dotnet": False,
            "clr_runtime_version": None,
            "entropy": cls.calculate_entropy(data),
            "sections": [],
            "metadata_streams": [],
            "suspicious_indicators": [],
        }

        if len(data) < 64 or data[:2] != b"MZ":
            return res

        res["is_pe"] = True
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return res

        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]

        # Magic: 0x10b (PE32) or 0x20b (PE32+)
        cli_rva_offset = e_lfanew + 24 + (208 if magic == 0x10B else 224)
        if cli_rva_offset + 8 <= len(data):
            clr_rva, clr_size = struct.unpack_from("<II", data, cli_rva_offset)
            if clr_rva > 0 and clr_size > 0:
                res["is_dotnet"] = True

        # Parse Section Headers
        sec_hdr_start = e_lfanew + 24 + opt_hdr_size
        for i in range(num_sections):
            sec_offset = sec_hdr_start + (i * 40)
            if sec_offset + 40 > len(data):
                break
            name = (
                data[sec_offset : sec_offset + 8]
                .decode("latin1", errors="ignore")
                .strip("\x00")
            )
            vsize = struct.unpack_from("<I", data, sec_offset + 8)[0]
            vaddr = struct.unpack_from("<I", data, sec_offset + 12)[0]
            rsize = struct.unpack_from("<I", data, sec_offset + 16)[0]
            rptr = struct.unpack_from("<I", data, sec_offset + 20)[0]

            sec_bytes = data[rptr : rptr + rsize] if rptr + rsize <= len(data) else b""
            sec_entropy = cls.calculate_entropy(sec_bytes)

            res["sections"].append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vaddr),
                "raw_size": rsize,
                "entropy": sec_entropy,
            })

            if sec_entropy > 7.2:
                res["suspicious_indicators"].append(
                    f"High entropy in section '{name}' ({sec_entropy}) -> Likely encrypted/packed"
                )

        # Detect Metadata Streams (#~, #-, #Strings, #US, #GUID, #Blob)
        for stream in [b"#~", b"#-", b"#Strings", b"#US", b"#GUID", b"#Blob"]:
            if stream in data:
                res["metadata_streams"].append(stream.decode("latin1"))

        # Check for Anti-Tamper / Zeroed methods heuristic
        if res["is_dotnet"] and b"#Strings" not in data and b"#US" not in data:
            res["suspicious_indicators"].append(
                "Absence of standard #Strings and #US streams -> Heuristic: Stripped or ConfuserEx Anti-Tamper"
            )

        return res
