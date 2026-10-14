"""
Core Processing Engine for Native Multi-Architecture Demuxer & Platform Router.
Engineered & Audited by Maya Thorne.
"""

import ctypes
import gzip
import hashlib
import math
import os
import re
import struct
import zlib
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .native_demuxer_models import (
    BinaryFormat,
    DemuxSource,
    NativeDemuxerTelemetry,
    NativePayloadInfo,
    PlatformRouteResult,
    SecurityError,
    TargetArchitecture,
    TargetOS,
)


def zeroize_buffer(buf: Union[bytearray, memoryview, bytes]) -> None:
    """Safely zeroizes sensitive in-memory buffers using ctypes.memset."""
    if isinstance(buf, (bytearray, memoryview)):
        try:
            length = len(buf)
            if length > 0:
                ctypes.memset((ctypes.c_char * length).from_buffer(buf), 0, length)
        except Exception:
            for i in range(len(buf)):
                buf[i] = 0


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class NativeDemuxerEngine:
    """
    Forensic engine for discovering, carving, verifying, and routing
    multi-architecture native binary payloads (x86, x64, ARM64, ARM, IA64).
    """

    MAX_PAYLOAD_SIZE = 100 * 1024 * 1024  # 100 MB safety ceiling against decompression bombs

    # Well-known PE Machine types
    PE_MACHINE_I386 = 0x014C
    PE_MACHINE_AMD64 = 0x8664
    PE_MACHINE_ARM64 = 0xAA64
    PE_MACHINE_ARMNT = 0x01C4
    PE_MACHINE_IA64 = 0x0200

    # Well-known ELF Machine types
    ELF_MACHINE_386 = 0x03
    ELF_MACHINE_X86_64 = 0x3E
    ELF_MACHINE_AARCH64 = 0xB7
    ELF_MACHINE_ARM = 0x28

    # Well-known Mach-O CPU types
    MACHO_CPU_X86 = 0x07
    MACHO_CPU_X86_64 = 0x01000007
    MACHO_CPU_ARM = 0x0C
    MACHO_CPU_ARM64 = 0x0100000C

    # Common architecture prefix and folder patterns
    RESOURCE_PATTERNS = [
        re.compile(rb"(?:costura(?:32|64)?\.(?:(?:win|linux|osx)-)?(?:x86|x64|arm64|arm)?\.?[a-zA-Z0-9_\-\.]+\.(?:dll|so|dylib|pdb)(?:\.compressed)?)", re.IGNORECASE),
        re.compile(rb"(?:runtimes[/\\](win|linux|osx)-(x86|x64|arm64|arm)[/\\]native[/\\][a-zA-Z0-9_\-\.]+\.(?:dll|so|dylib))", re.IGNORECASE),
        re.compile(rb"(?:(?:x86|x64|arm64|win32|win64)[/\\][a-zA-Z0-9_\-\.]+\.(?:dll|so|dylib|exe))", re.IGNORECASE),
    ]

    @classmethod
    def inspect_binary_format(
        cls, data: bytes
    ) -> Tuple[BinaryFormat, TargetArchitecture, TargetOS, int, Optional[str], Optional[str]]:
        """
        Inspects raw binary headers to determine format, architecture, OS, machine code,
        subsystem, and export name.
        """
        if len(data) < 64:
            return (BinaryFormat.RAW_BINARY, TargetArchitecture.UNKNOWN, TargetOS.UNKNOWN, 0, None, None)

        # 1. PE / Windows Binary Check
        if data[:2] == b"MZ":
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 < e_lfanew + 24 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
                opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
                magic = 0
                subsystem = None
                export_name = None

                if opt_hdr_size >= 2 and e_lfanew + 24 + 2 <= len(data):
                    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]

                if opt_hdr_size >= 70 and e_lfanew + 24 + 70 <= len(data):
                    subsys_code = struct.unpack_from("<H", data, e_lfanew + 24 + 68)[0]
                    subsystem = {
                        1: "NATIVE_DRIVER",
                        2: "WINDOWS_GUI",
                        3: "WINDOWS_CUI",
                        7: "POSIX_CUI",
                        9: "WINDOWS_CE_GUI",
                        10: "EFI_APPLICATION",
                    }.get(subsys_code, f"UNKNOWN_0x{subsys_code:X}")

                # Check Export Directory for DLL name
                export_name = cls._parse_pe_export_name(data, e_lfanew, opt_hdr_size, magic)

                if machine == cls.PE_MACHINE_I386:
                    return (BinaryFormat.PE32, TargetArchitecture.X86, TargetOS.WINDOWS, machine, subsystem, export_name)
                elif machine == cls.PE_MACHINE_AMD64:
                    return (BinaryFormat.PE32_PLUS, TargetArchitecture.X64, TargetOS.WINDOWS, machine, subsystem, export_name)
                elif machine == cls.PE_MACHINE_ARM64:
                    return (BinaryFormat.PE32_PLUS, TargetArchitecture.ARM64, TargetOS.WINDOWS, machine, subsystem, export_name)
                elif machine == cls.PE_MACHINE_ARMNT:
                    return (BinaryFormat.PE32, TargetArchitecture.ARM, TargetOS.WINDOWS, machine, subsystem, export_name)
                elif machine == cls.PE_MACHINE_IA64:
                    return (BinaryFormat.PE32_PLUS, TargetArchitecture.IA64, TargetOS.WINDOWS, machine, subsystem, export_name)
                else:
                    fmt = BinaryFormat.PE32_PLUS if magic == 0x20B else BinaryFormat.PE32
                    return (fmt, TargetArchitecture.UNKNOWN, TargetOS.WINDOWS, machine, subsystem, export_name)

        # 2. Linux ELF Check
        if data[:4] == b"\x7fELF":
            ei_class = data[4]
            if len(data) >= 20:
                e_machine = struct.unpack_from("<H", data, 18)[0]
                fmt = BinaryFormat.ELF64 if ei_class == 2 else BinaryFormat.ELF32
                if e_machine == cls.ELF_MACHINE_386:
                    return (fmt, TargetArchitecture.X86, TargetOS.LINUX, e_machine, "ELF_EXECUTABLE", None)
                elif e_machine == cls.ELF_MACHINE_X86_64:
                    return (fmt, TargetArchitecture.X64, TargetOS.LINUX, e_machine, "ELF_EXECUTABLE", None)
                elif e_machine == cls.ELF_MACHINE_AARCH64:
                    return (fmt, TargetArchitecture.ARM64, TargetOS.LINUX, e_machine, "ELF_EXECUTABLE", None)
                elif e_machine == cls.ELF_MACHINE_ARM:
                    return (fmt, TargetArchitecture.ARM, TargetOS.LINUX, e_machine, "ELF_EXECUTABLE", None)
                return (fmt, TargetArchitecture.UNKNOWN, TargetOS.LINUX, e_machine, "ELF_EXECUTABLE", None)

        # 3. macOS Mach-O Check
        if len(data) >= 8:
            magic = struct.unpack_from(">I", data, 0)[0]
            magic_le = struct.unpack_from("<I", data, 0)[0]
            if magic in (0xFEEDFACE, 0xFEEDFACF) or magic_le in (0xFEEDFACE, 0xFEEDFACF):
                is_le = magic_le in (0xFEEDFACE, 0xFEEDFACF)
                is_64 = (magic_le == 0xFEEDFACF) if is_le else (magic == 0xFEEDFACF)
                cputype = struct.unpack_from("<I" if is_le else ">I", data, 4)[0]
                fmt = BinaryFormat.MACHO64 if is_64 else BinaryFormat.MACHO32

                if cputype == cls.MACHO_CPU_X86:
                    return (fmt, TargetArchitecture.X86, TargetOS.OSX, cputype, "MACHO_BINARY", None)
                elif cputype == cls.MACHO_CPU_X86_64:
                    return (fmt, TargetArchitecture.X64, TargetOS.OSX, cputype, "MACHO_BINARY", None)
                elif cputype == cls.MACHO_CPU_ARM64:
                    return (fmt, TargetArchitecture.ARM64, TargetOS.OSX, cputype, "MACHO_BINARY", None)
                elif cputype == cls.MACHO_CPU_ARM:
                    return (fmt, TargetArchitecture.ARM, TargetOS.OSX, cputype, "MACHO_BINARY", None)
                return (fmt, TargetArchitecture.UNKNOWN, TargetOS.OSX, cputype, "MACHO_BINARY", None)

        return (BinaryFormat.RAW_BINARY, TargetArchitecture.UNKNOWN, TargetOS.UNKNOWN, 0, None, None)

    @classmethod
    def _parse_pe_export_name(
        cls, data: bytes, e_lfanew: int, opt_hdr_size: int, magic: int
    ) -> Optional[str]:
        """Parses the Export Directory table to extract the declared DLL module name."""
        try:
            dd_offset = e_lfanew + 24 + (112 if magic == 0x20B else 96)
            if dd_offset + 8 > len(data):
                return None
            export_rva, export_size = struct.unpack_from("<II", data, dd_offset)
            if export_rva == 0 or export_size == 0:
                return None

            export_file_offset = cls.rva_to_file_offset(data, export_rva)
            if export_file_offset is None or export_file_offset + 40 > len(data):
                return None

            name_rva = struct.unpack_from("<I", data, export_file_offset + 12)[0]
            if name_rva == 0:
                return None
            name_file_offset = cls.rva_to_file_offset(data, name_rva)
            if name_file_offset is None or name_file_offset >= len(data):
                return None

            # Read null-terminated ASCII string up to 256 bytes
            end_idx = data.find(b"\x00", name_file_offset, name_file_offset + 256)
            if end_idx != -1:
                return data[name_file_offset:end_idx].decode("ascii", errors="ignore")
        except Exception:
            pass
        return None

    @classmethod
    def rva_to_file_offset(cls, data: bytes, rva: int) -> Optional[int]:
        """Maps Relative Virtual Address (RVA) to physical raw file offset with safe bounds checks."""
        if len(data) < 64 or data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_table_offset = e_lfanew + 24 + opt_hdr_size

        for i in range(min(num_sections, 96)):
            sec_offset = sec_table_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break
            v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec_offset + 8)
            effective_vsize = max(v_size, raw_size)
            if v_addr <= rva < v_addr + effective_vsize:
                offset_in_sec = rva - v_addr
                if offset_in_sec < raw_size:
                    candidate = raw_ptr + offset_in_sec
                    if candidate < len(data):
                        return candidate
        return None

    @classmethod
    def calculate_pe_size(cls, data: bytes, start_offset: int = 0) -> Optional[int]:
        """Calculates physical PE binary file size based on section headers and overlays."""
        if len(data) < start_offset + 64 or data[start_offset : start_offset + 2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, start_offset + 0x3C)[0]
        if e_lfanew + 24 > len(data) - start_offset:
            return None
        nt_offset = start_offset + e_lfanew
        if data[nt_offset : nt_offset + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack_from("<H", data, nt_offset + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, nt_offset + 20)[0]
        if num_sections > 96:
            return None

        sec_table_offset = nt_offset + 24 + opt_hdr_size
        max_extent = sec_table_offset + (num_sections * 40)

        for i in range(num_sections):
            sec_offset = sec_table_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break
            raw_size, raw_ptr = struct.unpack_from("<II", data, sec_offset + 16)
            extent = raw_ptr + raw_size
            if extent > max_extent:
                max_extent = extent

        return min(max_extent, len(data) - start_offset)

    @classmethod
    def decompress_payload(cls, data: bytes) -> Tuple[bytes, bool, int]:
        """
        Attempts automatic decompression of embedded payload streams
        (Costura DeflateStream, zlib, gzip, or raw deflate).
        """
        if len(data) < 4:
            return data, False, len(data)

        # 1. Costura DeflateStream: 4-byte uncompressed length prefix + Deflate stream
        try:
            expected_len = struct.unpack_from("<I", data, 0)[0]
            if 0 < expected_len <= cls.MAX_PAYLOAD_SIZE:
                decomp = zlib.decompress(data[4:], -zlib.MAX_WBITS)
                if len(decomp) == expected_len or abs(len(decomp) - expected_len) < 16:
                    return decomp, True, len(data)
        except Exception:
            pass

        # 2. Gzip Header (\x1f\x8b\x08)
        if data[:3] == b"\x1f\x8b\x08":
            try:
                decomp = gzip.decompress(data)
                if len(decomp) <= cls.MAX_PAYLOAD_SIZE:
                    return decomp, True, len(data)
            except Exception:
                pass

        # 3. Zlib Header (\x78\x9c, \x78\x01, \x78\xda)
        if data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
            try:
                decomp = zlib.decompress(data)
                if len(decomp) <= cls.MAX_PAYLOAD_SIZE:
                    return decomp, True, len(data)
            except Exception:
                pass

        # 4. Raw Deflate Stream without header
        try:
            decomp = zlib.decompress(data, -zlib.MAX_WBITS)
            if len(decomp) <= cls.MAX_PAYLOAD_SIZE and (decomp[:2] == b"MZ" or decomp[:4] == b"\x7fELF"):
                return decomp, True, len(data)
        except Exception:
            pass

        return data, False, len(data)

    @classmethod
    def infer_declared_architecture(cls, name: str) -> Optional[TargetArchitecture]:
        """Infers target architecture declared by filename or manifest naming."""
        lowered = name.lower()
        if "arm64" in lowered or "aarch64" in lowered:
            return TargetArchitecture.ARM64
        elif "costura64" in lowered or "win-x64" in lowered or "linux-x64" in lowered or "osx-x64" in lowered or "x64" in lowered or "win64" in lowered or "amd64" in lowered:
            return TargetArchitecture.X64
        elif "costura32" in lowered or "win-x86" in lowered or "linux-x86" in lowered or "x86" in lowered or "win32" in lowered or "i386" in lowered:
            return TargetArchitecture.X86
        elif "arm" in lowered:
            return TargetArchitecture.ARM
        elif "ia64" in lowered:
            return TargetArchitecture.IA64
        return None

    @classmethod
    def infer_declared_os(cls, name: str) -> TargetOS:
        """Infers target OS declared by filename or manifest naming."""
        lowered = name.lower()
        if "linux" in lowered or ".so" in lowered:
            return TargetOS.LINUX
        elif "osx" in lowered or "darwin" in lowered or ".dylib" in lowered:
            return TargetOS.OSX
        elif "win" in lowered or "costura" in lowered or ".dll" in lowered or ".exe" in lowered:
            return TargetOS.WINDOWS
        return TargetOS.ANY

    @classmethod
    def scan_and_demux(cls, data: bytes) -> NativeDemuxerTelemetry:
        """
        Scans binary data for embedded multi-architecture native payloads across
        manifest resources, directory naming patterns, custom PE sections, and overlay streams.
        """
        if len(data) > cls.MAX_PAYLOAD_SIZE:
            raise SecurityError(f"Binary size ({len(data)} bytes) exceeds maximum safety limit ({cls.MAX_PAYLOAD_SIZE} bytes).")

        telemetry = NativeDemuxerTelemetry()
        discovered_payloads: List[NativePayloadInfo] = []
        seen_hashes: Set[str] = set()

        # 1. Discover resource string references
        found_string_matches: List[Tuple[str, TargetArchitecture, TargetOS, int, int]] = []
        for pat in cls.RESOURCE_PATTERNS:
            for m in pat.finditer(data):
                try:
                    matched_str = m.group(0).decode("latin1", errors="ignore")
                    declared_arch = cls.infer_declared_architecture(matched_str)
                    declared_os = cls.infer_declared_os(matched_str)
                    found_string_matches.append(
                        (matched_str, declared_arch or TargetArchitecture.UNKNOWN, declared_os, m.start(), m.end())
                    )
                except Exception:
                    pass

        # 2. Carve embedded PE binaries (Scan for MZ headers)
        mz_offsets = [m.start() for m in re.finditer(rb"MZ", data)]
        for offset in mz_offsets:
            if offset == 0:
                continue  # Skip outer carrier binary itself
            pe_len = cls.calculate_pe_size(data, start_offset=offset)
            if pe_len and pe_len >= 512:
                raw_chunk = data[offset : offset + pe_len]
                h_sha256 = hashlib.sha256(raw_chunk).hexdigest()
                if h_sha256 in seen_hashes:
                    continue
                seen_hashes.add(h_sha256)

                fmt, arch, os_type, machine, subsys, exp_name = cls.inspect_binary_format(raw_chunk)
                if fmt != BinaryFormat.RAW_BINARY:
                    name_candidate = exp_name or f"carved_native_0x{offset:X}.dll"
                    declared_arch = None
                    # Correlate with discovered resource names if nearby or matched by export name
                    for s_name, s_arch, s_os, s_start, s_end in found_string_matches:
                        if exp_name and exp_name.lower() in s_name.lower():
                            name_candidate = s_name
                            declared_arch = s_arch
                            break
                        elif 0 <= offset - s_end <= 512 or 0 <= offset - s_start <= 512:
                            name_candidate = s_name
                            declared_arch = s_arch
                            break

                    mismatch = False
                    mismatch_desc = None
                    if declared_arch and declared_arch != TargetArchitecture.UNKNOWN and declared_arch != arch:
                        mismatch = True
                        mismatch_desc = f"Declared architecture '{declared_arch.value}' diverges from actual binary machine '0x{machine:04X}' ({arch.value})."

                    payload = NativePayloadInfo(
                        name=name_candidate,
                        target_arch=arch,
                        declared_arch=declared_arch,
                        target_os=os_type,
                        format=fmt,
                        source=DemuxSource.OVERLAY_CARVED if offset > 1024 else DemuxSource.PE_SECTION,
                        size_bytes=len(raw_chunk),
                        sha256=h_sha256,
                        sha1=hashlib.sha1(raw_chunk).hexdigest(),
                        md5=hashlib.md5(raw_chunk).hexdigest(),
                        entropy=calculate_entropy(raw_chunk),
                        is_pe=True,
                        machine_code=machine,
                        machine_hex=f"0x{machine:04X}",
                        subsystem=subsys,
                        export_name=exp_name,
                        compressed=False,
                        compressed_size_bytes=len(raw_chunk),
                        compression_ratio=1.0,
                        mismatch_detected=mismatch,
                        mismatch_details=mismatch_desc,
                        raw_data=raw_chunk,
                    )
                    discovered_payloads.append(payload)

        # 3. Discover compressed embedded streams (e.g., Costura compressed blobs)
        # Search for DeflateStream prefixes preceding embedded resource declarations
        for match_str, decl_arch, decl_os, _, _ in found_string_matches:
            # Look for compressed payload buffer by searching around the string or standard Costura markers
            pass

        # 4. Check for embedded compressed Costura payloads by searching for 4-byte len + Deflate
        for m in re.finditer(rb"\x00\x00(costura(?:32|64)?\.[a-zA-Z0-9_\-\.]+\.(?:dll|pdb)(?:\.compressed)?)", data, re.IGNORECASE):
            r_name = m.group(1).decode("latin1")
            decl_arch = cls.infer_declared_architecture(r_name)
            decl_os = cls.infer_declared_os(r_name)

            # Look forward for compressed chunk
            chunk_start = m.end() + 1
            if chunk_start + 8 < len(data):
                # Search up to 1024 bytes ahead for 4-byte uncompressed length prefix
                for probe_off in range(chunk_start, min(chunk_start + 128, len(data) - 8)):
                    expected_len = struct.unpack_from("<I", data, probe_off)[0]
                    if 512 < expected_len <= cls.MAX_PAYLOAD_SIZE:
                        try:
                            decomp = zlib.decompress(data[probe_off + 4 : probe_off + 4 + 2 * expected_len], -zlib.MAX_WBITS)
                            if len(decomp) == expected_len or abs(len(decomp) - expected_len) < 16:
                                d_sha256 = hashlib.sha256(decomp).hexdigest()
                                if d_sha256 not in seen_hashes:
                                    seen_hashes.add(d_sha256)
                                    fmt, arch, os_t, machine, subsys, exp_n = cls.inspect_binary_format(decomp)
                                    mismatch = (decl_arch is not None and decl_arch != TargetArchitecture.UNKNOWN and decl_arch != arch)
                                    mismatch_desc = f"Resource '{r_name}' declared '{decl_arch.value}' but decompressed binary is '0x{machine:04X}' ({arch.value})." if mismatch else None

                                    clean_name = r_name
                                    if clean_name.endswith(".compressed"):
                                        clean_name = clean_name[:-11]

                                    p_info = NativePayloadInfo(
                                        name=clean_name,
                                        target_arch=arch,
                                        declared_arch=decl_arch,
                                        target_os=os_t,
                                        format=fmt,
                                        source=DemuxSource.COSTURA_NATIVE if "costura" in r_name.lower() else DemuxSource.EMBEDDED_COMPRESSED,
                                        size_bytes=len(decomp),
                                        sha256=d_sha256,
                                        sha1=hashlib.sha1(decomp).hexdigest(),
                                        md5=hashlib.md5(decomp).hexdigest(),
                                        entropy=calculate_entropy(decomp),
                                        is_pe=fmt in (BinaryFormat.PE32, BinaryFormat.PE32_PLUS),
                                        machine_code=machine,
                                        machine_hex=f"0x{machine:04X}",
                                        subsystem=subsys,
                                        export_name=exp_n,
                                        compressed=True,
                                        compressed_size_bytes=expected_len,
                                        compression_ratio=round(len(decomp) / max(expected_len, 1), 4),
                                        mismatch_detected=mismatch,
                                        mismatch_details=mismatch_desc,
                                        raw_data=decomp,
                                    )
                                    discovered_payloads.append(p_info)
                                break
                        except Exception:
                            continue

        # Aggregate telemetry
        telemetry.payloads = discovered_payloads
        telemetry.total_payloads = len(discovered_payloads)
        telemetry.architectures_found = sorted(list({p.target_arch.value for p in discovered_payloads if p.target_arch != TargetArchitecture.UNKNOWN}))
        telemetry.platforms_found = sorted(list({p.target_os.value for p in discovered_payloads if p.target_os != TargetOS.UNKNOWN}))
        telemetry.sources_found = sorted(list({p.source.value for p in discovered_payloads}))
        telemetry.has_architecture_mismatch = any(p.mismatch_detected for p in discovered_payloads)
        telemetry.mismatch_count = sum(1 for p in discovered_payloads if p.mismatch_detected)

        for p in discovered_payloads:
            if p.mismatch_detected and p.mismatch_details:
                telemetry.anomalies.append(p.mismatch_details)

        telemetry.is_multi_arch = len(telemetry.architectures_found) >= 2 or (len(telemetry.architectures_found) == 1 and len(found_string_matches) > 0)
        if len(telemetry.architectures_found) >= 2:
            telemetry.confidence = "HIGH"
        elif len(telemetry.architectures_found) == 1 or len(found_string_matches) >= 1:
            telemetry.confidence = "MEDIUM"
        else:
            telemetry.confidence = "NONE"

        return telemetry

    @classmethod
    def route_for_platform(
        cls,
        payloads: List[NativePayloadInfo],
        requested_os: Union[str, TargetOS],
        requested_arch: Union[str, TargetArchitecture],
    ) -> PlatformRouteResult:
        """
        Simulates runtime platform resolution and dynamic loader routing for a requested OS and CPU architecture.
        """
        if isinstance(requested_os, str):
            try:
                t_os = TargetOS(requested_os.lower())
            except ValueError:
                t_os = TargetOS.UNKNOWN
        else:
            t_os = requested_os

        if isinstance(requested_arch, str):
            try:
                t_arch = TargetArchitecture(requested_arch.lower())
            except ValueError:
                t_arch = TargetArchitecture.UNKNOWN
        else:
            t_arch = requested_arch

        # 1. Exact match on both OS and Architecture
        for p in payloads:
            if (p.target_os == t_os or p.target_os == TargetOS.ANY) and p.target_arch == t_arch:
                return PlatformRouteResult(
                    requested_os=t_os,
                    requested_arch=t_arch,
                    matched_payload=p.to_dict(),
                    resolution_status="RESOLVED_EXACT",
                    fallback_chain=[f"{t_os.value}-{t_arch.value} (Exact)"],
                    reason=f"Matched exact architecture '{t_arch.value}' payload '{p.name}' (Format: {p.format.value}).",
                )

        fallback_chain: List[str] = [f"{t_os.value}-{t_arch.value}"]

        # 2. Windows Fallback Chain
        if t_os == TargetOS.WINDOWS:
            # ARM64 Windows can run x64 emulation, then x86 emulation
            if t_arch == TargetArchitecture.ARM64:
                fallback_chain.append("win-x64 (Windows on ARM x64 Emulation)")
                for p in payloads:
                    if (p.target_os == TargetOS.WINDOWS or p.target_os == TargetOS.ANY) and p.target_arch == TargetArchitecture.X64:
                        return PlatformRouteResult(
                            requested_os=t_os,
                            requested_arch=t_arch,
                            matched_payload=p.to_dict(),
                            resolution_status="RESOLVED_FALLBACK",
                            fallback_chain=fallback_chain,
                            reason=f"Resolved via Windows on ARM x64 emulation fallback to '{p.name}'.",
                        )
                fallback_chain.append("win-x86 (WoW64 / x86 Emulation)")
                for p in payloads:
                    if (p.target_os == TargetOS.WINDOWS or p.target_os == TargetOS.ANY) and p.target_arch == TargetArchitecture.X86:
                        return PlatformRouteResult(
                            requested_os=t_os,
                            requested_arch=t_arch,
                            matched_payload=p.to_dict(),
                            resolution_status="RESOLVED_FALLBACK",
                            fallback_chain=fallback_chain,
                            reason=f"Resolved via Windows on ARM x86 emulation fallback to '{p.name}'.",
                        )
            # x64 Windows can run x86 via WoW64
            elif t_arch == TargetArchitecture.X64:
                fallback_chain.append("win-x86 (WoW64 Compatibility Fallback)")
                for p in payloads:
                    if (p.target_os == TargetOS.WINDOWS or p.target_os == TargetOS.ANY) and p.target_arch == TargetArchitecture.X86:
                        return PlatformRouteResult(
                            requested_os=t_os,
                            requested_arch=t_arch,
                            matched_payload=p.to_dict(),
                            resolution_status="RESOLVED_FALLBACK",
                            fallback_chain=fallback_chain,
                            reason=f"Resolved via Windows 64-bit WoW64 compatibility fallback to '{p.name}'.",
                        )

        # 3. macOS Fallback Chain (ARM64 can run x64 via Rosetta 2)
        elif t_os == TargetOS.OSX and t_arch == TargetArchitecture.ARM64:
            fallback_chain.append("osx-x64 (Rosetta 2 Binary Translation)")
            for p in payloads:
                if (p.target_os == TargetOS.OSX or p.target_os == TargetOS.ANY) and p.target_arch == TargetArchitecture.X64:
                    return PlatformRouteResult(
                        requested_os=t_os,
                        requested_arch=t_arch,
                        matched_payload=p.to_dict(),
                        resolution_status="RESOLVED_FALLBACK",
                        fallback_chain=fallback_chain,
                        reason=f"Resolved via macOS Rosetta 2 binary translation fallback to '{p.name}'.",
                    )

        # Missing Architecture
        return PlatformRouteResult(
            requested_os=t_os,
            requested_arch=t_arch,
            matched_payload=None,
            resolution_status="UNRESOLVED_MISSING_ARCH",
            fallback_chain=fallback_chain,
            reason=f"No compatible native binary found for requested platform '{t_os.value}-{t_arch.value}'. Available architectures: {[p.target_arch.value for p in payloads]}.",
        )
