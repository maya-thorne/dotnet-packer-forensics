"""
CLI Metadata Anti-Tamper Forensic Unpacker & Bytecode Decrypter.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from ..dotnet_analyzer import DotNetAnalyzer
from .antitamper_jit import (
    AntiTamperDecrypter,
    CorILMethodParser,
    JITDumperInterface,
)
from .antitamper_models import (
    AntiTamperDetectionResult,
    AntiTamperSectionInfo,
    AntiTamperType,
    CorILMethodFormat,
    JITMethodRecord,
    SecurityError,
    token_to_hex,
)


class AntiTamperUnpacker:
    """Forensic orchestrator for .NET Anti-Tamper heuristic detection, decryption, and PE restoration."""

    ANTITAMPER_SECTION_NAMES = [
        b".tamper",
        b".cctor",
        b".confuser",
        b".atamp",
        b".jit",
    ]

    JIT_HOOK_SIGNATURES = [
        b"compileMethod",
        b"clrjit.dll",
        b"mscorjit.dll",
        b"ICorJitCompiler",
        b"VirtualProtect",
        b"AntiTamper",
        b"JITHook",
        b"InitializeAntiTamper",
    ]

    CONFUSEREX_MARKERS = [
        b"Confuser.Runtime.AntiTamper",
        b"AntiTamperNormal",
        b"AntiTamperJIT",
    ]

    MAX_PAYLOAD_SIZE = 100 * 1024 * 1024  # 100 MB safety limit

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """Runs heuristic static detection for CLI metadata anti-tamper protections."""
        indicators: List[Dict[str, Any]] = []
        detected_types: List[str] = []
        corrupted_streams: List[str] = []
        jit_signatures: List[str] = []
        matched_sections: List[str] = []

        is_pe = len(data) >= 64 and data[:2] == b"MZ"
        if not is_pe:
            return AntiTamperDetectionResult(
                is_tampered=False,
                confidence="NONE",
                indicators=[{"category": "PE", "message": "Non-PE input binary"}],
            ).to_dict()

        entropy = DotNetAnalyzer.calculate_entropy(data)

        # 1. Scan for known AntiTamper section names and high-entropy sections
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0x80
        if e_lfanew + 24 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            sec_table_start = e_lfanew + 24 + opt_hdr_size

            for i in range(num_sections):
                s_off = sec_table_start + (i * 40)
                if s_off + 40 > len(data):
                    break
                sec_name = data[s_off : s_off + 8].strip(b"\x00")
                sec_name_str = sec_name.decode("latin1", errors="ignore")

                for marker in cls.ANTITAMPER_SECTION_NAMES:
                    if marker in sec_name:
                        matched_sections.append(sec_name_str)
                        indicators.append({
                            "category": "SECTION",
                            "severity": "HIGH",
                            "message": f"Identified anti-tamper PE section: {sec_name_str}",
                        })
                        if AntiTamperType.CUSTOM_SECTION.value not in detected_types:
                            detected_types.append(AntiTamperType.CUSTOM_SECTION.value)

                rsize = struct.unpack_from("<I", data, s_off + 16)[0]
                rptr = struct.unpack_from("<I", data, s_off + 20)[0]
                if rptr + rsize <= len(data) and rsize > 0:
                    sec_entropy = DotNetAnalyzer.calculate_entropy(data[rptr : rptr + rsize])
                    if sec_entropy > 7.4 and sec_name_str not in (".rsrc", ".reloc"):
                        indicators.append({
                            "category": "ENTROPY",
                            "severity": "MEDIUM",
                            "message": f"High entropy ({sec_entropy}) in section '{sec_name_str}', likely encrypted payload",
                        })

        # 2. Scan for JIT Hooking and Memory Protection imports / signatures
        for sig in cls.JIT_HOOK_SIGNATURES:
            if sig in data:
                sig_str = sig.decode("latin1")
                jit_signatures.append(sig_str)
                indicators.append({
                    "category": "JIT_HOOK",
                    "severity": "HIGH",
                    "message": f"Detected CLR JIT-hook signature: {sig_str}",
                })
                if AntiTamperType.JIT_HOOK.value not in detected_types:
                    detected_types.append(AntiTamperType.JIT_HOOK.value)

        # 3. Scan for ConfuserEx AntiTamper runtime signatures
        for c_sig in cls.CONFUSEREX_MARKERS:
            if c_sig in data:
                c_str = c_sig.decode("latin1")
                indicators.append({
                    "category": "CONFUSEREX",
                    "severity": "HIGH",
                    "message": f"Identified ConfuserEx AntiTamper runtime marker: {c_str}",
                })
                t_val = (
                    AntiTamperType.CONFUSEREX_JIT.value
                    if b"JIT" in c_sig
                    else AntiTamperType.CONFUSEREX_NORMAL.value
                )
                if t_val not in detected_types:
                    detected_types.append(t_val)

        # 4. Scan for Corrupted CLI Metadata Streams (#~, #-, #Strings, #US)
        has_tilde = b"#~" in data
        has_minus = b"#-" in data
        has_strings = b"#Strings" in data
        has_us = b"#US" in data

        if has_minus and not has_tilde:
            corrupted_streams.append("#- (Uncompressed Metadata Table)")
            indicators.append({
                "category": "METADATA_STREAM",
                "severity": "MEDIUM",
                "message": "Stream '#~' stripped and replaced with uncompressed '#-' stream",
            })
            if AntiTamperType.CORRUPTED_METADATA.value not in detected_types:
                detected_types.append(AntiTamperType.CORRUPTED_METADATA.value)

        if not has_strings and not has_us and (has_tilde or has_minus):
            corrupted_streams.append("Missing #Strings and #US")
            indicators.append({
                "category": "METADATA_STREAM",
                "severity": "HIGH",
                "message": "Standard #Strings and #US streams completely stripped",
            })
            if AntiTamperType.CORRUPTED_METADATA.value not in detected_types:
                detected_types.append(AntiTamperType.CORRUPTED_METADATA.value)

        # 5. Evaluate overall confidence score
        score = 0
        if matched_sections:
            score += 3
        if jit_signatures:
            score += 3
        if len(corrupted_streams) > 0:
            score += 2
        if any("CONFUSEREX" in t for t in detected_types):
            score += 4

        confidence = "NONE"
        is_tampered = False

        if score >= 6:
            confidence = "HIGH"
            is_tampered = True
        elif score >= 3:
            confidence = "MEDIUM"
            is_tampered = True
        elif score >= 1:
            confidence = "LOW"
            is_tampered = True

        return AntiTamperDetectionResult(
            is_tampered=is_tampered,
            confidence=confidence,
            detected_types=detected_types,
            indicators=indicators,
            encrypted_methods_count=len(matched_sections) * 5,  # Heuristic estimate
            corrupted_streams=corrupted_streams,
            jit_signatures=jit_signatures,
            anti_tamper_sections=matched_sections,
            entropy=entropy,
        ).to_dict()

    @classmethod
    def extract_encrypted_containers(cls, data: bytes) -> List[AntiTamperSectionInfo]:
        """Locates and extracts sections associated with anti-tamper encrypted method payloads."""
        if len(data) < 64 or data[:2] != b"MZ":
            return []

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0x80
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return []

        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_table_start = e_lfanew + 24 + opt_hdr_size

        containers: List[AntiTamperSectionInfo] = []
        for i in range(num_sections):
            s_off = sec_table_start + (i * 40)
            if s_off + 40 > len(data):
                break
            sec_name_bytes = data[s_off : s_off + 8].strip(b"\x00")
            sec_name = sec_name_bytes.decode("latin1", errors="ignore")
            vsize = struct.unpack_from("<I", data, s_off + 8)[0]
            vaddr = struct.unpack_from("<I", data, s_off + 12)[0]
            rsize = struct.unpack_from("<I", data, s_off + 16)[0]
            rptr = struct.unpack_from("<I", data, s_off + 20)[0]

            if rptr + rsize <= len(data) and rsize > 0:
                sec_bytes = data[rptr : rptr + rsize]
                sec_entropy = DotNetAnalyzer.calculate_entropy(sec_bytes)
                is_target = any(m in sec_name_bytes for m in cls.ANTITAMPER_SECTION_NAMES) or (
                    sec_entropy > 7.3 and sec_name not in (".rsrc", ".reloc", ".text")
                )

                if is_target:
                    containers.append(
                        AntiTamperSectionInfo(
                            name=sec_name,
                            virtual_address=vaddr,
                            virtual_size=vsize,
                            raw_pointer=rptr,
                            raw_size=rsize,
                            entropy=sec_entropy,
                            is_encrypted=sec_entropy > 6.0,
                        )
                    )

        return containers

    @classmethod
    def decrypt_and_restore_methods(
        cls,
        data: bytes,
        jit_records: Optional[List[JITMethodRecord]] = None,
        master_seed: int = 0x5A5A5A5A,
    ) -> List[JITMethodRecord]:
        """
        Decrypts anti-tampered methods or merges supplied in-memory JIT dump records.
        Applies LCG/token-keyed stream decryption on encrypted containers.
        """
        if jit_records and len(jit_records) > 0:
            return jit_records

        containers = cls.extract_encrypted_containers(data)
        records: List[JITMethodRecord] = []
        method_idx = 1

        for c in containers:
            if c.raw_pointer + c.raw_size <= len(data):
                chunk = bytearray(data[c.raw_pointer : c.raw_pointer + c.raw_size])
                # Attempt LCG stream decryption
                decrypted = AntiTamperDecrypter.decrypt_lcg_stream(bytes(chunk), seed=master_seed)
                # Parse decrypted chunk for CorILMethod headers
                dumped = JITDumperInterface.ingest_memory_dump(
                    decrypted, base_address=c.virtual_address
                )
                if dumped:
                    records.extend(dumped)
                else:
                    # Attempt token-keyed XOR scanning
                    for step_token in range(0x06000001, 0x06000010):
                        token_dec = AntiTamperDecrypter.decrypt_token_keyed_xor(
                            bytes(chunk[:256]), token=step_token, salt=master_seed
                        )
                        hdr = CorILMethodParser.parse_method_header(token_dec)
                        if hdr and hdr.code_size > 0:
                            is_valid, _ = CorILMethodParser.validate_cil_instructions(hdr.code_bytes)
                            if is_valid:
                                records.append(
                                    JITMethodRecord(
                                        token=step_token,
                                        rid=step_token & 0x00FFFFFF,
                                        name=f"RecoveredMethod_{step_token:08X}",
                                        rva=c.virtual_address,
                                        format=hdr.format.value,
                                        code_size=hdr.code_size,
                                        max_stack=hdr.max_stack,
                                        local_var_sig_tok=hdr.local_var_sig_tok,
                                        cil_bytes=hdr.code_bytes,
                                        raw_method_body=hdr.raw_body,
                                        verified_cil=True,
                                    )
                                )
                                break
                # Zeroize temporary decryption buffer
                AntiTamperDecrypter.zeroize_buffer(chunk)

        return records

    @classmethod
    def restore_assembly(
        cls,
        data: bytes,
        restored_methods: List[JITMethodRecord],
        section_name: str = ".antitamper",
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Reconstructs PE binary by synthesizing an aligned .antitamper section
        containing all decrypted CIL method bodies, updating headers, and neutralizing hooks.
        """
        if len(data) > cls.MAX_PAYLOAD_SIZE:
            raise SecurityError(f"Input binary ({len(data)} bytes) exceeds limit")

        buf = bytearray(data)
        e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0] if len(buf) >= 0x40 else 0x80

        if e_lfanew + 0xF8 > len(buf):
            raise SecurityError("PE header boundary truncated")

        num_sections = struct.unpack_from("<H", buf, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", buf, e_lfanew + 20)[0]
        sect_table_offset = e_lfanew + 24 + opt_hdr_size

        if sect_table_offset + (num_sections + 1) * 40 > len(buf):
            raise SecurityError("Insufficient header space for section table expansion")

        # Pack all restored method bodies into payload buffer with 4-byte alignment
        method_payload = bytearray()
        method_rvas: Dict[int, int] = {}

        # Get last section metrics to calculate new virtual address and raw offset
        last_sect_off = sect_table_offset + (num_sections - 1) * 40
        last_va = struct.unpack_from("<I", buf, last_sect_off + 12)[0]
        last_vsize = struct.unpack_from("<I", buf, last_sect_off + 8)[0]
        last_raw_ptr = struct.unpack_from("<I", buf, last_sect_off + 20)[0]
        last_raw_size = struct.unpack_from("<I", buf, last_sect_off + 16)[0]

        new_va = (last_va + last_vsize + 0x1FFF) & ~0x1FFF
        new_raw_ptr = (last_raw_ptr + last_raw_size + 0x1FF) & ~0x1FF

        for m in restored_methods:
            # Align method to 4-byte boundary
            while len(method_payload) % 4 != 0:
                method_payload.append(0)
            method_rva = new_va + len(method_payload)
            method_rvas[m.token] = method_rva
            method_payload.extend(m.raw_method_body)

        if not method_payload:
            # Fallback tiny body (ret) if no methods were unpacked
            method_payload.extend(CorILMethodParser.build_tiny_method(b"\x2A"))

        raw_size = (len(method_payload) + 0x1FF) & ~0x1FF

        # Write new section header
        new_sect_off = sect_table_offset + num_sections * 40
        sect_hdr = bytearray(40)
        encoded_name = section_name.encode("ascii")[:8].ljust(8, b"\x00")
        sect_hdr[0:8] = encoded_name
        struct.pack_into("<I", sect_hdr, 8, len(method_payload))
        struct.pack_into("<I", sect_hdr, 12, new_va)
        struct.pack_into("<I", sect_hdr, 16, raw_size)
        struct.pack_into("<I", sect_hdr, 20, new_raw_ptr)
        struct.pack_into("<I", sect_hdr, 36, 0x60000020)  # CODE | EXECUTE | READ
        buf[new_sect_off : new_sect_off + 40] = sect_hdr

        # Update number of sections
        struct.pack_into("<H", buf, e_lfanew + 6, num_sections + 1)

        # Update SizeOfImage
        opt_base = e_lfanew + 24
        new_image_size = (new_va + raw_size + 0x1FFF) & ~0x1FFF
        struct.pack_into("<I", buf, opt_base + 56, new_image_size)

        # Append section data to buffer
        if len(buf) < new_raw_ptr:
            buf.extend(b"\x00" * (new_raw_ptr - len(buf)))
        buf.extend(method_payload)
        if len(method_payload) < raw_size:
            buf.extend(b"\x00" * (raw_size - len(method_payload)))

        # Neutralize ConfuserEx/AntiTamper .cctor hook if present in .text
        for sig in cls.JIT_HOOK_SIGNATURES:
            idx = buf.find(sig)
            if idx != -1:
                # Nop out the signature string reference
                buf[idx : idx + len(sig)] = b"\x00" * len(sig)

        report = {
            "section_injected": section_name,
            "section_va": f"0x{new_va:08X}",
            "section_raw_size": raw_size,
            "methods_restored_count": len(restored_methods),
            "restored_pe_size": len(buf),
            "sha256": hashlib.sha256(buf).hexdigest(),
            "method_rva_map": {token_to_hex(k): f"0x{v:08X}" for k, v in method_rvas.items()},
        }

        return bytes(buf), report

    @classmethod
    def _safe_path(cls, real_output_dir: str, filename: str) -> str:
        """Validates that candidate filename resolves strictly within the output directory."""
        target = os.path.realpath(os.path.join(real_output_dir, filename))
        if not target.startswith(real_output_dir + os.sep) and target != real_output_dir:
            raise SecurityError(f"Path traversal detected: {filename}")
        return target

    @classmethod
    def unpack_to_directory(
        cls,
        data: bytes,
        output_dir: str,
        jit_dump_file: Optional[str] = None,
        master_seed: int = 0x5A5A5A5A,
    ) -> Dict[str, Any]:
        """
        Unpacks anti-tampered binary, writing restored executable, dumped methods JSON,
        individual raw CIL bytecode files, and forensic manifest safely to disk.
        """
        os.makedirs(output_dir, exist_ok=True)
        real_output_dir = os.path.realpath(output_dir)

        # 1. Ingest JIT dump if provided
        jit_records: List[JITMethodRecord] = []
        if jit_dump_file and os.path.exists(jit_dump_file):
            with open(jit_dump_file, "r", encoding="utf-8") as f:
                dump_content = f.read()
            jit_records = JITDumperInterface.ingest_json_dump(dump_content)

        # 2. Run detection and decrypt methods
        detect_res = cls.detect(data)
        restored_methods = cls.decrypt_and_restore_methods(
            data, jit_records=jit_records, master_seed=master_seed
        )

        # 3. Restore assembly
        rebuilt_pe, restore_report = cls.restore_assembly(data, restored_methods)

        # 4. Write restored binary
        rebuilt_path = cls._safe_path(real_output_dir, "restored_antitamper.exe")
        with open(rebuilt_path, "wb") as f:
            f.write(rebuilt_pe)

        # 5. Write dumped methods JSON
        dump_json_path = cls._safe_path(real_output_dir, "dumped_methods.json")
        with open(dump_json_path, "w", encoding="utf-8") as f:
            f.write(JITDumperInterface.export_jit_json(restored_methods))

        # 6. Write individual method CIL files
        methods_dir = cls._safe_path(real_output_dir, "methods")
        os.makedirs(methods_dir, exist_ok=True)
        for m in restored_methods:
            fname = f"method_{m.token:08X}.cil"
            m_path = cls._safe_path(methods_dir, fname)
            with open(m_path, "wb") as f:
                f.write(m.cil_bytes)

        # 7. Write manifest
        manifest_data = {
            "detection": detect_res,
            "restoration": restore_report,
            "methods_count": len(restored_methods),
            "restored_binary": "restored_antitamper.exe",
            "methods_catalog": "dumped_methods.json",
        }
        manifest_path = cls._safe_path(real_output_dir, "antitamper_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        return {
            "output_directory": real_output_dir,
            "restored_binary": rebuilt_path,
            "methods_count": len(restored_methods),
            "detection": detect_res,
            "restoration": restore_report,
        }
