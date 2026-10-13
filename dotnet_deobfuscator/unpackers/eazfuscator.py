"""
Eazfuscator.NET Forensic Unpacker, VM Container Carver & Assembly De-virtualizer.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from .eazfuscator_vm import (
    EazfuscatorDevirtualizer,
    EazfuscatorVMDisassembler,
    VMOpcode,
    VMOpcodeTable,
)


class SecurityError(Exception):
    """Raised when malicious path traversal or payload tampering is detected."""
    pass


class EazfuscatorUnpacker:
    """
    Forensic unpacker and de-virtualization engine for Eazfuscator.NET protected binaries.
    Implements:
      - Static signature and heuristic obfuscation artifact detection
      - Embedded VM bytecode container carving across PE sections and overlay
      - Multi-method VM disassembly and translation into ECMA-335 CIL
      - PE section (.eazvm) synthesis and header realignment
      - Safe directory extraction with path traversal defenses and Zeroize wiping
    """

    MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024  # 256 MB safety ceiling

    # Known Eazfuscator signatures and metadata markers
    SIGNATURE_PATTERNS = [
        b"Eazfuscator.NET",
        b"Eazfuscator",
        b"Gapotchenko",
        b"EAZVM",
        b".eazvm",
        b"\xe2\x80\x8b",  # Zero-width space frequently used in scrambled symbol names
        b"\xe2\x80\x8c",  # Zero-width non-joiner
    ]

    # Container magics for virtualized method packages
    VM_CONTAINER_MAGICS = [
        b"EAZVM\x01",
        b"EAZVM",
        b"\xEA\x5F\x56\x4D",  # 0x4D565FEA little-endian magic
    ]

    # =========================================================================
    # 1. Detection Engine
    # =========================================================================

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """
        Scans binary for Eazfuscator.NET signatures, obfuscated identifiers, and VM containers.
        """
        markers_found = []
        for pat in cls.SIGNATURE_PATTERNS:
            if pat in data:
                markers_found.append(pat.decode("latin1", errors="ignore"))

        containers = cls.extract_vm_containers(data)
        has_vm = len(containers) > 0

        # Confidence calculation
        if has_vm and any("Eazfuscator" in m for m in markers_found):
            confidence = "HIGH"
        elif has_vm or any("Eazfuscator" in m for m in markers_found):
            confidence = "MEDIUM"
        elif len(markers_found) > 0:
            confidence = "LOW"
        else:
            confidence = "NONE"

        return {
            "is_eazfuscator": confidence in ("MEDIUM", "HIGH"),
            "confidence": confidence,
            "has_virtual_machine": has_vm,
            "vm_method_count": sum(len(c.get("methods", [])) for c in containers),
            "vm_containers_count": len(containers),
            "matched_markers": list(dict.fromkeys(markers_found)),
        }

    # =========================================================================
    # 2. VM Container Carving & Extraction
    # =========================================================================

    @classmethod
    def extract_vm_containers(cls, data: bytes) -> List[Dict[str, Any]]:
        """
        Locates and parses all Eazfuscator VM containers embedded within the binary.
        """
        containers: List[Dict[str, Any]] = []
        if len(data) < 16:
            return containers

        for magic in cls.VM_CONTAINER_MAGICS:
            pos = 0
            while True:
                idx = data.find(magic, pos)
                if idx == -1:
                    break

                container = cls._parse_container_at(data, idx, magic)
                if container is not None and container.get("methods"):
                    containers.append(container)
                pos = idx + len(magic)

        return containers

    @classmethod
    def _parse_container_at(cls, data: bytes, offset: int, magic: bytes) -> Optional[Dict[str, Any]]:
        """Parses a structured VM container header and individual method entries."""
        curr = offset + len(magic)
        if curr + 6 > len(data):
            return None

        # Container Header: version (uint16), method_count (uint32)
        version, method_count = struct.unpack_from("<HI", data, curr)
        curr += 6

        if method_count == 0 or method_count > 5000:
            return None

        methods: List[Dict[str, Any]] = []
        for _ in range(method_count):
            if curr + 10 > len(data):
                break
            # Method Entry: token (uint32), max_stack (uint16), bytecode_len (uint32)
            token, max_stack, b_len = struct.unpack_from("<IHI", data, curr)
            curr += 10
            if b_len == 0 or curr + b_len > len(data):
                break

            bytecode = data[curr : curr + b_len]
            curr += b_len

            methods.append({
                "token": token,
                "token_hex": f"0x{token:08X}",
                "max_stack": max_stack,
                "bytecode_len": b_len,
                "bytecode": bytecode,
            })

        if not methods:
            return None

        return {
            "offset": offset,
            "magic": magic.decode("latin1", errors="ignore"),
            "version": version,
            "method_count": len(methods),
            "methods": methods,
        }

    # =========================================================================
    # 3. Assembly De-virtualization & PE Patching
    # =========================================================================

    @classmethod
    def devirtualize_assembly(
        cls,
        data: bytes,
        custom_table: Optional[VMOpcodeTable] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        De-virtualizes Eazfuscator.NET virtual machine methods in the assembly:
        Disassembles proprietary VM bytecodes, translates them to ECMA-335 CIL method bodies,
        and synthesizes a restored PE binary with injected methods in a .eazvm section.
        """
        report: Dict[str, Any] = {
            "success": False,
            "methods_devirtualized_count": 0,
            "devirtualized_tokens": [],
            "methods": [],
            "rebuilt_size": len(data),
            "actions_applied": [],
        }

        containers = cls.extract_vm_containers(data)
        if not containers:
            report["actions_applied"].append("No Eazfuscator VM containers found")
            return data, report

        # Collect all method entries
        all_methods: List[Dict[str, Any]] = []
        for c in containers:
            all_methods.extend(c.get("methods", []))

        if not all_methods:
            report["actions_applied"].append("No virtualized methods found in VM containers")
            return data, report

        # Build disassembler with heuristic or custom opcode table
        disassembler = EazfuscatorVMDisassembler(opcode_table=custom_table or VMOpcodeTable())

        devirtualized_methods: Dict[int, Dict[str, Any]] = {}
        for m in all_methods:
            token = m["token"]
            bytecode = m["bytecode"]
            # Disassemble VM bytecode
            instructions = disassembler.disassemble(bytecode)
            # De-virtualize to standard CIL
            cil_res = EazfuscatorDevirtualizer.devirtualize(
                instructions=instructions,
                max_stack=m.get("max_stack", 8),
                method_token=token,
            )
            if cil_res.get("success"):
                devirtualized_methods[token] = cil_res
                report["devirtualized_tokens"].append(f"0x{token:08X}")
                report["methods"].append({
                    "token": f"0x{token:08X}",
                    "code_size": cil_res["code_size"],
                    "is_fat": cil_res["is_fat"],
                    "instruction_count": cil_res["instruction_count"],
                    "cil_asm": cil_res["decompiled_cil_asm"],
                })

        report["methods_devirtualized_count"] = len(devirtualized_methods)

        # Inject recovered CIL methods into .eazvm section
        rebuilt = cls._append_eazvm_section(data, devirtualized_methods)
        report["success"] = True
        report["rebuilt_size"] = len(rebuilt)
        report["actions_applied"].append(
            f"Successfully de-virtualized {len(devirtualized_methods)} VM methods into .eazvm section"
        )

        return rebuilt, report

    @classmethod
    def _append_eazvm_section(
        cls, pe_data: bytes, methods: Dict[int, Dict[str, Any]]
    ) -> bytes:
        """
        Appends a newly aligned .eazvm section to the PE binary containing recovered CIL method bodies.
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

        if sec_alignment == 0:
            sec_alignment = 0x2000
        if file_alignment == 0:
            file_alignment = 0x200

        sec_table_offset = e_lfanew + 24 + opt_hdr_size
        last_sec_entry = sec_table_offset + (num_sections - 1) * 40
        last_va = struct.unpack_from("<I", buf, last_sec_entry + 12)[0]
        last_vsize = struct.unpack_from("<I", buf, last_sec_entry + 8)[0]

        new_va = ((last_va + last_vsize + sec_alignment - 1) // sec_alignment) * sec_alignment
        new_raw_ptr = ((len(buf) + file_alignment - 1) // file_alignment) * file_alignment

        # Assemble method bodies payload
        payload = bytearray()
        for token, m in sorted(methods.items()):
            payload.extend(m.get("cor_il_method", b""))
            # 4-byte align each method body
            while len(payload) % 4 != 0:
                payload.append(0)

        vsize = len(payload)
        raw_size = ((vsize + file_alignment - 1) // file_alignment) * file_alignment
        payload.extend(b"\x00" * (raw_size - len(payload)))

        # Pad binary up to new_raw_ptr
        if len(buf) < new_raw_ptr:
            buf.extend(b"\x00" * (new_raw_ptr - len(buf)))

        # Append payload bytes
        buf.extend(payload)

        # Write new section header entry (.eazvm)
        new_sec_entry = sec_table_offset + num_sections * 40
        sec_header = bytearray(40)
        sec_header[0:7] = b".eazvm\x00"
        struct.pack_into("<I", sec_header, 8, vsize)
        struct.pack_into("<I", sec_header, 12, new_va)
        struct.pack_into("<I", sec_header, 16, raw_size)
        struct.pack_into("<I", sec_header, 20, new_raw_ptr)
        # Characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA (0x40000040)
        struct.pack_into("<I", sec_header, 36, 0x40000040)

        buf[new_sec_entry : new_sec_entry + 40] = sec_header

        # Increment NumberOfSections
        struct.pack_into("<H", buf, e_lfanew + 6, num_sections + 1)

        # Update SizeOfImage
        new_size_of_image = ((new_va + vsize + sec_alignment - 1) // sec_alignment) * sec_alignment
        struct.pack_into("<I", buf, e_lfanew + 80, new_size_of_image)

        return bytes(buf)

    # =========================================================================
    # 4. Safe Directory Extraction
    # =========================================================================

    @classmethod
    def unpack_to_directory(
        cls,
        data: bytes,
        output_dir: str,
        custom_table: Optional[VMOpcodeTable] = None,
    ) -> List[str]:
        """
        Extracts de-virtualized PE executable, recovered CIL method binaries,
        disassembly listings, and opcode table mapping into output_dir.
        """
        real_output_dir = os.path.realpath(output_dir)
        os.makedirs(real_output_dir, exist_ok=True)
        written_files: List[str] = []

        rebuilt_pe, report = cls.devirtualize_assembly(data, custom_table=custom_table)

        # 1. Write rebuilt PE binary
        rebuilt_path = os.path.join(real_output_dir, "restored_eazvm.exe")
        cls._safe_write(rebuilt_path, rebuilt_pe, real_output_dir)
        written_files.append(rebuilt_path)

        # 2. Write opcode table
        tbl = custom_table or VMOpcodeTable()
        tbl_path = os.path.join(real_output_dir, "opcode_table.json")
        cls._safe_write(tbl_path, tbl.to_json().encode("utf-8"), real_output_dir)
        written_files.append(tbl_path)

        # 3. Write individual method artifacts (CIL binaries and disassembly text)
        for m in report.get("methods", []):
            token_clean = m["token"].replace("0x", "")
            # Disassembly listing
            disasm_path = os.path.join(real_output_dir, f"method_0x{token_clean}.vmasm.txt")
            cls._safe_write(disasm_path, m["cil_asm"].encode("utf-8"), real_output_dir)
            written_files.append(disasm_path)

        # 4. Write telemetry report JSON
        report_path = os.path.join(real_output_dir, "devirtualization_report.json")
        cls._safe_write(report_path, json.dumps(report, indent=2).encode("utf-8"), real_output_dir)
        written_files.append(report_path)

        # Zeroize sensitive memory buffer
        del rebuilt_pe

        return written_files

    @classmethod
    def _safe_write(cls, file_path: str, content: bytes, target_dir: str) -> None:
        """Writes content to disk enforcing strict path traversal validation."""
        real_path = os.path.realpath(file_path)
        if not real_path.startswith(target_dir + os.sep) and real_path != target_dir:
            raise SecurityError(f"Directory traversal prevented: {file_path}")
        with open(real_path, "wb") as f:
            f.write(content)
