"""
ArmDot Forensic Unpacker, VM Container Carver & Assembly De-virtualizer.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .armdot_rebuilder import ArmDotDevirtualizer
from .armdot_vm import (
    ArmDotInstruction,
    ArmDotOpcode,
    ArmDotOpcodeTable,
    ArmDotVMDisassembler,
)


class SecurityError(Exception):
    """Raised when malicious path traversal or payload tampering is detected."""
    pass


__all__ = [
    "ArmDotUnpacker",
    "ArmDotVMDisassembler",
    "ArmDotDevirtualizer",
    "ArmDotOpcode",
    "ArmDotOpcodeTable",
    "ArmDotInstruction",
    "SecurityError",
]


class ArmDotUnpacker:
    """
    Forensic unpacker and de-virtualization engine for ArmDot protected binaries.
    Implements:
      - Static signature and metadata marker detection
      - VM bytecode container carving across PE sections and overlay
      - Rolling LCG/XOR bytecode decryption
      - Multi-method VM disassembly and translation into ECMA-335 CIL
      - PE section (.armdot) synthesis and header realignment
      - Safe directory extraction with path traversal defenses and Zeroize wiping
    """

    MAX_PAYLOAD_SIZE = 256 * 1024 * 1024  # 256 MB safety ceiling

    # Known ArmDot signatures and metadata markers
    SIGNATURE_PATTERNS = [
        b"ArmDot.Client.VirtualizeAttribute",
        b"ArmDot.Client.ObfuscateNamesAttribute",
        b"ArmDot.Client.ProtectAttribute",
        b"ArmDot.Client",
        b"ArmDot",
        b".armdot",
        b"ArmDot.Engine",
        b"ArmDot.VirtualMachine",
    ]

    # Container magics for virtualized method packages
    VM_CONTAINER_MAGICS = [
        b"ARMDOT\x01",
        b"ARMDOT",
        b"\x41\x52\x4D\x44",  # 0x444D5241 little-endian magic ("ARMD")
    ]

    # =========================================================================
    # 1. Detection Engine
    # =========================================================================

    @classmethod
    def detect(cls, data: bytes) -> Dict[str, Any]:
        """
        Scans binary for ArmDot signatures, obfuscated identifiers, and VM containers.
        """
        markers_found = []
        for pat in cls.SIGNATURE_PATTERNS:
            if pat in data:
                markers_found.append(pat.decode("latin1", errors="ignore"))

        containers = cls.extract_vm_containers(data)
        has_vm = len(containers) > 0

        # Confidence calculation
        if has_vm and any("ArmDot" in m for m in markers_found):
            confidence = "HIGH"
        elif has_vm or any("ArmDot" in m for m in markers_found):
            confidence = "MEDIUM"
        elif len(markers_found) > 0:
            confidence = "LOW"
        else:
            confidence = "NONE"

        return {
            "is_armdot": confidence in ("MEDIUM", "HIGH"),
            "confidence": confidence,
            "has_virtual_machine": has_vm,
            "vm_method_count": sum(len(c.get("methods", [])) for c in containers),
            "vm_containers_count": len(containers),
            "matched_markers": list(dict.fromkeys(markers_found)),
        }

    # =========================================================================
    # 2. Cryptographic Stream Cipher & Key Derivation
    # =========================================================================

    @staticmethod
    def decrypt_method_bytecode(ciphertext: bytes, key: int) -> bytes:
        """
        Inverts ArmDot's LCG/rolling XOR stream cipher to recover raw VM bytecode.
        Zeroizes intermediate key schedule buffers upon completion.
        """
        if not ciphertext or key == 0:
            return ciphertext

        seed = key & 0xFFFFFFFF
        plaintext = bytearray(len(ciphertext))

        for idx, b in enumerate(ciphertext):
            seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
            keystream_byte = (seed >> 16) & 0xFF
            plaintext[idx] = b ^ keystream_byte

        # Zeroize sensitive seed state
        seed = 0
        return bytes(plaintext)

    @classmethod
    def encrypt_method_bytecode(cls, plaintext: bytes, key: int) -> bytes:
        """Symmetric LCG/rolling XOR encryption helper used for fixture generation."""
        return cls.decrypt_method_bytecode(plaintext, key)

    # =========================================================================
    # 3. VM Container Carver
    # =========================================================================

    @classmethod
    def extract_vm_containers(cls, data: bytes) -> List[Dict[str, Any]]:
        """
        Scans data for embedded ArmDot VM method packages and parses method descriptors.
        """
        containers: List[Dict[str, Any]] = []
        if len(data) < 16:
            return containers

        data_len = len(data)

        for magic in cls.VM_CONTAINER_MAGICS:
            pos = 0
            magic_len = len(magic)
            while pos < data_len:
                idx = data.find(magic, pos)
                if idx == -1:
                    break
                pos = idx + magic_len

                # Try parsing container header at idx
                hdr_offset = idx + magic_len
                if hdr_offset + 8 > data_len:
                    continue

                try:
                    version, method_count, flags = struct.unpack_from("<HHI", data, hdr_offset)
                except struct.error:
                    continue

                if method_count == 0 or method_count > 1024 or version > 10:
                    continue

                curr_ptr = hdr_offset + 8
                methods: List[Dict[str, Any]] = []
                valid_container = True

                for _ in range(method_count):
                    # Each method entry: token(4) + stack_depth(2) + local_count(2) + key(4) + code_len(4) = 16 bytes
                    if curr_ptr + 16 > data_len:
                        valid_container = False
                        break

                    token, stack_depth, local_count, key, code_len = struct.unpack_from(
                        "<IHHI I", data, curr_ptr
                    )
                    curr_ptr += 16

                    if code_len > cls.MAX_PAYLOAD_SIZE or curr_ptr + code_len > data_len:
                        valid_container = False
                        break

                    enc_bytecode = data[curr_ptr : curr_ptr + code_len]
                    curr_ptr += code_len

                    # Decrypt bytecode if key is supplied
                    raw_bytecode = cls.decrypt_method_bytecode(enc_bytecode, key)

                    methods.append({
                        "token": token,
                        "token_hex": f"0x{token:08X}",
                        "stack_depth": stack_depth,
                        "local_count": local_count,
                        "key": key,
                        "code_len": code_len,
                        "bytecode": raw_bytecode,
                        "sha256": hashlib.sha256(raw_bytecode).hexdigest(),
                    })

                if valid_container and methods:
                    containers.append({
                        "offset": idx,
                        "magic": magic.decode("latin1", errors="replace"),
                        "version": version,
                        "flags": flags,
                        "method_count": len(methods),
                        "methods": methods,
                        "total_bytes": curr_ptr - idx,
                    })

        return containers

    @classmethod
    def build_vm_container(
        cls,
        methods: List[Dict[str, Any]],
        version: int = 1,
        magic: bytes = b"ARMDOT\x01",
    ) -> bytes:
        """Synthesizes a valid binary ArmDot VM container package for testing."""
        buf = bytearray()
        buf.extend(magic)
        buf.extend(struct.pack("<HHI", version, len(methods), 0))

        for m in methods:
            token = m.get("token", 0x06000001)
            stack_depth = m.get("stack_depth", 8)
            local_count = m.get("local_count", 0)
            key = m.get("key", 0)
            raw_bc = m.get("bytecode", b"")
            enc_bc = cls.encrypt_method_bytecode(raw_bc, key)

            buf.extend(struct.pack("<IHHI I", token, stack_depth, local_count, key, len(enc_bc)))
            buf.extend(enc_bc)

        return bytes(buf)

    # =========================================================================
    # 4. Assembly De-virtualization Pipeline
    # =========================================================================

    @classmethod
    def devirtualize_assembly(
        cls,
        data: bytes,
        custom_table: Optional[ArmDotOpcodeTable] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        De-virtualizes ArmDot virtual machine methods into standard CIL and
        rebuilds the PE binary by injecting an aligned .armdot section.
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
            report["actions_applied"].append("No ArmDot VM containers found")
            return data, report

        all_methods: List[Dict[str, Any]] = []
        for c in containers:
            all_methods.extend(c.get("methods", []))

        if not all_methods:
            report["actions_applied"].append("No virtualized methods found in VM containers")
            return data, report

        table = custom_table or ArmDotOpcodeTable()
        disassembler = ArmDotVMDisassembler(opcode_table=table)
        devirtualized_methods: Dict[int, Dict[str, Any]] = {}

        for m in all_methods:
            token = m["token"]
            if token in devirtualized_methods:
                continue

            bytecode = m["bytecode"]
            instructions = disassembler.disassemble(bytecode)
            cil_res = ArmDotDevirtualizer.devirtualize_method(
                instructions=instructions,
                token=token,
                local_count=m.get("local_count", 0),
            )
            devirtualized_methods[token] = cil_res
            report["devirtualized_tokens"].append(f"0x{token:08X}")
            report["methods"].append({
                "token": f"0x{token:08X}",
                "code_size": cil_res["code_size"],
                "header_format": cil_res["header_format"],
                "max_stack": cil_res["max_stack"],
                "disassembly": cil_res["disassembly"],
                "is_valid_cil": cil_res["is_valid_cil"],
            })

        report["methods_devirtualized_count"] = len(devirtualized_methods)

        # Inject recovered CIL methods into aligned .armdot PE section
        rebuilt = cls._append_armdot_section(data, devirtualized_methods)
        report["success"] = True
        report["rebuilt_size"] = len(rebuilt)
        report["actions_applied"].append(
            f"Successfully de-virtualized {len(devirtualized_methods)} VM methods into .armdot section"
        )

        return rebuilt, report

    @classmethod
    def _append_armdot_section(
        cls, pe_data: bytes, methods: Dict[int, Dict[str, Any]]
    ) -> bytes:
        """
        Appends an aligned .armdot section to PE binary containing CIL method bodies.
        """
        if len(pe_data) < 0x200 or not pe_data.startswith(b"MZ"):
            return pe_data

        try:
            buf = bytearray(pe_data)
            if len(buf) < 0x40:
                return pe_data
            e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
            if e_lfanew + 84 > len(buf) or buf[e_lfanew : e_lfanew + 4] != b"PE\0\0":
                return pe_data

            num_sections = struct.unpack_from("<H", buf, e_lfanew + 6)[0]
            opt_hdr_size = struct.unpack_from("<H", buf, e_lfanew + 20)[0]
            if opt_hdr_size < 68:
                return pe_data

            sec_alignment = struct.unpack_from("<I", buf, e_lfanew + 56)[0] or 0x2000
            file_alignment = struct.unpack_from("<I", buf, e_lfanew + 60)[0] or 0x200

            sec_table_offset = e_lfanew + 24 + opt_hdr_size
            if sec_table_offset > len(buf):
                return pe_data

            if num_sections == 0:
                last_va = 0x1000
                last_vsize = 0x1000
            else:
                last_sec_entry = sec_table_offset + (num_sections - 1) * 40
                if last_sec_entry + 40 > len(buf):
                    return pe_data
                last_va = struct.unpack_from("<I", buf, last_sec_entry + 12)[0]
                last_vsize = struct.unpack_from("<I", buf, last_sec_entry + 8)[0]

            new_sec_entry = sec_table_offset + num_sections * 40
            first_raw_ptr = struct.unpack_from("<I", buf, sec_table_offset + 20)[0] if num_sections > 0 else 0
            if first_raw_ptr > 0 and new_sec_entry + 40 > first_raw_ptr:
                return pe_data

            new_va = ((last_va + last_vsize + sec_alignment - 1) // sec_alignment) * sec_alignment
            new_raw_ptr = ((len(buf) + file_alignment - 1) // file_alignment) * file_alignment

            # Assemble CIL method bodies payload
            payload = bytearray()
            for token, m in sorted(methods.items()):
                payload.extend(m.get("method_body_bytes", b""))
                while len(payload) % 4 != 0:
                    payload.append(0)

            vsize = len(payload)
            raw_size = ((vsize + file_alignment - 1) // file_alignment) * file_alignment
            payload.extend(b"\x00" * (raw_size - len(payload)))

            if len(buf) < new_raw_ptr:
                buf.extend(b"\x00" * (new_raw_ptr - len(buf)))
            buf.extend(payload)

            if new_sec_entry + 40 > len(buf):
                buf.extend(b"\x00" * (new_sec_entry + 40 - len(buf)))

            # Section Header for .armdot
            sec_header = bytearray(40)
            sec_header[0:8] = b".armdot\x00"
            struct.pack_into("<I", sec_header, 8, vsize)
            struct.pack_into("<I", sec_header, 12, new_va)
            struct.pack_into("<I", sec_header, 16, raw_size)
            struct.pack_into("<I", sec_header, 20, new_raw_ptr)
            # IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA (0x40000040)
            struct.pack_into("<I", sec_header, 36, 0x40000040)

            buf[new_sec_entry : new_sec_entry + 40] = sec_header

            # Increment NumberOfSections
            struct.pack_into("<H", buf, e_lfanew + 6, num_sections + 1)

            # Update SizeOfImage
            new_size_of_image = ((new_va + vsize + sec_alignment - 1) // sec_alignment) * sec_alignment
            struct.pack_into("<I", buf, e_lfanew + 80, new_size_of_image)

            return bytes(buf)
        except (struct.error, ValueError, IndexError, OverflowError):
            return pe_data

    # =========================================================================
    # 5. Safe Directory Extraction
    # =========================================================================

    @classmethod
    def unpack_to_directory(
        cls,
        data: bytes,
        output_dir: str,
        custom_table: Optional[ArmDotOpcodeTable] = None,
    ) -> List[str]:
        """
        Extracts de-virtualized PE executable, recovered CIL method binaries,
        disassembly listings, and opcode table mapping into output_dir.
        """
        real_output_dir = os.path.realpath(output_dir)
        os.makedirs(real_output_dir, exist_ok=True)
        written_files: List[str] = []

        rebuilt_pe, rep = cls.devirtualize_assembly(data, custom_table=custom_table)

        # 1. Write reconstructed assembly
        if rep.get("success") or rep.get("methods_devirtualized_count", 0) > 0:
            out_exe = os.path.join(real_output_dir, "devirtualized_main.exe")
            real_dest = os.path.realpath(out_exe)
            if not (real_dest == real_output_dir or real_dest.startswith(real_output_dir + os.sep)):
                raise SecurityError(f"Path traversal detected: {out_exe}")
            with open(real_dest, "wb") as f:
                f.write(rebuilt_pe)
            written_files.append(real_dest)

        # 2. Write individual method CIL binary bodies & text disassembly
        table = custom_table or ArmDotOpcodeTable()
        disassembler = ArmDotVMDisassembler(opcode_table=table)
        containers = cls.extract_vm_containers(data)

        for c in containers:
            for m in c.get("methods", []):
                tok_hex = m["token_hex"]
                cil_bin_name = f"method_{tok_hex}.cil.bin"
                disasm_name = f"method_{tok_hex}.disasm.txt"

                dest_bin = os.path.realpath(os.path.join(real_output_dir, cil_bin_name))
                dest_dis = os.path.realpath(os.path.join(real_output_dir, disasm_name))

                for p in (dest_bin, dest_dis):
                    if not (p == real_output_dir or p.startswith(real_output_dir + os.sep)):
                        raise SecurityError(f"Path traversal detected: {p}")

                instructions = disassembler.disassemble(m["bytecode"])
                cil_res = ArmDotDevirtualizer.devirtualize_method(
                    instructions=instructions,
                    token=m["token"],
                    local_count=m.get("local_count", 0),
                )

                with open(dest_bin, "wb") as f:
                    f.write(cil_res["method_body_bytes"])
                written_files.append(dest_bin)

                with open(dest_dis, "w", encoding="utf-8") as f:
                    f.write(cil_res["disassembly"])
                written_files.append(dest_dis)

        # 3. Write opcode table JSON
        table_path = os.path.realpath(os.path.join(real_output_dir, "armdot_opcode_table.json"))
        if not (table_path == real_output_dir or table_path.startswith(real_output_dir + os.sep)):
            raise SecurityError(f"Path traversal detected: {table_path}")
        with open(table_path, "w", encoding="utf-8") as f:
            json.dump(table.to_dict(), f, indent=2)
        written_files.append(table_path)

        # 4. Write forensic telemetry report
        rep_path = os.path.realpath(os.path.join(real_output_dir, "armdot_report.json"))
        if not (rep_path == real_output_dir or rep_path.startswith(real_output_dir + os.sep)):
            raise SecurityError(f"Path traversal detected: {rep_path}")
        with open(rep_path, "w", encoding="utf-8") as f:
            clean_rep = dict(rep)
            json.dump(clean_rep, f, indent=2)
        written_files.append(rep_path)

        # Zeroize in-memory rebuilt buffer references
        del rebuilt_pe
        return written_files
