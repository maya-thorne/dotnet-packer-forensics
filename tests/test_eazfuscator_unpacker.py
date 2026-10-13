"""
Unit and Integration Test Suite for Eazfuscator.NET VM Disassembler & De-virtualizer.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator.cli import main as cli_main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.eazfuscator import EazfuscatorUnpacker, SecurityError
from dotnet_deobfuscator.unpackers.eazfuscator_vm import (
    EazfuscatorDevirtualizer,
    EazfuscatorVMDisassembler,
    VMInstruction,
    VMOpcode,
    VMOpcodeTable,
)


class TestEazfuscatorUnpacker(unittest.TestCase):
    """Test suite for Eazfuscator.NET bytecode VM disassembly, de-virtualization, and PE injection."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_eazfuscator_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_synthetic_pe(self, extra_payload: bytes = b"") -> bytes:
        """Synthesizes a minimal valid PE executable with standard DOS, NT, and section headers."""
        buf = bytearray(2048 + len(extra_payload))
        # DOS Header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 0x80

        # NT Headers @ 0x80
        nt_off = 0x80
        buf[nt_off : nt_off + 4] = b"PE\0\0"
        struct.pack_into("<H", buf, nt_off + 4, 0x014C)  # Machine: I386
        struct.pack_into("<H", buf, nt_off + 6, 1)       # NumberOfSections = 1
        struct.pack_into("<H", buf, nt_off + 20, 0xE0)   # SizeOfOptionalHeader = 0xE0
        struct.pack_into("<H", buf, nt_off + 22, 0x0102) # Characteristics: EXECUTABLE_IMAGE | 32BIT

        # Optional Header
        opt_off = nt_off + 24
        struct.pack_into("<H", buf, opt_off, 0x010B)     # Magic: PE32
        struct.pack_into("<I", buf, opt_off + 16, 0x1000) # AddressOfEntryPoint
        struct.pack_into("<I", buf, opt_off + 28, 0x00400000) # ImageBase
        struct.pack_into("<I", buf, opt_off + 32, 0x2000) # SectionAlignment
        struct.pack_into("<I", buf, opt_off + 36, 0x200)  # FileAlignment
        struct.pack_into("<I", buf, opt_off + 56, 0x4000) # SizeOfImage
        struct.pack_into("<I", buf, opt_off + 60, 0x400)  # SizeOfHeaders
        struct.pack_into("<H", buf, opt_off + 68, 3)      # Subsystem: Windows CUI
        struct.pack_into("<I", buf, opt_off + 92, 16)     # NumberOfRvaAndSizes

        # Section 1 (.text) @ 0x80 + 24 + 0xE0 = 0x184
        sec_off = opt_off + 0xE0
        buf[sec_off : sec_off + 8] = b".text\0\0\0"
        struct.pack_into("<I", buf, sec_off + 8, 0x800)   # VirtualSize
        struct.pack_into("<I", buf, sec_off + 12, 0x1000) # VirtualAddress
        struct.pack_into("<I", buf, sec_off + 16, 0x800)  # SizeOfRawData
        struct.pack_into("<I", buf, sec_off + 20, 0x400)  # PointerToRawData
        struct.pack_into("<I", buf, sec_off + 36, 0x60000020) # Characteristics

        # Append extra payload inside .text or after headers
        if extra_payload:
            payload_off = 0x400
            buf[payload_off : payload_off + len(extra_payload)] = extra_payload

        return bytes(buf)

    def _create_vm_container(self, methods: list, magic: bytes = b"EAZVM\x01", version: int = 1) -> bytes:
        """Serializes methods into an Eazfuscator VM container binary blob."""
        container = bytearray(magic)
        container.extend(struct.pack("<HI", version, len(methods)))
        for token, max_stack, bytecode in methods:
            container.extend(struct.pack("<IHI", token, max_stack, len(bytecode)))
            container.extend(bytecode)
        return bytes(container)

    # =========================================================================
    # 1. Opcode Table & Heuristic Inference Tests
    # =========================================================================

    def test_vm_opcode_table_defaults_and_custom_serialization(self):
        """Verifies default canonical opcode mappings and JSON serialization."""
        table = VMOpcodeTable()
        self.assertEqual(table.get_opcode(0x00), VMOpcode.NOP)
        self.assertEqual(table.get_opcode(0x10), VMOpcode.LD_I4)
        self.assertEqual(table.get_opcode(0x30), VMOpcode.ADD)
        self.assertEqual(table.get_opcode(0x7F), VMOpcode.RET)
        self.assertEqual(table.get_byte(VMOpcode.RET), 0x7F)

        # Custom mapping overrides
        table.set_mapping(0xAA, VMOpcode.LD_STR)
        self.assertEqual(table.get_opcode(0xAA), VMOpcode.LD_STR)

        # JSON Export and re-import
        json_str = table.to_json()
        imported_table = VMOpcodeTable.from_dict(json.loads(json_str))
        self.assertEqual(imported_table.get_opcode(0xAA), VMOpcode.LD_STR)
        self.assertEqual(imported_table.get_opcode(0x7F), VMOpcode.RET)

    def test_vm_opcode_table_heuristic_inference(self):
        """Tests automated deduction of randomized opcode bytes from bytecode patterns."""
        # Bytecode ending with an unknown terminal byte (0xEF) and containing a Call token (0x06000010)
        # preceded by byte 0xBB
        sample_bc = bytes([
            0xBB, 0x10, 0x00, 0x00, 0x06,  # 0xBB -> CALL 0x06000010
            0xCC, 0x05, 0x00, 0x00, 0x70,  # 0xCC -> LD_STR 0x70000005
            0xEF,                          # 0xEF -> RET
        ])
        inferred = VMOpcodeTable.infer_from_bytecode(sample_bc)
        self.assertEqual(inferred.get_opcode(0xEF), VMOpcode.RET)
        self.assertEqual(inferred.get_opcode(0xBB), VMOpcode.CALL)
        self.assertEqual(inferred.get_opcode(0xCC), VMOpcode.LD_STR)

    # =========================================================================
    # 2. Bytecode Disassembly Engine Tests
    # =========================================================================

    def test_disassembler_arithmetic_and_constants(self):
        """Tests disassembly of arithmetic, constant, and return VM instructions."""
        # VM Bytecode: LD_I4 42, LD_I4 8, ADD, RET
        bc = bytearray()
        bc.append(0x10)  # LD_I4
        bc.extend(struct.pack("<i", 42))
        bc.append(0x10)  # LD_I4
        bc.extend(struct.pack("<i", 8))
        bc.append(0x30)  # ADD
        bc.append(0x7F)  # RET

        disasm = EazfuscatorVMDisassembler()
        instructions = disasm.disassemble(bytes(bc))
        self.assertEqual(len(instructions), 4)

        self.assertEqual(instructions[0].opcode, VMOpcode.LD_I4)
        self.assertEqual(instructions[0].operand, 42)
        self.assertEqual(instructions[1].opcode, VMOpcode.LD_I4)
        self.assertEqual(instructions[1].operand, 8)
        self.assertEqual(instructions[2].opcode, VMOpcode.ADD)
        self.assertEqual(instructions[3].opcode, VMOpcode.RET)

        disasm_text = disasm.disassemble_to_text(bytes(bc))
        self.assertIn("LD_I4 42", disasm_text)
        self.assertIn("ADD", disasm_text)
        self.assertIn("RET", disasm_text)

    def test_disassembler_relative_branches(self):
        """Tests relative branch target calculation in VM disassembler."""
        # Instruction 1 @ 0x00: BR +5 -> target offset = 0x00 + 5 (inst size) + 5 = 10
        bc = bytearray()
        bc.append(0x50)  # BR
        bc.extend(struct.pack("<i", 5))  # rel offset 5
        bc.append(0x00)  # NOP @ 0x05
        bc.append(0x7F)  # RET @ 0x06

        disasm = EazfuscatorVMDisassembler()
        instructions = disasm.disassemble(bytes(bc))
        self.assertEqual(instructions[0].opcode, VMOpcode.BR)
        self.assertEqual(instructions[0].operand, 10)  # 0 + 5 + 5 = 10
        self.assertIn("IL_000A", instructions[0].format())

    # =========================================================================
    # 3. De-virtualizer & CIL Reconstruction Tests
    # =========================================================================

    def test_devirtualize_tiny_format_method(self):
        """Tests translation of simple arithmetic into ECMA-335 CIL with CorILMethod_TinyFormat."""
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x10\x05\x00\x00\x00", opcode=VMOpcode.LD_I4, operand=5),
            VMInstruction(offset=5, raw_bytes=b"\x10\x07\x00\x00\x00", opcode=VMOpcode.LD_I4, operand=7),
            VMInstruction(offset=10, raw_bytes=b"\x30", opcode=VMOpcode.ADD),
            VMInstruction(offset=11, raw_bytes=b"\x7F", opcode=VMOpcode.RET),
        ]

        res = EazfuscatorDevirtualizer.devirtualize(instructions, max_stack=8, method_token=0x06000001)
        self.assertTrue(res["success"])
        self.assertFalse(res["is_fat"])  # Tiny format header
        self.assertEqual(res["code_size"], 4)  # ldc.i4.5 (1b), ldc.i4.7 (1b), add (1b), ret (1b)

        # Header check: (4 << 2) | 0x02 = 18 = 0x12
        cor_method = res["cor_il_method"]
        self.assertEqual(cor_method[0], 0x12)
        # Check CIL opcodes: 0x1B (ldc.i4.5), 0x1D (ldc.i4.7), 0x58 (add), 0x2A (ret)
        self.assertEqual(cor_method[1:], bytes([0x1B, 0x1D, 0x58, 0x2A]))

        self.assertIn("ldc.i4.5", res["decompiled_cil_asm"])
        self.assertIn("add", res["decompiled_cil_asm"])
        self.assertIn("ret", res["decompiled_cil_asm"])

    def test_devirtualize_fat_format_method(self):
        """Tests emission of CorILMethod_FatFormat when code size or maxstack exceeds limits."""
        # Create 70 NOP instructions followed by RET (code_size = 71 > 63)
        instructions = [
            VMInstruction(offset=i, raw_bytes=b"\x00", opcode=VMOpcode.NOP)
            for i in range(70)
        ]
        instructions.append(VMInstruction(offset=70, raw_bytes=b"\x7F", opcode=VMOpcode.RET))

        res = EazfuscatorDevirtualizer.devirtualize(instructions, max_stack=16, method_token=0x06000002)
        self.assertTrue(res["success"])
        self.assertTrue(res["is_fat"])
        self.assertEqual(res["code_size"], 71)

        cor_method = res["cor_il_method"]
        # Fat header is 12 bytes
        self.assertEqual(len(cor_method), 12 + 71)
        flags_size, max_stack, code_size, loc_tok = struct.unpack_from("<HHI I", cor_method, 0)
        self.assertEqual(flags_size, 0x3002)
        self.assertEqual(max_stack, 16)
        self.assertEqual(code_size, 71)

    def test_devirtualize_branch_relative_fixups(self):
        """Tests 2-pass relative target offset resolution for CIL branches."""
        # Branch from offset 0 to target offset 6 (which is RET)
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x50\x01\x00\x00\x00", opcode=VMOpcode.BR, operand=6),
            VMInstruction(offset=5, raw_bytes=b"\x00", opcode=VMOpcode.NOP),
            VMInstruction(offset=6, raw_bytes=b"\x7F", opcode=VMOpcode.RET),
        ]

        res = EazfuscatorDevirtualizer.devirtualize(instructions, max_stack=8)
        self.assertTrue(res["success"])
        cil = res["cil_bytes"]
        # cil layout:
        # 0: br (0x38), followed by 4 bytes rel_offset (bytes 1..4)
        # 5: nop (0x00)
        # 6: ret (0x2A)
        # target is ret @ 6. Next instruction after br is @ 5.
        # rel_offset = target_cil (6) - (patch_offset (1) + 4) = 6 - 5 = 1
        rel_offset = struct.unpack_from("<i", cil, 1)[0]
        self.assertEqual(rel_offset, 1)

    def test_devirtualize_invocations_and_tokens(self):
        """Tests method calls, virtual calls, new objects, and string token conversions."""
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x60\x02\x00\x00\x06", opcode=VMOpcode.CALL, operand=0x06000002),
            VMInstruction(offset=5, raw_bytes=b"\x61\x03\x00\x00\x06", opcode=VMOpcode.CALLVIRT, operand=0x06000003),
            VMInstruction(offset=10, raw_bytes=b"\x62\x04\x00\x00\x06", opcode=VMOpcode.NEWOBJ, operand=0x06000004),
            VMInstruction(offset=15, raw_bytes=b"\x14\x01\x00\x00\x70", opcode=VMOpcode.LD_STR, operand=0x70000001),
            VMInstruction(offset=20, raw_bytes=b"\x7F", opcode=VMOpcode.RET),
        ]

        res = EazfuscatorDevirtualizer.devirtualize(instructions)
        self.assertTrue(res["success"])
        self.assertIn("call 0x06000002", res["decompiled_cil_asm"])
        self.assertIn("callvirt 0x06000003", res["decompiled_cil_asm"])
        self.assertIn("newobj 0x06000004", res["decompiled_cil_asm"])
        self.assertIn("ldstr 0x70000001", res["decompiled_cil_asm"])

    # =========================================================================
    # 4. Eazfuscator Unpacker Detection & Container Carving Tests
    # =========================================================================

    def test_eazfuscator_detector_and_marker_heuristics(self):
        """Tests static detection heuristics and confidence scoring."""
        # Non-Eazfuscator data
        det_clean = EazfuscatorUnpacker.detect(b"Clean .NET assembly with no obfuscation")
        self.assertFalse(det_clean["is_eazfuscator"])
        self.assertEqual(det_clean["confidence"], "NONE")

        # Eazfuscator marker present
        det_marker = EazfuscatorUnpacker.detect(b"Protected with Eazfuscator.NET by Gapotchenko")
        self.assertTrue(det_marker["is_eazfuscator"])
        self.assertEqual(det_marker["confidence"], "MEDIUM")
        self.assertIn("Eazfuscator.NET", det_marker["matched_markers"])

    def test_vm_container_carving_and_parsing(self):
        """Tests parsing embedded VM containers containing virtualized methods."""
        method1_bc = bytes([0x10, 0x05, 0x00, 0x00, 0x00, 0x7F])  # LD_I4 5, RET
        method2_bc = bytes([0x10, 0x0A, 0x00, 0x00, 0x00, 0x7F])  # LD_I4 10, RET

        container_bytes = self._create_vm_container([
            (0x06000001, 8, method1_bc),
            (0x06000002, 16, method2_bc),
        ])

        pe_sample = self._create_synthetic_pe(extra_payload=b"Eazfuscator.NET" + container_bytes)
        containers = EazfuscatorUnpacker.extract_vm_containers(pe_sample)
        self.assertEqual(len(containers), 1)
        c = containers[0]
        self.assertEqual(c["method_count"], 2)
        self.assertEqual(c["methods"][0]["token_hex"], "0x06000001")
        self.assertEqual(c["methods"][0]["bytecode"], method1_bc)
        self.assertEqual(c["methods"][1]["token_hex"], "0x06000002")
        self.assertEqual(c["methods"][1]["bytecode"], method2_bc)

        det = EazfuscatorUnpacker.detect(pe_sample)
        self.assertTrue(det["is_eazfuscator"])
        self.assertEqual(det["confidence"], "HIGH")
        self.assertEqual(det["vm_method_count"], 2)

    # =========================================================================
    # 5. PE Reconstruction & Directory Extraction Tests
    # =========================================================================

    def test_devirtualize_assembly_pe_section_injection(self):
        """Tests injecting recovered CIL methods into a new .eazvm PE section."""
        method_bc = bytes([0x10, 0x2A, 0x00, 0x00, 0x00, 0x7F])  # LD_I4 42, RET
        container = self._create_vm_container([(0x06000005, 8, method_bc)])
        pe_sample = self._create_synthetic_pe(extra_payload=b"Eazfuscator.NET\0" + container)

        rebuilt_pe, report = EazfuscatorUnpacker.devirtualize_assembly(pe_sample)
        self.assertTrue(report["success"])
        self.assertEqual(report["methods_devirtualized_count"], 1)
        self.assertIn("0x06000005", report["devirtualized_tokens"])

        # Check that .eazvm section exists in rebuilt PE headers
        self.assertIn(b".eazvm\x00", rebuilt_pe)
        e_lfanew = struct.unpack_from("<I", rebuilt_pe, 0x3C)[0]
        num_sections = struct.unpack_from("<H", rebuilt_pe, e_lfanew + 6)[0]
        self.assertEqual(num_sections, 2)  # Originally 1, now 2

    def test_unpack_to_directory_artifacts_and_path_traversal_defense(self):
        """Tests safe directory extraction and path traversal attack prevention."""
        method_bc = bytes([0x10, 0x01, 0x00, 0x00, 0x00, 0x7F])
        container = self._create_vm_container([(0x06000008, 8, method_bc)])
        pe_sample = self._create_synthetic_pe(extra_payload=b"Eazfuscator.NET\0" + container)

        out_dir = os.path.join(self.temp_dir, "unpacked_eaz")
        written = EazfuscatorUnpacker.unpack_to_directory(pe_sample, out_dir)
        self.assertTrue(len(written) >= 3)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "restored_eazvm.exe")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "opcode_table.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "devirtualization_report.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "method_0x06000008.vmasm.txt")))

        # Test path traversal defense
        malicious_path = os.path.join(out_dir, "../../../evil.exe")
        with self.assertRaises(SecurityError):
            EazfuscatorUnpacker._safe_write(malicious_path, b"evil", out_dir)

    # =========================================================================
    # 6. Core Orchestrator & CLI Integration Tests
    # =========================================================================

    def test_core_orchestrator_integration(self):
        """Tests DotNetPackerCore analyze_file, devirtualize, and disassemble APIs."""
        method_bc = bytes([0x10, 0x64, 0x00, 0x00, 0x00, 0x7F])
        container = self._create_vm_container([(0x06000009, 8, method_bc)])
        pe_sample = self._create_synthetic_pe(extra_payload=b"Eazfuscator.NET\0" + container)

        target_file = os.path.join(self.temp_dir, "test_core_eaz.exe")
        with open(target_file, "wb") as f:
            f.write(pe_sample)

        # 1. analyze_file
        rep = DotNetPackerCore.analyze_file(target_file)
        self.assertIn("eazfuscator", rep)
        self.assertTrue(rep["eazfuscator"]["detected"])
        self.assertEqual(rep["eazfuscator"]["vm_method_count"], 1)

        # 2. disassemble_eazfuscator_vm
        disasm_res = DotNetPackerCore.disassemble_eazfuscator_vm(target_file)
        self.assertEqual(len(disasm_res), 1)
        self.assertEqual(disasm_res[0]["token"], "0x06000009")
        self.assertIn("LD_I4 100", disasm_res[0]["disassembly"])

        # 3. devirtualize_eazfuscator
        out_file = os.path.join(self.temp_dir, "core_devirtualized.exe")
        rebuilt_pe, devirt_rep = DotNetPackerCore.devirtualize_eazfuscator(target_file, output_path=out_file)
        self.assertTrue(devirt_rep["success"])
        self.assertTrue(os.path.exists(out_file))

    def test_cli_flags_devirtualize_and_disassembly(self):
        """Tests CLI command line execution with --devirtualize-eaz and --disasm-vm flags."""
        method_bc = bytes([0x10, 0x07, 0x00, 0x00, 0x00, 0x7F])
        container = self._create_vm_container([(0x0600000A, 8, method_bc)])
        pe_sample = self._create_synthetic_pe(extra_payload=b"Eazfuscator.NET\0" + container)

        target_file = os.path.join(self.temp_dir, "cli_test_eaz.exe")
        with open(target_file, "wb") as f:
            f.write(pe_sample)

        # Test CLI disasm
        code = cli_main([target_file, "--disasm-vm"])
        self.assertEqual(code, 0)

        # Test CLI devirtualize
        out_dest = os.path.join(self.temp_dir, "cli_out.exe")
        code = cli_main([target_file, "--devirtualize-eaz", "--eaz-out", out_dest])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(out_dest))

    # =========================================================================
    # 7. Comprehensive Extended Opcode & Edge Case Tests
    # =========================================================================

    def test_eazfuscator_unpacker_disassemble_and_devirtualize_apis(self):
        """Tests high-level EazfuscatorUnpacker class methods for disassembly and method devirtualization."""
        # 1. disassemble_bytecode
        bc = bytes([0x10, 0x14, 0x00, 0x00, 0x00, 0x7F])  # LD_I4 20, RET
        instructions = EazfuscatorUnpacker.disassemble_bytecode(bc)
        self.assertEqual(len(instructions), 2)
        self.assertEqual(instructions[0].opcode, VMOpcode.LD_I4)
        self.assertEqual(instructions[0].operand, 20)
        self.assertEqual(instructions[1].opcode, VMOpcode.RET)

        # 2. devirtualize_method
        res = EazfuscatorUnpacker.devirtualize_method(bc, max_stack=8, method_token=0x06000050)
        self.assertTrue(res["success"])
        self.assertEqual(res["method_token"], 0x06000050)
        self.assertIn("ldc.i4.s 20", res["decompiled_cil_asm"])
        self.assertIn("ret", res["decompiled_cil_asm"])

        # 3. disassemble_assembly
        container = self._create_vm_container([(0x06000050, 8, bc)])
        pe = self._create_synthetic_pe(extra_payload=b"Eazfuscator.NET\0" + container)
        disasm_list = EazfuscatorUnpacker.disassemble_assembly(pe)
        self.assertEqual(len(disasm_list), 1)
        self.assertEqual(disasm_list[0]["token"], 0x06000050)
        self.assertEqual(disasm_list[0]["token_hex"], "0x06000050")
        self.assertEqual(disasm_list[0]["instruction_count"], 2)

    def test_devirtualize_advanced_opcodes_loca_arga_arrays(self):
        """Tests LD_LOCA, LD_ARGA, NEWARR, and LDLEN translation to authentic CIL."""
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x22\x02\x00", opcode=VMOpcode.LD_LOCA, operand=2),
            VMInstruction(offset=3, raw_bytes=b"\x22\x00\x02", opcode=VMOpcode.LD_LOCA, operand=512),
            VMInstruction(offset=6, raw_bytes=b"\x27\x01\x00", opcode=VMOpcode.LD_ARGA, operand=1),
            VMInstruction(offset=9, raw_bytes=b"\x27\x00\x02", opcode=VMOpcode.LD_ARGA, operand=512),
            VMInstruction(offset=12, raw_bytes=b"\x63\x05\x00\x00\x01", opcode=VMOpcode.NEWARR, operand=0x01000005),
            VMInstruction(offset=17, raw_bytes=b"\x64", opcode=VMOpcode.LDLEN),
            VMInstruction(offset=18, raw_bytes=b"\x7F", opcode=VMOpcode.RET),
        ]
        res = EazfuscatorDevirtualizer.devirtualize(instructions)
        self.assertTrue(res["success"])
        asm = res["decompiled_cil_asm"]
        self.assertIn("ldloca.s 2", asm)
        self.assertIn("ldloca 512", asm)
        self.assertIn("ldarga.s 1", asm)
        self.assertIn("ldarga 512", asm)
        self.assertIn("newarr 0x01000005", asm)
        self.assertIn("ldlen", asm)

        # Check format() for NEWARR includes hex token
        self.assertIn("0x01000005", instructions[4].format())

    def test_devirtualize_comparisons_and_conversions(self):
        """Tests CEQ, CGT, CLT comparisons and CONV_* numeric type conversions."""
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x40", opcode=VMOpcode.CEQ),
            VMInstruction(offset=1, raw_bytes=b"\x41", opcode=VMOpcode.CGT),
            VMInstruction(offset=2, raw_bytes=b"\x42", opcode=VMOpcode.CLT),
            VMInstruction(offset=3, raw_bytes=b"\x70", opcode=VMOpcode.CONV_I4),
            VMInstruction(offset=4, raw_bytes=b"\x71", opcode=VMOpcode.CONV_I8),
            VMInstruction(offset=5, raw_bytes=b"\x72", opcode=VMOpcode.CONV_R4),
            VMInstruction(offset=6, raw_bytes=b"\x73", opcode=VMOpcode.CONV_R8),
            VMInstruction(offset=7, raw_bytes=b"\x74", opcode=VMOpcode.CONV_U4),
            VMInstruction(offset=8, raw_bytes=b"\x75", opcode=VMOpcode.CONV_U8),
            VMInstruction(offset=9, raw_bytes=b"\x7F", opcode=VMOpcode.RET),
        ]
        res = EazfuscatorDevirtualizer.devirtualize(instructions)
        self.assertTrue(res["success"])
        asm = res["decompiled_cil_asm"]
        for mnemonic in ["ceq", "cgt", "clt", "conv.i4", "conv.i8", "conv.r4", "conv.r8", "conv.u4", "conv.u8"]:
            self.assertIn(mnemonic, asm)

    def test_devirtualize_arithmetic_and_bitwise_full(self):
        """Tests all arithmetic and bitwise opcodes: SUB, MUL, DIV, REM, NEG, AND, OR, XOR, NOT, SHL, SHR."""
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x31", opcode=VMOpcode.SUB),
            VMInstruction(offset=1, raw_bytes=b"\x32", opcode=VMOpcode.MUL),
            VMInstruction(offset=2, raw_bytes=b"\x33", opcode=VMOpcode.DIV),
            VMInstruction(offset=3, raw_bytes=b"\x34", opcode=VMOpcode.REM),
            VMInstruction(offset=4, raw_bytes=b"\x35", opcode=VMOpcode.NEG),
            VMInstruction(offset=5, raw_bytes=b"\x36", opcode=VMOpcode.AND),
            VMInstruction(offset=6, raw_bytes=b"\x37", opcode=VMOpcode.OR),
            VMInstruction(offset=7, raw_bytes=b"\x38", opcode=VMOpcode.XOR),
            VMInstruction(offset=8, raw_bytes=b"\x39", opcode=VMOpcode.NOT),
            VMInstruction(offset=9, raw_bytes=b"\x3A", opcode=VMOpcode.SHL),
            VMInstruction(offset=10, raw_bytes=b"\x3B", opcode=VMOpcode.SHR),
            VMInstruction(offset=11, raw_bytes=b"\x7E", opcode=VMOpcode.THROW),
        ]
        res = EazfuscatorDevirtualizer.devirtualize(instructions)
        self.assertTrue(res["success"])
        asm = res["decompiled_cil_asm"]
        for op in ["sub", "mul", "div", "rem", "neg", "and", "or", "xor", "not", "shl", "shr", "throw"]:
            self.assertIn(op, asm)

    def test_devirtualize_all_branch_conditions(self):
        """Tests BR_TRUE, BR_FALSE, BEQ, BNE, BGT, BGE, BLT, BLE relative target calculation."""
        branch_ops = [
            VMOpcode.BR_TRUE,
            VMOpcode.BR_FALSE,
            VMOpcode.BEQ,
            VMOpcode.BNE,
            VMOpcode.BGT,
            VMOpcode.BGE,
            VMOpcode.BLT,
            VMOpcode.BLE,
        ]
        instructions = []
        for i, op in enumerate(branch_ops):
            instructions.append(VMInstruction(offset=i * 5, raw_bytes=b"\x50\x00\x00\x00\x00", opcode=op, operand=100))
        instructions.append(VMInstruction(offset=100, raw_bytes=b"\x7F", opcode=VMOpcode.RET))

        res = EazfuscatorDevirtualizer.devirtualize(instructions)
        self.assertTrue(res["success"])
        self.assertEqual(res["instruction_count"], len(branch_ops) + 1)
        asm = res["decompiled_cil_asm"]
        for b_name in ["brtrue", "brfalse", "beq", "bne.un", "bgt", "bge", "blt", "ble"]:
            self.assertIn(b_name, asm)

    def test_devirtualize_stack_and_constants_edge_cases(self):
        """Tests POP, DUP, LD_NULL, LD_I8, LD_R4, LD_R8, and LD_I4 numeric boundaries."""
        instructions = [
            VMInstruction(offset=0, raw_bytes=b"\x01", opcode=VMOpcode.POP),
            VMInstruction(offset=1, raw_bytes=b"\x02", opcode=VMOpcode.DUP),
            VMInstruction(offset=2, raw_bytes=b"\x03", opcode=VMOpcode.LD_NULL),
            VMInstruction(offset=3, raw_bytes=b"\x10\xFF\xFF\xFF\xFF", opcode=VMOpcode.LD_I4, operand=-1),
            VMInstruction(offset=8, raw_bytes=b"\x10\xCE\xFF\xFF\xFF", opcode=VMOpcode.LD_I4, operand=-50),
            VMInstruction(offset=13, raw_bytes=b"\x10\x64\x00\x00\x00", opcode=VMOpcode.LD_I4, operand=100),
            VMInstruction(offset=18, raw_bytes=b"\x10\xA0\x86\x01\x00", opcode=VMOpcode.LD_I4, operand=100000),
            VMInstruction(offset=23, raw_bytes=b"\x11\x00\x00\x00\x00\x00\x00\x00\x01", opcode=VMOpcode.LD_I8, operand=0x0100000000),
            VMInstruction(offset=32, raw_bytes=b"\x12\x00\x00\x48\x41", opcode=VMOpcode.LD_R4, operand=12.5),
            VMInstruction(offset=37, raw_bytes=b"\x13\x00\x00\x00\x00\x00\x00\x45\x40", opcode=VMOpcode.LD_R8, operand=42.0),
            VMInstruction(offset=46, raw_bytes=b"\x7F", opcode=VMOpcode.RET),
        ]
        res = EazfuscatorDevirtualizer.devirtualize(instructions)
        self.assertTrue(res["success"])
        asm = res["decompiled_cil_asm"]
        self.assertIn("pop", asm)
        self.assertIn("dup", asm)
        self.assertIn("ldnull", asm)
        self.assertIn("ldc.i4.m1", asm)
        self.assertIn("ldc.i4.s -50", asm)
        self.assertIn("ldc.i4.s 100", asm)
        self.assertIn("ldc.i4 100000", asm)
        self.assertIn("ldc.i8", asm)
        self.assertIn("ldc.r4", asm)
        self.assertIn("ldc.r8", asm)

    def test_unpack_to_directory_clean_binary_returns_empty(self):
        """Verifies unpack_to_directory returns [] when binary has no Eazfuscator containers."""
        clean_pe = self._create_synthetic_pe(extra_payload=b"No obfuscation here")
        out_dir = os.path.join(self.temp_dir, "clean_unpack_test")
        written = EazfuscatorUnpacker.unpack_to_directory(clean_pe, out_dir)
        self.assertEqual(written, [])
        self.assertFalse(os.path.exists(os.path.join(out_dir, "restored_eazvm.exe")))

    def test_devirtualize_assembly_no_containers(self):
        """Verifies devirtualize_assembly returns unmodified data and failure report if no containers exist."""
        clean_pe = self._create_synthetic_pe()
        rebuilt, rep = EazfuscatorUnpacker.devirtualize_assembly(clean_pe)
        self.assertEqual(rebuilt, clean_pe)
        self.assertFalse(rep["success"])
        self.assertEqual(rep["methods_devirtualized_count"], 0)

    def test_extract_vm_containers_corrupted_or_truncated(self):
        """Verifies extract_vm_containers safely rejects truncated or corrupt container headers."""
        # Less than 16 bytes
        self.assertEqual(EazfuscatorUnpacker.extract_vm_containers(b"EAZVM"), [])

        # Method count = 0
        container_zero = bytearray(b"EAZVM\x01")
        container_zero.extend(struct.pack("<HI", 1, 0))
        self.assertEqual(EazfuscatorUnpacker.extract_vm_containers(bytes(container_zero)), [])

        # Method count > 5000 (unrealistic / corrupt)
        container_overflow = bytearray(b"EAZVM\x01")
        container_overflow.extend(struct.pack("<HI", 1, 99999))
        self.assertEqual(EazfuscatorUnpacker.extract_vm_containers(bytes(container_overflow)), [])

        # Bytecode length exceeds buffer
        container_trunc = bytearray(b"EAZVM\x01")
        container_trunc.extend(struct.pack("<HI", 1, 1))
        container_trunc.extend(struct.pack("<IHI", 0x06000001, 8, 10000))  # claims 10000 bytes, but ends
        self.assertEqual(EazfuscatorUnpacker.extract_vm_containers(bytes(container_trunc)), [])

    def test_append_eazvm_section_edge_cases(self):
        """Verifies _append_eazvm_section edge cases: non-PE data and empty methods."""
        # Non-PE input
        non_pe = b"Hello, world! Not a PE."
        self.assertEqual(EazfuscatorUnpacker._append_eazvm_section(non_pe, {}), non_pe)

        # Truncated PE header (< 0x200)
        short_mz = b"MZ" + b"\x00" * 100
        self.assertEqual(EazfuscatorUnpacker._append_eazvm_section(short_mz, {}), short_mz)


if __name__ == "__main__":
    unittest.main()
