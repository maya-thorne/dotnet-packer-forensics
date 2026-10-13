"""
Comprehensive Unit & Integration Test Suite for ArmDot Unpacker & CIL Rebuilder.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.armdot import (
    ArmDotDevirtualizer,
    ArmDotInstruction,
    ArmDotOpcode,
    ArmDotOpcodeTable,
    ArmDotUnpacker,
    ArmDotVMDisassembler,
    SecurityError,
)
from dotnet_deobfuscator.unpackers.armdot_rebuilder import (
    ArmDotCFG,
    CILOpcode,
    CorILMethodBuilder,
)
from dotnet_deobfuscator.unpackers.armdot_vm import ArmDotStackEmulator


def make_minimal_pe(sections: int = 1) -> bytearray:
    """Creates a well-formed minimal 32-bit PE binary buffer for testing."""
    buf = bytearray(0x400)
    # DOS Header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # NT Header
    e_lfanew = 0x80
    buf[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", buf, e_lfanew + 4, 0x014C)  # Machine: i386
    struct.pack_into("<H", buf, e_lfanew + 6, sections)  # NumberOfSections
    struct.pack_into("<H", buf, e_lfanew + 20, 0xE0)  # SizeOfOptionalHeader (224 bytes)

    # Optional Header
    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, 0x010B)  # Magic: PE32
    struct.pack_into("<I", buf, opt + 32, 0x2000)  # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)  # FileAlignment
    struct.pack_into("<I", buf, opt + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, 0x200)  # SizeOfHeaders

    # Section table
    sec_offset = opt + 0xE0
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<I", sec, 8, 0x200)  # VirtualSize
    struct.pack_into("<I", sec, 12, 0x2000)  # VirtualAddress
    struct.pack_into("<I", sec, 16, 0x200)  # SizeOfRawData
    struct.pack_into("<I", sec, 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", sec, 36, 0x60000020)  # Characteristics
    buf[sec_offset : sec_offset + 40] = sec

    return buf


class TestArmDotUnpacker(unittest.TestCase):
    """Test suite validating ArmDot VM disassembly, emulation, and de-virtualization."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_armdot_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_opcode_table_defaults_and_customization(self):
        table = ArmDotOpcodeTable()
        self.assertEqual(table.get_opcode(0x00), ArmDotOpcode.NOP)
        self.assertEqual(table.get_opcode(0x03), ArmDotOpcode.RET)
        self.assertEqual(table.get_opcode(0x11), ArmDotOpcode.LD_I4)
        self.assertEqual(table.get_opcode(0x30), ArmDotOpcode.ADD)
        self.assertEqual(table.get_opcode(0xFF), ArmDotOpcode.UNKNOWN)

        # Customization
        table.set_opcode(0xFE, ArmDotOpcode.XOR)
        self.assertEqual(table.get_opcode(0xFE), ArmDotOpcode.XOR)

        # JSON Roundtrip
        d = table.to_dict()
        self.assertIn("0x00", d)
        self.assertEqual(d["0x03"], "RET")

        table_restored = ArmDotOpcodeTable.from_dict(d)
        self.assertEqual(table_restored.get_opcode(0x03), ArmDotOpcode.RET)
        self.assertEqual(table_restored.get_opcode(0xFE), ArmDotOpcode.XOR)

    def test_opcode_table_deduction(self):
        # Bytecode ending in 0xAA as RET, with embedded call token 0x06000005 preceded by opcode 0xCC
        call_tok = 0x06000005
        tok_bytes = struct.pack("<I", call_tok)
        bytecode = b"\x10\x20" + bytes([0xCC]) + tok_bytes + b"\xAA"

        table = ArmDotOpcodeTable.deduce_from_bytecode(bytecode, metadata_tokens=[call_tok])
        self.assertEqual(table.get_opcode(0xAA), ArmDotOpcode.RET)
        self.assertEqual(table.get_opcode(0xCC), ArmDotOpcode.CALL)

    def test_vm_disassembler_basic(self):
        disasm = ArmDotVMDisassembler()
        # NOP (0x00), LD_I4 42 (0x11, 42 as i32), DUP (0x02), ADD (0x30), RET (0x03)
        bytecode = (
            bytes([0x00])
            + bytes([0x11]) + struct.pack("<i", 42)
            + bytes([0x02])
            + bytes([0x30])
            + bytes([0x03])
        )
        instructions = disasm.disassemble(bytecode)
        self.assertEqual(len(instructions), 5)
        self.assertEqual(instructions[0].opcode, ArmDotOpcode.NOP)
        self.assertEqual(instructions[1].opcode, ArmDotOpcode.LD_I4)
        self.assertEqual(instructions[1].operand, 42)
        self.assertEqual(instructions[2].opcode, ArmDotOpcode.DUP)
        self.assertEqual(instructions[3].opcode, ArmDotOpcode.ADD)
        self.assertEqual(instructions[4].opcode, ArmDotOpcode.RET)

        formatted = disasm.format_disassembly(instructions)
        self.assertIn("NOP", formatted)
        self.assertIn("LD_I4      42", formatted)
        self.assertIn("RET", formatted)

    def test_vm_disassembler_operand_types(self):
        disasm = ArmDotVMDisassembler()
        str_val = "SecurePayload"
        str_bytes = str_val.encode("utf-8")
        bytecode = (
            bytes([0x12]) + struct.pack("<q", 9876543210)  # LD_I8
            + bytes([0x13]) + struct.pack("<f", 3.14)  # LD_R4
            + bytes([0x14]) + struct.pack("<d", 2.71828)  # LD_R8
            + bytes([0x15]) + struct.pack("<H", len(str_bytes)) + str_bytes  # LD_STR
            + bytes([0x20]) + struct.pack("<H", 3)  # LD_LOC 3
            + bytes([0x60]) + struct.pack("<I", 0x06000008)  # CALL
            + bytes([0x03])  # RET
        )
        insts = disasm.disassemble(bytecode)
        self.assertEqual(len(insts), 7)
        self.assertEqual(insts[0].operand, 9876543210)
        self.assertAlmostEqual(insts[1].operand, 3.14, places=2)
        self.assertAlmostEqual(insts[2].operand, 2.71828, places=4)
        self.assertEqual(insts[3].operand, "SecurePayload")
        self.assertEqual(insts[4].operand, 3)
        self.assertEqual(insts[5].operand, 0x06000008)

    def test_vm_disassembler_branches(self):
        disasm = ArmDotVMDisassembler()
        # LD_I4 10 (offset 0, len 5)
        # BR_TRUE rel +2 (offset 5, len 5, target = 10 + 2 = 12)
        # NOP (offset 10, len 1)
        # NOP (offset 11, len 1)
        # RET (offset 12, len 1)
        bytecode = (
            bytes([0x11]) + struct.pack("<i", 10)
            + bytes([0x51]) + struct.pack("<i", 2)
            + bytes([0x00])
            + bytes([0x00])
            + bytes([0x03])
        )
        insts = disasm.disassemble(bytecode)
        self.assertEqual(len(insts), 5)
        self.assertEqual(insts[1].opcode, ArmDotOpcode.BR_TRUE)
        self.assertEqual(insts[1].branch_target, 12)
        formatted = insts[1].format()
        self.assertIn("IL_000C", formatted)

    def test_vm_disassembler_switch(self):
        disasm = ArmDotVMDisassembler()
        # SWITCH 2 targets: rel +4, rel +8
        bytecode = (
            bytes([0x59])
            + struct.pack("<I", 2)  # 2 cases
            + struct.pack("<i", 4)
            + struct.pack("<i", 8)
            + bytes([0x00]) * 10
        )
        insts = disasm.disassemble(bytecode)
        self.assertEqual(len(insts), 11)
        self.assertEqual(insts[0].opcode, ArmDotOpcode.SWITCH)
        self.assertEqual(len(insts[0].switch_targets), 2)

    def test_stack_emulator_balance_and_underflow(self):
        emu = ArmDotStackEmulator()
        insts = [
            ArmDotInstruction(0, ArmDotOpcode.LD_I4, b"", 10),
            ArmDotInstruction(5, ArmDotOpcode.LD_I4, b"", 20),
            ArmDotInstruction(10, ArmDotOpcode.ADD, b""),
            ArmDotInstruction(11, ArmDotOpcode.RET, b""),
        ]
        for inst in insts:
            emu.step(inst)
        self.assertEqual(emu.max_depth, 2)
        self.assertFalse(emu.underflow_detected)

        # Underflow check
        emu_under = ArmDotStackEmulator()
        emu_under.step(ArmDotInstruction(0, ArmDotOpcode.POP, b""))
        self.assertTrue(emu_under.underflow_detected)

    def test_corilmethod_headers(self):
        # Tiny method: code_size <= 63
        code = bytes([CILOpcode.LDC_I4_1, CILOpcode.RET])
        tiny_hdr = CorILMethodBuilder.build_tiny_method(code)
        self.assertEqual(len(tiny_hdr), 3)
        self.assertEqual(tiny_hdr[0], (2 << 2) | 0x02)

        # Tiny limit exceeded raises error
        with self.assertRaises(ValueError):
            CorILMethodBuilder.build_tiny_method(bytes([0] * 64))

        # Fat method: 12-byte header
        fat_hdr = CorILMethodBuilder.build_fat_method(code, max_stack=16, local_sig_tok=0x11000001)
        self.assertEqual(len(fat_hdr), 14)
        flags_size, max_stk, c_size, loc_tok = struct.unpack("<HHII", fat_hdr[:12])
        self.assertEqual(flags_size & 0x3, 0x03)
        self.assertEqual(max_stk, 16)
        self.assertEqual(c_size, 2)
        self.assertEqual(loc_tok, 0x11000001)

    def test_devirtualizer_method_reconstruction(self):
        # Construct VM method: ldloc.0, ldc.i4 5, add, stloc.0, ret
        insts = [
            ArmDotInstruction(0, ArmDotOpcode.LD_LOC, b"", 0),
            ArmDotInstruction(1, ArmDotOpcode.LD_I4, b"", 5),
            ArmDotInstruction(6, ArmDotOpcode.ADD, b""),
            ArmDotInstruction(7, ArmDotOpcode.ST_LOC, b"", 0),
            ArmDotInstruction(8, ArmDotOpcode.RET, b""),
        ]
        res = ArmDotDevirtualizer.devirtualize_method(insts, token=0x06000010, local_count=1)
        self.assertEqual(res["token"], 0x06000010)
        self.assertEqual(res["header_format"], "Fat")  # local_count > 0 forces Fat header
        self.assertTrue(res["is_valid_cil"])
        self.assertIn("Method_0x06000010", res["disassembly"])

    def test_devirtualizer_short_and_long_branch_fixup(self):
        # Short branch: br to target
        insts_short = [
            ArmDotInstruction(0, ArmDotOpcode.BR, b"", branch_target=7),
            ArmDotInstruction(5, ArmDotOpcode.NOP, b""),
            ArmDotInstruction(6, ArmDotOpcode.NOP, b""),
            ArmDotInstruction(7, ArmDotOpcode.RET, b""),
        ]
        res_short = ArmDotDevirtualizer.devirtualize_method(insts_short, token=0x06000001)
        self.assertTrue(res_short["is_valid_cil"])
        self.assertEqual(res_short["header_format"], "Tiny")

        # Long branch (> 127 bytes away)
        nops = [ArmDotInstruction(5 + i, ArmDotOpcode.NOP, b"") for i in range(150)]
        insts_long = [
            ArmDotInstruction(0, ArmDotOpcode.BR, b"", branch_target=155),
            *nops,
            ArmDotInstruction(155, ArmDotOpcode.RET, b""),
        ]
        res_long = ArmDotDevirtualizer.devirtualize_method(insts_long, token=0x06000002)
        self.assertTrue(res_long["is_valid_cil"])
        self.assertEqual(res_long["header_format"], "Fat")

    def test_cfg_construction(self):
        insts = [
            ArmDotInstruction(0, ArmDotOpcode.LD_I4, b"", 1),
            ArmDotInstruction(5, ArmDotOpcode.BR_TRUE, b"", branch_target=10),
            ArmDotInstruction(10, ArmDotOpcode.NOP, b""),
            ArmDotInstruction(11, ArmDotOpcode.RET, b""),
        ]
        cfg = ArmDotCFG(insts)
        self.assertTrue(len(cfg.blocks) >= 2)

    def test_stream_cipher_symmetry(self):
        plaintext = b"ArmDotVirtualizedCodeTestPayload12345"
        key = 0x5A8E12F0
        enc = ArmDotUnpacker.encrypt_method_bytecode(plaintext, key)
        self.assertNotEqual(enc, plaintext)
        dec = ArmDotUnpacker.decrypt_method_bytecode(enc, key)
        self.assertEqual(dec, plaintext)

    def test_vm_container_packing_and_carving(self):
        bc1 = bytes([0x11]) + struct.pack("<i", 100) + bytes([0x03])
        bc2 = bytes([0x00, 0x00, 0x03])
        methods = [
            {"token": 0x06000001, "stack_depth": 8, "local_count": 0, "key": 0x12345678, "bytecode": bc1},
            {"token": 0x06000002, "stack_depth": 4, "local_count": 2, "key": 0x87654321, "bytecode": bc2},
        ]
        container_bytes = ArmDotUnpacker.build_vm_container(methods, version=1)

        # Embed into random buffer
        full_data = b"RANDOM_PREFIX" + container_bytes + b"RANDOM_SUFFIX"
        containers = ArmDotUnpacker.extract_vm_containers(full_data)
        self.assertEqual(len(containers), 1)
        c = containers[0]
        self.assertEqual(c["method_count"], 2)
        self.assertEqual(c["methods"][0]["token"], 0x06000001)
        self.assertEqual(c["methods"][0]["bytecode"], bc1)
        self.assertEqual(c["methods"][1]["token"], 0x06000002)
        self.assertEqual(c["methods"][1]["bytecode"], bc2)

    def test_detection_engine(self):
        # Empty data -> NONE
        det_empty = ArmDotUnpacker.detect(b"\x00" * 100)
        self.assertEqual(det_empty["confidence"], "NONE")
        self.assertFalse(det_empty["is_armdot"])

        # Marker only -> MEDIUM
        det_marker = ArmDotUnpacker.detect(b"Header...ArmDot.Client.VirtualizeAttribute...Footer")
        self.assertEqual(det_marker["confidence"], "MEDIUM")
        self.assertTrue(det_marker["is_armdot"])

        # Container only -> MEDIUM
        bc = bytes([0x03])
        c_bytes = ArmDotUnpacker.build_vm_container([{"token": 0x06000001, "bytecode": bc}])
        det_vm = ArmDotUnpacker.detect(c_bytes)
        self.assertEqual(det_vm["confidence"], "MEDIUM")
        self.assertTrue(det_vm["has_virtual_machine"])

        # Marker + Container -> HIGH
        det_high = ArmDotUnpacker.detect(b"ArmDot" + c_bytes)
        self.assertEqual(det_high["confidence"], "HIGH")
        self.assertTrue(det_high["is_armdot"])

    def test_assembly_devirtualization_and_pe_section_injection(self):
        # Build minimal PE
        pe = make_minimal_pe(sections=1)
        # Create container
        bc = bytes([0x11]) + struct.pack("<i", 42) + bytes([0x03])
        methods = [{"token": 0x0600000A, "bytecode": bc, "key": 0}]
        container = ArmDotUnpacker.build_vm_container(methods)
        pe.extend(container)

        rebuilt, rep = ArmDotUnpacker.devirtualize_assembly(bytes(pe))
        self.assertTrue(rep["success"])
        self.assertEqual(rep["methods_devirtualized_count"], 1)
        self.assertIn("0x0600000A", rep["devirtualized_tokens"])
        self.assertIn(b".armdot", rebuilt)

        # Inspect NumberOfSections in rebuilt PE
        e_lfanew = struct.unpack_from("<I", rebuilt, 0x3C)[0]
        num_sec = struct.unpack_from("<H", rebuilt, e_lfanew + 6)[0]
        self.assertEqual(num_sec, 2)  # Original 1 + 1 new .armdot section

    def test_safe_directory_extraction(self):
        pe = make_minimal_pe(sections=1)
        bc = bytes([0x11]) + struct.pack("<i", 999) + bytes([0x03])
        container = ArmDotUnpacker.build_vm_container([{"token": 0x06000001, "bytecode": bc}])
        pe.extend(container)

        out_dir = os.path.join(self.temp_dir, "armdot_extract")
        files = ArmDotUnpacker.unpack_to_directory(bytes(pe), out_dir)
        self.assertTrue(len(files) >= 4)
        self.assertTrue(any(f.endswith("devirtualized_main.exe") for f in files))
        self.assertTrue(any(f.endswith(".cil.bin") for f in files))
        self.assertTrue(any(f.endswith(".disasm.txt") for f in files))
        self.assertTrue(any(f.endswith("armdot_opcode_table.json") for f in files))
        self.assertTrue(any(f.endswith("armdot_report.json") for f in files))

    def test_path_traversal_defense(self):
        pe = make_minimal_pe(sections=1)
        container = ArmDotUnpacker.build_vm_container([{"token": 0x06000001, "bytecode": bytes([0x03])}])
        pe.extend(container)

        # Attempt extraction with malicious directory traversal
        traversal_dir = os.path.join(self.temp_dir, "nested", "..", "..", "escape_attempt")
        # Should either resolve cleanly inside or handle without escaping root boundaries
        try:
            files = ArmDotUnpacker.unpack_to_directory(bytes(pe), traversal_dir)
            for f in files:
                self.assertTrue(os.path.realpath(f).startswith(os.path.realpath(traversal_dir)))
        except SecurityError:
            pass

    def test_core_orchestration_apis(self):
        pe = make_minimal_pe(sections=1)
        bc = bytes([0x11]) + struct.pack("<i", 777) + bytes([0x03])
        container = ArmDotUnpacker.build_vm_container([{"token": 0x06000005, "bytecode": bc}])
        pe.extend(b"ArmDot.Client.VirtualizeAttribute")
        pe.extend(container)

        target_file = os.path.join(self.temp_dir, "armdot_sample.exe")
        with open(target_file, "wb") as f:
            f.write(pe)

        # Analyze file
        report = DotNetPackerCore.analyze_file(target_file)
        self.assertIn("armdot", report)
        armdot_rep = report["armdot"]
        self.assertTrue(armdot_rep["detected"])
        self.assertTrue(armdot_rep["has_virtual_machine"])
        self.assertEqual(armdot_rep["vm_method_count"], 1)

        # Disassemble API
        disasm_list = DotNetPackerCore.disassemble_armdot_vm(target_file)
        self.assertEqual(len(disasm_list), 1)
        self.assertEqual(disasm_list[0]["token"], "0x06000005")

        # Devirtualize API
        out_exe = os.path.join(self.temp_dir, "armdot_devirtualized.exe")
        rebuilt_pe, rep = DotNetPackerCore.devirtualize_armdot(target_file, output_path=out_exe)
        self.assertTrue(rep["success"])
        self.assertTrue(os.path.exists(out_exe))


if __name__ == "__main__":
    unittest.main()
