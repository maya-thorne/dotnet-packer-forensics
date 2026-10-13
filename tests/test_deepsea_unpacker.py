"""
Comprehensive Unit & Integration Test Suite for DeepSea Obfuscator Forensic Unpacker.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from dotnet_deobfuscator.cli import main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.deepsea import DeepSeaUnpacker, SecurityError
from dotnet_deobfuscator.unpackers.deepsea_deflattener import (
    ASTReconstructor,
    CILDisassembler,
    CILEmitter,
    DeepSeaDeflattener,
    OpaquePredicateEliminator,
)
from dotnet_deobfuscator.unpackers.deepsea_models import (
    ASTBlock,
    ASTMethod,
    ASTStatement,
    BasicBlock,
    CILInstruction,
    CILOpcode,
    CILOperandType,
    ControlFlowGraph,
    FlowControl,
)


def make_synthetic_pe(section_name: bytes = b".text\x00\x00\x00") -> bytearray:
    """Constructs minimal valid 32-bit PE binary buffer for testing."""
    buf = bytearray(4096)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)

    # NT Header
    struct.pack_into("<I", buf, 0x80, 0x00004550)  # 'PE\0\0'
    struct.pack_into("<H", buf, 0x84, 0x014C)      # i386
    struct.pack_into("<H", buf, 0x86, 1)           # 1 section
    struct.pack_into("<H", buf, 0x94, 0x00E0)      # Optional Header size: 224 bytes
    struct.pack_into("<H", buf, 0x96, 0x0102)      # Executable image

    # Optional Header (PE32)
    opt_base = 0x98
    struct.pack_into("<H", buf, opt_base, 0x010B)  # PE32 magic
    struct.pack_into("<I", buf, opt_base + 16, 0x1000)  # EntryPoint
    struct.pack_into("<I", buf, opt_base + 32, 0x2000)  # SectionAlignment
    struct.pack_into("<I", buf, opt_base + 36, 0x0200)  # FileAlignment
    struct.pack_into("<I", buf, opt_base + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", buf, opt_base + 60, 0x0200)  # SizeOfHeaders
    struct.pack_into("<H", buf, opt_base + 68, 2)       # Windows CUI
    struct.pack_into("<I", buf, opt_base + 116, 16)     # NumberOfRvaAndSizes

    # Section 1 (.text)
    sect_base = 0x178
    buf[sect_base : sect_base + 8] = section_name
    struct.pack_into("<I", buf, sect_base + 8, 0x0200)   # VirtualSize
    struct.pack_into("<I", buf, sect_base + 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", buf, sect_base + 16, 0x0200)  # SizeOfRawData
    struct.pack_into("<I", buf, sect_base + 20, 0x0200)  # PointerToRawData
    struct.pack_into("<I", buf, sect_base + 36, 0x60000020)  # Code, Executable, Readable

    # Code payload in .text section
    buf[0x0200 : 0x0200 + 4] = b"\x16\x2a\x00\x00"  # ldc.i4.0, ret
    return buf


class TestDeepSeaModelsAndDisassembler(unittest.TestCase):
    """Tests CIL instruction models, disassembler, and basic block structures."""

    def test_disassemble_basic_instructions(self):
        # ldc.i4.1, stloc.0, ldloc.0, ret
        bytecode = bytes([0x17, 0x0A, 0x06, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(len(insts), 4)
        self.assertEqual(insts[0].name, "ldc.i4.1")
        self.assertEqual(insts[1].name, "stloc.0")
        self.assertEqual(insts[2].name, "ldloc.0")
        self.assertEqual(insts[3].name, "ret")
        self.assertTrue(insts[3].is_terminator())

    def test_disassemble_two_byte_opcodes(self):
        # ceq (FE 01), cgt (FE 02), clt (FE 04)
        bytecode = bytes([0xFE, 0x01, 0xFE, 0x02, 0xFE, 0x04])
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(len(insts), 3)
        self.assertEqual(insts[0].opcode, 0xFE01)
        self.assertEqual(insts[0].name, "ceq")
        self.assertEqual(insts[1].opcode, 0xFE02)
        self.assertEqual(insts[1].name, "cgt")
        self.assertEqual(insts[2].opcode, 0xFE04)
        self.assertEqual(insts[2].name, "clt")

    def test_disassemble_branch_and_switch(self):
        # br.s +2 (0x2B, 0x02), switch count=2 offsets (0x45, count=2, off1, off2)
        bytecode = bytes([
            0x2B, 0x02,              # br.s -> offset 4
            0x00, 0x00,              # nop, nop
            0x45, 0x02, 0x00, 0x00, 0x00,  # switch count=2
            0x04, 0x00, 0x00, 0x00,        # target 1
            0x08, 0x00, 0x00, 0x00,        # target 2
        ])
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(insts[0].name, "br.s")
        self.assertEqual(insts[0].branch_target, 4)
        self.assertEqual(insts[3].name, "switch")
        self.assertEqual(len(insts[3].switch_targets), 2)

    def test_opaque_predicate_elimination(self):
        # ldc.i4.1, brtrue.s +4 -> converts to br.s
        # ldc.i4.0, brtrue.s +4 -> pruned dead branch
        bytecode = bytes([
            0x17, 0x2D, 0x04,  # ldc.i4.1, brtrue.s
            0x16, 0x2D, 0x04,  # ldc.i4.0, brtrue.s (dead)
            0x2A,              # ret
        ])
        insts = CILDisassembler.disassemble(bytecode)
        clean = OpaquePredicateEliminator.eliminate(insts)
        self.assertEqual(len(clean), 2)
        self.assertEqual(clean[0].name, "br.s")
        self.assertEqual(clean[1].name, "ret")

    def test_cfg_export_formats(self):
        b0 = BasicBlock(0, 0)
        b0.instructions.append(CILInstruction(0, CILOpcode.LDC_I4_1, "ldc.i4.1"))
        b0.successors.add(1)

        b1 = BasicBlock(1, 2)
        b1.instructions.append(CILInstruction(2, CILOpcode.RET, "ret", flow_control=FlowControl.RET))

        cfg = ControlFlowGraph(blocks={0: b0, 1: b1}, entry_id=0)
        dot = cfg.export_dot()
        mermaid = cfg.export_mermaid()

        self.assertIn("digraph", dot)
        self.assertIn("B0 -> B1", dot)
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("B0 --> B1", mermaid)


class TestDeepSeaControlFlowDeflattener(unittest.TestCase):
    """Tests control flow de-flattening algorithm and state machine resolution."""

    def setUp(self):
        # Constructs a synthetic flattened state machine:
        # Prologue:
        #   0: ldc.i4.1
        #   1: stloc.0
        #   2: br.s IL_04 (dispatcher)
        # Dispatcher:
        #   4: ldloc.0
        #   5: switch count=3 [IL_16 (case 0), IL_1C (case 1), IL_22 (case 2)]
        # Case 0 (Terminal):
        #   16: ret
        # Case 1 (Step 1):
        #   1C: ldc.i4.2
        #   1D: stloc.0
        #   1E: br.s IL_04
        # Case 2 (Step 2):
        #   22: ldc.i4.0
        #   23: stloc.0
        #   24: br.s IL_04
        self.flattened_bytecode = bytes([
            # Prologue
            0x17,              # 0x00: ldc.i4.1 (initial state = 1)
            0x0A,              # 0x01: stloc.0
            0x2B, 0x01,        # 0x02: br.s -> 0x05 (dispatcher)
            0x00,              # 0x04: nop alignment
            # Dispatcher
            0x06,              # 0x05: ldloc.0
            0x45, 0x03, 0x00, 0x00, 0x00,  # 0x06..0x0A: switch count=3
            0x00, 0x00, 0x00, 0x00,        # 0x0B..0x0E: case 0 rel=0 -> 0x17
            0x01, 0x00, 0x00, 0x00,        # 0x0F..0x12: case 1 rel=1 -> 0x18
            0x05, 0x00, 0x00, 0x00,        # 0x13..0x16: case 2 rel=5 -> 0x1C
            # Case 0 (State 0, Terminal)
            0x2A,              # 0x17: ret
            # Case 1 (State 1, Step 1)
            0x18,              # 0x18: ldc.i4.2 (next state = 2)
            0x0A,              # 0x19: stloc.0
            0x2B, 0xE9,        # 0x1A..0x1B: br.s -> dispatcher @ 0x05 (0x1C - 23 = 0x05)
            # Case 2 (State 2, Step 2)
            0x16,              # 0x1C: ldc.i4.0 (next state = 0)
            0x0A,              # 0x1D: stloc.0
            0x2B, 0xE5,        # 0x1E..0x1F: br.s -> dispatcher @ 0x05 (0x20 - 27 = 0x05)
        ])

    def test_deflatten_state_machine_flow(self):
        raw_insts = CILDisassembler.disassemble(self.flattened_bytecode)
        ordered_blocks, clean_cfg = DeepSeaDeflattener.deflatten(raw_insts)

        # Dispatcher should be pruned
        for b in ordered_blocks:
            self.assertFalse(b.is_dispatcher)

        # Flow must connect Case 1 -> Case 2 -> Case 0
        state_map = {b.state_id: b for b in ordered_blocks if b.state_id is not None}
        self.assertIn(1, state_map)
        self.assertIn(2, state_map)
        self.assertIn(0, state_map)

        block_state1 = state_map[1]
        block_state2 = state_map[2]
        block_state0 = state_map[0]

        self.assertIn(block_state2.block_id, block_state1.successors)
        self.assertIn(block_state0.block_id, block_state2.successors)

    def test_cil_emission(self):
        raw_insts = CILDisassembler.disassemble(self.flattened_bytecode)
        ordered_blocks, clean_cfg = DeepSeaDeflattener.deflatten(raw_insts)
        clean_cil = CILEmitter.emit_method(ordered_blocks)

        self.assertIsInstance(clean_cil, bytes)
        self.assertGreater(len(clean_cil), 0)
        # Should terminate with ret (0x2A)
        self.assertEqual(clean_cil[-1], 0x2A)

    def test_ast_reconstruction(self):
        raw_insts = CILDisassembler.disassemble(self.flattened_bytecode)
        ordered_blocks, clean_cfg = DeepSeaDeflattener.deflatten(raw_insts)
        ast = ASTReconstructor.reconstruct(ordered_blocks)

        self.assertIsInstance(ast, ASTMethod)
        self.assertEqual(ast.name, "RestoredMethod")
        csharp_code = ast.to_csharp()
        self.assertIn("public void RestoredMethod()", csharp_code)
        self.assertIn("return", csharp_code)

        ast_dict = ast.to_dict()
        self.assertEqual(ast_dict["type"], "METHOD")
        self.assertIn("body", ast_dict)


class TestDeepSeaUnpackerOrchestrator(unittest.TestCase):
    """Tests high-level DeepSeaUnpacker detection, assembly de-flattening, and directory export."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pe_data = bytes(make_synthetic_pe())

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_detect_positive_markers(self):
        data_with_marker = self.pe_data + b"DeepSeaObfuscator\x00DSAttribute\x00"
        res = DeepSeaUnpacker.detect(data_with_marker)
        self.assertTrue(res["is_deepsea"])
        self.assertIn("DeepSeaObfuscator", res["matched_markers"])

    def test_detect_negative_markers(self):
        clean_data = self.pe_data
        res = DeepSeaUnpacker.detect(clean_data)
        self.assertFalse(res["is_deepsea"])
        self.assertEqual(len(res["matched_markers"]), 0)

    def test_deflatten_assembly_section_injection(self):
        data = self.pe_data + b"DeepSeaObfuscator\x00"
        rebuilt_pe, rep = DeepSeaUnpacker.deflatten_assembly(data)

        self.assertGreater(len(rebuilt_pe), len(data))
        self.assertIn(b".deepsea", rebuilt_pe)
        self.assertEqual(rep["methods_deflattened"], 1)
        self.assertEqual(len(rep["methods"]), 1)

    def test_unpack_to_directory_artifacts(self):
        data = self.pe_data + b"DeepSeaObfuscator\x00"
        out_dir = os.path.join(self.tmp_dir.name, "deepsea_out")
        manifest = DeepSeaUnpacker.unpack_to_directory(data, out_dir)

        self.assertTrue(os.path.exists(os.path.join(out_dir, "deflattened_main.exe")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "deepsea_forensic_report.json")))
        methods_dir = os.path.join(out_dir, "methods")
        self.assertTrue(os.path.exists(methods_dir))
        self.assertTrue(os.path.exists(os.path.join(methods_dir, "EntryMethod_clean.bin")))
        self.assertTrue(os.path.exists(os.path.join(methods_dir, "EntryMethod_ast.json")))
        self.assertTrue(os.path.exists(os.path.join(methods_dir, "EntryMethod_decompiled.cs")))
        self.assertTrue(os.path.exists(os.path.join(methods_dir, "EntryMethod_cfg.dot")))
        self.assertTrue(os.path.exists(os.path.join(methods_dir, "EntryMethod_cfg.mermaid")))
        self.assertEqual(manifest["rebuilt_binary"], "deflattened_main.exe")

    def test_path_traversal_defense(self):
        with self.assertRaises(SecurityError):
            DeepSeaUnpacker._safe_path(self.tmp_dir.name, "../../escaped.exe")

    def test_payload_bounds_check(self):
        oversized = bytes(101 * 1024 * 1024)  # 101 MB exceeds 100 MB cap
        with self.assertRaises(SecurityError):
            DeepSeaUnpacker.deflatten_method(oversized)


class TestCoreAndCLIIntegration(unittest.TestCase):
    """Tests core orchestrator and CLI invocation with DeepSea flags."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.sample_exe = os.path.join(self.tmp_dir.name, "deepsea_sample.exe")
        pe_buf = make_synthetic_pe() + b"DeepSeaObfuscator\x00"
        with open(self.sample_exe, "wb") as f:
            f.write(pe_buf)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_core_analyze_file_includes_deepsea(self):
        rep = DotNetPackerCore.analyze_file(self.sample_exe)
        self.assertIn("deepsea", rep)
        self.assertTrue(rep["deepsea"]["detected"])
        self.assertIn("DeepSeaObfuscator", rep["deepsea"]["matched_markers"])

    def test_core_deflatten_deepsea_api(self):
        out_exe = os.path.join(self.tmp_dir.name, "core_deflattened.exe")
        rebuilt_pe, ds_rep = DotNetPackerCore.deflatten_deepsea(self.sample_exe, output_path=out_exe)
        self.assertTrue(os.path.exists(out_exe))
        self.assertGreater(len(rebuilt_pe), 0)
        self.assertEqual(len(ds_rep["methods"]), 1)

    def test_cli_deflatten_flags(self):
        out_exe = os.path.join(self.tmp_dir.name, "cli_deflattened.exe")
        ret = main([
            self.sample_exe,
            "--deflatten-deepsea",
            "--deepsea-out",
            out_exe,
            "--export-ast",
            "--export-cfg",
            "--format",
            "text",
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(out_exe))
        self.assertTrue(os.path.exists(f"{out_exe}.ast.json"))
        self.assertTrue(os.path.exists(f"{out_exe}.cfg.dot"))


if __name__ == "__main__":
    unittest.main()
