"""
Comprehensive Unit & Integration Test Suite for CIL Control Flow Graph (CFG) & Visualizer.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET

from dotnet_deobfuscator.cfg import (
    BlockAnomalyFlag,
    BlockEntropyLevel,
    CFGAnalysisResult,
    CFGAnalyzer,
    CFGBlock,
    CFGBuilder,
    CFGEdgeType,
    CFGInstruction,
    CFGTelemetry,
    CFGVisualizer,
    CILDisassembler,
    FlowControl,
    MethodCFG,
    SecurityError,
    calculate_entropy,
    zeroize_buffer,
)


class TestCFGDisassembler(unittest.TestCase):
    """Tests ECMA-335 CIL bytecode disassembly across 1-byte, 2-byte, branch, and switch opcodes."""

    def test_cil_disassembler_basic(self):
        # ldc.i4.0 (0x16), stloc.0 (0x0A), ldloc.0 (0x06), ldc.i4.1 (0x17), add (0x58), ret (0x2A)
        bytecode = bytes([0x16, 0x0A, 0x06, 0x17, 0x58, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(len(insts), 6)
        self.assertEqual(insts[0].name, "ldc.i4.0")
        self.assertEqual(insts[1].name, "stloc.0")
        self.assertEqual(insts[4].name, "add")
        self.assertEqual(insts[5].name, "ret")
        self.assertEqual(insts[5].flow_control, FlowControl.RET)

    def test_cil_disassembler_branches(self):
        # ldc.i4.1 (0x17), brtrue.s +2 (0x2D, 0x02), ldc.i4.0 (0x16), ret (0x2A), ldc.i4.1 (0x17), ret (0x2A)
        # Offsets:
        # 0: ldc.i4.1 (1)
        # 1: brtrue.s (2) -> target is 1 + 2 + 2 = 5
        # 3: ldc.i4.0 (1)
        # 4: ret (1)
        # 5: ldc.i4.1 (1)
        # 6: ret (1)
        bytecode = bytes([0x17, 0x2D, 0x02, 0x16, 0x2A, 0x17, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(len(insts), 6)
        br_inst = insts[1]
        self.assertEqual(br_inst.name, "brtrue.s")
        self.assertEqual(br_inst.branch_target, 5)
        self.assertTrue(br_inst.is_conditional())

    def test_cil_disassembler_two_byte_opcodes(self):
        # ldloc.0 (0x06), ldloc.1 (0x07), ceq (0xFE, 0x01), ret (0x2A)
        bytecode = bytes([0x06, 0x07, 0xFE, 0x01, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(len(insts), 4)
        ceq_inst = insts[2]
        self.assertEqual(ceq_inst.opcode, 0xFE01)
        self.assertEqual(ceq_inst.name, "ceq")
        self.assertEqual(ceq_inst.size, 2)

    def test_cil_disassembler_switch(self):
        # switch with 2 targets
        # 0: switch (0x45), count=2 (0x02,0x00,0x00,0x00), rel0 = 0x05, rel1 = 0x07
        # Switch size = 1 + 4 + 8 = 13 bytes. Next instruction is at 13.
        # target0 = 13 + 5 = 18, target1 = 13 + 7 = 20
        bytecode = (
            bytes([0x45])
            + (2).to_bytes(4, "little")
            + (5).to_bytes(4, "little", signed=True)
            + (7).to_bytes(4, "little", signed=True)
        )
        insts = CILDisassembler.disassemble(bytecode)
        self.assertEqual(len(insts), 1)
        sw_inst = insts[0]
        self.assertEqual(sw_inst.name, "switch")
        self.assertEqual(len(sw_inst.switch_targets), 2)
        self.assertEqual(sw_inst.switch_targets[0], 18)
        self.assertEqual(sw_inst.switch_targets[1], 20)


class TestCFGBuilder(unittest.TestCase):
    """Tests Basic Block formation, directed edge creation, cyclomatic complexity, loops, and dead code."""

    def test_cfg_builder_linear(self):
        # Straight-line code: ldc.i4.0, stloc.0, ret
        bytecode = bytes([0x16, 0x0A, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        cfg = CFGBuilder.build(insts, method_token=0x06000001, method_name="LinearMethod")

        self.assertEqual(len(cfg.blocks), 1)
        self.assertEqual(len(cfg.edges), 0)
        self.assertEqual(cfg.cyclomatic_complexity, 1)
        self.assertTrue(cfg.blocks[0].is_entry)
        self.assertTrue(cfg.blocks[0].is_exit)
        self.assertFalse(cfg.blocks[0].is_dead)

    def test_cfg_builder_if_else(self):
        # if (x) { return 1; } else { return 0; }
        # 0: ldc.i4.1 (1)
        # 1: brfalse.s IL_0006 (2, rel=+3 -> 1+2+3=6)
        # 3: ldc.i4.1 (1)
        # 4: ret (1)
        # 5: nop (1) [dead or separator]
        # 6: ldc.i4.0 (1)
        # 7: ret (1)
        bytecode = bytes([0x17, 0x2D, 0x03, 0x17, 0x2A, 0x00, 0x16, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        cfg = CFGBuilder.build(insts, method_token=0x06000002, method_name="IfElseMethod")

        self.assertGreaterEqual(len(cfg.blocks), 2)
        self.assertGreaterEqual(cfg.cyclomatic_complexity, 2)
        self.assertIn(0, cfg.blocks)
        b0 = cfg.blocks[0]
        self.assertTrue(b0.is_entry)
        self.assertGreaterEqual(len(b0.successors), 2)

    def test_cfg_builder_loop_and_backedge(self):
        # Simple loop:
        # 0: ldc.i4.0 (1)
        # 1: br.s IL_0005 (rel=+2 -> 1+2+2 = 5)
        # 3: ldc.i4.1 (1)
        # 4: add (1)
        # 5: dup (1)
        # 6: ldc.i4.5 (1)
        # 7: blt.s IL_0003 (rel=-6 -> 7+2-6 = 3) [back-edge!]
        # 9: ret (1)
        bytecode = bytes([0x16, 0x2B, 0x02, 0x17, 0x58, 0x25, 0x1B, 0x37, 0xFA, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        cfg = CFGBuilder.build(insts, method_token=0x06000003, method_name="LoopMethod")

        self.assertGreaterEqual(cfg.loop_count, 1)
        has_loop_head = any(b.is_loop_head for b in cfg.blocks.values())
        self.assertTrue(has_loop_head)
        self.assertGreaterEqual(cfg.cyclomatic_complexity, 2)

    def test_cfg_builder_dead_code(self):
        # 0: ldc.i4.1
        # 1: ret
        # 2: ldc.i4.2  <-- unreachable dead code
        # 3: ret
        bytecode = bytes([0x17, 0x2A, 0x18, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        cfg = CFGBuilder.build(insts, method_token=0x06000004, method_name="DeadCodeMethod")

        self.assertEqual(len(cfg.blocks), 2)
        self.assertEqual(cfg.dead_block_count, 1)
        self.assertTrue(cfg.blocks[1].is_dead)
        self.assertIn(BlockAnomalyFlag.UNREACHABLE_DEAD_CODE, cfg.blocks[1].anomaly_flags)

    def test_cfg_builder_entropy_profiling(self):
        # High entropy block constructed with varied 64-bit constants
        high_ent_bytes = bytearray()
        for i in range(16):
            high_ent_bytes += bytes([0x21]) + bytes([(i * 31 + j * 7 + 13) % 256 for j in range(8)])
        high_ent_bytes += bytes([0x2A])  # ret
        insts = CILDisassembler.disassemble(bytes(high_ent_bytes))
        cfg = CFGBuilder.build(insts, method_token=0x06000005, method_name="HighEntropyMethod")

        self.assertGreaterEqual(cfg.max_entropy, 5.5)
        self.assertGreaterEqual(len(cfg.blocks), 1)
        self.assertGreaterEqual(cfg.high_entropy_block_count, 1)


class TestCFGVisualizer(unittest.TestCase):
    """Tests Mermaid, Graphviz DOT, standalone SVG, ASCII, and JSON diagram generation."""

    def setUp(self):
        # if-else method
        bytecode = bytes([0x17, 0x2D, 0x03, 0x17, 0x2A, 0x00, 0x16, 0x2A])
        insts = CILDisassembler.disassemble(bytecode)
        self.cfg = CFGBuilder.build(insts, method_token=0x0600000A, method_name="VisualTarget")

    def test_export_mermaid(self):
        mmd = CFGVisualizer.export_mermaid(self.cfg)
        self.assertTrue(mmd.startswith("flowchart TD"))
        self.assertIn("classDef default", mmd)
        self.assertIn("classDef highEntropy", mmd)
        self.assertIn("B0", mmd)
        self.assertIn("-->", mmd)

    def test_export_dot(self):
        dot = CFGVisualizer.export_dot(self.cfg)
        self.assertTrue(dot.startswith('digraph "'))
        self.assertIn('rankdir="TB";', dot)
        self.assertIn("B0 [", dot)
        self.assertIn("->", dot)

    def test_export_svg_well_formedness(self):
        svg = CFGVisualizer.export_svg(self.cfg)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        # Strict XML parse verification (validates 100% well-formedness, no unescaped entities)
        root = ET.fromstring(svg)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        # Ensure zero external images or href leaks
        self.assertNotIn("http://", svg.replace("http://www.w3.org/2000/svg", ""))
        self.assertNotIn("https://", svg)

    def test_export_ascii(self):
        ascii_text = CFGVisualizer.export_ascii(self.cfg)
        self.assertIn("=== [CIL Control Flow Graph: VisualTarget", ascii_text)
        self.assertIn("Nodes (Blocks):", ascii_text)
        self.assertIn("+----------------------------------------------------------------------+", ascii_text)
        self.assertIn("Block B0", ascii_text)

    def test_export_json(self):
        j_dict = CFGVisualizer.export_json(self.cfg)
        self.assertIsInstance(j_dict, dict)
        self.assertEqual(j_dict["method_token_hex"], "0x0600000A")
        self.assertIn("blocks", j_dict)
        self.assertIn("edges", j_dict)


class TestCFGAnalyzerAndExporter(unittest.TestCase):
    """Tests high-level CFG forensic analyzer, safe directory exporter, and memory security."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_cfg_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_analyze_bytecode(self):
        bytecode = bytes([0x16, 0x0A, 0x06, 0x17, 0x58, 0x2A])
        cfg = CFGAnalyzer.analyze_bytecode(bytecode, method_token=0x06000010, method_name="BytecodeTest")
        self.assertEqual(cfg.method_token, 0x06000010)
        self.assertEqual(len(cfg.blocks), 1)

    def test_analyze_binary_buffer(self):
        # Synthetic binary containing CorILMethod Tiny header (0x0A = (2 << 2) | 0x02) + 2 bytes code + ret
        # header = 0x0A, code = ldc.i4.0 (0x16), ret (0x2A)
        data = b"\x00" * 32 + bytes([0x0A, 0x16, 0x2A]) + b"\x00" * 32
        result = CFGAnalyzer.analyze(data, file_name="synthetic.exe")

        self.assertIsInstance(result, CFGAnalysisResult)
        self.assertEqual(result.file_name, "synthetic.exe")
        self.assertGreaterEqual(result.telemetry.total_methods_analyzed, 1)
        self.assertGreaterEqual(result.telemetry.total_blocks, 1)

    def test_export_to_directory(self):
        data = b"\x00" * 32 + bytes([0x0A, 0x16, 0x2A]) + b"\x00" * 32
        result = CFGAnalyzer.analyze(data, file_name="test_binary.exe")

        export_dir = os.path.join(self.temp_dir, "cfg_out")
        exp_res = CFGAnalyzer.export_to_directory(result, export_dir, formats=["all"])

        self.assertTrue(os.path.isdir(export_dir))
        self.assertTrue(os.path.isfile(exp_res["manifest_path"]))
        self.assertGreater(exp_res["exported_files_count"], 1)

        # Verify manifest content
        with open(exp_res["manifest_path"], "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["source_file"], "test_binary.exe")
        self.assertIn("telemetry", manifest)

        # Verify SVG well-formedness among exported files
        for fpath in exp_res["exported_files"]:
            if fpath.endswith(".svg"):
                with open(fpath, "r", encoding="utf-8") as fp:
                    svg_content = fp.read()
                ET.fromstring(svg_content)  # Must parse without exception

    def test_security_path_traversal(self):
        data = bytes([0x16, 0x2A])
        result = CFGAnalyzer.analyze(data)
        with self.assertRaises(SecurityError):
            from dotnet_deobfuscator.cfg.analyzer import _safe_path
            _safe_path(self.temp_dir, "../../escaped.json")

    def test_zeroize_buffer(self):
        buf = bytearray(b"SecretCILDecryptedBytes12345")
        self.assertNotEqual(bytes(buf), bytes(len(buf)))
        zeroize_buffer(buf)
        self.assertEqual(bytes(buf), bytes(len(buf)))


if __name__ == "__main__":
    unittest.main()
