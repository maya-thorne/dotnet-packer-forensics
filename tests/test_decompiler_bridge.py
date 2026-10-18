"""
Unit and Integration Test Suite for Ghidra & IDA Pro Decompiler Headless Bridge.
Engineered & Audited by Maya Thorne.
"""

import csv
import ctypes
import json
import os
import shutil
import tempfile
import unittest

from dotnet_deobfuscator import (
    CommentType,
    DecompilerBookmark,
    DecompilerBridgeEngine,
    DecompilerBridgeOptions,
    DecompilerBridgeResult,
    DecompilerBridgeTelemetry,
    DecompilerComment,
    DecompilerEngine,
    DecompilerSymbol,
    DecompilerTypeStruct,
    DotNetPackerCore,
    GhidraBridgeGenerator,
    IDABridgeGenerator,
    Radare2BridgeGenerator,
    SymbolSynchronizer,
    SymbolType,
)
from dotnet_deobfuscator.cli_args import build_parser
from dotnet_deobfuscator.decompiler_bridge import SecurityError
from dotnet_deobfuscator.decompiler_bridge.models import (
    calculate_entropy,
    safe_path,
    zeroize_buffer,
)
from dotnet_deobfuscator.fuzzing import SyntheticMutatedBinaryGenerator


def create_mock_pe() -> bytes:
    """Generates a minimal valid baseline PE binary for testing."""
    return SyntheticMutatedBinaryGenerator.generate_baseline_pe(is_64bit=True)


class TestDecompilerModelsAndSecurity(unittest.TestCase):
    """Tests for data models, enums, dataclasses, and security sanitizers."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_dec_models_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_enums_and_dataclasses(self):
        self.assertEqual(DecompilerEngine.GHIDRA.value, "ghidra")
        self.assertEqual(DecompilerEngine.IDA_PRO.value, "ida_pro")
        self.assertEqual(DecompilerEngine.RADARE2.value, "radare2")
        self.assertEqual(DecompilerEngine.ALL.value, "all")

        sym = DecompilerSymbol(
            name="TestSymbol",
            rva=0x1000,
            size=64,
            symbol_type=SymbolType.FUNCTION,
            is_function=True,
            token=0x06000001,
            confidence=0.95,
            tags=["test", "unit"],
            demangled_name="MyNamespace.MyClass.TestMethod()",
        )
        d_sym = sym.to_dict()
        self.assertEqual(d_sym["name"], "TestSymbol")
        self.assertEqual(d_sym["rva"], 0x1000)
        self.assertEqual(d_sym["symbol_type"], "function")
        self.assertEqual(d_sym["token"], 0x06000001)
        self.assertIn("unit", d_sym["tags"])

        cmt = DecompilerComment(
            rva=0x1000,
            text="Test plate comment",
            comment_type=CommentType.PLATE,
            is_repeatable=True,
        )
        d_cmt = cmt.to_dict()
        self.assertEqual(d_cmt["rva"], 0x1000)
        self.assertEqual(d_cmt["comment_type"], "plate")
        self.assertTrue(d_cmt["is_repeatable"])

        bm = DecompilerBookmark(rva=0x1000, category="Forensics", comment="Suspicious Block")
        self.assertEqual(bm.to_dict()["category"], "Forensics")

        st = DecompilerTypeStruct(name="MyStruct", size=16, fields=[{"name": "f1", "offset": 0}])
        self.assertEqual(st.to_dict()["name"], "MyStruct")

        tel = DecompilerBridgeTelemetry(
            total_symbols=5, total_comments=3, total_bookmarks=2, total_structs=1,
            engine="all", generation_time_ms=12.5, confidence_avg=0.92,
        )
        self.assertEqual(tel.to_dict()["total_symbols"], 5)

        res = DecompilerBridgeResult(
            engine=DecompilerEngine.ALL, base_addr=0x400000,
            symbols=[sym], comments=[cmt], bookmarks=[bm], structs=[st],
            telemetry=tel, ghidra_script="# ghidra", ida_script="# ida",
        )
        d_res = res.to_dict()
        self.assertEqual(d_res["engine"], "all")
        self.assertEqual(d_res["base_addr"], "0x400000")
        self.assertTrue(d_res["has_ghidra_script"])
        self.assertTrue(d_res["has_ida_script"])
        self.assertFalse(d_res["has_radare2_script"])

    def test_safe_path(self):
        base_dir = self.temp_dir
        valid_file = safe_path(base_dir, "subdir/script.py")
        self.assertTrue(valid_file.startswith(os.path.abspath(base_dir)))

        with self.assertRaises(SecurityError):
            safe_path(base_dir, "../outside.py")

        with self.assertRaises(SecurityError):
            safe_path(base_dir, "..\\outside.py")

        outside_abs = os.path.abspath(os.path.join(base_dir, "..", "forbidden_root.py"))
        with self.assertRaises(SecurityError):
            safe_path(base_dir, outside_abs)

    def test_zeroize_buffer(self):
        buf = bytearray(b"sensitive_bytes_key_material")
        zeroize_buffer(buf)
        self.assertTrue(all(b == 0 for b in buf))

        mv = memoryview(bytearray(b"another_secret"))
        zeroize_buffer(mv)
        self.assertTrue(all(b == 0 for b in mv))

        c_buf = (ctypes.c_char * 16)(*b"ctypes_key_1234\x00")
        zeroize_buffer(c_buf)
        self.assertTrue(all(b == 0 or b == b"\x00" for b in c_buf))

    def test_calculate_entropy(self):
        self.assertEqual(calculate_entropy(b""), 0.0)
        self.assertEqual(calculate_entropy(b"\x00" * 100), 0.0)
        full_byte_range = bytes(range(256))
        ent = calculate_entropy(full_byte_range)
        self.assertTrue(7.9 <= ent <= 8.0)


class TestGhidraBridgeGenerator(unittest.TestCase):
    """Tests for Ghidra headless post-analysis script generation and syntax validity."""

    def test_sanitize_label(self):
        self.assertEqual(GhidraBridgeGenerator.sanitize_label("ValidLabel_01"), "ValidLabel_01")
        self.assertEqual(GhidraBridgeGenerator.sanitize_label("123LeadingNum"), "sym_123LeadingNum")
        self.assertEqual(GhidraBridgeGenerator.sanitize_label("Invalid-Chars.With Space!"), "Invalid_Chars_With_Space")
        self.assertEqual(GhidraBridgeGenerator.sanitize_label(""), "sym_unnamed")

    def test_generate_script_syntax_validity(self):
        syms = [
            DecompilerSymbol(name="Sym1", rva=0x1000, size=32, is_function=True, symbol_type=SymbolType.FUNCTION),
            DecompilerSymbol(name="Sym2", rva=0x2000, size=0, is_function=False, symbol_type=SymbolType.METADATA_TOKEN),
        ]
        cmts = [
            DecompilerComment(rva=0x1000, text="Function entry point", comment_type=CommentType.PLATE),
            DecompilerComment(rva=0x1010, text="Call native thunk", comment_type=CommentType.EOL),
        ]
        bms = [
            DecompilerBookmark(rva=0x1000, category="Forensics", comment="Root method"),
        ]

        script = GhidraBridgeGenerator.generate_script(syms, cmts, bms, base_addr=0x140000000)
        compiled = compile(script, "<test_ghidra>", "exec")
        self.assertIsNotNone(compiled)
        self.assertIn("BASE_ADDR = 0x140000000", script)
        self.assertIn("Sym1", script)
        self.assertIn("Function entry point", script)

    def test_runners_generation(self):
        bat = GhidraBridgeGenerator.generate_runner_bat("my_ghidra.py", "my_proj")
        self.assertIn("analyzeHeadless.bat", bat)
        self.assertIn("my_ghidra.py", bat)

        sh = GhidraBridgeGenerator.generate_runner_sh("my_ghidra.py", "my_proj")
        self.assertIn("#!/usr/bin/env bash", sh)
        self.assertIn("analyzeHeadless", sh)


class TestIDABridgeGenerator(unittest.TestCase):
    """Tests for IDA Pro IDAPython script generation and syntax validity."""

    def test_sanitize_label(self):
        self.assertEqual(IDABridgeGenerator.sanitize_label("Sub_Func_01"), "Sub_Func_01")
        self.assertEqual(IDABridgeGenerator.sanitize_label("99Bottles"), "sub_99Bottles")
        self.assertEqual(IDABridgeGenerator.sanitize_label("Name With Spaces"), "Name_With_Spaces")
        self.assertEqual(IDABridgeGenerator.sanitize_label(""), "sub_unnamed")

    def test_generate_script_syntax_validity(self):
        syms = [
            DecompilerSymbol(name="RhpHelperMethod", rva=0x5000, size=128, is_function=True, symbol_type=SymbolType.RUNTIME_HELPER),
            DecompilerSymbol(name="DataBlock", rva=0x6000, size=64, is_function=False, symbol_type=SymbolType.METADATA_TOKEN),
        ]
        cmts = [
            DecompilerComment(rva=0x5000, text="Redhawk Runtime Helper\nMult-line comment", comment_type=CommentType.PLATE),
        ]
        bms = [
            DecompilerBookmark(rva=0x5000, category="Runtime", comment="RhpHelper"),
        ]

        script = IDABridgeGenerator.generate_script(syms, cmts, bms, base_addr=0x400000)
        compiled = compile(script, "<test_ida>", "exec")
        self.assertIsNotNone(compiled)
        self.assertIn("ida_auto.auto_wait()", script)
        self.assertIn("RhpHelperMethod", script)
        self.assertIn("BASE_ADDR = 0x400000", script)

    def test_runners_generation(self):
        bat = IDABridgeGenerator.generate_runner_bat("my_ida.py")
        self.assertIn("idat64.exe", bat)
        self.assertIn("my_ida.py", bat)

        sh = IDABridgeGenerator.generate_runner_sh("my_ida.py")
        self.assertIn("#!/usr/bin/env bash", sh)
        self.assertIn("idat64", sh)


class TestRadare2BridgeGenerator(unittest.TestCase):
    """Tests for Radare2/Cutter script generation."""

    def test_sanitize_flag(self):
        self.assertEqual(Radare2BridgeGenerator.sanitize_flag("flag.main"), "flag.main")
        self.assertEqual(Radare2BridgeGenerator.sanitize_flag("invalid spaces!@#"), "invalid_spaces")

    def test_generate_script_commands(self):
        syms = [
            DecompilerSymbol(name="entry_func", rva=0x1000, size=40, is_function=True, symbol_type=SymbolType.ENTRY_POINT),
        ]
        cmts = [
            DecompilerComment(rva=0x1000, text="Entry comment", comment_type=CommentType.PLATE),
        ]
        bms = [
            DecompilerBookmark(rva=0x1000, category="Entry", comment="Target Entry"),
        ]

        script = Radare2BridgeGenerator.generate_script(syms, cmts, bms, base_addr=0x400000)
        self.assertIn("f entry_func @ 0x401000", script)
        self.assertIn("af+ 0x401000 entry_func 40", script)
        self.assertIn('CC "Entry comment" @ 0x401000', script)

        bat = Radare2BridgeGenerator.generate_runner_bat("r2_test.r2")
        self.assertIn("r2 -q -i", bat)

        sh = Radare2BridgeGenerator.generate_runner_sh("r2_test.r2")
        self.assertIn("r2 -q -i", sh)


class TestSymbolSynchronizer(unittest.TestCase):
    """Tests for correlating forensic subsystems into unified symbols."""

    def test_synchronize_pe_and_cor20(self):
        pe_bytes = create_mock_pe()
        opts = DecompilerBridgeOptions(min_confidence=0.5)
        symbols, comments, bookmarks = SymbolSynchronizer.synchronize(pe_bytes, options=opts)
        self.assertIsInstance(symbols, list)
        self.assertIsInstance(comments, list)
        self.assertIsInstance(bookmarks, list)
        self.assertGreaterEqual(len(symbols), 1)

    def test_synchronize_with_forensic_context(self):
        pe_bytes = create_mock_pe()
        ctx = {
            "assembly_info": {
                "is_pe": True,
                "entry_point": 0x1200,
                "sections": [{"name": ".text", "virtual_address": 0x1000, "raw_size": 4096, "entropy": 6.2}],
            },
            "reactor_methods": {
                0x06000010: {"rva": 0x1500, "code_size": 64, "format": "fat"},
            },
            "eaz_containers": [
                {"id": 1, "rva": 0x2000, "methods": [{"token_hex": "0x06000001", "bytecode": b"\x00"}]},
            ],
            "armdot_containers": [
                {"id": 1, "rva": 0x3000, "methods": []},
            ],
            "babel_merged": [
                {"name": "SatelliteAssembly", "rva": 0x4000},
            ],
        }

        opts = DecompilerBridgeOptions(min_confidence=0.5)
        symbols, comments, bookmarks = SymbolSynchronizer.synchronize(pe_bytes, options=opts, forensic_context=ctx)

        sym_names = [s.name for s in symbols]
        self.assertIn("PE_EntryPoint", sym_names)
        self.assertIn("NecroBit_Method_06000010", sym_names)
        self.assertIn("Eazfuscator_VMContainer_1", sym_names)
        self.assertIn("ArmDot_VMDispatcher_1", sym_names)
        self.assertIn("Babel_Satellite_SatelliteAssembly", sym_names)

    def test_deduplication_and_priority(self):
        s_anomaly = DecompilerSymbol(name="AnomalyBlock", rva=0x1000, symbol_type=SymbolType.ANOMALY_BLOCK, confidence=0.7)
        s_entry = DecompilerSymbol(name="PE_EntryPoint", rva=0x1000, symbol_type=SymbolType.ENTRY_POINT, confidence=1.0)
        s_func = DecompilerSymbol(name="RegularFunc", rva=0x1000, symbol_type=SymbolType.FUNCTION, confidence=0.9)

        deduped = SymbolSynchronizer._deduplicate_symbols([s_anomaly, s_entry, s_func], min_confidence=0.5)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].name, "PE_EntryPoint")
        self.assertEqual(deduped[0].symbol_type, SymbolType.ENTRY_POINT)

    def test_comment_merging(self):
        c1 = DecompilerComment(rva=0x1000, text="First note")
        c2 = DecompilerComment(rva=0x1000, text="Second note")
        merged = SymbolSynchronizer._deduplicate_comments([c1, c2])
        self.assertEqual(len(merged), 1)
        self.assertIn("First note", merged[0].text)
        self.assertIn("Second note", merged[0].text)


class TestDecompilerBridgeEngine(unittest.TestCase):
    """Tests for high-level engine facade and directory exporting."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_dec_engine_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_analyze_and_export(self):
        pe_bytes = create_mock_pe()
        opts = DecompilerBridgeOptions(engine=DecompilerEngine.ALL, base_addr=0x400000)
        res = DecompilerBridgeEngine.analyze(pe_bytes, options=opts)

        self.assertIsInstance(res, DecompilerBridgeResult)
        self.assertIsNotNone(res.ghidra_script)
        self.assertIsNotNone(res.ida_script)
        self.assertIsNotNone(res.radare2_script)
        self.assertGreaterEqual(res.telemetry.total_symbols, 1)

        out_dir = os.path.join(self.temp_dir, "bridge_out")
        exp = DecompilerBridgeEngine.export_to_directory(res, output_dir=out_dir)

        self.assertTrue(os.path.exists(out_dir))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "forensic_annotations_ghidra.py")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "forensic_annotations_ida.py")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "forensic_annotations_r2.r2")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "run_ghidra.bat")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "run_ida.bat")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "symbols.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "symbols.csv")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "telemetry.json")))

        with open(os.path.join(out_dir, "symbols.csv"), "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertIn("Name", header)
            self.assertIn("RVA", header)

        with open(os.path.join(out_dir, "telemetry.json"), "r", encoding="utf-8") as f:
            t_data = json.load(f)
            self.assertIn("total_symbols", t_data)

    def test_analyze_file(self):
        pe_path = os.path.join(self.temp_dir, "sample.exe")
        with open(pe_path, "wb") as f:
            f.write(create_mock_pe())

        res = DecompilerBridgeEngine.analyze_file(pe_path)
        self.assertEqual(res.engine, DecompilerEngine.ALL)
        self.assertGreaterEqual(len(res.symbols), 1)


class TestCoreAndCLIIntegration(unittest.TestCase):
    """Tests for DotNetPackerCore bridge classmethods and CLI flag parsing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_dec_core_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_core_bridge_facade(self):
        pe_path = os.path.join(self.temp_dir, "target.exe")
        with open(pe_path, "wb") as f:
            f.write(create_mock_pe())

        res = DotNetPackerCore.generate_decompiler_bridge(pe_path, engine="ghidra", base_addr=0x140000000)
        self.assertIsInstance(res, DecompilerBridgeResult)
        self.assertIsNotNone(res.ghidra_script)
        self.assertIsNone(res.ida_script)

        out_dir = os.path.join(self.temp_dir, "core_bridge_export")
        exp = DotNetPackerCore.export_decompiler_bridge(pe_path, output_dir=out_dir, engine="ghidra")
        self.assertGreaterEqual(exp["exported_files_count"], 5)

    def test_core_analyze_bytes_wiring(self):
        pe_bytes = create_mock_pe()
        rep = DotNetPackerCore.analyze_bytes(pe_bytes)
        self.assertIn("decompiler_bridge", rep)
        db = rep["decompiler_bridge"]
        self.assertIn("total_symbols", db)
        self.assertIn("engine", db)
        self.assertGreaterEqual(db["total_symbols"], 1)

    def test_cli_parser_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "sample.exe",
            "--decompiler-bridge",
            "--bridge-engine", "ida_pro",
            "--bridge-base-addr", "0x140000000",
            "--bridge-out", "out_dir",
            "--bridge-min-confidence", "0.7",
        ])
        self.assertTrue(args.decompiler_bridge)
        self.assertEqual(args.bridge_engine, "ida_pro")
        self.assertEqual(args.bridge_base_addr, 0x140000000)
        self.assertEqual(args.bridge_out, "out_dir")
        self.assertEqual(args.bridge_min_confidence, 0.7)


if __name__ == "__main__":
    unittest.main()
