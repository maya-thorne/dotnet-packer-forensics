"""
Comprehensive Unit and Integration Test Suite for Babel Obfuscator Demangler & Unpacker.
Engineered & Audited by Maya Thorne.
"""

import gzip
import io
import json
import os
import shutil
import struct
import tempfile
import unittest
import zlib

from dotnet_deobfuscator.cli import build_parser, format_text_report, main as cli_main
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.unpackers.babel import BabelUnpacker, SecurityError
from dotnet_deobfuscator.unpackers.babel_demangler import (
    AssemblyNode,
    BabelDemangler,
    DemangleRule,
    DemangledSymbol,
    DependencyGraph,
)


class TestBabelDemanglerAndUnpacker(unittest.TestCase):
    """
    Test suite for Babel Obfuscator cross-assembly symbol demangler,
    dependency graph restorer, merged assembly carver, and CLI integration.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_babel_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_synthetic_pe(self, extra_payload: bytes = b"", section_name: str = ".text") -> bytes:
        """Synthesizes a minimal valid PE executable with standard DOS, NT, and section headers."""
        buf = bytearray(2048 + len(extra_payload))
        # DOS Header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 0x80

        # NT Headers @ 0x80
        nt_off = 0x80
        buf[nt_off : nt_off + 4] = b"PE\0\0"
        struct.pack_into("<H", buf, nt_off + 4, 0x014C)   # Machine: I386
        struct.pack_into("<H", buf, nt_off + 6, 1)        # NumberOfSections = 1
        struct.pack_into("<H", buf, nt_off + 20, 0xE0)    # SizeOfOptionalHeader = 0xE0
        struct.pack_into("<H", buf, nt_off + 22, 0x0102)  # Characteristics: EXECUTABLE_IMAGE | 32BIT

        # Optional Header
        opt_off = nt_off + 24
        struct.pack_into("<H", buf, opt_off, 0x010B)      # Magic: PE32
        struct.pack_into("<I", buf, opt_off + 16, 0x1000) # AddressOfEntryPoint
        struct.pack_into("<I", buf, opt_off + 28, 0x00400000) # ImageBase
        struct.pack_into("<I", buf, opt_off + 32, 0x2000) # SectionAlignment
        struct.pack_into("<I", buf, opt_off + 36, 0x200)  # FileAlignment
        struct.pack_into("<I", buf, opt_off + 56, 0x4000) # SizeOfImage
        struct.pack_into("<I", buf, opt_off + 60, 0x400)  # SizeOfHeaders
        struct.pack_into("<H", buf, opt_off + 68, 3)      # Subsystem: Windows CUI
        struct.pack_into("<I", buf, opt_off + 92, 16)     # NumberOfRvaAndSizes

        # Section Header @ 0x160
        sec_off = nt_off + 24 + 0xE0
        sec_name_bytes = section_name.encode("ascii")[:8].ljust(8, b"\x00")
        buf[sec_off : sec_off + 8] = sec_name_bytes
        struct.pack_into("<I", buf, sec_off + 8, 0x1000)  # VirtualSize
        struct.pack_into("<I", buf, sec_off + 12, 0x1000) # VirtualAddress
        raw_size = 0x400 + len(extra_payload)
        struct.pack_into("<I", buf, sec_off + 16, raw_size) # SizeOfRawData
        struct.pack_into("<I", buf, sec_off + 20, 0x400)    # PointerToRawData
        struct.pack_into("<I", buf, sec_off + 36, 0x60000020) # Characteristics

        # Section payload starting at 0x400
        if extra_payload:
            buf[0x400 : 0x400 + len(extra_payload)] = extra_payload

        return bytes(buf)

    # =========================================================================
    # 1. DemangleRule & DemangledSymbol Tests
    # =========================================================================

    def test_demangle_rule_attributes_and_dict(self):
        rule = DemangleRule(
            rule_id="TEST_RULE",
            rule_type="sanitization",
            description="Test demangling rule description",
            priority=5,
        )
        self.assertEqual(rule.rule_id, "TEST_RULE")
        self.assertEqual(rule.rule_type, "sanitization")
        self.assertEqual(rule.priority, 5)
        d = rule.to_dict()
        self.assertEqual(d["rule_id"], "TEST_RULE")
        self.assertEqual(d["priority"], 5)
        name, applied = rule.apply("TestSymbol")
        self.assertEqual(name, "TestSymbol")
        self.assertFalse(applied)

    def test_demangled_symbol_attributes_and_serialization(self):
        sym = DemangledSymbol(
            original_name="a\u200B1",
            demangled_name="Type_0001",
            symbol_type="type",
            token="0x02000001",
            declaring_type=None,
            rule_applied="PATTERN_NORMALIZATION",
            confidence="MEDIUM",
            is_mangled=True,
            metadata={"source": "test"},
        )
        self.assertEqual(sym.original_name, "a\u200B1")
        self.assertEqual(sym.demangled_name, "Type_0001")
        self.assertTrue(sym.is_mangled)
        d = sym.to_dict()
        self.assertEqual(d["token"], "0x02000001")
        self.assertEqual(d["rule_applied"], "PATTERN_NORMALIZATION")
        self.assertEqual(d["metadata"]["source"], "test")

    # =========================================================================
    # 2. AssemblyNode & DependencyGraph Tests
    # =========================================================================

    def test_assembly_node_serialization(self):
        node = AssemblyNode(
            name="MyModule",
            version="2.1.0.0",
            culture="en-US",
            public_key_token="b77a5c561934e089",
            is_merged=True,
            is_main=False,
            types=["TypeA", "TypeB"],
            dependencies=["mscorlib", "System"],
            symbols_count=10,
        )
        d = node.to_dict()
        self.assertEqual(d["name"], "MyModule")
        self.assertEqual(d["types_count"], 2)
        self.assertTrue(d["is_merged"])
        self.assertFalse(d["is_main"])
        self.assertIn("mscorlib", d["dependencies"])

    def test_dependency_graph_acyclic_dag(self):
        graph = DependencyGraph()
        n_main = AssemblyNode(name="MainApp", is_main=True)
        n_lib1 = AssemblyNode(name="CoreLib", is_merged=True)
        n_lib2 = AssemblyNode(name="DataLib", is_merged=True)
        n_mscor = AssemblyNode(name="mscorlib")

        graph.add_assembly(n_main)
        graph.add_assembly(n_lib1)
        graph.add_assembly(n_lib2)
        graph.add_assembly(n_mscor)

        graph.add_dependency("MainApp", "CoreLib")
        graph.add_dependency("MainApp", "DataLib")
        graph.add_dependency("CoreLib", "mscorlib")
        graph.add_dependency("DataLib", "mscorlib")

        self.assertTrue(graph.is_dag())
        self.assertEqual(len(graph.detect_cycles()), 0)
        self.assertEqual(graph.get_dependencies("MainApp"), ["CoreLib", "DataLib"])
        self.assertEqual(graph.get_dependents("mscorlib"), ["CoreLib", "DataLib"])

        order = graph.topological_sort()
        # In topological sort, MainApp comes before dependencies
        self.assertLess(order.index("MainApp"), order.index("CoreLib"))
        self.assertLess(order.index("MainApp"), order.index("DataLib"))

    def test_dependency_graph_cycle_detection(self):
        graph = DependencyGraph()
        graph.add_dependency("AssemblyA", "AssemblyB")
        graph.add_dependency("AssemblyB", "AssemblyC")
        graph.add_dependency("AssemblyC", "AssemblyA")  # Cycle

        self.assertFalse(graph.is_dag())
        cycles = graph.detect_cycles()
        self.assertGreaterEqual(len(cycles), 1)
        # Topological sort returns best effort without raising exception
        order = graph.topological_sort()
        self.assertEqual(len(order), 3)

    def test_dependency_graph_dot_and_mermaid_export(self):
        graph = DependencyGraph()
        graph.add_assembly(AssemblyNode(name="Main", is_main=True))
        graph.add_assembly(AssemblyNode(name="SubModule", is_merged=True))
        graph.add_dependency("Main", "SubModule")

        dot = graph.to_dot()
        self.assertIn("digraph DependencyGraph", dot)
        self.assertIn('"Main" [label="Main\\nv1.0.0.0\\n[Main]"', dot)
        self.assertIn('"SubModule" [label="SubModule\\nv1.0.0.0\\n[Merged]"', dot)
        self.assertIn('"Main" -> "SubModule";', dot)

        mermaid = graph.to_mermaid()
        self.assertIn("graph TD", mermaid)
        self.assertIn("classDef main", mermaid)
        self.assertIn("classDef merged", mermaid)
        self.assertIn('n_Main["Main v1.0.0.0 [Main]"]', mermaid)
        self.assertIn("n_Main --> n_SubModule", mermaid)

    # =========================================================================
    # 3. BabelDemangler Core Engine Tests
    # =========================================================================

    def test_unicode_sanitization(self):
        # Name with zero-width space, non-joiner, and bidirectional override
        dirty = "\u200B\u200CMyCleanClass\u202E\uFEFF"
        sanitized = BabelDemangler.sanitize_unicode(dirty)
        self.assertEqual(sanitized, "MyCleanClass")

        # Name with control characters
        dirty_ctrl = "Method\x01\x1FName"
        self.assertEqual(BabelDemangler.sanitize_unicode(dirty_ctrl), "MethodName")

        # Empty or purely zero-width string
        self.assertEqual(BabelDemangler.sanitize_unicode("\u200B\u200C"), "")

    def test_is_mangled_identifier(self):
        # Legitimate clean names
        self.assertFalse(BabelDemangler.is_mangled_identifier("CustomerRepository"))
        self.assertFalse(BabelDemangler.is_mangled_identifier("ExecutePayment"))
        self.assertFalse(BabelDemangler.is_mangled_identifier("IDisposable"))
        self.assertFalse(BabelDemangler.is_mangled_identifier("T"))  # Generic type param

        # Obfuscated names
        self.assertTrue(BabelDemangler.is_mangled_identifier("a\u200B"))
        self.assertTrue(BabelDemangler.is_mangled_identifier("1"))
        self.assertTrue(BabelDemangler.is_mangled_identifier("_0001"))
        self.assertTrue(BabelDemangler.is_mangled_identifier("A_0"))
        self.assertTrue(BabelDemangler.is_mangled_identifier("Babel_7f9a"))
        self.assertTrue(BabelDemangler.is_mangled_identifier("<Babel>stub"))
        self.assertTrue(BabelDemangler.is_mangled_identifier("a"))  # Single obscure character

    def test_infer_interface_methods(self):
        # Known standard interfaces
        disp = BabelDemangler.infer_interface_methods("IDisposable")
        self.assertEqual(disp, ["Dispose"])

        enum_methods = BabelDemangler.infer_interface_methods("IEnumerable")
        self.assertEqual(enum_methods, ["GetEnumerator"])

        comp = BabelDemangler.infer_interface_methods("System.IComparable")
        self.assertEqual(comp, ["CompareTo"])

        # Unknown custom interface
        custom = BabelDemangler.infer_interface_methods("ICustomService", method_count=2)
        self.assertEqual(custom, ["ExecuteCustomService_1", "ExecuteCustomService_2"])

    def test_restore_getter_setter(self):
        # Standard accessors
        acc1, prop1 = BabelDemangler.restore_getter_setter("get_Username")
        self.assertEqual(acc1, "get_Username")
        self.assertEqual(prop1, "Username")

        acc2, prop2 = BabelDemangler.restore_getter_setter("set_Username")
        self.assertEqual(acc2, "set_Username")
        self.assertEqual(prop2, "Username")

        # Accessor restoration with property hint
        acc3, prop3 = BabelDemangler.restore_getter_setter("get_data", property_name="Data")
        self.assertEqual(acc3, "get_Data")
        self.assertEqual(prop3, "Data")

    def test_normalize_pattern(self):
        self.assertEqual(BabelDemangler.normalize_pattern("foo", "type", 1), "Type_0001")
        self.assertEqual(BabelDemangler.normalize_pattern("bar", "method", 42), "Method_0042")
        self.assertEqual(BabelDemangler.normalize_pattern("baz", "field", 3), "Field_0003")
        self.assertEqual(BabelDemangler.normalize_pattern("qux", "property", 7), "Property_0007")

    def test_parse_embedded_map_formats(self):
        # XML format
        xml_map = """
        <BabelMap Version="2.0">
            <Type Old="_0001" New="AccountController"/>
            <Method Old="a" New="ValidateToken"/>
        </BabelMap>
        """
        parsed_xml = BabelDemangler.parse_embedded_map(xml_map)
        self.assertEqual(parsed_xml["_0001"], "AccountController")
        self.assertEqual(parsed_xml["a"], "ValidateToken")

        # Nested JSON format
        json_nested = """
        {
            "types": { "_0001": "AccountController" },
            "methods": { "a": "ValidateToken" }
        }
        """
        parsed_json = BabelDemangler.parse_embedded_map(json_nested)
        self.assertEqual(parsed_json["_0001"], "AccountController")
        self.assertEqual(parsed_json["a"], "ValidateToken")

        # Text mapping with ->
        text_arrow = """
        _0001 -> AccountController
        a -> ValidateToken
        """
        parsed_text = BabelDemangler.parse_embedded_map(text_arrow)
        self.assertEqual(parsed_text["_0001"], "AccountController")
        self.assertEqual(parsed_text["a"], "ValidateToken")

        # Text mapping with =
        text_eq = "_0001 = AccountController\na = ValidateToken"
        parsed_eq = BabelDemangler.parse_embedded_map(text_eq)
        self.assertEqual(parsed_eq["_0001"], "AccountController")

    def test_demangle_symbol_stages(self):
        # 1. Custom map override
        custom_map = {"_0001": "PaymentProcessor"}
        sym1 = BabelDemangler.demangle_symbol("_0001", symbol_type="type", custom_map=custom_map)
        self.assertEqual(sym1.demangled_name, "PaymentProcessor")
        self.assertEqual(sym1.rule_applied, "MAP_OVERRIDE")

        # 2. Interface inference
        sym2 = BabelDemangler.demangle_symbol("a", symbol_type="method", interface_hints=["IDisposable"])
        self.assertEqual(sym2.demangled_name, "Dispose")
        self.assertEqual(sym2.rule_applied, "INTERFACE_INFERENCE")

        # 3. Getter/setter restoration
        sym3 = BabelDemangler.demangle_symbol("get_Balance", symbol_type="method")
        self.assertEqual(sym3.demangled_name, "get_Balance")
        self.assertEqual(sym3.rule_applied, "GETTER_SETTER")

        # 4. Unicode cleaning
        sym4 = BabelDemangler.demangle_symbol("Clean\u200BClass", symbol_type="type")
        self.assertEqual(sym4.demangled_name, "CleanClass")
        self.assertEqual(sym4.rule_applied, "UNICODE_CLEAN")

        # 5. Pattern normalization fallback
        sym5 = BabelDemangler.demangle_symbol("_9999", symbol_type="type", index=5)
        self.assertEqual(sym5.demangled_name, "Type_0005")
        self.assertEqual(sym5.rule_applied, "PATTERN_NORMALIZATION")

    def test_batch_demangle_symbols(self):
        symbols = [
            {"name": "App", "symbol_type": "type"},
            {"name": "_0001", "symbol_type": "type"},
            {"name": "m1\u200B", "symbol_type": "method"},
            {"name": "get_Value", "symbol_type": "method"},
        ]
        results = BabelDemangler.demangle_symbols(symbols)
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0].demangled_name, "App")
        self.assertEqual(results[1].demangled_name, "Type_0002")
        self.assertEqual(results[2].demangled_name, "m1")
        self.assertEqual(results[3].demangled_name, "get_Value")

    # =========================================================================
    # 4. BabelUnpacker Forensic Extraction & Carving Tests
    # =========================================================================

    def test_detect_clean_vs_babel_binary(self):
        # Clean PE without Babel markers
        clean_pe = self._create_synthetic_pe()
        det_clean = BabelUnpacker.detect(clean_pe)
        self.assertFalse(det_clean["is_babel"])
        self.assertEqual(det_clean["confidence"], "NONE")

        # Babel signature markers
        babel_payload = b"BabelObfuscator.NET protected assembly v10.0\x00BabelAttribute"
        babel_pe = self._create_synthetic_pe(extra_payload=babel_payload)
        det_babel = BabelUnpacker.detect(babel_pe)
        self.assertTrue(det_babel["is_babel"])
        self.assertEqual(det_babel["confidence"], "HIGH")
        self.assertIn("BabelObfuscator", det_babel["markers_found"])

    def test_extract_merged_assemblies_uncompressed_and_compressed(self):
        # Create an embedded satellite PE
        satellite_pe = self._create_synthetic_pe(extra_payload=b"Satellite Assembly Code", section_name=".sat")

        # Embed uncompressed satellite PE inside host PE payload
        host_pe = self._create_synthetic_pe(extra_payload=satellite_pe)
        carved = BabelUnpacker.extract_merged_assemblies(host_pe)
        self.assertGreaterEqual(len(carved), 1)
        self.assertTrue(carved[0]["is_pe"])
        self.assertEqual(carved[0]["size_bytes"], len(satellite_pe))

        # Test Gzip compressed embedded PE
        gz_payload = gzip.compress(satellite_pe)
        host_gz_pe = self._create_synthetic_pe(extra_payload=gz_payload)
        carved_gz = BabelUnpacker.extract_merged_assemblies(host_gz_pe)
        self.assertGreaterEqual(len(carved_gz), 1)
        self.assertTrue(carved_gz[0]["is_pe"])

        # Test Zlib compressed embedded PE
        zlib_payload = zlib.compress(satellite_pe)
        host_zlib_pe = self._create_synthetic_pe(extra_payload=zlib_payload)
        carved_zlib = BabelUnpacker.extract_merged_assemblies(host_zlib_pe)
        self.assertGreaterEqual(len(carved_zlib), 1)

    def test_extract_symbols_from_metadata(self):
        # Synthetic binary with #Strings stream containing null-terminated tokens
        strings_stream = b"#Strings\x00" + b"MyType\x00get_Data\x00_0001\x00<Count>k__BackingField\x00\x00"
        pe_with_strings = self._create_synthetic_pe(extra_payload=strings_stream)
        symbols = BabelUnpacker.extract_symbols_from_metadata(pe_with_strings)
        sym_names = [s["name"] for s in symbols]
        self.assertIn("MyType", sym_names)
        self.assertIn("get_Data", sym_names)
        self.assertIn("_0001", sym_names)

    def test_extract_embedded_map(self):
        embedded_xml = b"<BabelMap><Type Old='_01' New='MainClass'/></BabelMap>"
        pe = self._create_synthetic_pe(extra_payload=embedded_xml)
        extracted = BabelUnpacker.extract_embedded_map(pe)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted["_01"], "MainClass")

    def test_demangle_assembly_pipeline(self):
        # Assemble PE with embedded map, strings stream, and satellite assembly
        satellite_pe = self._create_synthetic_pe(extra_payload=b"Satellite1")
        extra_content = (
            b"<BabelMap><Type Old='_0001' New='RestoredService'/></BabelMap>\x00"
            b"#Strings\x00_0001\x00get_Token\x00\x00"
            + satellite_pe
        )
        pe_data = self._create_synthetic_pe(extra_payload=extra_content)

        demangled_bytes, report = BabelUnpacker.demangle_assembly(pe_data)
        self.assertTrue(report["success"])
        self.assertIn("_0001", report["symbol_map"])
        self.assertEqual(report["symbol_map"]["_0001"], "RestoredService")
        self.assertGreaterEqual(report["merged_assemblies_count"], 1)
        self.assertIn("dependency_graph", report)
        self.assertIn("depgraph_dot", report)
        self.assertIn("depgraph_mermaid", report)

    def test_unpack_to_directory_and_path_traversal_defense(self):
        satellite_pe = self._create_synthetic_pe(extra_payload=b"Sat2")
        pe_data = self._create_synthetic_pe(
            extra_payload=b"BabelObfuscator\x00#Strings\x00_0001\x00\x00" + satellite_pe
        )
        out_dir = os.path.join(self.temp_dir, "unpack_out")
        written = BabelUnpacker.unpack_to_directory(pe_data, out_dir, export_depgraph=True)

        self.assertGreaterEqual(len(written), 5)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "demangled_main.exe")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "symbol_map.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dependency_graph.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dependency_graph.dot")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dependency_graph.mermaid")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "babel_report.json")))

        # Test Path Traversal Defense
        traversal_path = os.path.join(out_dir, "..", "escaped.exe")
        with self.assertRaises(SecurityError):
            BabelUnpacker._safe_write(traversal_path, b"malicious", out_dir)

    # =========================================================================
    # 5. DotNetPackerCore Integration Tests
    # =========================================================================

    def test_core_analyze_file_with_babel_telemetry(self):
        satellite_pe = self._create_synthetic_pe(extra_payload=b"SatCore")
        pe_data = self._create_synthetic_pe(
            extra_payload=b"BabelObfuscator\x00BabelAttribute\x00#Strings\x00_0001\x00\x00" + satellite_pe
        )
        target_file = os.path.join(self.temp_dir, "babel_test.exe")
        with open(target_file, "wb") as f:
            f.write(pe_data)

        report = DotNetPackerCore.analyze_file(target_file)
        self.assertIn("babel", report)
        babel_rep = report["babel"]
        self.assertTrue(babel_rep["detected"])
        self.assertEqual(babel_rep["confidence"], "HIGH")
        self.assertGreaterEqual(babel_rep["merged_assemblies_count"], 1)

    def test_core_demangle_babel_and_extract_assemblies(self):
        satellite_pe = self._create_synthetic_pe(extra_payload=b"SatCoreExtract")
        pe_data = self._create_synthetic_pe(
            extra_payload=b"BabelObfuscator\x00#Strings\x00_0001\x00\x00" + satellite_pe
        )
        target_file = os.path.join(self.temp_dir, "babel_core.exe")
        with open(target_file, "wb") as f:
            f.write(pe_data)

        # 1. Carve assemblies
        assemblies = DotNetPackerCore.extract_babel_assemblies(target_file)
        self.assertGreaterEqual(len(assemblies), 1)

        # 2. Demangle and write to file
        dest_out = os.path.join(self.temp_dir, "demangled_core.exe")
        custom_map = {"_0001": "CoreCleanType"}
        demangled_bytes, rep = DotNetPackerCore.demangle_babel(
            target_file, output_path=dest_out, custom_map=custom_map
        )
        self.assertTrue(rep["success"])
        self.assertTrue(os.path.exists(dest_out))
        self.assertEqual(rep["symbol_map"]["_0001"], "CoreCleanType")

    def test_core_unpack_to_dir_includes_babel(self):
        satellite_pe = self._create_synthetic_pe(extra_payload=b"SatCoreDir")
        pe_data = self._create_synthetic_pe(
            extra_payload=b"BabelObfuscator\x00#Strings\x00_0001\x00\x00" + satellite_pe
        )
        target_file = os.path.join(self.temp_dir, "babel_dir.exe")
        with open(target_file, "wb") as f:
            f.write(pe_data)

        out_dir = os.path.join(self.temp_dir, "core_unpack_dir")
        written = DotNetPackerCore.unpack_to_dir(target_file, out_dir)
        self.assertGreaterEqual(len(written), 1)

    # =========================================================================
    # 6. CLI Arguments & Output Reporting Tests
    # =========================================================================

    def test_cli_parser_arguments(self):
        parser = build_parser()
        args = parser.parse_args([
            "sample.exe",
            "--demangle-babel",
            "--babel-out", "out.exe",
            "--export-depgraph",
            "--custom-map", "map.xml",
        ])
        self.assertTrue(args.demangle_babel)
        self.assertEqual(args.babel_out, "out.exe")
        self.assertTrue(args.export_depgraph)
        self.assertEqual(args.custom_map, "map.xml")

    def test_cli_execution_with_demangle_babel(self):
        satellite_pe = self._create_synthetic_pe(extra_payload=b"SatCLI")
        pe_data = self._create_synthetic_pe(
            extra_payload=b"BabelObfuscator\x00#Strings\x00_0001\x00\x00" + satellite_pe
        )
        target_file = os.path.join(self.temp_dir, "babel_cli.exe")
        with open(target_file, "wb") as f:
            f.write(pe_data)

        # Create custom map file
        map_file = os.path.join(self.temp_dir, "custom_map.json")
        with open(map_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"_0001": "CLICleanType"}))

        out_exe = os.path.join(self.temp_dir, "cli_demangled.exe")
        ret = cli_main([
            target_file,
            "--demangle-babel",
            "--babel-out", out_exe,
            "--export-depgraph",
            "--custom-map", map_file,
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(out_exe))
        # Depgraph exports next to output binary
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "dependency_graph.dot")))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "dependency_graph.mermaid")))

    def test_cli_format_text_report_babel_section(self):
        report = {
            "file": "test.exe",
            "size_bytes": 4096,
            "sha256": "abcdef",
            "elapsed_ms": 1.2,
            "is_pe": True,
            "is_dotnet": True,
            "entropy": 4.5,
            "detected_protectors": [],
            "overlay": {"has_overlay": False},
            "unpacked_payload": {"success": False},
            "costura": {"detected": False},
            "confuserex": {"detected": False},
            "reactor": {"detected": False},
            "eazfuscator": {"detected": False},
            "babel": {
                "detected": True,
                "confidence": "HIGH",
                "has_merged_assemblies": True,
                "merged_assemblies_count": 2,
                "has_embedded_map": True,
                "obfuscated_symbols_count": 15,
                "markers_found": ["BabelObfuscator"],
                "merged_assemblies": [
                    {
                        "original_name": "Sub1.dll",
                        "output_filename": "merged_01.dll",
                        "size_bytes": 2048,
                        "sha256": "123456",
                        "compression": "raw",
                    }
                ],
            },
            "pe_rebuilder": {"repair_recommended": False},
            "sections": [],
            "suspicious_indicators": [],
        }
        text_out = format_text_report(report)
        self.assertIn("--- [Babel Obfuscator Forensics & Symbol Demangler] ---", text_out)
        self.assertIn("[+] Babel Obfuscator Detected! (Confidence: HIGH)", text_out)
        self.assertIn("Merged Assemblies  : YES (2 embedded assemblies carved)", text_out)
        self.assertIn("Embedded BabelMap  : YES (XML/JSON mapping table identified)", text_out)
        self.assertIn("merged_01.dll", text_out)


if __name__ == "__main__":
    unittest.main()
