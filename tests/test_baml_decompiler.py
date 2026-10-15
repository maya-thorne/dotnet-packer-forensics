"""
Unit & Integration Test Suite for WPF BAML & Embedded UI Resource Decompiler.
Engineered & Audited by Maya Thorne.
"""

import os
import shutil
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET

from dotnet_deobfuscator.baml import (
    BamlAnomalyFlag,
    BamlBinaryReader,
    BamlDecompiler,
    BamlDecompileStatus,
    BamlElement,
    BamlError,
    BamlExtractionResult,
    BamlRecordType,
    BamlResourceExtractor,
    BamlTelemetry,
    DecompiledXaml,
    ResourceSourceType,
    SecurityError,
    XamlEmitter,
    zeroize_buffer,
)
from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.cli import main as cli_main


def _write_7bit_int(value: int) -> bytes:
    """Encodes integer as variable-length 7-bit bytes."""
    res = bytearray()
    while value >= 0x80:
        res.append((value & 0x7F) | 0x80)
        value >>= 7
    res.append(value & 0x7F)
    return bytes(res)


def _write_baml_string(s: str) -> bytes:
    """Encodes length-prefixed UTF-8 string."""
    encoded = s.encode("utf-8")
    return _write_7bit_int(len(encoded)) + encoded


def build_synthetic_baml_stream(include_anomalies: bool = False) -> bytes:
    """Constructs a valid binary BAML record stream for testing."""
    stream = bytearray()

    # Optional version prefix (0.96)
    stream.extend(struct.pack("<I", 0x00600000))
    stream.extend(struct.pack("<I", 0x00000000))

    # 1. DocumentStart (0x01)
    stream.append(BamlRecordType.DOCUMENT_START.value)

    # 2. AssemblyInfo (0x1D): asm_id=1, name="PresentationFramework"
    stream.append(BamlRecordType.ASSEMBLY_INFO.value)
    stream.extend(struct.pack("<h", 1))
    stream.extend(_write_baml_string("PresentationFramework, Version=4.0.0.0"))

    # 3. StringInfo (0x21): str_id=1, value="ForensicView"
    stream.append(BamlRecordType.STRING_INFO.value)
    stream.extend(struct.pack("<h", 1))
    stream.extend(_write_baml_string("ForensicView"))

    # 4. ElementStart (0x03): type_id=-67 (Window), flags=0
    stream.append(BamlRecordType.ELEMENT_START.value)
    stream.extend(struct.pack("<h", -67))
    stream.append(0)

    # 5. DefAttribute (0x18): value="MyApp.MainWindow", name_string_id=2 (Class)
    stream.append(BamlRecordType.DEF_ATTRIBUTE.value)
    class_name = "᠎᠎᠎᠎_Obfuscated.MainWindow" if include_anomalies else "MyApp.MainWindow"
    stream.extend(_write_baml_string(class_name))
    stream.extend(struct.pack("<h", 2))

    # 6. Properties on Window: Title (-20), Width (-2), Height (-3)
    stream.append(BamlRecordType.PROPERTY.value)
    stream.extend(struct.pack("<h", -20))
    stream.extend(_write_baml_string("Forensic Analysis UI"))

    stream.append(BamlRecordType.PROPERTY.value)
    stream.extend(struct.pack("<h", -2))
    stream.extend(_write_baml_string("800"))

    stream.append(BamlRecordType.PROPERTY.value)
    stream.extend(struct.pack("<h", -3))
    stream.extend(_write_baml_string("600"))

    # If anomalies requested, inject suspicious URI or event handler
    if include_anomalies:
        stream.append(BamlRecordType.PROPERTY.value)
        stream.extend(struct.pack("<h", -22))  # Source
        stream.extend(_write_baml_string("http://192.168.1.100:8080/beacon.exe"))

    # 7. ElementStart (0x03): Grid (-16)
    stream.append(BamlRecordType.ELEMENT_START.value)
    stream.extend(struct.pack("<h", -16))
    stream.append(0)

    # 8. ElementStart (0x03): Button (-1)
    stream.append(BamlRecordType.ELEMENT_START.value)
    stream.extend(struct.pack("<h", -1))
    stream.append(0)

    # Button Properties: Content (-18), Width (-2)
    stream.append(BamlRecordType.PROPERTY.value)
    stream.extend(struct.pack("<h", -18))
    stream.extend(_write_baml_string("Click Here"))

    stream.append(BamlRecordType.PROPERTY.value)
    stream.extend(struct.pack("<h", -2))
    stream.extend(_write_baml_string("120"))

    if include_anomalies:
        # Suspicious event handler: Click -> Window_Loaded_ShellcodeInject
        stream.append(BamlRecordType.PROPERTY.value)
        stream.extend(struct.pack("<h", -23))  # Click
        stream.extend(_write_baml_string("Window_Loaded_ShellcodeInject"))

        # Hidden element with high-entropy Base64 payload in Tag (-49)
        stream.append(BamlRecordType.PROPERTY.value)
        stream.extend(struct.pack("<h", -8))  # Visibility
        stream.extend(_write_baml_string("Collapsed"))

        stream.append(BamlRecordType.PROPERTY.value)
        stream.extend(struct.pack("<h", -49))  # Tag
        # Base64 string with high entropy
        stream.extend(
            _write_baml_string(
                "dGhpcyBpcyBhIHNhbXBsZSBoaWdoIGVudHJvcHkgc2hlbGxjb2RlIHN0YWdlciBwYXlsb2FkIGZvciBmb3JlbnNpYyB0ZXN0aW5nIQ=="
            )
        )

    # 9. Text inside Button (0x10)
    stream.append(BamlRecordType.TEXT.value)
    stream.extend(_write_baml_string("Submit"))

    # 10. ElementEnd Button (0x04)
    stream.append(BamlRecordType.ELEMENT_END.value)

    # 11. ElementEnd Grid (0x04)
    stream.append(BamlRecordType.ELEMENT_END.value)

    # 12. ElementEnd Window (0x04)
    stream.append(BamlRecordType.ELEMENT_END.value)

    # 13. DocumentEnd (0x02)
    stream.append(BamlRecordType.DOCUMENT_END.value)

    return bytes(stream)


def build_synthetic_resources_container(resource_name: str, payload_bytes: bytes) -> bytes:
    """Constructs a minimal .NET .resources binary file (0xBEEFCACE) embedding a BAML stream."""
    buf = bytearray()
    # 1. Magic
    buf.extend(struct.pack("<I", 0xBEEFCACE))
    # 2. Number of resources in header (1)
    buf.extend(struct.pack("<I", 1))
    # 3. Header bytes to skip (0)
    buf.extend(struct.pack("<I", 0))

    # Runtime Header
    # Version = 2
    buf.extend(struct.pack("<I", 2))
    # num_resources = 1
    buf.extend(struct.pack("<I", 1))
    # num_types = 0
    buf.extend(struct.pack("<I", 0))

    # Hash values table (1 * 4 bytes)
    buf.extend(struct.pack("<I", 0x12345678))

    # Virtual name offsets (1 * 4 bytes: offset 0 from name_section_base)
    buf.extend(struct.pack("<I", 0))

    # Data section offset placeholder (will calculate after name section)
    # Name section:
    name_bytes = resource_name.encode("utf-16le")
    name_section = bytearray()
    name_section.extend(_write_7bit_int(len(name_bytes)))
    name_section.extend(name_bytes)
    # Data relative offset = 0
    name_section.extend(struct.pack("<I", 0))

    # Data section:
    # Type code = 0 (Byte array or stream), then length prefix, then data
    data_section = bytearray()
    data_section.extend(_write_7bit_int(0))  # type code
    data_section.extend(_write_7bit_int(len(payload_bytes)))
    data_section.extend(payload_bytes)

    # Calculate data_section_offset
    # Header up to data_section_offset is len(buf) + 4 + len(name_section)
    data_section_offset = len(buf) + 4 + len(name_section)
    buf.extend(struct.pack("<I", data_section_offset))
    buf.extend(name_section)
    buf.extend(data_section)

    return bytes(buf)


class TestBamlDecompiler(unittest.TestCase):
    """Test suite for BAML decoding, XAML reconstruction, and anomaly scanning."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_baml_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_01_primitive_reader_and_bounds_checking(self):
        """Verifies 7-bit integer decoding, string decoding, and bounds safety."""
        test_data = _write_7bit_int(16384) + _write_baml_string("Hello WPF")
        reader = BamlBinaryReader(test_data)
        val = reader.read_7bit_int()
        self.assertEqual(val, 16384)
        s = reader.read_string()
        self.assertEqual(s, "Hello WPF")

        # Test bounds checking exception
        with self.assertRaises(BamlError):
            reader.read_byte()

    def test_02_synthetic_baml_decompile_to_valid_xml(self):
        """Verifies full BAML record parsing into valid, well-formed XAML markup."""
        baml_data = build_synthetic_baml_stream(include_anomalies=False)
        result = BamlDecompiler.decompile_stream(baml_data, resource_name="mainwindow.baml")

        self.assertEqual(result.status, BamlDecompileStatus.SUCCESS)
        self.assertEqual(result.root_tag, "Window")
        self.assertTrue(result.is_valid_xml)
        self.assertGreaterEqual(result.element_count, 3)

        # Parse with standard xml.etree to guarantee 100% XML well-formedness
        xml_root = ET.fromstring(result.xaml_content.encode("utf-8"))
        self.assertTrue(xml_root.tag.endswith("Window"))
        self.assertEqual(xml_root.attrib.get("Title"), "Forensic Analysis UI")
        self.assertEqual(xml_root.attrib.get("Width"), "800")
        self.assertEqual(xml_root.attrib.get("Height"), "600")

    def test_03_xaml_emitter_escaping_and_namespaces(self):
        """Verifies attribute escaping, special character handling, and namespace injection."""
        elem = BamlElement(tag_name="Button")
        elem.add_attribute("Content", "Save & Continue <Test> 'Quotes' \"Double\"")
        elem.text = "Click & Run"

        emitter = XamlEmitter(indent_size=2)
        xaml = emitter.emit(elem)
        self.assertTrue(emitter.validate_xml(xaml))
        self.assertIn("&amp;", xaml)
        self.assertIn("&lt;", xaml)
        self.assertIn("&gt;", xaml)
        self.assertIn("&quot;", xaml)

    def test_04_anomaly_detection_suspicious_uri_and_handler(self):
        """Verifies detection of malicious URIs, hidden elements, and suspicious event handlers."""
        anom_baml = build_synthetic_baml_stream(include_anomalies=True)
        result = BamlDecompiler.decompile_stream(anom_baml, resource_name="anom.baml")

        self.assertGreater(len(result.anomalies), 0)
        anomaly_str = " ".join(result.anomalies)

        # Check for suspicious URI
        self.assertIn(BamlAnomalyFlag.SUSPICIOUS_URI.value, anomaly_str)
        # Check for suspicious event handler
        self.assertIn(BamlAnomalyFlag.SUSPICIOUS_EVENT_HANDLER.value, anomaly_str)
        # Check for hidden UI element
        self.assertIn(BamlAnomalyFlag.HIDDEN_UI_ELEMENT.value, anomaly_str)
        # Check for obfuscated identifier
        self.assertIn(BamlAnomalyFlag.OBFUSCATED_IDENTIFIER.value, anomaly_str)

    def test_05_managed_resources_container_extraction(self):
        """Verifies extraction and decompilation of BAML streams from .NET .resources containers."""
        baml_data = build_synthetic_baml_stream(include_anomalies=False)
        res_container = build_synthetic_resources_container("views/loginview.baml", baml_data)

        extraction = BamlDecompiler.decompile_assembly_data(
            res_container, file_name="TestApp.g.resources"
        )

        self.assertEqual(extraction.source_type, ResourceSourceType.MANAGED_RESOURCES)
        self.assertEqual(len(extraction.decompiled_items), 1)
        item = extraction.decompiled_items[0]
        self.assertEqual(item.resource_name, "views/loginview.baml")
        self.assertEqual(item.root_tag, "Window")
        self.assertTrue(item.is_valid_xml)

    def test_06_heuristic_baml_stream_carving(self):
        """Verifies heuristic carving of embedded BAML payloads from raw dummy byte streams."""
        baml_data = build_synthetic_baml_stream(include_anomalies=False)
        padded_blob = b"DUMMY_PADDING_BYTES_12345678" + baml_data + b"TRAILING_SLACK_BYTES"

        carved = BamlResourceExtractor.carve_baml_streams(padded_blob)
        self.assertGreaterEqual(len(carved), 1)

        carved_name, carved_bytes = carved[0]
        result = BamlDecompiler.decompile_stream(carved_bytes, resource_name=carved_name)
        self.assertEqual(result.root_tag, "Window")
        self.assertTrue(result.is_valid_xml)

    def test_07_safe_directory_export_and_manifest(self):
        """Verifies directory export of XAML files and structured JSON manifest."""
        baml_data = build_synthetic_baml_stream(include_anomalies=False)
        res_container = build_synthetic_resources_container("mainwindow.baml", baml_data)
        extraction = BamlDecompiler.decompile_assembly_data(res_container, file_name="Sample.exe")

        out_dir = os.path.join(self.temp_dir, "baml_export")
        export_rep = BamlDecompiler.export_to_directory(extraction, output_dir=out_dir)

        self.assertTrue(export_rep["success"])
        self.assertTrue(os.path.exists(os.path.join(out_dir, "mainwindow.xaml")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "baml_manifest.json")))

        # Verify manifest content
        with open(os.path.join(out_dir, "baml_manifest.json"), "r", encoding="utf-8") as f:
            manifest_data = f.read()
        self.assertIn("mainwindow.xaml", manifest_data)
        self.assertIn("telemetry", manifest_data)

    def test_08_path_traversal_defense(self):
        """Verifies strict directory boundary containment preventing path traversal vulnerabilities."""
        baml_data = build_synthetic_baml_stream(include_anomalies=False)
        fake_result = BamlExtractionResult(
            file_name="traversal_test.exe",
            file_size=100,
            source_type=ResourceSourceType.RAW_BAML_STREAM,
            decompiled_items=[
                DecompiledXaml(
                    resource_name="../../windows/system32/evil.baml",
                    xaml_content="<UserControl />",
                    status=BamlDecompileStatus.SUCCESS,
                    root_tag="UserControl",
                    element_count=1,
                    property_count=0,
                    anomalies=[],
                    raw_size=len(baml_data),
                    decompiled_size=15,
                    sha256="abc",
                    is_valid_xml=True,
                )
            ],
            telemetry=BamlTelemetry(),
            suspicious_findings=[],
        )

        out_dir = os.path.join(self.temp_dir, "safe_zone")
        # Base name resolution strips directory paths, but if attempted directly, _safe_path stops escape
        export_rep = BamlDecompiler.export_to_directory(fake_result, output_dir=out_dir)
        self.assertTrue(export_rep["success"])
        # Ensure file was contained inside out_dir as evil.xaml
        self.assertTrue(os.path.exists(os.path.join(out_dir, "evil.xaml")))

    def test_09_memory_zeroization(self):
        """Verifies that zeroize_buffer wipes memory buffers cleanly."""
        buf = bytearray(b"SENSITIVE_BAML_DECRYPTED_KEY_DATA")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(b"SENSITIVE_BAML_DECRYPTED_KEY_DATA")))

    def test_10_core_facade_and_analyze_file_integration(self):
        """Verifies DotNetPackerCore.analyze_baml, export_baml, and analyze_file report integration."""
        baml_data = build_synthetic_baml_stream(include_anomalies=True)
        res_container = build_synthetic_resources_container("mainwindow.baml", baml_data)
        test_file = os.path.join(self.temp_dir, "test_target.exe")
        with open(test_file, "wb") as f:
            f.write(res_container)

        # 1. analyze_baml
        baml_res = DotNetPackerCore.analyze_baml(test_file)
        self.assertGreaterEqual(len(baml_res.decompiled_items), 1)

        # 2. export_baml
        out_dir = os.path.join(self.temp_dir, "core_baml_out")
        exp = DotNetPackerCore.export_baml(test_file, output_dir=out_dir)
        self.assertTrue(exp["success"])
        self.assertTrue(os.path.exists(os.path.join(out_dir, "mainwindow.xaml")))

        # 3. analyze_file
        rep = DotNetPackerCore.analyze_file(test_file)
        self.assertIn("baml_forensics", rep)
        self.assertGreaterEqual(rep["baml_forensics"]["total_baml_streams"], 1)

    def test_11_cli_baml_options(self):
        """Verifies CLI execution with --baml and --baml-out arguments."""
        baml_data = build_synthetic_baml_stream(include_anomalies=False)
        test_file = os.path.join(self.temp_dir, "cli_baml_target.exe")
        with open(test_file, "wb") as f:
            f.write(baml_data)

        out_dir = os.path.join(self.temp_dir, "cli_baml_out")
        ret = cli_main(["--baml", "--baml-out", out_dir, test_file])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(out_dir))


if __name__ == "__main__":
    unittest.main()
