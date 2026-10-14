"""
Comprehensive Unit & Integration Test Suite for Threat Hunting YARA & Sigma Rule Synthesizer.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import shutil
import struct
import tempfile
import unittest

from dotnet_deobfuscator.core import DotNetPackerCore
from dotnet_deobfuscator.rules import (
    ExtractedThreatFeatures,
    RuleFormat,
    RuleGranularity,
    RuleSeverity,
    SecurityError,
    SigmaRule,
    SigmaSynthesizer,
    ThreatFeatureExtractor,
    ThreatRuleEngine,
    YARARule,
    YARASynthesizer,
    calculate_entropy,
    zeroize_buffer,
)


class TestThreatRuleSynthesizer(unittest.TestCase):
    """Test cases for threat hunting YARA & Sigma rule generation engine."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_rules_")
        self.sample_pe = self._create_test_pe_binary()
        self.sample_path = os.path.join(self.temp_dir, "test_target.exe")
        with open(self.sample_path, "wb") as f:
            f.write(self.sample_pe)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_pe_binary(self) -> bytes:
        """Synthesizes a minimal valid PE executable with embedded ConfuserEx & Costura artifacts."""
        dos_hdr = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80))
        dos_hdr += b"\x00" * (0x80 - len(dos_hdr))

        pe_sig = b"PE\x00\x00"
        file_hdr = struct.pack(
            "<HHIIIHH",
            0x014C,  # IMAGE_FILE_MACHINE_I386
            2,       # 2 sections
            0, 0, 0,
            224,     # SizeOfOptionalHeader
            0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
        )

        opt_hdr = bytearray(224)
        struct.pack_into("<H", opt_hdr, 0, 0x010B)  # PE32 magic
        struct.pack_into("<I", opt_hdr, 16, 0x1000)  # EntryPoint RVA
        struct.pack_into("<I", opt_hdr, 28, 0x00400000)  # ImageBase
        struct.pack_into("<I", opt_hdr, 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", opt_hdr, 36, 0x200)   # FileAlignment
        struct.pack_into("<H", opt_hdr, 68, 3)       # IMAGE_SUBSYSTEM_WINDOWS_CUI
        struct.pack_into("<I", opt_hdr, 56, 0x4000)  # SizeOfImage
        struct.pack_into("<I", opt_hdr, 60, 0x400)   # SizeOfHeaders
        struct.pack_into("<I", opt_hdr, 92, 16)      # NumberOfRvaAndSizes

        # DataDirectory[14]: CLR Cor20Header RVA
        cor20_rva = 0x2000
        cor20_size = 72
        struct.pack_into("<II", opt_hdr, 96 + (14 * 8), cor20_rva, cor20_size)

        # Section 1: .text (code)
        sec1 = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",
            0x800,   # VirtualSize
            0x1000,  # VirtualAddress
            0x400,   # SizeOfRawData
            0x400,   # PointerToRawData
            0, 0, 0, 0,
            0x60000020,
        )

        # Section 2: .tamper (anti-tamper marker)
        sec2 = struct.pack(
            "<8sIIIIIIHHI",
            b".tamper\x00",
            0x800,   # VirtualSize
            0x2000,  # VirtualAddress
            0x400,   # SizeOfRawData
            0x800,   # PointerToRawData
            0, 0, 0, 0,
            0x40000040,
        )

        headers = dos_hdr + pe_sig + file_hdr + opt_hdr + sec1 + sec2
        if len(headers) < 0x400:
            headers += b"\x00" * (0x400 - len(headers))

        # Payload data in .text
        text_body = bytearray(0x400)
        # Inject markers: ConfuserEx, AntiTamper, costura.
        markers = b"ConfuserEx\x00ConfusedByAttribute\x00AntiTamper\x00costura.dll.compressed\x00"
        text_body[: len(markers)] = markers

        # Payload data in .tamper: Cor20Header and BSJB metadata
        tamper_body = bytearray(0x400)
        # Cor20Header (cb=72)
        struct.pack_into("<IHHIIIIII", tamper_body, 0, 72, 2, 5, 0x2100, 0x200, 1, 0x06000001, 0, 0)
        # BSJB metadata header at 0x100
        tamper_body[0x100 : 0x104] = b"BSJB"
        # High entropy padding in tamper
        for i in range(0x200, 0x400):
            tamper_body[i] = (i * 137 + 13) % 256

        return bytes(headers + text_body + tamper_body)

    def test_feature_extractor(self):
        """Validates feature extraction from PE binary with protectors."""
        features = ThreatFeatureExtractor.extract_from_bytes(self.sample_pe, file_name="sample.exe")
        self.assertTrue(features.is_pe)
        self.assertEqual(features.section_count, 2)
        self.assertIn(".text", features.section_names)
        self.assertIn(".tamper", features.section_names)
        self.assertEqual(len(features.sha256), 64)
        self.assertEqual(len(features.md5), 32)
        self.assertIn("IMAGE_FILE_MACHINE_I386", features.machine_type)
        self.assertIn("ConfuserEx", features.string_markers)
        self.assertTrue(features.anti_tamper_active)

    def test_zeroize_buffer(self):
        """Verifies cryptographic buffer memory wiping."""
        buf = bytearray(b"SENSITIVE_KEY_AND_DECRYPTED_PAYLOAD_12345")
        zeroize_buffer(buf)
        self.assertEqual(buf, bytearray(len(buf)))

    def test_calculate_entropy(self):
        """Verifies Shannon entropy calculation bounds."""
        zero_ent = calculate_entropy(b"\x00" * 100)
        self.assertEqual(zero_ent, 0.0)

        # Uniform byte distribution has high entropy (~8.0)
        uniform_bytes = bytes(range(256)) * 4
        high_ent = calculate_entropy(uniform_bytes)
        self.assertGreater(high_ent, 7.9)

    def test_yara_synthesizer_specific_rule(self):
        """Validates YARA rule synthesis at SPECIFIC granularity level."""
        features = ThreatFeatureExtractor.extract_from_bytes(self.sample_pe, file_name="sample.exe")
        rules = YARASynthesizer.generate_rules(features, granularity=RuleGranularity.SPECIFIC)
        self.assertEqual(len(rules), 1)

        rule = rules[0]
        self.assertTrue(rule.rule_name.startswith("dotnet_sample_"))
        self.assertIn('import "pe"', rule.to_yara_string())
        self.assertEqual(rule.meta["hash_sha256"], features.sha256)
        self.assertEqual(rule.meta["file_size"], len(self.sample_pe))
        self.assertIn("uint16(0) == 0x5A4D", rule.condition)
        self.assertIn("pe.is_pe", rule.condition)
        self.assertIn("filesize", rule.condition)

        # Check clean YARA serialization
        yara_text = rule.to_yara_string()
        self.assertIn("rule dotnet_sample_", yara_text)
        self.assertIn("meta:", yara_text)
        self.assertIn("strings:", yara_text)
        self.assertIn("condition:", yara_text)

    def test_yara_synthesizer_behavioral_rules(self):
        """Validates YARA rule synthesis at BEHAVIORAL granularity level."""
        features = ThreatFeatureExtractor.extract_from_bytes(self.sample_pe, file_name="sample.exe")
        rules = YARASynthesizer.generate_rules(features, granularity=RuleGranularity.BEHAVIORAL)
        self.assertGreaterEqual(len(rules), 1)

        rule_names = [r.rule_name for r in rules]
        # Should detect ConfuserEx or Costura
        self.assertTrue(any("confuserex" in name or "costura" in name or "packed" in name for name in rule_names))

        for r in rules:
            text = r.to_yara_string()
            self.assertIn("meta:", text)
            self.assertIn("condition:", text)
            self.assertIn("uint16(0) == 0x5A4D", r.condition)

    def test_yara_synthesizer_hunting_rules(self):
        """Validates YARA rule synthesis at HUNT granularity level."""
        features = ThreatFeatureExtractor.extract_from_bytes(self.sample_pe, file_name="sample.exe")
        rules = YARASynthesizer.generate_rules(features, granularity=RuleGranularity.HUNT)
        self.assertGreaterEqual(len(rules), 1)

        rule_names = [r.rule_name for r in rules]
        self.assertIn("dotnet_hunt_high_entropy_packed_section", rule_names)

        # Verify math import and entropy condition
        high_ent_rule = next(r for r in rules if r.rule_name == "dotnet_hunt_high_entropy_packed_section")
        self.assertIn("math", high_ent_rule.imports)
        self.assertIn("math.entropy", high_ent_rule.condition)

    def test_sigma_synthesizer_specific_rules(self):
        """Validates Sigma rule synthesis at SPECIFIC granularity level."""
        features = ThreatFeatureExtractor.extract_from_bytes(self.sample_pe, file_name="target.exe")
        rules = SigmaSynthesizer.generate_rules(features, granularity=RuleGranularity.SPECIFIC)
        self.assertEqual(len(rules), 2)  # Process creation and file drop rules

        proc_rule = rules[0]
        self.assertEqual(proc_rule.logsource["category"], "process_creation")
        self.assertIn("attack.defense_evasion", proc_rule.tags)
        self.assertIn("attack.t1027.002", proc_rule.tags)

        yaml_text = proc_rule.to_sigma_yaml()
        self.assertIn(f"id: {proc_rule.id}", yaml_text)
        self.assertIn("logsource:", yaml_text)
        self.assertIn("category: process_creation", yaml_text)
        self.assertIn(features.sha256.upper(), yaml_text)
        self.assertIn(f"level: {RuleSeverity.HIGH.value}", yaml_text)

        file_rule = rules[1]
        self.assertEqual(file_rule.logsource["category"], "file_event")
        file_yaml = file_rule.to_sigma_yaml()
        self.assertIn("category: file_event", file_yaml)

    def test_sigma_synthesizer_behavioral_and_hunting(self):
        """Validates Sigma rule synthesis at BEHAVIORAL and HUNT granularity levels."""
        features = ThreatFeatureExtractor.extract_from_bytes(self.sample_pe, file_name="target.exe")

        # Behavioral rules
        b_rules = SigmaSynthesizer.generate_rules(features, granularity=RuleGranularity.BEHAVIORAL)
        self.assertGreaterEqual(len(b_rules), 1)
        self.assertTrue(any("Staging Directory" in r.title for r in b_rules))

        # Hunt rules
        h_rules = SigmaSynthesizer.generate_rules(features, granularity=RuleGranularity.HUNT)
        self.assertGreaterEqual(len(h_rules), 1)
        self.assertEqual(h_rules[0].logsource["category"], "image_load")

    def test_rule_engine_full_synthesis(self):
        """Verifies ThreatRuleEngine full orchestration from file and in-memory bytes."""
        res = ThreatRuleEngine.synthesize_from_file(
            self.sample_path, granularity=RuleGranularity.BEHAVIORAL, rule_format=RuleFormat.COMBINED
        )
        self.assertEqual(res.target_file, "test_target.exe")
        self.assertEqual(res.granularity, RuleGranularity.BEHAVIORAL)
        self.assertGreaterEqual(len(res.yara_rules), 1)
        self.assertGreaterEqual(len(res.sigma_rules), 1)
        self.assertGreater(res.generation_time_ms, 0.0)

        # Dictionary serialization
        r_dict = res.to_dict()
        self.assertEqual(r_dict["target_file"], "test_target.exe")
        self.assertIn("yara_rules", r_dict)
        self.assertIn("sigma_rules", r_dict)

    def test_rule_engine_export_to_directory(self):
        """Verifies safe export of YARA rules, Sigma YAMLs, and JSON manifest."""
        res = ThreatRuleEngine.synthesize_from_file(
            self.sample_path, granularity=RuleGranularity.BEHAVIORAL, rule_format=RuleFormat.COMBINED
        )
        out_dir = os.path.join(self.temp_dir, "exported_rules")
        exp_res = ThreatRuleEngine.export_to_directory(res, output_dir=out_dir)

        self.assertTrue(exp_res["success"])
        self.assertTrue(os.path.exists(out_dir))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "yara_rules.yar")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "rules_manifest.json")))

        # Check manifest contents
        with open(os.path.join(out_dir, "rules_manifest.json"), "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["target_file"], "test_target.exe")
        self.assertEqual(manifest["target_hashes"]["sha256"], res.features.sha256)
        self.assertGreaterEqual(len(manifest["exported_files"]), 3)

    def test_security_directory_traversal_defense(self):
        """Ensures directory traversal attacks are strictly blocked with SecurityError."""
        res = ThreatRuleEngine.synthesize_from_bytes(self.sample_pe, file_name="safe.exe")
        with self.assertRaises(SecurityError):
            ThreatRuleEngine._safe_path(self.temp_dir, "../../../evil.yar")
        with self.assertRaises(SecurityError):
            ThreatRuleEngine._safe_path(self.temp_dir, "sub/../../outside.yar")

    def test_core_integration(self):
        """Verifies DotNetPackerCore classmethod wrappers and automated telemetry in analyze_file."""
        # 1. generate_threat_rules wrapper
        res = DotNetPackerCore.generate_threat_rules(
            self.sample_path, granularity="behavioral", rule_format="combined"
        )
        self.assertGreaterEqual(len(res.yara_rules), 1)

        # 2. export_threat_rules wrapper
        out_dir = os.path.join(self.temp_dir, "core_export")
        exp = DotNetPackerCore.export_threat_rules(
            self.sample_path, output_dir=out_dir, granularity="specific"
        )
        self.assertTrue(exp["success"])
        self.assertTrue(os.path.exists(os.path.join(out_dir, "rules_manifest.json")))

        # 3. analyze_file telemetry contains threat_hunting_rules
        report = DotNetPackerCore.analyze_file(self.sample_path)
        self.assertIn("threat_hunting_rules", report)
        th_report = report["threat_hunting_rules"]
        self.assertTrue(th_report["synthesized"])
        self.assertGreater(th_report["yara_count"], 0)

    def test_cli_execution_flags(self):
        """Verifies CLI execution with --gen-rules, --gen-yara, --gen-sigma, and --rules-out."""
        from dotnet_deobfuscator.cli import main

        out_dir = os.path.join(self.temp_dir, "cli_rules_out")
        exit_code = main([
            self.sample_path,
            "--gen-rules",
            "--rule-level", "behavioral",
            "--rules-out", out_dir,
        ])
        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "yara_rules.yar")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "rules_manifest.json")))


if __name__ == "__main__":
    unittest.main()
