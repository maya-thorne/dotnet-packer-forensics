"""
Unit and integration tests for CLI interface.
"""

import os
import tempfile
import unittest
from dotnet_deobfuscator.cli import build_parser, format_text_report, main


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.dummy_exe = os.path.join(self.tmp_dir.name, "test_app.exe")
        with open(self.dummy_exe, "wb") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00" + (b"\x00" * 300))

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_parser_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["sample.exe"])
        self.assertEqual(args.target, "sample.exe")
        self.assertEqual(args.format, "text")
        self.assertEqual(args.key, "randomkey")

    def test_cli_execution_text(self):
        code = main([self.dummy_exe, "--format", "text"])
        self.assertEqual(code, 0)

    def test_cli_execution_json(self):
        code = main([self.dummy_exe, "--format", "json"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
