"""
Unit tests for .NET metadata analyzer and protector signatures.
"""

import unittest
from dotnet_deobfuscator.dotnet_analyzer import DotNetAnalyzer
from dotnet_deobfuscator.signatures import ProtectorSignatures


class TestDotNetAnalyzer(unittest.TestCase):
    def test_entropy_extremes(self):
        # Zero entropy for uniform data
        zero_ent = DotNetAnalyzer.calculate_entropy(b"\x00" * 1000)
        self.assertEqual(zero_ent, 0.0)

        # High entropy for random-like sequence
        diverse_bytes = bytes([i % 256 for i in range(10000)])
        high_ent = DotNetAnalyzer.calculate_entropy(diverse_bytes)
        self.assertGreater(high_ent, 7.9)

    def test_signature_identification(self):
        sample_confuser_bytes = b"SomeCode\x00ConfuserEx\x00ConfusedByAttribute\x00MoreData"
        detected = ProtectorSignatures.identify(sample_confuser_bytes)
        self.assertTrue(any(d["protector"] == "ConfuserEx" for d in detected))

        sample_reactor_bytes = b"NativePE_Header_Eziriz_.NET Reactor_Protected"
        detected_reactor = ProtectorSignatures.identify(sample_reactor_bytes)
        self.assertTrue(any(d["protector"] == ".NET Reactor" for d in detected_reactor))


if __name__ == "__main__":
    unittest.main()
