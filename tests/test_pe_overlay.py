"""
Unit tests for PE Overlay and xorPacker decryption module.
"""

import base64
import unittest
from dotnet_deobfuscator.pe_overlay import PEOverlayParser


class TestPEOverlay(unittest.TestCase):
    def test_xor_cipher_symmetry(self):
        plain = "This is a secret .NET payload string 12345!"
        key = "randomkey"
        ciphered = PEOverlayParser.xor_cipher(plain, key)
        decrypted = PEOverlayParser.xor_cipher(ciphered, key)
        self.assertEqual(decrypted, plain)

    def test_xor_packer_mock_extraction(self):
        # Construct synthetic xorPacker payload buffer matching exact C# builder logic
        master_key = "randomkey"
        dyn_key = "my_dynamic_key_999"
        raw_payload = b"MZ\x90\x00\x03\x00\x00\x00SyntheticPEPayloadData"

        # 1. Builder Encrypts dynamic key: Base64(XOR(dyn_key, master_key))
        enc_dyn_key_str = PEOverlayParser.xor_cipher(dyn_key, master_key)
        b64_enc_dyn_key = base64.b64encode(enc_dyn_key_str.encode("utf-8")).decode("ascii")

        # 2. Builder Encrypts payload:
        # Step A: Base64 encode raw payload
        raw_b64 = base64.b64encode(raw_payload).decode("ascii")
        # Step B: XOR with dynamic key
        xor_b64 = PEOverlayParser.xor_cipher(raw_b64, dyn_key)
        # Step C: Base64 encode the XOR string
        ciphered_payload = base64.b64encode(xor_b64.encode("utf-8")).decode("ascii")

        # 3. Assemble mock binary with '***' sentinel
        dummy_pe = b"MZ" + (b"\x00" * 200)
        overlay_content = f"{ciphered_payload}|{b64_enc_dyn_key}"
        mock_file_bytes = dummy_pe + b"***" + overlay_content.encode("ascii")

        # Test decryptor
        res = PEOverlayParser.decrypt_xor_packer(mock_file_bytes, master_key=master_key)
        self.assertIsNotNone(res)
        self.assertEqual(res["dynamic_key_recovered"], dyn_key)
        self.assertEqual(res["decrypted_payload_bytes"], raw_payload)
        self.assertTrue(res["is_valid_pe"])


if __name__ == "__main__":
    unittest.main()
