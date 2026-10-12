# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for dotnet-packer-forensics.

---

## Shipped Capabilities

- [x] **Static PE Forensic Pipeline** — Entropy calculation, PE overlay inspection, baseline unpacker, and 7 unit tests.
- [x] **Costura Packer Unpacker Module** — Extraction and decompression of embedded .NET assembly resources via DeflateStream inversion, path traversal sanitization, and SHA-256 validation.
- [x] **ConfuserEx String Protection Decryptor & Resource Unpacker** — Automated decryption of protected constants (PRNG stream ciphers), encrypted resource containers, and CLI resource catalog extraction.

---

## Planned Milestones

- [ ] **PE Section & IAT Header Rebuilder** — Reconstruction of damaged PE headers for standalone execution.
- [ ] **SHA-256 Regression Test Harness** — Bitwise comparison test suite for extracted payloads.
- [ ] **.NET Reactor NecroBit & Native Stub Envelope Unpacker** — Native wrapper envelope stripping and CIL method body restoration.
- [ ] **Eazfuscator.NET Bytecode VM Disassembler & De-virtualizer** — Custom VM opcode mapping and virtualized method recovery.
