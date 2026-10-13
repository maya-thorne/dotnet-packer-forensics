# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for dotnet-packer-forensics.

---

## Shipped Capabilities

- [x] **Static PE Forensic Pipeline** — Entropy calculation, PE overlay inspection, baseline unpacker, and 7 unit tests.
- [x] **Costura Packer Unpacker Module** — Extraction and decompression of embedded .NET assembly resources via DeflateStream inversion, path traversal sanitization, and SHA-256 validation.
- [x] **ConfuserEx String Protection Decryptor & Resource Unpacker** — Automated decryption of protected constants (PRNG stream ciphers), encrypted resource containers, and CLI resource catalog extraction.
- [x] **PE Section & IAT Header Rebuilder** — Reconstruction of damaged PE headers, section table realignment, process memory dump unmapping, and CLR Cor20Header RVA recovery.
- [x] **SHA-256 Regression Test Harness & PE Integrity Verifier** — Bitwise byte-level comparison diagnostics, cryptographic hash digest verification (SHA-256/SHA-1/MD5), and deep PE/CLR structural integrity testing with 16 dedicated unit tests.
- [x] **.NET Reactor NecroBit & Native Stub Envelope Unpacker** — Native wrapper envelope stripping, token-keyed PRNG stream decryption of hidden CIL methods, Tiny/Fat CorILMethod format validation, .necro section reconstruction, and CLI automation.
- [x] **Eazfuscator.NET Bytecode VM Disassembler & De-virtualizer** — Heuristic VM opcode mapping, proprietary bytecode disassembly, AST-to-CIL translation, Tiny/Fat CorILMethod emission, .eazvm PE section synthesis, and automated directory extraction.
- [x] **Babel Obfuscator Cross-Assembly Symbol Demangler & Dependency Graph Restorer** — Unicode unprintable sanitization, interface method inference, getter/setter restoration, embedded BabelMap parsing, merged satellite assembly carving, and inter-assembly DAG generation (JSON, DOT, Mermaid) with 26 dedicated unit tests.
- [x] **ArmDot Method-Level Virtual Machine Opcode Emulator & De-virtualizer** — Heuristic VM opcode recovery, abstract evaluation stack emulation, multi-pass relative branch fixups, CorILMethod Tiny/Fat header emission, .armdot PE section injection, and automated directory extraction with 18 dedicated unit tests.
- [x] **IntelliLock Hardware Lock Defeat & License Envelope Neutralizer** — De-enveloping of encapsulated assemblies, LCG/XOR stream decryption, deterministic hardware fingerprint profiling and bypassing, synthetic perpetual master license (.lic) generation, Cor20Header EntryPoint restoration, and directory extraction with 22 dedicated unit tests.

---

## Planned Milestones

- [ ] **DeepSea Control Flow De-flattening & AST Reconstructor** — Basic block reorganization and control flow restoration.
- [ ] **Single-File Host (AppHost) Virtual Volume Carving Engine** — Unbundling embedded assemblies in .NET 6/7/8/9 binaries.
- [ ] **.NET ILProtector Dynamic Unpacking Interface & InvokeWrapper Deobfuscator** — Method body decapsulation and static invoke wrapper resolution.
- [ ] **Crossgen2 PGO Profiling Metadata Forensic Carving Engine** — Profile-guided optimization metadata extraction.
- [ ] **CIL Polymorphic Mutation Pattern Detector & Bytecode Normalizer** — Transformation rule engine for metamorphic instruction streams.
- [ ] **Assembly Obfuscation Complexity Scoring Engine** — Cyclomatic complexity profiling and entropy scoring per method.
- [ ] **Native AOT Hybrid CIL-Native Stub Disassembler & Symbol Carver** — Mixed-mode boundary inspection for compiled .NET 8/9 executables.
- [ ] **.NET MAUI & Blazor WebAssembly AOT Package Forensics Engine** — Compressed Wasm virtual filesystem extraction and IL recovery.
