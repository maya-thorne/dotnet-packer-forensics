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
- [x] **DeepSea Control Flow De-flattening & AST Reconstructor** — ECMA-335 CIL opcode disassembler, opaque predicate pruning, state-machine loop de-flattening, symbolic block flow resolution, multi-pass branch offset calculation, high-level AST and C# pseudocode recovery, .deepsea PE section synthesis, and automated directory extraction with 17 dedicated unit tests.
- [x] **CLI Metadata Anti-Tamper Heuristics & In-Memory JIT Dumper Engine** — ECMA-335 CorILMethod Tiny/Fat header parser and serializer, PRNG/LCG stream cipher decryption with cryptographic buffer zeroizing, JIT dumper ingestion interface supporting in-memory scans, structured JSON descriptors, and binary JITD streams, static anti-tamper detection across corrupted `#~`/`#-` tables, PE `.antitamper` section injection, and safe directory extraction with 26 dedicated unit tests.
- [x] **Anti-Dump Process Memory PE Header Healer & Scylla Dump Normalizer** — Heuristic detection and classification of anti-dump corruptions, Scylla process memory dump unmapping (aligning virtual addresses to file offsets), BSJB CLR metadata scanning, ECMA-335 Cor20Header recovery and synthesis, standard mscoree.dll CLR import table (IAT) reconstruction, section table name sanitization and synthesis, and safe directory extraction with 16 dedicated unit tests.
- [x] **Native Multi-Architecture Resource Demuxer & Platform Router** — Static identification, carving, and decompression of multiplexed native PE/ELF/Mach-O binaries (x86, x64, ARM64, ARM, IA64) across manifest resources, directory structures, and PE sections. Includes automated architecture spoofing and mismatch detection, realistic runtime loader routing simulation (WoW64 compatibility, Windows on ARM x64/x86 emulation, macOS Rosetta 2 translation), memory buffer wiping via ctypes zeroization, and safe architecture-partitioned directory extraction with 14 dedicated unit tests (243 total suite tests).
- [x] **Automated .NET Threat Hunting YARA & Sigma Signature Rule Synthesizer** — Dynamic synthesis of production-ready YARA v4+ detection rules (with `import "pe"` and `import "math"` conditions, PE/CLR structural attributes, CIL opcode patterns, protector markers) and Sigma v2 YAML rules (process creation, file drop, and CLR image load telemetry). Supports Specific, Behavioral, and Threat Hunting tiers, deterministic UUID v5 generation, memory zeroization, safe directory export, and CLI automation with 13 dedicated unit tests (256 total suite tests).

---

## Planned Milestones

- [ ] **Single-File Host (AppHost) Virtual Volume Carving Engine** — Unbundling embedded assemblies in .NET 6/7/8/9 binaries.
- [ ] **.NET ILProtector Dynamic Unpacking Interface & InvokeWrapper Deobfuscator** — Method body decapsulation and static invoke wrapper resolution.
- [ ] **Crossgen2 PGO Profiling Metadata Forensic Carving Engine** — Profile-guided optimization metadata extraction.
- [ ] **CIL Polymorphic Mutation Pattern Detector & Bytecode Normalizer** — Transformation rule engine for metamorphic instruction streams.
- [ ] **Assembly Obfuscation Complexity Scoring Engine** — Cyclomatic complexity profiling and entropy scoring per method.
- [ ] **Native AOT Hybrid CIL-Native Stub Disassembler & Symbol Carver** — Mixed-mode boundary inspection for compiled .NET 8/9 executables.
- [ ] **.NET MAUI & Blazor WebAssembly AOT Package Forensics Engine** — Compressed Wasm virtual filesystem extraction and IL recovery.
- [ ] **CIL Exception Handling (EH) Table Reconstruction & Clause Normalizer** — CorILMethod protected block structure recovery.
- [ ] **JIT Compiler Method Hooking Interceptor & Emulation Bridge** — Static emulation of native JIT hooks and ICorJitCompiler transitions.
- [ ] **Opaque Predicate Algebraic Simplification & SMT Solver Engine** — Elimination of complex identity-based dead code branches.
- [ ] **Multi-Layer Steganographic PE Slack & High-Entropy Chunk Carver** — Extraction of hidden nested payloads within PE alignment gaps.
- [ ] **.NET 9 AppHost Native Runtime Bundle Decompressor & DLL/PDB Volume Mounter** — Virtual filesystem extraction for modern single-file hosts.
- [ ] **CIL Control Flow Graph Virtual Branch State Machine Detangler** — Normalization of non-linear nested loop switch dispatchers.
- [ ] **Enterprise SOC Real-Time YARA-L 2.0 & Falcon Sensor Query Engine** — Cloud SIEM/EDR detection rule synthesis.
