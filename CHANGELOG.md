# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-13

### Added
- **DeepSea Obfuscator Control Flow De-flattening & AST Reconstruction Engine (`dotnet_deobfuscator.unpackers.deepsea_models`, `dotnet_deobfuscator.unpackers.deepsea_deflattener`, `dotnet_deobfuscator.unpackers.deepsea`)**:
  - Full static signature detection and heuristic confidence scoring for DeepSea Obfuscator artifacts (`DeepSeaObfuscator`, `DeepSea Obfuscator`, `DeepSeaAttribute`, `__DeepSea`, `DSAttribute`, `.deepsea`), switch instruction density, and state variable store patterns.
  - Bytecode disassembler (`CILDisassembler`) parsing single-byte and two-byte (`0xFE` prefix) ECMA-335 CIL instructions, operand types, short/long relative branches, and jump table switch vectors.
  - Constant folding and opaque predicate eliminator (`OpaquePredicateEliminator`) detecting and pruning constant conditional branches (`ldc.i4.0`/`ldc.i4.1` followed by `brtrue`/`brfalse`).
  - Control flow de-flattener (`DeepSeaDeflattener`) partitioning CIL instructions into basic blocks based on leader offsets, identifying state variable allocation in method prologues, locating switch loop dispatchers, demuxing state-to-block transitions, symbolically extracting successor relationships, and stripping dispatch loops.
  - Multi-pass relative branch offset resolver and bytecode emitter (`CILEmitter`) reassembling de-flattened basic blocks into compliant ECMA-335 CIL streams with automatic short/long branch opcode expansion.
  - High-level Abstract Syntax Tree reconstructor (`ASTReconstructor`) recovering structured control flow blocks, generating structured JSON AST representations, and emitting formatted C# pseudocode.
  - Assembly reconstruction pipeline (`deflatten_assembly`) synthesizing clean PE binaries with restored `.deepsea` sections, incrementing section tables, and realigning `SizeOfImage`.
  - Safe directory export pipeline (`unpack_to_directory`) generating de-flattened executables, individual method CIL blobs, AST JSON trees, C# pseudocode listings, Graphviz DOT graphs, and Mermaid flowcharts with strict path traversal boundary verification.
- **CLI & Core Orchestrator Integration**:
  - Added `--deflatten-deepsea` and `--deepsea-out` flags to de-flatten protected assemblies and output repaired binaries.
  - Added `--export-ast` and `--export-cfg` to export Abstract Syntax Trees (JSON) and Control Flow Graphs (Graphviz DOT).
  - Integrated DeepSea telemetry into `DotNetPackerCore.analyze_file` and text/JSON reporting.
  - Added `DotNetPackerCore.deflatten_deepsea`, `DotNetPackerCore.deflatten_deepsea_method`, and `DotNetPackerCore.unpack_deepsea_dir` programmatic APIs.
- **Comprehensive DeepSea Test Suite (`tests/test_deepsea_unpacker.py`)**:
  - 17 unit and integration test cases covering instruction disassembly, two-byte opcodes, switch table parsing, opaque predicate pruning, basic block slicing, state machine de-flattening, multi-pass CIL bytecode emission, AST reconstruction, Graphviz DOT and Mermaid exports, signature detection, PE section injection, directory safety, and CLI execution (expanding the total test suite to 187 tests).

## [1.9.0] - 2026-10-13

### Added
- **IntelliLock Hardware Lock Defeat & License Envelope Neutralizer (`dotnet_deobfuscator.unpackers.intellilock_models` & `dotnet_deobfuscator.unpackers.intellilock`)**:
  - Full static signature detection and confidence heuristic scoring for IntelliLock and Eziriz licensing envelope artifacts (`IntelliLock`, `Eziriz`, `IntelliLock.Licensing`, `TrialAttribute`, `EvaluationMode`, `LicenseStatus`, `LockType`, `.itllock`, `.ilock`, `ILOCK\x01`).
  - Container carving engine extracting encapsulated assemblies from PE sections (`.itllock`, `.ilock`, `.lic`), resources, and overlays with safety ceilings (100 MB payload cap, 256 MB decompression bomb defense).
  - Multi-scheme stream decryption engine inverting dynamic LCG/PRNG rolling XOR ciphers and multi-byte XOR keys with intermediate keystream buffer zeroization.
  - Deterministic hardware fingerprint profiling (`HardwareProfile`) calculating canonical 16-character hardware identifier hashes (`XXXX-XXXX-XXXX-XXXX`) across CPU ID, HDD serial, MAC address, and motherboard UUID.
  - Synthetic perpetual master license generator (`VirtualLicense`) constructing tamper-resistant binary `.lic` containers with HMAC signatures, unbounded trial days, and full enterprise feature masks.
  - Envelope de-enveloping and in-place neutralization pipelines restoring original managed entry point RVAs and Cor20Header EntryPointTokens, stripping license verification stubs, and realigning PE sections.
  - Safe directory extraction (`unpack_to_directory`) generating de-enveloped executables, synthetic master licenses, hardware profile bypass descriptors, and manifest metadata with strict path traversal defenses.
- **CLI & Core Orchestrator Integration**:
  - Added `--strip-intellilock` and `--intellilock-out` flags to de-envelope protected assemblies and write unlocked binaries.
  - Added `--bypass-hwlock` and `--gen-license` (with `--license-out`) to synthesize perpetual master licenses bypassing machine binding.
  - Integrated IntelliLock telemetry into `DotNetPackerCore.analyze_file` and CLI text/JSON reporting.
  - Added `DotNetPackerCore.strip_intellilock`, `DotNetPackerCore.bypass_intellilock_hwlock`, and `DotNetPackerCore.unpack_intellilock_dir` high-level programmatic APIs.
- **Comprehensive IntelliLock Test Suite (`tests/test_intellilock_unpacker.py`)**:
  - 23 unit and integration test cases covering static detection, hardware ID hashing, virtual license HMAC serialization and tamper detection, LCG/XOR decryption, container carving, PE header restoration, directory safety, decompression bomb defense, and CLI execution (expanding the total test suite to 170 tests).

## [1.8.0] - 2026-10-13

### Added
- **ArmDot Method-Level Virtual Machine Opcode Emulator & De-virtualizer (`dotnet_deobfuscator.unpackers.armdot_vm`, `dotnet_deobfuscator.unpackers.armdot_rebuilder` & `dotnet_deobfuscator.unpackers.armdot`)**:
  - Full static signature detection and confidence heuristic scoring for ArmDot protector artifacts (`ArmDot.Client.VirtualizeAttribute`, `ArmDot.Client.ObfuscateNamesAttribute`, `ArmDot.Client.ProtectAttribute`, `ArmDot.Engine`, `.armdot`).
  - Embedded VM container carving across PE sections (`.text`, `.rdata`, custom data sections) and overlay, parsing container headers, method descriptors, tokens, stack depths, and encrypted method bytecode streams.
  - Symmetric rolling LCG/XOR bytecode decryption inverting ArmDot stream ciphers with intermediate key schedule zeroization.
  - Semantic VM opcode architecture (`ArmDotOpcode`) covering stack operations, constant loads, local/argument slots, arithmetic, bitwise logic, comparisons, branch instructions, switch tables, member invocations, conversions, and exception handling.
  - Dynamic VM opcode table manager (`ArmDotOpcodeTable`) with heuristic mapping deduction from terminal instructions, relative branch boundaries, and metadata tokens, plus JSON export and import.
  - Abstract evaluation stack emulator (`ArmDotStackEmulator`) computing stack balance, calculating required max_stack depth, and detecting underflows or stack leaks.
  - ECMA-335 CIL de-virtualizer (`ArmDotDevirtualizer`) translating VM instructions to standard CIL bytecodes with multi-pass relative short/long branch resolution and CorILMethod Tiny/Fat header emission.
  - Assembly reconstruction pipeline synthesizing de-virtualized PE binaries with injected CIL methods into an aligned `.armdot` section, incrementing section headers, and recalculating `SizeOfImage`.
  - Safe directory extraction (`unpack_to_directory`) generating rebuilt executables, individual method CIL blobs, VM disassembly listings, and opcode tables with path traversal defenses and memory zeroizing.
- **CLI & Core Orchestrator Integration**:
  - Added `--devirtualize-armdot` and `--armdot-out` to unpack and reconstruct virtualized assemblies.
  - Added `--disasm-armdot` to disassemble embedded ArmDot VM method containers to formatted assembly.
  - Added `--armdot-table` to specify custom opcode table mappings via JSON configuration files.
  - Integrated ArmDot telemetry and VM container metrics into `DotNetPackerCore.analyze_file` and CLI reports.
  - Added `DotNetPackerCore.devirtualize_armdot`, `DotNetPackerCore.disassemble_armdot_vm`, and `DotNetPackerCore.extract_armdot_containers` high-level APIs.
- **Comprehensive ArmDot Test Suite (`tests/test_armdot_unpacker.py`)**:
  - 18 unit and integration test cases covering opcode table mappings, heuristic deduction, arithmetic and relative branch disassembly, Tiny and Fat method header construction, stream cipher decryption, container carving, PE section injection, directory safety, and CLI execution (total test suite expanded to 147 tests).

## [1.7.0] - 2026-10-13

### Added
- **Babel Obfuscator Cross-Assembly Symbol Demangler & Dependency Graph Restorer (`dotnet_deobfuscator.unpackers.babel_demangler` & `dotnet_deobfuscator.unpackers.babel`)**:
  - Full static signature detection and confidence heuristic scoring for Babel Obfuscator, BabelAttribute, Babel.NET, and embedded BabelCore runtime stubs.
  - Multi-stage symbol demangling pipeline:
    - Zero-width character sanitization stripping invisible Unicode markers (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u2060`) and bidirectional override marks (`\u202A`–`\u202E`).
    - Cryptic and mangled identifier detection isolating single-character names, non-ASCII symbols, numeric tokens, and Babel-generated hash prefixes.
    - Standard interface method inference deriving canonical names for BCL and custom interfaces (`IDisposable` -> `Dispose`, `IEnumerable` -> `GetEnumerator`, `IComparable` -> `CompareTo`, etc.).
    - Accessor restoration identifying getter/setter pairs and linking compiler backing fields back to unified property declarations.
    - Deterministic pattern normalization generating cleanly structured fallbacks (`Type_0001`, `Method_0001`, `Field_0001`).
  - Embedded and external BabelMap parser supporting XML (`<BabelMap>`), JSON (flat and nested categories), and line-based text (`Old -> New`, `Old = New`).
  - Satellite assembly carving engine extracting embedded merged assemblies from PE sections, resources, and overlay, supporting raw, Deflate, Gzip, and Zlib compressed payloads with decompression bomb safety ceilings (256 MB).
  - Cross-assembly Directed Acyclic Graph (DAG) reconstructor:
    - Kahn's algorithm topological sorting determining deterministic assembly load order.
    - Tarjan-style DFS cycle detection for circular dependency diagnostics.
    - Multi-format diagram exports producing structured JSON, Graphviz DOT, and Mermaid flowcharts with distinct styling for main, merged, and external assemblies.
  - Directory extraction engine (`unpack_to_directory`) generating demangled executables, carved merged DLLs, symbol maps, dependency graphs, and forensic telemetry reports with strict path traversal defenses.
- **CLI & Core Orchestrator Integration**:
  - Added `--demangle-babel` and `--babel-out` flags to demangle symbols and write restored binaries.
  - Added `--export-depgraph` flag to output dependency graph DOT and Mermaid diagrams.
  - Added `--custom-map` flag to ingest user-defined or external Babel mapping definitions.
  - Integrated Babel telemetry, merged assembly counts, and mangled symbol heuristics into `DotNetPackerCore.analyze_file` and CLI text/JSON reports.
  - Added `DotNetPackerCore.demangle_babel` and `DotNetPackerCore.extract_babel_assemblies` high-level APIs.
- **Comprehensive Babel Test Suite (`tests/test_babel_unpacker.py`)**:
  - 26 unit and integration test cases covering rule models, symbol serialization, graph topology and cycle detection, Unicode sanitization, interface inference, getter/setter restoration, map parsing, satellite carving, safe file extraction, and CLI automation (expanding the project test suite to 129 tests).

## [1.6.0] - 2026-10-13

### Added
- **Eazfuscator.NET Bytecode VM Disassembler & De-virtualizer (`dotnet_deobfuscator.unpackers.eazfuscator_vm` & `dotnet_deobfuscator.unpackers.eazfuscator`)**:
  - Full static marker detection and confidence scoring for Eazfuscator.NET, Gapotchenko runtime stubs, and zero-width unicode identifier obfuscation.
  - VM container carving engine: scans PE sections (`.text`, `.rdata`, custom data sections) and overlay for embedded `EAZVM` containers, extracting method metadata tokens, stack depth limits, and proprietary bytecodes.
  - Semantic VM opcode architecture (`VMOpcode`) covering stack operations, constant loads, local/argument slots, arithmetic, bitwise logic, comparisons, branch instructions, invocations, and return flow.
  - Dynamic VM opcode table manager (`VMOpcodeTable`) with heuristic mapping deduction from terminal instructions, relative branch boundaries, and metadata tokens, plus JSON export and import.
  - VM bytecode disassembler (`EazfuscatorVMDisassembler`) producing structured instruction trees and human-readable disassembly text listings with resolved branch targets.
  - ECMA-335 CIL de-virtualizer (`EazfuscatorDevirtualizer`) translating VM abstract instructions to standard CIL bytecodes, with two-pass relative branch fixup calculation and CorILMethod Tiny/Fat header emission.
  - Assembly reconstruction pipeline synthesizing de-virtualized PE binaries with injected CIL methods into a dedicated aligned `.eazvm` section, incrementing section headers, and recalculating `SizeOfImage`.
  - Directory extraction engine (`unpack_to_directory`) outputting rebuilt binaries, individual method CIL blobs, VM disassembly listings, and opcode tables with path traversal defenses and memory zeroizing.
- **CLI & Core Orchestrator Integration**:
  - Added `--devirtualize-eaz` and `--eaz-out` to unpack and reconstruct virtualized assemblies.
  - Added `--disasm-vm` to disassemble embedded VM method containers directly to assembly text.
  - Added `--vm-table` to specify custom opcode table mappings via JSON configuration files.
  - Integrated Eazfuscator telemetry and VM container counts into `DotNetPackerCore.analyze_file` and CLI reports.
  - Added `DotNetPackerCore.devirtualize_eazfuscator` and `DotNetPackerCore.disassemble_eazfuscator_vm` high-level APIs.
- **Comprehensive Eazfuscator Test Suite (`tests/test_eazfuscator_unpacker.py`)**:
  - 24 unit and integration test cases covering opcode table mappings, heuristic deduction, arithmetic and relative branch disassembly, Tiny and Fat method header construction, token invocations, container carving, PE section injection, directory safety, and CLI execution (total test suite expanded to 103 tests).

## [1.5.0] - 2026-10-13

### Added
- **.NET Reactor NecroBit & Native Stub Envelope Unpacker (`dotnet_deobfuscator.unpackers.reactor`)**:
  - Full static marker detection and confidence scoring for .NET Reactor, Eziriz runtime stubs, and NecroBit method replacement artifacts.
  - Native stub envelope stripper: identifies Win32/x64 native wrapper executables, carves encapsulated managed .NET PE assemblies from sections, resources, or overlay, and handles compressed (Deflate/Zlib/Gzip) or single-byte XOR protected envelopes.
  - NecroBit CIL method body extraction and decryption engine: parses encrypted method containers, inverts token-keyed PRNG stream ciphers, and handles token salt key schedules.
  - ECMA-335 CorILMethod header parser and validator: parses and verifies both `CorILMethod_TinyFormat` (1-byte header, <=63 byte bytecode) and `CorILMethod_FatFormat` (12-byte header, max stack, code size, local variable signature tokens).
  - CIL opcode validator ensuring recovered bytecodes begin with valid ECMA-335 instructions (`nop`, `ldarg`, `ldloc`, `call`, `newobj`, `ret`, etc.).
  - Assembly reconstruction pipeline: synthesizes a restored executable with injected CIL method bodies in a newly aligned `.necro` PE section, increments section counts, and realigns `SizeOfImage`.
  - Directory unpacking engine (`unpack_to_directory`) with path traversal defenses, decompression bomb protection (256 MB ceiling), and Zeroize memory buffer wiping.
- **CLI & Core Orchestrator Integration**:
  - Added `--strip-envelope` and `--envelope-out` to carve managed assemblies from native stub envelopes.
  - Added `--restore-necrobit` and `--necrobit-out` to decrypt and inject CIL method bodies directly.
  - Added `--necrobit-seed` to configure custom decryption seeds for PRNG stream ciphers (default: `0x14725836`).
  - Integrated .NET Reactor telemetry and method counts into `DotNetPackerCore.analyze_file` and CLI output.
  - Added `DotNetPackerCore.strip_reactor_envelope` and `DotNetPackerCore.restore_necrobit` high-level APIs.
- **Comprehensive .NET Reactor Test Suite (`tests/test_reactor_unpacker.py`)**:
  - 14 new test cases validating marker detection, Tiny and Fat method header parsing, opcode validation, NecroBit container decryption, native envelope carving (uncompressed and XOR-encoded), PE reconstruction, directory extraction security, and CLI flags.

## [1.4.0] - 2026-10-13

### Added
- **Payload Verification & PE Structural Integrity Regression Test Harness (`dotnet_deobfuscator.payload_verifier`)**:
  - Full cryptographic hash digest computation engine covering SHA-256, SHA-1, and MD5 algorithms with byte-level bounds checking.
  - Bitwise differential diagnostics: byte-by-byte comparison against reference payloads, pinpointing the exact byte offset of divergence, length mismatch deltas, and side-by-side hex dump context representations.
  - Deep PE & CLR container structural conformance verification:
    - DOS and NT header parsing: DOS magic (`MZ`), `e_lfanew` boundary validation, and NT signature verification.
    - Architecture and subsystem classification (x86, x64, ARM64, Windows CUI/GUI).
    - Section table bounds and alignment verification: enforces valid file offset boundaries, monotonically increasing virtual addresses, and calculates Shannon byte entropy per section.
    - CLR COM Descriptor (Cor20Header) and CLI metadata validation: verifies directory entry 14, `cb=72` length descriptors, metadata stream headers (`BSJB`), and embedded stream names (`#Strings`, `#US`, `#Blob`, `#GUID`, `#~`).
  - Directory-wide batch auditing engine: scans unpacked payload directories and matches discovered files against golden hash registries.
- **CLI & Core Orchestrator Integration**:
  - Added `--verify` flag to run payload and structural PE audits directly from the command line.
  - Added `--verify-against <ref_path>` for automated bitwise comparison against known reference baselines.
  - Added `--expected-sha256 <hex>` to enforce strict golden checksum matching.
  - Added `--strict-pe` to enforce strict PE headers and reject non-PE containers or structural anomalies.
  - Integrated `hashes` and SHA-256 digest telemetry into `DotNetPackerCore.analyze_file` and CLI reports.
  - Added `DotNetPackerCore.verify_payload`, `verify_payload_buffer`, and `verify_directory` APIs.
- **Comprehensive Verification Test Suite (`tests/test_payload_verifier.py`)**:
  - 16 new test cases covering hash computation, entropy calculations, bitwise parity and divergence pinpointing, synthetic PE header verification, Cor20Header and BSJB metadata parsing, directory batch auditing, and CLI command execution.

## [1.3.0] - 2026-10-13

### Added
- **PE Header & Section Rebuilder Engine (`dotnet_deobfuscator.pe_rebuilder`)**:
  - Full structural health diagnostics identifying corrupted DOS headers, invalid `e_lfanew` pointers, damaged NT signatures, non-power-of-two alignments, and process memory dump layouts.
  - DOS and NT header reconstruction: auto-locates orphaned PE signatures, restores valid `MZ` and `e_lfanew` pointers, synthesizes standard MS-DOS stubs, and normalizes Machine architecture and subsystem fields.
  - Section table realignment: realigns section headers, enforces power-of-two FileAlignment and SectionAlignment padding, and recalculates `SizeOfHeaders` and `SizeOfImage`.
  - Process memory dump unmapping: unmaps mapped section RVAs back to compact sequential disk raw offsets, transforming in-memory process dumps into runnable disk binaries.
  - CLR COM Descriptor recovery: scans `.text` and code sections for anti-dump zeroed Cor20Header descriptors, verifies `BSJB` CLI metadata streams, and restores directory entry 14 RVA and 72-byte size.
  - Authenticode stripping: automatically clears obsolete, broken Certificate / Security directory tables post-unpacking.
  - Safe bounds checks and buffer zeroizing on sensitive intermediate rebuild buffers.
- **CLI & Core Orchestrator Integration**:
  - Added `--rebuild`, `--rebuild-out`, and `--unmap-dump` flags to `dotnet-packer-re` CLI.
  - Extended text and JSON telemetry with `PE Structural Health & Rebuilder Diagnostics`.
  - Added `DotNetPackerCore.rebuild_pe` and `DotNetPackerCore.rebuild_pe_buffer`.
- **Comprehensive PE Rebuilder Test Suite (`tests/test_pe_rebuilder.py`)**:
  - 14 test cases covering anomaly detection, DOS/NT header repairs, section realignment, memory dump unmapping, Cor20Header recovery, security directory stripping, bounds checks, and CLI commands.
- **GitHub Actions Automated CI Pipeline (`.github/workflows/ci.yml`)**:
  - Continuous integration testing across Python 3.10, 3.11, and 3.12 with asset integrity verification.

## [1.2.0] - 2026-10-13

### Added
- **ConfuserEx Forensic Unpacker & Decryption Engine (`dotnet_deobfuscator.unpackers.confuserex`)**:
  - Full static analysis and marker detection for ConfuserEx attributes (`ConfusedByAttribute`), runtime indicators, and Unicode mangled identifiers.
  - Multi-mode constants and string decryption supporting LCG/XorShift 32-bit PRNG stream ciphers, key mutation schedules, and entropy-minimizing auto key recovery.
  - Encrypted resource container parsing, CLI Cor20Header resource stream decoding, and multi-format decompression (Deflate, Zlib, Gzip, raw).
  - Internal resource catalog parser extracting embedded assemblies, bitmaps, XML configurations, and managed resources.
  - Safe extraction to directory (`-d, --unpack-dir`) with strict directory traversal neutralization and memory buffer Zeroize wiping.
  - Dedicated CLI command flag `--dump-strings` for direct extraction and cataloging of decrypted strings.
- **Comprehensive ConfuserEx Test Suite (`tests/test_confuserex_unpacker.py`)**:
  - Added 19 test cases validating detection heuristics, PRNG keystream generation, string table decoding, resource catalog parsing, path traversal defense, and CLI command integration.

### Changed
- Integrated ConfuserEx forensics into `DotNetPackerCore.analyze_file`, returning structured telemetry for active protections, decrypted strings, and extracted resources.
- Extended `dotnet-packer-re` CLI to format ConfuserEx detection and telemetry in text and JSON modes.

## [1.1.0] - 2026-10-13

### Added
- **Costura.Fody Unpacker Engine (`dotnet_deobfuscator.unpackers.costura`)**:
  - Full static analysis and extraction of embedded managed assemblies, native unmanaged DLLs (`costura32`/`costura64`), and PDB symbols.
  - Multi-tier RFC 1951 DeflateStream inversion supporting raw deflate, 4-byte/8-byte length prefixes, zlib, and gzip fallbacks.
  - CLI Cor20Header and metadata `#Strings` parser to recover authentic assembly resource names.
  - Heuristic stream carving fallback for packed, stripped, or anti-tampered binaries.
  - Directory extraction support (`-d, --unpack-dir`) with strict path traversal defenses and safe filename normalization.
  - SHA-256 integrity hashing, PE structure validation (`MZ` / `PE\0\0`), and Shannon entropy profiling on all extracted payloads.
- **Protector Signatures Expansion**:
  - Added Costura heuristic rules to `ProtectorSignatures.RULES`.
- **Comprehensive Test Suite (`tests/test_costura_unpacker.py`)**:
  - Added 9 new unit test cases covering raw deflate, length prefixes, filename sanitization, synthetic PE assembly resource extraction, CLI integration, and carving fallbacks.
- **Architecture Roadmap Expansion**:
  - Expanded project architecture roadmap covering upcoming unpackers, VM de-virtualizers, and memory forensics modules.

### Changed
- Updated `dotnet-packer-re` CLI to format Costura embedded assembly forensics in text and JSON telemetry outputs.
- Enhanced `DotNetPackerCore.unpack_to_file` and added `DotNetPackerCore.unpack_to_dir`.

## [1.0.0] - 2026-10-11

### Added
- Initial baseline release of `dotnet-packer-forensics`.
- xorPacker dual-stage XOR decryption engine and PE overlay carver.
- .NET CLI metadata stream parser (`#Strings`, `#US`, `#Blob`, `#GUID`, `#~`).
- Heuristic signature matcher for 8 major .NET packers (ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, DeepSea, IntelliLock, xorPacker).
- CLI toolchain (`dotnet-packer-re`) and verification pipeline.
