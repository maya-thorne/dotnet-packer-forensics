# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.11.0] - 2026-10-17

### Added
- **Kernel Memory Dump Carving & Residual CIL Metadata Reconstructor (`dotnet_deobfuscator.dump_carver`)**:
  - Full Windows Minidump (MDMP) and raw memory stream parser (`MinidumpParser` in `minidump_parser.py`):
    - Parses `MINIDUMP_HEADER`, stream directory entries, and system info architectures (x86, x64, ARM, ARM64).
    - Decodes standard 32-bit `MemoryListStream` (stream 5) and 64-bit `Memory64ListStream` (stream 9) descriptors, establishing contiguous virtual address mappings.
    - Decodes `ModuleListStream` (stream 4) extracting loaded binary names (via UTF-16LE decoding), image base addresses, checksums, and timestamps.
    - Gracefully handles truncated stream descriptors and supports fallback linear partitioning for raw crash dump memory blocks.
  - ECMA-335 BSJB metadata root scanner and stream carver (`BSJBCarver` in `bsjb_carver.py`):
    - Scans arbitrary memory segments for the `BSJB` signature (`0x424A5342`) and extracts version strings (e.g. `v4.0.30319`).
    - Recovers stream directory descriptors (`#~`, `#-`, `#Strings`, `#US`, `#Blob`, `#GUID`).
    - Decodes the `#US` (User Strings) heap via 7-bit compressed integer lengths and UTF-16LE character decoding to uncover decrypted string constants, URLs, and commands.
    - Extracts null-terminated UTF-8 identifier tokens from `#Strings`.
    - Parses `#~` and `#-` metadata table stream headers, recovering valid table bitmasks, sorted bitmasks, and row counts across Module, TypeDef, MethodDef, and Assembly tables.
  - Residual CIL method body carver and instruction validator (`MethodCarver` in `method_carver.py`):
    - Heuristically carves Tiny method headers (1-byte, code size 1-63 bytes) and Fat method headers (12-byte header, MaxStack, CodeSize, LocalVarSigTok).
    - Validates instruction streams against known 1-byte and 2-byte ECMA-335 CIL opcodes, checking immediate operand boundaries and verifying method termination (`ret`, `throw`, unconditional branches).
    - Filters out random memory noise and non-code blocks using instruction density thresholds and Shannon entropy checks.
  - PE container synthesization and layout unmapper (`AssemblyReconstructor` in `reconstructor.py`):
    - Locates surrounding `MZ` headers to unmap virtual memory allocations back to physical file alignments.
    - Synthesizes a minimal compliant PE32/CLR container when original PE headers are missing or wiped by anti-forensic hooks, binding carved BSJB metadata, tables, and residual methods into a valid PE image with CLR COM descriptors.
  - High-level orchestrator facade (`KernelDumpCarver` in `analyzer.py`) and safe artifact exporter:
    - Provides comprehensive telemetry: dump format, dump size, memory ranges scanned, modules detected, BSJB roots found, assemblies carved, methods recovered, strings recovered, and anomaly flags (`CORRUPTED_PE_HEADER`, `TRUNCATED_BSJB_STREAM`, `ORPHANED_METHOD_BODIES`, `SUSPICIOUS_MEMORY_GAP`).
    - Safe artifact export (`summary.json`, `carved_assemblies/`, `residual_methods.json`, `extracted_strings.txt`) with strict path traversal defenses (`safe_path`) and memory wiping (`zeroize_buffer`).
  - Core orchestrator integration (`DotNetPackerCore.carve_dump` and `DotNetPackerCore.export_carved_dump`).
- **CLI Toolchain Integration**:
  - Added `--dump-carver` flag enabling memory dump inspection and residual CIL carving.
  - Added `--dump-extract-methods` flag to carve Tiny and Fat method bodies from memory pages.
  - Added `--dump-out <DIR>` option for exporting carved assemblies, residual method JSON, strings, and metadata tables.
  - Added `--dump-min-confidence <FLOAT>` option setting the minimum confidence threshold for reconstructed assemblies (default: 0.5).
  - Added `--dump-max-methods <INT>` option configuring maximum residual CIL methods to carve (default: 100).
- **Comprehensive Unit & Integration Test Suite (`tests/test_dump_carver.py`)**:
  - 16 dedicated unit and integration tests covering data models, enum serialization, path traversal security, buffer zeroization, synthetic minidump parsing (32-bit and 64-bit memory list streams, module list streams), BSJB root scanning, `#US` and `#Strings` extraction, `#~` table row count decoding, Tiny and Fat CIL method carving, PE synthesization, memory unmapping, analyzer facade execution, directory export, and CLI automation (expanding total suite to 417 passing tests).

## [2.10.0] - 2026-10-16

### Added
- **Native AOT & ReadyToRun (R2R) Composite PE Forensic Disassembler & Symbol Parser (`dotnet_deobfuscator.native_aot`)**:
  - Full ReadyToRun (R2R) header and section parser (`R2RParser` in `r2r_parser.py`):
    - Parses `READYTORUN_HEADER` (`RTR\0` magic: `0x00525452`), major/minor version, and flags from `IMAGE_COR20_HEADER.ManagedNativeHeader` or via section fallback scan.
    - Decodes all standard ReadyToRun section descriptors: `COMPILER_IDENTIFIER` (100), `IMPORT_SECTIONS` (101), `RUNTIME_FUNCTIONS` (102), `METHODDEF_ENTRYPOINTS` (103), `EXCEPTION_INFO` (104), `DEBUG_INFO` (105), `DELAYLOAD_METHODCALL_THUNKS` (106), `AVAILABLE_TYPES` (107), `INSTANCE_METHOD_ENTRYPOINTS` (108), `INLINING_INFO` (109), `PROFILE_DATA` (110), `MANIFEST_METADATA` (111), `ATTRIBUTE_PRESENCE` (112), and `INLINING_INFO2` (113).
    - Extracts compiler identifier string (e.g. Crossgen2 / CoreCLR version and release metadata).
    - Parses Windows x64/ARM64 SEH `RUNTIME_FUNCTION` records (`BeginAddress`, `EndAddress`, `UnwindDataAddress`) to establish native method boundaries and sizes.
    - Resolves `METHODDEF_ENTRYPOINTS` lookup tables, cross-referencing ECMA-335 MethodDef tokens (`0x0600XXXX`) to precompiled native function entry RVAs.
  - Native AOT (.NET 7/8/9) detection and symbol demangling engine (`AOTSymbolParser` in `aot_symbol_parser.py`):
    - Scans and fingerprints characteristic Redhawk (Rhp*) runtime helper functions (`RhpReversePInvoke`, `RhpPInvoke`, `RhpNewFast`, `RhpNewArray`, `RhpAllocate`, `RhpAssignRef`, `RhpTypeCast`, `RhpCheckCast`, `RhpThrowEx`, `RhpInitialDynamicInterfaceDispatch`, `RhGetRuntimeVersion`).
    - Infers target .NET generation (.NET 7, .NET 8, .NET 9) based on compiler identifiers, Redhawk helper variants, frozen segment signatures, and section topology.
    - Demangles C-style mangled symbol tokens (e.g. `System_Private_CoreLib_System_Console_WriteLine` -> `System.Console.WriteLine`, constructor `.ctor` tokens) into clean .NET namespaces and method signatures.
    - Parses PE export directory to recover `UnmanagedCallersOnly` exports and native entrypoint thunks.
  - Standalone native machine code instruction disassembler (`NativeDisassembler` in `disassembler.py`):
    - Pure Python x64/x86 instruction decoder handling stack frame management (`PUSH RBP`, `MOV RBP, RSP`, `SUB RSP, imm`), ALU and register operations, direct and indirect calls (`CALL rel32`, `CALL [RIP + disp32]`), unconditional and conditional branches (`JE`, `JNE`, `JL`, `JG`, `JA`, `JB`, `JMP`), and epilogues (`ADD RSP, imm`, `POP RBP`, `RET`).
    - Automatically annotates call targets with identified Rhp* runtime helper names and resolved symbols.
    - Partitions basic block topology using branch targets and fallthrough leader instructions.
  - High-level forensic orchestrator facade (`NativeAOTAnalyzer` in `analyzer.py`) and safe artifact exporter:
    - Automatically classifies compilation type (`READYTORUN_R2R`, `NATIVE_AOT`, `HYBRID_AOT_MANAGED`, `STANDARD_MANAGED`, `STANDARD_NATIVE`, `CORRUPTED_OR_ANOMALOUS`).
    - Telemetry metrics: R2R sections count, runtime functions count, mapped entrypoint count, recovered symbols count, Rhp helper list, risk scoring, and structural anomalies.
    - Safe artifact export (`summary.json`, `r2r_sections.json`, `symbols.csv`, `disassembly.txt`, `disassembly.json`) with path traversal sanitization (`safe_path`) and memory zeroization (`zeroize_buffer`).
  - Core orchestrator integration (`DotNetPackerCore.analyze_native_aot`, `DotNetPackerCore.export_native_aot`, and `DotNetPackerCore.analyze_bytes`).
- **CLI Toolchain Integration**:
  - Added `--native-aot` flag to trigger deep Native AOT and ReadyToRun forensic inspection and detailed telemetry.
  - Added `--r2r-disasm` flag to disassemble native code methods from runtime functions or AOT stubs.
  - Added `--aot-symbols` flag to extract and display recovered native symbols, exports, and runtime helpers.
  - Added `--native-aot-out <DIR>` option for exporting parsed symbols (CSV), R2R sections, and disassembled methods (TXT/JSON).
  - Added `--native-aot-max-methods <INT>` option configuring maximum disassembly count (default: 50).
- **Comprehensive Unit & Integration Test Suite (`tests/test_native_aot.py`)**:
  - 20 unit and integration tests covering data models, enum values, dataclass serialization, security path traversal defenses, buffer zeroization, synthetic ReadyToRun PE binary generation and parsing, fallback section scans, corrupted header resilience, Redhawk helper scanning, version inference (.NET 7/8/9), symbol demangling, x64 method disassembly, call target annotation, basic block construction, indirect calls, analyzer facade inspection across all compilation types, artifact directory export, core orchestrator facade integration, report formatting, and CLI execution (expanding total suite to 401 passing tests).

## [2.9.0] - 2026-10-16

### Added
- **Batch Forensic Automation CLI Engine & Multi-Threaded PE Directory Scanner (`dotnet_deobfuscator.batch`)**:
  - Modular data models and security primitives (`models.py`): `FileScanStatus` (scanned, packed, clean, skipped, error, timeout), `ThreatLevel` (clean, low, medium, high, critical) with automated threat scoring and severity comparisons, `BatchScanOptions`, `SingleScanResult`, `BatchScanSummary`, and `BatchScanReport`.
  - Memory sanitization (`zeroize_buffer`) using `ctypes.memset` to prevent memory leaks and strict path traversal defense (`safe_path`) preventing directory escape attacks.
  - Multi-threaded PE directory scanner (`BatchDirectoryScanner` in `scanner.py`):
    - Fast MZ and `PE\0\0` header pre-filter inspecting initial bytes to bypass non-executable files early without heavy CLR initialization.
    - Concurrent worker pool utilizing `concurrent.futures.ThreadPoolExecutor` with thread-safe progress tracking callbacks.
    - Deterministic per-file timeout enforcement catching and isolating hung tasks without blocking the scanner.
    - Recursive and shallow directory discovery with glob pattern matching (`*.exe;*.dll`, `*`) and file size threshold filtering (`min_size_bytes`, `max_size_bytes`).
    - Robust error isolation ensuring corrupted or malformed binaries do not abort batch processing.
  - Multi-format forensic reporting engine (`BatchReporter` in `reporter.py`):
    - Structured terminal console table with executive summary, throughput rates (files/sec, MB/s), threat breakdown, and aligned file inventory.
    - RFC 4180-compliant CSV exporter for SIEM spreadsheet ingestion and automated pipeline processing.
    - Comprehensive JSON manifest exporter capturing full scan options, summary metrics, and per-file telemetry.
    - Self-contained, offline HTML dashboard generator featuring a dark-mode cybersecurity theme, responsive summary cards, threat distribution metrics, protector summary pills, strict HTML entity escaping, and client-side instant search/filtering with zero external CDN dependencies.
  - High-level orchestrator facade (`BatchForensicEngine` in `engine.py`) and `DotNetPackerCore.batch_scan` / `DotNetPackerCore.export_batch_report` integration.
- **CLI Toolchain Integration**:
  - Added `--batch [DIR]` argument for batch directory scanning.
  - Added `--batch-recursive` flag for recursive subdirectory scanning.
  - Added `--batch-workers <INT>` option for concurrent thread configuration (default: 4).
  - Added `--batch-out <DIR>` option for automated multi-format report exports (JSON, CSV, HTML dashboard).
  - Added `--batch-json <PATH>`, `--batch-csv <PATH>`, and `--batch-html <PATH>` destination options.
  - Added `--batch-pattern <GLOB>` option for file filtering (default: `*`).
  - Added `--batch-timeout <FLOAT>` option for per-file execution bounds (default: 30.0s).
  - Added `--batch-min-size <INT>` and `--batch-max-size <INT>` threshold options.
- **Comprehensive Batch Scanner Test Suite (`tests/test_batch_scanner.py`)**:
  - 41 unit and integration tests covering model serialization, buffer zeroization, path traversal defenses, shallow vs recursive discovery, glob and size filtering, fast PE pre-filtering, multi-threaded concurrency, per-file timeouts, dynamic worker replenishment, error isolation, console tables, JSON/CSV exports, self-contained HTML dashboard validation, core facade methods, and CLI command execution (expanding total suite to 381 passing tests).

## [2.8.0] - 2026-10-15

### Added
- **Deobfuscation Regression Fuzzing Harness & Synthetic Mutated Binary Generator (`dotnet_deobfuscator.fuzzing`)**:
  - Structurally valid baseline PE32 and .NET executable generator (`SyntheticMutatedBinaryGenerator.generate_baseline_pe`) constructing conforming DOS stubs, NT File and Optional headers, Section tables, Cor20Header COM descriptors, BSJB metadata roots, stream catalogs (#Strings, #US, #~), and valid CIL method bodies (Tiny format).
  - 11 targeted architectural mutation operators (`MutationStrategy`): `BIT_FLIP` (targeted bitwise flipping), `BYTE_NOISE` (random byte substitution and edge integers), `DOS_HEADER_MANGLE` (MZ and e_lfanew pointer corruption), `NT_HEADER_MANGLE` (PE\\0\\0 signature and machine architecture mangling), `OPTIONAL_HEADER_MANGLE` (magic, alignments, and Cor20 DataDirectory anomalies), `SECTION_TABLE_MANGLE` (section names, out-of-bounds raw pointers, and integer overflow sizes), `COR20_DESCRIPTOR_MANGLE` (Cor20 cb, metadata RVA/size, and entrypoint token alteration), `METADATA_STREAM_MANGLE` (BSJB signature, version string, and stream count bloating), `CIL_BYTECODE_FUZZ` (invalid 0xFE 0xFF opcodes, out-of-bounds branch targets, and stack underflow sequences), `OVERLAY_INJECTION` (high-entropy noise, pseudo-protector signatures, and corrupted archive headers), and `TRUNCATION` (boundary slicing across headers and metadata).
  - Multi-strategy corpus generation engine (`SyntheticMutatedBinaryGenerator.generate_corpus`) emitting batches of mutated test samples with deterministic PRNG seeding.
  - Sandboxed regression fuzzing execution harness (`RegressionFuzzingHarness`) evaluating mutated samples against all forensic subsystems (`ANALYZE`, `REBUILD`, `VERIFY`, `CFG`, `BAML`, `MIXED_MODE`, `ANTIDUMP`, `ANTITAMPER`, `RULES`, `ALL`).
  - Robust crash severity classifier (`CrashSeverity`): `CLEAN_PASS`, `HANDLED_ERROR` (graceful rejection), `REGRESSION_CRASH` (unhandled fatal parser crash), `TIMEOUT_HANG` (execution time threshold breach), and `RESOURCE_EXHAUSTION` (memory/recursion boundaries).
  - Persistent regression ledger (`RegressionLedger`) for tracking discovered crashes, exporting reproduction bundles (mutated binary `.bin` and execution telemetry `.json`), and executing deterministic regression verification replays (`replay_crash`).
  - Memory sanitization (`zeroize_buffer`) using `ctypes.memset` and directory traversal defense (`safe_path`).
- **CLI & Core Orchestrator Integration**:
  - Added `--fuzz` CLI flag to trigger automated regression fuzzing campaign across forensic targets.
  - Added `--fuzz-iterations <INT>` CLI option specifying fuzz iteration count (default: 50).
  - Added `--fuzz-seed <INT>` CLI option specifying PRNG seed for deterministic fuzzing (default: 1337).
  - Added `--fuzz-targets <LIST>` CLI option to filter target subsystems to fuzz.
  - Added `--fuzz-timeout <FLOAT>` CLI option configuring per-iteration timeout limit (default: 3.0s).
  - Added `--fuzz-out <DIR>` CLI option to export campaign JSON report, text summary, crashing seeds, and regression ledger.
  - Added `--gen-mutants` CLI flag to generate and export synthetic mutated binaries directly.
  - Added `--mutant-count <INT>` CLI option configuring generated synthetic mutant count (default: 10).
  - Integrated in-memory buffer analysis `DotNetPackerCore.analyze_bytes` and campaign runners `DotNetPackerCore.run_fuzzing_campaign` and `DotNetPackerCore.generate_synthetic_corpus`.
- **Comprehensive Fuzzing Harness Test Suite (`tests/test_fuzzing_harness.py`)**:
  - 42 dedicated unit and integration tests covering baseline PE generation validity, all 11 individual mutation strategies, corpus generation, clean pass execution across all targets, handled error capture on corrupted data, timeout detection, end-to-end fuzzing campaign execution, crash replay, regression ledger persistence, core orchestrator facade integration, CLI commands, path traversal protection, memory zeroization, subprocess isolation, stderr traceback preservation, stdout pollution resilience, corrupted header boundaries, and extreme section size memory limits (expanding total suite to 340 passing tests).

## [2.7.0] - 2026-10-15

### Added
- **WPF BAML & Embedded UI Resource Decompiler & XML Restorer (`dotnet_deobfuscator.baml`)**:
  - Full-stack MS-BAML binary record parser and XAML reconstructor (`BamlBinaryReader`) supporting variable-length 7-bit encoded integers, 16-bit/32-bit little-endian fields, and tokenized record streams.
  - Comprehensive record type support across `DocumentStart`, `DocumentEnd`, `ElementStart`, `ElementEnd`, `Property`, `PropertyCustom`, `Text`, `Comment`, `XmlnsProperty`, `PIMapping`, `DefAttribute`, `AssemblyInfo`, `TypeInfo`, `AttributeInfo`, `StringInfo`, and complex property start/end tokens.
  - Built-in WPF token dictionary (`tokens.py`) mapping negative type IDs and attribute IDs to canonical WPF control names (`Window`, `Grid`, `Button`, `TextBox`, `TextBlock`, `StackPanel`, `Border`, `Canvas`, etc.) and dependency properties (`Width`, `Height`, `Margin`, `Visibility`, `Content`, `Title`, `Click`, `Loaded`, etc.).
  - Robust XAML/XML generator (`XamlEmitter`) emitting human-readable, well-indented XAML documents with XML entity escaping (`&`, `<`, `>`, `"`, `'`), root namespace declarations (`xmlns`, `xmlns:x`), self-closing tags, and syntactic well-formedness validation via `xml.etree.ElementTree`.
  - Managed resource container parser (`BamlResourceExtractor.extract_from_resources`) reading standard .NET `.resources` manifests (`0xBEEFCACE` magic) to extract embedded `.baml` streams.
  - Heuristic raw BAML stream carver (`BamlResourceExtractor.carve_baml_streams`) recovering standalone BAML byte sequences from PE sections and raw binary buffers.
  - Automated static forensic anomaly detection (`detect_anomalies`) flagging suspicious event handlers (`_Loaded`, `_Click` bound to shellcode/stager routines), concealed UI elements (`Visibility="Collapsed"` or `Opacity="0"` with active controls), external C2 URIs, obfuscated Unicode identifiers (`x:Class`), and high-entropy Base64 payloads.
  - High-level orchestration facade (`BamlDecompiler`) and safe directory export engine (`export_to_directory`) outputting `.xaml` documents and structured `baml_manifest.json` manifests with strict directory traversal prevention (`_safe_path`).
  - Cryptographic memory sanitization (`zeroize_buffer`) using `ctypes.memset` to scrub intermediate byte streams and decrypted resource buffers.
- **CLI & Core Orchestrator Integration**:
  - Added `--baml` CLI flag to extract and decompile embedded WPF BAML UI resources to clean XAML markup.
  - Added `--baml-out <DIR>` CLI flag to export decompiled XAML documents and structured JSON manifests to disk.
  - Added `--baml-raw` CLI flag to optionally export raw `.baml` binary streams alongside `.xaml` documents.
  - Integrated BAML forensics telemetry into `DotNetPackerCore.analyze_file`, `DotNetPackerCore.analyze_baml`, `DotNetPackerCore.export_baml`, `analysis_collector.py`, and `report_formatter.py`.
- **Architectural Refactoring & Modularity**:
  - Extracted CLI argument parser into dedicated `dotnet_deobfuscator/cli_args.py` (260 lines), reducing `cli.py` to 483 lines.
  - Extracted multi-protector payload unpacking and directory extraction dispatch logic into `dotnet_deobfuscator/unpacker_dispatcher.py` (112 lines), keeping `core.py` under 665 lines.
- **Comprehensive BAML Decompiler Test Suite (`tests/test_baml_decompiler.py`)**:
  - 11 dedicated unit and integration tests covering primitive reader bounds, synthetic BAML decoding, XML well-formedness validation, entity escaping, suspicious URI and event handler anomaly detection, .resources container parsing, stream carving, safe directory export, path traversal defense, memory zeroization, core facade integration, and CLI execution (expanding total test suite to 298 passing tests).

## [2.6.0] - 2026-10-15

### Added
- **CIL Control Flow Graph (CFG) Generator & High-Entropy Block Visualizer (`dotnet_deobfuscator.cfg`)**:
  - Full ECMA-335 CIL instruction disassembler (`CILDisassembler`) decoding 1-byte opcodes (0x00–0xDF), 2-byte opcodes (0xFE00–0xFE1E), short/long relative branches, and switch tables with exact byte offset resolutions.
  - Basic block partitioner and graph constructor (`CFGBuilder`) identifying branch leaders, slicing instruction spans, connecting directed edges across fallthrough, conditional true/false, unconditional jumps, and multi-way switch cases.
  - Precise McCabe cyclomatic complexity calculation modeling branch decision points ($M = 1 + \\sum(\\text{out-degree} - 1)$) and depth-first search (DFS) traversal detecting back-edges, cycle headers, and natural loops.
  - Unreachable dead code analyzer flagging disconnected basic blocks following unconditional returns or throws.
  - Bytecode Shannon entropy profiler measuring informational density per basic block (Low < 3.0, Normal 3.0–5.5, Suspicious 5.5–6.8, High >= 6.8) to detect encrypted method stubs, packed shellcode payloads, and arithmetic mutations.
  - Multi-format visualization suite (`CFGVisualizer`) producing GitHub-compatible Mermaid flowcharts with entropy class styling, Graphviz DOT specifications with HTML-like record tables, self-contained XML-compliant SVG vector diagrams (with zero external images), terminal ASCII box layouts, and structured JSON graphs.
  - Unified orchestration facade (`CFGAnalyzer`) scanning assemblies for CorILMethod Tiny/Fat headers, computing aggregate telemetry, and exporting visualization suites via safe path traversal sanitization (`_safe_path`).
  - Cryptographic memory sanitization (`zeroize_buffer`) using `ctypes.memset` to scrub intermediate disassembly bytecode slices from process memory.
- **CLI & Core Orchestrator Integration**:
  - Added `--cfg` CLI flag to trigger static CIL control flow graph analysis and report method complexity and entropy metrics.
  - Added `--cfg-token <TOKEN>` CLI flag to inspect a specific method token (e.g. `0x06000001`).
  - Added `--cfg-format <mermaid|dot|svg|ascii|json|all>` CLI flag configuring visualization output formats.
  - Added `--cfg-out <DIR>` CLI flag to export visual diagrams, SVG vector charts, and JSON manifests to disk.
  - Integrated CFG forensics telemetry into `DotNetPackerCore.analyze_file`, `DotNetPackerCore.analyze_cfg`, `DotNetPackerCore.export_cfg`, `analysis_collector.py`, and `report_formatter.py`.
- **Comprehensive CFG Visualizer Test Suite (`tests/test_cfg_visualizer.py`)**:
  - 19 dedicated unit and integration tests covering disassembler opcodes, branch targets, switch tables, linear/if-else/loop/dead-code CFG topologies, cyclomatic complexity calculations, Shannon entropy tiers, Mermaid, DOT, valid XML SVG parsing, ASCII output, directory export manifests, and path traversal defenses (expanding total test suite to 287 passing tests).

## [2.5.0] - 2026-10-14

### Added
- **Native Mixed-Mode PE Static Analyzer & CIL-Native Transition Tracer (`dotnet_deobfuscator.mixed_mode`)**:
  - Dedicated mixed-mode (IJWH / C++/CLI) binary forensics engine detecting and classifying execution models across pure managed (`CLR_ILONLY`), mixed-mode, pure native, and anomalous PE executables.
  - VTable Fixup Table parser (`VTFixupParser`) decoding `IMAGE_COR_VTABLEFIXUP` header arrays, extracting entry point tokens (`MethodDef`, `MemberRef`, `MethodSpec`), resolving slot bit-widths (`COR_VTABLE_32BIT`, `COR_VTABLE_64BIT`), and validating call transition thunks (`COR_VTABLE_FROM_UNMANAGED`, `COR_VTABLE_CALL_MOST_DERIVED`).
  - CIL-Native execution boundary tracer (`TransitionTracer`) mapping unmanaged entrypoint bootstrap jumps, native TLS callback tables (`IMAGE_DIRECTORY_ENTRY_TLS`), unmanaged export thunks bridging into managed metadata tokens, and P/Invoke marshalling thunks.
  - Multi-factor threat risk scoring engine (`MixedModeAnalyzer.calculate_risk_score`) identifying security anomalies, stealth native execution branches, concealed managed payloads, and unsigned TLS callbacks.
  - Safe forensic artifact exporter (`export_to_directory`) generating structured transition manifests (`mixed_mode_manifest.json`), unmanaged export tables (`vtfixup_exports.json`), and TLS telemetry with strict directory traversal sanitization (`_safe_path`).
  - Memory zeroization (`zeroize_buffer`) using `ctypes.memset` to scrub intermediate byte arrays, unpacked fixup slots, and parsed token structures from process memory.
- **CLI & Core Orchestrator Integration**:
  - Added `--mixed-mode` CLI flag to trigger static mixed-mode PE analysis and print diagnostic telemetry to stdout.
  - Added `--trace-transitions` CLI flag to trace native entrypoints, TLS callbacks, and unmanaged export bridges.
  - Added `--mixed-mode-out <DIR>` CLI flag to export structured JSON manifests and analysis diagnostics to disk.
  - Integrated mixed-mode forensics telemetry into `DotNetPackerCore.analyze_file`, `DotNetPackerCore.analyze_mixed_mode`, `DotNetPackerCore.export_mixed_mode`, `analysis_collector.py`, and `report_formatter.py`.
- **Comprehensive Mixed-Mode Test Suite (`tests/test_mixed_mode.py`)**:
  - 12 dedicated unit and integration test cases covering pure managed, pure native, mixed-mode IJWH, native entrypoint detection, 32/64-bit VTFixup parsing, unmanaged export bridges, TLS callbacks, risk scoring, safe directory exports, and CLI execution (expanding total test suite to 268 passing tests).

## [2.4.0] - 2026-10-14

### Added
- **Automated Threat Hunting YARA & Sigma Rule Synthesizer (`dotnet_deobfuscator.rules`)**:
  - Modular threat rule synthesis engine generating production-ready detection rules in YARA v4+ and Sigma v2 YAML formats from static binary forensics.
  - Threat feature extraction engine (`ThreatFeatureExtractor`) capturing binary hashes (SHA-256, SHA-1, MD5), PE imphash, section topology and Shannon entropies, CLR Cor20Header and BSJB metadata streams, CIL bytecode pattern signatures, and detected protector tokens.
  - Multi-tier YARA rule generator (`YARASynthesizer`) synthesizing pristine rules across Specific (exact file size bounds, cryptographic hashes, section counts, unique bytecodes), Behavioral (protector family rules targeting ConfuserEx, .NET Reactor, Costura, Eazfuscator, Babel, ArmDot, IntelliLock, DeepSea, xorPacker overlay), and Threat Hunting tiers (high-entropy non-resource sections via `math.entropy`, anti-dump header corruptions, multi-architecture carriers).
  - Spec-compliant Sigma v2 rule generator (`SigmaSynthesizer`) emitting valid YAML definitions for Process Creation (Event ID 4688 / Sysmon 1), File Creation / Drop (Sysmon 11), and Image Load (Sysmon 7) events with deterministic UUID v5 identifiers and MITRE ATT&CK taxonomy tags (`attack.defense_evasion`, `attack.t1027`, `attack.t1027.002`, `attack.execution`).
  - Unified orchestration facade (`ThreatRuleEngine`) providing single-call synthesis from raw bytes or files, and safe export pipeline (`export_to_directory`) organizing rules into `.yar`, `.yml`, and structured `rules_manifest.json` files with strict directory traversal validation (`_safe_path`).
  - Cryptographic buffer zeroizing (`zeroize_buffer`) utilizing `ctypes.memset` to scrub in-memory decryption scratchpads and feature extraction buffers.
- **CLI & Core Orchestrator Integration**:
  - Added `--gen-rules` flag to synthesize both YARA and Sigma rules and print them to stdout.
  - Added `--gen-yara` and `--gen-sigma` flags for standalone rule format synthesis.
  - Added `--rule-level <specific|behavioral|hunt>` to configure rule granularity and strictness.
  - Added `--rules-out <DIR>` flag to export formatted rule files and JSON manifest to a target directory.
  - Integrated automated behavioral rule telemetry into `DotNetPackerCore.analyze_file`, `analysis_collector.py`, and `report_formatter.py`.
- **Comprehensive Rule Generator Test Suite (`tests/test_rule_generator.py`)**:
  - 13 dedicated unit and integration test cases covering feature extraction, PE imphash calculation, Shannon entropy verification, specific/behavioral/hunting YARA rule generation, Sigma YAML formatting and UUID v5 validation, buffer memory wiping via `ctypes.memset`, directory traversal defenses, core orchestrator methods, and CLI command-line execution (expanding total suite to 256 passing tests).

## [2.3.0] - 2026-10-14

### Added
- **Native Multi-Architecture Resource Demuxer & Platform Router (`dotnet_deobfuscator.unpackers.native_demuxer_models`, `dotnet_deobfuscator.unpackers.native_demuxer_engine`, `dotnet_deobfuscator.unpackers.native_demuxer`)**:
  - Full static discovery and demuxing engine for multi-architecture native binary payloads (x86, x64, ARM64, ARM, IA64) embedded or bundled within .NET assemblies, wrappers, and single-file carrier hosts.
  - Deep binary format and architecture inspection (`inspect_binary_format`) identifying Windows PE (`IMAGE_FILE_MACHINE_I386`, `IMAGE_FILE_MACHINE_AMD64`, `IMAGE_FILE_MACHINE_ARM64`, `IMAGE_FILE_MACHINE_ARMNT`), Linux ELF (`ELF32`, `ELF64`), and macOS Mach-O (`MACHO32`, `MACHO64`) binaries from raw byte streams.
  - Multi-source container carver locating embedded payloads across CLR manifest resources, Costura naming conventions (`costura32.*`, `costura64.*`), NuGet runtime catalog directories (`runtimes/<rid>/native/`), folder prefixes, and appended PE overlay data.
  - Embedded stream decompressor (`decompress_payload`) automatically handling Costura DeflateStream payloads (4-byte uncompressed length prefix + DeflateStream), standard zlib streams, gzip headers, and raw deflate streams with 100 MB bounds checking against decompression bombs.
  - Automated architecture mismatch and spoofing detection (`mismatch_detected`) cross-verifying declared manifest/path architectures against physical binary machine headers to alert analysts to masqueraded or corrupted payloads.
  - Platform routing simulator (`route_for_platform`) modeling OS dynamic loader resolution rules, including exact match routing, Windows on ARM x64/x86 emulation fallbacks, 64-bit Windows WoW64 compatibility fallbacks, and macOS Rosetta 2 binary translation fallbacks.
  - Safe directory export pipeline (`unpack_to_directory`) organizing carved binaries into dedicated architecture subdirectories (`x86/`, `x64/`, `arm64/`, etc.) and generating structured `routing_manifest.json` reports with strict path traversal defenses (`_safe_path`).
  - Cryptographic memory sanitization (`zeroize_buffer`) using `ctypes.memset` to wipe transient decryption and decompression buffers immediately upon extraction.
- **CLI & Core Orchestrator Integration**:
  - Added `--demux-native` flag to run static multi-architecture demuxing and display all carved payloads, machine types, and mismatch warnings.
  - Added `--demux-out <DIR>` flag to carve and export demuxed native binaries into architecture-organized folders with a complete routing manifest.
  - Added `--route-arch <ARCH>` and `--route-os <OS>` flags to simulate runtime platform routing and loader resolution for specified architectures.
  - Integrated native demuxer telemetry and reporting into `DotNetPackerCore.analyze_file`, `DotNetPackerCore.demux_native`, `DotNetPackerCore.route_native`, `DotNetPackerCore.unpack_native_dir`, `analysis_collector.py`, and `report_formatter.py`.
- **Comprehensive Native Demuxer Test Suite (`tests/test_native_demuxer.py`)**:
  - 14 dedicated unit and integration test cases covering x86/x64/ARM64 PE header inspection, ELF/Mach-O machine parsing, buffer zeroization, DeflateStream decompression, multi-architecture carving, architecture mismatch detection, exact and fallback platform routing (WoW64, ARM64 emulation, Rosetta 2), path traversal defense, directory exports, and CLI execution (expanding the total test suite to 243 tests).

## [2.2.0] - 2026-10-13

### Added
- **Anti-Dump Process Memory PE Header Healer & Scylla Dump Normalizer (`dotnet_deobfuscator.unpackers.antidump_models`, `dotnet_deobfuscator.unpackers.antidump_healer`, `dotnet_deobfuscator.unpackers.antidump`)**:
  - Comprehensive anti-dump detection heuristics and confidence scoring identifying erased DOS magic (`MZ`), wiped NT headers, orphaned PE signatures, stripped section tables, corrupted COM descriptors, and memory-mapped section alignments (`VirtualAddress == PointerToRawData`).
  - ECMA-335 BSJB CLR metadata scanner (`scan_bsjb_metadata`) locating `BSJB` signatures (`0x424A5342`), parsing version strings, stream counts, and metadata boundaries across raw memory buffers.
  - Cor20Header recovery and synthesis engine (`scan_or_synthesize_cor20_header`) restoring stripped COM descriptors in DataDirectory[14] or synthesizing valid ECMA-335 Cor20Headers (`cb=72`, `MajorRuntimeVersion=2`, `MinorRuntimeVersion=5`, MetaData RVA, ILONLY flags, EntryPointToken).
  - CLR Import Table (IAT) reconstruction engine (`build_clr_import_table`) synthesizing standard `mscoree.dll` bootstrap jump thunks (`FF 25 [IAT RVA]`), `IMAGE_IMPORT_DESCRIPTOR`, INT, and IAT thunks to ensure full compatibility with disassemblers (ILSpy, dnSpy, de4dot) and native Windows PE loaders.
  - Scylla and process memory dump unmapper converting virtual memory page alignments into compact, file-aligned (`0x200`) raw disk layouts, recalculating section raw pointers and `SizeOfImage`.
  - Section table healing engine sanitizing erased or randomized section names, inferring section semantics (`CODE_AND_CLR`, `METADATA_BSJB`, `IMPORT_TABLE`, `WIN32_RESOURCES`), and synthesizing baseline `.text` sections when section tables are completely wiped.
  - Safe directory export pipeline (`unpack_to_directory`) generating normalized PE executables (`healed_dump.exe`/`.dll`), individual section binary dumps, JSON telemetry manifests, and Scylla import reports with strict path traversal defenses (`_safe_path`).
- **Telemetry Aggregator (`dotnet_deobfuscator.analysis_collector`)**:
  - Modularized unified analysis dictionary construction (`build_analysis_report`), ensuring `core.py` remains lean and well within standard modularity thresholds (619 lines).
- **CLI & Core Orchestrator Integration**:
  - Added `--heal-dump` and `--heal-out` flags to detect anti-dump corruptions, heal process memory dumps, and write normalized PE binaries.
  - Added `--scylla-mode` flag enforcing Scylla-compatible memory dump unmapping and CLR import reconstruction.
  - Added `--anti-dump-dir` for full artifact and carved section directory exports.
  - Integrated anti-dump telemetry into `DotNetPackerCore.analyze_file`, `DotNetPackerCore.heal_anti_dump`, `DotNetPackerCore.detect_anti_dump`, and `DotNetPackerCore.unpack_anti_dump_dir`.
- **Comprehensive Anti-Dump Test Suite (`tests/test_antidump_healer.py`)**:
  - 16 unit and integration test cases covering clean PE detection, erased DOS/NT header repairs, virtual memory dump unmapping, stripped section name sanitization, ConfuserEx anti-dump runtime detection, BSJB metadata extraction, CLR import table synthesis, Cor20Header synthesis, scratchpad buffer zeroizing, path traversal prevention, and CLI execution (expanding the total test suite to 229 tests).

## [2.1.0] - 2026-10-13


### Added
- **CLI Metadata Anti-Tamper Heuristics & In-Memory JIT Dumper Engine (`dotnet_deobfuscator.unpackers.antitamper_models`, `dotnet_deobfuscator.unpackers.antitamper_jit`, `dotnet_deobfuscator.unpackers.antitamper`)**:
  - ECMA-335 CorILMethod header parser and serializer (`CorILMethodParser`) supporting Tiny format (`CorILMethod_TinyFormat`, 1-byte header, max code size 63, implicit maxstack 8) and Fat format (`CorILMethod_FatFormat`, 12-byte header, arbitrary code size, explicit maxstack, local variable signatures, exception handling flags).
  - CIL method bytecode validator verifying valid terminating opcodes (`ret`, `throw`, `rethrow`, `jmp`) and instruction stream consistency.
  - Cryptographic stream decrypter (`AntiTamperDecrypter`) inverting dynamic LCG PRNG stream ciphers, token-keyed XOR ciphers, and rolling byte XOR transformations with intermediate buffer zeroizing (`ctypes.memset`).
  - In-memory CLR JIT dumper interface (`JITDumperInterface`) supporting raw memory dump scans, structured JSON method dumps, and binary JITD (`JITD\x01`) stream deserialization with 100 MB bounds checking.
  - Static heuristic detection engine (`AntiTamperUnpacker.detect`) identifying corrupted `#~` and `#-` metadata tables, JIT hook assembly sequences, ConfuserEx anti-tamper runtime attributes, and high-entropy `.tamper` PE sections.
  - Assembly reconstruction pipeline (`restore_antitamper_assembly`) synthesizing clean PE binaries with decrypted CIL method bodies injected into an aligned `.antitamper` section, incrementing section headers, and realigning `SizeOfImage`.
  - Safe directory export pipeline (`unpack_to_directory`) generating restored executables, individual method CIL blobs, JSON telemetry manifests, and dump diagnostics with strict path traversal defenses.
- **Forensic Telemetry Formatter (`dotnet_deobfuscator.report_formatter`)**:
  - Extracted human-readable terminal report generation (`format_text_report`) into a dedicated module, maintaining strict 500-700 line limits across `cli.py` and core orchestrators.
- **CLI & Core Orchestrator Integration**:
  - Added `--anti-tamper` and `--anti-tamper-out` flags to detect anti-tamper protections, decrypt CIL method bodies, and write restored binaries.
  - Added `--dump-jit` to ingest in-memory CLR JIT dumps from external debuggers or memory carvers.
  - Added `--anti-tamper-dir` for multi-method CIL artifact and diagnostics exports.
  - Integrated anti-tamper telemetry into `DotNetPackerCore.analyze_file`, `restore_antitamper`, and `unpack_antitamper_dir`.
- **Comprehensive Anti-Tamper Test Suite (`tests/test_antitamper_unpacker.py`)**:
  - 26 unit and integration test cases covering CorILMethod header parsing/serialization, CIL instruction validation, PRNG stream decryption, zeroize buffer wiping, JIT dump JSON/stream ingestion, heuristic detection, PE section injection, directory path traversal defense, and CLI execution (expanding the total test suite to 213 tests).

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
