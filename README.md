<div align="center">

<p align="center">
  <strong>🇺🇸 English</strong> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 中文</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/dotnet-packer-forensics"><img src="./docs/assets/locales/en/banner.svg" alt="dotnet-packer-forensics banner" width="100%" /></a>
</p>

# 🔬 dotnet-packer-forensics

**Static Forensic Unpacker, CLR Metadata Analysis & PE Overlay Research Archive**

[![Engine](https://img.shields.io/badge/Engine-Python_Zero--Dependency-10b981.svg)](#4-repository-structure--source-code-breakdown)
[![Dual-XOR Carve](https://img.shields.io/badge/Forensics-xorPacker_PE_Overlay-0ea5e9.svg)](#1-architecture--forensic-pipeline)
[![Protector Signatures](https://img.shields.io/badge/Signatures-9_Major_Packers-f59e0b.svg)](#3-core-research-whitepapers)
[![Release](https://img.shields.io/github/v/release/maya-thorne/dotnet-packer-forensics?color=10b981&label=Release&logo=github)](https://github.com/maya-thorne/dotnet-packer-forensics/releases)
[![License: MT-SRL](https://img.shields.io/badge/License-MT--SRL-blue.svg)](./LICENSE)

<sub>Engineered &amp; Audited by **[Maya Thorne](https://github.com/maya-thorne)** · Low-Level Systems &amp; Reverse Engineering Research</sub>

<br />

<p align="center">
  <a href="#1-architecture--forensic-pipeline"><b>🏛️ Architecture</b></a> •
  <a href="#2-cli-toolchain--usage-guide"><b>💻 CLI Toolchain</b></a> •
  <a href="#3-core-research-whitepapers"><b>📚 Research Whitepapers</b></a> •
  <a href="#4-repository-structure--source-code-breakdown"><b>📁 Repo Structure</b></a> •
  <a href="#5-license--security-research-attribution"><b>📜 License &amp; Attribution</b></a>
</p>

</div>

---

<span id="table-of-contents"></span>
## 📑 Table of Contents

- [🏛️ 1. Architecture & Forensic Pipeline](#1-architecture--forensic-pipeline)
- [💻 2. CLI Toolchain & Usage Guide](#2-cli-toolchain--usage-guide)
  - [Quickstart Installation](#quickstart-installation)
  - [CLI Options Matrix](#cli-options-matrix)
- [📚 3. Core Research Whitepapers](#3-core-research-whitepapers)
- [📁 4. Repository Structure & Source Code Breakdown](#4-repository-structure--source-code-breakdown)
  - [📦 Core Deobfuscator Package (`dotnet_deobfuscator/`)](#core-deobfuscator-package)
  - [🧪 Forensic Sample Corpus (`samples/`)](#forensic-sample-corpus)
  - [🔬 Test & Validation Suite (`tests/`)](#test-validation-suite)
- [📜 5. License & Security Research Attribution](#5-license--security-research-attribution)

---

<span id="1-architecture--forensic-pipeline"></span><span id="architecture-pipeline"></span>
<details open>
<summary><h2 style="display:inline-block; margin:0;" id="1-architecture--forensic-pipeline">🏛️ 1. Architecture &amp; Forensic Pipeline</h2></summary>

<br />

`dotnet-packer-forensics` delivers a zero-dependency Python reverse engineering engine designed to extract PE overlays, invert two-stage XOR ciphers (xorPacker), and inspect .NET CIL metadata and section entropy across 8 flagship protectors (ConfuserEx, .NET Reactor, Eazfuscator, Babel, ArmDot, etc.).

<p align="center">
  <a href="https://github.com/maya-thorne/dotnet-packer-forensics"><img src="./docs/assets/locales/en/architecture_diagram.svg" alt="Architecture Diagram" width="100%" /></a>
</p>

</details>

---

<span id="2-cli-toolchain--usage-guide"></span><span id="cli-toolchain"></span>
<details open>
<summary><h2 style="display:inline-block; margin:0;" id="2-cli-toolchain--usage-guide">💻 2. CLI Toolchain &amp; Usage Guide</h2></summary>

<br />

<p align="center">
  <img src="./docs/assets/demo_terminal.svg" alt="Terminal Demo" width="100%" />
</p>

<span id="quickstart-installation"></span>
### Quickstart Installation
```bash
# Clone the repository
git clone https://github.com/maya-thorne/dotnet-packer-forensics.git
cd dotnet-packer-forensics

# Run directly via Python module
python -m dotnet_deobfuscator samples/xorPacker_packed_sample.exe -v

# Or extract decrypted payload directly to disk
python -m dotnet_deobfuscator samples/xorPacker_packed_sample.exe -o unpacked_payload.exe

# Compare original vs packed binary and export visual HTML diff dashboard
python -m dotnet_deobfuscator --diff original.exe --diff-against packed.exe --diff-out ./diff_results --diff-html diff.html
```

<span id="cli-options-matrix"></span>
### CLI Options Matrix
| Flag | Description | Default |
| :--- | :--- | :---: |
| `target` | Path to target executable (`.exe` / `.dll`) (optional if `--fuzz` or `--gen-mutants`) | *Required\** |
| `-o, --output` | Output file path or directory for extracted payload | None |
| `-d, --unpack-dir` | Directory path to extract all embedded Costura & ConfuserEx assemblies | None |
| `--dump-strings` | Extract and dump decrypted ConfuserEx constants and literal strings | `False` |
| `--strip-envelope` | Strip native wrapper envelope and carve encapsulated managed .NET assembly | `False` |
| `--envelope-out` | Destination path for de-enveloped managed assembly binary | None |
| `--restore-necrobit` | Decrypt NecroBit CIL method bodies and reconstruct deobfuscated assembly | `False` |
| `--necrobit-out` | Destination path for NecroBit restored assembly binary | None |
| `--necrobit-seed` | Decryption seed integer for NecroBit PRNG stream cipher | `0x14725836` |
| `--devirtualize-eaz` | De-virtualize Eazfuscator.NET VM methods and reconstruct assembly | `False` |
| `--eaz-out` | Destination path for devirtualized assembly binary | None |
| `--disasm-vm` | Disassemble Eazfuscator VM bytecode containers to formatted assembly | `False` |
| `--vm-table` | Custom VM opcode table JSON configuration file path | None |
| `--devirtualize-armdot` | De-virtualize ArmDot VM methods and reconstruct assembly | `False` |
| `--armdot-out` | Destination path for ArmDot devirtualized assembly binary | None |
| `--disasm-armdot` | Disassemble ArmDot VM bytecode containers to formatted assembly | `False` |
| `--armdot-table` | Custom ArmDot VM opcode table JSON configuration file path | None |
| `--demangle-babel` | Demangle Babel Obfuscator symbols and reconstruct cross-assembly dependency graph | `False` |
| `--babel-out` | Destination path for demangled assembly binary | None |
| `--export-depgraph` | Export inter-assembly dependency graph in JSON, Graphviz DOT, and Mermaid formats | `False` |
| `--custom-map` | Path to external Babel mapping file (XML, JSON, or text format) | None |
| `--strip-intellilock` | Strip IntelliLock licensing envelope and restore original managed assembly | `False` |
| `--intellilock-out` | Destination path for unlocked assembly binary | None |
| `--bypass-hwlock` | Generate synthetic hardware license to bypass hardware locking and trial expiration | `False` |
| `--gen-license` | Generate a valid synthetic perpetual master license (.lic) file | `False` |
| `--license-out` | Destination file path for generated synthetic license (.lic) | None |
| `--deflatten-deepsea` | De-flatten DeepSea control flow distortion and reconstruct clean CIL methods | `False` |
| `--deepsea-out` | Destination path for de-flattened assembly binary | None |
| `--export-ast` | Export high-level Abstract Syntax Tree (AST) in JSON format | `False` |
| `--export-cfg` | Export de-flattened Control Flow Graph (CFG) in Graphviz DOT format | `False` |
| `--anti-tamper` | Detect anti-tamper protections, decrypt CIL method bodies, and restore assembly | `False` |
| `--anti-tamper-out` | Destination path for anti-tamper restored assembly binary | None |
| `--dump-jit` | Path to in-memory JIT dump file (JSON or binary JITD stream) | None |
| `--anti-tamper-dir` | Directory path to extract restored assembly and CIL method payload binaries | None |
| `--heal-dump` | Heal anti-dump memory corruptions, restore PE headers, and unmap memory dump | `False` |
| `--heal-out` | Destination path for healed standalone PE binary | None |
| `--scylla-mode` | Enforce Scylla-compatible memory dump unmapping and CLR import reconstruction | `False` |
| `--anti-dump-dir` | Directory path to export healed binary, carved sections, and telemetry manifest | None |
| `--demux-native` | Demux embedded multi-architecture native binaries (x86, x64, ARM64) | `False` |
| `--demux-out` | Directory path to export demuxed native binaries organized by architecture | None |
| `--route-arch` | Target CPU architecture to simulate runtime loader routing for (e.g. x86, x64, arm64) | None |
| `--route-os` | Target OS platform for routing simulation (windows, linux, osx) | `windows` |
| `--gen-rules` | Synthesize automated threat hunting YARA and Sigma detection rules | `False` |
| `--gen-yara` | Synthesize and display YARA detection rules for target binary | `False` |
| `--gen-sigma` | Synthesize and display Sigma detection rules for target binary | `False` |
| `--rules-out` | Directory path to export synthesized YARA/Sigma rules and manifest | None |
| `--rule-level` | Threat rule granularity level (`specific`, `behavioral`, `hunt`) | `behavioral` |
| `--mixed-mode` | Execute native C++/CLI mixed-mode PE analysis and transition tracing | `False` |
| `--trace-transitions` | Trace native TLS callbacks, entry points, and export thunks | `False` |
| `--mixed-mode-out` | Output directory for carved native transition telemetry & manifest | None |
| `--cfg` | Generate CIL control flow graph and entropy analysis for assembly methods | `False` |
| `--cfg-token` | Target specific method token (e.g. 0x06000001) for CFG visualization | None |
| `--cfg-format` | Visualization export format (`mermaid`, `dot`, `svg`, `ascii`, `json`, `all`) | `all` |
| `--cfg-out` | Directory path to export CFG diagrams, vector SVG charts, and JSON manifests | None |
| `--baml` | Extract and decompile embedded WPF BAML UI resources to clean XAML | `False` |
| `--baml-out` | Directory path to export decompiled XAML documents and structured JSON manifest | None |
| `--baml-raw` | Also export raw binary .baml streams alongside decompiled .xaml files | `False` |
| `--rebuild` | Reconstruct damaged PE headers, realign sections, and repair standalone binary | `False` |
| `--rebuild-out` | Output destination path for rebuilt PE binary | None |
| `--unmap-dump` | Force process memory dump unmapping (realign RVA mapped sections to disk raw offsets) | `False` |
| `--verify` | Execute forensic payload verification & PE/CLR structural integrity audit | `False` |
| `--verify-against` | Reference binary path to perform bitwise byte divergence comparison against | None |
| `--expected-sha256` | Expected SHA-256 golden hash digest to enforce verification against | None |
| `--strict-pe` | Enforce strict PE header bounds and treat structural warnings as failures | `False` |
| `--fuzz` | Execute regression fuzzing campaign across target deobfuscation stages | `False` |
| `--fuzz-iterations` | Number of fuzzing iterations per target stage | `50` |
| `--fuzz-seed` | Master PRNG seed for deterministic fuzzing mutation generation | `1337` |
| `--fuzz-targets` | Comma-delimited list of fuzzing targets (`all`, `analyze`, `rebuild`, `verify`, `cfg`, `baml`, `mixed_mode`, `antidump`, `antitamper`, `rules`) | `all` |
| `--fuzz-timeout` | Maximum execution timeout in seconds per fuzz iteration | `3.0` |
| `--fuzz-out` | Output directory path for fuzz campaign reports, crashes, and regression ledger | None |
| `--gen-mutants` | Generate standalone synthetic mutated PE corpus and export to disk | `False` |
| `--mutant-count` | Number of synthetic mutated binary test cases to generate | `10` |
| `--batch [DIR]` | Execute batch forensic scanning across directory of PE binaries | None |
| `--batch-recursive` | Recursively scan subdirectories for candidate PE binaries | `False` |
| `--batch-workers` | Number of concurrent worker threads for directory scanning | `4` |
| `--batch-out` | Directory path to export batch reports (JSON, CSV, HTML dashboard) | None |
| `--batch-json` | Destination file path for batch scan JSON manifest report | None |
| `--batch-csv` | Destination file path for batch scan CSV summary report | None |
| `--batch-html` | Destination file path for self-contained offline HTML dashboard | None |
| `--batch-pattern` | File glob pattern filter for candidate binaries (e.g. `'*.exe;*.dll'`) | `'*'` |
| `--batch-timeout` | Per-file scanning execution timeout limit in seconds | `30.0` |
| `--batch-min-size` | Minimum file size threshold in bytes to include in scan | `0` |
| `--batch-max-size` | Maximum file size threshold in bytes to include in scan | `104857600` |
| `--native-aot` | Enable deep Native AOT & ReadyToRun (R2R) forensic inspection and report | `False` |
| `--r2r-disasm` | Disassemble precompiled native code methods from ReadyToRun runtime functions or AOT stubs | `False` |
| `--aot-symbols` | Extract and display recovered Native AOT symbols, exports, and Redhawk runtime helpers | `False` |
| `--native-aot-out` | Directory path to export parsed symbols (CSV), R2R sections, and disassembled methods (TXT/JSON) | None |
| `--native-aot-max-methods` | Maximum number of methods to disassemble in Native AOT / R2R analysis | `50` |
| `--dump-carver` | Enable kernel crash dump, minidump (MDMP), and process memory carving for residual .NET metadata | `False` |
| `--dump-extract-methods` | Carve residual CIL method bodies (Tiny & Fat format) directly from memory pages | `False` |
| `--dump-out` | Directory path to export carved assemblies, residual method JSON, strings, and metadata tables | None |
| `--dump-min-confidence` | Minimum confidence threshold [0.0 - 1.0] for assembly reconstruction | `0.5` |
| `--dump-max-methods` | Maximum residual CIL methods to carve from memory dump | `100` |
| `--decompiler-bridge` | Generate headless decompiler bridge scripts and synchronize symbols | `False` |
| `--bridge-engine` | Target disassembler engine (`ghidra`, `ida_pro`, `radare2`, `all`) | `all` |
| `--bridge-base-addr` | Base address for RVA rebasing (e.g. `0x400000` or `0x140000000`) | `0x400000` |
| `--bridge-out` | Directory path to export generated scripts, runner batch files, and symbols | None |
| `--bridge-min-confidence` | Minimum symbol confidence threshold [0.0 - 1.0] | `0.5` |
| `--diff` | Baseline binary path to compare against target assembly | None |
| `--diff-against` | Target comparison binary path (alternative to positional argument) | None |
| `--diff-engine` | Diff comparison engine (`metadata`, `bytecode`, `cfg`, `ast`, `all`) | `all` |
| `--diff-out` | Output directory path for diff reports (JSON, CSV, HTML dashboard, TXT) | None |
| `--diff-threshold` | Similarity alerting threshold [0.0 - 1.0] for divergence reporting | `0.8` |
| `--diff-html` | Output file path for standalone offline interactive HTML diff dashboard | None |
| `--diff-json` | Output structured diff telemetry in JSON format to stdout | `False` |
| `--jit-trace` | Analyze CLR runtime JIT compilation hooks and trace method bytecode | `False` |
| `--jit-trace-log` | Path to external JIT trace log file (JSON, CSV, JITD stream, or debugger log) | None |
| `--jit-out` | Directory path to export JIT trace summary, captured methods, and disassembly | None |
| `--jit-max-methods` | Maximum number of JIT methods to trace and capture | `500` |
| `--jit-tier` | Target JIT compilation optimization tier (`tier0`, `tier1`, `quick_jit`, `min_opts`, `all`) | `all` |
| `--jit-restore-pe` | Reconstruct and synthesize a standalone PE32 assembly containing captured JIT bytecode | `False` |
| `--bundle`, `--unbundle` | Extract and unbundle embedded assemblies and resources from .NET Single-File Host (AppHost) | `False` |
| `--bundle-out` | Directory path to carve and export unbundled single-file assemblies and manifest | None |
| `--bundle-filter` | Filter subset of bundled files to extract (`all`, `assemblies`, `native`, `symbols`, `configs`) | `all` |
| `--bundle-mount` | Mount single-file host and display virtual volume filesystem directory tree | `False` |
| `--bundle-no-decompress` | Skip decompressing compressed bundle payload streams | `False` |
| `-k, --key` | Master XOR key for overlay decryption | `'randomkey'` |
| `--format` | Output telemetry format (`text` or `json`) | `text` |
| `-v, --verbose` | Verbose section topology and entropy metrics | `False` |
| `--version` | Display engine version and exit | `v2.15.0` |


</details>

---

<span id="3-core-research-whitepapers"></span><span id="research-whitepapers"></span>
<details open>
<summary><h2 style="display:inline-block; margin:0;" id="3-core-research-whitepapers">📚 3. Core Research Whitepapers</h2></summary>

<br />

<table width="100%">
  <thead>
    <tr>
      <th width="22%"><nobr>Whitepaper Document</nobr></th>
      <th width="78%"><nobr>Technical Scope &amp; Forensic Highlights</nobr></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>🔬 <b><a href="./docs/whitepapers/DOTNET_OBFUSCATION_ARCHITECTURE_AND_CODE_ANALYSIS.md">DOTNET_<wbr>OBFUSCATION_<wbr>ARCHITECTURE_<wbr>AND_<wbr>CODE_<wbr>ANALYSIS.md</a></b></td>
      <td>CIL Bytecode &amp; CLI Metadata Streams, dnlib AST Parsing, ConfuserEx Pipeline Phases</td>
    </tr>
    <tr>
      <td>🔏 <b><a href="./docs/whitepapers/XORPACKER_AND_PE_OVERLAY_FORENSICS.md">XORPACKER_<wbr>AND_<wbr>PE_<wbr>OVERLAY_<wbr>FORENSICS.md</a></b></td>
      <td>Section Boundary Calculations, <code>***</code> Sentinel Seeking, Dynamic Key Inversion</td>
    </tr>
    <tr>
      <td>🛡️ <b><a href="./docs/whitepapers/CONFUSEREX_8_PROTECTIONS_DEEP_DIVE.md">CONFUSEREX_<wbr>8_<wbr>PROTECTIONS_<wbr>DEEP_<wbr>DIVE.md</a></b></td>
      <td>Control Flow Flattening, Anti-Tamper JIT In-Memory Decryption, Dynamic Ciphers</td>
    </tr>
    <tr>
      <td>🏢 <b><a href="./docs/whitepapers/ENTERPRISE_DOTNET_PROTECTORS_MATRIX.md">ENTERPRISE_<wbr>DOTNET_<wbr>PROTECTORS_<wbr>MATRIX.md</a></b></td>
      <td>Architectural Comparison of 8 COTS &amp; Open Source Packers (.NET Reactor, Eazfuscator, Babel)</td>
    </tr>
  </tbody>
</table>

</details>

---

<span id="4-repository-structure--source-code-breakdown"></span><span id="repository-structure"></span>
<details open>
<summary><h2 style="display:inline-block; margin:0;" id="4-repository-structure--source-code-breakdown">📁 4. Repository Structure &amp; Source Code Breakdown</h2></summary>

<br />

The project is structured into three modular tiers: the zero-dependency Python forensic engine package (`dotnet_deobfuscator/`), the authentic packed sample corpus (`samples/`), and the comprehensive automated test suite (`tests/`).

<span id="core-deobfuscator-package"></span>
### 📦 Core Deobfuscator Package (`dotnet_deobfuscator/`)

<table width="100%">
  <thead>
    <tr>
      <th width="26%"><nobr>Module / File</nobr></th>
      <th width="22%"><nobr>Component Role</nobr></th>
      <th width="52%"><nobr>1-Line Technical Scope &amp; Forensic Functionality</nobr></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>dotnet_deobfuscator/__init__.py</code></td>
      <td><b>Package Initializer</b></td>
      <td>Exports package metadata, semantic version (<code>v1.0.0</code>), and author attribution (<code>Maya Thorne</code>).</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/__main__.py</code></td>
      <td><b>CLI Entry Point</b></td>
      <td>Enables direct module execution via <code>python -m dotnet_deobfuscator</code>, delegating to <code>cli.main()</code>.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/cli.py</code></td>
      <td><b>CLI &amp; Telemetry Engine</b></td>
      <td>Implements argument parsing (<code>-o</code>, <code>-k</code>, <code>-v</code>, <code>--format</code>), exit codes, and text/JSON telemetry reporting.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/core.py</code></td>
      <td><b>Forensic Orchestrator</b></td>
      <td>Coordinates multi-pass static analysis: PE header validation, signature detection, and overlay decryption.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dotnet_analyzer.py</code></td>
      <td><b>Metadata &amp; Entropy Parser</b></td>
      <td>Computes Shannon byte entropy (0.0–8.0), locates CLI metadata streams (<code>#Strings</code>, <code>#US</code>, <code>#Blob</code>, <code>#GUID</code>, <code>#~</code>), and detects .NET runtime.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/pe_overlay.py</code></td>
      <td><b>PE Overlay &amp; XOR Carver</b></td>
      <td>Calculates physical PE section boundaries, carves overlay data past EOF, and inverts xorPacker two-stage dynamic XOR ciphers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/signatures.py</code></td>
      <td><b>Heuristic Signatures</b></td>
      <td>Houses heuristic byte and string signatures for 8 major .NET packers (ConfuserEx, .NET Reactor, Eazfuscator, Babel, etc.).</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/costura.py</code></td>
      <td><b>Costura Unpacker Engine</b></td>
      <td>Extracts and decompresses embedded assemblies (.compressed) via DeflateStream inversion, path traversal sanitization, and SHA-256 validation.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/confuserex_constants.py</code></td>
      <td><b>ConfuserEx Constants Decryptor</b></td>
      <td>Decodes string constants (LCG/XorShift PRNG stream ciphers, key schedules), parses 7-bit length encoded tables, and manages auto key recovery.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/confuserex.py</code></td>
      <td><b>ConfuserEx Unpacker Engine</b></td>
      <td>Identifies ConfuserEx protections, unpacks encrypted resource containers, and handles CLI resource catalogs with safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/reactor.py</code></td>
      <td><b>.NET Reactor Unpacker Engine</b></td>
      <td>Strips native wrapper envelopes, decrypts NecroBit token-keyed CIL method bodies, restores Tiny/Fat headers, and synthesizes .necro sections.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/eazfuscator_vm.py</code></td>
      <td><b>Eazfuscator VM Disassembler</b></td>
      <td>Decodes proprietary Eazfuscator.NET VM bytecodes, supports dynamic/heuristic opcode table mapping, and devirtualizes AST into ECMA-335 CIL.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/eazfuscator.py</code></td>
      <td><b>Eazfuscator Unpacker Engine</b></td>
      <td>Carves embedded VM bytecode containers across PE sections and overlay, synthesizes aligned .eazvm sections, and extracts devirtualized assemblies.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/babel_demangler.py</code></td>
      <td><b>Babel Demangler Engine</b></td>
      <td>Cleans Unicode unprintable characters, infers interface methods, restores getter/setters, parses BabelMap files, and builds inter-assembly DAGs.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/babel.py</code></td>
      <td><b>Babel Unpacker Engine</b></td>
      <td>Identifies Babel signatures, carves and decompresses embedded merged satellite assemblies, and manages safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/armdot_vm.py</code></td>
      <td><b>ArmDot VM Disassembler &amp; Stack Emulator</b></td>
      <td>Disassembles proprietary ArmDot VM bytecodes, supports dynamic opcode table mapping, and tracks abstract evaluation stack balance.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/armdot_rebuilder.py</code></td>
      <td><b>ArmDot CIL Method Rebuilder</b></td>
      <td>Translates ArmDot VM instructions into ECMA-335 CIL, resolves short/long branch relative fixups, and builds CorILMethod Tiny/Fat headers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/armdot.py</code></td>
      <td><b>ArmDot Unpacker Engine</b></td>
      <td>Scans ArmDot markers, carves embedded VM containers, decrypts LCG/XOR bytecodes, synthesizes .armdot PE sections, and extracts assemblies.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/intellilock_models.py</code></td>
      <td><b>IntelliLock Models &amp; Licensing</b></td>
      <td>Models licensing state, bitmask restrictions, deterministic hardware fingerprint profiles, and binary .lic container generators.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/intellilock.py</code></td>
      <td><b>IntelliLock Unpacker Engine</b></td>
      <td>Carves enveloped assemblies, inverts LCG/XOR ciphers, defeats hardware locking, restores Cor20Header EntryPoints, and manages safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/deepsea_models.py</code></td>
      <td><b>DeepSea Models &amp; AST</b></td>
      <td>Encapsulates CIL instruction definitions, basic block flow models, Control Flow Graph representations, and structured AST nodes.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/deepsea_deflattener.py</code></td>
      <td><b>Control Flow De-flattener</b></td>
      <td>Disassembles CIL bytecodes, prunes opaque predicates, resolves state-machine switch loops, reorders basic blocks, and emits clean CIL.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/deepsea.py</code></td>
      <td><b>DeepSea Unpacker Engine</b></td>
      <td>Scans DeepSea signatures, de-flattens CIL method bodies, injects .deepsea PE sections, and manages safe directory artifact exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/antitamper_models.py</code></td>
      <td><b>Anti-Tamper Models &amp; Headers</b></td>
      <td>Models ECMA-335 CorILMethod Tiny/Fat headers, JIT method records, and anti-tamper detection indicators.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/antitamper_jit.py</code></td>
      <td><b>JIT Dumper &amp; Decryptor Engine</b></td>
      <td>Parses and serializes CIL method headers, executes LCG/XOR stream ciphers, and ingests in-memory/JSON/binary JIT dumps.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/antitamper.py</code></td>
      <td><b>Anti-Tamper Unpacker &amp; Restorer</b></td>
      <td>Detects corrupted metadata streams (#~/#-), restores method bodies, synthesizes .antitamper sections, and manages safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/antidump_models.py</code></td>
      <td><b>Anti-Dump Models &amp; Enums</b></td>
      <td>Models anti-dump techniques, dump sources, normalized sections, and synthesized CLR bootstrap import descriptors.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/antidump_healer.py</code></td>
      <td><b>Anti-Dump PE Header Healer</b></td>
      <td>Heals erased DOS/PE headers, unmaps Scylla memory dumps, scans BSJB metadata, recovers Cor20Headers, and reconstructs CLR IAT imports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/antidump.py</code></td>
      <td><b>Anti-Dump Unpacker Engine</b></td>
      <td>Detects anti-dump corruptions, normalizes memory dumps, and manages safe directory exports with path traversal defenses.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/native_demuxer_models.py</code></td>
      <td><b>Native Demuxer Models &amp; Enums</b></td>
      <td>Encapsulates TargetArchitecture, TargetOS, BinaryFormat, DemuxSource enums, and platform routing telemetry data structures.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/native_demuxer_engine.py</code></td>
      <td><b>Multi-Arch Inspection &amp; Router Engine</b></td>
      <td>Inspects PE/ELF/Mach-O machine architectures, carves compressed/raw native binaries, wipes memory buffers, and simulates platform routing.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/unpackers/native_demuxer.py</code></td>
      <td><b>Native Demuxer Unpacker Facade</b></td>
      <td>High-level orchestrator for static discovery, architecture mismatch detection, and organized directory export with routing manifests.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/analysis_collector.py</code></td>
      <td><b>Forensic Telemetry Aggregator</b></td>
      <td>Aggregates forensic telemetry into unified analysis report dictionaries while maintaining modular code boundaries.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/report_formatter.py</code></td>
      <td><b>Forensic Telemetry Formatter</b></td>
      <td>Formats human-readable multi-protector diagnostic text reports with strict separation of concerns and modular limits.</td>
    </tr>

    <tr>
      <td><code>dotnet_deobfuscator/pe_rebuilder.py</code></td>
      <td><b>PE Header &amp; Section Rebuilder</b></td>
      <td>Reconstructs damaged PE headers, realigns section tables, unmaps process memory dumps, and recovers CLR Cor20Header descriptors.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/payload_verifier.py</code></td>
      <td><b>Payload Verifier &amp; Test Harness</b></td>
      <td>Performs bitwise byte-level divergence comparison, cryptographic hashing (SHA-256/SHA-1/MD5), and PE/CLR structural integrity regression auditing.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/rules/models.py</code></td>
      <td><b>Threat Rule Models &amp; Enums</b></td>
      <td>Encapsulates YARARule, SigmaRule, RuleGranularity, RuleSeverity, ExtractedThreatFeatures, and generation results.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/rules/feature_extractor.py</code></td>
      <td><b>Threat Feature Extractor</b></td>
      <td>Extracts binary hashes, PE structure, imphash, section entropy, CIL bytecodes, and zeroes scratchpad buffers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/rules/yara_synthesizer.py</code></td>
      <td><b>Dynamic YARA Synthesizer</b></td>
      <td>Generates syntactically pristine YARA v4+ rules across Specific, Behavioral, and Threat Hunting tiers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/rules/sigma_synthesizer.py</code></td>
      <td><b>Dynamic Sigma Synthesizer</b></td>
      <td>Emits spec-compliant Sigma v2 YAML rules with deterministic UUID v5 identifiers and MITRE ATT&CK tags.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/rules/rule_engine.py</code></td>
      <td><b>Threat Rule Engine Facade</b></td>
      <td>Orchestrates feature extraction, rule synthesis, and safe directory exports with path traversal defenses.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/mixed_mode/models.py</code></td>
      <td><b>Mixed-Mode Models &amp; Enums</b></td>
      <td>Encapsulates MixedModeType, VTFixupSlot, VTFixupTable, CILNativeTransition, and telemetry manifest models.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/mixed_mode/vtfixup_parser.py</code></td>
      <td><b>VTable Fixup Table Parser</b></td>
      <td>Decodes IMAGE_COR_VTABLEFIXUP headers, parses 32/64-bit slot tokens, and zeroes scratchpad buffers via ctypes.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/mixed_mode/transition_tracer.py</code></td>
      <td><b>CIL-Native Boundary Tracer</b></td>
      <td>Traces unmanaged entrypoint bootstrap jumps, native TLS callbacks, export thunk hops, and P/Invoke boundaries.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/mixed_mode/analyzer.py</code></td>
      <td><b>Mixed-Mode Analyzer &amp; Exporter</b></td>
      <td>Orchestrates PE/Cor20 inspection, threat risk scoring, and safe directory exports with path traversal defenses.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/fuzzing/models.py</code></td>
      <td><b>Fuzzing Data Models &amp; Ledger</b></td>
      <td>Encapsulates MutationStrategy, FuzzTarget, CrashSeverity, telemetry records, and persistent JSON RegressionLedger.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/fuzzing/generator.py</code></td>
      <td><b>Synthetic Binary Generator &amp; Mutator</b></td>
      <td>Constructs structural baseline PE assemblies and applies 11 deterministic structural mutation operators.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/fuzzing/harness.py</code></td>
      <td><b>Regression Fuzzing Harness &amp; Exporter</b></td>
      <td>Executes sandboxed fuzzing across pipeline targets with crash triage, timeout enforcement, and bundle export.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/batch/models.py</code></td>
      <td><b>Batch Scan Models &amp; Sanitizers</b></td>
      <td>Encapsulates FileScanStatus, ThreatLevel, BatchScanOptions, SingleScanResult, summary metrics, and safe path traversal defenses.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/batch/scanner.py</code></td>
      <td><b>Multi-Threaded PE Directory Scanner</b></td>
      <td>Discovers binaries with glob/size filtering, performs fast MZ/PE pre-filtering, and executes concurrent thread pool inspection with per-file timeouts.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/batch/reporter.py</code></td>
      <td><b>Multi-Format Batch Reporter</b></td>
      <td>Renders structured terminal console tables, CSV data exports, JSON manifests, and self-contained offline HTML dashboards with zero external CDN dependencies.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/batch/engine.py</code></td>
      <td><b>Batch Forensic Engine Facade</b></td>
      <td>Coordinates directory discovery, multi-threaded worker pools, payload extraction, and report generation workflows.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/native_aot/models.py</code></td>
      <td><b>Native AOT &amp; R2R Models</b></td>
      <td>Encapsulates CompilationType, R2RSectionType, AOTVersion, TargetArchitecture, R2R headers/sections, and security sanitizers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/native_aot/r2r_parser.py</code></td>
      <td><b>ReadyToRun Header &amp; Section Parser</b></td>
      <td>Parses ReadyToRun headers, compiler identifiers, RUNTIME_FUNCTION arrays, and MethodDef entrypoint tables.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/native_aot/aot_symbol_parser.py</code></td>
      <td><b>Native AOT Symbol &amp; Helper Parser</b></td>
      <td>Scans Redhawk (Rhp*) runtime helpers, infers .NET 7/8/9 generation, and demangles C-style symbols into clean .NET names.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/native_aot/disassembler.py</code></td>
      <td><b>Native Machine Code Disassembler</b></td>
      <td>Decodes x64/x86 native machine instructions, resolves runtime helper call targets, and constructs basic block topologies.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/native_aot/analyzer.py</code></td>
      <td><b>Native AOT Forensic Analyzer Facade</b></td>
      <td>Orchestrates PE inspection, R2R/AOT classification, method disassembly, risk scoring, and safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dump_carver/models.py</code></td>
      <td><b>Dump Carver Models &amp; Structures</b></td>
      <td>Encapsulates DumpSourceType, CarveStrategy, MemorySegment, CarvedCILMethod, and AssemblyReconstructionResult.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dump_carver/minidump_parser.py</code></td>
      <td><b>Minidump &amp; Memory Stream Parser</b></td>
      <td>Parses MDMP directory streams, Memory64List streams, memory page permissions, and zeroes scratchpad buffers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dump_carver/method_carver.py</code></td>
      <td><b>CIL Method Memory Carver</b></td>
      <td>Scans process memory pages for ECMA-335 CorILMethod Tiny &amp; Fat method headers and extracts bytecode bodies.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dump_carver/bsjb_carver.py</code></td>
      <td><b>BSJB CLI Metadata Stream Carver</b></td>
      <td>Locates BSJB magic signatures in unmapped memory, parses stream headers, and extracts metadata heaps.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dump_carver/reconstructor.py</code></td>
      <td><b>PE Assembly Reconstructor</b></td>
      <td>Reconstructs valid PE files from carved memory streams, realigns sections, synthesizes Cor20 headers, and repairs tables.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/dump_carver/analyzer.py</code></td>
      <td><b>Dump Carver Forensic Facade</b></td>
      <td>Orchestrates dump parsing, method carving, assembly reconstruction, risk scoring, and safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/decompiler_bridge/models.py</code></td>
      <td><b>Decompiler Bridge Models &amp; Enums</b></td>
      <td>Encapsulates DecompilerEngine, SymbolType, CommentType, DecompilerSymbol, DecompilerComment, and telemetry results.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/decompiler_bridge/ghidra_bridge.py</code></td>
      <td><b>Ghidra Headless Bridge Generator</b></td>
      <td>Synthesizes Python 3/Jython FlatProgramAPI scripts for labels, functions, plate/EOL comments, bookmarks, and headless runners.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/decompiler_bridge/ida_bridge.py</code></td>
      <td><b>IDA Pro Headless Bridge Generator</b></td>
      <td>Synthesizes IDAPython 7.x–9.x scripts with dynamic rebasing, ida_name, ida_funcs, ida_bytes, idc bookmarks, and batch runners.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/decompiler_bridge/radare2_bridge.py</code></td>
      <td><b>Radare2 Headless Bridge Generator</b></td>
      <td>Synthesizes radare2 r2 scripts (flags, functions, comments) and cross-platform headless execution scripts.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/decompiler_bridge/symbol_sync.py</code></td>
      <td><b>Multi-Engine Symbol Synchronizer</b></td>
      <td>Correlates PE headers, NecroBit methods, VM containers, Babel demangled symbols, mixed-mode VTFixups, Native AOT helpers, and memory carved methods.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/decompiler_bridge/analyzer.py</code></td>
      <td><b>Decompiler Bridge Engine Facade</b></td>
      <td>Orchestrates multi-engine script generation, symbol synchronization, telemetry aggregation, and safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/models.py</code></td>
      <td><b>Binary Diffing Models &amp; Structures</b></td>
      <td>Encapsulates DiffCategory, ChangeType, DiffEngine, ObfuscationImpact enums, SectionDiff, MethodDiff, and telemetry results.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/metadata_differ.py</code></td>
      <td><b>PE &amp; CLI Metadata Differ</b></td>
      <td>Measures section alignment shifts, entropy deltas, injected protector sections (.necro, .eazvm, .armdot), and BSJB metadata drift.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/bytecode_differ.py</code></td>
      <td><b>CIL Bytecode Sequence Differ</b></td>
      <td>Computes opcode normalization, multiset Jaccard similarity, normalized Levenshtein distance, and 3-gram Sørensen-Dice similarity.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/cfg_differ.py</code></td>
      <td><b>Control Flow Graph (CFG) Differ</b></td>
      <td>Builds basic block topologies, matches block signatures, measures McCabe complexity variance, and identifies flattening dispatchers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/ast_differ.py</code></td>
      <td><b>AST Flow Graph Differ</b></td>
      <td>Abstracts statement-level control structures, compares loop topologies, and detects dead-code injection and opaque predicates.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/html_reporter.py</code></td>
      <td><b>Visual HTML Diff Dashboard Generator</b></td>
      <td>Renders self-contained offline dark-themed HTML reports with live filtering, metrics cards, side-by-side comparison tables, and XSS escaping.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/diffing/comparator.py</code></td>
      <td><b>Binary Diff Engine Facade</b></td>
      <td>Pairs assembly methods, computes composite weighted similarity, classifies obfuscation impact, formats text diffs, and manages directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/jit_tracer/models.py</code></td>
      <td><b>JIT Tracer Models &amp; Enums</b></td>
      <td>Encapsulates JITHookType, JITExecutionState, CaptureSource, OptimizationTier, CipherFamily, and telemetry models.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/jit_tracer/hook_detector.py</code></td>
      <td><b>CLR JIT Hook Detector</b></td>
      <td>Scans clrjit/mscorjit exports and imports, identifies detour patterns (indirect jumps, trampolines), and flags protector hooks.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/jit_tracer/emulator.py</code></td>
      <td><b>Virtual JIT Compiler Emulator</b></td>
      <td>Emulates ICorJitCompiler::compileMethod, decodes CorILMethod Tiny/Fat headers, validates opcodes, and inverts LCG/XOR ciphers.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/jit_tracer/trace_parser.py</code></td>
      <td><b>Multi-Format JIT Trace Parser</b></td>
      <td>Ingests structured JSON, CSV, proprietary binary JITD streams, and text debugger log traces.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/jit_tracer/assembly_restorer.py</code></td>
      <td><b>JIT Assembly Restorer</b></td>
      <td>Injects recovered CIL methods into PE .jitcapt section, synthesizes minimal PE32 wrappers, and generates CIL disassembly.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/jit_tracer/analyzer.py</code></td>
      <td><b>JIT Tracer Engine Facade</b></td>
      <td>Coordinates static PE inspection, virtual emulation, trace log ingestion, bytecode recovery, and safe directory exports.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/bundle/models.py</code></td>
      <td><b>Single-File Bundle Data Models</b></td>
      <td>Defines BundleFileType, BundleVersion, CompressionKind, SuperPackerKind, BundleEntry, and safe path traversal defenses.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/bundle/marker_scanner.py</code></td>
      <td><b>Bundle Marker &amp; Superpacker Scanner</b></td>
      <td>Locates 32-byte Microsoft BundleMarker, resolves 64-bit header offsets, and identifies Warp, BoxedApp, Enigma signatures.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/bundle/header_parser.py</code></td>
      <td><b>BundleHeader Parser &amp; Serializer</b></td>
      <td>Decodes BundleHeader v1, v2, v6 (.NET 6/7/8/9/10), 7-bit encoded integers (LEB128), and embedded manifest entries.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/bundle/decompressor.py</code></td>
      <td><b>Stream Decompressor &amp; Buffer Zeroizer</b></td>
      <td>Decompresses payload streams across raw Deflate, standard Zlib, Brotli, and LZMA with memory zeroizing.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/bundle/virtual_volume.py</code></td>
      <td><b>Virtual Volume Mount &amp; Hierarchy</b></td>
      <td>In-memory filesystem mounting, directory tree navigation, ASCII tree rendering, and category-based entry filtering.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/bundle/unbundler.py</code></td>
      <td><b>Single-File Bundle Engine Facade</b></td>
      <td>Orchestrates bundle detection, virtual volume mounting, full payload carving, manifest generation, and directory export.</td>
    </tr>
  </tbody>
</table>

<span id="forensic-sample-corpus"></span>
### 🧪 Forensic Sample Corpus (`samples/`)

<table width="100%">
  <thead>
    <tr>
      <th width="26%"><nobr>Sample File</nobr></th>
      <th width="22%"><nobr>File Type</nobr></th>
      <th width="52%"><nobr>1-Line Technical Scope &amp; Forensic Functionality</nobr></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>samples/xorPacker_packed_sample.exe</code></td>
      <td><b>Packed PE Binary</b></td>
      <td>Real-world test sample packed with xorPacker containing dynamic XOR encrypted payload in overlay.</td>
    </tr>
    <tr>
      <td><code>samples/xorStub_sample.exe</code></td>
      <td><b>Dropper Stub Binary</b></td>
      <td>Native loader stub featuring embedded <code>***</code> sentinel delimiter and static decryption logic.</td>
    </tr>
    <tr>
      <td><code>samples/unpacked_output.bin</code></td>
      <td><b>Decrypted Ground Truth</b></td>
      <td>Reference extracted raw payload used for automated regression testing and bit-level verification.</td>
    </tr>
  </tbody>
</table>

<span id="test-validation-suite"></span>
### 🔬 Test &amp; Validation Suite (`tests/`)

<table width="100%">
  <thead>
    <tr>
      <th width="26%"><nobr>Test Module</nobr></th>
      <th width="22%"><nobr>Test Domain</nobr></th>
      <th width="52%"><nobr>1-Line Technical Scope &amp; Forensic Functionality</nobr></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>tests/test_cli.py</code></td>
      <td><b>CLI Integration Test</b></td>
      <td>Validates command-line argument parsing, default flags, and text/JSON telemetry report generation.</td>
    </tr>
    <tr>
      <td><code>tests/test_dotnet_analyzer.py</code></td>
      <td><b>Metadata &amp; Signatures Test</b></td>
      <td>Tests Shannon entropy calculation extremes (0.0 vs &gt;7.9) and heuristic protector signature detection.</td>
    </tr>
    <tr>
      <td><code>tests/test_pe_overlay.py</code></td>
      <td><b>Overlay &amp; Unpacker Test</b></td>
      <td>Validates XOR cipher mathematical symmetry, mock payload generation, and two-stage key inversion.</td>
    </tr>
    <tr>
      <td><code>tests/test_costura_unpacker.py</code></td>
      <td><b>Costura Unpacker Test</b></td>
      <td>Validates DeflateStream decompression, CLI metadata/manifest resource parsing, filename sanitization, and directory extraction.</td>
    </tr>
    <tr>
      <td><code>tests/test_confuserex_unpacker.py</code></td>
      <td><b>ConfuserEx Unpacker Test</b></td>
      <td>Validates ConfuserEx signature detection, PRNG string decryption, encrypted resource parsing, bounds checks, and CLI string dumping.</td>
    </tr>
    <tr>
      <td><code>tests/test_pe_rebuilder.py</code></td>
      <td><b>PE Rebuilder Test</b></td>
      <td>Validates PE anomaly detection, DOS/NT header repairs, section table realignment, memory dump unmapping, Cor20Header recovery, and CLI commands.</td>
    </tr>
    <tr>
      <td><code>tests/test_payload_verifier.py</code></td>
      <td><b>Payload Verifier Test Harness</b></td>
      <td>Validates bitwise divergence pinpointing, cryptographic hashes (SHA-256/SHA-1/MD5), PE/CLR section structure verification, directory batch auditing, and CLI --verify flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_reactor_unpacker.py</code></td>
      <td><b>.NET Reactor Unpacker Test</b></td>
      <td>Validates native stub envelope carving, XOR/compressed stream de-enveloping, NecroBit token decryption, CorILMethod parsing, and .necro section reconstruction.</td>
    </tr>
    <tr>
      <td><code>tests/test_eazfuscator_unpacker.py</code></td>
      <td><b>Eazfuscator Unpacker Test</b></td>
      <td>Validates opcode table inference, bytecode disassembly, CIL Tiny/Fat translation, branch relative fixups, .eazvm PE section injection, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_babel_unpacker.py</code></td>
      <td><b>Babel Unpacker &amp; Demangler Test</b></td>
      <td>Validates Unicode cleaning, interface inference, getter/setter restoration, DAG topological sorting, cycle detection, DOT/Mermaid export, merged PE carving, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_armdot_unpacker.py</code></td>
      <td><b>ArmDot VM Unpacker &amp; Rebuilder Test</b></td>
      <td>Validates VM opcode deduction, bytecode disassembly, abstract stack balance, relative branch resolution, CorILMethod Tiny/Fat emission, and PE section injection.</td>
    </tr>
    <tr>
      <td><code>tests/test_intellilock_unpacker.py</code></td>
      <td><b>IntelliLock Unpacker Test</b></td>
      <td>Validates hardware ID hashing, perpetual license generation, LCG/XOR stream decryption, container carving, PE header restoration, and directory safety.</td>
    </tr>
    <tr>
      <td><code>tests/test_deepsea_unpacker.py</code></td>
      <td><b>DeepSea De-flattener &amp; AST Test</b></td>
      <td>Validates CIL instruction disassembly, opaque predicate pruning, state machine loop de-flattening, multi-pass branch offset calculation, AST reconstruction, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_antitamper_unpacker.py</code></td>
      <td><b>Anti-Tamper &amp; JIT Dumper Test</b></td>
      <td>Validates CorILMethod Tiny/Fat serialization, PRNG stream decryption, JIT dumper ingestion (JSON/binary stream), anti-tamper heuristics, PE section synthesis, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_antidump_healer.py</code></td>
      <td><b>Anti-Dump Healer &amp; Scylla Normalizer Test</b></td>
      <td>Validates DOS/NT header repairs, Scylla dump unmapping, BSJB scanning, Cor20Header recovery, IAT synthesis, and directory exports.</td>
    </tr>
    <tr>
      <td><code>tests/test_native_demuxer.py</code></td>
      <td><b>Native Multi-Arch Demuxer &amp; Platform Router Test</b></td>
      <td>Validates PE/ELF/Mach-O machine parsing, buffer zeroization, DeflateStream decompression, multi-arch carving, spoofing detection, and platform loader routing.</td>
    </tr>
    <tr>
      <td><code>tests/test_rule_generator.py</code></td>
      <td><b>Automated Threat Hunting Rule Generator Test</b></td>
      <td>Validates feature extraction, PE imphash, Shannon entropy, Specific/Behavioral/Hunt YARA rules, Sigma YAML and UUID v5 validation, and directory exports.</td>
    </tr>
    <tr>
      <td><code>tests/test_mixed_mode.py</code></td>
      <td><b>Native Mixed-Mode PE &amp; Transition Tracer Test</b></td>
      <td>Validates pure managed/native/IJWH classification, native entry points, 32/64-bit VTFixups, unmanaged export bridges, TLS callbacks, risk scoring, safe exports, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_fuzzing_harness.py</code></td>
      <td><b>Regression Fuzzing Harness &amp; Mutator Test</b></td>
      <td>Validates baseline PE generation, 11 mutation operators, sandboxed target triage, crash bundling, timeout detection, ledger persistence, path traversal defense, and CLI options.</td>
    </tr>
    <tr>
      <td><code>tests/test_dump_carver.py</code></td>
      <td><b>Dump Carver &amp; Memory Reconstructor Test</b></td>
      <td>Validates MDMP parsing, raw memory carving, BSJB stream discovery, Tiny/Fat method body extraction, PE synthesis, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_decompiler_bridge.py</code></td>
      <td><b>Decompiler Headless Bridge &amp; Symbol Sync Test</b></td>
      <td>Validates Ghidra, IDA Pro, and Radare2 script generation, syntax compilation, symbol synchronization, directory exports, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_binary_diffing.py</code></td>
      <td><b>Binary Diffing &amp; AST Flow Test</b></td>
      <td>Validates PE structural differ, CIL opcode sequence alignment, CFG topology comparison, AST flow matching, HTML report escaping, directory exports, and CLI flags.</td>
    </tr>
    <tr>
      <td><code>tests/test_jit_tracer.py</code></td>
      <td><b>CLR JIT Tracer &amp; Bytecode Capture Test</b></td>
      <td>Validates JIT hook detector, virtual JIT compiler emulation, LCG/XOR decryption, trace log parsers, PE assembly restorer, directory exports, and CLI flags.</td>
    </tr>
  </tbody>
</table>

</details>

---

<span id="5-license--security-research-attribution"></span><span id="license-attribution"></span>
<details>
<summary><h2 style="display:inline-block; margin:0;" id="5-license--security-research-attribution">📜 5. License &amp; Security Research Attribution</h2></summary>

<br />

This project is licensed under the **Maya Thorne Systems &amp; Security Research License (MT-SRL)**. Copyright © 2026 Maya Thorne. All rights reserved. Published strictly for academic analysis, vulnerability research, and systems engineering.

</details>
