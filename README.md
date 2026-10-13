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
[![Protector Signatures](https://img.shields.io/badge/Signatures-8_Major_Packers-f59e0b.svg)](#3-core-research-whitepapers)
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
```

<span id="cli-options-matrix"></span>
### CLI Options Matrix
| Flag | Description | Default |
| :--- | :--- | :---: |
| `target` | Path to target executable (`.exe` / `.dll`) | *Required* |
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
| `--rebuild` | Reconstruct damaged PE headers, realign sections, and repair standalone binary | `False` |
| `--rebuild-out` | Output destination path for rebuilt PE binary | None |
| `--unmap-dump` | Force process memory dump unmapping (realign RVA mapped sections to disk raw offsets) | `False` |
| `--verify` | Execute forensic payload verification & PE/CLR structural integrity audit | `False` |
| `--verify-against` | Reference binary path to perform bitwise byte divergence comparison against | None |
| `--expected-sha256` | Expected SHA-256 golden hash digest to enforce verification against | None |
| `--strict-pe` | Enforce strict PE header bounds and treat structural warnings as failures | `False` |
| `-k, --key` | Master XOR key for overlay decryption | `'randomkey'` |
| `--format` | Output telemetry format (`text` or `json`) | `text` |
| `-v, --verbose` | Verbose section topology and entropy metrics | `False` |
| `--version` | Display engine version and exit | `v1.8.0` |

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
      <td><code>dotnet_deobfuscator/pe_rebuilder.py</code></td>
      <td><b>PE Header &amp; Section Rebuilder</b></td>
      <td>Reconstructs damaged PE headers, realigns section tables, unmaps process memory dumps, and recovers CLR Cor20Header descriptors.</td>
    </tr>
    <tr>
      <td><code>dotnet_deobfuscator/payload_verifier.py</code></td>
      <td><b>Payload Verifier &amp; Test Harness</b></td>
      <td>Performs bitwise byte-level divergence comparison, cryptographic hashing (SHA-256/SHA-1/MD5), and PE/CLR structural integrity regression auditing.</td>
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
