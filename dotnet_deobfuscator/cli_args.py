"""
Command-Line Argument Parser Definition for dotnet-packer-forensics.
Engineered & Audited by Maya Thorne.
"""

import argparse
from . import __version__


def build_parser() -> argparse.ArgumentParser:
    """Builds and returns command-line argument parser for dotnet-packer-re."""
    parser = argparse.ArgumentParser(
        prog="dotnet-packer-re",
        description="Static Forensic Unpacker & Obfuscation Analyzer for .NET & PE Binaries.",
    )
    parser.add_argument("target", help="Path to target executable (.exe/.dll)")
    parser.add_argument(
        "-o", "--output", help="Write decrypted unpacked payload to specified file or directory"
    )
    parser.add_argument(
        "-d", "--unpack-dir", help="Directory path to extract all embedded Costura & ConfuserEx assemblies"
    )
    parser.add_argument(
        "-k",
        "--key",
        default="randomkey",
        help="Master key for overlay decryption (default: 'randomkey')",
    )
    parser.add_argument(
        "--dump-strings",
        action="store_true",
        help="Extract and dump decrypted ConfuserEx constants and literal strings",
    )
    parser.add_argument(
        "--rebuild", action="store_true",
        help="Reconstruct damaged PE headers, realign sections, and repair standalone binary",
    )
    parser.add_argument("--rebuild-out", help="Output destination path for rebuilt PE binary")
    parser.add_argument(
        "--unmap-dump", action="store_true",
        help="Force process memory dump unmapping (realign RVA mapped sections to disk raw offsets)",
    )
    parser.add_argument(
        "--strip-envelope", action="store_true",
        help="Strip native wrapper envelope and carve encapsulated managed .NET assembly",
    )
    parser.add_argument("--envelope-out", help="Destination path for de-enveloped managed assembly binary")
    parser.add_argument(
        "--restore-necrobit", action="store_true",
        help="Decrypt NecroBit CIL method bodies and reconstruct deobfuscated assembly",
    )
    parser.add_argument("--necrobit-out", help="Destination path for NecroBit restored assembly binary")
    parser.add_argument(
        "--necrobit-seed", type=lambda x: int(x, 0), default=0x14725836,
        help="Decryption seed integer for NecroBit PRNG stream cipher (default: 0x14725836)",
    )
    parser.add_argument(
        "--devirtualize-eaz", action="store_true",
        help="De-virtualize Eazfuscator.NET VM methods and reconstruct assembly",
    )
    parser.add_argument("--eaz-out", help="Destination path for devirtualized assembly binary")
    parser.add_argument(
        "--disasm-vm", action="store_true",
        help="Disassemble Eazfuscator VM bytecode containers to formatted assembly",
    )
    parser.add_argument("--vm-table", help="Custom VM opcode table JSON configuration file path")
    parser.add_argument(
        "--devirtualize-armdot", action="store_true",
        help="De-virtualize ArmDot VM methods and reconstruct assembly",
    )
    parser.add_argument("--armdot-out", help="Destination path for ArmDot devirtualized assembly binary")
    parser.add_argument(
        "--disasm-armdot", action="store_true",
        help="Disassemble ArmDot VM bytecode containers to formatted assembly",
    )
    parser.add_argument("--armdot-table", help="Custom ArmDot VM opcode table JSON configuration file path")
    parser.add_argument(
        "--demangle-babel", action="store_true",
        help="Demangle Babel Obfuscator symbols and reconstruct dependency graph",
    )
    parser.add_argument("--babel-out", help="Destination path for demangled assembly binary")
    parser.add_argument(
        "--export-depgraph", action="store_true",
        help="Export inter-assembly dependency graph in JSON, Graphviz DOT, and Mermaid formats",
    )
    parser.add_argument("--custom-map", help="Path to external Babel mapping file (XML, JSON, or text format)")
    parser.add_argument(
        "--strip-intellilock", action="store_true",
        help="Strip IntelliLock licensing envelope and restore original managed assembly",
    )
    parser.add_argument("--intellilock-out", help="Destination path for unlocked assembly binary")
    parser.add_argument(
        "--bypass-hwlock", action="store_true",
        help="Generate synthetic hardware license to bypass hardware locking and trial expiration",
    )
    parser.add_argument(
        "--gen-license", action="store_true",
        help="Generate a valid synthetic perpetual master license (.lic) file",
    )
    parser.add_argument("--license-out", help="Destination file path for generated synthetic license (.lic)")
    parser.add_argument(
        "--deflatten-deepsea", action="store_true",
        help="De-flatten DeepSea control flow distortion and reconstruct clean CIL methods",
    )
    parser.add_argument("--deepsea-out", help="Destination path for de-flattened assembly binary")
    parser.add_argument("--export-ast", action="store_true", help="Export high-level Abstract Syntax Tree (AST) in JSON format")
    parser.add_argument("--export-cfg", action="store_true", help="Export de-flattened Control Flow Graph (CFG) in Graphviz DOT format")
    parser.add_argument(
        "--anti-tamper",
        action="store_true",
        help="Restore anti-tampered assembly by recovering decrypted CIL method bodies",
    )
    parser.add_argument(
        "--anti-tamper-out",
        help="Destination path for restored anti-tamper assembly binary",
    )
    parser.add_argument(
        "--dump-jit",
        help="Path to captured in-memory JIT dump file (JSON) to ingest",
    )
    parser.add_argument(
        "--anti-tamper-dir",
        help="Directory path to export unpacked methods, CIL bytecodes, and manifest",
    )
    parser.add_argument(
        "--heal-dump",
        action="store_true",
        help="Heal anti-dump memory corruptions, restore PE headers, and unmap memory dump",
    )
    parser.add_argument(
        "--heal-out",
        help="Destination path for healed standalone PE binary",
    )
    parser.add_argument(
        "--scylla-mode",
        action="store_true",
        help="Enforce Scylla-compatible memory dump unmapping and CLR import reconstruction",
    )
    parser.add_argument(
        "--anti-dump-dir",
        help="Directory path to export healed binary, carved sections, and telemetry manifest",
    )
    parser.add_argument(
        "--demux-native",
        action="store_true",
        help="Demux embedded multi-architecture native binaries (x86, x64, ARM64)",
    )
    parser.add_argument(
        "--demux-out",
        help="Directory path to export demuxed native binaries organized by architecture",
    )
    parser.add_argument(
        "--route-arch",
        help="Target CPU architecture to simulate runtime loader routing for (e.g. x86, x64, arm64)",
    )
    parser.add_argument(
        "--route-os",
        default="windows",
        help="Target OS platform for routing simulation (windows, linux, osx, default: windows)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Execute forensic payload verification & PE/CLR structural integrity audit",
    )
    parser.add_argument(
        "--verify-against",
        dest="verify_against",
        help="Reference binary path to perform bitwise byte divergence comparison against",
    )
    parser.add_argument(
        "--expected-sha256",
        dest="expected_sha256",
        help="Expected SHA-256 golden hash digest to enforce verification against",
    )
    parser.add_argument(
        "--strict-pe",
        action="store_true",
        help="Enforce strict PE header bounds and treat structural warnings as failures",
    )
    parser.add_argument(
        "--gen-rules",
        action="store_true",
        help="Synthesize automated threat hunting YARA and Sigma detection rules",
    )
    parser.add_argument(
        "--gen-yara",
        action="store_true",
        help="Synthesize and display YARA detection rules for target binary",
    )
    parser.add_argument(
        "--gen-sigma",
        action="store_true",
        help="Synthesize and display Sigma detection rules for target binary",
    )
    parser.add_argument(
        "--rules-out",
        help="Directory path to export synthesized YARA/Sigma rules and manifest",
    )
    parser.add_argument(
        "--rule-level",
        choices=["specific", "behavioral", "hunt"],
        default="behavioral",
        help="Threat rule granularity level (specific, behavioral, or hunt, default: behavioral)",
    )
    parser.add_argument(
        "--mixed-mode", action="store_true",
        help="Analyze mixed-mode C++/CLI characteristics and VTableFixup tables",
    )
    parser.add_argument(
        "--trace-transitions", action="store_true",
        help="Trace execution boundary hops between unmanaged native code and managed CIL",
    )
    parser.add_argument(
        "--mixed-mode-out",
        help="Directory path to export mixed-mode analysis manifest, transitions, and VTFixup tables",
    )
    parser.add_argument(
        "--cfg",
        action="store_true",
        help="Generate CIL control flow graph and entropy analysis for assembly methods",
    )
    parser.add_argument(
        "--cfg-token",
        dest="cfg_token",
        help="Target specific method token (e.g. 0x06000001) for CFG visualization",
    )
    parser.add_argument(
        "--cfg-format",
        dest="cfg_format",
        choices=["mermaid", "dot", "svg", "ascii", "json", "all"],
        default="all",
        help="Visualization export format for CFG diagrams (default: all)",
    )
    parser.add_argument(
        "--cfg-out",
        dest="cfg_out",
        help="Directory path to export CFG diagrams, vector SVG charts, and JSON manifests",
    )
    parser.add_argument(
        "--baml",
        action="store_true",
        help="Extract and decompile embedded WPF BAML UI resources to clean XAML markup",
    )
    parser.add_argument(
        "--baml-out",
        dest="baml_out",
        help="Directory path to export decompiled XAML documents and structured JSON manifest",
    )
    parser.add_argument(
        "--baml-raw",
        action="store_true",
        help="Also export raw binary .baml streams alongside decompiled .xaml files",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Telemetry format (text or json)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Display verbose section metrics")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser
