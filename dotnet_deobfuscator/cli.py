"""
Command-Line Interface (CLI) for dotnet-packer-forensics.
Engineered & Audited by Maya Thorne.
"""

import argparse
import json
import os
import sys
from typing import Optional

from . import __version__
from .core import DotNetPackerCore
from .payload_verifier import PayloadVerifier
from .pe_rebuilder import PERebuildOptions
from .unpackers.armdot_vm import ArmDotOpcodeTable
from .unpackers.eazfuscator_vm import VMOpcodeTable


def build_parser() -> argparse.ArgumentParser:
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
        "--rebuild",
        action="store_true",
        help="Reconstruct damaged PE headers, realign sections, and repair standalone binary",
    )
    parser.add_argument(
        "--rebuild-out",
        help="Output destination path for rebuilt PE binary",
    )
    parser.add_argument(
        "--unmap-dump",
        action="store_true",
        help="Force process memory dump unmapping (realign RVA mapped sections to disk raw offsets)",
    )
    parser.add_argument(
        "--strip-envelope",
        action="store_true",
        help="Strip native wrapper envelope and carve encapsulated managed .NET assembly",
    )
    parser.add_argument(
        "--envelope-out",
        help="Destination path for de-enveloped managed assembly binary",
    )
    parser.add_argument(
        "--restore-necrobit",
        action="store_true",
        help="Decrypt NecroBit CIL method bodies and reconstruct deobfuscated assembly",
    )
    parser.add_argument(
        "--necrobit-out",
        help="Destination path for NecroBit restored assembly binary",
    )
    parser.add_argument(
        "--necrobit-seed",
        type=lambda x: int(x, 0),
        default=0x14725836,
        help="Decryption seed integer for NecroBit PRNG stream cipher (default: 0x14725836)",
    )
    parser.add_argument(
        "--devirtualize-eaz",
        action="store_true",
        help="De-virtualize Eazfuscator.NET VM methods and reconstruct assembly",
    )
    parser.add_argument(
        "--eaz-out",
        help="Destination path for devirtualized assembly binary",
    )
    parser.add_argument(
        "--disasm-vm",
        action="store_true",
        help="Disassemble Eazfuscator VM bytecode containers to formatted assembly",
    )
    parser.add_argument(
        "--vm-table",
        help="Custom VM opcode table JSON configuration file path",
    )
    parser.add_argument(
        "--devirtualize-armdot",
        action="store_true",
        help="De-virtualize ArmDot VM methods and reconstruct assembly",
    )
    parser.add_argument(
        "--armdot-out",
        help="Destination path for ArmDot devirtualized assembly binary",
    )
    parser.add_argument(
        "--disasm-armdot",
        action="store_true",
        help="Disassemble ArmDot VM bytecode containers to formatted assembly",
    )
    parser.add_argument(
        "--armdot-table",
        help="Custom ArmDot VM opcode table JSON configuration file path",
    )
    parser.add_argument(
        "--demangle-babel",
        action="store_true",
        help="Demangle Babel Obfuscator symbols and reconstruct dependency graph",
    )
    parser.add_argument(
        "--babel-out",
        help="Destination path for demangled assembly binary",
    )
    parser.add_argument(
        "--export-depgraph",
        action="store_true",
        help="Export inter-assembly dependency graph in JSON, Graphviz DOT, and Mermaid formats",
    )
    parser.add_argument(
        "--custom-map",
        help="Path to external Babel mapping file (XML, JSON, or text format)",
    )
    parser.add_argument(
        "--strip-intellilock",
        action="store_true",
        help="Strip IntelliLock licensing envelope and restore original managed assembly",
    )
    parser.add_argument(
        "--intellilock-out",
        help="Destination path for unlocked assembly binary",
    )
    parser.add_argument(
        "--bypass-hwlock",
        action="store_true",
        help="Generate synthetic hardware license to bypass hardware locking and trial expiration",
    )
    parser.add_argument(
        "--gen-license",
        action="store_true",
        help="Generate a valid synthetic perpetual master license (.lic) file",
    )
    parser.add_argument(
        "--license-out",
        help="Destination file path for generated synthetic license (.lic)",
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
        "--format",
        choices=["text", "json"],
        default="text",
        help="Telemetry format (text or json)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Display verbose section metrics"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def format_text_report(report: dict, verbose: bool = False) -> str:
    lines = [
        "==============================================================================",
        f"[dotnet-packer-re v{__version__}] Static Forensic Analysis Report",
        "==============================================================================",
        f"Target File     : {report['file']}",
        f"File Size       : {report['size_bytes']:,} bytes",
        f"SHA-256 Digest  : {report.get('sha256', 'N/A')}",
        f"Analysis Time   : {report['elapsed_ms']} ms",
        f"PE Binary       : {'YES' if report['is_pe'] else 'NO'}",
        f".NET Assembly   : {'YES' if report['is_dotnet'] else 'NO'}",
        f"Shannon Entropy : {report['entropy']} / 8.000",
        "",
        "--- [Protector Detections] ---",
    ]

    if report["detected_protectors"]:
        for p in report["detected_protectors"]:
            lines.append(f"  [+] {p['protector']} ({p['type']}) - Confidence: {p['confidence']}")
            lines.append(f"      Matched Tokens: {', '.join(p['matched_tokens'])}")
    else:
        lines.append("  [-] No standard signature matches detected.")

    lines.append("")
    lines.append("--- [PE Overlay Forensics] ---")
    ov = report["overlay"]
    lines.append(f"  Has Overlay     : {'YES' if ov['has_overlay'] else 'NO'}")
    if ov["has_overlay"]:
        lines.append(f"  Overlay Size    : {ov['overlay_size_bytes']:,} bytes")
        lines.append(f"  PE Virtual Size : {ov['pe_virtual_size']:,} bytes")

    up = report["unpacked_payload"]
    lines.append("")
    lines.append("--- [xorPacker Status] ---")
    if up["success"]:
        details = up["details"]
        lines.append("  [+] xorPacker Payload Successfully Decrypted!")
        lines.append(f"      Sentinel Offset   : 0x{details['sentinel_offset']:X}")
        lines.append(f"      Dynamic Key Found : '{details['dynamic_key']}'")
        lines.append(f"      Payload Size      : {details['payload_size']:,} bytes")
        lines.append(f"      Valid PE Output   : {'YES' if details['is_valid_pe'] else 'NO'}")
    else:
        lines.append("  [-] No decryptable xorPacker overlay detected.")

    costura = report.get("costura", {})
    lines.append("")
    lines.append("--- [Costura Embedded Assemblies Forensics] ---")
    if costura.get("detected"):
        lines.append(f"  [+] Costura Packer Detected! (Confidence: {costura.get('confidence', 'HIGH')})")
        lines.append(f"      Embedded Payloads Count: {costura.get('payloads_count', 0)}")
        for payload in costura.get("payloads", []):
            pe_flag = "PE Assembly" if payload["is_pe"] else ("PDB Symbols" if payload["is_pdb"] else "Binary Resource")
            lines.append(f"      -> {payload['output_filename']} ({payload['size_bytes']:,} bytes, {pe_flag})")
            lines.append(f"         SHA-256 : {payload['sha256']}")
            lines.append(f"         Entropy : {payload['entropy']} / 8.000 (Orig: {payload['original_name']})")
    else:
        lines.append("  [-] No Costura embedded assemblies detected.")

    confuser = report.get("confuserex", {})
    lines.append("")
    lines.append("--- [ConfuserEx Modular Protector Forensics] ---")
    if confuser.get("detected"):
        lines.append(f"  [+] ConfuserEx Protector Detected! (Confidence: {confuser.get('confidence', 'HIGH')})")
        if confuser.get("detected_protections"):
            lines.append(f"      Active Protections : {', '.join(confuser['detected_protections'])}")
        if confuser.get("markers_found"):
            lines.append(f"      Matched Markers    : {', '.join(confuser['markers_found'])}")
        if confuser.get("obfuscated_names_count", 0) > 0:
            lines.append(f"      Unicode Mangled IDs: {confuser['obfuscated_names_count']:,} tokens")
        lines.append(f"      Decrypted Strings  : {confuser.get('decrypted_strings_count', 0)}")
        if confuser.get("decrypted_strings"):
            for s in confuser["decrypted_strings"][:8]:
                lines.append(f"        * \"{s}\"")
            if confuser["decrypted_strings_count"] > 8:
                lines.append(f"        * ... ({confuser['decrypted_strings_count'] - 8} more strings)")
        lines.append(f"      Embedded Resources : {confuser.get('resources_count', 0)}")
        for res in confuser.get("resources", []):
            lines.append(f"      -> {res['output_filename']} ({res['size_bytes']:,} bytes, {res['resource_type']})")
            lines.append(f"         SHA-256 : {res['sha256']}")
            lines.append(f"         Entropy : {res['entropy']} / 8.000 (Orig: {res['original_name']})")
    else:
        lines.append("  [-] No ConfuserEx protection artifacts detected.")

    reactor = report.get("reactor", {})
    lines.append("")
    lines.append("--- [.NET Reactor & NecroBit Forensics] ---")
    if reactor.get("detected"):
        lines.append(f"  [+] .NET Reactor Detected! (Confidence: {reactor.get('confidence', 'HIGH')})")
        if reactor.get("is_native_envelope"):
            lines.append("      Wrapper Envelope   : Native Win32/x64 Stub Envelope Identified")
        if reactor.get("has_necrobit"):
            lines.append(f"      NecroBit Protected : YES ({reactor.get('methods_count', 0)} encrypted methods)")
        if reactor.get("markers_found"):
            lines.append(f"      Matched Markers    : {', '.join(reactor['markers_found'])}")
        if reactor.get("restored_methods"):
            lines.append("      Decrypted CIL Stubs:")
            for m in reactor["restored_methods"][:8]:
                valid_str = "Valid CIL" if m["is_valid_cil"] else "Raw Bytecode"
                lines.append(f"        * Token {m['token']} ({m['header_format']}, {m['code_size']} bytes, {valid_str})")
            if len(reactor["restored_methods"]) > 8:
                lines.append(f"        * ... ({len(reactor['restored_methods']) - 8} more methods)")
        if reactor.get("payloads"):
            lines.append(f"      Carved Artifacts   : {len(reactor['payloads'])}")
            for p in reactor["payloads"]:
                lines.append(f"      -> {p['output_filename']} ({p['size_bytes']:,} bytes, {p['artifact_type']})")
                lines.append(f"         SHA-256 : {p['sha256']}")
    else:
        lines.append("  [-] No .NET Reactor protection artifacts detected.")

    eaz = report.get("eazfuscator", {})
    lines.append("")
    lines.append("--- [Eazfuscator.NET VM Forensics & De-virtualizer] ---")
    if eaz.get("detected"):
        lines.append(f"  [+] Eazfuscator.NET Detected! (Confidence: {eaz.get('confidence', 'HIGH')})")
        if eaz.get("has_virtual_machine"):
            lines.append(f"      Virtual Machine    : YES ({eaz.get('vm_method_count', 0)} virtualized methods in {eaz.get('vm_containers_count', 0)} containers)")
        if eaz.get("matched_markers"):
            lines.append(f"      Matched Markers    : {', '.join(eaz['matched_markers'])}")
        if eaz.get("containers"):
            lines.append("      VM Containers:")
            for c in eaz["containers"][:5]:
                lines.append(f"        * Container @ {c['offset']} (v{c['version']}, {c['method_count']} methods, Magic: {c['magic']})")
                for t in c.get("tokens", [])[:4]:
                    lines.append(f"          - Method Token: {t}")
    else:
        lines.append("  [-] No Eazfuscator.NET virtualization artifacts detected.")

    babel = report.get("babel", {})
    lines.append("")
    lines.append("--- [Babel Obfuscator Forensics & Symbol Demangler] ---")
    if babel.get("detected"):
        lines.append(f"  [+] Babel Obfuscator Detected! (Confidence: {babel.get('confidence', 'HIGH')})")
        if babel.get("has_merged_assemblies"):
            lines.append(f"      Merged Assemblies  : YES ({babel.get('merged_assemblies_count', 0)} embedded assemblies carved)")
        if babel.get("has_embedded_map"):
            lines.append("      Embedded BabelMap  : YES (XML/JSON mapping table identified)")
        if babel.get("obfuscated_symbols_count", 0) > 0:
            lines.append(f"      Mangled Tokens     : {babel['obfuscated_symbols_count']:,} Unicode tokens identified")
        if babel.get("markers_found"):
            lines.append(f"      Matched Markers    : {', '.join(babel['markers_found'])}")
        if babel.get("merged_assemblies"):
            lines.append("      Carved Assemblies:")
            for m in babel["merged_assemblies"][:5]:
                lines.append(f"        * {m['output_filename']} ({m['size_bytes']:,} bytes, {m['compression']}, Orig: {m['original_name']})")
                lines.append(f"          SHA-256 : {m['sha256']}")
    else:
        lines.append("  [-] No Babel Obfuscator artifacts detected.")

    armdot = report.get("armdot", {})
    lines.append("")
    lines.append("--- [ArmDot VM Forensics & De-virtualizer] ---")
    if armdot.get("detected"):
        lines.append(f"  [+] ArmDot Detected! (Confidence: {armdot.get('confidence', 'HIGH')})")
        if armdot.get("has_virtual_machine"):
            lines.append(f"      Virtual Machine    : YES ({armdot.get('vm_method_count', 0)} virtualized methods in {armdot.get('vm_containers_count', 0)} containers)")
        if armdot.get("matched_markers"):
            lines.append(f"      Matched Markers    : {', '.join(armdot['matched_markers'])}")
        if armdot.get("containers"):
            lines.append("      VM Containers:")
            for c in armdot["containers"][:5]:
                lines.append(f"        * Container @ {c['offset']} (v{c['version']}, {c['method_count']} methods, Magic: {c['magic']})")
                for t in c.get("tokens", [])[:4]:
                    lines.append(f"          - Method Token: {t}")
    else:
        lines.append("  [-] No ArmDot virtualization artifacts detected.")

    itllock = report.get("intellilock", {})
    lines.append("")
    lines.append("--- [IntelliLock License Management Forensics] ---")
    if itllock.get("detected"):
        lines.append(f"  [+] IntelliLock Detected! (Confidence: {itllock.get('confidence', 'HIGH')})")
        if itllock.get("is_enveloped"):
            lines.append("      Licensing Envelope : Encapsulated Assembly Identified")
        if itllock.get("has_hardware_lock"):
            lines.append("      Hardware Lock      : YES (Bound to Host Machine Fingerprint)")
        if itllock.get("has_trial_expiration"):
            lines.append("      Trial Expiration   : YES (Execution count / Calendar deadline enforced)")
        if itllock.get("markers_found"):
            lines.append(f"      Matched Markers    : {', '.join(itllock['markers_found'])}")
        if itllock.get("sections_matched"):
            lines.append(f"      Matched Sections   : {', '.join(itllock['sections_matched'])}")
    else:
        lines.append("  [-] No IntelliLock protection artifacts detected.")

    pe_reb = report.get("pe_rebuilder", {})
    lines.append("")
    lines.append("--- [PE Structural Health & Rebuilder Diagnostics] ---")
    if pe_reb.get("repair_recommended"):
        lines.append(f"  [!] Structural Anomalies Detected: {pe_reb.get('anomalies_count', 0)}")
        if pe_reb.get("is_memory_dump"):
            lines.append("      Format Classification : Process Memory Dump (Unmapping Required)")
        for anom in pe_reb.get("anomalies_detected", []):
            lines.append(f"      - {anom}")
        lines.append("  [+] Recommended Action    : Run with --rebuild to reconstruct headers & sections")
    else:
        lines.append("  [+] PE Structural Status  : HEALTHY (Valid headers and aligned sections)")

    if verbose and report["sections"]:
        lines.append("")
        lines.append("--- [Section Topology & Entropy] ---")
        for s in report["sections"]:
            lines.append(
                f"  Section: {s['name']:<8} RawSize: {s['raw_size']:<8} Entropy: {s['entropy']}  VAddr: {s['virtual_address']}"
            )

    if report["suspicious_indicators"]:
        lines.append("")
        lines.append("--- [Suspicious Anomaly Flags] ---")
        for ind in report["suspicious_indicators"]:
            lines.append(f"  [!] {ind}")

    lines.append("==============================================================================")
    return "\n".join(lines)


def main(argv: Optional[list] = None) -> int:
    # Ensure stdout handles UTF-8 gracefully across Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = DotNetPackerCore.analyze_file(args.target, master_key=args.key)
    except Exception as e:
        sys.stderr.write(f"[-] Error: {e}\n")
        return 1

    # Payload Verification & PE/CLR structural integrity regression checks
    if args.verify or args.verify_against or args.expected_sha256:
        try:
            ver_res = DotNetPackerCore.verify_payload(
                target_path=args.target,
                reference_path=args.verify_against,
                expected_sha256=args.expected_sha256,
                strict_pe=args.strict_pe,
            )
            if args.format == "json":
                sys.stdout.write(json.dumps(ver_res.to_dict(), indent=2) + "\n")
            else:
                sys.stdout.write(PayloadVerifier.format_text_report(ver_res, verbose=args.verbose) + "\n")
            return 0 if ver_res.passed else 2
        except Exception as e:
            sys.stderr.write(f"[-] Verification failed: {e}\n")
            return 1

    # Reconstruct and repair damaged PE binary if requested
    if args.rebuild:
        try:
            dest_path = args.rebuild_out or args.output or f"{args.target}.rebuilt.exe"
            options = PERebuildOptions(
                unmap_memory_dump=args.unmap_dump or report.get("pe_rebuilder", {}).get("is_memory_dump", False)
            )
            rebuild_report = DotNetPackerCore.rebuild_pe(args.target, dest_path, options=options)
            sys.stdout.write(
                f"[+] Successfully rebuilt PE binary -> {dest_path} ({rebuild_report.rebuilt_size:,} bytes)\n"
            )
            for act in rebuild_report.actions_applied:
                sys.stdout.write(f"    * {act}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Rebuild failed: {e}\n")

    # Strip native wrapper envelope if requested
    if args.strip_envelope:
        try:
            dest_path = args.envelope_out or args.output or f"{args.target}.de_enveloped.dll"
            success = DotNetPackerCore.strip_reactor_envelope(args.target, dest_path)
            if success:
                sys.stdout.write(
                    f"[+] Successfully stripped native envelope -> {dest_path}\n"
                )
            else:
                sys.stderr.write("[-] No native envelope or valid embedded managed PE found.\n")
        except Exception as e:
            sys.stderr.write(f"[-] Envelope stripping failed: {e}\n")

    # Restore NecroBit encrypted CIL method bodies if requested
    if args.restore_necrobit:
        try:
            dest_path = args.necrobit_out or args.output or f"{args.target}.necrobit_restored.exe"
            necro_rep = DotNetPackerCore.restore_necrobit(
                args.target, dest_path, seed=args.necrobit_seed
            )
            count = necro_rep.get("methods_restored_count", 0)
            sys.stdout.write(
                f"[+] Successfully restored {count} NecroBit CIL methods -> {dest_path}\n"
            )
            for act in necro_rep.get("actions_applied", []):
                sys.stdout.write(f"    * {act}\n")
        except Exception as e:
            sys.stderr.write(f"[-] NecroBit restoration failed: {e}\n")

    # Disassemble Eazfuscator VM bytecode containers if requested
    if args.disasm_vm:
        try:
            custom_tbl = None
            if args.vm_table:
                with open(args.vm_table, "r", encoding="utf-8") as f:
                    custom_tbl = VMOpcodeTable.from_dict(json.load(f))
            disasm_res = DotNetPackerCore.disassemble_eazfuscator_vm(args.target, custom_table=custom_tbl)
            sys.stdout.write(f"[+] Disassembled {len(disasm_res)} Eazfuscator VM method bodies:\n")
            for item in disasm_res:
                sys.stdout.write(f"\n--- Method {item['token']} ({item['instruction_count']} VM instructions) ---\n")
                sys.stdout.write(item["disassembly"] + "\n")
        except Exception as e:
            sys.stderr.write(f"[-] VM disassembly failed: {e}\n")

    # De-virtualize Eazfuscator VM assembly if requested
    if args.devirtualize_eaz:
        try:
            custom_tbl = None
            if args.vm_table:
                with open(args.vm_table, "r", encoding="utf-8") as f:
                    custom_tbl = VMOpcodeTable.from_dict(json.load(f))
            dest_path = args.eaz_out or args.output or f"{args.target}.devirtualized.exe"
            rebuilt_pe, eaz_rep = DotNetPackerCore.devirtualize_eazfuscator(
                args.target, output_path=dest_path, custom_table=custom_tbl
            )
            count = eaz_rep.get("methods_devirtualized_count", 0)
            sys.stdout.write(
                f"[+] Successfully de-virtualized {count} Eazfuscator VM methods -> {dest_path}\n"
            )
            for act in eaz_rep.get("actions_applied", []):
                sys.stdout.write(f"    * {act}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Eazfuscator de-virtualization failed: {e}\n")

    # Demangle Babel Obfuscator symbols and reconstruct dependency graph if requested
    if args.demangle_babel:
        try:
            dest_path = args.babel_out or args.output or f"{args.target}.demangled.exe"
            demangled_pe, babel_rep = DotNetPackerCore.demangle_babel(
                args.target, output_path=dest_path, custom_map=args.custom_map
            )
            count = babel_rep.get("symbols_demangled", 0)
            sys.stdout.write(
                f"[+] Successfully demangled {count} Babel symbols -> {dest_path}\n"
            )
            for act in babel_rep.get("actions_applied", []):
                sys.stdout.write(f"    * {act}\n")
            if args.export_depgraph:
                base_dir = os.path.dirname(os.path.abspath(dest_path))
                dot_file = os.path.join(base_dir, "dependency_graph.dot")
                mermaid_file = os.path.join(base_dir, "dependency_graph.mermaid")
                with open(dot_file, "w", encoding="utf-8") as f:
                    f.write(babel_rep.get("depgraph_dot", ""))
                with open(mermaid_file, "w", encoding="utf-8") as f:
                    f.write(babel_rep.get("depgraph_mermaid", ""))
                sys.stdout.write(f"    * Exported dependency graph DOT -> {dot_file}\n")
                sys.stdout.write(f"    * Exported dependency graph Mermaid -> {mermaid_file}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Babel demangling failed: {e}\n")

    # Disassemble ArmDot VM bytecode containers if requested
    if args.disasm_armdot:
        try:
            custom_tbl = None
            if args.armdot_table:
                with open(args.armdot_table, "r", encoding="utf-8") as f:
                    custom_tbl = ArmDotOpcodeTable.from_dict(json.load(f))
            disasm_res = DotNetPackerCore.disassemble_armdot_vm(args.target, custom_table=custom_tbl)
            sys.stdout.write(f"[+] Disassembled {len(disasm_res)} ArmDot VM method bodies:\n")
            for item in disasm_res:
                sys.stdout.write(f"\n--- Method {item['token']} ({item['instruction_count']} VM instructions) ---\n")
                sys.stdout.write(item["disassembly"] + "\n")
        except Exception as e:
            sys.stderr.write(f"[-] ArmDot VM disassembly failed: {e}\n")

    # De-virtualize ArmDot VM assembly if requested
    if args.devirtualize_armdot:
        try:
            custom_tbl = None
            if args.armdot_table:
                with open(args.armdot_table, "r", encoding="utf-8") as f:
                    custom_tbl = ArmDotOpcodeTable.from_dict(json.load(f))
            dest_path = args.armdot_out or args.output or f"{args.target}.armdot_devirtualized.exe"
            rebuilt_pe, armdot_rep = DotNetPackerCore.devirtualize_armdot(
                args.target, output_path=dest_path, custom_table=custom_tbl
            )
            count = armdot_rep.get("methods_devirtualized_count", 0)
            sys.stdout.write(
                f"[+] Successfully de-virtualized {count} ArmDot VM methods -> {dest_path}\n"
            )
            for act in armdot_rep.get("actions_applied", []):
                sys.stdout.write(f"    * {act}\n")
        except Exception as e:
            sys.stderr.write(f"[-] ArmDot de-virtualization failed: {e}\n")

    # Strip IntelliLock license envelope if requested
    if args.strip_intellilock:
        try:
            dest_path = args.intellilock_out or args.output or f"{args.target}.unlocked.exe"
            res = DotNetPackerCore.strip_intellilock(args.target, output_path=dest_path)
            sys.stdout.write(
                f"[+] Successfully neutralized IntelliLock license envelope -> {dest_path} ({res['size_bytes']:,} bytes)\n"
            )
            sys.stdout.write("    * De-enveloped clean PE with restored EntryPoint\n")
            sys.stdout.write("    * Hardware lock and trial expiration checks bypassed\n")
        except Exception as e:
            sys.stderr.write(f"[-] IntelliLock stripping failed: {e}\n")

    # Generate synthetic master license or bypass hardware lock if requested
    if args.gen_license or args.bypass_hwlock:
        try:
            lic = DotNetPackerCore.bypass_intellilock_hwlock()
            dest_path = args.license_out or "master_license.lic"
            with open(dest_path, "wb") as f:
                f.write(lic.to_bytes())
            sys.stdout.write(
                f"[+] Generated synthetic perpetual master license -> {dest_path}\n"
            )
            sys.stdout.write(f"    * Licensee: {lic.licensee} ({lic.company})\n")
            sys.stdout.write(f"    * Status: {lic.status.value}, Expiration: {lic.expiration_date}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Synthetic license generation failed: {e}\n")

    # Dump decrypted ConfuserEx strings if requested
    if args.dump_strings:
        try:
            strings = DotNetPackerCore.dump_strings(args.target)
            sys.stdout.write(f"[+] Decrypted {len(strings)} strings/constants:\n")
            for idx, s in enumerate(strings):
                sys.stdout.write(f"  [{idx:04d}] {s}\n")
        except Exception as e:
            sys.stderr.write(f"[-] String dump failed: {e}\n")

    # Embedded assemblies directory extraction
    if args.unpack_dir:
        try:
            written = DotNetPackerCore.unpack_to_dir(args.target, args.unpack_dir)
            sys.stdout.write(f"[+] Successfully extracted {len(written)} embedded assemblies to -> {args.unpack_dir}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Extraction failed: {e}\n")

    if args.output and not args.rebuild:
        # Check if output path is an existing directory or ends with slash
        if os.path.isdir(args.output) or args.output.endswith(("/", "\\")):
            try:
                written = DotNetPackerCore.unpack_to_dir(args.target, args.output)
                sys.stdout.write(f"[+] Successfully extracted {len(written)} embedded assemblies to directory -> {args.output}\n")
            except Exception as e:
                sys.stderr.write(f"[-] Extraction to directory failed: {e}\n")
        else:
            success = DotNetPackerCore.unpack_to_file(
                args.target, args.output, master_key=args.key
            )
            if success:
                sys.stdout.write(f"[+] Successfully extracted unpacked payload -> {args.output}\n")
            else:
                sys.stderr.write("[-] Failed to extract unpacked payload.\n")

    if args.format == "json":
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        sys.stdout.write(format_text_report(report, verbose=args.verbose) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
