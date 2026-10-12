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

    if args.output:
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
