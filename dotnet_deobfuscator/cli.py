"""
Command-Line Interface (CLI) for dotnet-packer-forensics.
Engineered & Audited by Maya Thorne.
"""

import argparse
import json
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
        "-o", "--output", help="Write decrypted unpacked payload to specified path"
    )
    parser.add_argument(
        "-k",
        "--key",
        default="randomkey",
        help="Master key for overlay decryption (default: 'randomkey')",
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
    lines.append("--- [Unpacking Status] ---")
    if up["success"]:
        details = up["details"]
        lines.append("  [+] xorPacker Payload Successfully Decrypted!")
        lines.append(f"      Sentinel Offset   : 0x{details['sentinel_offset']:X}")
        lines.append(f"      Dynamic Key Found : '{details['dynamic_key']}'")
        lines.append(f"      Payload Size      : {details['payload_size']:,} bytes")
        lines.append(f"      Valid PE Output   : {'YES' if details['is_valid_pe'] else 'NO'}")
    else:
        lines.append("  [-] No decryptable xorPacker overlay detected.")

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

    if args.output:
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
