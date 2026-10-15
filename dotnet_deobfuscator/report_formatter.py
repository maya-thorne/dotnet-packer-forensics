"""
Forensic Report Text Formatter for dotnet-packer-forensics.
Engineered & Audited by Maya Thorne.
"""

from typing import Dict

from . import __version__


def format_text_report(report: dict, verbose: bool = False) -> str:
    """Formats forensic analysis report dictionary into human-readable text."""
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

    if report.get("detected_protectors"):
        for p in report["detected_protectors"]:
            lines.append(f"  [+] {p['protector']} ({p['type']}) - Confidence: {p['confidence']}")
            lines.append(f"      Matched Tokens: {', '.join(p['matched_tokens'])}")
    else:
        lines.append("  [-] No standard signature matches detected.")

    lines.append("")
    lines.append("--- [PE Overlay Forensics] ---")
    ov = report.get("overlay", {})
    lines.append(f"  Has Overlay     : {'YES' if ov.get('has_overlay') else 'NO'}")
    if ov.get("has_overlay"):
        lines.append(f"  Overlay Size    : {ov['overlay_size_bytes']:,} bytes")
        lines.append(f"  PE Virtual Size : {ov['pe_virtual_size']:,} bytes")

    up = report.get("unpacked_payload", {})
    lines.append("")
    lines.append("--- [xorPacker Status] ---")
    if up.get("success"):
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

    ds = report.get("deepsea", {})
    lines.append("")
    lines.append("--- [DeepSea Control Flow & AST De-flattener] ---")
    if ds.get("detected"):
        lines.append(f"  [+] DeepSea Obfuscator Detected! (Confidence: {ds.get('confidence', 'HIGH')})")
        if ds.get("matched_markers"):
            lines.append(f"      Matched Markers    : {', '.join(ds['matched_markers'])}")
        lines.append(f"      Switch Density     : {ds.get('switch_density', 0)} opcodes identified")
        lines.append(f"      State Var Updates  : {ds.get('state_var_density', 0)} slot assignments")
    else:
        lines.append("  [-] No DeepSea obfuscation artifacts detected.")

    atamp = report.get("anti_tamper", {})
    lines.append("")
    lines.append("--- [CLI Metadata Anti-Tamper Forensics & JIT Dumper] ---")
    if atamp.get("detected"):
        lines.append(f"  [+] Anti-Tamper Protection Detected! (Confidence: {atamp.get('confidence', 'HIGH')})")
        if atamp.get("detected_types"):
            lines.append(f"      Protection Types   : {', '.join(atamp['detected_types'])}")
        if atamp.get("jit_signatures"):
            lines.append(f"      JIT Hook Signatures: {', '.join(atamp['jit_signatures'])}")
        if atamp.get("corrupted_streams"):
            lines.append(f"      Corrupted Streams  : {', '.join(atamp['corrupted_streams'])}")
        if atamp.get("anti_tamper_sections"):
            lines.append(f"      Tamper PE Sections : {', '.join(atamp['anti_tamper_sections'])}")
        lines.append(f"      Encrypted Methods  : ~{atamp.get('encrypted_methods_count', 0)} methods protected")
    else:
        lines.append("  [-] No CLI metadata anti-tamper artifacts detected.")

    adump = report.get("anti_dump", {})
    lines.append("")
    lines.append("--- [Anti-Dump Forensics & Memory Healer (Scylla-Compatible)] ---")
    if adump.get("detected"):
        lines.append(f"  [+] Anti-Dump Memory Corruption Detected! (Confidence: {adump.get('confidence', 'HIGH')})")
        lines.append(f"      Dump Source Class  : {adump.get('dump_source', 'UNKNOWN')}")
        if adump.get("detected_techniques"):
            lines.append(f"      Active Techniques  : {', '.join(adump['detected_techniques'])}")
        lines.append(f"      BSJB CLR Metadata  : {'YES' if adump.get('bsjb_found') else 'NO'}")
        if adump.get("bsjb_rva"):
            lines.append(f"      BSJB Header RVA    : {adump['bsjb_rva']}")
        lines.append(f"      Cor20 COM Descriptor: {'RECOVERED' if adump.get('cor20_recovered') else 'STRIPPED/ABSENT'}")
        if adump.get("anomalies"):
            for anom in adump["anomalies"][:4]:
                lines.append(f"        * {anom}")
        lines.append("  [+] Recommended Action    : Run with --heal-dump to reconstruct PE headers & normalize sections")
    else:
        lines.append("  [-] No anti-dump memory corruptions detected.")

    demux = report.get("native_demuxer", {})
    lines.append("")
    lines.append("--- [Native Multi-Architecture Resource Demuxer & Platform Router] ---")
    if demux.get("detected") or demux.get("total_payloads", 0) > 0:
        lines.append(f"  [+] Multi-Architecture Artifacts Detected! (Confidence: {demux.get('confidence', 'HIGH')})")
        lines.append(f"      Total Payloads     : {demux.get('total_payloads', 0):,}")
        lines.append(f"      Architectures      : {', '.join(demux.get('architectures_found', [])) or 'None'}")
        lines.append(f"      Target Platforms   : {', '.join(demux.get('platforms_found', [])) or 'None'}")
        lines.append(f"      Container Sources  : {', '.join(demux.get('sources_found', [])) or 'None'}")
        if demux.get("has_architecture_mismatch"):
            lines.append(f"  [!] Architecture Spoofing / Mismatch Detected: {demux.get('mismatch_count')} anomalies")
            for anom in demux.get("anomalies", [])[:4]:
                lines.append(f"        * {anom}")
        for p in demux.get("payloads", [])[:6]:
            mismatch_tag = " [!] MISMATCH" if p.get("mismatch_detected") else ""
            lines.append(f"      -> {p.get('name')} ({p.get('size_bytes', 0):,} bytes, Arch: {p.get('target_arch')}{mismatch_tag})")
            lines.append(f"         Format  : {p.get('format')} | Machine: {p.get('machine_hex')} | OS: {p.get('target_os')}")
            lines.append(f"         SHA-256 : {p.get('sha256')}")
        if len(demux.get("payloads", [])) > 6:
            lines.append(f"      -> ... ({len(demux.get('payloads', [])) - 6} more native binaries)")
        lines.append("  [+] Recommended Action    : Run with --demux-out <DIR> to carve & organize by architecture")
    else:
        lines.append("  [-] No native multi-architecture embedded resources detected.")

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

    threat_rules = report.get("threat_hunting_rules", {})
    if threat_rules.get("synthesized"):
        lines.append("")
        lines.append("--- [Threat Hunting Rules Synthesis (YARA & Sigma)] ---")
        lines.append(f"  [+] Rules Synthesized: {threat_rules.get('yara_count', 0)} YARA / {threat_rules.get('sigma_count', 0)} Sigma (Granularity: {threat_rules.get('granularity', 'BEHAVIORAL').upper()})")
        for yr in threat_rules.get("yara_rules", [])[:4]:
            lines.append(f"      * YARA: {yr}")
        for sr in threat_rules.get("sigma_rules", [])[:4]:
            lines.append(f"      * Sigma: {sr}")

    mixed = report.get("mixed_mode", {})
    lines.append("")
    lines.append("--- [Native Mixed-Mode Forensics & CIL-Native Transition Tracer] ---")
    if mixed.get("is_mixed_mode"):
        lines.append(f"  [+] Mixed-Mode Assembly Detected! (Type: {mixed.get('mixed_mode_type')}, Confidence: {mixed.get('confidence', 'HIGH')})")
        lines.append(f"      Risk Assessment    : {mixed.get('risk_severity', 'MEDIUM').upper()} (Score: {mixed.get('risk_score', 0)}/100)")
        lines.append(f"      Cor20 Flags        : {', '.join(mixed.get('cor20_flags', [])) or 'None'}")
        if mixed.get("has_native_entrypoint"):
            lines.append(f"      Native EntryPoint  : RVA {hex(mixed.get('native_entrypoint_rva', 0))} (Executes before CLR bootstrap)")
        lines.append(f"      VTableFixup Tables : {mixed.get('vtfixup_tables_count', 0)} ({mixed.get('total_vtfixup_slots', 0)} slots, {mixed.get('from_unmanaged_slots_count', 0)} unmanaged thunks)")
        if mixed.get("bridged_exports_count", 0) > 0:
            lines.append(f"      Bridged Exports    : {mixed.get('bridged_exports_count', 0)} / {mixed.get('unmanaged_exports_count', 0)} total exports")
        if mixed.get("tls_callbacks_count", 0) > 0:
            lines.append(f"  [!] Native TLS Callbacks Identified: {mixed.get('tls_callbacks_count', 0)} pre-runtime execution hooks")
        if mixed.get("anomalies"):
            for anom in mixed.get("anomalies", [])[:4]:
                lines.append(f"      * {anom}")
        lines.append("  [+] Recommended Action : Run with --trace-transitions to inspect execution boundary hops")
    else:
        lines.append(f"  [-] Standard {mixed.get('mixed_mode_type', 'pure_managed')} PE binary (no mixed-mode CIL-native transitions).")

    cfg = report.get("cfg_forensics", {})
    if cfg.get("total_methods_analyzed", 0) > 0:
        lines.append("")
        lines.append("--- [CIL Control Flow Graph (CFG) & Block Entropy Diagnostics] ---")
        lines.append(f"  [+] Methods Analyzed   : {cfg.get('total_methods_analyzed', 0)} methods ({cfg.get('total_blocks', 0)} basic blocks, {cfg.get('total_edges', 0)} edges)")
        lines.append(f"      Cyclomatic Health  : Peak Complexity = {cfg.get('max_cyclomatic_complexity', 1)} ({cfg.get('complex_methods_count', 0)} high-complexity methods)")
        lines.append(f"      Entropy Metrics    : Avg Method Entropy = {cfg.get('average_method_entropy', 0.0):.4f} / 8.000")
        if cfg.get("high_entropy_blocks_total", 0) > 0:
            lines.append(f"  [!] High Entropy Blocks: {cfg.get('high_entropy_blocks_total')} encrypted or packed bytecode blocks identified")
        if cfg.get("methods_with_dead_code", 0) > 0:
            lines.append(f"  [!] Dead Code Detected : {cfg.get('methods_with_dead_code')} method(s) contain unreachable instructions")
        if cfg.get("suspicious_methods"):
            for sm in cfg.get("suspicious_methods", [])[:3]:
                lines.append(f"      * {sm}")

    baml = report.get("baml_forensics", {})
    if baml.get("total_baml_streams", 0) > 0:
        lines.append("")
        lines.append("--- [WPF BAML & Embedded UI Resource Forensics] ---")
        lines.append(
            f"  [+] BAML Streams       : {baml.get('total_baml_streams', 0)} streams ({baml.get('successful_decompiles', 0)} decompiled, {baml.get('failed_decompiles', 0)} failed)"
        )
        lines.append(
            f"      UI Structure       : {baml.get('total_elements', 0)} elements, {baml.get('total_attributes', 0)} properties"
        )
        if baml.get("total_anomalies", 0) > 0:
            lines.append(
                f"  [!] UI Security Alerts : {baml.get('total_anomalies', 0)} anomaly indicator(s) identified in XAML markup"
            )
            for anom_k, anom_cnt in list(baml.get("anomaly_types", {}).items())[:4]:
                lines.append(f"      * {anom_k}: {anom_cnt} occurrence(s)")

    if verbose and report.get("sections"):
        lines.append("")
        lines.append("--- [Section Topology & Entropy] ---")
        for s in report["sections"]:
            lines.append(
                f"  Section: {s['name']:<8} RawSize: {s['raw_size']:<8} Entropy: {s['entropy']}  VAddr: {s['virtual_address']}"
            )

    if report.get("suspicious_indicators"):
        lines.append("")
        lines.append("--- [Suspicious Anomaly Flags] ---")
        for ind in report["suspicious_indicators"]:
            lines.append(f"  [!] {ind}")

    lines.append("==============================================================================")
    return "\n".join(lines)
