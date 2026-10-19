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
from .cli_args import build_parser
from .core import DotNetPackerCore
from .payload_verifier import PayloadVerifier
from .pe_rebuilder import PERebuildOptions
from .report_formatter import format_text_report
from .unpackers.armdot_vm import ArmDotOpcodeTable
from .unpackers.eazfuscator_vm import VMOpcodeTable


def main(argv: Optional[list] = None) -> int:
    # Ensure stdout handles UTF-8 gracefully across Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    # Automated Regression Fuzzing Campaign Mode
    if args.fuzz:
        try:
            targets = [t.strip() for t in args.fuzz_targets.split(",")] if args.fuzz_targets else None
            fuzz_res = DotNetPackerCore.run_fuzzing_campaign(
                target_path=args.target,
                iterations=args.fuzz_iterations,
                seed=args.fuzz_seed,
                targets=targets,
                timeout_sec=args.fuzz_timeout,
                output_dir=args.fuzz_out,
                is_64bit=args.fuzz_64,
                isolate_process=args.fuzz_isolate,
            )
            if args.format == "json":
                sys.stdout.write(json.dumps(fuzz_res.to_dict(), indent=2) + "\n")
            else:
                from .fuzzing import RegressionFuzzingHarness
                sys.stdout.write(RegressionFuzzingHarness.format_campaign_summary(fuzz_res) + "\n")
            return 1 if fuzz_res.telemetry.has_regressions else 0
        except Exception as e:
            sys.stderr.write(f"[-] Fuzzing campaign failed: {e}\n")
            return 1

    # Synthetic Mutated Binary Generator Mode
    if args.gen_mutants:
        try:
            mutants = DotNetPackerCore.generate_synthetic_corpus(
                base_path=args.target,
                count=args.mutant_count,
                output_dir=args.output or args.fuzz_out,
                is_64bit=args.fuzz_64,
            )
            if args.format == "json":
                sys.stdout.write(json.dumps(mutants, indent=2) + "\n")
            else:
                sys.stdout.write(f"[+] Generated {len(mutants)} synthetic mutated binaries.\n")
                for m in mutants:
                    sys.stdout.write(f"    * [{m['index']:02d}] {m['file_name']} ({m['size_bytes']:,} bytes, {m['mutations_count']} mutations)\n")
            return 0
        except Exception as e:
            sys.stderr.write(f"[-] Synthetic mutant generation failed: {e}\n")
            return 1

    # Batch Directory Forensic Scanner Mode
    if args.batch is not None:
        try:
            target_dir = args.batch if (args.batch and args.batch != "") else args.target
            if not target_dir:
                sys.stderr.write("[-] Error: Target directory for batch scanning is required\n")
                return 2

            from .batch import BatchForensicEngine, BatchReporter, BatchScanOptions
            options = BatchScanOptions(
                target_dir=target_dir,
                recursive=args.batch_recursive,
                workers=args.batch_workers,
                pattern=args.batch_pattern,
                timeout_sec=args.batch_timeout,
                min_size_bytes=args.batch_min_size,
                max_size_bytes=args.batch_max_size,
                unpack_payloads=bool(args.output or args.unpack_dir),
                unpack_out_dir=args.output or args.unpack_dir,
                output_dir=args.batch_out,
                json_out=args.batch_json,
                csv_out=args.batch_csv,
                html_out=args.batch_html,
                master_key=args.key,
            )
            batch_report = BatchForensicEngine.run(options)
            if args.format == "json":
                sys.stdout.write(json.dumps(batch_report.to_dict(), indent=2, ensure_ascii=False) + "\n")
            else:
                sys.stdout.write(BatchReporter.format_console_table(batch_report) + "\n")
            return 0
        except Exception as e:
            sys.stderr.write(f"[-] Batch forensic scan failed: {e}\n")
            return 1

    if not args.target:
        parser.print_usage(sys.stderr)
        sys.stderr.write("[-] Error: the following arguments are required: target\n")
        return 2

    # Multi-Engine Binary Diffing Mode
    if args.diff_target:
        try:
            from .diffing import BinaryDiffEngine, BinaryDiffOptions, DiffEngine, HTMLDiffReporter
            opts = BinaryDiffOptions(engine=DiffEngine(args.diff_engine.lower()), min_similarity_threshold=args.diff_threshold)
            diff_res = DotNetPackerCore.diff_binaries(args.target, args.diff_target, options=opts)
            if args.format == "json":
                sys.stdout.write(json.dumps(diff_res.to_dict(), indent=2) + "\n")
            else:
                sys.stdout.write(BinaryDiffEngine.format_text_diff(diff_res) + "\n")
            if args.diff_out:
                exp_diff = DotNetPackerCore.export_diff_report(diff_res, output_dir=args.diff_out)
                sys.stdout.write(f"[+] Exported {exp_diff['files_count']} diff report files to -> {args.diff_out}\n")
            if args.diff_html:
                with open(args.diff_html, "w", encoding="utf-8") as f:
                    f.write(HTMLDiffReporter.generate(diff_res))
                sys.stdout.write(f"[+] Exported visual HTML diff report to -> {args.diff_html}\n")
            if args.diff_json:
                with open(args.diff_json, "w", encoding="utf-8") as f:
                    json.dump(diff_res.to_dict(), f, indent=2)
                sys.stdout.write(f"[+] Exported JSON diff summary to -> {args.diff_json}\n")
            return 0
        except Exception as e:
            sys.stderr.write(f"[-] Binary diffing failed: {e}\n")
            return 1

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

    # De-flatten DeepSea control flow if requested
    if args.deflatten_deepsea:
        try:
            dest_path = args.deepsea_out or args.output or f"{args.target}.deflattened.exe"
            rebuilt_pe, ds_rep = DotNetPackerCore.deflatten_deepsea(args.target, output_path=dest_path)
            sys.stdout.write(f"[+] Successfully de-flattened DeepSea methods -> {dest_path}\n")
            if args.export_ast and ds_rep.get("methods"):
                ast_path = f"{dest_path}.ast.json"
                with open(ast_path, "w", encoding="utf-8") as f:
                    json.dump([m["ast"] for m in ds_rep["methods"]], f, indent=2)
                sys.stdout.write(f"    * Exported AST -> {ast_path}\n")
            if args.export_cfg and ds_rep.get("methods"):
                cfg_path = f"{dest_path}.cfg.dot"
                with open(cfg_path, "w", encoding="utf-8") as f:
                    f.write(ds_rep["methods"][0]["cfg_dot"])
                sys.stdout.write(f"    * Exported CFG -> {cfg_path}\n")
        except Exception as e:
            sys.stderr.write(f"[-] DeepSea de-flattening failed: {e}\n")

    # Restore Anti-Tamper protected assembly if requested
    if args.anti_tamper or args.anti_tamper_out:
        try:
            dest_path = args.anti_tamper_out or args.output or f"{args.target}.antitamper_restored.exe"
            rebuilt_pe, at_rep = DotNetPackerCore.restore_antitamper(
                args.target, output_path=dest_path, jit_dump_path=args.dump_jit
            )
            sys.stdout.write(
                f"[+] Successfully restored Anti-Tamper assembly -> {dest_path} ({len(rebuilt_pe):,} bytes)\n"
            )
            sys.stdout.write(f"    * Section Injected  : {at_rep.get('section_injected')}\n")
            sys.stdout.write(f"    * Methods Restored  : {at_rep.get('methods_restored_count', 0)}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Anti-Tamper restoration failed: {e}\n")

    # Anti-Tamper Directory Export
    if args.anti_tamper_dir:
        try:
            res = DotNetPackerCore.unpack_antitamper_dir(
                args.target, output_dir=args.anti_tamper_dir, jit_dump_path=args.dump_jit
            )
            sys.stdout.write(
                f"[+] Successfully unpacked Anti-Tamper artifacts ({res.get('methods_count', 0)} methods) -> {res.get('output_directory')}\n"
            )
        except Exception as e:
            sys.stderr.write(f"[-] Anti-Tamper directory export failed: {e}\n")

    # Heal Anti-Dump memory corruptions if requested
    if args.heal_dump or args.heal_out or args.scylla_mode:
        try:
            dest_path = args.heal_out or args.output or f"{args.target}.healed.exe"
            healed_pe, hd_rep = DotNetPackerCore.heal_anti_dump(args.target, output_path=dest_path)
            sys.stdout.write(
                f"[+] Successfully healed process dump -> {dest_path} ({len(healed_pe):,} bytes)\n"
            )
            telem = hd_rep.get("telemetry", {})
            sys.stdout.write(f"    * Dump Source       : {telem.get('dump_source', 'UNKNOWN')}\n")
            sys.stdout.write(f"    * Sections Healed   : {hd_rep.get('sections_count', len(hd_rep.get('sections', [])))}\n")
            if telem.get("bsjb_metadata_found"):
                sys.stdout.write(f"    * CLR Metadata BSJB : Found at {telem.get('bsjb_rva')}\n")
            if telem.get("iat_reconstructed"):
                sys.stdout.write("    * CLR Import IAT    : Synthesized mscoree.dll bootstrap\n")
        except Exception as e:
            sys.stderr.write(f"[-] Anti-Dump healing failed: {e}\n")

    # Anti-Dump directory export
    if args.anti_dump_dir:
        try:
            res = DotNetPackerCore.unpack_anti_dump_dir(args.target, output_dir=args.anti_dump_dir)
            sys.stdout.write(
                f"[+] Successfully exported healed dump & sections -> {res.get('output_dir')}\n"
            )
        except Exception as e:
            sys.stderr.write(f"[-] Anti-Dump directory export failed: {e}\n")

    # Native multi-architecture demuxing and routing
    if args.demux_native:
        try:
            res = DotNetPackerCore.demux_native(args.target)
            telem = res.get("telemetry", {})
            payloads = res.get("payloads", [])
            sys.stdout.write(f"[+] Native Demuxer Analysis: Found {len(payloads)} native payloads\n")
            sys.stdout.write(f"    * Architectures   : {', '.join(telem.get('architectures_found', [])) or 'None'}\n")
            sys.stdout.write(f"    * Target Platforms: {', '.join(telem.get('platforms_found', [])) or 'None'}\n")
            for p in payloads:
                mismatch_flag = " [!] MISMATCH" if p.get("mismatch_detected") else ""
                sys.stdout.write(
                    f"    -> {p.get('name')} (Arch: {p.get('target_arch')}{mismatch_flag}, Format: {p.get('format')}, Size: {p.get('size_bytes'):,} bytes)\n"
                )
        except Exception as e:
            sys.stderr.write(f"[-] Native demuxing failed: {e}\n")

    if args.demux_out:
        try:
            res = DotNetPackerCore.unpack_native_dir(
                args.target, output_dir=args.demux_out, target_arch=args.route_arch
            )
            sys.stdout.write(
                f"[+] Successfully demuxed and exported {res.get('total_extracted', 0)} native binaries -> {res.get('output_dir')}\n"
            )
            sys.stdout.write(f"    * Manifest: {res.get('manifest_path')}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Native demuxing export failed: {e}\n")

    if args.route_arch:
        try:
            route_res = DotNetPackerCore.route_native(args.target, target_os=args.route_os, target_arch=args.route_arch)
            sys.stdout.write(f"[+] Platform Route for '{args.route_os}-{args.route_arch}': {route_res.get('resolution_status')} ({route_res.get('reason')})\n")
            matched = route_res.get("matched_payload")
            if matched:
                sys.stdout.write(f"    * Matched Binary: {matched.get('name')} (Format: {matched.get('format')})\n")
        except Exception as e:
            sys.stderr.write(f"[-] Platform routing failed: {e}\n")



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

    # Automated Threat Hunting Rule Synthesis (YARA & Sigma)
    if args.gen_rules or args.gen_yara or args.gen_sigma or args.rules_out:
        rule_fmt = "combined"
        if args.gen_yara and not (args.gen_sigma or args.gen_rules):
            rule_fmt = "yara"
        elif args.gen_sigma and not (args.gen_yara or args.gen_rules):
            rule_fmt = "sigma"

        try:
            rule_res = DotNetPackerCore.generate_threat_rules(
                args.target, granularity=args.rule_level, rule_format=rule_fmt
            )
            sys.stdout.write(
                f"[+] Synthesized {len(rule_res.yara_rules)} YARA & {len(rule_res.sigma_rules)} Sigma rules ({args.rule_level.upper()} level)\n"
            )
            if args.gen_yara or (args.gen_rules and not args.rules_out):
                for yr in rule_res.yara_rules:
                    sys.stdout.write(f"\n--- [YARA: {yr.rule_name}] ---\n{yr.to_yara_string()}\n")
            if args.gen_sigma or (args.gen_rules and not args.rules_out):
                for sr in rule_res.sigma_rules:
                    sys.stdout.write(f"\n--- [SIGMA: {sr.title}] ---\n{sr.to_sigma_yaml()}\n")

            if args.rules_out:
                exp_res = DotNetPackerCore.export_threat_rules(
                    args.target, output_dir=args.rules_out, granularity=args.rule_level, rule_format=rule_fmt
                )
                sys.stdout.write(f"[+] Exported {len(exp_res['exported_files'])} rule files to -> {args.rules_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Threat rule synthesis failed: {e}\n")

    # Native Mixed-Mode C++/CLI (IJWH) Forensics & Transition Tracer
    if args.mixed_mode or args.trace_transitions or args.mixed_mode_out:
        try:
            mm_res = DotNetPackerCore.analyze_mixed_mode(args.target)
            mt = mm_res.telemetry
            sys.stdout.write(f"[+] Mixed-Mode: {mt.mixed_mode_type} (Risk: {mt.risk_severity.upper()}, Score: {mt.risk_score}/100)\n")
            if args.trace_transitions:
                sys.stdout.write(f"\n--- [CIL <-> Native Transitions: {len(mm_res.transitions)}] ---\n")
                for tr in mm_res.transitions:
                    sys.stdout.write(f"  [{tr.transition_id}] {tr.direction.value.upper()}: {tr.source_location} -> {tr.target_location} ({tr.description})\n")
            if args.mixed_mode_out:
                exp_mm = DotNetPackerCore.export_mixed_mode(args.target, output_dir=args.mixed_mode_out)
                sys.stdout.write(f"[+] Exported {len(exp_mm['exported_files'])} mixed-mode files to -> {args.mixed_mode_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Mixed-mode analysis failed: {e}\n")

    # CIL Control Flow Graph (CFG) & High-Entropy Block Diagnostics
    if args.cfg or args.cfg_out or args.cfg_token:
        try:
            cfg_res = DotNetPackerCore.analyze_cfg(args.target)
            sys.stdout.write(f"[+] CIL CFG Analysis: {cfg_res.telemetry.total_methods_analyzed} methods ({cfg_res.telemetry.total_blocks} blocks, {cfg_res.telemetry.total_edges} edges, peak complexity={cfg_res.telemetry.max_cyclomatic_complexity})\n")
            if cfg_res.telemetry.high_entropy_blocks_total > 0:
                sys.stdout.write(f"    [!] Identified {cfg_res.telemetry.high_entropy_blocks_total} high-entropy encrypted/packed basic blocks\n")
            if cfg_res.telemetry.suspicious_methods:
                sys.stdout.write("    [!] Suspicious Methods:\n")
                for sm in cfg_res.telemetry.suspicious_methods[:4]:
                    sys.stdout.write(f"        * {sm}\n")
            if args.cfg_out:
                formats = [args.cfg_format] if args.cfg_format != "all" else None
                exp_cfg = DotNetPackerCore.export_cfg(args.target, output_dir=args.cfg_out, formats=formats)
                sys.stdout.write(f"[+] Exported {exp_cfg['exported_files_count']} CFG diagram files to -> {args.cfg_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] CFG analysis failed: {e}\n")

    # WPF BAML & Embedded UI Resource Decompiler
    if args.baml or args.baml_out:
        try:
            baml_res = DotNetPackerCore.analyze_baml(args.target)
            sys.stdout.write(f"[+] WPF BAML Extraction: {len(baml_res.decompiled_items)} UI docs ({baml_res.telemetry.total_elements} elements, {baml_res.telemetry.total_attributes} props)\n")
            if baml_res.suspicious_findings:
                sys.stdout.write(f"    [!] Identified {len(baml_res.suspicious_findings)} UI security anomaly findings:\n")
                for finding in baml_res.suspicious_findings[:4]:
                    sys.stdout.write(f"        * {finding}\n")
            if args.baml_out:
                exp_baml = DotNetPackerCore.export_baml(args.target, output_dir=args.baml_out, export_raw_baml=args.baml_raw)
                sys.stdout.write(f"[+] Exported {len(exp_baml['exported_files'])} XAML and manifest files to -> {args.baml_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] BAML decompiler failed: {e}\n")

    # Native AOT & ReadyToRun (R2R) Forensics
    if args.native_aot or args.r2r_disasm or args.aot_symbols or args.native_aot_out:
        try:
            aot_res = DotNetPackerCore.analyze_native_aot(args.target, max_methods=args.native_aot_max_methods)
            at = aot_res.telemetry
            sys.stdout.write(f"[+] Native AOT / R2R Inspection: {at.compilation_type} ({at.inferred_dotnet_version}) - Arch: {at.target_arch.upper()}\n")
            if at.compiler_identifier:
                sys.stdout.write(f"    Compiler ID: {at.compiler_identifier}\n")
            if at.r2r_sections_count > 0:
                sys.stdout.write(f"    R2R Sections: {at.r2r_sections_count} sections, {at.runtime_functions_count} methods\n")
            if args.aot_symbols and aot_res.symbols:
                sys.stdout.write(f"\n--- [Recovered Native Symbols: {len(aot_res.symbols)}] ---\n")
                for s in aot_res.symbols[:20]:
                    tok = f"0x{s.token:08X}" if s.token else "N/A"
                    sys.stdout.write(f"  [{tok}] {hex(s.rva)}: {s.demangled_name} ({s.symbol_type})\n")
            if args.r2r_disasm and aot_res.disassembled_methods:
                sys.stdout.write(f"\n--- [Disassembled Methods: {len(aot_res.disassembled_methods)}] ---\n")
                for dm in aot_res.disassembled_methods[:5]:
                    sys.stdout.write(f"=== Method: {dm.name} ({dm.blocks_count} blocks, {dm.calls_count} calls) ===\n")
                    for ins in dm.instructions[:8]:
                        target = f" -> {hex(ins.target_rva)}" if ins.target_rva else ""
                        helper = f" <{ins.helper_name}>" if ins.helper_name else ""
                        sys.stdout.write(f"  0x{ins.offset:08X}:  {ins.raw_bytes:<12} {ins.mnemonic:<6} {ins.operands}{target}{helper}\n")
            if args.native_aot_out:
                exp_aot = DotNetPackerCore.export_native_aot(args.target, output_dir=args.native_aot_out, max_methods=args.native_aot_max_methods)
                sys.stdout.write(f"[+] Exported {len(exp_aot['exported_files'])} AOT/R2R forensic files to -> {args.native_aot_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Native AOT / R2R analysis failed: {e}\n")

    # Kernel Memory Dump Carving & Residual CIL Forensics
    if args.dump_carver or args.dump_extract_methods or args.dump_out:
        try:
            dump_res = DotNetPackerCore.carve_dump(
                args.target, min_confidence=args.dump_min_confidence, max_methods=args.dump_max_methods
            )
            dt = dump_res.telemetry
            sys.stdout.write(
                f"[+] Memory Dump Carving: {dt.dump_format.upper()} ({dt.dump_size:,}b, {dt.memory_ranges_scanned} ranges, "
                f"{dt.bsjb_roots_found} roots, {dt.assemblies_carved} asms, {dt.methods_recovered} methods)\n"
            )
            if dump_res.carved_assemblies:
                sys.stdout.write(f"\n--- [Carved Assemblies: {len(dump_res.carved_assemblies)}] ---\n")
                for asm in dump_res.carved_assemblies:
                    sys.stdout.write(f"  * {asm.identifier}: {asm.name} (v{asm.version}) - Conf: {asm.confidence*100:.0f}%, SHA256: {asm.sha256[:16]}...\n")
            if args.dump_extract_methods and dump_res.residual_methods:
                sys.stdout.write(f"\n--- [Recovered Residual Methods: {len(dump_res.residual_methods)}] ---\n")
                for m in dump_res.residual_methods[:10]:
                    sys.stdout.write(f"  [0x{m.token:08X} @ {hex(m.offset)}] {m.format.upper()} ({m.code_size}b) - Entropy: {m.entropy:.2f}\n")
            if args.dump_out:
                exp_dump = DotNetPackerCore.export_carved_dump(
                    args.target, output_dir=args.dump_out, min_confidence=args.dump_min_confidence, max_methods=args.dump_max_methods,
                )
                sys.stdout.write(f"[+] Exported {len(exp_dump['exported_files'])} carved dump files to -> {args.dump_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Memory dump carving failed: {e}\n")

    # Ghidra & IDA Pro Decompiler Headless Bridge
    if args.decompiler_bridge or args.bridge_out:
        try:
            br_res = DotNetPackerCore.generate_decompiler_bridge(
                args.target, engine=args.bridge_engine, base_addr=args.bridge_base_addr, min_confidence=args.bridge_min_confidence,
            )
            bt = br_res.telemetry
            sys.stdout.write(f"[+] Decompiler Bridge: {br_res.engine.value.upper()} ({bt.total_symbols} syms, {bt.total_comments} cmts, {bt.total_bookmarks} bms @ {hex(br_res.base_addr)})\n")
            if br_res.symbols:
                sys.stdout.write(f"\n--- [Synchronized Decompiler Symbols: {len(br_res.symbols)}] ---\n")
                for s in br_res.symbols[:10]:
                    sys.stdout.write(f"  [0x{s.rva:08X}] {s.name} ({s.symbol_type.value}) - Conf: {s.confidence*100:.0f}%\n")
                if len(br_res.symbols) > 10:
                    sys.stdout.write(f"  ... and {len(br_res.symbols) - 10} more symbols\n")
            if args.bridge_out:
                exp_br = DotNetPackerCore.export_decompiler_bridge(
                    args.target, output_dir=args.bridge_out, engine=args.bridge_engine, base_addr=args.bridge_base_addr, min_confidence=args.bridge_min_confidence,
                )
                sys.stdout.write(f"[+] Exported {len(exp_br['exported_files'])} decompiler bridge files to -> {args.bridge_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Decompiler bridge generation failed: {e}\n")

    # JIT Compilation Tracing & Bytecode Capture Harness
    if args.jit_trace or args.jit_trace_log or args.jit_out:
        try:
            from .jit_tracer import JITCaptureOptions, JITTracerEngine, OptimizationTier
            tier_map = {
                "minopt": OptimizationTier.TIER_0_MINOPT,
                "quickjit": OptimizationTier.TIER_0_QUICKJIT,
                "optimized": OptimizationTier.TIER_1_OPTIMIZED,
            }
            jit_opts = JITCaptureOptions(
                emulate_unpacker=True,
                max_methods=args.jit_max_methods,
                export_reconstructed_pe=args.jit_restore_pe or bool(args.jit_out),
                target_tier=tier_map.get(args.jit_tier, OptimizationTier.TIER_0_MINOPT),
            )
            if args.jit_trace_log:
                jit_res = JITTracerEngine.parse_trace_file(
                    args.jit_trace_log, base_binary_path=args.target, options=jit_opts
                )
            else:
                jit_res = DotNetPackerCore.trace_jit_compilation(args.target, options=jit_opts)

            sys.stdout.write(
                f"[+] JIT Compilation Tracing: {jit_res.telemetry.methods_captured} methods captured "
                f"({jit_res.telemetry.methods_validated} validated, {jit_res.telemetry.total_bytes_captured} bytes, "
                f"{jit_res.telemetry.hooks_detected} hooks detected)\n"
            )
            if jit_res.hooks:
                sys.stdout.write(f"\n--- [Active JIT Hooks: {len(jit_res.hooks)}] ---\n")
                for h in jit_res.hooks[:5]:
                    sys.stdout.write(f"  * {h.hook_type.value}: {h.target_module} ({h.hook_pattern}) - Conf: {h.confidence*100:.0f}%\n")
            if jit_res.captured_methods:
                sys.stdout.write(f"\n--- [Captured CIL Methods: {len(jit_res.captured_methods)}] ---\n")
                for cm in jit_res.captured_methods[:6]:
                    sys.stdout.write(f"  [0x{cm.token:08X} @ {hex(cm.rva)}] {cm.name}: {cm.il_size}b ({cm.header_format}) - {cm.state.value}\n")
            if args.jit_out:
                exp_jit = JITTracerEngine.export_to_directory(jit_res, output_dir=args.jit_out)
                sys.stdout.write(f"[+] Exported {len(exp_jit['exported_files'])} JIT capture files to -> {args.jit_out}\n")
        except Exception as e:
            sys.stderr.write(f"[-] JIT compilation tracing failed: {e}\n")

    if args.format == "json":
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        sys.stdout.write(format_text_report(report, verbose=args.verbose) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
