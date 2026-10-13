"""
Forensic Analysis Telemetry Collector & Dictionary Aggregator.
Engineered & Audited by Maya Thorne.
"""

from typing import Any, Dict, List, Optional


def build_analysis_report(
    file_path: str,
    file_size: int,
    elapsed_ms: float,
    hashes: Dict[str, str],
    assembly_info: Dict[str, Any],
    detected_protectors: List[Dict[str, Any]],
    pe_diag: Dict[str, Any],
    overlay_bytes: bytes,
    pe_size: int,
    xor_result: Optional[Dict[str, Any]],
    costura_detect: Dict[str, Any],
    costura_payloads: List[Dict[str, Any]],
    confuser_detect: Dict[str, Any],
    confuser_payloads: List[Dict[str, Any]],
    confuser_strings_list: List[str],
    reactor_detect: Dict[str, Any],
    reactor_payloads: List[Dict[str, Any]],
    reactor_methods: Dict[int, Dict[str, Any]],
    eaz_detect: Dict[str, Any],
    eaz_containers: List[Dict[str, Any]],
    babel_detect: Dict[str, Any],
    babel_merged: List[Dict[str, Any]],
    armdot_detect: Dict[str, Any],
    armdot_containers: List[Dict[str, Any]],
    intellilock_detect: Dict[str, Any],
    deepsea_detect: Dict[str, Any],
    antitamper_detect: Dict[str, Any],
    antidump_detect: Dict[str, Any],
) -> Dict[str, Any]:
    """Assembles all subsystem forensic findings into a unified analysis report dictionary."""
    return {
        "file": file_path,
        "size_bytes": file_size,
        "elapsed_ms": elapsed_ms,
        "sha256": hashes["sha256"],
        "hashes": hashes,
        "is_pe": assembly_info["is_pe"],
        "is_dotnet": assembly_info["is_dotnet"],
        "entropy": assembly_info["entropy"],
        "sections": assembly_info["sections"],
        "metadata_streams": assembly_info["metadata_streams"],
        "suspicious_indicators": assembly_info["suspicious_indicators"],
        "detected_protectors": detected_protectors,
        "pe_rebuilder": {
            "is_valid_pe": assembly_info["is_pe"],
            "is_memory_dump": pe_diag["is_memory_dump"],
            "anomalies_detected": pe_diag["anomalies"],
            "anomalies_count": len(pe_diag["anomalies"]),
            "repair_recommended": len(pe_diag["anomalies"]) > 0,
        },
        "overlay": {
            "has_overlay": len(overlay_bytes) > 0,
            "overlay_size_bytes": len(overlay_bytes),
            "pe_virtual_size": pe_size,
        },
        "unpacked_payload": {
            "success": xor_result is not None,
            "details": (
                {
                    "sentinel_offset": xor_result["sentinel_offset"],
                    "dynamic_key": xor_result["dynamic_key_recovered"],
                    "payload_size": len(xor_result["decrypted_payload_bytes"]),
                    "is_valid_pe": xor_result["is_valid_pe"],
                }
                if xor_result
                else None
            ),
        },
        "costura": {
            "detected": costura_detect["is_costura"],
            "confidence": costura_detect["confidence"],
            "payloads_count": len(costura_payloads),
            "payloads": [
                {
                    "original_name": p["original_name"],
                    "output_filename": p["output_filename"],
                    "compressed_size_bytes": p["compressed_size_bytes"],
                    "size_bytes": p["size_bytes"],
                    "sha256": p["sha256"],
                    "is_pe": p["is_pe"],
                    "is_pdb": p["is_pdb"],
                    "entropy": p["entropy"],
                }
                for p in costura_payloads
            ],
        },
        "confuserex": {
            "detected": confuser_detect["is_confuserex"],
            "confidence": confuser_detect["confidence"],
            "detected_protections": confuser_detect["detected_protections"],
            "markers_found": confuser_detect["markers_found"],
            "obfuscated_names_count": confuser_detect["obfuscated_names_count"],
            "has_antidump": confuser_detect["has_antidump"],
            "has_antitamper": confuser_detect["has_antitamper"],
            "has_constants": confuser_detect["has_constants"],
            "has_resources": confuser_detect["has_resources"],
            "decrypted_strings_count": len(confuser_strings_list),
            "decrypted_strings": confuser_strings_list[:100],
            "resources_count": len(confuser_payloads),
            "resources": [
                {
                    "original_name": r["original_name"],
                    "output_filename": r["output_filename"],
                    "size_bytes": r["size_bytes"],
                    "sha256": r["sha256"],
                    "is_pe": r["is_pe"],
                    "resource_type": r.get("resource_type", "Binary Resource"),
                    "entropy": r["entropy"],
                }
                for r in confuser_payloads
            ],
        },
        "reactor": {
            "detected": reactor_detect["is_reactor"],
            "confidence": reactor_detect["confidence"],
            "is_native_envelope": reactor_detect["is_native_envelope"],
            "has_necrobit": reactor_detect["has_necrobit"],
            "markers_found": reactor_detect["markers_found"],
            "methods_count": len(reactor_methods),
            "restored_methods": [
                {"token": m["token"], "header_format": m["header_format"], "code_size": m["code_size"], "is_valid_cil": m["is_valid_cil"]}
                for m in reactor_methods.values()
            ][:50],
            "payloads_count": len(reactor_payloads),
            "payloads": [
                {"output_filename": p["output_filename"], "size_bytes": p["size_bytes"], "sha256": p["sha256"], "artifact_type": p["artifact_type"]}
                for p in reactor_payloads
            ],
        },
        "eazfuscator": {
            "detected": eaz_detect["is_eazfuscator"],
            "confidence": eaz_detect["confidence"],
            "has_virtual_machine": eaz_detect["has_virtual_machine"],
            "vm_method_count": eaz_detect["vm_method_count"],
            "vm_containers_count": eaz_detect["vm_containers_count"],
            "matched_markers": eaz_detect["matched_markers"],
            "containers": [
                {"offset": f"0x{c['offset']:X}", "magic": c["magic"], "version": c["version"], "method_count": c["method_count"], "tokens": [m["token_hex"] for m in c.get("methods", [])]}
                for c in eaz_containers
            ],
        },
        "babel": {
            "detected": babel_detect["is_babel"],
            "confidence": babel_detect["confidence"],
            "has_merged_assemblies": babel_detect["has_merged_assemblies"],
            "merged_assemblies_count": babel_detect["merged_assemblies_count"],
            "has_embedded_map": babel_detect["has_embedded_map"],
            "obfuscated_symbols_count": babel_detect["obfuscated_symbols_count"],
            "markers_found": babel_detect["markers_found"],
            "merged_assemblies": [
                {"original_name": m["original_name"], "output_filename": m["output_filename"], "size_bytes": m["size_bytes"], "sha256": m["sha256"], "is_pe": m["is_pe"], "compression": m["compression"], "entropy": m["entropy"]}
                for m in babel_merged
            ],
        },
        "armdot": {
            "detected": armdot_detect["is_armdot"],
            "confidence": armdot_detect["confidence"],
            "has_virtual_machine": armdot_detect["has_virtual_machine"],
            "vm_method_count": armdot_detect["vm_method_count"],
            "vm_containers_count": armdot_detect["vm_containers_count"],
            "matched_markers": armdot_detect["matched_markers"],
            "containers": [
                {"offset": f"0x{c['offset']:X}", "magic": c["magic"], "version": c["version"], "method_count": c["method_count"], "tokens": [m["token_hex"] for m in c.get("methods", [])]}
                for c in armdot_containers
            ],
        },
        "intellilock": {
            "detected": intellilock_detect["is_intellilock"],
            "confidence": intellilock_detect["confidence"],
            "is_enveloped": intellilock_detect["is_enveloped"],
            "has_hardware_lock": intellilock_detect["has_hardware_lock"],
            "has_trial_expiration": intellilock_detect["has_trial_expiration"],
            "markers_found": intellilock_detect["markers_found"],
            "sections_matched": intellilock_detect["sections_matched"],
        },
        "deepsea": {
            "detected": deepsea_detect["is_deepsea"],
            "confidence": deepsea_detect["confidence"],
            "matched_markers": deepsea_detect["matched_markers"],
            "switch_density": deepsea_detect["switch_density"],
            "state_var_density": deepsea_detect["state_var_density"],
        },
        "anti_tamper": {
            "detected": antitamper_detect["is_tampered"],
            "confidence": antitamper_detect["confidence"],
            "detected_types": antitamper_detect["detected_types"],
            "encrypted_methods_count": antitamper_detect["encrypted_methods_count"],
            "corrupted_streams": antitamper_detect["corrupted_streams"],
            "jit_signatures": antitamper_detect["jit_signatures"],
            "anti_tamper_sections": antitamper_detect["anti_tamper_sections"],
        },
        "anti_dump": {
            "detected": antidump_detect["is_anti_dump"],
            "confidence": antidump_detect["confidence"],
            "dump_source": antidump_detect["dump_source"],
            "detected_techniques": antidump_detect["detected_techniques"],
            "original_header_intact": antidump_detect["original_header_intact"],
            "bsjb_found": antidump_detect["bsjb_found"],
            "bsjb_rva": antidump_detect["bsjb_rva"],
            "cor20_recovered": antidump_detect["cor20_recovered"],
            "anomalies": antidump_detect["anomalies"],
        },
    }
