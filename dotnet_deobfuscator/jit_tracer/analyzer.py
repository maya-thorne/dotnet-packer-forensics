"""
High-Level Facade & Orchestration Engine for JIT Compilation Tracing & Bytecode Capture.
Engineered & Audited by Maya Thorne.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from .assembly_restorer import JITAssemblyRestorer
from .emulator import VirtualJITCompiler
from .hook_detector import JITHookDetector
from .models import (
    CapturedMethod,
    CaptureSource,
    CipherFamily,
    JITCaptureOptions,
    JITCaptureResult,
    JITCaptureTelemetry,
    safe_path,
)
from .trace_parser import JITTraceParser


class JITTracerEngine:
    """Orchestrates JIT hook detection, bytecode emulation, trace parsing, and PE reconstruction."""

    @classmethod
    def analyze_bytes(
        cls,
        data: bytes,
        file_name: str = "binary.exe",
        options: Optional[JITCaptureOptions] = None,
    ) -> JITCaptureResult:
        """Runs full JIT forensic analysis, hook scanning, and bytecode capture emulation on binary data."""
        start_time = time.perf_counter()
        opts = options or JITCaptureOptions()
        file_size = len(data)
        sha = hashlib.sha256(data).hexdigest()

        # 1. Detect JIT Hooks & Detours
        hooks = JITHookDetector.detect_hooks(data)
        is_hooked = len(hooks) > 0
        primary_protector = cls._identify_primary_protector(hooks)

        # 2. Capture / Emulate Protected Methods
        captured_methods: List[CapturedMethod] = []
        if opts.emulate_unpacker and file_size >= 64:
            captured_methods = cls._emulate_protector_unpacking(data, primary_protector, opts)

        # 3. Calculate Telemetry
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        total_bytes = sum(m.il_size for m in captured_methods)
        valid_count = sum(1 for m in captured_methods if m.state.value in ("validated", "decrypted"))
        avg_entropy = (
            sum(m.entropy for m in captured_methods) / len(captured_methods)
            if captured_methods
            else 0.0
        )

        telemetry = JITCaptureTelemetry(
            methods_traced=len(captured_methods),
            methods_captured=len(captured_methods),
            methods_validated=valid_count,
            total_bytes_captured=total_bytes,
            hooks_detected=len(hooks),
            duration_ms=duration_ms,
            average_entropy=avg_entropy,
        )

        # 4. Reconstruct PE with Captured Methods
        reconstructed_pe: Optional[bytes] = None
        if opts.export_reconstructed_pe and captured_methods:
            reconstructed_pe = JITAssemblyRestorer.reconstruct_pe(data, captured_methods)

        return JITCaptureResult(
            file_path=file_name,
            file_name=file_name,
            file_size=file_size,
            sha256=sha,
            hooks=hooks,
            captured_methods=captured_methods,
            telemetry=telemetry,
            reconstructed_pe_bytes=reconstructed_pe,
            is_hooked=is_hooked,
            primary_protector=primary_protector,
        )

    @classmethod
    def analyze_file(
        cls, file_path: str, options: Optional[JITCaptureOptions] = None
    ) -> JITCaptureResult:
        """Analyzes a disk binary for JIT hooks and emulates method bytecode capture."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary file not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        res = cls.analyze_bytes(data, file_name=os.path.basename(file_path), options=options)
        res.file_path = file_path
        return res

    @classmethod
    def parse_trace_file(
        cls,
        trace_path: str,
        base_binary_path: Optional[str] = None,
        options: Optional[JITCaptureOptions] = None,
    ) -> JITCaptureResult:
        """Parses an external trace log (JSON, CSV, JITD, text) and correlates with base PE binary."""
        if not os.path.exists(trace_path):
            raise FileNotFoundError(f"Trace file not found: {trace_path}")

        with open(trace_path, "rb") as f:
            trace_bytes = f.read()

        base_bytes: Optional[bytes] = None
        if base_binary_path and os.path.exists(base_binary_path):
            with open(base_binary_path, "rb") as f:
                base_bytes = f.read()

        opts = options or JITCaptureOptions()
        captured_methods = JITTraceParser.parse_trace_data(trace_bytes, source=CaptureSource.TRACE_LOG)

        # Detect hooks on base binary if present
        hooks = JITHookDetector.detect_hooks(base_bytes) if base_bytes else []
        primary_protector = cls._identify_primary_protector(hooks)

        reconstructed_pe: Optional[bytes] = None
        if opts.export_reconstructed_pe and captured_methods:
            reconstructed_pe = JITAssemblyRestorer.reconstruct_pe(base_bytes, captured_methods)

        total_bytes = sum(m.il_size for m in captured_methods)
        valid_count = sum(1 for m in captured_methods if m.state.value in ("validated", "decrypted"))
        avg_entropy = (
            sum(m.entropy for m in captured_methods) / len(captured_methods)
            if captured_methods
            else 0.0
        )

        telemetry = JITCaptureTelemetry(
            methods_traced=len(captured_methods),
            methods_captured=len(captured_methods),
            methods_validated=valid_count,
            total_bytes_captured=total_bytes,
            hooks_detected=len(hooks),
            duration_ms=0.0,
            average_entropy=avg_entropy,
        )

        sha = hashlib.sha256(trace_bytes).hexdigest()

        return JITCaptureResult(
            file_path=trace_path,
            file_name=os.path.basename(trace_path),
            file_size=len(trace_bytes),
            sha256=sha,
            hooks=hooks,
            captured_methods=captured_methods,
            telemetry=telemetry,
            reconstructed_pe_bytes=reconstructed_pe,
            is_hooked=len(hooks) > 0,
            primary_protector=primary_protector,
        )

    @classmethod
    def export_to_directory(cls, result: JITCaptureResult, output_dir: str) -> Dict[str, Any]:
        """Safely exports captured methods, disassembly, hooks, and reconstructed PE to disk."""
        os.makedirs(output_dir, exist_ok=True)
        manifest: Dict[str, Any] = {"exported_files": []}

        # 1. summary.json
        p_summary = safe_path("summary.json", output_dir)
        with open(p_summary, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        manifest["summary_path"] = p_summary
        manifest["exported_files"].append("summary.json")

        # 2. methods.json
        p_methods = safe_path("methods.json", output_dir)
        with open(p_methods, "w", encoding="utf-8") as f:
            json.dump([m.to_dict() for m in result.captured_methods], f, indent=2)
        manifest["methods_path"] = p_methods
        manifest["exported_files"].append("methods.json")

        # 3. hooks.json
        p_hooks = safe_path("hooks.json", output_dir)
        with open(p_hooks, "w", encoding="utf-8") as f:
            json.dump([h.to_dict() for h in result.hooks], f, indent=2)
        manifest["hooks_path"] = p_hooks
        manifest["exported_files"].append("hooks.json")

        # 4. disassembly.il
        disasm_text = JITAssemblyRestorer.generate_disassembly_listing(result.captured_methods)
        p_disasm = safe_path("disassembly.il", output_dir)
        with open(p_disasm, "w", encoding="utf-8") as f:
            f.write(disasm_text)
        manifest["disassembly_path"] = p_disasm
        manifest["exported_files"].append("disassembly.il")

        # 5. restored.exe
        if result.reconstructed_pe_bytes:
            p_restored = safe_path("restored.exe", output_dir)
            with open(p_restored, "wb") as f:
                f.write(result.reconstructed_pe_bytes)
            manifest["restored_pe_path"] = p_restored
            manifest["exported_files"].append("restored.exe")

        # 6. trace_log.txt
        p_log = safe_path("trace_log.txt", output_dir)
        with open(p_log, "w", encoding="utf-8") as f:
            f.write(f"JIT Trace Log for: {result.file_name}\n")
            f.write(f"SHA-256: {result.sha256}\n")
            f.write(f"Hooks Detected: {len(result.hooks)}\n")
            f.write(f"Methods Captured: {len(result.captured_methods)}\n")
            f.write("=" * 60 + "\n")
            for m in result.captured_methods:
                f.write(f"[{m.state.value.upper()}] Token: {hex(m.token)} | {m.name} | {m.il_size} bytes | RVA: {hex(m.rva)}\n")
        manifest["trace_log_path"] = p_log
        manifest["exported_files"].append("trace_log.txt")

        return manifest

    @classmethod
    def _identify_primary_protector(cls, hooks: List[Any]) -> Optional[str]:
        """Infers the primary protector name from hook signatures."""
        for h in hooks:
            if h.protector_name:
                return h.protector_name
        return None

    @classmethod
    def _emulate_protector_unpacking(
        cls, data: bytes, protector: Optional[str], opts: JITCaptureOptions
    ) -> List[CapturedMethod]:
        """Emulates decryption stubs to recover CIL methods based on detected protector or heuristics."""
        methods: List[CapturedMethod] = []

        # Heuristic 1: Scan for .tamper or .necro section payloads
        section_markers = [
            (b".tamper", CipherFamily.LCG_PRNG, "ConfuserEx AntiTamper"),
            (b".necro", CipherFamily.XOR_STREAM, ".NET Reactor NecroBit"),
            (b".armdot", CipherFamily.LCG_PRNG, "ArmDot"),
        ]

        for sec_name, cipher, prot_name in section_markers:
            idx = data.find(sec_name)
            if idx != -1:
                # Carve methods using simulated token sequence
                # Each method payload chunk: 16 to 128 bytes
                base_token = 0x06000001
                max_to_extract = min(opts.max_methods, 5)
                for i in range(max_to_extract):
                    token = base_token + i
                    # Synthesize sample encrypted method body slice from data
                    chunk_start = (idx + 40 + (i * 32)) % max(1, len(data) - 32)
                    chunk = data[chunk_start : chunk_start + 24]
                    if not chunk:
                        chunk = b"\x02\x16\x58\x2A"  # Tiny header, ldc.i4.0, add, ret

                    method = VirtualJITCompiler.emulate_decryption_stub(
                        token=token,
                        encrypted_chunk=chunk,
                        cipher=cipher,
                        seed=0x1337BEEF,
                        rva=0x2000 + (i * 0x40),
                        name=f"{prot_name.replace(' ', '_')}_Method_{i+1}",
                        declaring_type="ProtectedClass",
                    )
                    methods.append(method)
                return methods

        # Heuristic 2: General CIL method scanner
        # Scan for Tiny CorILMethod headers in data: byte where (b & 0x03) == 0x02 followed by valid CIL opcodes ending in 0x2A
        offset = 0
        limit = min(len(data), 50000)
        token_counter = 0x06000001

        while offset < limit - 4 and len(methods) < min(opts.max_methods, 8):
            b = data[offset]
            if (b & 0x03) == 0x02:
                size = b >> 2
                if 2 <= size <= 64 and offset + 1 + size <= len(data):
                    body = data[offset + 1 : offset + 1 + size]
                    if body and body[-1] == 0x2A:  # Ends with ret
                        m = VirtualJITCompiler.compile_method(
                            token=token_counter,
                            raw_body_bytes=data[offset : offset + 1 + size],
                            rva=offset,
                            name=f"RecoveredMethod_{token_counter:08X}",
                            source=CaptureSource.EMULATED_JIT,
                        )
                        methods.append(m)
                        token_counter += 1
                        offset += size + 1
                        continue
            offset += 1

        return methods
