"""
Static Inspection & Signature Detection of CLR JIT Hooks.
Engineered & Audited by Maya Thorne.
"""

import re
import struct
from typing import List, Optional, Tuple

from .models import JITHookSignature, JITHookType


class JITHookDetector:
    """Detects CLR JIT hooks, VTable hijacks, and protector detour trampolines."""

    # Known JIT DLLs and runtime functions
    KNOWN_JIT_MODULES = [
        b"clrjit.dll",
        b"mscorjit.dll",
        b"clr.dll",
        b"coreclr.dll",
        b"mscoree.dll",
        b"mscorwks.dll",
    ]

    KNOWN_JIT_EXPORTS = [
        b"getJit",
        b"jitStartup",
        b"sxsJitStartup",
        b"ICorJitCompiler",
        b"compileMethod",
        b"_CorExeMain",
        b"_CorDllMain",
    ]

    # Native JIT hook bytecode detour patterns (x86 & x64)
    # E9 xx xx xx xx -> jmp rel32
    PATTERN_REL32_JMP = re.compile(rb"\xE9(....)", re.DOTALL)
    # FF 25 00 00 00 00 -> jmp [rip + 0] (64-bit absolute indirect jump)
    PATTERN_RIP_INDIRECT_JMP = re.compile(rb"\xFF\x25\x00\x00\x00\x00(........)", re.DOTALL)
    # 48 B8 xx xx xx xx xx xx xx xx 50 C3 -> mov rax, imm64; push rax; ret
    PATTERN_MOV_PUSH_RET = re.compile(rb"\x48\xB8(........)\x50\xC3", re.DOTALL)
    # 48 B8 xx xx xx xx xx xx xx xx FF E0 -> mov rax, imm64; jmp rax
    PATTERN_MOV_JMP_RAX = re.compile(rb"\x48\xB8(........)\xFF\xE0", re.DOTALL)

    @classmethod
    def detect_hooks(cls, data: bytes) -> List[JITHookSignature]:
        """
        Inspects binary buffer for active JIT compilation hooks,
        VTable overrides, and protector method interception stubs.
        """
        if not data or len(data) < 64:
            return []

        signatures: List[JITHookSignature] = []

        # 1. Inspect JIT Module & Function References
        cls._scan_module_imports(data, signatures)

        # 2. Inspect Protector JIT Hook Signatures
        cls._scan_protector_jit_patterns(data, signatures)

        # 3. Inspect Native Machine Code Detour Trampolines
        cls._scan_native_detours(data, signatures)

        # 4. Inspect VTable Slot 0 Manipulation
        cls._scan_vtable_overrides(data, signatures)

        return signatures

    @classmethod
    def _scan_module_imports(cls, data: bytes, out: List[JITHookSignature]) -> None:
        """Identifies references to clrjit/mscorjit libraries and compilation exports."""
        lower_data = data.lower()
        for mod in cls.KNOWN_JIT_MODULES:
            idx = lower_data.find(mod)
            if idx != -1:
                rva = idx  # Approximate byte offset
                out.append(
                    JITHookSignature(
                        hook_type=JITHookType.CORJIT_COMPILEMETHOD,
                        target_module=mod.decode("ascii", errors="ignore"),
                        hook_pattern="import_reference",
                        detected_rva=rva,
                        confidence=0.85,
                        description=f"Direct import/string reference to CLR JIT runtime module: {mod.decode('ascii', errors='ignore')}",
                    )
                )

        for fn in cls.KNOWN_JIT_EXPORTS:
            idx = data.find(fn)
            if idx != -1:
                out.append(
                    JITHookSignature(
                        hook_type=JITHookType.CORJIT_COMPILEMETHOD,
                        target_module="clrjit.dll",
                        hook_pattern="export_reference",
                        detected_rva=idx,
                        confidence=0.80,
                        description=f"Reference to CLR JIT compilation export or interface: {fn.decode('ascii', errors='ignore')}",
                    )
                )

    @classmethod
    def _scan_protector_jit_patterns(cls, data: bytes, out: List[JITHookSignature]) -> None:
        """Detects known protector JIT interceptors (ConfuserEx, Reactor, ILProtector)."""
        # ConfuserEx AntiTamper JIT Hook
        if b".tamper" in data or (b"AntiTamper" in data and b"ConfusedByAttribute" in data):
            idx = data.find(b".tamper") if b".tamper" in data else data.find(b"AntiTamper")
            out.append(
                JITHookSignature(
                    hook_type=JITHookType.CUSTOM_CLR_HOOK,
                    target_module="clr.dll",
                    hook_pattern="confuserex_antitamper_vtable",
                    detected_rva=max(0, idx),
                    confidence=0.98,
                    description="ConfuserEx Anti-Tamper dynamic JIT method decryption hook",
                    protector_name="ConfuserEx AntiTamper",
                )
            )

        # .NET Reactor NecroBit JIT Hook
        if b".necro" in data or b"NecroBit" in data:
            idx = data.find(b".necro") if b".necro" in data else data.find(b"NecroBit")
            out.append(
                JITHookSignature(
                    hook_type=JITHookType.CORJIT_COMPILEMETHOD,
                    target_module="mscorjit.dll",
                    hook_pattern="reactor_necrobit_vtable_slot0",
                    detected_rva=max(0, idx),
                    confidence=0.98,
                    description=".NET Reactor NecroBit native envelope ICorJitCompiler::compileMethod hook",
                    protector_name=".NET Reactor NecroBit",
                )
            )

        # ILProtector InvokeMethod Hook
        if b"ILProtector" in data or b"ProtectMethods" in data:
            idx = data.find(b"ILProtector") if b"ILProtector" in data else data.find(b"ProtectMethods")
            out.append(
                JITHookSignature(
                    hook_type=JITHookType.DYNAMIC_METHOD_EMIT,
                    target_module="clr.dll",
                    hook_pattern="ilprotector_dynamic_invoke",
                    detected_rva=max(0, idx),
                    confidence=0.95,
                    description="ILProtector dynamic delegate invocation & method body hook",
                    protector_name="ILProtector",
                )
            )

        # ArmDot Method JIT Hook
        if b".armdot" in data or b"ArmDot" in data:
            idx = data.find(b".armdot") if b".armdot" in data else data.find(b"ArmDot")
            out.append(
                JITHookSignature(
                    hook_type=JITHookType.PRE_JIT_STUB,
                    target_module="clrjit.dll",
                    hook_pattern="armdot_prejit_stub",
                    detected_rva=max(0, idx),
                    confidence=0.92,
                    description="ArmDot method-level virtualization pre-JIT interceptor",
                    protector_name="ArmDot",
                )
            )

        # Eazfuscator VM Hook
        if b".eazvm" in data or b"Eazfuscator" in data:
            idx = data.find(b".eazvm") if b".eazvm" in data else data.find(b"Eazfuscator")
            out.append(
                JITHookSignature(
                    hook_type=JITHookType.DYNAMIC_METHOD_EMIT,
                    target_module="clr.dll",
                    hook_pattern="eazfuscator_vm_dispatcher",
                    detected_rva=max(0, idx),
                    confidence=0.92,
                    description="Eazfuscator.NET bytecode virtual machine dynamic dispatcher",
                    protector_name="Eazfuscator.NET",
                )
            )

    @classmethod
    def _scan_native_detours(cls, data: bytes, out: List[JITHookSignature]) -> None:
        """Detects in-line machine code detour trampolines commonly injected into JIT compilers."""
        # 14-byte 64-bit indirect jump (FF 25 00 00 00 00 <8-byte target>)
        for match in cls.PATTERN_RIP_INDIRECT_JMP.finditer(data):
            offset = match.start()
            target_addr = struct.unpack("<Q", match.group(1))[0]
            # Heuristic filter for plausible user-space addresses
            if 0x10000 <= target_addr <= 0x7FFFFFFFFFFF:
                out.append(
                    JITHookSignature(
                        hook_type=JITHookType.CUSTOM_CLR_HOOK,
                        target_module="clrjit.dll",
                        hook_pattern="rip_relative_indirect_detour",
                        detected_rva=offset,
                        confidence=0.88,
                        description=f"64-bit RIP-relative indirect detour (target: 0x{target_addr:016X})",
                    )
                )

        # Mov-push-ret detour (48 B8 <8-byte> 50 C3)
        for match in cls.PATTERN_MOV_PUSH_RET.finditer(data):
            offset = match.start()
            target_addr = struct.unpack("<Q", match.group(1))[0]
            if 0x10000 <= target_addr <= 0x7FFFFFFFFFFF:
                out.append(
                    JITHookSignature(
                        hook_type=JITHookType.CUSTOM_CLR_HOOK,
                        target_module="clrjit.dll",
                        hook_pattern="mov_push_ret_detour",
                        detected_rva=offset,
                        confidence=0.84,
                        description=f"64-bit mov-push-ret trampoline detour (target: 0x{target_addr:016X})",
                    )
                )

    @classmethod
    def _scan_vtable_overrides(cls, data: bytes, out: List[JITHookSignature]) -> None:
        """Detects instructions writing function pointers into VTable slot 0 (compileMethod)."""
        # x86: mov dword ptr [eax], hook_fn -> 89 08 / 89 10 / C7 00 ...
        # x64: mov qword ptr [rax], hook_fn -> 48 89 08 / 48 89 10
        vtable_slot0_patterns = [
            (re.compile(rb"\x48\x89\x08"), "mov [rax], rcx (x64 vtable slot 0 write)"),
            (re.compile(rb"\x48\x89\x10"), "mov [rax], rdx (x64 vtable slot 0 write)"),
            (re.compile(rb"\x89\x08"), "mov [eax], ecx (x86 vtable slot 0 write)"),
            (re.compile(rb"\x89\x10"), "mov [eax], edx (x86 vtable slot 0 write)"),
        ]
        for pattern, desc in vtable_slot0_patterns:
            for match in pattern.finditer(data):
                offset = match.start()
                out.append(
                    JITHookSignature(
                        hook_type=JITHookType.CORJIT_COMPILEMETHOD,
                        target_module="clrjit.dll",
                        hook_pattern="vtable_slot_0_overwrite",
                        detected_rva=offset,
                        confidence=0.75,
                        description=desc,
                    )
                )
                if len(out) > 50:
                    break
