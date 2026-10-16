"""
Native Machine Code Disassembler & Method Analyzer for ReadyToRun & Native AOT.
Disassembles x64/x86 native instructions, maps branches, resolves Rhp* helper calls, and partitions basic blocks.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    DisassembledMethod,
    R2RInstruction,
    TargetArchitecture,
)


class NativeDisassembler:
    """Disassembles precompiled native method bodies and annotates runtime helper calls."""

    COND_JUMPS_REL8: Dict[int, str] = {
        0x70: "JO",
        0x71: "JNO",
        0x72: "JB",
        0x73: "JAE",
        0x74: "JE",
        0x75: "JNE",
        0x76: "JBE",
        0x77: "JA",
        0x78: "JS",
        0x79: "JNS",
        0x7A: "JP",
        0x7B: "JNP",
        0x7C: "JL",
        0x7D: "JGE",
        0x7E: "JLE",
        0x7F: "JG",
    }

    COND_JUMPS_REL32: Dict[int, str] = {
        0x80: "JO",
        0x81: "JNO",
        0x82: "JB",
        0x83: "JAE",
        0x84: "JE",
        0x85: "JNE",
        0x86: "JBE",
        0x87: "JA",
        0x88: "JS",
        0x89: "JNS",
        0x8A: "JP",
        0x8B: "JNP",
        0x8C: "JL",
        0x8D: "JGE",
        0x8E: "JLE",
        0x8F: "JG",
    }

    @classmethod
    def disassemble_method(
        cls,
        code_bytes: bytes,
        start_rva: int,
        name: str = "NativeMethod",
        token: Optional[int] = None,
        arch: TargetArchitecture = TargetArchitecture.X64,
        known_helpers: Optional[Dict[int, str]] = None,
        max_instructions: int = 4096,
    ) -> DisassembledMethod:
        """
        Disassembles a sequence of native instructions into an annotated DisassembledMethod.
        Resolves call targets to known Rhp* helpers or runtime symbols.
        """
        helper_map = known_helpers or {}
        instructions: List[R2RInstruction] = []
        offset = 0
        end_rva = start_rva + len(code_bytes)
        calls_count = 0
        helpers_called: Set[str] = set()
        branch_targets: Set[int] = set()

        while offset < len(code_bytes) and len(instructions) < max_instructions:
            ins_rva = start_rva + offset
            ins = cls._decode_instruction(
                code_bytes, offset, ins_rva, arch, helper_map
            )
            instructions.append(ins)
            offset += ins.size

            if ins.is_call:
                calls_count += 1
                if ins.helper_name:
                    helpers_called.add(ins.helper_name)

            if ins.is_branch and ins.target_rva:
                branch_targets.add(ins.target_rva)

            # Terminate on function epilogue ret if followed by padding nops or int3
            if ins.mnemonic == "RET" and offset < len(code_bytes):
                # If remaining bytes are padding (0xCC or 0x90), terminate early
                rem = code_bytes[offset:]
                if all(b in (0xCC, 0x90) for b in rem[:16]):
                    break

        # Compute basic blocks count
        # Leaders are: first instruction, targets of branches, and instructions following branches
        leader_rvas: Set[int] = {start_rva}
        for i, ins in enumerate(instructions):
            if ins.is_branch:
                if ins.target_rva:
                    leader_rvas.add(ins.target_rva)
                if i + 1 < len(instructions):
                    leader_rvas.add(instructions[i + 1].offset)

        blocks_count = max(1, len(leader_rvas.intersection({ins.offset for ins in instructions})))

        return DisassembledMethod(
            name=name,
            token=token,
            start_rva=start_rva,
            end_rva=end_rva,
            size_bytes=len(code_bytes),
            instructions=instructions,
            blocks_count=blocks_count,
            calls_count=calls_count,
            helpers_called=sorted(list(helpers_called)),
        )

    @classmethod
    def _decode_instruction(
        cls,
        code: bytes,
        offset: int,
        rva: int,
        arch: TargetArchitecture,
        helper_map: Dict[int, str],
    ) -> R2RInstruction:
        """Decodes a single instruction at given offset."""
        rem_len = len(code) - offset
        b0 = code[offset]

        # 1. Check for multi-byte prefixes (REX prefixes 0x40-0x4F on x64)
        prefix_len = 0
        rex_w = False
        if arch == TargetArchitecture.X64 and 0x40 <= b0 <= 0x4F and rem_len > 1:
            rex_w = (b0 & 0x08) != 0
            prefix_len = 1
            b0 = code[offset + 1]

        eff_off = offset + prefix_len
        eff_rem = len(code) - eff_off

        # RET (0xC3)
        if b0 == 0xC3:
            raw = code[offset : offset + prefix_len + 1].hex().upper()
            return R2RInstruction(rva, "RET", "", raw, prefix_len + 1, False, False)

        # RET imm16 (0xC2)
        if b0 == 0xC2 and eff_rem >= 3:
            imm16 = struct.unpack_from("<H", code, eff_off + 1)[0]
            raw = code[offset : offset + prefix_len + 3].hex().upper()
            return R2RInstruction(rva, "RET", f"0x{imm16:X}", raw, prefix_len + 3, False, False)

        # NOP (0x90)
        if b0 == 0x90:
            raw = code[offset : offset + prefix_len + 1].hex().upper()
            return R2RInstruction(rva, "NOP", "", raw, prefix_len + 1, False, False)

        # INT3 (0xCC)
        if b0 == 0xCC:
            raw = code[offset : offset + prefix_len + 1].hex().upper()
            return R2RInstruction(rva, "INT3", "", raw, prefix_len + 1, False, False)

        # PUSH reg (0x50 - 0x57)
        if 0x50 <= b0 <= 0x57:
            regs_64 = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"]
            reg = regs_64[b0 - 0x50]
            raw = code[offset : offset + prefix_len + 1].hex().upper()
            return R2RInstruction(rva, "PUSH", reg, raw, prefix_len + 1, False, False)

        # POP reg (0x58 - 0x5F)
        if 0x58 <= b0 <= 0x5F:
            regs_64 = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"]
            reg = regs_64[b0 - 0x58]
            raw = code[offset : offset + prefix_len + 1].hex().upper()
            return R2RInstruction(rva, "POP", reg, raw, prefix_len + 1, False, False)

        # CALL rel32 (0xE8)
        if b0 == 0xE8 and eff_rem >= 5:
            rel32 = struct.unpack_from("<i", code, eff_off + 1)[0]
            ins_size = prefix_len + 5
            target_rva = rva + ins_size + rel32
            helper = helper_map.get(target_rva)
            operands = f"0x{target_rva:08X}"
            if helper:
                operands += f" <{helper}>"
            raw = code[offset : offset + ins_size].hex().upper()
            return R2RInstruction(
                rva, "CALL", operands, raw, ins_size, True, False, target_rva, helper
            )

        # JMP rel32 (0xE9)
        if b0 == 0xE9 and eff_rem >= 5:
            rel32 = struct.unpack_from("<i", code, eff_off + 1)[0]
            ins_size = prefix_len + 5
            target_rva = rva + ins_size + rel32
            helper = helper_map.get(target_rva)
            operands = f"0x{target_rva:08X}"
            if helper:
                operands += f" <{helper}>"
            raw = code[offset : offset + ins_size].hex().upper()
            return R2RInstruction(
                rva, "JMP", operands, raw, ins_size, False, True, target_rva, helper
            )

        # JMP rel8 (0xEB)
        if b0 == 0xEB and eff_rem >= 2:
            rel8 = struct.unpack_from("<b", code, eff_off + 1)[0]
            ins_size = prefix_len + 2
            target_rva = rva + ins_size + rel8
            operands = f"0x{target_rva:08X}"
            raw = code[offset : offset + ins_size].hex().upper()
            return R2RInstruction(
                rva, "JMP", operands, raw, ins_size, False, True, target_rva, None
            )

        # Conditional Jumps (rel8: 0x70 - 0x7F)
        if b0 in cls.COND_JUMPS_REL8 and eff_rem >= 2:
            mnemonic = cls.COND_JUMPS_REL8[b0]
            rel8 = struct.unpack_from("<b", code, eff_off + 1)[0]
            ins_size = prefix_len + 2
            target_rva = rva + ins_size + rel8
            operands = f"0x{target_rva:08X}"
            raw = code[offset : offset + ins_size].hex().upper()
            return R2RInstruction(
                rva, mnemonic, operands, raw, ins_size, False, True, target_rva, None
            )

        # Two-byte opcode: 0x0F
        if b0 == 0x0F and eff_rem >= 2:
            b1 = code[eff_off + 1]
            # Conditional jumps rel32 (0x0F 0x80 - 0x0F 0x8F)
            if b1 in cls.COND_JUMPS_REL32 and eff_rem >= 6:
                mnemonic = cls.COND_JUMPS_REL32[b1]
                rel32 = struct.unpack_from("<i", code, eff_off + 2)[0]
                ins_size = prefix_len + 6
                target_rva = rva + ins_size + rel32
                operands = f"0x{target_rva:08X}"
                raw = code[offset : offset + ins_size].hex().upper()
                return R2RInstruction(
                    rva, mnemonic, operands, raw, ins_size, False, True, target_rva, None
                )

        # Common MOV / SUB / ADD stack frame patterns (0x83, 0x81, 0x89, 0x8B, 0x8D)
        # SUB rsp, imm8 (0x83 0xEC imm8)
        if b0 == 0x83 and eff_rem >= 3:
            modrm = code[eff_off + 1]
            imm8 = code[eff_off + 2]
            ins_size = prefix_len + 3
            raw = code[offset : offset + ins_size].hex().upper()
            if modrm == 0xEC:
                return R2RInstruction(rva, "SUB", f"RSP, 0x{imm8:X}", raw, ins_size, False, False)
            if modrm == 0xC4:
                return R2RInstruction(rva, "ADD", f"RSP, 0x{imm8:X}", raw, ins_size, False, False)

        # SUB rsp, imm32 (0x81 0xEC imm32)
        if b0 == 0x81 and eff_rem >= 6:
            modrm = code[eff_off + 1]
            imm32 = struct.unpack_from("<I", code, eff_off + 2)[0]
            ins_size = prefix_len + 6
            raw = code[offset : offset + ins_size].hex().upper()
            if modrm == 0xEC:
                return R2RInstruction(rva, "SUB", f"RSP, 0x{imm32:X}", raw, ins_size, False, False)
            if modrm == 0xC4:
                return R2RInstruction(rva, "ADD", f"RSP, 0x{imm32:X}", raw, ins_size, False, False)

        # MOV rbp, rsp (0x89 0xE5)
        if b0 == 0x89 and eff_rem >= 2 and code[eff_off + 1] == 0xE5:
            ins_size = prefix_len + 2
            raw = code[offset : offset + ins_size].hex().upper()
            return R2RInstruction(rva, "MOV", "RBP, RSP", raw, ins_size, False, False)

        # MOV rsp, rbp (0x89 0xEC)
        if b0 == 0x89 and eff_rem >= 2 and code[eff_off + 1] == 0xEC:
            ins_size = prefix_len + 2
            raw = code[offset : offset + ins_size].hex().upper()
            return R2RInstruction(rva, "MOV", "RSP, RBP", raw, ins_size, False, False)

        # XOR rax, rax (0x31 0xC0) or XOR eax, eax
        if b0 == 0x31 and eff_rem >= 2 and code[eff_off + 1] == 0xC0:
            ins_size = prefix_len + 2
            raw = code[offset : offset + ins_size].hex().upper()
            reg = "RAX" if rex_w else "EAX"
            return R2RInstruction(rva, "XOR", f"{reg}, {reg}", raw, ins_size, False, False)

        # TEST rax, rax (0x85 0xC0)
        if b0 == 0x85 and eff_rem >= 2 and code[eff_off + 1] == 0xC0:
            ins_size = prefix_len + 2
            raw = code[offset : offset + ins_size].hex().upper()
            reg = "RAX" if rex_w else "EAX"
            return R2RInstruction(rva, "TEST", f"{reg}, {reg}", raw, ins_size, False, False)

        # Indirect CALL/JMP [rip + disp32] (0xFF 0x15 / 0xFF 0x25)
        if b0 == 0xFF and eff_rem >= 6:
            modrm = code[eff_off + 1]
            disp32 = struct.unpack_from("<i", code, eff_off + 2)[0]
            ins_size = prefix_len + 6
            target_rva = rva + ins_size + disp32
            helper = helper_map.get(target_rva)
            raw = code[offset : offset + ins_size].hex().upper()
            if modrm == 0x15:  # CALL [RIP + disp32]
                operands = f"[RIP + 0x{disp32:X}] (0x{target_rva:08X})"
                if helper:
                    operands += f" <{helper}>"
                return R2RInstruction(
                    rva, "CALL", operands, raw, ins_size, True, False, target_rva, helper
                )
            if modrm == 0x25:  # JMP [RIP + disp32]
                operands = f"[RIP + 0x{disp32:X}] (0x{target_rva:08X})"
                if helper:
                    operands += f" <{helper}>"
                return R2RInstruction(
                    rva, "JMP", operands, raw, ins_size, False, True, target_rva, helper
                )

        # Generic 1-byte fallback instruction
        raw = code[offset : offset + 1].hex().upper()
        return R2RInstruction(rva, f"DB 0x{b0:02X}", "", raw, 1, False, False)
