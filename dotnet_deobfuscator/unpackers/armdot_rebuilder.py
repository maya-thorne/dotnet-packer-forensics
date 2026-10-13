"""
ArmDot Virtual Machine to ECMA-335 CIL Method Rebuilder & De-virtualizer.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .armdot_vm import (
    ArmDotInstruction,
    ArmDotOpcode,
    ArmDotStackEmulator,
    ArmDotVMDisassembler,
)


class CILOpcode:
    """Standard ECMA-335 Common Intermediate Language (CIL) Opcode constants."""

    NOP = 0x00
    LDARG_0 = 0x02
    LDARG_1 = 0x03
    LDARG_2 = 0x04
    LDARG_3 = 0x05
    LDLOC_0 = 0x06
    LDLOC_1 = 0x07
    LDLOC_2 = 0x08
    LDLOC_3 = 0x09
    STLOC_0 = 0x0A
    STLOC_1 = 0x0B
    STLOC_2 = 0x0C
    STLOC_3 = 0x0D
    LDARG_S = 0x0E
    LDARGA_S = 0x0F
    STARG_S = 0x10
    LDLOC_S = 0x11
    LDLOCA_S = 0x12
    STLOC_S = 0x13
    LDNULL = 0x14
    LDC_I4_M1 = 0x15
    LDC_I4_0 = 0x16
    LDC_I4_1 = 0x17
    LDC_I4_2 = 0x18
    LDC_I4_3 = 0x19
    LDC_I4_4 = 0x1A
    LDC_I4_5 = 0x1B
    LDC_I4_6 = 0x1C
    LDC_I4_7 = 0x1D
    LDC_I4_8 = 0x1E
    LDC_I4_S = 0x1F
    LDC_I4 = 0x20
    LDC_I8 = 0x21
    LDC_R4 = 0x22
    LDC_R8 = 0x23
    DUP = 0x25
    POP = 0x26
    CALL = 0x28
    CALLVIRT = 0x6F
    RET = 0x2A
    BR_S = 0x2B
    BRFALSE_S = 0x2C
    BRTRUE_S = 0x2D
    BEQ_S = 0x2E
    BGE_S = 0x2F
    BGT_S = 0x30
    BLE_S = 0x31
    BLT_S = 0x32
    BNE_UN_S = 0x33
    BR = 0x38
    BRFALSE = 0x39
    BRTRUE = 0x3A
    BEQ = 0x3B
    BGE = 0x3C
    BGT = 0x3D
    BLE = 0x3E
    BLT = 0x3F
    BNE_UN = 0x40
    SWITCH = 0x45
    LDSTR = 0x72
    NEWOBJ = 0x73
    THROW = 0x7A
    LDFLD = 0x7B
    STFLD = 0x7D
    LDSFLD = 0x7E
    STSFLD = 0x80
    CONV_I4 = 0x69
    CONV_I8 = 0x6A
    CONV_R4 = 0x6B
    CONV_R8 = 0x6C
    CONV_U4 = 0x6D
    CONV_U8 = 0x6E
    NEWARR = 0x8D
    LDLEN = 0x8E
    ADD = 0x58
    SUB = 0x59
    MUL = 0x5A
    DIV = 0x5B
    REM = 0x5D
    AND = 0x5F
    OR = 0x60
    XOR = 0x61
    SHL = 0x62
    SHR = 0x63
    NEG = 0x65
    NOT = 0x66
    RETHROW = 0xFE1A
    CEQ = 0xFE01
    CGT = 0xFE02
    CLT = 0xFE04


class CorILMethodBuilder:
    """Constructs ECMA-335 compliant CorILMethod Tiny and Fat headers."""

    @staticmethod
    def build_tiny_method(code_bytes: bytes) -> bytes:
        """
        Emits CorILMethod_TinyFormat (1 byte header).
        Header format: (code_size << 2) | 0x02
        Valid only if code_size <= 63 bytes, max_stack <= 8, and no local variables.
        """
        code_size = len(code_bytes)
        if code_size > 63:
            raise ValueError(f"Code size {code_size} exceeds TinyFormat limit (63 bytes)")
        header_byte = (code_size << 2) | 0x02
        return bytes([header_byte]) + code_bytes

    @staticmethod
    def build_fat_method(
        code_bytes: bytes,
        max_stack: int = 8,
        local_sig_tok: int = 0,
        flags: int = 0x3003,
    ) -> bytes:
        """
        Emits CorILMethod_FatFormat (12-byte header).
        Structure:
          Flags (12 bits) + Size (4 bits): 0x3003 (Size=3 dwords, CorILMethod_FatFormat=0x03)
          MaxStack: uint16
          CodeSize: uint32
          LocalVarSigTok: uint32 (e.g. 0x11000001 or 0)
        """
        code_size = len(code_bytes)
        # Header Size is count of 4-byte DWORDs (12 bytes = 3 DWORDs)
        flags_and_size = (flags & 0xFFF) | (3 << 12)
        header = struct.pack("<HHII", flags_and_size, max(max_stack, 1), code_size, local_sig_tok)
        return header + code_bytes


class ArmDotBasicBlock:
    """Represents a basic block of VM instructions with control flow edges."""

    def __init__(self, start_idx: int, start_offset: int):
        self.start_idx = start_idx
        self.start_offset = start_offset
        self.end_idx = start_idx
        self.end_offset = start_offset
        self.instructions: List[ArmDotInstruction] = []
        self.successors: List[int] = []
        self.predecessors: List[int] = []


class ArmDotCFG:
    """Control Flow Graph builder for ArmDot VM instructions."""

    def __init__(self, instructions: List[ArmDotInstruction]):
        self.instructions = instructions
        self.blocks: List[ArmDotBasicBlock] = []
        self._build_cfg()

    def _build_cfg(self) -> None:
        if not self.instructions:
            return

        # Find leader offsets (block starts)
        leaders: Set[int] = {self.instructions[0].offset}
        for idx, inst in enumerate(self.instructions):
            if inst.branch_target is not None:
                leaders.add(inst.branch_target)
                if idx + 1 < len(self.instructions):
                    leaders.add(self.instructions[idx + 1].offset)
            elif inst.switch_targets:
                for tgt in inst.switch_targets:
                    leaders.add(tgt)
                if idx + 1 < len(self.instructions):
                    leaders.add(self.instructions[idx + 1].offset)
            elif inst.opcode in (ArmDotOpcode.RET, ArmDotOpcode.THROW, ArmDotOpcode.RETHROW):
                if idx + 1 < len(self.instructions):
                    leaders.add(self.instructions[idx + 1].offset)

        # Slice instructions into basic blocks
        cur_block: Optional[ArmDotBasicBlock] = None
        for idx, inst in enumerate(self.instructions):
            if inst.offset in leaders:
                if cur_block:
                    self.blocks.append(cur_block)
                cur_block = ArmDotBasicBlock(idx, inst.offset)
            if cur_block:
                cur_block.instructions.append(inst)
                cur_block.end_idx = idx
                cur_block.end_offset = inst.offset + inst.length
        if cur_block:
            self.blocks.append(cur_block)


class ArmDotDevirtualizer:
    """
    De-virtualizes ArmDot VM bytecode into standard ECMA-335 CIL method bodies.
    Performs abstract stack emulation, multi-pass branch target fixups,
    and CorILMethod Tiny/Fat header emission.
    """

    BRANCH_OPCODES_SHORT = {
        ArmDotOpcode.BR: CILOpcode.BR_S,
        ArmDotOpcode.BR_TRUE: CILOpcode.BRTRUE_S,
        ArmDotOpcode.BR_FALSE: CILOpcode.BRFALSE_S,
        ArmDotOpcode.BEQ: CILOpcode.BEQ_S,
        ArmDotOpcode.BNE: CILOpcode.BNE_UN_S,
        ArmDotOpcode.BGT: CILOpcode.BGT_S,
        ArmDotOpcode.BGE: CILOpcode.BGE_S,
        ArmDotOpcode.BLT: CILOpcode.BLT_S,
        ArmDotOpcode.BLE: CILOpcode.BLE_S,
    }

    BRANCH_OPCODES_LONG = {
        ArmDotOpcode.BR: CILOpcode.BR,
        ArmDotOpcode.BR_TRUE: CILOpcode.BRTRUE,
        ArmDotOpcode.BR_FALSE: CILOpcode.BRFALSE,
        ArmDotOpcode.BEQ: CILOpcode.BEQ,
        ArmDotOpcode.BNE: CILOpcode.BNE_UN,
        ArmDotOpcode.BGT: CILOpcode.BGT,
        ArmDotOpcode.BGE: CILOpcode.BGE,
        ArmDotOpcode.BLT: CILOpcode.BLT,
        ArmDotOpcode.BLE: CILOpcode.BLE,
    }

    @classmethod
    def emit_cil_instruction(
        cls,
        inst: ArmDotInstruction,
        use_long_branch: bool = False,
    ) -> bytes:
        """Translates a single ArmDotInstruction into CIL opcode bytes."""
        op = inst.opcode
        operand = inst.operand

        # 1. Stack & Flow
        if op == ArmDotOpcode.NOP:
            return bytes([CILOpcode.NOP])
        if op == ArmDotOpcode.POP:
            return bytes([CILOpcode.POP])
        if op == ArmDotOpcode.DUP:
            return bytes([CILOpcode.DUP])
        if op == ArmDotOpcode.RET:
            return bytes([CILOpcode.RET])

        # 2. Constants
        if op == ArmDotOpcode.LD_NULL:
            return bytes([CILOpcode.LDNULL])
        if op == ArmDotOpcode.LD_I4:
            val = int(operand) if operand is not None else 0
            if -1 <= val <= 8:
                return bytes([CILOpcode.LDC_I4_M1 + (val + 1)])
            if -128 <= val <= 127:
                return bytes([CILOpcode.LDC_I4_S, val & 0xFF])
            return bytes([CILOpcode.LDC_I4]) + struct.pack("<i", val)
        if op == ArmDotOpcode.LD_I8:
            val = int(operand) if operand is not None else 0
            return bytes([CILOpcode.LDC_I8]) + struct.pack("<q", val)
        if op == ArmDotOpcode.LD_R4:
            val = float(operand) if operand is not None else 0.0
            return bytes([CILOpcode.LDC_R4]) + struct.pack("<f", val)
        if op == ArmDotOpcode.LD_R8:
            val = float(operand) if operand is not None else 0.0
            return bytes([CILOpcode.LDC_R8]) + struct.pack("<d", val)
        if op == ArmDotOpcode.LD_STR:
            # Emit ldstr placeholder with user string token (0x70000001)
            tok = int(operand) if isinstance(operand, int) else 0x70000001
            return bytes([CILOpcode.LDSTR]) + struct.pack("<I", tok)

        # 3. Local Variables
        if op == ArmDotOpcode.LD_LOC:
            idx = int(operand) if operand is not None else 0
            if idx == 0:
                return bytes([CILOpcode.LDLOC_0])
            if idx == 1:
                return bytes([CILOpcode.LDLOC_1])
            if idx == 2:
                return bytes([CILOpcode.LDLOC_2])
            if idx == 3:
                return bytes([CILOpcode.LDLOC_3])
            return bytes([CILOpcode.LDLOC_S, idx & 0xFF])
        if op == ArmDotOpcode.ST_LOC:
            idx = int(operand) if operand is not None else 0
            if idx == 0:
                return bytes([CILOpcode.STLOC_0])
            if idx == 1:
                return bytes([CILOpcode.STLOC_1])
            if idx == 2:
                return bytes([CILOpcode.STLOC_2])
            if idx == 3:
                return bytes([CILOpcode.STLOC_3])
            return bytes([CILOpcode.STLOC_S, idx & 0xFF])
        if op == ArmDotOpcode.LD_LOCA:
            idx = int(operand) if operand is not None else 0
            return bytes([CILOpcode.LDLOCA_S, idx & 0xFF])

        # 4. Arguments
        if op == ArmDotOpcode.LD_ARG:
            idx = int(operand) if operand is not None else 0
            if idx == 0:
                return bytes([CILOpcode.LDARG_0])
            if idx == 1:
                return bytes([CILOpcode.LDARG_1])
            if idx == 2:
                return bytes([CILOpcode.LDARG_2])
            if idx == 3:
                return bytes([CILOpcode.LDARG_3])
            return bytes([CILOpcode.LDARG_S, idx & 0xFF])
        if op == ArmDotOpcode.ST_ARG:
            idx = int(operand) if operand is not None else 0
            return bytes([CILOpcode.STARG_S, idx & 0xFF])
        if op == ArmDotOpcode.LD_ARGA:
            idx = int(operand) if operand is not None else 0
            return bytes([CILOpcode.LDARGA_S, idx & 0xFF])

        # 5. Arithmetic & Bitwise Logic
        if op == ArmDotOpcode.ADD:
            return bytes([CILOpcode.ADD])
        if op == ArmDotOpcode.SUB:
            return bytes([CILOpcode.SUB])
        if op == ArmDotOpcode.MUL:
            return bytes([CILOpcode.MUL])
        if op == ArmDotOpcode.DIV:
            return bytes([CILOpcode.DIV])
        if op == ArmDotOpcode.REM:
            return bytes([CILOpcode.REM])
        if op == ArmDotOpcode.NEG:
            return bytes([CILOpcode.NEG])
        if op == ArmDotOpcode.AND:
            return bytes([CILOpcode.AND])
        if op == ArmDotOpcode.OR:
            return bytes([CILOpcode.OR])
        if op == ArmDotOpcode.XOR:
            return bytes([CILOpcode.XOR])
        if op == ArmDotOpcode.NOT:
            return bytes([CILOpcode.NOT])
        if op == ArmDotOpcode.SHL:
            return bytes([CILOpcode.SHL])
        if op == ArmDotOpcode.SHR:
            return bytes([CILOpcode.SHR])

        # 6. Comparisons
        if op == ArmDotOpcode.CEQ:
            return bytes([0xFE, 0x01])
        if op == ArmDotOpcode.CGT:
            return bytes([0xFE, 0x02])
        if op == ArmDotOpcode.CLT:
            return bytes([0xFE, 0x04])

        # 7. Branches (placeholders)
        if op in cls.BRANCH_OPCODES_SHORT:
            if use_long_branch:
                cil_op = cls.BRANCH_OPCODES_LONG[op]
                return bytes([cil_op, 0, 0, 0, 0])
            cil_op = cls.BRANCH_OPCODES_SHORT[op]
            return bytes([cil_op, 0])

        # 8. Invocations & Members
        if op == ArmDotOpcode.CALL:
            tok = int(operand) if operand is not None else 0x06000001
            return bytes([CILOpcode.CALL]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.CALLVIRT:
            tok = int(operand) if operand is not None else 0x06000001
            return bytes([CILOpcode.CALLVIRT]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.NEWOBJ:
            tok = int(operand) if operand is not None else 0x06000001
            return bytes([CILOpcode.NEWOBJ]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.NEWARR:
            tok = int(operand) if operand is not None else 0x01000001
            return bytes([CILOpcode.NEWARR]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.LDLEN:
            return bytes([CILOpcode.LDLEN])
        if op == ArmDotOpcode.LDFLD:
            tok = int(operand) if operand is not None else 0x04000001
            return bytes([CILOpcode.LDFLD]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.STFLD:
            tok = int(operand) if operand is not None else 0x04000001
            return bytes([CILOpcode.STFLD]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.LDSFLD:
            tok = int(operand) if operand is not None else 0x04000001
            return bytes([CILOpcode.LDSFLD]) + struct.pack("<I", tok)
        if op == ArmDotOpcode.STSFLD:
            tok = int(operand) if operand is not None else 0x04000001
            return bytes([CILOpcode.STSFLD]) + struct.pack("<I", tok)

        # 9. Conversions
        if op == ArmDotOpcode.CONV_I4:
            return bytes([CILOpcode.CONV_I4])
        if op == ArmDotOpcode.CONV_I8:
            return bytes([CILOpcode.CONV_I8])
        if op == ArmDotOpcode.CONV_R4:
            return bytes([CILOpcode.CONV_R4])
        if op == ArmDotOpcode.CONV_R8:
            return bytes([CILOpcode.CONV_R8])
        if op == ArmDotOpcode.CONV_U4:
            return bytes([CILOpcode.CONV_U4])
        if op == ArmDotOpcode.CONV_U8:
            return bytes([CILOpcode.CONV_U8])

        # 10. Exceptions
        if op == ArmDotOpcode.THROW:
            return bytes([CILOpcode.THROW])
        if op == ArmDotOpcode.RETHROW:
            return bytes([0xFE, 0x1A])

        return bytes([CILOpcode.NOP])

    @classmethod
    def devirtualize_method(
        cls,
        instructions: List[ArmDotInstruction],
        token: int = 0x06000001,
        local_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Translates a sequence of ArmDot instructions into a valid CIL method body.
        Resolves branch offsets in two passes and builds Tiny or Fat CorILMethod header.
        """
        # 1. Run stack emulator to compute maximum stack depth
        emulator = ArmDotStackEmulator()
        for inst in instructions:
            emulator.step(inst)
        max_stack = max(emulator.max_depth, 8)

        # 2. Determine initial branch formats (try short 1-byte offsets first)
        use_long_branch: Dict[int, bool] = {i: False for i in range(len(instructions))}

        # Multi-pass branch fixup convergence loop
        for _ in range(5):
            # Calculate instruction start offsets
            cil_chunks: List[bytes] = []
            inst_cil_offsets: Dict[int, int] = {}
            current_cil_offset = 0

            for idx, inst in enumerate(instructions):
                inst_cil_offsets[inst.offset] = current_cil_offset
                chunk = cls.emit_cil_instruction(inst, use_long_branch=use_long_branch[idx])
                cil_chunks.append(chunk)
                current_cil_offset += len(chunk)

            # Check branch offsets
            needs_retry = False
            for idx, inst in enumerate(instructions):
                if inst.branch_target is not None:
                    target_cil = inst_cil_offsets.get(inst.branch_target, current_cil_offset)
                    inst_end_cil = inst_cil_offsets[inst.offset] + len(cil_chunks[idx])
                    rel_target = target_cil - inst_end_cil
                    if not (-128 <= rel_target <= 127) and not use_long_branch[idx]:
                        use_long_branch[idx] = True
                        needs_retry = True
            if not needs_retry:
                break

        # Final pass: emit and patch branch offsets
        final_chunks: List[bytearray] = []
        inst_cil_offsets = {}
        current_cil_offset = 0
        for idx, inst in enumerate(instructions):
            inst_cil_offsets[inst.offset] = current_cil_offset
            chunk = bytearray(cls.emit_cil_instruction(inst, use_long_branch=use_long_branch[idx]))
            final_chunks.append(chunk)
            current_cil_offset += len(chunk)

        for idx, inst in enumerate(instructions):
            if inst.branch_target is not None:
                target_cil = inst_cil_offsets.get(inst.branch_target, current_cil_offset)
                inst_end_cil = inst_cil_offsets[inst.offset] + len(final_chunks[idx])
                rel_target = target_cil - inst_end_cil
                if use_long_branch[idx]:
                    struct.pack_into("<i", final_chunks[idx], 1, rel_target)
                else:
                    struct.pack_into("<b", final_chunks[idx], 1, rel_target)

        raw_code = bytes().join(final_chunks)

        # Choose Tiny vs Fat method header
        # Tiny requires code_size <= 63 bytes, max_stack <= 8, and no local variables
        if len(raw_code) <= 63 and max_stack <= 8 and local_count == 0:
            header_format = "Tiny"
            method_body = CorILMethodBuilder.build_tiny_method(raw_code)
        else:
            header_format = "Fat"
            local_sig_tok = 0x11000001 if local_count > 0 else 0
            method_body = CorILMethodBuilder.build_fat_method(
                raw_code, max_stack=max_stack, local_sig_tok=local_sig_tok
            )

        # Build disassembly listing
        disasm_lines = [
            f".method public static void Method_0x{token:08X}() cil managed",
            "{",
            f"  // Code Size: {len(raw_code)} bytes, MaxStack: {max_stack}, Header: {header_format}",
        ]
        for inst in instructions:
            disasm_lines.append(f"  {inst.format()}")
        disasm_lines.append("}")

        return {
            "token": token,
            "token_hex": f"0x{token:08X}",
            "header_format": header_format,
            "max_stack": max_stack,
            "code_size": len(raw_code),
            "raw_cil_bytes": raw_code,
            "method_body_bytes": method_body,
            "disassembly": "\n".join(disasm_lines),
            "is_valid_cil": len(raw_code) > 0 and raw_code[-1] == CILOpcode.RET,
        }
