"""
ECMA-335 CIL Bytecode Disassembler for Control Flow Graph Generation.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import CFGInstruction, FlowControl


class CILDisassembler:
    """Disassembles raw ECMA-335 Common Intermediate Language (CIL) byte streams."""

    # Operand encodings
    OP_NONE = 0
    OP_INT8 = 1
    OP_INT32 = 2
    OP_INT64 = 3
    OP_FLOAT32 = 4
    OP_FLOAT64 = 5
    OP_TOKEN = 6
    OP_SHORT_BR = 7
    OP_BR = 8
    OP_SWITCH = 9
    OP_UINT16 = 10

    # 1-byte opcode mapping: opcode -> (name, operand_type, flow_control)
    ONE_BYTE_OPCODES: Dict[int, Tuple[str, int, FlowControl]] = {
        0x00: ("nop", OP_NONE, FlowControl.NEXT),
        0x01: ("break", OP_NONE, FlowControl.NEXT),
        0x02: ("ldarg.0", OP_NONE, FlowControl.NEXT),
        0x03: ("ldarg.1", OP_NONE, FlowControl.NEXT),
        0x04: ("ldarg.2", OP_NONE, FlowControl.NEXT),
        0x05: ("ldarg.3", OP_NONE, FlowControl.NEXT),
        0x06: ("ldloc.0", OP_NONE, FlowControl.NEXT),
        0x07: ("ldloc.1", OP_NONE, FlowControl.NEXT),
        0x08: ("ldloc.2", OP_NONE, FlowControl.NEXT),
        0x09: ("ldloc.3", OP_NONE, FlowControl.NEXT),
        0x0A: ("stloc.0", OP_NONE, FlowControl.NEXT),
        0x0B: ("stloc.1", OP_NONE, FlowControl.NEXT),
        0x0C: ("stloc.2", OP_NONE, FlowControl.NEXT),
        0x0D: ("stloc.3", OP_NONE, FlowControl.NEXT),
        0x0E: ("ldarg.s", OP_INT8, FlowControl.NEXT),
        0x0F: ("ldarga.s", OP_INT8, FlowControl.NEXT),
        0x10: ("starg.s", OP_INT8, FlowControl.NEXT),
        0x11: ("ldloc.s", OP_INT8, FlowControl.NEXT),
        0x12: ("ldloca.s", OP_INT8, FlowControl.NEXT),
        0x13: ("stloc.s", OP_INT8, FlowControl.NEXT),
        0x14: ("ldnull", OP_NONE, FlowControl.NEXT),
        0x15: ("ldc.i4.m1", OP_NONE, FlowControl.NEXT),
        0x16: ("ldc.i4.0", OP_NONE, FlowControl.NEXT),
        0x17: ("ldc.i4.1", OP_NONE, FlowControl.NEXT),
        0x18: ("ldc.i4.2", OP_NONE, FlowControl.NEXT),
        0x19: ("ldc.i4.3", OP_NONE, FlowControl.NEXT),
        0x1A: ("ldc.i4.4", OP_NONE, FlowControl.NEXT),
        0x1B: ("ldc.i4.5", OP_NONE, FlowControl.NEXT),
        0x1C: ("ldc.i4.6", OP_NONE, FlowControl.NEXT),
        0x1D: ("ldc.i4.7", OP_NONE, FlowControl.NEXT),
        0x1E: ("ldc.i4.8", OP_NONE, FlowControl.NEXT),
        0x1F: ("ldc.i4.s", OP_INT8, FlowControl.NEXT),
        0x20: ("ldc.i4", OP_INT32, FlowControl.NEXT),
        0x21: ("ldc.i8", OP_INT64, FlowControl.NEXT),
        0x22: ("ldc.r4", OP_FLOAT32, FlowControl.NEXT),
        0x23: ("ldc.r8", OP_FLOAT64, FlowControl.NEXT),
        0x25: ("dup", OP_NONE, FlowControl.NEXT),
        0x26: ("pop", OP_NONE, FlowControl.NEXT),
        0x27: ("jmp", OP_TOKEN, FlowControl.BRANCH),
        0x28: ("call", OP_TOKEN, FlowControl.NEXT),
        0x29: ("calli", OP_TOKEN, FlowControl.NEXT),
        0x2A: ("ret", OP_NONE, FlowControl.RET),
        0x2B: ("br.s", OP_SHORT_BR, FlowControl.BRANCH),
        0x2C: ("brfalse.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x2D: ("brtrue.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x2E: ("beq.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x2F: ("bge.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x30: ("bgt.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x31: ("ble.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x32: ("blt.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x33: ("bne.un.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x34: ("bge.un.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x35: ("bgt.un.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x36: ("ble.un.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x37: ("blt.un.s", OP_SHORT_BR, FlowControl.COND_BRANCH),
        0x38: ("br", OP_BR, FlowControl.BRANCH),
        0x39: ("brfalse", OP_BR, FlowControl.COND_BRANCH),
        0x3A: ("brtrue", OP_BR, FlowControl.COND_BRANCH),
        0x3B: ("beq", OP_BR, FlowControl.COND_BRANCH),
        0x3C: ("bge", OP_BR, FlowControl.COND_BRANCH),
        0x3D: ("bgt", OP_BR, FlowControl.COND_BRANCH),
        0x3E: ("ble", OP_BR, FlowControl.COND_BRANCH),
        0x3F: ("blt", OP_BR, FlowControl.COND_BRANCH),
        0x40: ("bne.un", OP_BR, FlowControl.COND_BRANCH),
        0x41: ("bge.un", OP_BR, FlowControl.COND_BRANCH),
        0x42: ("bgt.un", OP_BR, FlowControl.COND_BRANCH),
        0x43: ("ble.un", OP_BR, FlowControl.COND_BRANCH),
        0x44: ("blt.un", OP_BR, FlowControl.COND_BRANCH),
        0x45: ("switch", OP_SWITCH, FlowControl.SWITCH),
        0x46: ("ldind.i1", OP_NONE, FlowControl.NEXT),
        0x47: ("ldind.u1", OP_NONE, FlowControl.NEXT),
        0x48: ("ldind.i2", OP_NONE, FlowControl.NEXT),
        0x49: ("ldind.u2", OP_NONE, FlowControl.NEXT),
        0x4A: ("ldind.i4", OP_NONE, FlowControl.NEXT),
        0x4B: ("ldind.u4", OP_NONE, FlowControl.NEXT),
        0x4C: ("ldind.i8", OP_NONE, FlowControl.NEXT),
        0x4D: ("ldind.i", OP_NONE, FlowControl.NEXT),
        0x4E: ("ldind.r4", OP_NONE, FlowControl.NEXT),
        0x4F: ("ldind.r8", OP_NONE, FlowControl.NEXT),
        0x50: ("ldind.ref", OP_NONE, FlowControl.NEXT),
        0x51: ("stind.ref", OP_NONE, FlowControl.NEXT),
        0x52: ("stind.i1", OP_NONE, FlowControl.NEXT),
        0x53: ("stind.i2", OP_NONE, FlowControl.NEXT),
        0x54: ("stind.i4", OP_NONE, FlowControl.NEXT),
        0x55: ("stind.i8", OP_NONE, FlowControl.NEXT),
        0x56: ("stind.r4", OP_NONE, FlowControl.NEXT),
        0x57: ("stind.r8", OP_NONE, FlowControl.NEXT),
        0x58: ("add", OP_NONE, FlowControl.NEXT),
        0x59: ("sub", OP_NONE, FlowControl.NEXT),
        0x5A: ("mul", OP_NONE, FlowControl.NEXT),
        0x5B: ("div", OP_NONE, FlowControl.NEXT),
        0x5C: ("div.un", OP_NONE, FlowControl.NEXT),
        0x5D: ("rem", OP_NONE, FlowControl.NEXT),
        0x5E: ("rem.un", OP_NONE, FlowControl.NEXT),
        0x5F: ("and", OP_NONE, FlowControl.NEXT),
        0x60: ("or", OP_NONE, FlowControl.NEXT),
        0x61: ("xor", OP_NONE, FlowControl.NEXT),
        0x62: ("shl", OP_NONE, FlowControl.NEXT),
        0x63: ("shr", OP_NONE, FlowControl.NEXT),
        0x64: ("shr.un", OP_NONE, FlowControl.NEXT),
        0x65: ("neg", OP_NONE, FlowControl.NEXT),
        0x66: ("not", OP_NONE, FlowControl.NEXT),
        0x67: ("conv.i1", OP_NONE, FlowControl.NEXT),
        0x68: ("conv.i2", OP_NONE, FlowControl.NEXT),
        0x69: ("conv.i4", OP_NONE, FlowControl.NEXT),
        0x6A: ("conv.i8", OP_NONE, FlowControl.NEXT),
        0x6B: ("conv.r4", OP_NONE, FlowControl.NEXT),
        0x6C: ("conv.r8", OP_NONE, FlowControl.NEXT),
        0x6D: ("conv.u4", OP_NONE, FlowControl.NEXT),
        0x6E: ("conv.u8", OP_NONE, FlowControl.NEXT),
        0x6F: ("callvirt", OP_TOKEN, FlowControl.NEXT),
        0x70: ("cpobj", OP_TOKEN, FlowControl.NEXT),
        0x71: ("ldobj", OP_TOKEN, FlowControl.NEXT),
        0x72: ("ldstr", OP_TOKEN, FlowControl.NEXT),
        0x73: ("newobj", OP_TOKEN, FlowControl.NEXT),
        0x74: ("castclass", OP_TOKEN, FlowControl.NEXT),
        0x75: ("isinst", OP_TOKEN, FlowControl.NEXT),
        0x76: ("conv.r.un", OP_NONE, FlowControl.NEXT),
        0x79: ("unbox", OP_TOKEN, FlowControl.NEXT),
        0x7A: ("throw", OP_NONE, FlowControl.THROW),
        0x7B: ("ldfld", OP_TOKEN, FlowControl.NEXT),
        0x7C: ("ldflda", OP_TOKEN, FlowControl.NEXT),
        0x7D: ("stfld", OP_TOKEN, FlowControl.NEXT),
        0x7E: ("ldsfld", OP_TOKEN, FlowControl.NEXT),
        0x7F: ("ldsflda", OP_TOKEN, FlowControl.NEXT),
        0x80: ("stsfld", OP_TOKEN, FlowControl.NEXT),
        0x81: ("stobj", OP_TOKEN, FlowControl.NEXT),
        0x82: ("conv.ovf.i1", OP_NONE, FlowControl.NEXT),
        0x83: ("conv.ovf.u1", OP_NONE, FlowControl.NEXT),
        0x84: ("conv.ovf.i2", OP_NONE, FlowControl.NEXT),
        0x85: ("conv.ovf.u2", OP_NONE, FlowControl.NEXT),
        0x86: ("conv.ovf.i4", OP_NONE, FlowControl.NEXT),
        0x87: ("conv.ovf.u4", OP_NONE, FlowControl.NEXT),
        0x88: ("conv.ovf.i8", OP_NONE, FlowControl.NEXT),
        0x89: ("conv.ovf.u8", OP_NONE, FlowControl.NEXT),
        0x8D: ("newarr", OP_TOKEN, FlowControl.NEXT),
        0x8E: ("ldlen", OP_NONE, FlowControl.NEXT),
        0x8F: ("ldelema", OP_TOKEN, FlowControl.NEXT),
        0x90: ("ldelem.i1", OP_NONE, FlowControl.NEXT),
        0x91: ("ldelem.u1", OP_NONE, FlowControl.NEXT),
        0x92: ("ldelem.i2", OP_NONE, FlowControl.NEXT),
        0x93: ("ldelem.u2", OP_NONE, FlowControl.NEXT),
        0x94: ("ldelem.i4", OP_NONE, FlowControl.NEXT),
        0x95: ("ldelem.u4", OP_NONE, FlowControl.NEXT),
        0x96: ("ldelem.i8", OP_NONE, FlowControl.NEXT),
        0x97: ("ldelem.i", OP_NONE, FlowControl.NEXT),
        0x98: ("ldelem.r4", OP_NONE, FlowControl.NEXT),
        0x99: ("ldelem.r8", OP_NONE, FlowControl.NEXT),
        0x9A: ("ldelem.ref", OP_NONE, FlowControl.NEXT),
        0x9B: ("stelem.i", OP_NONE, FlowControl.NEXT),
        0x9C: ("stelem.i1", OP_NONE, FlowControl.NEXT),
        0x9D: ("stelem.i2", OP_NONE, FlowControl.NEXT),
        0x9E: ("stelem.i4", OP_NONE, FlowControl.NEXT),
        0x9F: ("stelem.i8", OP_NONE, FlowControl.NEXT),
        0xA0: ("stelem.r4", OP_NONE, FlowControl.NEXT),
        0xA1: ("stelem.r8", OP_NONE, FlowControl.NEXT),
        0xA2: ("stelem.ref", OP_NONE, FlowControl.NEXT),
        0xA3: ("box", OP_TOKEN, FlowControl.NEXT),
        0xDD: ("leave", OP_BR, FlowControl.BRANCH),
        0xDE: ("leave.s", OP_SHORT_BR, FlowControl.BRANCH),
        0xDF: ("endfinally", OP_NONE, FlowControl.RET),
    }

    # 2-byte opcode mapping (0xFE prefix): second_byte -> (name, operand_type, flow_control)
    TWO_BYTE_OPCODES: Dict[int, Tuple[str, int, FlowControl]] = {
        0x01: ("ceq", OP_NONE, FlowControl.NEXT),
        0x02: ("cgt", OP_NONE, FlowControl.NEXT),
        0x03: ("cgt.un", OP_NONE, FlowControl.NEXT),
        0x04: ("clt", OP_NONE, FlowControl.NEXT),
        0x05: ("clt.un", OP_NONE, FlowControl.NEXT),
        0x06: ("ldftn", OP_TOKEN, FlowControl.NEXT),
        0x07: ("ldvirtftn", OP_TOKEN, FlowControl.NEXT),
        0x09: ("ldarg", OP_UINT16, FlowControl.NEXT),
        0x0A: ("ldarga", OP_UINT16, FlowControl.NEXT),
        0x0B: ("starg", OP_UINT16, FlowControl.NEXT),
        0x0C: ("ldloc", OP_UINT16, FlowControl.NEXT),
        0x0D: ("ldloca", OP_UINT16, FlowControl.NEXT),
        0x0E: ("stloc", OP_UINT16, FlowControl.NEXT),
        0x0F: ("localloc", OP_NONE, FlowControl.NEXT),
        0x11: ("endfilter", OP_NONE, FlowControl.RET),
        0x12: ("unaligned.", OP_INT8, FlowControl.NEXT),
        0x13: ("volatile.", OP_NONE, FlowControl.NEXT),
        0x14: ("tail.", OP_NONE, FlowControl.NEXT),
        0x15: ("initobj", OP_TOKEN, FlowControl.NEXT),
        0x16: ("constrained.", OP_TOKEN, FlowControl.NEXT),
        0x17: ("cpblk", OP_NONE, FlowControl.NEXT),
        0x18: ("initblk", OP_NONE, FlowControl.NEXT),
        0x1A: ("rethrow", OP_NONE, FlowControl.THROW),
        0x1C: ("sizeof", OP_TOKEN, FlowControl.NEXT),
        0x1D: ("ldtoken", OP_TOKEN, FlowControl.NEXT),
    }

    @classmethod
    def disassemble(cls, bytecode: bytes, base_offset: int = 0) -> List[CFGInstruction]:
        """Disassembles a raw CIL bytecode slice into structured CFGInstruction instances."""
        instructions: List[CFGInstruction] = []
        pc = 0
        total_len = len(bytecode)

        while pc < total_len:
            inst_offset = pc
            raw_b0 = bytecode[pc]
            pc += 1

            if raw_b0 == 0xFE and pc < total_len:
                # 2-byte opcode
                raw_b1 = bytecode[pc]
                pc += 1
                full_op = 0xFE00 | raw_b1
                op_info = cls.TWO_BYTE_OPCODES.get(raw_b1, (f"unknown.0xfe{raw_b1:02x}", cls.OP_NONE, FlowControl.NEXT))
            else:
                full_op = raw_b0
                op_info = cls.ONE_BYTE_OPCODES.get(raw_b0, (f"unknown.0x{raw_b0:02x}", cls.OP_NONE, FlowControl.NEXT))

            name, op_type, flow_ctrl = op_info
            operand: Any = None
            branch_target: Optional[int] = None
            switch_targets: List[int] = []

            if op_type == cls.OP_NONE:
                pass
            elif op_type == cls.OP_INT8:
                if pc < total_len:
                    operand = struct.unpack("b", bytecode[pc:pc + 1])[0]
                    pc += 1
            elif op_type == cls.OP_UINT16:
                if pc + 2 <= total_len:
                    operand = struct.unpack("<H", bytecode[pc:pc + 2])[0]
                    pc += 2
            elif op_type == cls.OP_INT32:
                if pc + 4 <= total_len:
                    operand = struct.unpack("<i", bytecode[pc:pc + 4])[0]
                    pc += 4
            elif op_type == cls.OP_INT64:
                if pc + 8 <= total_len:
                    operand = struct.unpack("<q", bytecode[pc:pc + 8])[0]
                    pc += 8
            elif op_type == cls.OP_FLOAT32:
                if pc + 4 <= total_len:
                    operand = struct.unpack("<f", bytecode[pc:pc + 4])[0]
                    pc += 4
            elif op_type == cls.OP_FLOAT64:
                if pc + 8 <= total_len:
                    operand = struct.unpack("<d", bytecode[pc:pc + 8])[0]
                    pc += 8
            elif op_type == cls.OP_TOKEN:
                if pc + 4 <= total_len:
                    operand = struct.unpack("<I", bytecode[pc:pc + 4])[0]
                    pc += 4
            elif op_type == cls.OP_SHORT_BR:
                if pc < total_len:
                    rel_offset = struct.unpack("b", bytecode[pc:pc + 1])[0]
                    pc += 1
                    target = base_offset + pc + rel_offset
                    branch_target = target
                    operand = rel_offset
            elif op_type == cls.OP_BR:
                if pc + 4 <= total_len:
                    rel_offset = struct.unpack("<i", bytecode[pc:pc + 4])[0]
                    pc += 4
                    target = base_offset + pc + rel_offset
                    branch_target = target
                    operand = rel_offset
            elif op_type == cls.OP_SWITCH:
                if pc + 4 <= total_len:
                    count = struct.unpack("<I", bytecode[pc:pc + 4])[0]
                    pc += 4
                    switch_base = pc + count * 4
                    if pc + count * 4 <= total_len:
                        for _ in range(count):
                            s_rel = struct.unpack("<i", bytecode[pc:pc + 4])[0]
                            pc += 4
                            switch_targets.append(base_offset + switch_base + s_rel)
                        operand = len(switch_targets)

            inst_size = pc - inst_offset
            inst_raw = bytecode[inst_offset:pc]

            instructions.append(
                CFGInstruction(
                    offset=base_offset + inst_offset,
                    opcode=full_op,
                    name=name,
                    operand=operand,
                    size=inst_size,
                    raw_bytes=inst_raw,
                    branch_target=branch_target,
                    switch_targets=switch_targets,
                    flow_control=flow_ctrl,
                )
            )

        return instructions
