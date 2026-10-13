"""
Eazfuscator.NET Virtual Machine Bytecode Disassembler & CIL De-virtualizer.
Engineered & Audited by Maya Thorne.
"""

import json
import os
import struct
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class VMOpcode(str, Enum):
    """Semantic opcodes for Eazfuscator.NET Virtual Machine."""

    # Stack Manipulation
    NOP = "NOP"
    POP = "POP"
    DUP = "DUP"

    # Constant Loading
    LD_NULL = "LD_NULL"
    LD_I4 = "LD_I4"
    LD_I8 = "LD_I8"
    LD_R4 = "LD_R4"
    LD_R8 = "LD_R8"
    LD_STR = "LD_STR"

    # Local Variable Operations
    LD_LOC = "LD_LOC"
    ST_LOC = "ST_LOC"
    LD_LOCA = "LD_LOCA"

    # Argument Operations
    LD_ARG = "LD_ARG"
    ST_ARG = "ST_ARG"
    LD_ARGA = "LD_ARGA"

    # Arithmetic & Logic
    ADD = "ADD"
    SUB = "SUB"
    MUL = "MUL"
    DIV = "DIV"
    REM = "REM"
    NEG = "NEG"
    AND = "AND"
    OR = "OR"
    XOR = "XOR"
    NOT = "NOT"
    SHL = "SHL"
    SHR = "SHR"

    # Comparisons
    CEQ = "CEQ"
    CGT = "CGT"
    CLT = "CLT"

    # Control Flow & Branching
    BR = "BR"
    BR_TRUE = "BR_TRUE"
    BR_FALSE = "BR_FALSE"
    BEQ = "BEQ"
    BNE = "BNE"
    BGT = "BGT"
    BGE = "BGE"
    BLT = "BLT"
    BLE = "BLE"

    # Invocations & Objects
    CALL = "CALL"
    CALLVIRT = "CALLVIRT"
    NEWOBJ = "NEWOBJ"
    NEWARR = "NEWARR"
    LDLEN = "LDLEN"

    # Conversions
    CONV_I4 = "CONV_I4"
    CONV_I8 = "CONV_I8"
    CONV_R4 = "CONV_R4"
    CONV_R8 = "CONV_R8"
    CONV_U4 = "CONV_U4"
    CONV_U8 = "CONV_U8"

    # Flow Termination
    RET = "RET"
    THROW = "THROW"

    UNKNOWN = "UNKNOWN"


# Mapping from VMOpcode to expected operand encoding format
OPERAND_FORMATS: Dict[VMOpcode, str] = {
    VMOpcode.NOP: "none",
    VMOpcode.POP: "none",
    VMOpcode.DUP: "none",
    VMOpcode.LD_NULL: "none",
    VMOpcode.LD_I4: "i32",
    VMOpcode.LD_I8: "i64",
    VMOpcode.LD_R4: "r4",
    VMOpcode.LD_R8: "r8",
    VMOpcode.LD_STR: "token",
    VMOpcode.LD_LOC: "u16",
    VMOpcode.ST_LOC: "u16",
    VMOpcode.LD_LOCA: "u16",
    VMOpcode.LD_ARG: "u16",
    VMOpcode.ST_ARG: "u16",
    VMOpcode.LD_ARGA: "u16",
    VMOpcode.ADD: "none",
    VMOpcode.SUB: "none",
    VMOpcode.MUL: "none",
    VMOpcode.DIV: "none",
    VMOpcode.REM: "none",
    VMOpcode.NEG: "none",
    VMOpcode.AND: "none",
    VMOpcode.OR: "none",
    VMOpcode.XOR: "none",
    VMOpcode.NOT: "none",
    VMOpcode.SHL: "none",
    VMOpcode.SHR: "none",
    VMOpcode.CEQ: "none",
    VMOpcode.CGT: "none",
    VMOpcode.CLT: "none",
    VMOpcode.BR: "target",
    VMOpcode.BR_TRUE: "target",
    VMOpcode.BR_FALSE: "target",
    VMOpcode.BEQ: "target",
    VMOpcode.BNE: "target",
    VMOpcode.BGT: "target",
    VMOpcode.BGE: "target",
    VMOpcode.BLT: "target",
    VMOpcode.BLE: "target",
    VMOpcode.CALL: "token",
    VMOpcode.CALLVIRT: "token",
    VMOpcode.NEWOBJ: "token",
    VMOpcode.NEWARR: "token",
    VMOpcode.LDLEN: "none",
    VMOpcode.CONV_I4: "none",
    VMOpcode.CONV_I8: "none",
    VMOpcode.CONV_R4: "none",
    VMOpcode.CONV_R8: "none",
    VMOpcode.CONV_U4: "none",
    VMOpcode.CONV_U8: "none",
    VMOpcode.RET: "none",
    VMOpcode.THROW: "none",
    VMOpcode.UNKNOWN: "none",
}


class VMOpcodeTable:
    """
    Manages translation between raw VM opcode bytes (0x00..0xFF) and semantic VMOpcode.
    Supports default canonical mappings, custom user tables, and heuristic deduction.
    """

    # Canonical baseline opcode mapping (standard Eazfuscator reference)
    DEFAULT_BYTE_MAP: Dict[int, VMOpcode] = {
        0x00: VMOpcode.NOP,
        0x01: VMOpcode.POP,
        0x02: VMOpcode.DUP,
        0x03: VMOpcode.LD_NULL,
        0x10: VMOpcode.LD_I4,
        0x11: VMOpcode.LD_I8,
        0x12: VMOpcode.LD_R4,
        0x13: VMOpcode.LD_R8,
        0x14: VMOpcode.LD_STR,
        0x20: VMOpcode.LD_LOC,
        0x21: VMOpcode.ST_LOC,
        0x22: VMOpcode.LD_LOCA,
        0x25: VMOpcode.LD_ARG,
        0x26: VMOpcode.ST_ARG,
        0x27: VMOpcode.LD_ARGA,
        0x30: VMOpcode.ADD,
        0x31: VMOpcode.SUB,
        0x32: VMOpcode.MUL,
        0x33: VMOpcode.DIV,
        0x34: VMOpcode.REM,
        0x35: VMOpcode.NEG,
        0x36: VMOpcode.AND,
        0x37: VMOpcode.OR,
        0x38: VMOpcode.XOR,
        0x39: VMOpcode.NOT,
        0x3A: VMOpcode.SHL,
        0x3B: VMOpcode.SHR,
        0x40: VMOpcode.CEQ,
        0x41: VMOpcode.CGT,
        0x42: VMOpcode.CLT,
        0x50: VMOpcode.BR,
        0x51: VMOpcode.BR_TRUE,
        0x52: VMOpcode.BR_FALSE,
        0x53: VMOpcode.BEQ,
        0x54: VMOpcode.BNE,
        0x55: VMOpcode.BGT,
        0x56: VMOpcode.BGE,
        0x57: VMOpcode.BLT,
        0x58: VMOpcode.BLE,
        0x60: VMOpcode.CALL,
        0x61: VMOpcode.CALLVIRT,
        0x62: VMOpcode.NEWOBJ,
        0x63: VMOpcode.NEWARR,
        0x64: VMOpcode.LDLEN,
        0x70: VMOpcode.CONV_I4,
        0x71: VMOpcode.CONV_I8,
        0x72: VMOpcode.CONV_R4,
        0x73: VMOpcode.CONV_R8,
        0x74: VMOpcode.CONV_U4,
        0x75: VMOpcode.CONV_U8,
        0x7E: VMOpcode.THROW,
        0x7F: VMOpcode.RET,
    }

    def __init__(self, initial_map: Optional[Dict[int, VMOpcode]] = None):
        self._byte_to_opcode: Dict[int, VMOpcode] = {}
        self._opcode_to_byte: Dict[VMOpcode, int] = {}
        base_map = initial_map if initial_map is not None else self.DEFAULT_BYTE_MAP
        for b_val, op in base_map.items():
            self.set_mapping(b_val, op)

    def set_mapping(self, byte_val: int, opcode: Union[VMOpcode, str]) -> None:
        """Assigns byte value (0..255) to a semantic VMOpcode."""
        if isinstance(opcode, str):
            try:
                op_enum = VMOpcode(opcode)
            except ValueError:
                op_enum = VMOpcode.UNKNOWN
        else:
            op_enum = opcode

        b = byte_val & 0xFF
        self._byte_to_opcode[b] = op_enum
        self._opcode_to_byte[op_enum] = b

    def get_opcode(self, byte_val: int) -> VMOpcode:
        """Retrieves VMOpcode for a given byte value."""
        return self._byte_to_opcode.get(byte_val & 0xFF, VMOpcode.UNKNOWN)

    def get_byte(self, opcode: VMOpcode) -> Optional[int]:
        """Retrieves raw byte value associated with a semantic VMOpcode."""
        return self._opcode_to_byte.get(opcode)

    def to_dict(self) -> Dict[str, str]:
        """Exports opcode mapping as hex string dictionary."""
        return {f"0x{b:02X}": op.value for b, op in sorted(self._byte_to_opcode.items())}

    def to_json(self, indent: int = 2) -> str:
        """Serializes opcode table to JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, d: Dict[Union[int, str], str]) -> "VMOpcodeTable":
        """Instantiates VMOpcodeTable from dictionary."""
        tbl = cls(initial_map={})
        for k, v in d.items():
            if isinstance(k, str):
                b_val = int(k, 16) if (k.startswith("0x") or k.startswith("0X")) else int(k)
            else:
                b_val = int(k)
            tbl.set_mapping(b_val, v)
        return tbl

    @classmethod
    def infer_from_bytecode(cls, bytecode: bytes) -> "VMOpcodeTable":
        """
        Heuristically reconstructs randomized VM opcode mapping by analyzing
        terminal instruction positions, branch pointer boundaries, and token formats.
        """
        tbl = cls()
        if not bytecode:
            return tbl

        # 1. Terminal Ret Detection: Last byte of simple function is predominantly RET
        if len(bytecode) >= 1:
            last_byte = bytecode[-1]
            if tbl.get_opcode(last_byte) == VMOpcode.UNKNOWN:
                tbl.set_mapping(last_byte, VMOpcode.RET)

        # 2. Scan for metadata tokens (0x06xxxxxx for MethodDef, 0x0Axxxxxx for MemberRef, 0x70xxxxxx for UserString)
        # Often preceded by CALL (0x06 / 0x0A) or LD_STR (0x70)
        idx = 0
        while idx + 5 <= len(bytecode):
            op_byte = bytecode[idx]
            token = struct.unpack_from("<I", bytecode, idx + 1)[0]
            token_table = (token >> 24) & 0xFF
            if token_table in (0x06, 0x0A):  # MethodDef or MemberRef
                if tbl.get_opcode(op_byte) in (VMOpcode.UNKNOWN, VMOpcode.CALL):
                    tbl.set_mapping(op_byte, VMOpcode.CALL)
                idx += 5
                continue
            elif token_table == 0x70:  # UserString
                if tbl.get_opcode(op_byte) in (VMOpcode.UNKNOWN, VMOpcode.LD_STR):
                    tbl.set_mapping(op_byte, VMOpcode.LD_STR)
                idx += 5
                continue
            idx += 1

        return tbl


class VMInstruction:
    """Represents a single decoded instruction within an Eazfuscator VM bytecode stream."""

    def __init__(
        self,
        offset: int,
        raw_bytes: bytes,
        opcode: VMOpcode,
        operand: Any = None,
        mnemonic: Optional[str] = None,
    ):
        self.offset = offset
        self.raw_bytes = raw_bytes
        self.opcode = opcode
        self.operand = operand
        self.mnemonic = mnemonic or opcode.value

    def format(self) -> str:
        """Formats instruction into readable disassembly assembly text."""
        addr_str = f"{self.offset:04X}:"
        hex_bytes = self.raw_bytes.hex().upper()
        if self.operand is None:
            return f"{addr_str} {hex_bytes:12s} {self.mnemonic}"

        if self.opcode in (
            VMOpcode.BR,
            VMOpcode.BR_TRUE,
            VMOpcode.BR_FALSE,
            VMOpcode.BEQ,
            VMOpcode.BNE,
            VMOpcode.BGT,
            VMOpcode.BGE,
            VMOpcode.BLT,
            VMOpcode.BLE,
        ):
            target_str = f"IL_{self.operand:04X}" if isinstance(self.operand, int) else str(self.operand)
            return f"{addr_str} {hex_bytes:12s} {self.mnemonic} {target_str}"

        if self.opcode in (VMOpcode.CALL, VMOpcode.CALLVIRT, VMOpcode.NEWOBJ, VMOpcode.LD_STR, VMOpcode.NEWARR):
            if isinstance(self.operand, int):
                return f"{addr_str} {hex_bytes:12s} {self.mnemonic} 0x{self.operand:08X}"

        return f"{addr_str} {hex_bytes:12s} {self.mnemonic} {self.operand}"

    def __repr__(self) -> str:
        return f"<VMInstruction offset=0x{self.offset:X} opcode={self.opcode.value} operand={self.operand}>"


class EazfuscatorVMDisassembler:
    """Disassembler engine for Eazfuscator.NET proprietary VM bytecode."""

    def __init__(self, opcode_table: Optional[VMOpcodeTable] = None):
        self.table = opcode_table or VMOpcodeTable()

    def disassemble(self, bytecode: bytes, base_address: int = 0) -> List[VMInstruction]:
        """Decodes raw VM bytecode stream into a sequential list of VMInstructions."""
        instructions: List[VMInstruction] = []
        pc = 0
        total_len = len(bytecode)

        while pc < total_len:
            inst_offset = base_address + pc
            op_byte = bytecode[pc]
            pc += 1

            op_enum = self.table.get_opcode(op_byte)
            fmt = OPERAND_FORMATS.get(op_enum, "none")
            operand = None
            consumed_bytes = bytearray([op_byte])

            if fmt == "none":
                pass
            elif fmt == "i32":
                if pc + 4 <= total_len:
                    val = struct.unpack_from("<i", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 4])
                    pc += 4
                    operand = val
            elif fmt == "i64":
                if pc + 8 <= total_len:
                    val = struct.unpack_from("<q", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 8])
                    pc += 8
                    operand = val
            elif fmt == "r4":
                if pc + 4 <= total_len:
                    val = struct.unpack_from("<f", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 4])
                    pc += 4
                    operand = val
            elif fmt == "r8":
                if pc + 8 <= total_len:
                    val = struct.unpack_from("<d", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 8])
                    pc += 8
                    operand = val
            elif fmt == "u16":
                if pc + 2 <= total_len:
                    val = struct.unpack_from("<H", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 2])
                    pc += 2
                    operand = val
                elif pc + 1 <= total_len:
                    val = bytecode[pc]
                    consumed_bytes.append(val)
                    pc += 1
                    operand = val
            elif fmt == "token":
                if pc + 4 <= total_len:
                    val = struct.unpack_from("<I", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 4])
                    pc += 4
                    operand = val
            elif fmt == "target":
                # Relative jump target offset
                if pc + 4 <= total_len:
                    rel_offset = struct.unpack_from("<i", bytecode, pc)[0]
                    consumed_bytes.extend(bytecode[pc : pc + 4])
                    pc += 4
                    operand = inst_offset + len(consumed_bytes) + rel_offset
                elif pc + 1 <= total_len:
                    rel_offset = struct.unpack_from("<b", bytecode, pc)[0]
                    consumed_bytes.append(bytecode[pc])
                    pc += 1
                    operand = inst_offset + len(consumed_bytes) + rel_offset

            inst = VMInstruction(
                offset=inst_offset,
                raw_bytes=bytes(consumed_bytes),
                opcode=op_enum,
                operand=operand,
            )
            instructions.append(inst)

        return instructions

    def disassemble_to_text(self, bytecode: bytes, base_address: int = 0) -> str:
        """Returns disassembled bytecode as multiline formatted assembly text."""
        instructions = self.disassemble(bytecode, base_address=base_address)
        return "\n".join(inst.format() for inst in instructions)


class EazfuscatorDevirtualizer:
    """
    De-virtualizer engine: translates Eazfuscator VM instructions back into authentic
    standard ECMA-335 CIL (Common Intermediate Language) bytecodes and CorILMethod headers.
    """

    @classmethod
    def devirtualize(
        cls,
        instructions: List[VMInstruction],
        max_stack: int = 8,
        method_token: int = 0x06000001,
    ) -> Dict[str, Any]:
        """
        Translates a sequence of VMInstructions into standard CIL bytecodes,
        resolves branch targets, and wraps in an ECMA-335 CorILMethod header.
        """
        result: Dict[str, Any] = {
            "success": False,
            "method_token": method_token,
            "cil_bytes": b"",
            "cor_il_method": b"",
            "is_fat": False,
            "code_size": 0,
            "max_stack": max_stack,
            "instruction_count": len(instructions),
            "decompiled_cil_asm": "",
        }

        if not instructions:
            return result

        # Pass 1: Build preliminary CIL byte stream and record address mapping
        # vm_offset -> cil_offset
        vm_to_cil_offset: Dict[int, int] = {}
        cil_builder = bytearray()
        disasm_lines: List[str] = []

        # Temporary holder for branch fixups: (cil_patch_offset, target_vm_offset, op_name)
        branch_fixups: List[Tuple[int, int, str]] = []

        for inst in instructions:
            cil_pc = len(cil_builder)
            vm_to_cil_offset[inst.offset] = cil_pc
            op = inst.opcode
            arg = inst.operand

            if op == VMOpcode.NOP:
                cil_builder.append(0x00)
                disasm_lines.append(f"IL_{cil_pc:04X}: nop")

            elif op == VMOpcode.POP:
                cil_builder.append(0x26)
                disasm_lines.append(f"IL_{cil_pc:04X}: pop")

            elif op == VMOpcode.DUP:
                cil_builder.append(0x25)
                disasm_lines.append(f"IL_{cil_pc:04X}: dup")

            elif op == VMOpcode.LD_NULL:
                cil_builder.append(0x14)
                disasm_lines.append(f"IL_{cil_pc:04X}: ldnull")

            elif op == VMOpcode.LD_I4:
                val = int(arg) if arg is not None else 0
                if val > 0x7FFFFFFF:
                    val = (val & 0xFFFFFFFF) - 0x100000000
                elif val < -0x80000000:
                    val = -0x80000000

                if val == -1:
                    cil_builder.append(0x15)  # ldc.i4.m1
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldc.i4.m1")
                elif 0 <= val <= 8:
                    cil_builder.append(0x16 + val)  # ldc.i4.0 .. ldc.i4.8
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldc.i4.{val}")
                elif -128 <= val <= 127:
                    cil_builder.append(0x1F)  # ldc.i4.s
                    cil_builder.append(val & 0xFF)
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldc.i4.s {val}")
                else:
                    cil_builder.append(0x20)  # ldc.i4
                    cil_builder.extend(struct.pack("<i", val))
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldc.i4 {val}")

            elif op == VMOpcode.LD_I8:
                val = int(arg) if arg is not None else 0
                if val > 0x7FFFFFFFFFFFFFFF:
                    val = (val & 0xFFFFFFFFFFFFFFFF) - 0x10000000000000000
                elif val < -0x8000000000000000:
                    val = -0x8000000000000000
                cil_builder.append(0x21)  # ldc.i8
                cil_builder.extend(struct.pack("<q", val))
                disasm_lines.append(f"IL_{cil_pc:04X}: ldc.i8 {val}")

            elif op == VMOpcode.LD_R4:
                val = float(arg) if arg is not None else 0.0
                cil_builder.append(0x22)  # ldc.r4
                cil_builder.extend(struct.pack("<f", val))
                disasm_lines.append(f"IL_{cil_pc:04X}: ldc.r4 {val}")

            elif op == VMOpcode.LD_R8:
                val = float(arg) if arg is not None else 0.0
                cil_builder.append(0x23)  # ldc.r8
                cil_builder.extend(struct.pack("<d", val))
                disasm_lines.append(f"IL_{cil_pc:04X}: ldc.r8 {val}")

            elif op == VMOpcode.LD_STR:
                token = (int(arg) & 0xFFFFFFFF) if arg is not None else 0x70000001
                cil_builder.append(0x72)  # ldstr
                cil_builder.extend(struct.pack("<I", token))
                disasm_lines.append(f"IL_{cil_pc:04X}: ldstr 0x{token:08X}")

            elif op == VMOpcode.LD_LOC:
                idx = max(0, min(65535, int(arg) if arg is not None else 0))
                if 0 <= idx <= 3:
                    cil_builder.append(0x06 + idx)  # ldloc.0 .. ldloc.3
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldloc.{idx}")
                elif idx < 256:
                    cil_builder.extend([0x11, idx])  # ldloc.s
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldloc.s {idx}")
                else:
                    cil_builder.extend([0xFE, 0x0C])  # ldloc
                    cil_builder.extend(struct.pack("<H", idx))
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldloc {idx}")

            elif op == VMOpcode.ST_LOC:
                idx = max(0, min(65535, int(arg) if arg is not None else 0))
                if 0 <= idx <= 3:
                    cil_builder.append(0x0A + idx)  # stloc.0 .. stloc.3
                    disasm_lines.append(f"IL_{cil_pc:04X}: stloc.{idx}")
                elif idx < 256:
                    cil_builder.extend([0x13, idx])  # stloc.s
                    disasm_lines.append(f"IL_{cil_pc:04X}: stloc.s {idx}")
                else:
                    cil_builder.extend([0xFE, 0x0E])  # stloc
                    cil_builder.extend(struct.pack("<H", idx))
                    disasm_lines.append(f"IL_{cil_pc:04X}: stloc {idx}")

            elif op == VMOpcode.LD_LOCA:
                idx = max(0, min(65535, int(arg) if arg is not None else 0))
                if idx < 256:
                    cil_builder.extend([0x12, idx])  # ldloca.s
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldloca.s {idx}")
                else:
                    cil_builder.extend([0xFE, 0x0D])  # ldloca
                    cil_builder.extend(struct.pack("<H", idx))
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldloca {idx}")

            elif op == VMOpcode.LD_ARG:
                idx = max(0, min(65535, int(arg) if arg is not None else 0))
                if 0 <= idx <= 3:
                    cil_builder.append(0x02 + idx)  # ldarg.0 .. ldarg.3
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldarg.{idx}")
                elif idx < 256:
                    cil_builder.extend([0x0E, idx])  # ldarg.s
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldarg.s {idx}")
                else:
                    cil_builder.extend([0xFE, 0x09])  # ldarg
                    cil_builder.extend(struct.pack("<H", idx))
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldarg {idx}")

            elif op == VMOpcode.ST_ARG:
                idx = max(0, min(65535, int(arg) if arg is not None else 0))
                if idx < 256:
                    cil_builder.extend([0x10, idx])  # starg.s
                    disasm_lines.append(f"IL_{cil_pc:04X}: starg.s {idx}")
                else:
                    cil_builder.extend([0xFE, 0x0B])  # starg
                    cil_builder.extend(struct.pack("<H", idx))
                    disasm_lines.append(f"IL_{cil_pc:04X}: starg {idx}")

            elif op == VMOpcode.LD_ARGA:
                idx = max(0, min(65535, int(arg) if arg is not None else 0))
                if idx < 256:
                    cil_builder.extend([0x0F, idx])  # ldarga.s
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldarga.s {idx}")
                else:
                    cil_builder.extend([0xFE, 0x0A])  # ldarga
                    cil_builder.extend(struct.pack("<H", idx))
                    disasm_lines.append(f"IL_{cil_pc:04X}: ldarga {idx}")

            elif op == VMOpcode.ADD:
                cil_builder.append(0x58)
                disasm_lines.append(f"IL_{cil_pc:04X}: add")
            elif op == VMOpcode.SUB:
                cil_builder.append(0x59)
                disasm_lines.append(f"IL_{cil_pc:04X}: sub")
            elif op == VMOpcode.MUL:
                cil_builder.append(0x5A)
                disasm_lines.append(f"IL_{cil_pc:04X}: mul")
            elif op == VMOpcode.DIV:
                cil_builder.append(0x5B)
                disasm_lines.append(f"IL_{cil_pc:04X}: div")
            elif op == VMOpcode.REM:
                cil_builder.append(0x5D)
                disasm_lines.append(f"IL_{cil_pc:04X}: rem")
            elif op == VMOpcode.NEG:
                cil_builder.append(0x65)
                disasm_lines.append(f"IL_{cil_pc:04X}: neg")
            elif op == VMOpcode.AND:
                cil_builder.append(0x5F)
                disasm_lines.append(f"IL_{cil_pc:04X}: and")
            elif op == VMOpcode.OR:
                cil_builder.append(0x60)
                disasm_lines.append(f"IL_{cil_pc:04X}: or")
            elif op == VMOpcode.XOR:
                cil_builder.append(0x61)
                disasm_lines.append(f"IL_{cil_pc:04X}: xor")
            elif op == VMOpcode.NOT:
                cil_builder.append(0x66)
                disasm_lines.append(f"IL_{cil_pc:04X}: not")
            elif op == VMOpcode.SHL:
                cil_builder.append(0x62)
                disasm_lines.append(f"IL_{cil_pc:04X}: shl")
            elif op == VMOpcode.SHR:
                cil_builder.append(0x63)
                disasm_lines.append(f"IL_{cil_pc:04X}: shr")

            elif op == VMOpcode.CEQ:
                cil_builder.extend([0xFE, 0x01])
                disasm_lines.append(f"IL_{cil_pc:04X}: ceq")
            elif op == VMOpcode.CGT:
                cil_builder.extend([0xFE, 0x02])
                disasm_lines.append(f"IL_{cil_pc:04X}: cgt")
            elif op == VMOpcode.CLT:
                cil_builder.extend([0xFE, 0x04])
                disasm_lines.append(f"IL_{cil_pc:04X}: clt")

            elif op in (
                VMOpcode.BR,
                VMOpcode.BR_TRUE,
                VMOpcode.BR_FALSE,
                VMOpcode.BEQ,
                VMOpcode.BNE,
                VMOpcode.BGT,
                VMOpcode.BGE,
                VMOpcode.BLT,
                VMOpcode.BLE,
            ):
                # Emit 5-byte long form branch placeholder: opcode (1 byte) + rel_target (4 bytes)
                branch_opcodes = {
                    VMOpcode.BR: (0x38, "br"),
                    VMOpcode.BR_TRUE: (0x3A, "brtrue"),
                    VMOpcode.BR_FALSE: (0x39, "brfalse"),
                    VMOpcode.BEQ: (0x3B, "beq"),
                    VMOpcode.BNE: (0x40, "bne.un"),
                    VMOpcode.BGT: (0x3D, "bgt"),
                    VMOpcode.BGE: (0x3C, "bge"),
                    VMOpcode.BLT: (0x3F, "blt"),
                    VMOpcode.BLE: (0x3E, "ble"),
                }
                b_code, b_name = branch_opcodes[op]
                cil_builder.append(b_code)
                patch_offset = len(cil_builder)
                cil_builder.extend([0, 0, 0, 0])  # 4 bytes zero placeholder
                target_vm = int(arg) if arg is not None else inst.offset
                branch_fixups.append((patch_offset, target_vm, b_name))
                disasm_lines.append(f"IL_{cil_pc:04X}: {b_name} [rel]")

            elif op == VMOpcode.CALL:
                token = (int(arg) & 0xFFFFFFFF) if arg is not None else 0x06000001
                cil_builder.append(0x28)  # call
                cil_builder.extend(struct.pack("<I", token))
                disasm_lines.append(f"IL_{cil_pc:04X}: call 0x{token:08X}")

            elif op == VMOpcode.CALLVIRT:
                token = (int(arg) & 0xFFFFFFFF) if arg is not None else 0x06000001
                cil_builder.append(0x6F)  # callvirt
                cil_builder.extend(struct.pack("<I", token))
                disasm_lines.append(f"IL_{cil_pc:04X}: callvirt 0x{token:08X}")

            elif op == VMOpcode.NEWOBJ:
                token = (int(arg) & 0xFFFFFFFF) if arg is not None else 0x06000001
                cil_builder.append(0x73)  # newobj
                cil_builder.extend(struct.pack("<I", token))
                disasm_lines.append(f"IL_{cil_pc:04X}: newobj 0x{token:08X}")

            elif op == VMOpcode.NEWARR:
                token = (int(arg) & 0xFFFFFFFF) if arg is not None else 0x01000001
                cil_builder.append(0x8D)  # newarr
                cil_builder.extend(struct.pack("<I", token))
                disasm_lines.append(f"IL_{cil_pc:04X}: newarr 0x{token:08X}")

            elif op == VMOpcode.LDLEN:
                cil_builder.append(0x8E)  # ldlen
                disasm_lines.append(f"IL_{cil_pc:04X}: ldlen")

            elif op == VMOpcode.CONV_I4:
                cil_builder.append(0x69)
                disasm_lines.append(f"IL_{cil_pc:04X}: conv.i4")
            elif op == VMOpcode.CONV_I8:
                cil_builder.append(0x6A)
                disasm_lines.append(f"IL_{cil_pc:04X}: conv.i8")
            elif op == VMOpcode.CONV_R4:
                cil_builder.append(0x6B)
                disasm_lines.append(f"IL_{cil_pc:04X}: conv.r4")
            elif op == VMOpcode.CONV_R8:
                cil_builder.append(0x6C)
                disasm_lines.append(f"IL_{cil_pc:04X}: conv.r8")
            elif op == VMOpcode.CONV_U4:
                cil_builder.append(0x6D)
                disasm_lines.append(f"IL_{cil_pc:04X}: conv.u4")
            elif op == VMOpcode.CONV_U8:
                cil_builder.append(0x6E)
                disasm_lines.append(f"IL_{cil_pc:04X}: conv.u8")

            elif op == VMOpcode.RET:
                cil_builder.append(0x2A)  # ret
                disasm_lines.append(f"IL_{cil_pc:04X}: ret")

            elif op == VMOpcode.THROW:
                cil_builder.append(0x7A)  # throw
                disasm_lines.append(f"IL_{cil_pc:04X}: throw")

            else:
                cil_builder.append(0x00)  # nop fallback
                disasm_lines.append(f"IL_{cil_pc:04X}: nop // unmapped")

        # Pass 2: Resolve relative branch targets
        for patch_offset, target_vm, b_name in branch_fixups:
            target_cil = vm_to_cil_offset.get(target_vm, len(cil_builder))
            # Relative offset is from the byte following the instruction (i.e. patch_offset + 4)
            rel_offset = target_cil - (patch_offset + 4)
            struct.pack_into("<i", cil_builder, patch_offset, rel_offset)

        cil_bytes = bytes(cil_builder)
        code_size = len(cil_bytes)

        # Construct ECMA-335 Method Header:
        # CorILMethod_TinyFormat: 1 byte: (CodeSize << 2) | 0x02 (if code_size <= 63 and maxstack <= 8)
        # CorILMethod_FatFormat: 12 bytes: Flags_Size (0x3002), MaxStack, CodeSize, LocalVarSigTok (0)
        is_fat = code_size > 63 or max_stack > 8
        if not is_fat:
            tiny_hdr = bytes([(code_size << 2) | 0x02])
            cor_il_method = tiny_hdr + cil_bytes
        else:
            fat_hdr = struct.pack("<HHI I", 0x3002, max_stack, code_size, 0)
            cor_il_method = fat_hdr + cil_bytes

        result["success"] = True
        result["cil_bytes"] = cil_bytes
        result["cor_il_method"] = cor_il_method
        result["is_fat"] = is_fat
        result["code_size"] = code_size
        result["decompiled_cil_asm"] = "\n".join(disasm_lines)
        return result
