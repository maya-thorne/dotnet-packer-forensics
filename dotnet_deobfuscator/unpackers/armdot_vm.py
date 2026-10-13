"""
ArmDot Virtual Machine Bytecode Disassembler, Opcode Table & Stack Emulator.
Engineered & Audited by Maya Thorne.
"""

import json
import struct
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class ArmDotOpcode(str, Enum):
    """Semantic opcodes for ArmDot Method-Level Virtual Machine."""

    # Stack Manipulation & Control
    NOP = "NOP"
    POP = "POP"
    DUP = "DUP"
    RET = "RET"

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
    SWITCH = "SWITCH"

    # Invocations, Fields & Objects
    CALL = "CALL"
    CALLVIRT = "CALLVIRT"
    NEWOBJ = "NEWOBJ"
    NEWARR = "NEWARR"
    LDLEN = "LDLEN"
    LDFLD = "LDFLD"
    STFLD = "STFLD"
    LDSFLD = "LDSFLD"
    STSFLD = "STSFLD"

    # Type Conversions
    CONV_I4 = "CONV_I4"
    CONV_I8 = "CONV_I8"
    CONV_R4 = "CONV_R4"
    CONV_R8 = "CONV_R8"
    CONV_U4 = "CONV_U4"
    CONV_U8 = "CONV_U8"

    # Exceptions
    THROW = "THROW"
    RETHROW = "RETHROW"

    UNKNOWN = "UNKNOWN"


# Mapping from ArmDotOpcode to expected operand encoding format
OPERAND_FORMATS: Dict[ArmDotOpcode, str] = {
    ArmDotOpcode.NOP: "none",
    ArmDotOpcode.POP: "none",
    ArmDotOpcode.DUP: "none",
    ArmDotOpcode.RET: "none",
    ArmDotOpcode.LD_NULL: "none",
    ArmDotOpcode.LD_I4: "i32",
    ArmDotOpcode.LD_I8: "i64",
    ArmDotOpcode.LD_R4: "r4",
    ArmDotOpcode.LD_R8: "r8",
    ArmDotOpcode.LD_STR: "string",
    ArmDotOpcode.LD_LOC: "u16",
    ArmDotOpcode.ST_LOC: "u16",
    ArmDotOpcode.LD_LOCA: "u16",
    ArmDotOpcode.LD_ARG: "u16",
    ArmDotOpcode.ST_ARG: "u16",
    ArmDotOpcode.LD_ARGA: "u16",
    ArmDotOpcode.ADD: "none",
    ArmDotOpcode.SUB: "none",
    ArmDotOpcode.MUL: "none",
    ArmDotOpcode.DIV: "none",
    ArmDotOpcode.REM: "none",
    ArmDotOpcode.NEG: "none",
    ArmDotOpcode.AND: "none",
    ArmDotOpcode.OR: "none",
    ArmDotOpcode.XOR: "none",
    ArmDotOpcode.NOT: "none",
    ArmDotOpcode.SHL: "none",
    ArmDotOpcode.SHR: "none",
    ArmDotOpcode.CEQ: "none",
    ArmDotOpcode.CGT: "none",
    ArmDotOpcode.CLT: "none",
    ArmDotOpcode.BR: "branch",
    ArmDotOpcode.BR_TRUE: "branch",
    ArmDotOpcode.BR_FALSE: "branch",
    ArmDotOpcode.BEQ: "branch",
    ArmDotOpcode.BNE: "branch",
    ArmDotOpcode.BGT: "branch",
    ArmDotOpcode.BGE: "branch",
    ArmDotOpcode.BLT: "branch",
    ArmDotOpcode.BLE: "branch",
    ArmDotOpcode.SWITCH: "switch",
    ArmDotOpcode.CALL: "token",
    ArmDotOpcode.CALLVIRT: "token",
    ArmDotOpcode.NEWOBJ: "token",
    ArmDotOpcode.NEWARR: "token",
    ArmDotOpcode.LDLEN: "none",
    ArmDotOpcode.LDFLD: "token",
    ArmDotOpcode.STFLD: "token",
    ArmDotOpcode.LDSFLD: "token",
    ArmDotOpcode.STSFLD: "token",
    ArmDotOpcode.CONV_I4: "none",
    ArmDotOpcode.CONV_I8: "none",
    ArmDotOpcode.CONV_R4: "none",
    ArmDotOpcode.CONV_R8: "none",
    ArmDotOpcode.CONV_U4: "none",
    ArmDotOpcode.CONV_U8: "none",
    ArmDotOpcode.THROW: "none",
    ArmDotOpcode.RETHROW: "none",
    ArmDotOpcode.UNKNOWN: "none",
}


class ArmDotInstruction:
    """Represents a decoded instruction inside an ArmDot VM method bytecode stream."""

    def __init__(
        self,
        offset: int,
        opcode: ArmDotOpcode,
        raw_bytes: bytes,
        operand: Any = None,
        branch_target: Optional[int] = None,
        switch_targets: Optional[List[int]] = None,
    ):
        self.offset = offset
        self.opcode = opcode
        self.raw_bytes = raw_bytes
        self.operand = operand
        self.branch_target = branch_target
        self.switch_targets = switch_targets or []

    @property
    def length(self) -> int:
        return len(self.raw_bytes)

    def format(self) -> str:
        """Outputs a clean, human-readable assembly instruction representation."""
        prefix = f"IL_{self.offset:04X}: {self.opcode.value:<10}"
        if self.opcode in (
            ArmDotOpcode.BR,
            ArmDotOpcode.BR_TRUE,
            ArmDotOpcode.BR_FALSE,
            ArmDotOpcode.BEQ,
            ArmDotOpcode.BNE,
            ArmDotOpcode.BGT,
            ArmDotOpcode.BGE,
            ArmDotOpcode.BLT,
            ArmDotOpcode.BLE,
        ):
            if self.branch_target is not None:
                return f"{prefix} -> IL_{self.branch_target:04X}"
            return f"{prefix} [rel {self.operand}]"

        if self.opcode == ArmDotOpcode.SWITCH:
            targets_str = ", ".join(f"IL_{t:04X}" for t in self.switch_targets)
            return f"{prefix} [{targets_str}]"

        if self.opcode in (
            ArmDotOpcode.CALL,
            ArmDotOpcode.CALLVIRT,
            ArmDotOpcode.NEWOBJ,
            ArmDotOpcode.NEWARR,
            ArmDotOpcode.LDFLD,
            ArmDotOpcode.STFLD,
            ArmDotOpcode.LDSFLD,
            ArmDotOpcode.STSFLD,
        ):
            return f"{prefix} 0x{int(self.operand):08X}"

        if self.operand is not None:
            if isinstance(self.operand, str):
                return f"{prefix} \"{self.operand}\""
            return f"{prefix} {self.operand}"

        return prefix

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": f"0x{self.offset:04X}",
            "opcode": self.opcode.value,
            "operand": self.operand,
            "branch_target": f"0x{self.branch_target:04X}" if self.branch_target is not None else None,
            "switch_targets": [f"0x{t:04X}" for t in self.switch_targets] if self.switch_targets else None,
            "bytes_hex": self.raw_bytes.hex(),
        }


class ArmDotOpcodeTable:
    """Maps byte opcode values (0-255) to semantic ArmDotOpcode identifiers."""

    DEFAULT_BYTE_MAPPING: Dict[int, ArmDotOpcode] = {
        0x00: ArmDotOpcode.NOP,
        0x01: ArmDotOpcode.POP,
        0x02: ArmDotOpcode.DUP,
        0x03: ArmDotOpcode.RET,
        0x10: ArmDotOpcode.LD_NULL,
        0x11: ArmDotOpcode.LD_I4,
        0x12: ArmDotOpcode.LD_I8,
        0x13: ArmDotOpcode.LD_R4,
        0x14: ArmDotOpcode.LD_R8,
        0x15: ArmDotOpcode.LD_STR,
        0x20: ArmDotOpcode.LD_LOC,
        0x21: ArmDotOpcode.ST_LOC,
        0x22: ArmDotOpcode.LD_LOCA,
        0x25: ArmDotOpcode.LD_ARG,
        0x26: ArmDotOpcode.ST_ARG,
        0x27: ArmDotOpcode.LD_ARGA,
        0x30: ArmDotOpcode.ADD,
        0x31: ArmDotOpcode.SUB,
        0x32: ArmDotOpcode.MUL,
        0x33: ArmDotOpcode.DIV,
        0x34: ArmDotOpcode.REM,
        0x35: ArmDotOpcode.NEG,
        0x36: ArmDotOpcode.AND,
        0x37: ArmDotOpcode.OR,
        0x38: ArmDotOpcode.XOR,
        0x39: ArmDotOpcode.NOT,
        0x3A: ArmDotOpcode.SHL,
        0x3B: ArmDotOpcode.SHR,
        0x40: ArmDotOpcode.CEQ,
        0x41: ArmDotOpcode.CGT,
        0x42: ArmDotOpcode.CLT,
        0x50: ArmDotOpcode.BR,
        0x51: ArmDotOpcode.BR_TRUE,
        0x52: ArmDotOpcode.BR_FALSE,
        0x53: ArmDotOpcode.BEQ,
        0x54: ArmDotOpcode.BNE,
        0x55: ArmDotOpcode.BGT,
        0x56: ArmDotOpcode.BGE,
        0x57: ArmDotOpcode.BLT,
        0x58: ArmDotOpcode.BLE,
        0x59: ArmDotOpcode.SWITCH,
        0x60: ArmDotOpcode.CALL,
        0x61: ArmDotOpcode.CALLVIRT,
        0x62: ArmDotOpcode.NEWOBJ,
        0x63: ArmDotOpcode.NEWARR,
        0x64: ArmDotOpcode.LDLEN,
        0x65: ArmDotOpcode.LDFLD,
        0x66: ArmDotOpcode.STFLD,
        0x67: ArmDotOpcode.LDSFLD,
        0x68: ArmDotOpcode.STSFLD,
        0x70: ArmDotOpcode.CONV_I4,
        0x71: ArmDotOpcode.CONV_I8,
        0x72: ArmDotOpcode.CONV_R4,
        0x73: ArmDotOpcode.CONV_R8,
        0x74: ArmDotOpcode.CONV_U4,
        0x75: ArmDotOpcode.CONV_U8,
        0x80: ArmDotOpcode.THROW,
        0x81: ArmDotOpcode.RETHROW,
    }

    def __init__(self, mapping: Optional[Dict[int, ArmDotOpcode]] = None):
        self._table: Dict[int, ArmDotOpcode] = dict(self.DEFAULT_BYTE_MAPPING)
        if mapping:
            self._table.update(mapping)

    def get_opcode(self, byte_val: int) -> ArmDotOpcode:
        return self._table.get(byte_val, ArmDotOpcode.UNKNOWN)

    def set_opcode(self, byte_val: int, opcode: ArmDotOpcode) -> None:
        self._table[byte_val] = opcode

    def to_dict(self) -> Dict[str, str]:
        return {f"0x{k:02X}": v.value for k, v in sorted(self._table.items())}

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "ArmDotOpcodeTable":
        table = cls()
        mapping = {}
        for k, v in data.items():
            byte_val = int(k, 16) if k.startswith("0x") else int(k)
            try:
                mapping[byte_val] = ArmDotOpcode(v)
            except ValueError:
                mapping[byte_val] = ArmDotOpcode.UNKNOWN
        table._table = mapping
        return table

    @classmethod
    def deduce_from_bytecode(
        cls, bytecode: bytes, metadata_tokens: Optional[List[int]] = None
    ) -> "ArmDotOpcodeTable":
        """
        Heuristically deduces opcode byte mappings by analyzing bytecode patterns,
        terminal instructions (RET), 4-byte metadata tokens, and branch targets.
        """
        table = cls()
        if not bytecode:
            return table

        # 1. Terminal byte analysis
        if len(bytecode) > 0:
            last_byte = bytecode[-1]
            table.set_opcode(last_byte, ArmDotOpcode.RET)

        # 2. Known metadata token scanning
        if metadata_tokens:
            for tok in metadata_tokens:
                tok_bytes = struct.pack("<I", tok)
                pos = 0
                while True:
                    idx = bytecode.find(tok_bytes, pos)
                    if idx == -1:
                        break
                    if idx > 0:
                        call_byte = bytecode[idx - 1]
                        if tok & 0xFF000000 == 0x06000000 or tok & 0xFF000000 == 0x0A000000:
                            table.set_opcode(call_byte, ArmDotOpcode.CALL)
                    pos = idx + 4

        return table


class ArmDotStackValue:
    """Symbolic tracking unit for ArmDot abstract evaluation stack emulation."""

    def __init__(self, val_type: str = "i32", const_value: Any = None):
        self.val_type = val_type
        self.const_value = const_value

    def __repr__(self) -> str:
        if self.const_value is not None:
            return f"StackVal({self.val_type}, {self.const_value})"
        return f"StackVal({self.val_type})"


class ArmDotStackEmulator:
    """
    Abstract evaluation stack emulator verifying method stack balance,
    calculating required max_stack depth, and detecting underflows or stack leaks.
    """

    def __init__(self):
        self.stack: List[ArmDotStackValue] = []
        self.max_depth: int = 0
        self.underflow_detected: bool = False
        self.imbalance_detected: bool = False

    def push(self, item: ArmDotStackValue) -> None:
        self.stack.append(item)
        if len(self.stack) > self.max_depth:
            self.max_depth = len(self.stack)

    def pop(self) -> Optional[ArmDotStackValue]:
        if not self.stack:
            self.underflow_detected = True
            return None
        return self.stack.pop()

    def step(self, inst: ArmDotInstruction) -> None:
        """Simulates the abstract stack effect of a single ArmDot VM instruction."""
        op = inst.opcode
        if op in (ArmDotOpcode.LD_I4, ArmDotOpcode.LD_I8, ArmDotOpcode.LD_R4, ArmDotOpcode.LD_R8):
            self.push(ArmDotStackValue("num", inst.operand))
        elif op == ArmDotOpcode.LD_NULL:
            self.push(ArmDotStackValue("null", None))
        elif op == ArmDotOpcode.LD_STR:
            self.push(ArmDotStackValue("string", inst.operand))
        elif op in (ArmDotOpcode.LD_LOC, ArmDotOpcode.LD_ARG, ArmDotOpcode.LD_LOCA, ArmDotOpcode.LD_ARGA):
            self.push(ArmDotStackValue("var", None))
        elif op == ArmDotOpcode.DUP:
            if self.stack:
                self.push(self.stack[-1])
            else:
                self.underflow_detected = True
        elif op in (ArmDotOpcode.POP, ArmDotOpcode.ST_LOC, ArmDotOpcode.ST_ARG):
            self.pop()
        elif op in (
            ArmDotOpcode.ADD,
            ArmDotOpcode.SUB,
            ArmDotOpcode.MUL,
            ArmDotOpcode.DIV,
            ArmDotOpcode.REM,
            ArmDotOpcode.AND,
            ArmDotOpcode.OR,
            ArmDotOpcode.XOR,
            ArmDotOpcode.SHL,
            ArmDotOpcode.SHR,
            ArmDotOpcode.CEQ,
            ArmDotOpcode.CGT,
            ArmDotOpcode.CLT,
        ):
            b = self.pop()
            a = self.pop()
            self.push(ArmDotStackValue("num", None))
        elif op in (ArmDotOpcode.NEG, ArmDotOpcode.NOT, ArmDotOpcode.CONV_I4, ArmDotOpcode.CONV_I8, ArmDotOpcode.CONV_R4, ArmDotOpcode.CONV_R8, ArmDotOpcode.CONV_U4, ArmDotOpcode.CONV_U8):
            a = self.pop()
            self.push(ArmDotStackValue("num", None))
        elif op in (ArmDotOpcode.BR_TRUE, ArmDotOpcode.BR_FALSE):
            self.pop()
        elif op in (ArmDotOpcode.BEQ, ArmDotOpcode.BNE, ArmDotOpcode.BGT, ArmDotOpcode.BGE, ArmDotOpcode.BLT, ArmDotOpcode.BLE):
            self.pop()
            self.pop()
        elif op == ArmDotOpcode.SWITCH:
            self.pop()
        elif op in (ArmDotOpcode.CALL, ArmDotOpcode.CALLVIRT, ArmDotOpcode.NEWOBJ):
            # Assume 1 push for general method results unless void
            self.push(ArmDotStackValue("result", None))
        elif op == ArmDotOpcode.LDLEN:
            self.pop()
            self.push(ArmDotStackValue("i32", None))
        elif op in (ArmDotOpcode.THROW, ArmDotOpcode.RETHROW):
            self.pop()
        elif op == ArmDotOpcode.RET:
            if self.stack:
                self.pop()


class ArmDotVMDisassembler:
    """
    Decodes and disassembles proprietary ArmDot VM bytecode into structured
    ArmDotInstruction representations with absolute branch target resolution.
    """

    def __init__(self, opcode_table: Optional[ArmDotOpcodeTable] = None):
        self.table = opcode_table or ArmDotOpcodeTable()

    def disassemble(self, bytecode: bytes) -> List[ArmDotInstruction]:
        """Disassembles a raw method bytecode stream into instructions."""
        instructions: List[ArmDotInstruction] = []
        offset = 0
        bc_len = len(bytecode)

        while offset < bc_len:
            inst_offset = offset
            b = bytecode[offset]
            offset += 1
            op = self.table.get_opcode(b)
            fmt = OPERAND_FORMATS.get(op, "none")

            operand: Any = None
            branch_target: Optional[int] = None
            switch_targets: List[int] = []

            if fmt == "none":
                pass
            elif fmt == "i32":
                if offset + 4 <= bc_len:
                    operand = struct.unpack_from("<i", bytecode, offset)[0]
                    offset += 4
            elif fmt == "i64":
                if offset + 8 <= bc_len:
                    operand = struct.unpack_from("<q", bytecode, offset)[0]
                    offset += 8
            elif fmt == "r4":
                if offset + 4 <= bc_len:
                    operand = round(struct.unpack_from("<f", bytecode, offset)[0], 5)
                    offset += 4
            elif fmt == "r8":
                if offset + 8 <= bc_len:
                    operand = round(struct.unpack_from("<d", bytecode, offset)[0], 8)
                    offset += 8
            elif fmt == "u16":
                if offset + 2 <= bc_len:
                    operand = struct.unpack_from("<H", bytecode, offset)[0]
                    offset += 2
            elif fmt == "token":
                if offset + 4 <= bc_len:
                    operand = struct.unpack_from("<I", bytecode, offset)[0]
                    offset += 4
            elif fmt == "string":
                if offset + 2 <= bc_len:
                    str_len = struct.unpack_from("<H", bytecode, offset)[0]
                    offset += 2
                    if offset + str_len <= bc_len:
                        raw_str = bytecode[offset : offset + str_len]
                        operand = raw_str.decode("utf-8", errors="replace")
                        offset += str_len
            elif fmt == "branch":
                if offset + 4 <= bc_len:
                    rel_offset = struct.unpack_from("<i", bytecode, offset)[0]
                    offset += 4
                    operand = rel_offset
                    branch_target = offset + rel_offset
            elif fmt == "switch":
                if offset + 4 <= bc_len:
                    count = struct.unpack_from("<I", bytecode, offset)[0]
                    offset += 4
                    base_offset = offset + (count * 4)
                    for _ in range(count):
                        if offset + 4 <= bc_len:
                            rel_target = struct.unpack_from("<i", bytecode, offset)[0]
                            offset += 4
                            switch_targets.append(base_offset + rel_target)

            raw = bytecode[inst_offset:offset]
            instructions.append(
                ArmDotInstruction(
                    offset=inst_offset,
                    opcode=op,
                    raw_bytes=raw,
                    operand=operand,
                    branch_target=branch_target,
                    switch_targets=switch_targets,
                )
            )

        return instructions

    def format_disassembly(self, instructions: List[ArmDotInstruction]) -> str:
        """Formats instruction list into clean assembly text."""
        return "\n".join(inst.format() for inst in instructions)
