"""
DeepSea Obfuscator Control Flow & Abstract Syntax Tree (AST) Data Models.
Engineered & Audited by Maya Thorne.
"""

from enum import Enum, auto
import struct
from typing import Any, Dict, List, Optional, Set, Tuple


class CILOpcode:
    """Standard ECMA-335 Common Intermediate Language (CIL) Opcode constants and definitions."""

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


class CILOperandType(Enum):
    """ECMA-335 operand encoding styles."""

    INLINE_NONE = auto()
    SHORT_INLINE_I = auto()
    INLINE_I = auto()
    INLINE_I8 = auto()
    SHORT_INLINE_R = auto()
    INLINE_R = auto()
    SHORT_INLINE_BR_TARGET = auto()
    INLINE_BR_TARGET = auto()
    INLINE_SWITCH = auto()
    SHORT_INLINE_VAR = auto()
    INLINE_VAR = auto()
    INLINE_STRING = auto()
    INLINE_METHOD = auto()
    INLINE_FIELD = auto()
    INLINE_TYPE = auto()
    INLINE_TOK = auto()


class FlowControl(Enum):
    """Instruction flow control characteristics."""

    NEXT = auto()
    BRANCH = auto()
    COND_BRANCH = auto()
    SWITCH = auto()
    RET = auto()
    THROW = auto()


class CILInstruction:
    """Represents a single decoded CIL instruction."""

    def __init__(
        self,
        offset: int,
        opcode: int,
        name: str,
        operand: Any = None,
        size: int = 1,
        branch_target: Optional[int] = None,
        switch_targets: Optional[List[int]] = None,
        flow_control: FlowControl = FlowControl.NEXT,
    ):
        self.offset = offset
        self.opcode = opcode
        self.name = name
        self.operand = operand
        self.size = size
        self.branch_target = branch_target
        self.switch_targets = switch_targets or []
        self.flow_control = flow_control

    def is_branch(self) -> bool:
        return self.flow_control in (FlowControl.BRANCH, FlowControl.COND_BRANCH)

    def is_conditional(self) -> bool:
        return self.flow_control == FlowControl.COND_BRANCH

    def is_terminator(self) -> bool:
        return self.flow_control in (
            FlowControl.BRANCH,
            FlowControl.COND_BRANCH,
            FlowControl.SWITCH,
            FlowControl.RET,
            FlowControl.THROW,
        )

    def __repr__(self) -> str:
        op_str = ""
        if self.branch_target is not None:
            op_str = f" IL_{self.branch_target:04X}"
        elif self.switch_targets:
            targets_str = ", ".join(f"IL_{t:04X}" for t in self.switch_targets)
            op_str = f" ({targets_str})"
        elif self.operand is not None:
            op_str = f" {self.operand}"
        return f"IL_{self.offset:04X}: {self.name}{op_str}"


class BasicBlock:
    """Represents a discrete basic block in a CIL method Control Flow Graph."""

    def __init__(self, block_id: int, start_offset: int):
        self.block_id = block_id
        self.start_offset = start_offset
        self.end_offset = start_offset
        self.instructions: List[CILInstruction] = []
        self.predecessors: Set[int] = set()
        self.successors: Set[int] = set()
        self.is_dispatcher: bool = False
        self.is_prologue: bool = False
        self.is_dead: bool = False
        self.state_id: Optional[int] = None
        self.next_state: Optional[int] = None
        self.conditional_states: Optional[Tuple[int, int]] = None  # (true_state, false_state)

    @property
    def last_instruction(self) -> Optional[CILInstruction]:
        return self.instructions[-1] if self.instructions else None

    def __repr__(self) -> str:
        return (
            f"BasicBlock(id={self.block_id}, range=[IL_{self.start_offset:04X}..IL_{self.end_offset:04X}], "
            f"state={self.state_id}, insts={len(self.instructions)}, succs={list(self.successors)})"
        )


class ControlFlowGraph:
    """Directed graph representing method control flow with visualization support."""

    def __init__(self, blocks: Optional[Dict[int, BasicBlock]] = None, entry_id: int = 0):
        self.blocks: Dict[int, BasicBlock] = blocks or {}
        self.entry_id = entry_id

    def add_block(self, block: BasicBlock) -> None:
        self.blocks[block.block_id] = block

    def get_block(self, block_id: int) -> Optional[BasicBlock]:
        return self.blocks.get(block_id)

    def compute_predecessors(self) -> None:
        """Computes block predecessors based on successor links."""
        for b in self.blocks.values():
            b.predecessors.clear()
        for b in self.blocks.values():
            for succ_id in b.successors:
                if succ_id in self.blocks:
                    self.blocks[succ_id].predecessors.add(b.block_id)

    def topological_sort(self) -> List[int]:
        """Returns block IDs in topological execution order using DFS."""
        visited: Set[int] = set()
        order: List[int] = []

        def dfs(bid: int) -> None:
            if bid in visited:
                return
            visited.add(bid)
            block = self.blocks.get(bid)
            if block:
                for succ in sorted(block.successors):
                    if succ not in visited:
                        dfs(succ)
            order.append(bid)

        if self.entry_id in self.blocks:
            dfs(self.entry_id)
        for bid in sorted(self.blocks.keys()):
            if bid not in visited:
                dfs(bid)

        order.reverse()
        return order

    def export_dot(self, title: str = "ControlFlowGraph") -> str:
        """Exports graph to Graphviz DOT specification."""
        lines = [f'digraph "{title}" {{', '  rankdir="TB";', '  node [shape=box, fontname="Courier"];']
        for bid, b in sorted(self.blocks.items()):
            label = f"Block {bid} (IL_{b.start_offset:04X})\\n"
            if b.state_id is not None:
                label += f"State: {b.state_id}\\n"
            for inst in b.instructions[:6]:
                label += f"{inst}\\n"
            if len(b.instructions) > 6:
                label += f"... ({len(b.instructions) - 6} more)\\n"
            color = "gray" if b.is_dead else ("lightblue" if b.is_dispatcher else "black")
            lines.append(f'  B{bid} [label="{label}", color="{color}"];')

        for bid, b in sorted(self.blocks.items()):
            for succ in sorted(b.successors):
                lines.append(f"  B{bid} -> B{succ};")
        lines.append("}")
        return "\n".join(lines)

    def export_mermaid(self) -> str:
        """Exports graph to GitHub-compatible Mermaid flowchart."""
        lines = ["flowchart TD"]
        for bid, b in sorted(self.blocks.items()):
            first_inst = b.instructions[0].name if b.instructions else "empty"
            state_tag = f"State {b.state_id}" if b.state_id is not None else f"IL_{b.start_offset:04X}"
            lines.append(f'  B{bid}["Block {bid} ({state_tag})<br/>{first_inst}.."]')
        for bid, b in sorted(self.blocks.items()):
            for succ in sorted(b.successors):
                lines.append(f"  B{bid} --> B{succ}")
        return "\n".join(lines)


class ASTNodeType(Enum):
    """Abstract Syntax Tree node classification."""

    METHOD = auto()
    BLOCK = auto()
    STATEMENT = auto()
    IF = auto()
    WHILE = auto()
    RETURN = auto()
    EXPRESSION = auto()


class ASTNode:
    """Base class for high-level AST representation."""

    def __init__(self, node_type: ASTNodeType):
        self.node_type = node_type

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.node_type.name}

    def to_csharp(self, indent: int = 0) -> str:
        return " " * indent + "// AST Node"


class ASTStatement(ASTNode):
    """Single high-level statement."""

    def __init__(self, text: str):
        super().__init__(ASTNodeType.STATEMENT)
        self.text = text

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.node_type.name, "text": self.text}

    def to_csharp(self, indent: int = 0) -> str:
        return " " * indent + f"{self.text};"


class ASTBlock(ASTNode):
    """Block containing sequential statements."""

    def __init__(self, statements: Optional[List[ASTNode]] = None):
        super().__init__(ASTNodeType.BLOCK)
        self.statements: List[ASTNode] = statements or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.node_type.name,
            "statements": [s.to_dict() for s in self.statements],
        }

    def to_csharp(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [prefix + "{"]
        for stmt in self.statements:
            lines.append(stmt.to_csharp(indent + 2))
        lines.append(prefix + "}")
        return "\n".join(lines)


class ASTIf(ASTNode):
    """If-Then-Else branch structure."""

    def __init__(self, condition: str, then_body: ASTBlock, else_body: Optional[ASTBlock] = None):
        super().__init__(ASTNodeType.IF)
        self.condition = condition
        self.then_body = then_body
        self.else_body = else_body

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "type": self.node_type.name,
            "condition": self.condition,
            "then": self.then_body.to_dict(),
        }
        if self.else_body:
            res["else"] = self.else_body.to_dict()
        return res

    def to_csharp(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}if ({self.condition})", self.then_body.to_csharp(indent)]
        if self.else_body:
            lines.append(f"{prefix}else")
            lines.append(self.else_body.to_csharp(indent))
        return "\n".join(lines)


class ASTWhile(ASTNode):
    """While loop structure."""

    def __init__(self, condition: str, body: ASTBlock):
        super().__init__(ASTNodeType.WHILE)
        self.condition = condition
        self.body = body

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.node_type.name,
            "condition": self.condition,
            "body": self.body.to_dict(),
        }

    def to_csharp(self, indent: int = 0) -> str:
        prefix = " " * indent
        return f"{prefix}while ({self.condition})\n" + self.body.to_csharp(indent)


class ASTMethod(ASTNode):
    """Top-level Method AST root."""

    def __init__(self, name: str, return_type: str = "void", body: Optional[ASTBlock] = None):
        super().__init__(ASTNodeType.METHOD)
        self.name = name
        self.return_type = return_type
        self.body = body or ASTBlock()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.node_type.name,
            "name": self.name,
            "return_type": self.return_type,
            "body": self.body.to_dict(),
        }

    def to_csharp(self, indent: int = 0) -> str:
        prefix = " " * indent
        header = f"{prefix}public {self.return_type} {self.name}()"
        return f"{header}\n" + self.body.to_csharp(indent)
