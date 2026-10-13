"""
DeepSea Control Flow De-flattening & AST Reconstruction Engine.
Engineered & Audited by Maya Thorne.
"""

import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .deepsea_models import (
    ASTBlock,
    ASTIf,
    ASTMethod,
    ASTNode,
    ASTStatement,
    ASTWhile,
    BasicBlock,
    CILInstruction,
    CILOpcode,
    CILOperandType,
    ControlFlowGraph,
    FlowControl,
)


class CILDisassembler:
    """Decodes ECMA-335 Common Intermediate Language (CIL) bytecode streams."""

    OPCODE_INFO: Dict[int, Tuple[str, CILOperandType, FlowControl]] = {
        0x00: ("nop", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x02: ("ldarg.0", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x03: ("ldarg.1", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x04: ("ldarg.2", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x05: ("ldarg.3", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x06: ("ldloc.0", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x07: ("ldloc.1", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x08: ("ldloc.2", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x09: ("ldloc.3", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x0A: ("stloc.0", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x0B: ("stloc.1", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x0C: ("stloc.2", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x0D: ("stloc.3", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x0E: ("ldarg.s", CILOperandType.SHORT_INLINE_VAR, FlowControl.NEXT),
        0x0F: ("ldarga.s", CILOperandType.SHORT_INLINE_VAR, FlowControl.NEXT),
        0x10: ("starg.s", CILOperandType.SHORT_INLINE_VAR, FlowControl.NEXT),
        0x11: ("ldloc.s", CILOperandType.SHORT_INLINE_VAR, FlowControl.NEXT),
        0x12: ("ldloca.s", CILOperandType.SHORT_INLINE_VAR, FlowControl.NEXT),
        0x13: ("stloc.s", CILOperandType.SHORT_INLINE_VAR, FlowControl.NEXT),
        0x14: ("ldnull", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x15: ("ldc.i4.m1", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x16: ("ldc.i4.0", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x17: ("ldc.i4.1", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x18: ("ldc.i4.2", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x19: ("ldc.i4.3", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1A: ("ldc.i4.4", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1B: ("ldc.i4.5", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1C: ("ldc.i4.6", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1D: ("ldc.i4.7", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1E: ("ldc.i4.8", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1F: ("ldc.i4.s", CILOperandType.SHORT_INLINE_I, FlowControl.NEXT),
        0x20: ("ldc.i4", CILOperandType.INLINE_I, FlowControl.NEXT),
        0x21: ("ldc.i8", CILOperandType.INLINE_I8, FlowControl.NEXT),
        0x22: ("ldc.r4", CILOperandType.SHORT_INLINE_R, FlowControl.NEXT),
        0x23: ("ldc.r8", CILOperandType.INLINE_R, FlowControl.NEXT),
        0x25: ("dup", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x26: ("pop", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x28: ("call", CILOperandType.INLINE_METHOD, FlowControl.NEXT),
        0x2A: ("ret", CILOperandType.INLINE_NONE, FlowControl.RET),
        0x2B: ("br.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.BRANCH),
        0x2C: ("brfalse.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x2D: ("brtrue.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x2E: ("beq.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x2F: ("bge.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x30: ("bgt.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x31: ("ble.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x32: ("blt.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x33: ("bne.un.s", CILOperandType.SHORT_INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x38: ("br", CILOperandType.INLINE_BR_TARGET, FlowControl.BRANCH),
        0x39: ("brfalse", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x3A: ("brtrue", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x3B: ("beq", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x3C: ("bge", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x3D: ("bgt", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x3E: ("ble", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x3F: ("blt", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x40: ("bne.un", CILOperandType.INLINE_BR_TARGET, FlowControl.COND_BRANCH),
        0x45: ("switch", CILOperandType.INLINE_SWITCH, FlowControl.SWITCH),
        0x58: ("add", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x59: ("sub", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x5A: ("mul", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x5B: ("div", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x5D: ("rem", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x5F: ("and", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x60: ("or", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x61: ("xor", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x62: ("shl", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x63: ("shr", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x65: ("neg", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x66: ("not", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x69: ("conv.i4", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x6A: ("conv.i8", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x6F: ("callvirt", CILOperandType.INLINE_METHOD, FlowControl.NEXT),
        0x72: ("ldstr", CILOperandType.INLINE_STRING, FlowControl.NEXT),
        0x73: ("newobj", CILOperandType.INLINE_METHOD, FlowControl.NEXT),
        0x7A: ("throw", CILOperandType.INLINE_NONE, FlowControl.THROW),
        0x7B: ("ldfld", CILOperandType.INLINE_FIELD, FlowControl.NEXT),
        0x7D: ("stfld", CILOperandType.INLINE_FIELD, FlowControl.NEXT),
        0x7E: ("ldsfld", CILOperandType.INLINE_FIELD, FlowControl.NEXT),
        0x80: ("stsfld", CILOperandType.INLINE_FIELD, FlowControl.NEXT),
        0x8D: ("newarr", CILOperandType.INLINE_TYPE, FlowControl.NEXT),
        0x8E: ("ldlen", CILOperandType.INLINE_NONE, FlowControl.NEXT),
    }

    TWO_BYTE_OPCODES: Dict[int, Tuple[str, CILOperandType, FlowControl]] = {
        0x01: ("ceq", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x02: ("cgt", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x04: ("clt", CILOperandType.INLINE_NONE, FlowControl.NEXT),
        0x1A: ("rethrow", CILOperandType.INLINE_NONE, FlowControl.THROW),
    }

    @classmethod
    def disassemble(cls, bytecode: bytes, max_instructions: int = 50000) -> List[CILInstruction]:
        """Disassembles CIL byte stream into instruction models with bounds checking."""
        instructions: List[CILInstruction] = []
        pc = 0
        code_len = len(bytecode)

        while pc < code_len and len(instructions) < max_instructions:
            inst_offset = pc
            b0 = bytecode[pc]
            pc += 1

            if b0 == 0xFE:
                if pc >= code_len:
                    break
                b1 = bytecode[pc]
                pc += 1
                op_val = 0xFE00 | b1
                op_info = cls.TWO_BYTE_OPCODES.get(b1, (f"fe.{b1:02x}", CILOperandType.INLINE_NONE, FlowControl.NEXT))
            else:
                op_val = b0
                op_info = cls.OPCODE_INFO.get(b0, (f"op_{b0:02x}", CILOperandType.INLINE_NONE, FlowControl.NEXT))

            name, op_type, flow = op_info
            operand = None
            branch_target: Optional[int] = None
            switch_targets: Optional[List[int]] = None

            if op_type == CILOperandType.INLINE_NONE:
                pass
            elif op_type in (CILOperandType.SHORT_INLINE_I, CILOperandType.SHORT_INLINE_VAR):
                if pc + 1 <= code_len:
                    operand = struct.unpack_from("<b", bytecode, pc)[0]
                    pc += 1
            elif op_type == CILOperandType.SHORT_INLINE_BR_TARGET:
                if pc + 1 <= code_len:
                    rel = struct.unpack_from("<b", bytecode, pc)[0]
                    pc += 1
                    branch_target = pc + rel
                    operand = rel
            elif op_type in (CILOperandType.INLINE_I, CILOperandType.INLINE_METHOD, CILOperandType.INLINE_FIELD,
                             CILOperandType.INLINE_TYPE, CILOperandType.INLINE_STRING, CILOperandType.INLINE_TOK,
                             CILOperandType.INLINE_VAR):
                if pc + 4 <= code_len:
                    operand = struct.unpack_from("<i", bytecode, pc)[0]
                    pc += 4
            elif op_type == CILOperandType.INLINE_BR_TARGET:
                if pc + 4 <= code_len:
                    rel = struct.unpack_from("<i", bytecode, pc)[0]
                    pc += 4
                    branch_target = pc + rel
                    operand = rel
            elif op_type == CILOperandType.INLINE_I8:
                if pc + 8 <= code_len:
                    operand = struct.unpack_from("<q", bytecode, pc)[0]
                    pc += 8
            elif op_type == CILOperandType.SHORT_INLINE_R:
                if pc + 4 <= code_len:
                    operand = struct.unpack_from("<f", bytecode, pc)[0]
                    pc += 4
            elif op_type == CILOperandType.INLINE_R:
                if pc + 8 <= code_len:
                    operand = struct.unpack_from("<d", bytecode, pc)[0]
                    pc += 8
            elif op_type == CILOperandType.INLINE_SWITCH:
                if pc + 4 <= code_len:
                    count = struct.unpack_from("<I", bytecode, pc)[0]
                    pc += 4
                    base_target = pc + 4 * count
                    switch_targets = []
                    for _ in range(count):
                        if pc + 4 <= code_len:
                            rel = struct.unpack_from("<i", bytecode, pc)[0]
                            pc += 4
                            switch_targets.append(base_target + rel)
                    operand = switch_targets

            inst_size = pc - inst_offset
            instructions.append(
                CILInstruction(
                    offset=inst_offset,
                    opcode=op_val,
                    name=name,
                    operand=operand,
                    size=inst_size,
                    branch_target=branch_target,
                    switch_targets=switch_targets,
                    flow_control=flow,
                )
            )

        return instructions


class OpaquePredicateEliminator:
    """Simplifies constant conditional branches and eliminates opaque predicates."""

    @staticmethod
    def eliminate(instructions: List[CILInstruction]) -> List[CILInstruction]:
        """Scans for constant condition branch patterns and converts them."""
        clean: List[CILInstruction] = []
        i = 0
        n = len(instructions)

        while i < n:
            inst = instructions[i]

            # Pattern: ldc.i4.0 / ldc.i4.1 followed by brtrue / brfalse
            if i + 1 < n and inst.opcode in (CILOpcode.LDC_I4_0, CILOpcode.LDC_I4_1):
                next_inst = instructions[i + 1]
                val = 1 if inst.opcode == CILOpcode.LDC_I4_1 else 0

                if next_inst.opcode in (CILOpcode.BRTRUE, CILOpcode.BRTRUE_S):
                    if val == 1:
                        # Always branches -> convert to unconditional branch
                        br_op = CILOpcode.BR if next_inst.opcode == CILOpcode.BRTRUE else CILOpcode.BR_S
                        name = "br" if br_op == CILOpcode.BR else "br.s"
                        clean.append(
                            CILInstruction(
                                offset=inst.offset,
                                opcode=br_op,
                                name=name,
                                operand=next_inst.operand,
                                size=next_inst.size,
                                branch_target=next_inst.branch_target,
                                flow_control=FlowControl.BRANCH,
                            )
                        )
                    # If val == 0, brtrue never jumps -> simply skip both instructions (NOP dead branch)
                    i += 2
                    continue

                if next_inst.opcode in (CILOpcode.BRFALSE, CILOpcode.BRFALSE_S):
                    if val == 0:
                        # Always branches -> convert to unconditional branch
                        br_op = CILOpcode.BR if next_inst.opcode == CILOpcode.BRFALSE else CILOpcode.BR_S
                        name = "br" if br_op == CILOpcode.BR else "br.s"
                        clean.append(
                            CILInstruction(
                                offset=inst.offset,
                                opcode=br_op,
                                name=name,
                                operand=next_inst.operand,
                                size=next_inst.size,
                                branch_target=next_inst.branch_target,
                                flow_control=FlowControl.BRANCH,
                            )
                        )
                    # If val == 1, brfalse never jumps -> skip both instructions
                    i += 2
                    continue

            clean.append(inst)
            i += 1

        return clean


class DeepSeaDeflattener:
    """Detects and resolves control flow flattening state machines into structured CFGs."""

    @staticmethod
    def slice_basic_blocks(instructions: List[CILInstruction]) -> Dict[int, BasicBlock]:
        """Partitions instructions into BasicBlocks based on leaders."""
        if not instructions:
            return {}

        leaders: Set[int] = {instructions[0].offset}
        for i, inst in enumerate(instructions):
            if inst.branch_target is not None:
                leaders.add(inst.branch_target)
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
            elif inst.switch_targets:
                for t in inst.switch_targets:
                    leaders.add(t)
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
            elif inst.flow_control in (FlowControl.RET, FlowControl.THROW):
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)

        blocks: Dict[int, BasicBlock] = {}
        cur_block: Optional[BasicBlock] = None
        bid = 0

        for inst in instructions:
            if inst.offset in leaders:
                if cur_block and cur_block.instructions:
                    cur_block.end_offset = cur_block.instructions[-1].offset + cur_block.instructions[-1].size
                    blocks[cur_block.block_id] = cur_block
                cur_block = BasicBlock(bid, inst.offset)
                bid += 1

            if cur_block:
                cur_block.instructions.append(inst)

        if cur_block and cur_block.instructions:
            cur_block.end_offset = cur_block.instructions[-1].offset + cur_block.instructions[-1].size
            blocks[cur_block.block_id] = cur_block

        return blocks

    @classmethod
    def deflatten(cls, instructions: List[CILInstruction]) -> Tuple[List[BasicBlock], ControlFlowGraph]:
        """
        Main de-flattening algorithm:
        1. Slices basic blocks.
        2. Detects state variable, initial state, and switch loop dispatcher.
        3. Maps state machine values to body basic blocks.
        4. Symbolically evaluates block state transitions.
        5. Reconnects true execution flow, pruning dispatcher loops.
        """
        # Eliminate simple opaque predicates first
        instructions = OpaquePredicateEliminator.eliminate(instructions)
        blocks = cls.slice_basic_blocks(instructions)
        cfg = ControlFlowGraph(blocks=blocks, entry_id=0)

        if len(blocks) < 3:
            return list(blocks.values()), cfg

        # Find switch dispatcher block
        dispatcher_block: Optional[BasicBlock] = None
        switch_inst: Optional[CILInstruction] = None
        for b in blocks.values():
            for inst in b.instructions:
                if inst.opcode == CILOpcode.SWITCH and inst.switch_targets:
                    dispatcher_block = b
                    switch_inst = inst
                    b.is_dispatcher = True
                    break
            if dispatcher_block:
                break

        if not dispatcher_block or not switch_inst or not switch_inst.switch_targets:
            # Fallback if no explicit switch dispatcher is present: link standard successors
            cls._link_standard_successors(blocks)
            cfg.compute_predecessors()
            return list(blocks.values()), cfg

        # Map state index -> target basic block
        target_to_block = {b.start_offset: b for b in blocks.values()}
        state_to_block: Dict[int, BasicBlock] = {}
        for state_idx, target_off in enumerate(switch_inst.switch_targets):
            if target_off in target_to_block:
                blk = target_to_block[target_off]
                blk.state_id = state_idx
                state_to_block[state_idx] = blk

        # Analyze prologue block for initial state
        prologue_block = blocks[0]
        initial_state: Optional[int] = None
        for i, inst in enumerate(prologue_block.instructions):
            if inst.opcode in (CILOpcode.LDC_I4_0, CILOpcode.LDC_I4_1, CILOpcode.LDC_I4_2, CILOpcode.LDC_I4_3,
                               CILOpcode.LDC_I4_4, CILOpcode.LDC_I4_5, CILOpcode.LDC_I4_S, CILOpcode.LDC_I4):
                if i + 1 < len(prologue_block.instructions):
                    next_op = prologue_block.instructions[i + 1].opcode
                    if next_op in (CILOpcode.STLOC_0, CILOpcode.STLOC_1, CILOpcode.STLOC_2, CILOpcode.STLOC_3,
                                   CILOpcode.STLOC_S):
                        initial_state = cls._extract_int_constant(inst)

        # For each case block, identify state transition update
        deflattened_blocks: List[BasicBlock] = []
        for b in blocks.values():
            if b.is_dispatcher:
                continue

            # Check if block transitions to a new state before returning to loop
            cls._extract_block_state_transition(b)
            deflattened_blocks.append(b)

        # Rewire successors: replace state transition jump with direct link to target block
        for b in deflattened_blocks:
            b.successors.clear()
            if b.next_state is not None and b.next_state in state_to_block:
                target_blk = state_to_block[b.next_state]
                b.successors.add(target_blk.block_id)
            elif b.conditional_states:
                s_true, s_false = b.conditional_states
                if s_true in state_to_block:
                    b.successors.add(state_to_block[s_true].block_id)
                if s_false in state_to_block:
                    b.successors.add(state_to_block[s_false].block_id)
            else:
                # Ret or throw
                if b.last_instruction and b.last_instruction.flow_control not in (FlowControl.RET, FlowControl.THROW):
                    if b.block_id + 1 in blocks:
                        b.successors.add(b.block_id + 1)

        # Wire prologue to initial state block
        if initial_state is not None and initial_state in state_to_block:
            prologue_block.successors = {state_to_block[initial_state].block_id}

        # Filter out dispatcher block from CFG
        clean_blocks = {b.block_id: b for b in deflattened_blocks}
        clean_cfg = ControlFlowGraph(blocks=clean_blocks, entry_id=prologue_block.block_id)
        clean_cfg.compute_predecessors()

        # Reorder blocks in topological flow order
        top_order = clean_cfg.topological_sort()
        ordered_blocks = [clean_blocks[bid] for bid in top_order if bid in clean_blocks]

        return ordered_blocks, clean_cfg

    @staticmethod
    def _extract_int_constant(inst: CILInstruction) -> Optional[int]:
        if inst.opcode == CILOpcode.LDC_I4_M1:
            return -1
        if inst.opcode == CILOpcode.LDC_I4_0:
            return 0
        if inst.opcode == CILOpcode.LDC_I4_1:
            return 1
        if inst.opcode == CILOpcode.LDC_I4_2:
            return 2
        if inst.opcode == CILOpcode.LDC_I4_3:
            return 3
        if inst.opcode == CILOpcode.LDC_I4_4:
            return 4
        if inst.opcode == CILOpcode.LDC_I4_5:
            return 5
        if inst.opcode == CILOpcode.LDC_I4_6:
            return 6
        if inst.opcode == CILOpcode.LDC_I4_7:
            return 7
        if inst.opcode == CILOpcode.LDC_I4_8:
            return 8
        if inst.opcode in (CILOpcode.LDC_I4_S, CILOpcode.LDC_I4) and isinstance(inst.operand, int):
            return inst.operand
        return None

    @classmethod
    def _extract_block_state_transition(cls, block: BasicBlock) -> None:
        """Inspects trailing instructions in basic block for state updates."""
        insts = block.instructions
        n = len(insts)
        for i in range(max(0, n - 4), n - 1):
            inst = insts[i]
            next_inst = insts[i + 1]
            c_val = cls._extract_int_constant(inst)
            if c_val is not None and next_inst.opcode in (
                CILOpcode.STLOC_0,
                CILOpcode.STLOC_1,
                CILOpcode.STLOC_2,
                CILOpcode.STLOC_3,
                CILOpcode.STLOC_S,
            ):
                block.next_state = c_val
                # Strip state assignment and dispatcher jump from emitted body
                block.instructions = [ins for ins in insts if ins not in (inst, next_inst) and ins.flow_control != FlowControl.BRANCH]
                break

    @staticmethod
    def _link_standard_successors(blocks: Dict[int, BasicBlock]) -> None:
        for b in blocks.values():
            b.successors.clear()
            last = b.last_instruction
            if not last:
                continue
            if last.branch_target is not None:
                for target_b in blocks.values():
                    if target_b.start_offset == last.branch_target:
                        b.successors.add(target_b.block_id)
            if last.flow_control in (FlowControl.NEXT, FlowControl.COND_BRANCH):
                # Fallthrough
                for target_b in blocks.values():
                    if target_b.start_offset == b.end_offset:
                        b.successors.add(target_b.block_id)


class CILEmitter:
    """Reassembles rearranged basic blocks into valid ECMA-335 CIL bytecode."""

    @classmethod
    def emit_method(cls, blocks: List[BasicBlock], max_stack: int = 8) -> bytes:
        """Multi-pass branch offset calculation and CIL bytecode emission."""
        if not blocks:
            return b"\x2a"  # ret

        # Build clean instruction sequence
        emitted_insts: List[Dict[str, Any]] = []
        for i, b in enumerate(blocks):
            for inst in b.instructions:
                emitted_insts.append({"block_idx": i, "inst": inst, "is_jump": False})
            # Add synthetic jump if needed between non-adjacent blocks
            if b.successors:
                succ_id = next(iter(b.successors))
                # Check if succ is next block in emission order
                is_fallthrough = (i + 1 < len(blocks) and blocks[i + 1].block_id == succ_id)
                if not is_fallthrough:
                    emitted_insts.append({
                        "block_idx": i,
                        "inst": CILInstruction(0, CILOpcode.BR, "br", operand=succ_id, flow_control=FlowControl.BRANCH),
                        "is_jump": True,
                        "target_block_id": succ_id,
                    })

        # Ensure trailing return if not present
        if not emitted_insts or emitted_insts[-1]["inst"].opcode != CILOpcode.RET:
            emitted_insts.append({
                "block_idx": len(blocks) - 1,
                "inst": CILInstruction(0, CILOpcode.RET, "ret", flow_control=FlowControl.RET),
                "is_jump": False,
            })

        # Multi-pass relative offset resolution (up to 5 passes)
        block_offsets: Dict[int, int] = {}
        bytecode = bytearray()

        for _ in range(5):
            bytecode.clear()
            block_offsets.clear()
            cur_off = 0

            # Record block start offsets
            cur_block_idx = -1
            for entry in emitted_insts:
                b_idx = entry["block_idx"]
                if b_idx != cur_block_idx:
                    cur_block_idx = b_idx
                    block_offsets[blocks[b_idx].block_id] = cur_off
                inst: CILInstruction = entry["inst"]
                cur_off += cls._estimate_instruction_size(inst)

            # Emit bytes
            for entry in emitted_insts:
                inst: CILInstruction = entry["inst"]
                if entry["is_jump"]:
                    target_bid = entry["target_block_id"]
                    target_off = block_offsets.get(target_bid, cur_off)
                    rel = target_off - (len(bytecode) + 5)
                    bytecode.append(CILOpcode.BR)
                    bytecode.extend(struct.pack("<i", rel))
                else:
                    cls._encode_instruction(bytecode, inst, block_offsets)

        return bytes(bytecode)

    @classmethod
    def _estimate_instruction_size(cls, inst: CILInstruction) -> int:
        if inst.opcode == CILOpcode.BR:
            return 5
        if inst.opcode in (CILOpcode.LDC_I4_S, CILOpcode.LDARG_S, CILOpcode.LDLOC_S, CILOpcode.STLOC_S):
            return 2
        if inst.opcode in (CILOpcode.LDC_I4, CILOpcode.CALL, CILOpcode.CALLVIRT, CILOpcode.LDSTR):
            return 5
        if inst.opcode > 0xFF:
            return 2
        return 1

    @classmethod
    def _encode_instruction(cls, buf: bytearray, inst: CILInstruction, block_offsets: Dict[int, int]) -> None:
        op = inst.opcode
        if op > 0xFF:
            buf.extend(struct.pack(">H", op))
        else:
            buf.append(op)

        if inst.operand is not None:
            if op in (CILOpcode.LDC_I4_S, CILOpcode.LDARG_S, CILOpcode.LDLOC_S, CILOpcode.STLOC_S):
                buf.extend(struct.pack("<b", inst.operand))
            elif op in (CILOpcode.LDC_I4, CILOpcode.CALL, CILOpcode.CALLVIRT, CILOpcode.LDSTR):
                buf.extend(struct.pack("<i", inst.operand))


class ASTReconstructor:
    """Recovers structured statements and loops from de-flattened CFG."""

    @staticmethod
    def reconstruct(blocks: List[BasicBlock]) -> ASTMethod:
        """Constructs an ASTMethod representing high-level program structure."""
        method = ASTMethod("RestoredMethod", "void")
        root_block = method.body

        for b in blocks:
            stmt_texts = []
            for inst in b.instructions:
                if inst.opcode == CILOpcode.NOP:
                    continue
                if inst.opcode in (CILOpcode.LDSTR, CILOpcode.CALL, CILOpcode.CALLVIRT, CILOpcode.ADD, CILOpcode.SUB):
                    stmt_texts.append(f"{inst.name}({inst.operand or ''})")
                elif inst.opcode == CILOpcode.RET:
                    stmt_texts.append("return")
                else:
                    stmt_texts.append(f"{inst.name}")

            if stmt_texts:
                combined_text = "; ".join(stmt_texts)
                root_block.statements.append(ASTStatement(combined_text))

        return method
