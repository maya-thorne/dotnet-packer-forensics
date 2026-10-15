"""
CIL Control Flow Graph (CFG) Builder & Obfuscation Heuristic Analyzer.
Engineered & Audited by Maya Thorne.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    BlockAnomalyFlag,
    BlockEntropyLevel,
    CFGBlock,
    CFGEdge,
    CFGEdgeType,
    CFGInstruction,
    FlowControl,
    MethodCFG,
    calculate_entropy,
)


class CFGBuilder:
    """Builds structured Control Flow Graphs (CFG) from disassembled CIL instructions."""

    @classmethod
    def build(
        cls,
        instructions: List[CFGInstruction],
        method_token: int = 0x06000001,
        method_name: str = "Method",
    ) -> MethodCFG:
        """Constructs a complete MethodCFG with basic blocks, edges, entropy profiling, and anomaly diagnostics."""
        if not instructions:
            empty_block = CFGBlock(
                block_id=0,
                start_offset=0,
                end_offset=0,
                instructions=[],
                raw_bytes=b"",
                entropy=0.0,
                entropy_level=BlockEntropyLevel.LOW,
            )
            empty_block.is_entry = True
            empty_block.is_exit = True
            return MethodCFG(
                method_token=method_token,
                method_name=method_name,
                entry_block_id=0,
                blocks={0: empty_block},
                edges=[],
                cyclomatic_complexity=1,
            )

        # 1. Identify all basic block leader offsets
        leaders: Set[int] = {instructions[0].offset}
        inst_by_offset: Dict[int, CFGInstruction] = {i.offset: i for i in instructions}
        all_offsets: List[int] = sorted(inst_by_offset.keys())
        last_inst_offset = all_offsets[-1]
        method_end_offset = last_inst_offset + inst_by_offset[last_inst_offset].size

        for idx, inst in enumerate(instructions):
            next_inst = instructions[idx + 1] if idx + 1 < len(instructions) else None

            # Branch targets are leaders
            if inst.branch_target is not None:
                leaders.add(inst.branch_target)

            # Switch targets are leaders
            for sw_target in inst.switch_targets:
                leaders.add(sw_target)

            # Instructions immediately following branches/terminators are leaders
            if inst.is_terminator() and next_inst is not None:
                leaders.add(next_inst.offset)

        # 2. Group instructions into basic blocks
        sorted_leaders = sorted(leaders)
        blocks: Dict[int, CFGBlock] = {}
        offset_to_block_id: Dict[int, int] = {}

        # Partition instructions by leader boundaries
        current_leader_idx = 0
        current_block_id = 0
        current_insts: List[CFGInstruction] = []
        current_start = sorted_leaders[0]

        for inst in instructions:
            # Check if this instruction starts a new block
            if inst.offset in sorted_leaders and inst.offset != current_start and current_insts:
                # Seal previous block
                raw_bytes = b"".join(i.raw_bytes for i in current_insts)
                entropy = calculate_entropy(raw_bytes)
                ent_lvl = cls._classify_entropy(entropy, len(raw_bytes))
                end_off = current_insts[-1].offset + current_insts[-1].size

                b = CFGBlock(
                    block_id=current_block_id,
                    start_offset=current_start,
                    end_offset=end_off,
                    instructions=current_insts,
                    raw_bytes=raw_bytes,
                    entropy=entropy,
                    entropy_level=ent_lvl,
                )
                blocks[current_block_id] = b
                offset_to_block_id[current_start] = current_block_id

                current_block_id += 1
                current_insts = []
                current_start = inst.offset

            current_insts.append(inst)

        # Seal final block
        if current_insts:
            raw_bytes = b"".join(i.raw_bytes for i in current_insts)
            entropy = calculate_entropy(raw_bytes)
            ent_lvl = cls._classify_entropy(entropy, len(raw_bytes))
            end_off = current_insts[-1].offset + current_insts[-1].size

            b = CFGBlock(
                block_id=current_block_id,
                start_offset=current_start,
                end_offset=end_off,
                instructions=current_insts,
                raw_bytes=raw_bytes,
                entropy=entropy,
                entropy_level=ent_lvl,
            )
            blocks[current_block_id] = b
            offset_to_block_id[current_start] = current_block_id

        # Map block offsets range for branch targeting
        block_list = sorted(blocks.values(), key=lambda b: b.start_offset)
        for idx, b in enumerate(block_list):
            b.block_id = idx  # Normalize 0..N-1

        normalized_blocks: Dict[int, CFGBlock] = {b.block_id: b for b in block_list}
        offset_to_bid: Dict[int, int] = {b.start_offset: b.block_id for b in block_list}

        # 3. Connect directed edges
        edges: List[CFGEdge] = []
        anomalies_detected: List[str] = []

        for bid, b in sorted(normalized_blocks.items()):
            if bid == 0:
                b.is_entry = True

            last_inst = b.last_instruction
            if not last_inst:
                continue

            if last_inst.flow_control in (FlowControl.RET, FlowControl.THROW):
                b.is_exit = True
                continue

            next_seq_bid = bid + 1 if bid + 1 < len(normalized_blocks) else None

            if last_inst.flow_control == FlowControl.BRANCH:
                # Unconditional branch (br, br.s, leave, leave.s)
                tgt_bid = offset_to_bid.get(last_inst.branch_target)
                if tgt_bid is not None:
                    edges.append(CFGEdge(bid, tgt_bid, CFGEdgeType.UNCONDITIONAL_BRANCH))
                    b.successors.add(tgt_bid)
                else:
                    b.anomaly_flags.append(BlockAnomalyFlag.ABNORMAL_BRANCH_TARGET)
                    tgt_str = f"IL_{last_inst.branch_target:04X}" if last_inst.branch_target is not None else "None"
                    anomalies_detected.append(f"Block B{bid}: Branch target {tgt_str} out of bounds")

            elif last_inst.flow_control == FlowControl.COND_BRANCH:
                # Conditional branch (brtrue, brfalse, beq, etc.)
                tgt_bid = offset_to_bid.get(last_inst.branch_target)
                if tgt_bid is not None:
                    edges.append(CFGEdge(bid, tgt_bid, CFGEdgeType.CONDITIONAL_TRUE, "true"))
                    b.successors.add(tgt_bid)
                else:
                    b.anomaly_flags.append(BlockAnomalyFlag.ABNORMAL_BRANCH_TARGET)
                    tgt_str = f"IL_{last_inst.branch_target:04X}" if last_inst.branch_target is not None else "None"
                    anomalies_detected.append(f"Block B{bid}: Conditional target {tgt_str} out of bounds")

                # Fallthrough branch
                if next_seq_bid is not None:
                    edges.append(CFGEdge(bid, next_seq_bid, CFGEdgeType.CONDITIONAL_FALSE, "false"))
                    b.successors.add(next_seq_bid)

                # Heuristic: Check for opaque predicate (both true/false point to same block)
                if tgt_bid is not None and tgt_bid == next_seq_bid:
                    b.anomaly_flags.append(BlockAnomalyFlag.OPAQUE_PREDICATE_SUSPECT)
                    anomalies_detected.append(f"Block B{bid}: True and false branches converge unconditionally -> Opaque predicate suspected")

            elif last_inst.flow_control == FlowControl.SWITCH:
                # Switch table
                seen_switch_targets = set()
                for s_idx, sw_target in enumerate(last_inst.switch_targets):
                    tgt_bid = offset_to_bid.get(sw_target)
                    if tgt_bid is not None:
                        edges.append(CFGEdge(bid, tgt_bid, CFGEdgeType.SWITCH_BRANCH, f"case {s_idx}"))
                        b.successors.add(tgt_bid)
                        seen_switch_targets.add(tgt_bid)
                    else:
                        b.anomaly_flags.append(BlockAnomalyFlag.ABNORMAL_BRANCH_TARGET)

                # Default fallthrough
                if next_seq_bid is not None:
                    edges.append(CFGEdge(bid, next_seq_bid, CFGEdgeType.FALLTHROUGH, "default"))
                    b.successors.add(next_seq_bid)

                # High fanout dispatcher
                if len(last_inst.switch_targets) >= 4:
                    b.anomaly_flags.append(BlockAnomalyFlag.STATE_DISPATCHER)

            else:
                # Standard sequential fallthrough
                if next_seq_bid is not None:
                    edges.append(CFGEdge(bid, next_seq_bid, CFGEdgeType.FALLTHROUGH))
                    b.successors.add(next_seq_bid)

        # 4. Compute predecessors
        for edge in edges:
            if edge.target_id in normalized_blocks:
                normalized_blocks[edge.target_id].predecessors.add(edge.source_id)

        # 5. Reachability and Dead Code detection
        reachable: Set[int] = set()
        queue = deque([0])
        while queue:
            curr = queue.popleft()
            if curr in reachable:
                continue
            reachable.add(curr)
            if curr in normalized_blocks:
                for succ in normalized_blocks[curr].successors:
                    if succ not in reachable:
                        queue.append(succ)

        dead_count = 0
        for bid, b in normalized_blocks.items():
            if bid not in reachable:
                b.is_dead = True
                b.anomaly_flags.append(BlockAnomalyFlag.UNREACHABLE_DEAD_CODE)
                dead_count += 1
                anomalies_detected.append(f"Block B{bid} (IL_{b.start_offset:04X}): Unreachable dead code identified")

        # 6. Cycle & Natural Loop detection (Tarjan/DFS back-edges)
        loop_count = 0
        visited: Set[int] = set()
        rec_stack: Set[int] = set()

        def dfs_detect_loops(node: int):
            nonlocal loop_count
            visited.add(node)
            rec_stack.add(node)
            block = normalized_blocks.get(node)
            if block:
                for succ in sorted(block.successors):
                    if succ not in visited:
                        dfs_detect_loops(succ)
                    elif succ in rec_stack:
                        # Back-edge detected!
                        loop_count += 1
                        if succ in normalized_blocks:
                            normalized_blocks[succ].is_loop_head = True
            rec_stack.remove(node)

        if 0 in normalized_blocks:
            dfs_detect_loops(0)

        # 7. High-Entropy Anomaly Flagging
        high_entropy_count = 0
        total_entropy = 0.0
        max_ent = 0.0

        for b in normalized_blocks.values():
            total_entropy += b.entropy
            if b.entropy > max_ent:
                max_ent = b.entropy
            if b.entropy_level == BlockEntropyLevel.HIGH_ENTROPY or (len(b.raw_bytes) >= 16 and b.entropy >= 6.0):
                b.anomaly_flags.append(BlockAnomalyFlag.HIGH_ENTROPY_BLOCK)
                high_entropy_count += 1
                anomalies_detected.append(
                    f"Block B{b.block_id} (IL_{b.start_offset:04X}): High Shannon entropy ({b.entropy:.4f}) across {len(b.raw_bytes)} bytes"
                )

        avg_ent = round(total_entropy / len(normalized_blocks), 4) if normalized_blocks else 0.0

        # 8. McCabe Cyclomatic Complexity:
        # Evaluated via branch decision points: M = 1 + sum(out_degree(b) - 1 for b with out_degree >= 2)
        decision_points = sum(len(b.successors) - 1 for b in normalized_blocks.values() if len(b.successors) >= 2)
        cyclomatic = max(1, decision_points + 1)

        return MethodCFG(
            method_token=method_token,
            method_name=method_name,
            entry_block_id=0,
            blocks=normalized_blocks,
            edges=edges,
            cyclomatic_complexity=cyclomatic,
            max_entropy=round(max_ent, 4),
            average_entropy=avg_ent,
            high_entropy_block_count=high_entropy_count,
            dead_block_count=dead_count,
            loop_count=loop_count,
            anomalies_detected=anomalies_detected,
        )

    @classmethod
    def _classify_entropy(cls, entropy: float, byte_count: int) -> BlockEntropyLevel:
        """Classifies Shannon entropy into discrete security tiers."""
        if byte_count < 4 or entropy < 3.0:
            return BlockEntropyLevel.LOW
        if entropy < 5.5:
            return BlockEntropyLevel.NORMAL
        if entropy < 6.8:
            return BlockEntropyLevel.SUSPICIOUS
        return BlockEntropyLevel.HIGH_ENTROPY
