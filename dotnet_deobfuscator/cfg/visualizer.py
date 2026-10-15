"""
CIL Control Flow Graph (CFG) Visualizer & Multi-Format Diagram Renderer.
Engineered & Audited by Maya Thorne.
"""

from collections import deque
import html
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    BlockAnomalyFlag,
    BlockEntropyLevel,
    CFGBlock,
    CFGEdge,
    CFGEdgeType,
    MethodCFG,
)


class CFGVisualizer:
    """Renders MethodCFG graphs into Mermaid, Graphviz DOT, standalone SVG, ASCII, and JSON formats."""

    @classmethod
    def export_mermaid(
        cls, method_cfg: MethodCFG, max_insts_per_block: int = 5
    ) -> str:
        """Exports graph to a GitHub-compatible Mermaid flowchart."""
        lines = [
            "flowchart TD",
            "  %% Styling class definitions",
            "  classDef default fill:#f8f9fa,stroke:#495057,stroke-width:1.5px,color:#212529;",
            "  classDef highEntropy fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c;",
            "  classDef suspicious fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#e65100;",
            "  classDef deadCode fill:#eceff1,stroke:#90a4ae,stroke-dasharray: 4 4,color:#546e7a;",
            "  classDef loopHead fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#01579b;",
            "  classDef entryBlock fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#4a148c;",
            "",
        ]

        # Blocks
        for bid, b in sorted(method_cfg.blocks.items()):
            header = f"B{bid} [IL_{b.start_offset:04X}..IL_{b.end_offset:04X}]"
            ent_tag = f"H:{b.entropy:.2f}"
            tags = [ent_tag]
            if b.is_entry:
                tags.append("ENTRY")
            if b.is_exit:
                tags.append("EXIT")
            if b.is_loop_head:
                tags.append("LOOP")
            if b.is_dead:
                tags.append("DEAD")

            tag_str = " | ".join(tags)
            inst_lines = []
            for inst in b.instructions[:max_insts_per_block]:
                clean_name = inst.format().replace('"', "'").replace("<", "&lt;").replace(">", "&gt;")
                inst_lines.append(clean_name)
            if len(b.instructions) > max_insts_per_block:
                inst_lines.append(f"... ({len(b.instructions) - max_insts_per_block} more)")

            content = f"<b>{header}</b><br/>[{tag_str}]"
            if inst_lines:
                content += "<br/>" + "<br/>".join(inst_lines)

            lines.append(f'  B{bid}["{content}"]')

        lines.append("")
        # Edges
        for edge in method_cfg.edges:
            src = f"B{edge.source_id}"
            tgt = f"B{edge.target_id}"
            if edge.edge_type == CFGEdgeType.CONDITIONAL_TRUE:
                label = f"|{edge.condition_label or 'true'}|"
                lines.append(f"  {src} -->{label} {tgt}")
            elif edge.edge_type == CFGEdgeType.CONDITIONAL_FALSE:
                label = f"|{edge.condition_label or 'false'}|"
                lines.append(f"  {src} -.->{label} {tgt}")
            elif edge.edge_type == CFGEdgeType.SWITCH_BRANCH:
                label = f"|{edge.condition_label or 'case'}|"
                lines.append(f"  {src} -->{label} {tgt}")
            elif edge.edge_type == CFGEdgeType.UNCONDITIONAL_BRANCH:
                lines.append(f"  {src} ==> {tgt}")
            else:
                label = f"|{edge.condition_label}|" if edge.condition_label else ""
                lines.append(f"  {src} -->{label} {tgt}")

        lines.append("")
        # Class attachments
        for bid, b in sorted(method_cfg.blocks.items()):
            if b.is_dead:
                lines.append(f"  class B{bid} deadCode;")
            elif b.entropy_level == BlockEntropyLevel.HIGH_ENTROPY:
                lines.append(f"  class B{bid} highEntropy;")
            elif b.entropy_level == BlockEntropyLevel.SUSPICIOUS:
                lines.append(f"  class B{bid} suspicious;")
            elif b.is_loop_head:
                lines.append(f"  class B{bid} loopHead;")
            elif b.is_entry:
                lines.append(f"  class B{bid} entryBlock;")

        return "\n".join(lines)

    @classmethod
    def export_dot(
        cls, method_cfg: MethodCFG, title: Optional[str] = None, max_insts_per_block: int = 8
    ) -> str:
        """Exports graph to Graphviz DOT specification with HTML-like record formatting."""
        graph_title = title or f"CFG_0x{method_cfg.method_token:08X}_{method_cfg.method_name}"
        lines = [
            f'digraph "{graph_title}" {{',
            '  rankdir="TB";',
            '  bgcolor="#ffffff";',
            '  node [shape=box, fontname="Consolas", fontsize=10, style="filled,rounded", margin="0.15,0.1"];',
            '  edge [fontname="Consolas", fontsize=9];',
            "",
        ]

        for bid, b in sorted(method_cfg.blocks.items()):
            # Color palette
            if b.is_dead:
                fill_color = "#eceff1"
                border_color = "#90a4ae"
                style = "filled,dashed,rounded"
            elif b.entropy_level == BlockEntropyLevel.HIGH_ENTROPY:
                fill_color = "#ffebee"
                border_color = "#c62828"
                style = "filled,rounded"
            elif b.entropy_level == BlockEntropyLevel.SUSPICIOUS:
                fill_color = "#fff8e1"
                border_color = "#f57f17"
                style = "filled,rounded"
            elif b.is_loop_head:
                fill_color = "#e1f5fe"
                border_color = "#0277bd"
                style = "filled,rounded"
            elif b.is_entry:
                fill_color = "#f3e5f5"
                border_color = "#7b1fa2"
                style = "filled,rounded"
            else:
                fill_color = "#f8f9fa"
                border_color = "#495057"
                style = "filled,rounded"

            header_text = f"Block B{bid} [IL_{b.start_offset:04X}..IL_{b.end_offset:04X}]"
            ent_text = f"H: {b.entropy:.4f} ({b.entropy_level.value.upper()})"

            label_parts = [header_text, ent_text, "------------------------------"]
            for inst in b.instructions[:max_insts_per_block]:
                label_parts.append(inst.format())
            if len(b.instructions) > max_insts_per_block:
                label_parts.append(f"... ({len(b.instructions) - max_insts_per_block} more instructions)")

            label = "\\l".join(label_parts) + "\\l"
            lines.append(
                f'  B{bid} [label="{label}", fillcolor="{fill_color}", color="{border_color}", style="{style}"];'
            )

        lines.append("")
        for edge in method_cfg.edges:
            src = f"B{edge.source_id}"
            tgt = f"B{edge.target_id}"
            if edge.edge_type == CFGEdgeType.CONDITIONAL_TRUE:
                lines.append(f'  {src} -> {tgt} [color="#2e7d32", label="true", fontcolor="#2e7d32"];')
            elif edge.edge_type == CFGEdgeType.CONDITIONAL_FALSE:
                lines.append(f'  {src} -> {tgt} [color="#c62828", style="dashed", label="false", fontcolor="#c62828"];')
            elif edge.edge_type == CFGEdgeType.SWITCH_BRANCH:
                lbl = edge.condition_label or "switch"
                lines.append(f'  {src} -> {tgt} [color="#1565c0", label="{lbl}", fontcolor="#1565c0"];')
            elif edge.edge_type == CFGEdgeType.UNCONDITIONAL_BRANCH:
                lines.append(f'  {src} -> {tgt} [color="#37474f", penwidth=2.0];')
            else:
                label_str = f', label="{edge.condition_label}"' if edge.condition_label else ""
                lines.append(f'  {src} -> {tgt} [color="#546e7a"{label_str}];')

        lines.append("}")
        return "\n".join(lines)

    @classmethod
    def export_svg(
        cls, method_cfg: MethodCFG, width: int = 1000, max_insts_per_block: int = 5
    ) -> str:
        """Generates a self-contained, valid XML SVG vector flowchart diagram with zero external image dependencies."""
        if not method_cfg.blocks:
            return (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 120" width="400" height="120">'
                '<rect width="100%" height="100%" fill="#f8f9fa"/>'
                '<text x="200" y="60" text-anchor="middle" font-family="sans-serif" font-size="14" fill="#6c757d">'
                'Empty Control Flow Graph'
                '</text></svg>'
            )

        # 1. Topological layering for vertical layout
        layers: Dict[int, List[int]] = {}
        node_depth: Dict[int, int] = {0: 0}
        visited: Set[int] = {0}
        queue = deque([0])

        while queue:
            curr = queue.popleft()
            curr_d = node_depth[curr]
            block = method_cfg.blocks.get(curr)
            if block:
                for succ in sorted(block.successors):
                    if succ not in node_depth or node_depth[succ] < curr_d + 1:
                        node_depth[succ] = curr_d + 1
                    if succ not in visited:
                        visited.add(succ)
                        queue.append(succ)

        # Catch unreachable blocks
        for bid in sorted(method_cfg.blocks.keys()):
            if bid not in node_depth:
                node_depth[bid] = max(node_depth.values(), default=0) + 1

        for bid, d in sorted(node_depth.items()):
            layers.setdefault(d, []).append(bid)

        # Layout parameters
        box_width = 280
        layer_gap_y = 70
        horizontal_gap = 40
        start_x = 40
        start_y = 60

        # Calculate coordinates for each block
        block_coords: Dict[int, Tuple[int, int, int, int]] = {}  # bid -> (x, y, w, h)
        current_y = start_y

        for d in sorted(layers.keys()):
            layer_nodes = layers[d]
            layer_total_width = len(layer_nodes) * box_width + (len(layer_nodes) - 1) * horizontal_gap
            layer_start_x = max(start_x, (width - layer_total_width) // 2)

            max_h_in_layer = 0
            for idx, bid in enumerate(layer_nodes):
                b = method_cfg.blocks[bid]
                displayed_insts = min(len(b.instructions), max_insts_per_block)
                box_h = 56 + displayed_insts * 16 + (16 if len(b.instructions) > max_insts_per_block else 0)
                if box_h > max_h_in_layer:
                    max_h_in_layer = box_h
                x = layer_start_x + idx * (box_width + horizontal_gap)
                block_coords[bid] = (x, current_y, box_width, box_h)

            current_y += max_h_in_layer + layer_gap_y

        total_height = current_y + 40
        total_width = max(width, max(x + w for x, _, w, _ in block_coords.values()) + 60)

        # 2. Build SVG elements
        svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_width} {total_height}" width="{total_width}" height="{total_height}">',
            '  <defs>',
            '    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#495057"/>',
            '    </marker>',
            '    <marker id="arrow-true" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#2e7d32"/>',
            '    </marker>',
            '    <marker id="arrow-false" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#c62828"/>',
            '    </marker>',
            '    <marker id="arrow-switch" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#1565c0"/>',
            '    </marker>',
            '  </defs>',
            '  <rect width="100%" height="100%" fill="#ffffff"/>',
            f'  <text x="{total_width // 2}" y="32" text-anchor="middle" font-family="Segoe UI, -apple-system, sans-serif" font-size="18" font-weight="bold" fill="#212529">',
            f'    CIL CFG: {html.escape(method_cfg.method_name)} (Token: 0x{method_cfg.method_token:08X}, Cyclomatic: {method_cfg.cyclomatic_complexity})',
            '  </text>',
        ]

        # Draw connecting edges
        for edge in method_cfg.edges:
            if edge.source_id not in block_coords or edge.target_id not in block_coords:
                continue
            sx, sy, sw, sh = block_coords[edge.source_id]
            tx, ty, tw, _ = block_coords[edge.target_id]

            start_point = (sx + sw // 2, sy + sh)
            end_point = (tx + tw // 2, ty)

            stroke_color = "#495057"
            marker = "arrow"
            dash_array = ""

            if edge.edge_type == CFGEdgeType.CONDITIONAL_TRUE:
                stroke_color = "#2e7d32"
                marker = "arrow-true"
            elif edge.edge_type == CFGEdgeType.CONDITIONAL_FALSE:
                stroke_color = "#c62828"
                marker = "arrow-false"
                dash_array = ' stroke-dasharray="4,4"'
            elif edge.edge_type == CFGEdgeType.SWITCH_BRANCH:
                stroke_color = "#1565c0"
                marker = "arrow-switch"

            # Route cubic bezier or orthogonal curve
            mid_y = (start_point[1] + end_point[1]) // 2
            path_d = f"M {start_point[0]} {start_point[1]} C {start_point[0]} {mid_y}, {end_point[0]} {mid_y}, {end_point[0]} {end_point[1]}"

            svg.append(
                f'  <path d="{path_d}" fill="none" stroke="{stroke_color}" stroke-width="1.8"{dash_array} marker-end="url(#{marker})"/>'
            )
            if edge.condition_label:
                lbl_x = (start_point[0] + end_point[0]) // 2
                lbl_y = mid_y - 4
                clean_lbl = html.escape(edge.condition_label)
                svg.append(
                    f'  <text x="{lbl_x}" y="{lbl_y}" text-anchor="middle" font-family="Consolas, monospace" font-size="10" font-weight="bold" fill="{stroke_color}">{clean_lbl}</text>'
                )

        # Draw blocks
        for bid, (bx, by, bw, bh) in block_coords.items():
            b = method_cfg.blocks[bid]

            # Colors
            if b.is_dead:
                card_bg = "#f5f5f5"
                card_border = "#90a4ae"
                badge_bg = "#cfd8dc"
                badge_text = "#455a64"
                dash = ' stroke-dasharray="5,5"'
            elif b.entropy_level == BlockEntropyLevel.HIGH_ENTROPY:
                card_bg = "#fff5f5"
                card_border = "#c62828"
                badge_bg = "#ffcdd2"
                badge_text = "#b71c1c"
                dash = ""
            elif b.entropy_level == BlockEntropyLevel.SUSPICIOUS:
                card_bg = "#fffdf0"
                card_border = "#f57f17"
                badge_bg = "#ffe082"
                badge_text = "#e65100"
                dash = ""
            elif b.is_loop_head:
                card_bg = "#f0f9ff"
                card_border = "#0277bd"
                badge_bg = "#b3e5fc"
                badge_text = "#01579b"
                dash = ""
            elif b.is_entry:
                card_bg = "#fdf4ff"
                card_border = "#7b1fa2"
                badge_bg = "#e1bee7"
                badge_text = "#4a148c"
                dash = ""
            else:
                card_bg = "#f8f9fa"
                card_border = "#6c757d"
                badge_bg = "#e9ecef"
                badge_text = "#343a40"
                dash = ""

            # Card background
            svg.append(
                f'  <rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="6" ry="6" fill="{card_bg}" stroke="{card_border}" stroke-width="1.8"{dash}/>'
            )
            # Header title
            header_str = f"Block B{bid} [IL_{b.start_offset:04X}..IL_{b.end_offset:04X}]"
            svg.append(
                f'  <text x="{bx + 10}" y="{by + 20}" font-family="Consolas, monospace" font-size="12" font-weight="bold" fill="#212529">{html.escape(header_str)}</text>'
            )

            # Entropy Badge
            ent_str = f"H: {b.entropy:.2f}"
            badge_w = 58
            badge_x = bx + bw - badge_w - 8
            svg.append(
                f'  <rect x="{badge_x}" y="{by + 8}" width="{badge_w}" height="18" rx="3" fill="{badge_bg}"/>'
            )
            svg.append(
                f'  <text x="{badge_x + badge_w // 2}" y="{by + 21}" text-anchor="middle" font-family="Consolas, monospace" font-size="10" font-weight="bold" fill="{badge_text}">{html.escape(ent_str)}</text>'
            )

            # Divider line
            svg.append(
                f'  <line x1="{bx}" y1="{by + 32}" x2="{bx + bw}" y2="{by + 32}" stroke="{card_border}" stroke-width="0.8"/>'
            )

            # Instructions
            inst_y = by + 48
            for inst in b.instructions[:max_insts_per_block]:
                inst_text = html.escape(inst.format())
                svg.append(
                    f'  <text x="{bx + 12}" y="{inst_y}" font-family="Consolas, monospace" font-size="10" fill="#343a40">{inst_text}</text>'
                )
                inst_y += 16

            if len(b.instructions) > max_insts_per_block:
                more_text = f"... ({len(b.instructions) - max_insts_per_block} more)"
                svg.append(
                    f'  <text x="{bx + 12}" y="{inst_y}" font-family="Consolas, monospace" font-size="9" fill="#868e96" font-style="italic">{html.escape(more_text)}</text>'
                )

        svg.append("</svg>")
        return "\n".join(svg)

    @classmethod
    def export_ascii(cls, method_cfg: MethodCFG, max_insts_per_block: int = 6) -> str:
        """Exports an ASCII box diagram visualization for terminal inspectability."""
        lines = [
            f"=== [CIL Control Flow Graph: {method_cfg.method_name} (0x{method_cfg.method_token:08X})] ===",
            f"Nodes (Blocks): {len(method_cfg.blocks)} | Edges: {len(method_cfg.edges)} | Cyclomatic: {method_cfg.cyclomatic_complexity} | Loops: {method_cfg.loop_count}",
            f"Entropy: max={method_cfg.max_entropy:.2f}, avg={method_cfg.average_entropy:.2f} | High Entropy Blocks: {method_cfg.high_entropy_block_count}",
            "",
        ]

        for bid, b in sorted(method_cfg.blocks.items()):
            tags = [f"H:{b.entropy:.2f}", b.entropy_level.value.upper()]
            if b.is_entry:
                tags.append("ENTRY")
            if b.is_exit:
                tags.append("EXIT")
            if b.is_loop_head:
                tags.append("LOOP_HEAD")
            if b.is_dead:
                tags.append("DEAD_CODE")

            tag_line = " | ".join(tags)
            lines.append(f"+----------------------------------------------------------------------+")
            lines.append(f"| Block B{bid:<3} [IL_{b.start_offset:04X}..IL_{b.end_offset:04X}]  [{tag_line}]")
            lines.append(f"+----------------------------------------------------------------------+")
            for inst in b.instructions[:max_insts_per_block]:
                lines.append(f"|   {inst.format():<66} |")
            if len(b.instructions) > max_insts_per_block:
                lines.append(f"|   ... ({len(b.instructions) - max_insts_per_block} more instructions){'':<40} |")
            lines.append(f"+----------------------------------------------------------------------+")

            # Outgoing transitions
            out_edges = [e for e in method_cfg.edges if e.source_id == bid]
            if out_edges:
                edge_descs = []
                for e in out_edges:
                    lbl = f" ({e.condition_label})" if e.condition_label else ""
                    edge_descs.append(f"-> B{e.target_id}{lbl}")
                lines.append(f"    Transitions: {', '.join(edge_descs)}")
            else:
                lines.append("    Transitions: (Terminal exit / return)")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def export_json(cls, method_cfg: MethodCFG) -> Dict[str, Any]:
        """Serializes MethodCFG to dictionary."""
        return method_cfg.to_dict()
