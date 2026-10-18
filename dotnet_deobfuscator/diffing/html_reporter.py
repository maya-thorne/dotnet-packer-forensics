"""
Self-Contained Offline Visual HTML Diff Report Generator.
Engineered & Audited by Maya Thorne.
"""

import html
from typing import Any, Dict

from .models import BinaryDiffResult


class HTMLDiffReporter:
    """Renders standalone dark-themed HTML visual diff dashboards with zero CDN leaks."""

    @classmethod
    def generate(cls, result: BinaryDiffResult) -> str:
        """Produces a responsive, accessible, zero-dependency HTML dashboard."""
        r = result
        tel = r.telemetry
        meta = r.metadata_diff
        byte = r.bytecode_diff
        cfg = r.cfg_diff
        ast = r.ast_diff

        # Color mapping for similarity
        score_pct = int(r.composite_similarity * 100)
        badge_color = "#10b981" if score_pct >= 90 else ("#f59e0b" if score_pct >= 60 else "#ef4444")

        # Render impact tags
        impact_tags = "".join(
            f'<span class="impact-pill">{html.escape(imp.value)}</span>'
            for imp in r.detected_impacts
        ) or '<span class="impact-pill none">None Detected</span>'

        # Render method rows
        method_rows = []
        for m in r.method_diffs:
            c_type = m.change_type.value
            badge_class = f"badge-{c_type}"
            m_score = int(m.overall_similarity * 100)
            m_color = "#10b981" if m_score >= 90 else ("#f59e0b" if m_score >= 60 else "#ef4444")
            tok_a = hex(m.token_a) if m.token_a else "-"
            tok_b = hex(m.token_b) if m.token_b else "-"
            trans = ", ".join(m.detected_transformations) if m.detected_transformations else "None"
            
            row = f"""
            <tr class="method-row" data-type="{html.escape(c_type)}">
                <td><span class="badge {badge_class}">{html.escape(c_type.upper())}</span></td>
                <td class="font-mono">{html.escape(tok_a)} / {html.escape(tok_b)}</td>
                <td class="font-mono">{html.escape(m.name_a or m.name_b)}</td>
                <td>
                    <div class="score-bar">
                        <div class="score-fill" style="width: {m_score}%; background: {m_color};"></div>
                        <span class="score-text">{m_score}%</span>
                    </div>
                </td>
                <td class="text-center">{int(m.opcode_similarity * 100)}%</td>
                <td class="text-center">{int(m.cfg_similarity * 100)}%</td>
                <td class="text-center">{int(m.ast_similarity * 100)}%</td>
                <td class="text-center">{m.cyclomatic_delta:+d}</td>
                <td><small>{html.escape(trans)}</small></td>
            </tr>
            """
            method_rows.append(row)

        methods_table_body = "".join(method_rows)

        # Section diff rows
        sec_rows = []
        for s in meta.section_diffs:
            s_type = s.change_type.value
            s_class = f"badge-{s_type}"
            sec_rows.append(f"""
            <tr>
                <td class="font-mono">{html.escape(s.name)}</td>
                <td><span class="badge {s_class}">{html.escape(s_type.upper())}</span></td>
                <td>{s.raw_size_a:,} &rarr; {s.raw_size_b:,} ({s.raw_size_delta:+,}b)</td>
                <td>{s.entropy_a:.2f} &rarr; {s.entropy_b:.2f} ({s.entropy_delta:+.2f})</td>
                <td>{'<span class="tag-alert">INJECTED</span>' if s.is_injected else ('<span class="tag-warn">SURGE</span>' if s.is_entropy_surge else 'NORMAL')}</td>
            </tr>
            """)
        sections_table_body = "".join(sec_rows)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Binary Forensic Diff Report: {html.escape(r.source_a)} vs {html.escape(r.source_b)}</title>
<style>
:root {{
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-tertiary: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --border: #334155;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.5;
    padding: 24px;
}}
.container {{ max-width: 1300px; margin: 0 auto; }}
.header {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}}
.header h1 {{ font-size: 1.5rem; color: var(--accent); }}
.header-meta {{ color: var(--text-secondary); font-size: 0.85rem; margin-top: 4px; }}
.overall-gauge {{
    text-align: right;
}}
.gauge-val {{
    font-size: 2.2rem;
    font-weight: 700;
    color: {badge_color};
}}
.gauge-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); }}
.cards-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}}
.card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
}}
.card-title {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 8px; }}
.card-val {{ font-size: 1.5rem; font-weight: 700; color: var(--text-primary); }}
.card-sub {{ font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px; }}
.impact-box {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
}}
.impact-pill {{
    display: inline-block;
    background: #4338ca;
    color: #e0e7ff;
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-right: 8px;
    margin-bottom: 4px;
}}
.impact-pill.none {{ background: var(--bg-tertiary); color: var(--text-secondary); }}
.section-panel {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
}}
.section-panel h2 {{ font-size: 1.15rem; margin-bottom: 16px; color: var(--accent); }}
.table-wrap {{ overflow-x: auto; }}
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
}}
th, td {{
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}}
th {{ background: var(--bg-tertiary); color: var(--text-secondary); font-weight: 600; }}
.font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
.text-center {{ text-align: center; }}
.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
}}
.badge-unchanged {{ background: #065f46; color: #a7f3d0; }}
.badge-modified {{ background: #854d0e; color: #fef08a; }}
.badge-added {{ background: #1e40af; color: #bfdbfe; }}
.badge-removed {{ background: #991b1b; color: #fecaca; }}
.tag-alert {{ color: #ef4444; font-weight: bold; font-size: 0.75rem; }}
.tag-warn {{ color: #f59e0b; font-weight: bold; font-size: 0.75rem; }}
.score-bar {{
    position: relative;
    background: var(--bg-tertiary);
    height: 18px;
    border-radius: 4px;
    overflow: hidden;
    min-width: 100px;
}}
.score-fill {{ height: 100%; }}
.score-text {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 0.7rem;
    font-weight: bold;
    color: #ffffff;
}}
.filter-bar {{
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    align-items: center;
    flex-wrap: wrap;
}}
.filter-input {{
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 0.85rem;
    min-width: 250px;
}}
.filter-btn {{
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 0.8rem;
    cursor: pointer;
}}
.filter-btn.active {{
    background: var(--accent);
    color: var(--bg-primary);
    font-weight: bold;
}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>Multi-Engine Binary Forensic Diff</h1>
            <div class="header-meta">
                Source A: <strong>{html.escape(r.source_a)}</strong> ({r.sha256_a[:16]}...)<br>
                Source B: <strong>{html.escape(r.source_b)}</strong> ({r.sha256_b[:16]}...)<br>
                Analysis Duration: {tel.comparison_time_ms:.1f}ms &bull; Category: <strong>{html.escape(r.diff_category.value.upper())}</strong>
            </div>
        </div>
        <div class="overall-gauge">
            <div class="gauge-val">{score_pct}%</div>
            <div class="gauge-label">Composite Similarity</div>
        </div>
    </div>

    <div class="cards-grid">
        <div class="card">
            <div class="card-title">Metadata Similarity</div>
            <div class="card-val">{int(meta.similarity_score * 100)}%</div>
            <div class="card-sub">{len(meta.section_diffs)} Sections &bull; Imphash: {'MATCH' if meta.imphash_matched else 'DIFF'}</div>
        </div>
        <div class="card">
            <div class="card-title">Bytecode Similarity</div>
            <div class="card-val">{int(byte.similarity_score * 100)}%</div>
            <div class="card-sub">Jaccard: {int(byte.opcode_jaccard_avg * 100)}% &bull; Edit: {int(byte.token_edit_similarity_avg * 100)}%</div>
        </div>
        <div class="card">
            <div class="card-title">CFG Graph Similarity</div>
            <div class="card-val">{int(cfg.similarity_score * 100)}%</div>
            <div class="card-sub">{cfg.total_blocks_b} Blocks &bull; &Delta;Complexity: {cfg.cyclomatic_complexity_delta:+d}</div>
        </div>
        <div class="card">
            <div class="card-title">AST Semantic Flow</div>
            <div class="card-val">{int(ast.similarity_score * 100)}%</div>
            <div class="card-sub">Opaque Predicates: {ast.opaque_predicates_detected} &bull; Loops: {int(ast.loop_structure_similarity * 100)}%</div>
        </div>
    </div>

    <div class="impact-box">
        <div class="card-title">Identified Obfuscation / Packing Signatures</div>
        <div>{impact_tags}</div>
    </div>

    <div class="section-panel">
        <h2>PE Section Headers &amp; Entropy Delta</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Section</th>
                        <th>Status</th>
                        <th>Raw Size (&Delta;)</th>
                        <th>Entropy (&Delta;)</th>
                        <th>Diagnostics</th>
                    </tr>
                </thead>
                <tbody>
                    {sections_table_body}
                </tbody>
            </table>
        </div>
    </div>

    <div class="section-panel">
        <h2>CIL Method Structural &amp; CFG Diff ({len(r.method_diffs)} Methods)</h2>
        <div class="filter-bar">
            <input type="text" id="methodSearch" class="filter-input" placeholder="Search methods..." oninput="filterMethods()">
            <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
            <button class="filter-btn" onclick="setFilter('modified', this)">Modified</button>
            <button class="filter-btn" onclick="setFilter('unchanged', this)">Identical</button>
            <button class="filter-btn" onclick="setFilter('added', this)">Added</button>
            <button class="filter-btn" onclick="setFilter('removed', this)">Removed</button>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Token A / B</th>
                        <th>Method Name</th>
                        <th>Overall</th>
                        <th class="text-center">Bytecode</th>
                        <th class="text-center">CFG</th>
                        <th class="text-center">AST</th>
                        <th class="text-center">&Delta;Cyc</th>
                        <th>Transformations</th>
                    </tr>
                </thead>
                <tbody id="methodsTbody">
                    {methods_table_body}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
let currentFilter = 'all';

function setFilter(type, btn) {{
    currentFilter = type;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterMethods();
}}

function filterMethods() {{
    const query = document.getElementById('methodSearch').value.toLowerCase();
    const rows = document.querySelectorAll('.method-row');
    rows.forEach(row => {{
        const rowType = row.getAttribute('data-type');
        const text = row.innerText.toLowerCase();
        const matchesType = (currentFilter === 'all' || rowType === currentFilter);
        const matchesQuery = !query || text.includes(query);
        row.style.display = (matchesType && matchesQuery) ? '' : 'none';
    }});
}}
</script>
</body>
</html>
"""
