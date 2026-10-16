"""
Batch Forensic Telemetry Reporters: Console Table, CSV, JSON & Self-Contained HTML Dashboard.
Engineered & Audited by Maya Thorne.
"""

import csv
import html
import json
import os
from typing import Optional

from .models import BatchScanReport, FileScanStatus, ThreatLevel, safe_path


class BatchReporter:
    """Multi-format report generator for batch forensic scanning campaigns."""

    @staticmethod
    def format_console_table(report: BatchScanReport, max_rows: int = 50) -> str:
        """Renders structured console summary table and binary inspection inventory."""
        s = report.summary
        opt = report.options
        lines = []

        lines.append("=" * 84)
        lines.append("DOTNET PACKER FORENSICS - BATCH DIRECTORY SCAN REPORT")
        lines.append("=" * 84)
        lines.append(f"Target Directory : {opt.target_dir}")
        lines.append(f"Scanner Version  : {report.scanner_version} | Timestamp: {report.timestamp_utc}")
        lines.append(
            f"Execution Time   : {s.elapsed_seconds:.2f}s | Workers: {opt.workers} | "
            f"Throughput: {s.scan_rate_files_per_sec:.1f} files/s ({s.scan_rate_mb_per_sec:.2f} MB/s)"
        )
        lines.append(
            f"Files Inventory  : {s.total_files_discovered} discovered | {s.total_files_scanned} scanned | "
            f"{s.total_files_skipped} skipped"
        )
        lines.append(
            f"Classification   : {s.total_pe_files} PE | {s.total_dotnet_files} .NET | "
            f"{s.total_packed_files} Packed | {s.total_clean_files} Clean | "
            f"{s.total_errors} Errors | {s.total_timeouts} Timeouts"
        )

        tc = s.threat_counts
        lines.append(
            f"Threat Breakdown : CRITICAL: {tc.get('critical', 0)} | HIGH: {tc.get('high', 0)} | "
            f"MEDIUM: {tc.get('medium', 0)} | LOW: {tc.get('low', 0)} | CLEAN: {tc.get('clean', 0)}"
        )

        if s.protector_counts:
            prot_str = ", ".join(f"{k}: {v}" for k, v in sorted(s.protector_counts.items(), key=lambda x: -x[1]))
            lines.append(f"Protectors Found : {prot_str}")

        lines.append("-" * 84)
        lines.append(
            f"{'STATUS':<8} {'THREAT':<9} {'FILE NAME':<30} {'SIZE':>11} {'.NET':<5} {'PROTECTORS':<12} {'TIME':>8}"
        )
        lines.append("-" * 84)

        display_results = report.results[:max_rows]
        for r in display_results:
            st = getattr(r.status, "value", str(r.status)).upper()[:7]
            th = getattr(r.threat_level, "value", str(r.threat_level)).upper()[:8]
            fn = r.file_name if len(r.file_name) <= 29 else r.file_name[:26] + "..."
            sz_str = f"{r.file_size:,}"
            dn_str = "-" if not r.is_pe else ("YES" if r.is_dotnet else "NO")
            p_str = ", ".join(r.protectors) if r.protectors else ("-" if r.is_pe else "N/A")
            if len(p_str) > 12:
                p_str = p_str[:9] + "..."
            dur_str = f"{r.scan_duration_ms:.1f}ms"
            lines.append(
                f"{st:<8} {th:<9} {fn:<30} {sz_str:>11} {dn_str:<5} {p_str:<12} {dur_str:>8}"
            )

        if len(report.results) > max_rows:
            lines.append(f"... and {len(report.results) - max_rows} more files.")

        lines.append("=" * 84)
        return "\n".join(lines)

    @classmethod
    def export_json(cls, report: BatchScanReport, output_path: str) -> str:
        """Exports batch scan report as structured JSON."""
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        return output_path

    @classmethod
    def export_csv(cls, report: BatchScanReport, output_path: str) -> str:
        """Exports batch scan report as comma-separated values (CSV)."""
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        headers = [
            "file_path",
            "file_name",
            "file_size_bytes",
            "sha256",
            "status",
            "threat_level",
            "is_pe",
            "is_dotnet",
            "protectors",
            "anomalies_count",
            "overlay_size_bytes",
            "duration_ms",
            "unpacked_count",
            "error_message",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in report.results:
                st_val = getattr(r.status, "value", str(r.status))
                th_val = getattr(r.threat_level, "value", str(r.threat_level))
                writer.writerow([
                    r.file_path,
                    r.file_name,
                    r.file_size,
                    r.sha256,
                    st_val,
                    th_val,
                    "true" if r.is_pe else "false",
                    "true" if r.is_dotnet else "false",
                    ";".join(r.protectors),
                    len(r.anomalies),
                    r.overlay_size,
                    f"{r.scan_duration_ms:.2f}",
                    r.unpacked_count,
                    r.error_message or "",
                ])
        return output_path

    @classmethod
    def generate_html_dashboard(cls, report: BatchScanReport, output_path: str) -> str:
        """Generates a self-contained, offline HTML dashboard with zero external CDN dependencies."""
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        s = report.summary
        opt = report.options

        # Build table rows with strict HTML entity escaping
        rows_html = []
        for r in report.results:
            st = html.escape(getattr(r.status, "value", str(r.status)), quote=True)
            th = html.escape(getattr(r.threat_level, "value", str(r.threat_level)), quote=True)
            fname = html.escape(r.file_name, quote=True)
            fpath = html.escape(r.file_path, quote=True)
            sha = html.escape(r.sha256, quote=True)
            dn_badge = '<span class="badge badge-dotnet">.NET</span>' if r.is_dotnet else '<span class="badge badge-muted">Native</span>'
            if not r.is_pe:
                dn_badge = '<span class="badge badge-muted">Non-PE</span>'

            prot_pills = []
            for p in r.protectors:
                prot_pills.append(f'<span class="pill pill-protector">{html.escape(p, quote=True)}</span>')
            prot_html = " ".join(prot_pills) if prot_pills else '<span class="text-muted">-</span>'

            err_html = ""
            if r.error_message:
                short_err = r.error_message[:40] + "..." if len(r.error_message) > 40 else r.error_message
                err_html = f'<div class="err-text" title="{html.escape(r.error_message, quote=True)}">{html.escape(short_err, quote=True)}</div>'

            sha_display = f"{sha[:12]}..." if len(sha) >= 12 else (sha or "-")

            row = (
                f'<tr data-status="{st}" data-threat="{th}">'
                f'<td><span class="badge badge-status-{st}">{st.upper()}</span></td>'
                f'<td><span class="badge badge-threat-{th}">{th.upper()}</span></td>'
                f'<td class="font-mono text-break" title="{fpath}"><b>{fname}</b>{err_html}</td>'
                f'<td class="font-mono text-muted text-small">{sha_display}</td>'
                f'<td class="text-right">{r.file_size:,} B</td>'
                f'<td class="text-center">{dn_badge}</td>'
                f'<td>{prot_html}</td>'
                f'<td class="text-right text-muted">{r.scan_duration_ms:.1f}ms</td>'
                f'</tr>'
            )
            rows_html.append(row)

        table_body = "\n".join(rows_html)

        # Protector badges summary
        prot_summary_pills = []
        for p, count in sorted(s.protector_counts.items(), key=lambda x: -x[1]):
            prot_summary_pills.append(
                f'<span class="pill pill-protector">{html.escape(p, quote=True)}: <b>{count}</b></span>'
            )
        prot_summary_html = " ".join(prot_summary_pills) if prot_summary_pills else '<span class="text-muted">None detected</span>'

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Batch Forensic Scan Dashboard — {html.escape(opt.target_dir, quote=True)}</title>
  <style>
    :root {{
      --bg-dark: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --color-critical: #ef4444;
      --color-high: #f97316;
      --color-medium: #eab308;
      --color-low: #3b82f6;
      --color-clean: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg-dark);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      padding: 24px;
    }}
    .container {{ max-width: 1440px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }}
    h1 {{ font-size: 22px; font-weight: 700; color: #fff; }}
    .meta-tag {{ font-size: 12px; color: var(--text-muted); }}
    .grid-cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
    }}
    .card-title {{ font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; }}
    .card-value {{ font-size: 26px; font-weight: 700; color: #fff; }}
    .card-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
    .threat-bar {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 12px;
    }}
    .pill {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }}
    .pill-protector {{ background: #374151; color: #e5e7eb; }}
    .badge {{
      display: inline-block;
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .badge-dotnet {{ background: #4f46e5; color: #fff; }}
    .badge-muted {{ background: #374151; color: #9ca3af; }}
    .badge-status-packed {{ background: #991b1b; color: #fecaca; }}
    .badge-status-clean {{ background: #065f46; color: #a7f3d0; }}
    .badge-status-skipped {{ background: #374151; color: #d1d5db; }}
    .badge-status-error {{ background: #6b21a8; color: #e9d5ff; }}
    .badge-status-timeout {{ background: #854d0e; color: #fef08a; }}
    .badge-threat-critical {{ background: var(--color-critical); color: #fff; }}
    .badge-threat-high {{ background: var(--color-high); color: #fff; }}
    .badge-threat-medium {{ background: var(--color-medium); color: #000; }}
    .badge-threat-low {{ background: var(--color-low); color: #fff; }}
    .badge-threat-clean {{ background: var(--color-clean); color: #fff; }}
    .toolbar {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 12px 16px;
      display: flex;
      gap: 16px;
      align-items: center;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }}
    .toolbar input, .toolbar select {{
      background: #1f2937;
      border: 1px solid #374151;
      color: #fff;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      outline: none;
    }}
    .toolbar input:focus, .toolbar select:focus {{ border-color: #6366f1; }}
    .toolbar input {{ flex: 1; min-width: 200px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      padding: 10px 14px;
      border-bottom: 1px solid var(--card-border);
      text-align: left;
    }}
    th {{
      background: #1f2937;
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 600;
    }}
    tr:hover td {{ background: #1a2234; }}
    .text-right {{ text-align: right; }}
    .text-center {{ text-align: center; }}
    .text-muted {{ color: var(--text-muted); }}
    .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .text-small {{ font-size: 11px; }}
    .text-break {{ word-break: break-all; }}
    .err-text {{ font-size: 11px; color: #f87171; margin-top: 2px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Batch PE Forensic Dashboard</h1>
        <div class="meta-tag">Target: {html.escape(opt.target_dir, quote=True)} · Generated: {html.escape(report.timestamp_utc, quote=True)} · v{html.escape(report.scanner_version, quote=True)}</div>
      </div>
      <div>
        <span class="pill pill-protector">Workers: {opt.workers}</span>
        <span class="pill pill-protector">Time: {s.elapsed_seconds:.2f}s</span>
        <span class="pill pill-protector">Rate: {s.scan_rate_files_per_sec:.1f} f/s</span>
      </div>
    </header>

    <div class="grid-cards">
      <div class="card">
        <div class="card-title">Total Binaries</div>
        <div class="card-value">{s.total_files_discovered:,}</div>
        <div class="card-sub">{s.total_files_scanned} scanned · {s.total_files_skipped} skipped</div>
      </div>
      <div class="card">
        <div class="card-title">Packed / Protected</div>
        <div class="card-value" style="color: #f87171;">{s.total_packed_files:,}</div>
        <div class="card-sub">{s.total_clean_files} verified clean</div>
      </div>
      <div class="card">
        <div class="card-title">.NET Assemblies</div>
        <div class="card-value" style="color: #818cf8;">{s.total_dotnet_files:,}</div>
        <div class="card-sub">{s.total_pe_files} total PE binaries</div>
      </div>
      <div class="card">
        <div class="card-title">Throughput & Size</div>
        <div class="card-value">{s.scan_rate_mb_per_sec:.2f} <span style="font-size: 14px; font-weight: normal;">MB/s</span></div>
        <div class="card-sub">{s.total_bytes_scanned:,} bytes total</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Detected Protectors & Threat Distribution</div>
      <div style="margin-bottom: 8px;">{prot_summary_html}</div>
      <div class="threat-bar">
        <span class="badge badge-threat-critical">Critical: {s.threat_counts.get('critical', 0)}</span>
        <span class="badge badge-threat-high">High: {s.threat_counts.get('high', 0)}</span>
        <span class="badge badge-threat-medium">Medium: {s.threat_counts.get('medium', 0)}</span>
        <span class="badge badge-threat-low">Low: {s.threat_counts.get('low', 0)}</span>
        <span class="badge badge-threat-clean">Clean: {s.threat_counts.get('clean', 0)}</span>
      </div>
    </div>

    <div class="toolbar">
      <input type="text" id="searchBox" placeholder="Filter by filename, SHA-256, protector..." onkeyup="filterTable()">
      <select id="statusFilter" onchange="filterTable()">
        <option value="all">All Statuses</option>
        <option value="packed">Packed</option>
        <option value="clean">Clean</option>
        <option value="skipped">Skipped</option>
        <option value="error">Error</option>
        <option value="timeout">Timeout</option>
      </select>
      <select id="threatFilter" onchange="filterTable()">
        <option value="all">All Threat Levels</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="clean">Clean</option>
      </select>
    </div>

    <table id="resultsTable">
      <thead>
        <tr>
          <th>Status</th>
          <th>Threat</th>
          <th>File Name</th>
          <th>SHA-256</th>
          <th class="text-right">Size</th>
          <th class="text-center">Runtime</th>
          <th>Protectors</th>
          <th class="text-right">Scan Time</th>
        </tr>
      </thead>
      <tbody>
{table_body}
      </tbody>
    </table>
  </div>

  <script>
    function filterTable() {{
      var q = document.getElementById('searchBox').value.toLowerCase();
      var sFilter = document.getElementById('statusFilter').value.toLowerCase();
      var tFilter = document.getElementById('threatFilter').value.toLowerCase();
      var rows = document.querySelectorAll('#resultsTable tbody tr');
      for (var i = 0; i < rows.length; i++) {{
        var r = rows[i];
        var text = (r.textContent || r.innerText || '').toLowerCase();
        var status = r.getAttribute('data-status') || '';
        var threat = r.getAttribute('data-threat') || '';
        var matchQ = !q || text.indexOf(q) !== -1;
        var matchS = (sFilter === 'all') || (status === sFilter);
        var matchT = (tFilter === 'all') || (threat === tFilter);
        r.style.display = (matchQ && matchS && matchT) ? '' : 'none';
      }}
    }}
  </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        return output_path
