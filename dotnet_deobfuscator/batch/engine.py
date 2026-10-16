"""
Batch Forensic Engine Facade: Scanner, Pipeline Coordinator & Multi-Format Reporter.
Engineered & Audited by Maya Thorne.
"""

import os
from typing import Any, Callable, Dict, Optional

from .models import BatchScanOptions, BatchScanReport, safe_path
from .reporter import BatchReporter
from .scanner import BatchDirectoryScanner


class BatchForensicEngine:
    """Facade orchestrating multi-threaded PE scanning, extraction, and report generation."""

    @classmethod
    def run(
        cls,
        options: BatchScanOptions,
        progress_callback: Optional[Callable[[int, int, Any], None]] = None,
    ) -> BatchScanReport:
        """Executes full batch scanning workflow and exports requested reports."""
        if not os.path.exists(options.target_dir):
            raise FileNotFoundError(f"Target directory does not exist: {options.target_dir}")

        report = BatchDirectoryScanner.scan_directory(options, progress_callback=progress_callback)

        # Handle output directory reports
        if options.output_dir:
            os.makedirs(options.output_dir, exist_ok=True)
            json_dest = options.json_out or os.path.join(options.output_dir, "batch_report.json")
            csv_dest = options.csv_out or os.path.join(options.output_dir, "batch_report.csv")
            html_dest = options.html_out or os.path.join(options.output_dir, "batch_dashboard.html")

            BatchReporter.export_json(report, json_dest)
            BatchReporter.export_csv(report, csv_dest)
            BatchReporter.generate_html_dashboard(report, html_dest)
        else:
            if options.json_out:
                BatchReporter.export_json(report, options.json_out)
            if options.csv_out:
                BatchReporter.export_csv(report, options.csv_out)
            if options.html_out:
                BatchReporter.generate_html_dashboard(report, options.html_out)

        return report

    @classmethod
    def export_reports(
        cls,
        report: BatchScanReport,
        output_dir: Optional[str] = None,
        json_path: Optional[str] = None,
        csv_path: Optional[str] = None,
        html_path: Optional[str] = None,
    ) -> Dict[str, str]:
        """Convenience utility to export report across any subset of supported formats."""
        exported: Dict[str, str] = {}
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            j_p = json_path or os.path.join(output_dir, "batch_report.json")
            c_p = csv_path or os.path.join(output_dir, "batch_report.csv")
            h_p = html_path or os.path.join(output_dir, "batch_dashboard.html")
            exported["json"] = BatchReporter.export_json(report, j_p)
            exported["csv"] = BatchReporter.export_csv(report, c_p)
            exported["html"] = BatchReporter.generate_html_dashboard(report, h_p)
        else:
            if json_path:
                exported["json"] = BatchReporter.export_json(report, json_path)
            if csv_path:
                exported["csv"] = BatchReporter.export_csv(report, csv_path)
            if html_path:
                exported["html"] = BatchReporter.generate_html_dashboard(report, html_path)
        return exported
