"""Network Reporter module for Infrastructure Security Auditor.

Generates consolidated HTML reports from BatchScanner results covering
an entire network: a lightweight summary page and a full detailed report
with per-server collapsible sections.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.config import APP_VERSION, logger

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class NetworkReporter:
    """Generate network-wide HTML security reports from BatchScanner output.

    Args:
        network_scan_data: Full result dict from
            :meth:`~src.scanner.batch_scanner.BatchScanner.scan_all`.

    Example:
        >>> reporter = NetworkReporter(batch_result)
        >>> paths = reporter.save_reports("./reports/network/")
    """

    def __init__(self, network_scan_data: dict[str, Any]) -> None:
        self.data = network_scan_data
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        self._env.filters["tojson"] = lambda v, **kw: json.dumps(v, **kw)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_network_summary(self) -> str:
        """Render a lightweight network overview HTML page.

        Sections: network overview, risk dashboard, OS breakdown,
        compliance bars, top-10 critical servers, common findings.

        Returns:
            Standalone UTF-8 HTML string.
        """
        return self._render(summary_only=True)

    def generate_consolidated_report(self) -> str:
        """Render the full network report with per-server detail sections.

        Sections: executive summary, network statistics, server-by-server
        collapsible details, unified remediation roadmap, technical appendix.

        Returns:
            Standalone UTF-8 HTML string.
        """
        return self._render(summary_only=False)

    def save_reports(self, output_dir: str) -> dict[str, Any]:
        """Generate and save both summary and consolidated reports.

        Creates ``output_dir`` if it does not exist.

        Args:
            output_dir: Directory path for output files.

        Returns:
            Dict with keys ``summary_path`` and ``consolidated_path``.

        Raises:
            OSError: If the directory cannot be created or files cannot be written.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        summary_path = out / "network_summary.html"
        consolidated_path = out / "network_consolidated_report.html"

        summary_html = self.generate_network_summary()
        summary_path.write_text(summary_html, encoding="utf-8")
        logger.info("Network summary saved: %s", summary_path)

        consolidated_html = self.generate_consolidated_report()
        consolidated_path.write_text(consolidated_html, encoding="utf-8")
        logger.info("Consolidated report saved: %s", consolidated_path)

        return {
            "summary_path": str(summary_path),
            "consolidated_path": str(consolidated_path),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _render(self, summary_only: bool) -> str:
        """Render the network_report.html template.

        Args:
            summary_only: If True, skip per-server finding details in context.

        Returns:
            Rendered HTML string.
        """
        tmpl = self._env.get_template("network_report.html")
        ctx = self._build_context(summary_only)
        return tmpl.render(**ctx)

    def _build_context(self, summary_only: bool) -> dict[str, Any]:
        """Build the Jinja2 template context from scan data.

        Args:
            summary_only: If True, server finding lists are omitted to
                keep the summary page lightweight.

        Returns:
            Template variable dict.
        """
        summary = self.data.get("network_summary", {})
        servers = self.data.get("servers", [])

        successful = [s for s in servers if s.get("status") == "success"]
        if successful:
            avg_risk = round(
                sum(s.get("risk_score", 0.0) for s in successful) / len(successful),
                1,
            )
        else:
            avg_risk = 0.0

        risk_label = (
            "CRITICAL" if avg_risk >= 8
            else "HIGH" if avg_risk >= 6
            else "MEDIUM" if avg_risk >= 4
            else "LOW" if avg_risk >= 2
            else "MINIMAL"
        )

        risk_color = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#16a34a",
            "MINIMAL": "#6366f1",
        }.get(risk_label, "#6366f1")

        # Common findings: appear on 3+ servers
        finding_freq: dict[str, dict[str, Any]] = {}
        for server in successful:
            for f in server.get("findings", []):
                if f.get("status") in ("FAIL", "WARNING"):
                    key = f.get("check", "")
                    if key not in finding_freq:
                        finding_freq[key] = {
                            "check": key,
                            "count": 0,
                            "severity": f.get("severity", "LOW"),
                        }
                    finding_freq[key]["count"] += 1

        common_findings = sorted(
            [v for v in finding_freq.values() if v["count"] >= 3],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        # Build server list for template
        template_servers = []
        for s in servers:
            entry: dict[str, Any] = {
                "ip": s.get("ip", ""),
                "hostname": s.get("hostname", "unknown"),
                "os": s.get("os", "unknown"),
                "status": s.get("status", "error"),
                "risk_score": s.get("risk_score", 0.0),
                "scan_duration_seconds": s.get("scan_duration_seconds", 0),
                "error_message": s.get("error_message", ""),
            }
            if not summary_only:
                entry["findings"] = s.get("findings", [])
            else:
                entry["fail_count"] = sum(
                    1 for f in s.get("findings", [])
                    if f.get("status") in ("FAIL", "WARNING")
                )
            template_servers.append(entry)

        template_servers.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "network": self.data.get("network", "unknown"),
            "scan_timestamp": self.data.get("scan_timestamp", ""),
            "scan_duration_seconds": self.data.get("scan_duration_seconds", 0),
            "app_version": APP_VERSION,
            "report_generated": datetime.now(tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            ),
            "summary_only": summary_only,
            "network_risk_score": avg_risk,
            "network_risk_label": risk_label,
            "network_risk_color": risk_color,
            "total_servers": summary.get("total_servers_scanned", 0),
            "successful_scans": summary.get("successful_scans", 0),
            "failed_scans": summary.get("failed_scans", 0),
            "total_findings": summary.get("total_findings", 0),
            "critical_findings": summary.get("critical_findings", 0),
            "high_findings": summary.get("high_findings", 0),
            "medium_findings": summary.get("medium_findings", 0),
            "low_findings": summary.get("low_findings", 0),
            "compliance_iso27001": round(
                summary.get("compliance_iso27001", 0) * 100, 1
            ),
            "compliance_cis": round(
                summary.get("compliance_cis_benchmarks", 0) * 100, 1
            ),
            "compliance_pci": round(
                summary.get("compliance_pci_dss", 0) * 100, 1
            ),
            "top_critical_servers": summary.get("top_critical_servers", []),
            "common_findings": common_findings,
            "servers": template_servers,
            "raw_json": (
                json.dumps(self.data, indent=2, default=str)
                if not summary_only
                else "{}"
            ),
        }
