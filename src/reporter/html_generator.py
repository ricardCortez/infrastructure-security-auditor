"""HTML Reporter module for Infrastructure Security Auditor.

Provides :class:`HTMLReporter` which renders a comprehensive, standalone
HTML security report from analysis data using a Jinja2 template.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.config import APP_VERSION, SEVERITY_ORDER, logger

# Path to the templates directory (sibling of this file)
_TEMPLATES_DIR = Path(__file__).parent / "templates"


class HTMLReporter:
    """Generates a standalone HTML security audit report from analysis data.

    The report is a fully self-contained HTML file with inline CSS and no
    external CDN dependencies, making it suitable for distribution or air-gap
    environments.

    Args:
        analysis_data: Full analysis dictionary as returned by
            :meth:`src.analyzer.analyzer.Analyzer.analyze`, which must include
            at least the keys ``findings``, ``risk_score``, ``risk_label``,
            ``severity_distribution``, ``compliance``, ``recommendations``,
            and ``summary``.

    Example:
        >>> reporter = HTMLReporter(analysis_data)
        >>> html = reporter.generate()
        >>> Path("report.html").write_text(html, encoding="utf-8")
    """

    def __init__(self, analysis_data: dict[str, Any]) -> None:
        self.data = analysis_data
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> str:
        """Render and return the complete HTML report as a string.

        Returns:
            A UTF-8 HTML string representing the full standalone report.

        Raises:
            jinja2.TemplateNotFound: If ``report.html`` is missing from the
                templates directory.
        """
        template = self._env.get_template("report.html")
        context = self._build_context()
        html = template.render(**context)
        logger.debug("HTML report rendered (%d bytes)", len(html))
        return html

    def save(self, output_path: str | Path) -> Path:
        """Render the report and write it to a file.

        Args:
            output_path: File path for the output HTML file.

        Returns:
            Resolved :class:`pathlib.Path` to the written file.
        """
        html = self.generate()
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        logger.info("Report saved to %s", out)
        return out

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_context(self) -> dict[str, Any]:
        """Build the Jinja2 template context from analysis data.

        Returns:
            Dictionary of template variables.
        """
        findings: list[dict[str, Any]] = self.data.get("findings", [])

        # Group findings by severity for the findings section
        findings_by_severity: dict[str, list[dict[str, Any]]] = {
            sev: [] for sev in SEVERITY_ORDER
        }
        for finding in findings:
            sev = finding.get("severity", "LOW")
            if sev in findings_by_severity:
                findings_by_severity[sev].append(finding)

        # Sort within each severity group: FAIL first, then WARNING, then PASS
        status_order = {"FAIL": 0, "WARNING": 1, "PASS": 2}
        for sev in findings_by_severity:
            findings_by_severity[sev].sort(
                key=lambda f: status_order.get(f.get("status", "PASS"), 2)
            )

        # Compliance: format with string keys for the template
        compliance = self.data.get("compliance", {})

        # Recommendations (already sorted by severity from Analyzer)
        recommendations = self.data.get("recommendations", [])

        # Determine scan server from first finding or fallback
        server = self.data.get("server", "Unknown Host")

        # Scan metadata
        scan_duration = self.data.get("scan_duration_seconds", "N/A")
        timestamp = self.data.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Format timestamp for display
        try:
            dt = datetime.fromisoformat(timestamp)
            generated_at = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            generated_at = timestamp

        # Compact raw JSON for the appendix (strip raw_output to keep size manageable)
        appendix_data = {
            "server": server,
            "timestamp": timestamp,
            "risk_score": self.data.get("risk_score"),
            "risk_label": self.data.get("risk_label"),
            "compliance": compliance,
            "findings": [
                {k: v for k, v in f.items() if k != "raw_output"} for f in findings
            ],
        }

        return {
            "server": server,
            "generated_at": generated_at,
            "scan_duration": scan_duration,
            "total_checks": self.data.get("total_checks", len(findings)),
            "risk_score": self.data.get("risk_score", 0.0),
            "risk_label": self.data.get("risk_label", "MINIMAL"),
            "severity_distribution": self.data.get(
                "severity_distribution",
                {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            ),
            "summary": self.data.get("summary", {"PASS": 0, "FAIL": 0, "WARNING": 0}),
            "compliance": compliance,
            "findings_by_severity": findings_by_severity,
            "recommendations": recommendations,
            "raw_json": json.dumps(appendix_data, indent=2, default=str),
            "app_version": APP_VERSION,
        }
