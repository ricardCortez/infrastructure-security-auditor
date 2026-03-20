"""Comprehensive tests for HTMLReporter.

Covers:
- Instantiation with valid / minimal / edge-case data
- generate(): DOCTYPE, structure, all 7 section IDs, key data in output
- save(): file creation, nested dirs, string paths, return type
- _build_context(): findings grouped by severity, raw_json strips raw_output,
  all required template keys present
- Edge cases: no findings, all critical, mixed severity, zero risk score
"""

from __future__ import annotations

import json
from pathlib import Path

from src.reporter.html_generator import HTMLReporter

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def make_analysis_data(**overrides) -> dict:
    """Return a complete, valid analysis dict suitable for HTMLReporter."""
    base = {
        "server": "test-server.example.com",
        "timestamp": "2026-03-20T12:00:00+00:00",
        "scan_duration_seconds": 10.5,
        "risk_score": 5.5,
        "risk_label": "MEDIUM",
        "severity_distribution": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0},
        "compliance": {
            "ISO_27001": 0.85,
            "CIS_Benchmarks": 0.78,
            "PCI_DSS": 0.72,
        },
        "recommendations": [
            {
                "check": "Firewall Status",
                "severity": "HIGH",
                "action": "Enable Windows Firewall",
                "command": "Set-NetFirewallProfile -All -Enabled True",
                "effort": "Low",
                "timeline": "Immediate",
            }
        ],
        "findings": [
            {
                "check": "Firewall Status",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "Firewall disabled on Private profile.",
                "recommendation": "Enable it.",
                "raw_output": "raw powershell output",
            },
            {
                "check": "SMBv1 Protocol",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": "SMBv1 is disabled.",
                "recommendation": "No action required.",
                "raw_output": None,
            },
        ],
        "total_checks": 2,
        "summary": {"PASS": 1, "FAIL": 1, "WARNING": 0},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


class TestHTMLReporterInstantiation:

    def test_instantiation_stores_data(self) -> None:
        data = make_analysis_data()
        reporter = HTMLReporter(data)
        assert reporter.data is data

    def test_instantiation_with_empty_findings(self) -> None:
        data = make_analysis_data(
            findings=[],
            total_checks=0,
            summary={"PASS": 0, "FAIL": 0, "WARNING": 0},
        )
        reporter = HTMLReporter(data)
        assert reporter is not None

    def test_jinja_environment_configured(self) -> None:
        reporter = HTMLReporter(make_analysis_data())
        assert reporter._env is not None


# ---------------------------------------------------------------------------
# generate() – HTML string output
# ---------------------------------------------------------------------------


class TestHTMLReporterGenerate:

    def test_returns_string(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert isinstance(html, str)

    def test_output_not_empty(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert len(html) > 500

    def test_doctype_present(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "<!DOCTYPE html>" in html

    def test_html_open_and_close_tags(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "<html" in html
        assert "</html>" in html

    def test_head_and_body_tags(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "<head>" in html or "<head " in html
        assert "<body" in html

    def test_all_seven_section_ids_present(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        section_ids = [
            "executive-summary",
            "risk-dashboard",
            "findings",
            "compliance",
            "recommendations",
            "roadmap",
            "appendix",
        ]
        for section_id in section_ids:
            assert section_id in html, f"Missing section: {section_id}"

    def test_server_name_rendered(self) -> None:
        data = make_analysis_data(server="prod-dc-01.corp.local")
        html = HTMLReporter(data).generate()
        assert "prod-dc-01.corp.local" in html

    def test_risk_score_rendered(self) -> None:
        data = make_analysis_data(risk_score=7.5, risk_label="HIGH")
        html = HTMLReporter(data).generate()
        assert "7.5" in html

    def test_risk_label_rendered(self) -> None:
        data = make_analysis_data(risk_score=10.0, risk_label="CRITICAL")
        html = HTMLReporter(data).generate()
        assert "CRITICAL" in html

    def test_check_name_rendered(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "Firewall Status" in html

    def test_compliance_standard_names_rendered(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "ISO_27001" in html or "ISO 27001" in html
        assert "CIS" in html
        assert "PCI" in html

    def test_timestamp_date_rendered(self) -> None:
        data = make_analysis_data(timestamp="2026-03-20T15:30:00+00:00")
        html = HTMLReporter(data).generate()
        assert "2026-03-20" in html

    def test_app_version_rendered(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "0.1.0" in html

    def test_recommendation_action_rendered(self) -> None:
        html = HTMLReporter(make_analysis_data()).generate()
        assert "Enable Windows Firewall" in html


# ---------------------------------------------------------------------------
# generate() – edge cases
# ---------------------------------------------------------------------------


class TestHTMLReporterEdgeCases:

    def test_no_findings_generates_valid_html(self) -> None:
        data = make_analysis_data(
            findings=[],
            total_checks=0,
            severity_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            summary={"PASS": 0, "FAIL": 0, "WARNING": 0},
            recommendations=[],
            risk_score=0.0,
            risk_label="MINIMAL",
        )
        html = HTMLReporter(data).generate()
        assert "<!DOCTYPE html>" in html
        assert "MINIMAL" in html

    def test_all_critical_findings(self) -> None:
        findings = [
            {
                "check": f"Critical Check {i}",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "Critical issue.",
                "recommendation": "Fix immediately.",
                "raw_output": None,
            }
            for i in range(3)
        ]
        data = make_analysis_data(
            findings=findings,
            severity_distribution={"CRITICAL": 3, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            risk_score=10.0,
            risk_label="CRITICAL",
        )
        html = HTMLReporter(data).generate()
        assert "CRITICAL" in html
        assert "Critical Check 0" in html

    def test_mixed_severity_all_statuses(self) -> None:
        findings = [
            {
                "check": "C Check",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "x",
                "recommendation": "x",
                "raw_output": None,
            },
            {
                "check": "H Check",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "x",
                "recommendation": "x",
                "raw_output": None,
            },
            {
                "check": "M Check",
                "status": "WARNING",
                "severity": "MEDIUM",
                "description": "x",
                "recommendation": "x",
                "raw_output": None,
            },
            {
                "check": "L Check",
                "status": "PASS",
                "severity": "LOW",
                "description": "x",
                "recommendation": "x",
                "raw_output": None,
            },
        ]
        data = make_analysis_data(findings=findings)
        html = HTMLReporter(data).generate()
        assert "C Check" in html
        assert "L Check" in html

    def test_zero_risk_score(self) -> None:
        data = make_analysis_data(
            findings=[
                {
                    "check": "Everything OK",
                    "status": "PASS",
                    "severity": "HIGH",
                    "description": "All good.",
                    "recommendation": "N/A",
                    "raw_output": None,
                }
            ],
            risk_score=0.0,
            risk_label="MINIMAL",
            recommendations=[],
        )
        html = HTMLReporter(data).generate()
        assert "MINIMAL" in html

    def test_no_recommendations(self) -> None:
        data = make_analysis_data(recommendations=[])
        html = HTMLReporter(data).generate()
        assert "<!DOCTYPE html>" in html

    def test_many_findings_renders_without_error(self) -> None:
        findings = [
            {
                "check": f"Check {i}",
                "status": "FAIL",
                "severity": "HIGH",
                "description": f"Issue {i}",
                "recommendation": "Fix it.",
                "raw_output": "x" * 100,
            }
            for i in range(15)
        ]
        data = make_analysis_data(findings=findings, total_checks=15)
        html = HTMLReporter(data).generate()
        assert "Check 0" in html
        assert "Check 14" in html


# ---------------------------------------------------------------------------
# save()
# ---------------------------------------------------------------------------


class TestHTMLReporterSave:

    def test_save_creates_file(self, tmp_path) -> None:
        output = tmp_path / "report.html"
        HTMLReporter(make_analysis_data()).save(output)
        assert output.exists()

    def test_save_returns_resolved_path(self, tmp_path) -> None:
        output = tmp_path / "report.html"
        result = HTMLReporter(make_analysis_data()).save(output)
        assert isinstance(result, Path)
        assert result.is_absolute()

    def test_save_file_has_html_content(self, tmp_path) -> None:
        output = tmp_path / "report.html"
        HTMLReporter(make_analysis_data()).save(output)
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_save_creates_parent_directories(self, tmp_path) -> None:
        nested = tmp_path / "sub" / "deep" / "report.html"
        HTMLReporter(make_analysis_data()).save(nested)
        assert nested.exists()

    def test_save_accepts_string_path(self, tmp_path) -> None:
        output = str(tmp_path / "string_report.html")
        HTMLReporter(make_analysis_data()).save(output)
        assert Path(output).exists()

    def test_save_file_is_utf8(self, tmp_path) -> None:
        output = tmp_path / "report.html"
        HTMLReporter(make_analysis_data()).save(output)
        content = output.read_text(encoding="utf-8")
        assert len(content) > 0


# ---------------------------------------------------------------------------
# _build_context()
# ---------------------------------------------------------------------------


class TestBuildContext:

    def test_context_has_all_required_keys(self) -> None:
        ctx = HTMLReporter(make_analysis_data())._build_context()
        required = {
            "server",
            "generated_at",
            "scan_duration",
            "total_checks",
            "risk_score",
            "risk_label",
            "severity_distribution",
            "summary",
            "compliance",
            "findings_by_severity",
            "recommendations",
            "raw_json",
            "app_version",
        }
        assert required.issubset(ctx.keys())

    def test_findings_grouped_by_severity(self) -> None:
        findings = [
            {
                "check": "C1",
                "status": "FAIL",
                "severity": "CRITICAL",
                "description": "x",
                "recommendation": "x",
            },
            {
                "check": "C2",
                "status": "PASS",
                "severity": "CRITICAL",
                "description": "x",
                "recommendation": "x",
            },
            {
                "check": "H1",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "x",
                "recommendation": "x",
            },
        ]
        data = make_analysis_data(findings=findings)
        ctx = HTMLReporter(data)._build_context()
        assert len(ctx["findings_by_severity"]["CRITICAL"]) == 2
        assert len(ctx["findings_by_severity"]["HIGH"]) == 1
        assert len(ctx["findings_by_severity"]["MEDIUM"]) == 0

    def test_findings_within_severity_sorted_fail_first(self) -> None:
        findings = [
            {
                "check": "Pass Check",
                "status": "PASS",
                "severity": "HIGH",
                "description": "x",
                "recommendation": "x",
            },
            {
                "check": "Fail Check",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "x",
                "recommendation": "x",
            },
        ]
        data = make_analysis_data(findings=findings)
        ctx = HTMLReporter(data)._build_context()
        high = ctx["findings_by_severity"]["HIGH"]
        assert high[0]["status"] == "FAIL"
        assert high[1]["status"] == "PASS"

    def test_raw_json_excludes_raw_output_field(self) -> None:
        findings = [
            {
                "check": "A",
                "status": "FAIL",
                "severity": "HIGH",
                "description": "x",
                "recommendation": "y",
                "raw_output": "SENSITIVE POWERSHELL DATA",
            }
        ]
        data = make_analysis_data(findings=findings)
        ctx = HTMLReporter(data)._build_context()
        parsed = json.loads(ctx["raw_json"])
        for f in parsed["findings"]:
            assert "raw_output" not in f

    def test_raw_json_includes_risk_score(self) -> None:
        data = make_analysis_data(risk_score=8.1)
        ctx = HTMLReporter(data)._build_context()
        parsed = json.loads(ctx["raw_json"])
        assert parsed["risk_score"] == 8.1

    def test_generated_at_formats_timestamp(self) -> None:
        data = make_analysis_data(timestamp="2026-03-20T15:30:00+00:00")
        ctx = HTMLReporter(data)._build_context()
        assert "2026-03-20" in ctx["generated_at"]
        assert "UTC" in ctx["generated_at"]

    def test_all_severity_keys_present_in_findings_by_severity(self) -> None:
        ctx = HTMLReporter(make_analysis_data())._build_context()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in ctx["findings_by_severity"]

    def test_server_passed_through_to_context(self) -> None:
        data = make_analysis_data(server="specific-host-99")
        ctx = HTMLReporter(data)._build_context()
        assert ctx["server"] == "specific-host-99"
