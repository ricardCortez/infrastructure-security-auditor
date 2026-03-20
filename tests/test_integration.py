"""Integration tests for the Infrastructure Security Auditor pipeline.

Tests the end-to-end flow:
    scan (Windows/Linux) → analyze → report

Verifies that both scanners produce compatible FindingDict output that the
Analyzer and HTMLReporter can consume identically.

Run with::

    pytest tests/test_integration.py -v
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest

from src.analyzer.analyzer import Analyzer
from src.reporter.html_generator import HTMLReporter
from src.scanner.linux_scanner import LinuxScanner
from src.scanner.windows_scanner import WindowsScanner

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_finding(
    check: str = "Test Check",
    status: str = "FAIL",
    severity: str = "HIGH",
    description: str = "Something is wrong",
    recommendation: str = "Fix it",
    raw_output: str | None = None,
) -> dict[str, Any]:
    """Build a minimal FindingDict for testing."""
    return {
        "check": check,
        "status": status,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "raw_output": raw_output,
    }


def _make_scan_result(
    os_name: str,
    findings: list[dict[str, Any]],
    server: str = "test-server",
) -> dict[str, Any]:
    """Build a minimal scan result dict mirroring scanner output."""
    summary: dict[str, int] = {"PASS": 0, "FAIL": 0, "WARNING": 0}
    for f in findings:
        summary[f["status"]] = summary.get(f["status"], 0) + 1
    return {
        "server": server,
        "os": os_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_duration_seconds": 1.23,
        "findings": findings,
        "total_checks": len(findings),
        "summary": summary,
    }


def _minimal_analysis(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Run Analyzer.analyze() with mocked Claude API (no network)."""
    with patch("src.analyzer.analyzer.CLAUDE_API_KEY", ""):
        analyzer = Analyzer(findings)
        return analyzer.analyze()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def windows_findings() -> list[dict[str, Any]]:
    return [
        _make_finding("Firewall Status", "FAIL", "HIGH"),
        _make_finding("SMBv1 Protocol", "FAIL", "CRITICAL"),
        _make_finding("Windows Defender", "PASS", "HIGH"),
        _make_finding("TLS Versions", "FAIL", "HIGH"),
        _make_finding("RDP NLA", "PASS", "HIGH"),
        _make_finding("LLMNR/NetBIOS", "WARNING", "MEDIUM"),
        _make_finding("Password Policies", "PASS", "MEDIUM"),
        _make_finding("Windows Update", "FAIL", "HIGH"),
        _make_finding("Admin Accounts", "PASS", "MEDIUM"),
        _make_finding("Privilege Creep", "PASS", "MEDIUM"),
        _make_finding("Event Log Config", "FAIL", "MEDIUM"),
        _make_finding("LSASS Protection", "PASS", "HIGH"),
        _make_finding("Weak Ciphers", "FAIL", "HIGH"),
        _make_finding("File Sharing", "PASS", "MEDIUM"),
        _make_finding("Installed Software", "WARNING", "MEDIUM"),
    ]


@pytest.fixture()
def linux_findings() -> list[dict[str, Any]]:
    return [
        _make_finding("SSH Key Authentication", "PASS", "HIGH"),
        _make_finding("SSH Root Login", "FAIL", "CRITICAL"),
        _make_finding("SSH Password Authentication", "FAIL", "HIGH"),
        _make_finding("Firewall Enabled", "PASS", "HIGH"),
        _make_finding("Sudo Configuration", "FAIL", "HIGH"),
        _make_finding("World-Writable Files", "PASS", "HIGH"),
        _make_finding("SUID Binaries", "WARNING", "HIGH"),
        _make_finding("File Permissions", "PASS", "HIGH"),
        _make_finding("Kernel Hardening", "FAIL", "MEDIUM"),
        _make_finding("SELinux/AppArmor", "PASS", "MEDIUM"),
        _make_finding("Package Updates", "FAIL", "MEDIUM"),
        _make_finding("SSL Certificates", "PASS", "HIGH"),
        _make_finding("Open Ports", "WARNING", "MEDIUM"),
        _make_finding("User Accounts", "PASS", "HIGH"),
        _make_finding("Failed Logins", "PASS", "MEDIUM"),
        _make_finding("Cron Jobs", "PASS", "MEDIUM"),
        _make_finding("Weak Ciphers", "FAIL", "HIGH"),
        _make_finding("Log Rotation", "PASS", "LOW"),
    ]


# ---------------------------------------------------------------------------
# Analyzer integration: Windows findings
# ---------------------------------------------------------------------------


class TestAnalyzerWithWindowsFindings:
    def test_analyze_returns_required_keys(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(windows_findings)
        required = {
            "risk_score",
            "risk_label",
            "severity_distribution",
            "compliance",
            "recommendations",
            "findings",
            "total_checks",
            "summary",
        }
        assert required.issubset(analysis.keys())

    def test_risk_score_in_range(self, windows_findings: list[dict[str, Any]]) -> None:
        analysis = _minimal_analysis(windows_findings)
        assert 0.0 <= analysis["risk_score"] <= 10.0

    def test_risk_label_is_string(self, windows_findings: list[dict[str, Any]]) -> None:
        analysis = _minimal_analysis(windows_findings)
        assert isinstance(analysis["risk_label"], str)
        assert analysis["risk_label"]

    def test_severity_distribution_keys(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(windows_findings)
        dist = analysis["severity_distribution"]
        assert set(dist.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_compliance_has_three_standards(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(windows_findings)
        compliance = analysis["compliance"]
        assert "ISO_27001" in compliance
        assert "CIS_Benchmarks" in compliance
        assert "PCI_DSS" in compliance

    def test_compliance_values_in_range(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(windows_findings)
        for std, val in analysis["compliance"].items():
            assert 0.0 <= val <= 1.0, f"{std} compliance out of range: {val}"

    def test_recommendations_list(self, windows_findings: list[dict[str, Any]]) -> None:
        analysis = _minimal_analysis(windows_findings)
        assert isinstance(analysis["recommendations"], list)

    def test_total_checks_matches_findings(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(windows_findings)
        assert analysis["total_checks"] == len(analysis["findings"])

    def test_summary_counts_are_correct(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(windows_findings)
        summary = analysis["summary"]
        findings = analysis["findings"]
        assert summary["PASS"] == sum(1 for f in findings if f["status"] == "PASS")
        assert summary["FAIL"] == sum(1 for f in findings if f["status"] == "FAIL")
        assert summary["WARNING"] == sum(
            1 for f in findings if f["status"] == "WARNING"
        )


# ---------------------------------------------------------------------------
# Analyzer integration: Linux findings
# ---------------------------------------------------------------------------


class TestAnalyzerWithLinuxFindings:
    def test_analyze_returns_required_keys(
        self, linux_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(linux_findings)
        required = {
            "risk_score",
            "risk_label",
            "severity_distribution",
            "compliance",
            "recommendations",
            "findings",
            "total_checks",
            "summary",
        }
        assert required.issubset(analysis.keys())

    def test_risk_score_in_range(self, linux_findings: list[dict[str, Any]]) -> None:
        analysis = _minimal_analysis(linux_findings)
        assert 0.0 <= analysis["risk_score"] <= 10.0

    def test_linux_findings_preserved(
        self, linux_findings: list[dict[str, Any]]
    ) -> None:
        """Analyzer must pass Linux findings through unchanged."""
        analysis = _minimal_analysis(linux_findings)
        assert analysis["findings"] == linux_findings

    def test_compliance_values_in_range(
        self, linux_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _minimal_analysis(linux_findings)
        for std, val in analysis["compliance"].items():
            assert 0.0 <= val <= 1.0


# ---------------------------------------------------------------------------
# Analyzer: both OS produce equivalent schema
# ---------------------------------------------------------------------------


class TestAnalyzerOSEquality:
    def test_both_os_produce_same_keys(
        self,
        windows_findings: list[dict[str, Any]],
        linux_findings: list[dict[str, Any]],
    ) -> None:
        win_analysis = _minimal_analysis(windows_findings)
        lin_analysis = _minimal_analysis(linux_findings)
        assert set(win_analysis.keys()) == set(lin_analysis.keys())

    def test_both_os_have_valid_risk_score(
        self,
        windows_findings: list[dict[str, Any]],
        linux_findings: list[dict[str, Any]],
    ) -> None:
        for findings in (windows_findings, linux_findings):
            analysis = _minimal_analysis(findings)
            assert 0.0 <= analysis["risk_score"] <= 10.0

    def test_all_pass_gives_zero_risk(self) -> None:
        findings = [_make_finding(f"Check {i}", "PASS", "HIGH") for i in range(10)]
        analysis = _minimal_analysis(findings)
        assert analysis["risk_score"] == 0.0

    def test_all_critical_fail_gives_max_risk(self) -> None:
        findings = [_make_finding(f"Check {i}", "FAIL", "CRITICAL") for i in range(5)]
        analysis = _minimal_analysis(findings)
        assert analysis["risk_score"] == 10.0

    def test_empty_findings_gives_zero_risk(self) -> None:
        analysis = _minimal_analysis([])
        assert analysis["risk_score"] == 0.0
        assert analysis["recommendations"] == []


# ---------------------------------------------------------------------------
# HTMLReporter integration
# ---------------------------------------------------------------------------


def _make_analysis_for_report(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build an analysis dict suitable for HTMLReporter."""
    return _minimal_analysis(findings)


class TestHTMLReporterWithWindowsFindings:
    def test_generate_returns_string(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _make_analysis_for_report(windows_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        assert isinstance(html, str)
        assert len(html) > 0

    def test_html_contains_doctype(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _make_analysis_for_report(windows_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()

    def test_html_has_risk_score(self, windows_findings: list[dict[str, Any]]) -> None:
        analysis = _make_analysis_for_report(windows_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        # Risk score should appear somewhere in the report
        score_str = str(round(analysis["risk_score"], 1))
        assert score_str in html

    def test_html_mentions_findings(
        self, windows_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _make_analysis_for_report(windows_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        # At least one finding check name should appear
        assert "Firewall" in html or "SMBv1" in html or "FAIL" in html


class TestHTMLReporterWithLinuxFindings:
    def test_generate_returns_string(
        self, linux_findings: list[dict[str, Any]]
    ) -> None:
        analysis = _make_analysis_for_report(linux_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        assert isinstance(html, str)
        assert len(html) > 0

    def test_html_contains_doctype(self, linux_findings: list[dict[str, Any]]) -> None:
        analysis = _make_analysis_for_report(linux_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()

    def test_html_has_risk_score(self, linux_findings: list[dict[str, Any]]) -> None:
        analysis = _make_analysis_for_report(linux_findings)
        reporter = HTMLReporter(analysis)
        html = reporter.generate()
        score_str = str(round(analysis["risk_score"], 1))
        assert score_str in html


class TestHTMLReporterBothOS:
    def test_both_os_produce_valid_html(
        self,
        windows_findings: list[dict[str, Any]],
        linux_findings: list[dict[str, Any]],
    ) -> None:
        for findings in (windows_findings, linux_findings):
            analysis = _make_analysis_for_report(findings)
            html = HTMLReporter(analysis).generate()
            assert isinstance(html, str)
            assert len(html) > 500  # meaningful content

    def test_html_output_is_standalone(
        self, linux_findings: list[dict[str, Any]]
    ) -> None:
        """Report must not reference external CDN URLs."""
        analysis = _make_analysis_for_report(linux_findings)
        html = HTMLReporter(analysis).generate()
        assert "cdn.jsdelivr.net" not in html
        assert "cdnjs.cloudflare.com" not in html

    def test_both_os_produce_compliance_section(
        self,
        windows_findings: list[dict[str, Any]],
        linux_findings: list[dict[str, Any]],
    ) -> None:
        for findings in (windows_findings, linux_findings):
            analysis = _make_analysis_for_report(findings)
            html = HTMLReporter(analysis).generate()
            # Compliance frameworks should appear in report
            assert "ISO" in html or "CIS" in html or "PCI" in html


# ---------------------------------------------------------------------------
# Scanner → Analyzer → Reporter: end-to-end mocked
# ---------------------------------------------------------------------------


class TestEndToEndWindows:
    def test_windows_scan_to_report(self) -> None:
        """Full pipeline: mock Windows scan → analyze → HTML report."""
        scanner = WindowsScanner("localhost")

        with patch.object(scanner, "_run_powershell", return_value=""):
            scan_result = scanner.run_scan()

        assert "findings" in scan_result
        assert len(scan_result["findings"]) == 15

        with patch("src.analyzer.analyzer.CLAUDE_API_KEY", ""):
            analyzer = Analyzer(scan_result["findings"])
            analysis = analyzer.analyze()

        assert 0.0 <= analysis["risk_score"] <= 10.0

        html = HTMLReporter(analysis).generate()
        assert isinstance(html, str)
        assert len(html) > 500


class TestEndToEndLinux:
    def test_linux_scan_to_report(self) -> None:
        """Full pipeline: mock Linux scan → analyze → HTML report."""
        scanner = LinuxScanner("localhost")

        with (
            patch.object(scanner, "_run_command", return_value=("", "", 0)),
            patch.object(scanner, "_read_file", return_value=""),
        ):
            scan_result = scanner.run_scan()

        assert scan_result["os"] == "linux"
        assert len(scan_result["findings"]) == 18

        with patch("src.analyzer.analyzer.CLAUDE_API_KEY", ""):
            analyzer = Analyzer(scan_result["findings"])
            analysis = analyzer.analyze()

        assert 0.0 <= analysis["risk_score"] <= 10.0

        html = HTMLReporter(analysis).generate()
        assert isinstance(html, str)
        assert len(html) > 500


class TestEndToEndFindingSchemaConsistency:
    def test_windows_and_linux_findings_have_same_keys(self) -> None:
        """Both scanners must produce FindingDicts with identical key sets."""
        win_scanner = WindowsScanner("localhost")
        lin_scanner = LinuxScanner("localhost")

        with patch.object(win_scanner, "_run_powershell", return_value=""):
            win_result = win_scanner.run_scan()

        with (
            patch.object(lin_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(lin_scanner, "_read_file", return_value=""),
        ):
            lin_result = lin_scanner.run_scan()

        win_keys = set(win_result["findings"][0].keys())
        lin_keys = set(lin_result["findings"][0].keys())
        assert win_keys == lin_keys, (
            f"Key mismatch between Windows and Linux findings:\n"
            f"  Windows only: {win_keys - lin_keys}\n"
            f"  Linux only: {lin_keys - win_keys}"
        )

    def test_both_scanners_produce_valid_status_values(self) -> None:
        valid_statuses = {"PASS", "FAIL", "WARNING"}
        win_scanner = WindowsScanner("localhost")
        lin_scanner = LinuxScanner("localhost")

        with patch.object(win_scanner, "_run_powershell", return_value=""):
            win_result = win_scanner.run_scan()

        with (
            patch.object(lin_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(lin_scanner, "_read_file", return_value=""),
        ):
            lin_result = lin_scanner.run_scan()

        for finding in win_result["findings"] + lin_result["findings"]:
            assert finding["status"] in valid_statuses
            assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_scan_result_schema_common_keys_present(self) -> None:
        """Both scan results must include the common required top-level keys."""
        common_keys = {
            "server",
            "timestamp",
            "scan_duration_seconds",
            "findings",
            "total_checks",
            "summary",
        }
        win_scanner = WindowsScanner("localhost")
        lin_scanner = LinuxScanner("localhost")

        with patch.object(win_scanner, "_run_powershell", return_value=""):
            win_result = win_scanner.run_scan()

        with (
            patch.object(lin_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(lin_scanner, "_read_file", return_value=""),
        ):
            lin_result = lin_scanner.run_scan()

        assert common_keys.issubset(
            win_result.keys()
        ), f"Windows scan result missing keys: {common_keys - win_result.keys()}"
        assert common_keys.issubset(
            lin_result.keys()
        ), f"Linux scan result missing keys: {common_keys - lin_result.keys()}"
        # Linux scanner additionally includes 'os'
        assert lin_result.get("os") == "linux"
