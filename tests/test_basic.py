"""Basic sanity tests – verify all modules import and classes can be instantiated.

These tests are intentionally minimal and should pass without any real Windows
environment, API keys, or network access.  Agente 2 will add full test coverage.
"""

from __future__ import annotations

import pytest  # noqa: F401


class TestImports:
    """Verify that all core modules import without errors."""

    def test_import_config(self) -> None:
        """Config module should import cleanly."""
        import src.config as config  # noqa: F401

        assert config.APP_VERSION == "0.1.0"
        assert "CRITICAL" in config.SEVERITY_WEIGHTS
        assert config.SEVERITY_WEIGHTS["CRITICAL"] == 10

    def test_import_windows_scanner(self) -> None:
        """WindowsScanner should be importable."""
        from src.scanner.windows_scanner import WindowsScanner  # noqa: F401

        assert WindowsScanner is not None

    def test_import_risk_scorer(self) -> None:
        """RiskScorer should be importable."""
        from src.analyzer.risk_scorer import RiskScorer  # noqa: F401

        assert RiskScorer is not None

    def test_import_analyzer(self) -> None:
        """Analyzer should be importable."""
        from src.analyzer.analyzer import Analyzer  # noqa: F401

        assert Analyzer is not None

    def test_import_html_reporter(self) -> None:
        """HTMLReporter should be importable."""
        from src.reporter.html_generator import HTMLReporter  # noqa: F401

        assert HTMLReporter is not None

    def test_import_cli(self) -> None:
        """CLI group should be importable."""
        from src.cli import cli  # noqa: F401

        assert cli is not None


class TestInstantiation:
    """Verify that core classes can be instantiated with minimal arguments."""

    def test_windows_scanner_local(self) -> None:
        """WindowsScanner should instantiate for localhost without credentials."""
        from src.scanner.windows_scanner import WindowsScanner

        scanner = WindowsScanner(target="localhost")
        assert scanner.target == "localhost"
        assert scanner._is_local is True

    def test_windows_scanner_remote_no_credentials(self) -> None:
        """WindowsScanner should instantiate for a remote host without WinRM init."""
        from src.scanner.windows_scanner import WindowsScanner

        scanner = WindowsScanner(target="192.168.1.100")
        assert scanner.target == "192.168.1.100"
        assert scanner._is_local is False
        # No credentials → _winrm_session should remain None
        assert scanner._winrm_session is None

    def test_risk_scorer_score_empty(self) -> None:
        """RiskScorer should return 0.0 for empty findings."""
        from src.analyzer.risk_scorer import RiskScorer

        score = RiskScorer.calculate_score([])
        assert score == 0.0

    def test_risk_scorer_all_pass(self) -> None:
        """RiskScorer should return 0.0 when all findings are PASS."""
        from src.analyzer.risk_scorer import RiskScorer

        findings = [
            {"status": "PASS", "severity": "CRITICAL"},
            {"status": "PASS", "severity": "HIGH"},
        ]
        assert RiskScorer.calculate_score(findings) == 0.0

    def test_risk_scorer_single_critical(self) -> None:
        """A single CRITICAL FAIL should produce maximum score."""
        from src.analyzer.risk_scorer import RiskScorer

        findings = [{"status": "FAIL", "severity": "CRITICAL"}]
        score = RiskScorer.calculate_score(findings)
        assert score == 10.0

    def test_risk_scorer_distribution(self) -> None:
        """Severity distribution should count all severity levels."""
        from src.analyzer.risk_scorer import RiskScorer

        findings = [
            {"status": "FAIL", "severity": "CRITICAL"},
            {"status": "FAIL", "severity": "HIGH"},
            {"status": "PASS", "severity": "LOW"},
        ]
        dist = RiskScorer.severity_distribution(findings)
        assert dist["CRITICAL"] == 1
        assert dist["HIGH"] == 1
        assert dist["MEDIUM"] == 0
        assert dist["LOW"] == 1

    def test_risk_scorer_label(self) -> None:
        """Risk labels should categorize scores correctly."""
        from src.analyzer.risk_scorer import RiskScorer

        assert RiskScorer.risk_label(9.0) == "CRITICAL"
        assert RiskScorer.risk_label(7.0) == "HIGH"
        assert RiskScorer.risk_label(5.0) == "MEDIUM"
        assert RiskScorer.risk_label(2.0) == "LOW"
        assert RiskScorer.risk_label(0.5) == "MINIMAL"

    def test_analyzer_instantiation(self) -> None:
        """Analyzer should instantiate with an empty findings list."""
        from src.analyzer.analyzer import Analyzer

        analyzer = Analyzer([])
        assert analyzer.findings == []

    def test_analyzer_calculate_risk_score_empty(self) -> None:
        """Analyzer risk score should be 0.0 for empty findings."""
        from src.analyzer.analyzer import Analyzer

        analyzer = Analyzer([])
        assert analyzer.calculate_risk_score() == 0.0

    def test_analyzer_severity_distribution_empty(self) -> None:
        """Severity distribution should have all zeros for empty findings."""
        from src.analyzer.analyzer import Analyzer

        analyzer = Analyzer([])
        dist = analyzer.assign_severity_distribution()
        assert all(v == 0 for v in dist.values())

    def test_analyzer_compliance_empty(self) -> None:
        """Compliance map should have keys for all three standards."""
        from src.analyzer.analyzer import Analyzer

        analyzer = Analyzer([])
        compliance = analyzer.map_to_compliance()
        assert "ISO_27001" in compliance
        assert "CIS_Benchmarks" in compliance
        assert "PCI_DSS" in compliance
        # With no failures, compliance should be high (close to 1.0)
        for val in compliance.values():
            assert 0.0 <= val <= 1.0

    def test_html_reporter_instantiation(self) -> None:
        """HTMLReporter should instantiate with minimal analysis data."""
        from src.reporter.html_generator import HTMLReporter

        data = {
            "server": "localhost",
            "timestamp": "2026-03-20T19:36:00+00:00",
            "scan_duration_seconds": 5.0,
            "risk_score": 0.0,
            "risk_label": "MINIMAL",
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "compliance": {"ISO_27001": 1.0, "CIS_Benchmarks": 1.0, "PCI_DSS": 1.0},
            "recommendations": [],
            "findings": [],
            "total_checks": 0,
            "summary": {"PASS": 0, "FAIL": 0, "WARNING": 0},
        }
        reporter = HTMLReporter(data)
        assert reporter.data == data

    def test_html_reporter_generate(self) -> None:
        """HTMLReporter.generate() should return a non-empty HTML string."""
        from src.reporter.html_generator import HTMLReporter

        data = {
            "server": "localhost",
            "timestamp": "2026-03-20T19:36:00+00:00",
            "scan_duration_seconds": 5.0,
            "risk_score": 7.5,
            "risk_label": "HIGH",
            "severity_distribution": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "compliance": {"ISO_27001": 0.85, "CIS_Benchmarks": 0.78, "PCI_DSS": 0.72},
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
                    "description": "Firewall disabled.",
                    "recommendation": "Enable it.",
                }
            ],
            "total_checks": 1,
            "summary": {"PASS": 0, "FAIL": 1, "WARNING": 0},
        }
        reporter = HTMLReporter(data)
        html = reporter.generate()

        assert isinstance(html, str)
        assert len(html) > 100
        assert "<!DOCTYPE html>" in html
        assert "localhost" in html
        assert "Firewall Status" in html
        # All 7 section IDs must be present
        for section_id in [
            "executive-summary",
            "risk-dashboard",
            "findings",
            "compliance",
            "recommendations",
            "roadmap",
            "appendix",
        ]:
            assert section_id in html, f"Missing section: {section_id}"


class TestWindowsScannerCheckStructure:
    """Verify check methods return properly structured FindingDicts (no PowerShell needed)."""

    REQUIRED_KEYS = {"check", "status", "severity", "description", "recommendation"}
    VALID_STATUSES = {"PASS", "FAIL", "WARNING"}
    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def _check_structure(self, result: dict) -> None:
        for key in self.REQUIRED_KEYS:
            assert key in result, f"Missing key: {key}"
        assert result["status"] in self.VALID_STATUSES
        assert result["severity"] in self.VALID_SEVERITIES
        assert isinstance(result["description"], str)
        assert isinstance(result["recommendation"], str)

    def test_scanner_has_15_plus_check_methods(self) -> None:
        """WindowsScanner must have at least 15 check_* methods."""
        from src.scanner.windows_scanner import WindowsScanner

        checks = [m for m in dir(WindowsScanner) if m.startswith("check_")]
        assert len(checks) >= 15, f"Only {len(checks)} check methods found"
