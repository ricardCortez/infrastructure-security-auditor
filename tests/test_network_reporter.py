"""Tests for NetworkReporter module."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.reporter.network_reporter import NetworkReporter

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_batch_result() -> dict:
    return {
        "network": "192.168.1.0/24",
        "scan_timestamp": "2024-03-20T10:00:00+00:00",
        "scan_duration_seconds": 120.5,
        "servers": [
            {
                "ip": "192.168.1.1",
                "hostname": "DC01",
                "os": "windows",
                "status": "success",
                "error_message": "",
                "findings": [
                    {
                        "check": "Firewall Status", "status": "FAIL",
                        "severity": "CRITICAL",
                        "description": "Firewall disabled",
                        "recommendation": "Enable it",
                    },
                    {
                        "check": "SMBv1 Protocol", "status": "PASS",
                        "severity": "CRITICAL",
                        "description": "SMBv1 disabled",
                        "recommendation": "",
                    },
                ],
                "risk_score": 7.5,
                "scan_duration_seconds": 45.2,
            },
            {
                "ip": "192.168.1.2",
                "hostname": "WEB01",
                "os": "linux",
                "status": "success",
                "error_message": "",
                "findings": [
                    {
                        "check": "SSH Config", "status": "FAIL",
                        "severity": "HIGH",
                        "description": "Root login enabled",
                        "recommendation": "Disable root login",
                    },
                    {
                        "check": "Firewall Status", "status": "FAIL",
                        "severity": "CRITICAL",
                        "description": "Firewall disabled",
                        "recommendation": "Enable it",
                    },
                ],
                "risk_score": 5.0,
                "scan_duration_seconds": 30.1,
            },
            {
                "ip": "192.168.1.3",
                "hostname": "unknown",
                "os": "windows",
                "status": "error",
                "error_message": "Connection refused",
                "findings": [],
                "risk_score": 0.0,
                "scan_duration_seconds": 5.0,
            },
        ],
        "network_summary": {
            "total_servers_scanned": 3,
            "successful_scans": 2,
            "failed_scans": 1,
            "total_findings": 3,
            "critical_findings": 2,
            "high_findings": 1,
            "medium_findings": 0,
            "low_findings": 0,
            "compliance_iso27001": 0.50,
            "compliance_cis_benchmarks": 0.48,
            "compliance_pci_dss": 0.45,
            "top_critical_servers": [
                {
                    "ip": "192.168.1.1",
                    "hostname": "DC01",
                    "risk_score": 7.5,
                    "critical_count": 1,
                }
            ],
        },
    }


@pytest.fixture
def reporter(sample_batch_result: dict) -> NetworkReporter:
    return NetworkReporter(sample_batch_result)


@pytest.fixture
def empty_reporter() -> NetworkReporter:
    return NetworkReporter({})


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_stores_data(self, sample_batch_result: dict) -> None:
        r = NetworkReporter(sample_batch_result)
        assert r.data is sample_batch_result

    def test_jinja2_env_configured(self, reporter: NetworkReporter) -> None:
        assert reporter._env is not None

    def test_template_loadable(self, reporter: NetworkReporter) -> None:
        tmpl = reporter._env.get_template("network_report.html")
        assert tmpl is not None


# ---------------------------------------------------------------------------
# _build_context
# ---------------------------------------------------------------------------


class TestBuildContext:
    def test_empty_data_no_key_error(self, empty_reporter: NetworkReporter) -> None:
        ctx = empty_reporter._build_context(summary_only=True)
        assert isinstance(ctx, dict)

    def test_avg_risk_calculated(self, reporter: NetworkReporter) -> None:
        ctx = reporter._build_context(summary_only=False)
        assert ctx["network_risk_score"] == pytest.approx(6.25, abs=0.5)

    def test_risk_label_critical_when_score_8(self) -> None:
        data = {
            "servers": [
                {"ip": "1.1.1.1", "status": "success", "risk_score": 8.5, "findings": [],
                 "hostname": "h", "os": "windows", "error_message": "",
                 "scan_duration_seconds": 1},
            ],
            "network_summary": {},
        }
        r = NetworkReporter(data)
        ctx = r._build_context(summary_only=False)
        assert ctx["network_risk_label"] == "CRITICAL"

    def test_risk_label_high_when_6(self) -> None:
        data = {
            "servers": [
                {"ip": "1.1.1.1", "status": "success", "risk_score": 7.0, "findings": [],
                 "hostname": "h", "os": "windows", "error_message": "",
                 "scan_duration_seconds": 1},
            ],
            "network_summary": {},
        }
        r = NetworkReporter(data)
        ctx = r._build_context(summary_only=False)
        assert ctx["network_risk_label"] == "HIGH"

    def test_risk_label_medium_when_4(self) -> None:
        data = {
            "servers": [
                {"ip": "1.1.1.1", "status": "success", "risk_score": 5.0, "findings": [],
                 "hostname": "h", "os": "windows", "error_message": "",
                 "scan_duration_seconds": 1},
            ],
            "network_summary": {},
        }
        r = NetworkReporter(data)
        ctx = r._build_context(summary_only=False)
        assert ctx["network_risk_label"] == "MEDIUM"

    def test_common_findings_threshold_3(
        self, sample_batch_result: dict
    ) -> None:
        # Firewall Status appears on 2 servers → should NOT appear in common_findings
        r = NetworkReporter(sample_batch_result)
        ctx = r._build_context(summary_only=False)
        assert len(ctx["common_findings"]) == 0

    def test_common_findings_threshold_3_with_3_servers(self) -> None:
        servers = [
            {
                "ip": f"1.1.1.{i}", "status": "success", "risk_score": 5.0,
                "hostname": "h", "os": "windows", "error_message": "",
                "scan_duration_seconds": 1,
                "findings": [
                    {"check": "Firewall Status", "status": "FAIL", "severity": "CRITICAL",
                     "description": "d", "recommendation": "r"},
                ],
            }
            for i in range(3)
        ]
        r = NetworkReporter({"servers": servers, "network_summary": {}})
        ctx = r._build_context(summary_only=False)
        assert any(f["check"] == "Firewall Status" for f in ctx["common_findings"])

    def test_summary_only_true_excludes_findings(
        self, reporter: NetworkReporter
    ) -> None:
        ctx = reporter._build_context(summary_only=True)
        for s in ctx["servers"]:
            assert "findings" not in s
            assert "fail_count" in s

    def test_summary_only_false_includes_findings(
        self, reporter: NetworkReporter
    ) -> None:
        ctx = reporter._build_context(summary_only=False)
        successful = [s for s in ctx["servers"] if "findings" in s]
        assert len(successful) > 0

    def test_servers_sorted_by_risk_desc(self, reporter: NetworkReporter) -> None:
        ctx = reporter._build_context(summary_only=True)
        scores = [s["risk_score"] for s in ctx["servers"]]
        assert scores == sorted(scores, reverse=True)

    def test_compliance_percentages_scaled(
        self, reporter: NetworkReporter
    ) -> None:
        ctx = reporter._build_context(summary_only=False)
        assert ctx["compliance_iso27001"] == pytest.approx(50.0, abs=1.0)
        assert ctx["compliance_cis"] == pytest.approx(48.0, abs=1.0)
        assert ctx["compliance_pci"] == pytest.approx(45.0, abs=1.0)

    def test_total_servers_from_summary(self, reporter: NetworkReporter) -> None:
        ctx = reporter._build_context(summary_only=False)
        assert ctx["total_servers"] == 3

    def test_scan_timestamp_in_context(self, reporter: NetworkReporter) -> None:
        ctx = reporter._build_context(summary_only=False)
        assert ctx["scan_timestamp"] == "2024-03-20T10:00:00+00:00"


# ---------------------------------------------------------------------------
# generate_network_summary
# ---------------------------------------------------------------------------


class TestGenerateNetworkSummary:
    def test_returns_html_string(self, reporter: NetworkReporter) -> None:
        html = reporter.generate_network_summary()
        assert isinstance(html, str)
        assert len(html) > 100

    def test_contains_doctype_or_html_tag(
        self, reporter: NetworkReporter
    ) -> None:
        html = reporter.generate_network_summary()
        assert "<!DOCTYPE" in html or "<html" in html

    def test_contains_network_name(self, reporter: NetworkReporter) -> None:
        html = reporter.generate_network_summary()
        assert "192.168.1.0/24" in html

    def test_contains_server_ips(self, reporter: NetworkReporter) -> None:
        html = reporter.generate_network_summary()
        assert "192.168.1.1" in html

    def test_contains_risk_label(self, reporter: NetworkReporter) -> None:
        html = reporter.generate_network_summary()
        assert any(label in html for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"))


# ---------------------------------------------------------------------------
# generate_consolidated_report
# ---------------------------------------------------------------------------


class TestGenerateConsolidatedReport:
    def test_returns_html_string(self, reporter: NetworkReporter) -> None:
        html = reporter.generate_consolidated_report()
        assert isinstance(html, str)

    def test_contains_raw_json_section(
        self, reporter: NetworkReporter
    ) -> None:
        html = reporter.generate_consolidated_report()
        assert "Technical Appendix" in html or "appendix" in html.lower()

    def test_contains_server_details_section(
        self, reporter: NetworkReporter
    ) -> None:
        html = reporter.generate_consolidated_report()
        assert "Server Details" in html or "details" in html.lower()

    def test_contains_compliance_section(
        self, reporter: NetworkReporter
    ) -> None:
        html = reporter.generate_consolidated_report()
        assert "ISO" in html or "Compliance" in html

    def test_contains_dc01_hostname(self, reporter: NetworkReporter) -> None:
        html = reporter.generate_consolidated_report()
        assert "DC01" in html


# ---------------------------------------------------------------------------
# save_reports
# ---------------------------------------------------------------------------


class TestSaveReports:
    def test_creates_output_directory(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "network_reports"
        reporter.save_reports(str(out_dir))
        assert out_dir.exists()

    def test_creates_summary_file(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        paths = reporter.save_reports(str(tmp_path))
        assert Path(paths["summary_path"]).exists()

    def test_creates_consolidated_file(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        paths = reporter.save_reports(str(tmp_path))
        assert Path(paths["consolidated_path"]).exists()

    def test_returns_dict_with_both_paths(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        paths = reporter.save_reports(str(tmp_path))
        assert "summary_path" in paths
        assert "consolidated_path" in paths

    def test_summary_file_contains_html(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        paths = reporter.save_reports(str(tmp_path))
        content = Path(paths["summary_path"]).read_text(encoding="utf-8")
        assert "<html" in content

    def test_consolidated_file_contains_html(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        paths = reporter.save_reports(str(tmp_path))
        content = Path(paths["consolidated_path"]).read_text(encoding="utf-8")
        assert "<html" in content

    def test_nested_directory_created(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "a" / "b" / "c"
        reporter.save_reports(str(out_dir))
        assert out_dir.exists()

    def test_summary_is_smaller_than_consolidated(
        self, reporter: NetworkReporter, tmp_path: Path
    ) -> None:
        paths = reporter.save_reports(str(tmp_path))
        summary_size = Path(paths["summary_path"]).stat().st_size
        consolidated_size = Path(paths["consolidated_path"]).stat().st_size
        assert consolidated_size >= summary_size
