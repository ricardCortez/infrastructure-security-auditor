"""Tests for BatchScanner module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.scanner.batch_scanner import BatchScanner

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_WINDOWS_HOST = {"ip": "192.168.1.1", "hostname": "DC01", "os_hint": "windows"}
_LINUX_HOST = {"ip": "192.168.1.2", "hostname": "WEB01", "os_hint": "linux"}
_UNKNOWN_HOST = {"ip": "192.168.1.3", "hostname": "unknown", "os_hint": "unknown"}

_SAMPLE_FINDINGS = [
    {
        "check": "Firewall Status", "status": "FAIL", "severity": "CRITICAL",
        "description": "Disabled", "recommendation": "Enable it",
    },
    {
        "check": "SMBv1 Protocol", "status": "PASS", "severity": "CRITICAL",
        "description": "Disabled", "recommendation": "",
    },
    {
        "check": "Password Policies", "status": "WARNING", "severity": "HIGH",
        "description": "Weak policy", "recommendation": "Strengthen",
    },
]

_SCAN_RESULT = {
    "server": "192.168.1.1",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "findings": _SAMPLE_FINDINGS,
    "summary": {"PASS": 1, "FAIL": 1, "WARNING": 1},
    "scan_duration_seconds": 10.0,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def batch_windows() -> BatchScanner:
    return BatchScanner([_WINDOWS_HOST], max_workers=2, timeout=30)


@pytest.fixture
def batch_mixed() -> BatchScanner:
    return BatchScanner(
        [_WINDOWS_HOST, _LINUX_HOST, _UNKNOWN_HOST], max_workers=3, timeout=30
    )


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_max_workers(self) -> None:
        b = BatchScanner([])
        assert b.max_workers == 10

    def test_default_timeout(self) -> None:
        b = BatchScanner([])
        assert b.timeout == 300

    def test_custom_values_stored(self) -> None:
        b = BatchScanner([_WINDOWS_HOST], max_workers=5, timeout=60)
        assert b.max_workers == 5
        assert b.timeout == 60

    def test_none_credentials_becomes_empty_dict(self) -> None:
        b = BatchScanner([], credentials=None)
        assert b.credentials == {}

    def test_credentials_stored(self) -> None:
        creds = {"username": "admin", "password": "secret"}
        b = BatchScanner([], credentials=creds)
        assert b.credentials == creds


# ---------------------------------------------------------------------------
# _calculate_risk_score
# ---------------------------------------------------------------------------


class TestCalculateRiskScore:
    def test_all_critical_fail_returns_high_score(
        self, batch_windows: BatchScanner
    ) -> None:
        findings = [
            {"check": "F", "status": "FAIL", "severity": "CRITICAL"},
        ] * 10
        score = batch_windows._calculate_risk_score(findings)
        assert score == 10.0

    def test_all_pass_returns_zero(self, batch_windows: BatchScanner) -> None:
        findings = [
            {"check": "F", "status": "PASS", "severity": "CRITICAL"},
        ] * 5
        assert batch_windows._calculate_risk_score(findings) == 0.0

    def test_empty_findings_returns_zero(self, batch_windows: BatchScanner) -> None:
        assert batch_windows._calculate_risk_score([]) == 0.0

    def test_warning_status_counts(self, batch_windows: BatchScanner) -> None:
        findings = [{"check": "F", "status": "WARNING", "severity": "HIGH"}]
        score = batch_windows._calculate_risk_score(findings)
        assert score > 0

    def test_mixed_severities_proportional(self, batch_windows: BatchScanner) -> None:
        findings = [
            {"check": "A", "status": "FAIL", "severity": "CRITICAL"},
            {"check": "B", "status": "PASS", "severity": "CRITICAL"},
        ]
        score = batch_windows._calculate_risk_score(findings)
        assert 4.0 < score < 6.0

    def test_score_capped_at_10(self, batch_windows: BatchScanner) -> None:
        findings = [
            {"check": f"F{i}", "status": "FAIL", "severity": "CRITICAL"}
            for i in range(100)
        ]
        assert batch_windows._calculate_risk_score(findings) <= 10.0

    def test_only_low_severity_low_score(self, batch_windows: BatchScanner) -> None:
        findings = [{"check": "F", "status": "FAIL", "severity": "LOW"}]
        score = batch_windows._calculate_risk_score(findings)
        assert score == 10.0  # Only finding, so 100% fail rate → 10


# ---------------------------------------------------------------------------
# _error_result
# ---------------------------------------------------------------------------


class TestErrorResult:
    def test_timeout_in_msg_sets_timeout_status(
        self, batch_windows: BatchScanner
    ) -> None:
        r = batch_windows._error_result(_WINDOWS_HOST, "connection timeout")
        assert r["status"] == "timeout"

    def test_other_error_sets_error_status(
        self, batch_windows: BatchScanner
    ) -> None:
        r = batch_windows._error_result(_WINDOWS_HOST, "connection refused")
        assert r["status"] == "error"

    def test_correct_keys_present(self, batch_windows: BatchScanner) -> None:
        r = batch_windows._error_result(_WINDOWS_HOST, "boom")
        for key in ("ip", "os", "hostname", "status", "error_message", "findings",
                    "risk_score", "scan_duration_seconds"):
            assert key in r

    def test_findings_is_empty_list(self, batch_windows: BatchScanner) -> None:
        r = batch_windows._error_result(_WINDOWS_HOST, "boom")
        assert r["findings"] == []

    def test_risk_score_is_zero(self, batch_windows: BatchScanner) -> None:
        r = batch_windows._error_result(_WINDOWS_HOST, "boom")
        assert r["risk_score"] == 0.0


# ---------------------------------------------------------------------------
# _infer_network_label
# ---------------------------------------------------------------------------


class TestInferNetworkLabel:
    def test_empty_hosts_returns_unknown(self) -> None:
        b = BatchScanner([])
        assert b._infer_network_label() == "unknown"

    def test_valid_ip_returns_24_cidr(self) -> None:
        b = BatchScanner([{"ip": "192.168.1.5"}])
        assert b._infer_network_label() == "192.168.1.0/24"

    def test_10_prefix(self) -> None:
        b = BatchScanner([{"ip": "10.0.0.50"}])
        assert b._infer_network_label() == "10.0.0.0/24"


# ---------------------------------------------------------------------------
# _aggregate_network_metrics
# ---------------------------------------------------------------------------


class TestAggregateNetworkMetrics:
    def _make_server(
        self,
        ip: str,
        status: str = "success",
        findings: list | None = None,
        risk_score: float = 5.0,
    ) -> dict:
        return {
            "ip": ip,
            "hostname": "h",
            "os": "windows",
            "status": status,
            "error_message": "",
            "findings": findings or [],
            "risk_score": risk_score,
            "scan_duration_seconds": 10,
        }

    def test_successful_count(self, batch_windows: BatchScanner) -> None:
        results = [
            self._make_server("1.1.1.1", status="success"),
            self._make_server("1.1.1.2", status="error"),
        ]
        m = batch_windows._aggregate_network_metrics(results)
        assert m["successful_scans"] == 1
        assert m["failed_scans"] == 1

    def test_severity_counts(self, batch_windows: BatchScanner) -> None:
        findings = [
            {"check": "A", "status": "FAIL", "severity": "CRITICAL"},
            {"check": "B", "status": "FAIL", "severity": "HIGH"},
            {"check": "C", "status": "PASS", "severity": "CRITICAL"},
        ]
        results = [self._make_server("1.1.1.1", findings=findings)]
        m = batch_windows._aggregate_network_metrics(results)
        assert m["critical_findings"] == 1
        assert m["high_findings"] == 1

    def test_total_findings_count(self, batch_windows: BatchScanner) -> None:
        findings = [
            {"check": "A", "status": "FAIL", "severity": "CRITICAL"},
            {"check": "B", "status": "FAIL", "severity": "HIGH"},
        ]
        results = [self._make_server("1.1.1.1", findings=findings)]
        m = batch_windows._aggregate_network_metrics(results)
        assert m["total_findings"] == 2

    def test_top_critical_servers_max_5(self, batch_windows: BatchScanner) -> None:
        results = [
            self._make_server(f"1.1.1.{i}", risk_score=float(i)) for i in range(10)
        ]
        m = batch_windows._aggregate_network_metrics(results)
        assert len(m["top_critical_servers"]) <= 5

    def test_top_critical_servers_sorted_desc(
        self, batch_windows: BatchScanner
    ) -> None:
        results = [
            self._make_server("1.1.1.1", risk_score=3.0),
            self._make_server("1.1.1.2", risk_score=9.0),
            self._make_server("1.1.1.3", risk_score=6.0),
        ]
        m = batch_windows._aggregate_network_metrics(results)
        scores = [s["risk_score"] for s in m["top_critical_servers"]]
        assert scores == sorted(scores, reverse=True)

    def test_all_required_keys(self, batch_windows: BatchScanner) -> None:
        m = batch_windows._aggregate_network_metrics([])
        for key in (
            "total_servers_scanned", "successful_scans", "failed_scans",
            "total_findings", "critical_findings", "high_findings",
            "medium_findings", "low_findings",
            "compliance_iso27001", "compliance_cis_benchmarks",
            "compliance_pci_dss", "top_critical_servers",
        ):
            assert key in m


# ---------------------------------------------------------------------------
# scan_all (mocked scanners)
# ---------------------------------------------------------------------------


class TestScanAll:
    @patch("src.scanner.batch_scanner.BatchScanner._scan_host")
    def test_returns_batch_result_schema(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = {
            "ip": "192.168.1.1", "os": "windows", "hostname": "DC01",
            "status": "success", "error_message": "",
            "findings": _SAMPLE_FINDINGS, "risk_score": 6.0,
            "scan_duration_seconds": 10.0,
        }
        b = BatchScanner([_WINDOWS_HOST], max_workers=1, timeout=30)
        result = b.scan_all()
        for key in ("network", "scan_timestamp", "scan_duration_seconds",
                    "servers", "network_summary"):
            assert key in result

    @patch("src.scanner.batch_scanner.BatchScanner._scan_host")
    def test_scan_timestamp_present(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = {
            "ip": "1.1.1.1", "os": "windows", "hostname": "h",
            "status": "success", "error_message": "",
            "findings": [], "risk_score": 0.0, "scan_duration_seconds": 1.0,
        }
        b = BatchScanner([_WINDOWS_HOST], max_workers=1, timeout=30)
        result = b.scan_all()
        assert result["scan_timestamp"]
        assert "T" in result["scan_timestamp"]

    @patch("src.scanner.batch_scanner.BatchScanner._scan_host")
    def test_handles_exception_gracefully(self, mock_scan: MagicMock) -> None:
        mock_scan.side_effect = Exception("connection refused")
        b = BatchScanner([_WINDOWS_HOST], max_workers=1, timeout=30)
        result = b.scan_all()
        assert result["network_summary"]["failed_scans"] == 1

    @patch("src.scanner.batch_scanner.BatchScanner._scan_host")
    def test_network_summary_has_required_keys(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = {
            "ip": "1.1.1.1", "os": "windows", "hostname": "h",
            "status": "success", "error_message": "",
            "findings": [], "risk_score": 0.0, "scan_duration_seconds": 1.0,
        }
        b = BatchScanner([_WINDOWS_HOST], max_workers=1, timeout=30)
        result = b.scan_all()
        ns = result["network_summary"]
        assert "total_servers_scanned" in ns
        assert "critical_findings" in ns
        assert "compliance_iso27001" in ns


# ---------------------------------------------------------------------------
# _scan_host routing
# ---------------------------------------------------------------------------


class TestScanHostRouting:
    def test_windows_host_routes_to_windows_scanner(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.run_scan.return_value = {"findings": [], "server": "1.1.1.1"}
        mock_cls = MagicMock(return_value=mock_scanner)
        b = BatchScanner([_WINDOWS_HOST], max_workers=1, timeout=30)
        with patch("src.scanner.windows_scanner.WindowsScanner", mock_cls):
            with patch(
                "src.scanner.batch_scanner.WindowsScanner", mock_cls, create=True
            ):
                b._scan_host(_WINDOWS_HOST)
        # WindowsScanner was used (mock_scanner.run_scan called)
        mock_scanner.run_scan.assert_called_once()

    def test_linux_host_routes_to_linux_scanner(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.run_scan.return_value = {"findings": [], "server": "1.1.1.2"}
        mock_cls = MagicMock(return_value=mock_scanner)
        b = BatchScanner([_LINUX_HOST], max_workers=1, timeout=30)
        with patch("src.scanner.linux_scanner.LinuxScanner", mock_cls):
            with patch(
                "src.scanner.batch_scanner.LinuxScanner", mock_cls, create=True
            ):
                b._scan_host(_LINUX_HOST)
        mock_scanner.run_scan.assert_called_once()

    def test_unknown_os_routes_to_windows_scanner(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.run_scan.return_value = {"findings": [], "server": "1.1.1.3"}
        mock_cls = MagicMock(return_value=mock_scanner)
        b = BatchScanner([_UNKNOWN_HOST], max_workers=1, timeout=30)
        with patch("src.scanner.windows_scanner.WindowsScanner", mock_cls):
            with patch(
                "src.scanner.batch_scanner.WindowsScanner", mock_cls, create=True
            ):
                b._scan_host(_UNKNOWN_HOST)
        mock_scanner.run_scan.assert_called_once()

    def test_scan_exception_returns_error_result(self) -> None:
        b = BatchScanner([_WINDOWS_HOST], max_workers=1, timeout=30)
        with patch(
            "src.scanner.windows_scanner.WindowsScanner",
            side_effect=Exception("refused"),
        ):
            result = b._scan_host(_WINDOWS_HOST)
        assert result["status"] == "error"
        assert result["findings"] == []
