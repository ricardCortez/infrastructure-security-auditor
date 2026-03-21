"""Unit tests for CLI Click commands using CliRunner (SQLite-backed, no server needed)."""
import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import cli.local_db as db
from cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ── auth commands ──────────────────────────────────────────────────

class TestAuthCommands:

    def test_auth_status_unauthenticated(self, runner) -> None:
        result = runner.invoke(cli, ["auth", "status"])
        assert result.exit_code == 0
        assert "Not authenticated" in result.output or "psi auth login" in result.output

    def test_auth_logout(self, runner) -> None:
        result = runner.invoke(cli, ["auth", "logout"])
        assert result.exit_code == 0

    def test_auth_help(self, runner) -> None:
        result = runner.invoke(cli, ["auth", "--help"])
        assert result.exit_code == 0
        assert "login" in result.output


# ── assets commands ────────────────────────────────────────────────

class TestAssetsCommands:

    def test_assets_list_empty(self, runner) -> None:
        result = runner.invoke(cli, ["assets", "list"])
        assert result.exit_code == 0

    def test_assets_list_table(self, runner, seed_asset) -> None:
        result = runner.invoke(cli, ["assets", "list"])
        assert result.exit_code == 0
        assert "test-server" in result.output or "server" in result.output.lower()

    def test_assets_list_json(self, runner, seed_asset) -> None:
        result = runner.invoke(cli, ["assets", "list", "--format", "json"])
        assert result.exit_code == 0

    def test_assets_list_csv(self, runner, seed_asset) -> None:
        result = runner.invoke(cli, ["assets", "list", "--format", "csv"])
        assert result.exit_code == 0

    def test_assets_create(self, runner) -> None:
        result = runner.invoke(cli, [
            "assets", "create",
            "--hostname", "new-server",
            "--ip", "10.0.0.5",
            "--type", "server",
            "--criticality", "high",
        ])
        assert result.exit_code == 0
        assert "new-server" in result.output or "created" in result.output.lower()

    def test_assets_show(self, runner, seed_asset) -> None:
        result = runner.invoke(cli, ["assets", "show", str(seed_asset["id"])])
        assert result.exit_code == 0

    def test_assets_show_not_found(self, runner) -> None:
        result = runner.invoke(cli, ["assets", "show", "9999"])
        assert result.exit_code == 0  # error printed, not sys.exit

    def test_assets_create_persisted(self, runner) -> None:
        runner.invoke(cli, [
            "assets", "create",
            "--hostname", "persist-host",
            "--ip", "1.2.3.4",
            "--type", "server",
            "--criticality", "low",
        ])
        assets = db.get_all("assets")
        assert any(a["hostname"] == "persist-host" for a in assets)


# ── findings commands ──────────────────────────────────────────────

class TestFindingsCommands:

    def test_findings_list_empty(self, runner) -> None:
        result = runner.invoke(cli, ["findings", "list"])
        assert result.exit_code == 0

    def test_findings_list(self, runner, seed_finding) -> None:
        result = runner.invoke(cli, ["findings", "list"])
        assert result.exit_code == 0

    def test_findings_list_severity_filter(self, runner, seed_findings) -> None:
        result = runner.invoke(cli, ["findings", "list", "--severity", "CRITICAL"])
        assert result.exit_code == 0

    def test_findings_list_status_filter(self, runner, seed_findings) -> None:
        result = runner.invoke(cli, ["findings", "list", "--status", "OPEN"])
        assert result.exit_code == 0

    def test_findings_list_json(self, runner, seed_findings) -> None:
        result = runner.invoke(cli, ["findings", "list", "--format", "json"])
        assert result.exit_code == 0

    def test_findings_create(self, runner, seed_asset) -> None:
        result = runner.invoke(cli, [
            "findings", "create",
            "--asset-id", str(seed_asset["id"]),
            "--title", "SQLi in login form",
            "--severity", "HIGH",
        ])
        assert result.exit_code == 0
        assert "SQLi" in result.output or "created" in result.output.lower()

    def test_findings_update(self, runner, seed_finding) -> None:
        result = runner.invoke(cli, [
            "findings", "update",
            "--id", str(seed_finding["id"]),
            "--status", "FIXED",
        ])
        assert result.exit_code == 0
        assert "FIXED" in result.output or str(seed_finding["id"]) in result.output

    def test_findings_summary(self, runner, seed_findings) -> None:
        result = runner.invoke(cli, ["findings", "summary"])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output or "Summary" in result.output

    def test_findings_summary_empty(self, runner) -> None:
        result = runner.invoke(cli, ["findings", "summary"])
        assert result.exit_code == 0


# ── scans commands ─────────────────────────────────────────────────

class TestScansCommands:

    def test_scans_list_empty(self, runner) -> None:
        result = runner.invoke(cli, ["scans", "list"])
        assert result.exit_code == 0

    def test_scans_list_with_job(self, runner, seed_job) -> None:
        result = runner.invoke(cli, ["scans", "list"])
        assert result.exit_code == 0
        assert "auditor_scan" in result.output or "192.168.1.100" in result.output

    def test_scans_status(self, runner, seed_job) -> None:
        result = runner.invoke(cli, ["scans", "status", str(seed_job["id"])])
        assert result.exit_code == 0
        assert "auditor_scan" in result.output or "completed" in result.output

    def test_scans_status_not_found(self, runner) -> None:
        result = runner.invoke(cli, ["scans", "status", "9999"])
        assert result.exit_code == 0

    def test_scans_list_json(self, runner, seed_job) -> None:
        result = runner.invoke(cli, ["scans", "list", "--format", "json"])
        assert result.exit_code == 0

    def test_scans_start_nessus(self, runner, seed_asset) -> None:
        result = runner.invoke(cli, [
            "scans", "start",
            "--asset-id", str(seed_asset["id"]),
            "--scanner", "nessus",
        ])
        assert result.exit_code == 0
        assert "queued" in result.output.lower() or "job" in result.output.lower()


# ── reports commands ───────────────────────────────────────────────

class TestReportsCommands:

    def test_reports_generate_terminal(self, runner) -> None:
        result = runner.invoke(cli, ["reports", "generate"])
        assert result.exit_code == 0

    def test_reports_generate_terminal_with_findings(self, runner, seed_findings) -> None:
        result = runner.invoke(cli, ["reports", "generate", "--format", "terminal"])
        assert result.exit_code == 0
        assert "findings" in result.output.lower() or "CRITICAL" in result.output

    def test_reports_generate_json(self, runner, seed_finding) -> None:
        result = runner.invoke(cli, ["reports", "generate", "--format", "json"])
        assert result.exit_code == 0

    def test_reports_list(self, runner) -> None:
        result = runner.invoke(cli, ["reports", "list"])
        assert result.exit_code == 0


# ── auditor commands ───────────────────────────────────────────────

class TestAuditorCommands:

    def test_auditor_help(self, runner) -> None:
        result = runner.invoke(cli, ["auditor", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "results" in result.output

    def test_auditor_results_empty(self, runner) -> None:
        result = runner.invoke(cli, ["auditor", "results"])
        assert result.exit_code == 0
        assert "No auditor findings" in result.output

    def test_auditor_results_shows_only_auditor_source(self, runner, seed_asset) -> None:
        """Only findings with source='auditor' appear, not 'manual'."""
        db.insert("findings", {
            "asset_id": seed_asset["id"],
            "title": "Manual finding",
            "severity": "LOW",
            "status": "OPEN",
            "source": "manual",
        })
        db.insert("findings", {
            "asset_id": seed_asset["id"],
            "title": "Auditor finding",
            "severity": "HIGH",
            "status": "OPEN",
            "source": "auditor",
        })
        result = runner.invoke(cli, ["auditor", "results"])
        assert result.exit_code == 0
        assert "Auditor finding" in result.output
        assert "Manual finding" not in result.output

    def test_auditor_results_json_format(self, runner, seed_asset) -> None:
        db.insert("findings", {
            "asset_id": seed_asset["id"],
            "title": "SSH weak key",
            "severity": "MEDIUM",
            "status": "OPEN",
            "source": "auditor",
        })
        result = runner.invoke(cli, ["auditor", "results", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert any(f["title"] == "SSH weak key" for f in data)

    def test_auditor_scan_creates_asset_if_missing(self, runner) -> None:
        """auditor scan auto-creates asset from target IP."""
        with patch("cli.commands.scans._run_auditor_scan"):
            result = runner.invoke(cli, [
                "auditor", "scan",
                "--target", "10.10.10.99",
                "--os-type", "linux",
            ])
        assert result.exit_code == 0
        assets = db.get_all("assets", {"ip_address": "10.10.10.99"})
        assert len(assets) == 1

    def test_auditor_scan_reuses_existing_asset(self, runner, seed_asset) -> None:
        """If asset with same IP already exists, no duplicate is created."""
        with patch("cli.commands.scans._run_auditor_scan"):
            result = runner.invoke(cli, [
                "auditor", "scan",
                "--target", seed_asset["ip_address"],
            ])
        assert result.exit_code == 0
        assets = db.get_all("assets", {"ip_address": seed_asset["ip_address"]})
        assert len(assets) == 1


# ── global options ─────────────────────────────────────────────────

class TestGlobalOptions:

    def test_version_flag(self, runner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0" in result.output

    def test_help_flag(self, runner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "assets" in result.output
        assert "findings" in result.output
        assert "auditor" in result.output

    def test_assets_help(self, runner) -> None:
        result = runner.invoke(cli, ["assets", "--help"])
        assert result.exit_code == 0

    def test_findings_help(self, runner) -> None:
        result = runner.invoke(cli, ["findings", "--help"])
        assert result.exit_code == 0

    def test_scans_help(self, runner) -> None:
        result = runner.invoke(cli, ["scans", "--help"])
        assert result.exit_code == 0

    def test_reports_help(self, runner) -> None:
        result = runner.invoke(cli, ["reports", "--help"])
        assert result.exit_code == 0
