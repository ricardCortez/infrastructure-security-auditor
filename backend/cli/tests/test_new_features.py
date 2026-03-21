"""Tests for recently added/fixed features.

Covers:
- _run_auditor_scan: filename format, status filter, subprocess failure
- _get_or_create_asset_id: create vs reuse logic
- _detect_os: port-based OS detection
- PSICLIApp._expand_range: CIDR expansion
- PSICLIApp._discover_hosts: reachability probe
- PSICLIApp._launch_auditor_tui: path resolution
"""
import json
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import cli.local_db as db
from cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ── _run_auditor_scan ──────────────────────────────────────────────────


class TestRunAuditorScan:

    def _make_json(self, tmp_path: Path, filename: str, findings: list) -> Path:
        f = tmp_path / filename
        f.write_text(json.dumps({"findings": findings}), encoding="utf-8")
        return f

    def test_fail_status_imported(self, tmp_path, monkeypatch) -> None:
        """String 'FAIL' status is imported as a finding."""
        import subprocess
        import cli.commands.scans as scans_mod

        target = "localhost"
        self._make_json(tmp_path, "localhost_scan.json", [
            {"check": "smb_v1", "status": "FAIL", "severity": "CRITICAL",
             "description": "SMBv1 enabled", "recommendation": "Disable it"},
        ])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": target, "ip_address": "127.0.0.1",
                                     "asset_type": "server", "criticality": "high"})
        scans_mod._run_auditor_scan(asset["id"], target, "windows")

        findings = db.get_all("findings")
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["source"] == "auditor"

    def test_warning_status_imported(self, tmp_path, monkeypatch) -> None:
        """String 'WARNING' status is also imported as a finding."""
        import subprocess
        import cli.commands.scans as scans_mod

        target = "localhost"
        self._make_json(tmp_path, "localhost_scan.json", [
            {"check": "tls", "status": "WARNING", "severity": "MEDIUM",
             "description": "TLS 1.0 enabled", "recommendation": "Disable TLS 1.0"},
        ])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": target, "ip_address": "127.0.0.1",
                                     "asset_type": "server", "criticality": "medium"})
        scans_mod._run_auditor_scan(asset["id"], target, "linux")

        assert len(db.get_all("findings")) == 1

    def test_bool_false_status_imported(self, tmp_path, monkeypatch) -> None:
        """Boolean False (legacy format) is also accepted as a failing check."""
        import subprocess
        import cli.commands.scans as scans_mod

        target = "localhost"
        self._make_json(tmp_path, "localhost_scan.json", [
            {"check": "rdp_nla", "status": False, "severity": "HIGH",
             "description": "NLA disabled", "recommendation": "Enable NLA"},
        ])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": target, "ip_address": "127.0.0.1",
                                     "asset_type": "server", "criticality": "medium"})
        scans_mod._run_auditor_scan(asset["id"], target, "windows")

        assert len(db.get_all("findings")) == 1

    def test_pass_status_not_imported(self, tmp_path, monkeypatch) -> None:
        """'PASS' findings are NOT imported — no noise for passing checks."""
        import subprocess
        import cli.commands.scans as scans_mod

        target = "localhost"
        self._make_json(tmp_path, "localhost_scan.json", [
            {"check": "firewall", "status": "PASS", "severity": "INFO",
             "description": "Firewall enabled", "recommendation": ""},
        ])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": target, "ip_address": "127.0.0.1",
                                     "asset_type": "server", "criticality": "low"})
        scans_mod._run_auditor_scan(asset["id"], target, "linux")

        assert len(db.get_all("findings")) == 0

    def test_filename_uses_underscores_for_dots(self, tmp_path, monkeypatch) -> None:
        """Dots in IP are replaced with underscores in the output filename."""
        import subprocess
        import cli.commands.scans as scans_mod

        target = "192.168.1.10"
        # auditor.py writes 192_168_1_10_scan.json (dots → underscores)
        self._make_json(tmp_path, "192_168_1_10_scan.json", [
            {"check": "firewall", "status": "FAIL", "severity": "HIGH",
             "description": "off", "recommendation": "on"},
        ])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": target, "ip_address": target,
                                     "asset_type": "server", "criticality": "medium"})
        scans_mod._run_auditor_scan(asset["id"], target, "linux")

        assert len(db.get_all("findings")) == 1

    def test_subprocess_failure_marks_job_failed(self, tmp_path, monkeypatch) -> None:
        """Non-zero returncode marks job as failed and imports zero findings."""
        import subprocess
        import cli.commands.scans as scans_mod

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=1, stdout="", stderr="Error"))

        asset = db.insert("assets", {"hostname": "bad-host", "ip_address": "1.2.3.4",
                                     "asset_type": "server", "criticality": "low"})
        scans_mod._run_auditor_scan(asset["id"], "1.2.3.4", "linux")

        assert len(db.get_all("findings")) == 0
        failed_jobs = db.get_all("scan_jobs", {"status": "failed"})
        assert len(failed_jobs) == 1

    def test_missing_json_file_completes_zero_findings(self, tmp_path, monkeypatch) -> None:
        """If JSON output file is missing, job completes with 0 findings."""
        import subprocess
        import cli.commands.scans as scans_mod

        monkeypatch.chdir(tmp_path)  # no JSON file written here
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": "localhost", "ip_address": "127.0.0.1",
                                     "asset_type": "server", "criticality": "low"})
        scans_mod._run_auditor_scan(asset["id"], "localhost", "linux")

        assert len(db.get_all("findings")) == 0
        completed_jobs = db.get_all("scan_jobs", {"status": "completed"})
        assert len(completed_jobs) == 1

    def test_multiple_findings_all_imported(self, tmp_path, monkeypatch) -> None:
        """All FAIL findings in the JSON are imported."""
        import subprocess
        import cli.commands.scans as scans_mod

        target = "localhost"
        self._make_json(tmp_path, "localhost_scan.json", [
            {"check": "smb_v1",    "status": "FAIL",    "severity": "CRITICAL", "description": "", "recommendation": ""},
            {"check": "firewall",  "status": "FAIL",    "severity": "HIGH",     "description": "", "recommendation": ""},
            {"check": "tls",       "status": "WARNING", "severity": "MEDIUM",   "description": "", "recommendation": ""},
            {"check": "defender",  "status": "PASS",    "severity": "INFO",     "description": "", "recommendation": ""},
        ])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))

        asset = db.insert("assets", {"hostname": target, "ip_address": "127.0.0.1",
                                     "asset_type": "server", "criticality": "high"})
        scans_mod._run_auditor_scan(asset["id"], target, "windows")

        # FAIL + FAIL + WARNING = 3 imported; PASS skipped
        assert len(db.get_all("findings")) == 3


# ── _get_or_create_asset_id ────────────────────────────────────────────


class TestGetOrCreateAssetId:

    def test_creates_new_asset_when_not_found(self) -> None:
        from cli.commands.auditor import _get_or_create_asset_id
        asset_id = _get_or_create_asset_id("10.0.0.99")
        assets = db.get_all("assets", {"ip_address": "10.0.0.99"})
        assert len(assets) == 1
        assert assets[0]["id"] == asset_id

    def test_returns_existing_asset_by_ip(self) -> None:
        from cli.commands.auditor import _get_or_create_asset_id
        existing = db.insert("assets", {
            "hostname": "known-host",
            "ip_address": "10.0.0.1",
            "asset_type": "server",
            "criticality": "medium",
        })
        result_id = _get_or_create_asset_id("10.0.0.1")
        assert result_id == existing["id"]
        assert len(db.get_all("assets", {"ip_address": "10.0.0.1"})) == 1  # no duplicate

    def test_returns_existing_asset_by_hostname(self) -> None:
        from cli.commands.auditor import _get_or_create_asset_id
        existing = db.insert("assets", {
            "hostname": "my-server",
            "ip_address": None,
            "asset_type": "server",
            "criticality": "low",
        })
        result_id = _get_or_create_asset_id("my-server")
        assert result_id == existing["id"]

    def test_no_duplicate_on_repeated_calls(self) -> None:
        from cli.commands.auditor import _get_or_create_asset_id
        id1 = _get_or_create_asset_id("172.16.0.1")
        id2 = _get_or_create_asset_id("172.16.0.1")
        assert id1 == id2
        assert len(db.get_all("assets")) == 1

    def test_created_asset_has_correct_fields(self) -> None:
        from cli.commands.auditor import _get_or_create_asset_id
        _get_or_create_asset_id("192.168.99.1")
        asset = db.get_all("assets")[0]
        assert asset["asset_type"] == "server"
        assert asset["criticality"] == "medium"


# ── _detect_os ─────────────────────────────────────────────────────────


class TestDetectOs:

    def test_returns_windows_when_rdp_open(self) -> None:
        from cli.commands.scans import _detect_os

        def fake_connect(addr, timeout):
            _, port = addr
            if port == 3389:
                return MagicMock(__enter__=MagicMock(), __exit__=MagicMock())
            raise OSError("closed")

        with patch("socket.create_connection", side_effect=fake_connect):
            assert _detect_os("192.168.1.1") == "windows"

    def test_returns_windows_when_smb_open(self) -> None:
        from cli.commands.scans import _detect_os

        def fake_connect(addr, timeout):
            _, port = addr
            if port == 445:
                return MagicMock(__enter__=MagicMock(), __exit__=MagicMock())
            raise OSError("closed")

        with patch("socket.create_connection", side_effect=fake_connect):
            assert _detect_os("192.168.1.1") == "windows"

    def test_returns_linux_when_no_windows_ports(self) -> None:
        from cli.commands.scans import _detect_os

        with patch("socket.create_connection", side_effect=OSError("refused")):
            assert _detect_os("192.168.1.1") == "linux"

    def test_returns_windows_when_netbios_open(self) -> None:
        from cli.commands.scans import _detect_os

        def fake_connect(addr, timeout):
            _, port = addr
            if port == 139:
                return MagicMock(__enter__=MagicMock(), __exit__=MagicMock())
            raise OSError("closed")

        with patch("socket.create_connection", side_effect=fake_connect):
            assert _detect_os("10.0.0.1") == "windows"


# ── PSICLIApp._expand_range ────────────────────────────────────────────


class TestExpandRange:

    @pytest.fixture
    def app(self):
        from cli.main import PSICLIApp
        return PSICLIApp()

    def test_single_ip_returned_as_list(self, app) -> None:
        result = app._expand_range("192.168.1.10")
        assert result == ["192.168.1.10"]

    def test_hostname_returned_as_single_item(self, app) -> None:
        result = app._expand_range("myserver.local")
        assert result == ["myserver.local"]

    def test_cidr_24_expands_to_254_hosts(self, app) -> None:
        result = app._expand_range("192.168.1.0/24")
        assert len(result) == 254
        assert "192.168.1.1" in result
        assert "192.168.1.254" in result
        assert "192.168.1.0" not in result    # network address excluded
        assert "192.168.1.255" not in result  # broadcast excluded

    def test_cidr_30_small_range(self, app) -> None:
        result = app._expand_range("10.0.0.0/30")
        assert len(result) == 2
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_cidr_32_single_host(self, app) -> None:
        result = app._expand_range("192.168.1.5/32")
        assert len(result) == 1

    def test_large_range_capped_at_256(self, app) -> None:
        result = app._expand_range("10.0.0.0/16")
        assert len(result) == 256


# ── PSICLIApp._discover_hosts ──────────────────────────────────────────


class TestDiscoverHosts:

    @pytest.fixture
    def app(self):
        from cli.main import PSICLIApp
        return PSICLIApp()

    def test_reachable_host_included(self, app) -> None:
        def fake_connect(addr, timeout):
            host, port = addr
            if host == "192.168.1.1" and port == 22:
                conn = MagicMock()
                return conn
            raise OSError("refused")

        with patch("socket.create_connection", side_effect=fake_connect):
            result = app._discover_hosts(["192.168.1.1", "192.168.1.2"])

        assert "192.168.1.1" in result
        assert "192.168.1.2" not in result

    def test_unreachable_hosts_excluded(self, app) -> None:
        with patch("socket.create_connection", side_effect=OSError("refused")):
            result = app._discover_hosts(["10.0.0.1", "10.0.0.2"])
        assert result == []

    def test_empty_list_returns_empty(self, app) -> None:
        result = app._discover_hosts([])
        assert result == []

    def test_multiple_hosts_all_reachable(self, app) -> None:
        def always_open(addr, timeout):
            return MagicMock()

        with patch("socket.create_connection", side_effect=always_open):
            result = app._discover_hosts(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        assert len(result) == 3


# ── PSICLIApp._launch_auditor_tui path ─────────────────────────────────


class TestLaunchAuditorTuiPath:

    def test_correct_path_resolves_to_project_root(self) -> None:
        """auditor.py should be 2 parent levels above backend/cli/main.py."""
        import cli.main as main_mod
        main_path = Path(main_mod.__file__).resolve()
        # main.py: .../infrastructure-security-auditor/backend/cli/main.py
        expected = main_path.parents[2] / "auditor.py"
        assert expected.name == "auditor.py"
        assert "infrastructure-security-auditor" in str(expected.parent)

    def test_auditor_py_actually_exists(self) -> None:
        """The computed path must point to a file that exists on disk."""
        import cli.main as main_mod
        main_path = Path(main_mod.__file__).resolve()
        auditor_path = main_path.parents[2] / "auditor.py"
        assert auditor_path.exists(), f"auditor.py not found at {auditor_path}"

    def test_launch_auditor_tui_shows_error_when_missing(self, monkeypatch) -> None:
        """_launch_auditor_tui calls Formatters.error gracefully when file missing."""
        from cli.main import PSICLIApp
        app = PSICLIApp()

        with patch("cli.main.Path.exists", return_value=False), \
             patch("cli.main.Formatters.error") as mock_err, \
             patch.object(app, "_pause"):
            app._launch_auditor_tui()

        mock_err.assert_called_once()
        assert "auditor.py" in mock_err.call_args[0][0].lower() \
            or "not found" in mock_err.call_args[0][0].lower()
