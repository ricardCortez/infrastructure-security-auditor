"""Tests for LinuxScanner.

Covers basic instantiation, method existence, return-value schema,
and mocked command outputs for each of the 18 checks.

Run with::

    pytest tests/test_linux_scanner.py -v
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.scanner.linux_scanner import LinuxScanner, _error_finding, _finding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def local_scanner() -> LinuxScanner:
    """Return a LinuxScanner pointed at localhost (no SSH)."""
    return LinuxScanner("localhost")


@pytest.fixture()
def remote_scanner() -> LinuxScanner:
    """Return a LinuxScanner configured for remote SSH (no actual connection)."""
    scanner = LinuxScanner.__new__(LinuxScanner)
    scanner.target = "192.168.1.50"
    scanner.credentials = {"username": "auditor", "password": "test"}
    scanner._is_local = False
    scanner._ssh_client = MagicMock()
    return scanner


# ---------------------------------------------------------------------------
# Helper: assert FindingDict schema
# ---------------------------------------------------------------------------


def assert_finding(result: dict[str, Any]) -> None:
    """Assert that *result* matches the required FindingDict schema."""
    required_keys = {"check", "status", "severity", "description", "recommendation"}
    assert required_keys.issubset(
        result.keys()
    ), f"Missing keys: {required_keys - result.keys()}"
    assert result["status"] in (
        "PASS",
        "FAIL",
        "WARNING",
    ), f"Invalid status: {result['status']}"
    assert result["severity"] in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ), f"Invalid severity: {result['severity']}"
    assert isinstance(result["description"], str) and result["description"]
    assert isinstance(result["recommendation"], str) and result["recommendation"]


# ---------------------------------------------------------------------------
# Unit: helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_finding_returns_correct_schema(self) -> None:
        f = _finding(
            check="Test",
            status="PASS",
            severity="LOW",
            description="All good",
            recommendation="Keep it up",
        )
        assert_finding(f)
        assert f["check"] == "Test"
        assert f["raw_output"] is None

    def test_finding_with_raw_output(self) -> None:
        f = _finding("T", "FAIL", "HIGH", "Bad", "Fix it", raw_output="raw")
        assert f["raw_output"] == "raw"

    def test_error_finding_is_warning(self) -> None:
        f = _error_finding("MyCheck", "something went wrong")
        assert f["status"] == "WARNING"
        assert f["severity"] == "LOW"
        assert "MyCheck" in f["check"] or "something went wrong" in f["description"]


# ---------------------------------------------------------------------------
# Unit: instantiation
# ---------------------------------------------------------------------------


class TestLinuxScannerInit:
    def test_local_target_detected(self) -> None:
        for target in ("localhost", "127.0.0.1", "::1"):
            s = LinuxScanner(target)
            assert s._is_local is True

    def test_remote_target_detected(self) -> None:
        s = LinuxScanner("192.168.1.50")
        assert s._is_local is False

    def test_no_credentials_by_default(self) -> None:
        s = LinuxScanner("localhost")
        assert s.credentials == {}

    def test_credentials_stored(self) -> None:
        creds = {"username": "admin", "password": "secret"}
        s = LinuxScanner("localhost", credentials=creds)
        assert s.credentials == creds


# ---------------------------------------------------------------------------
# Unit: 18 check methods exist and return valid schema
# ---------------------------------------------------------------------------


EXPECTED_CHECK_METHODS = [
    "check_ssh_key_auth",
    "check_ssh_root_login",
    "check_ssh_password_auth",
    "check_firewall_enabled",
    "check_sudo_configuration",
    "check_world_writable_files",
    "check_suid_binaries",
    "check_file_permissions",
    "check_kernel_hardening",
    "check_selinux_apparmor",
    "check_package_updates",
    "check_ssl_certificates",
    "check_open_ports",
    "check_user_accounts",
    "check_failed_logins",
    "check_cron_jobs",
    "check_weak_ciphers",
    "check_log_rotation",
]


class TestCheckMethodsExist:
    @pytest.mark.parametrize("method_name", EXPECTED_CHECK_METHODS)
    def test_method_exists(self, method_name: str) -> None:
        assert hasattr(
            LinuxScanner, method_name
        ), f"LinuxScanner is missing method: {method_name}"

    def test_exactly_18_check_methods(self) -> None:
        check_methods = [
            name for name in dir(LinuxScanner) if name.startswith("check_")
        ]
        assert (
            len(check_methods) == 18
        ), f"Expected 18 check methods, found {len(check_methods)}: {check_methods}"

    def test_run_scan_method_exists(self) -> None:
        assert hasattr(LinuxScanner, "run_scan")


# ---------------------------------------------------------------------------
# Integration: mocked _run_command / _read_file for each check
# ---------------------------------------------------------------------------


def make_cmd_mock(*responses: tuple[str, str, int]):
    """Return a side_effect list for _run_command mocking.

    Each tuple is ``(stdout, stderr, return_code)``.
    Remaining calls return a default PASS-like output.
    """
    default = ("", "", 0)
    call_list = list(responses)

    def side_effect(command: str, timeout: int = 30) -> tuple[str, str, int]:
        if call_list:
            return call_list.pop(0)
        return default

    return side_effect


class TestCheckSSHKeyAuth:
    def test_pass_when_pubkeyauth_yes(self, local_scanner: LinuxScanner) -> None:
        sshd = "PubkeyAuthentication yes\nPasswordAuthentication no\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_key_auth()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_pubkeyauth_no(self, local_scanner: LinuxScanner) -> None:
        sshd = "PubkeyAuthentication no\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_key_auth()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"


class TestCheckSSHRootLogin:
    def test_pass_when_permitroot_no(self, local_scanner: LinuxScanner) -> None:
        sshd = "PermitRootLogin no\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_root_login()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_critical_when_permitroot_yes(self, local_scanner: LinuxScanner) -> None:
        sshd = "PermitRootLogin yes\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_root_login()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert result["severity"] == "CRITICAL"

    def test_fail_when_permitroot_prohibit_password(
        self, local_scanner: LinuxScanner
    ) -> None:
        sshd = "PermitRootLogin prohibit-password\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_root_login()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckSSHPasswordAuth:
    def test_pass_when_password_auth_no(self, local_scanner: LinuxScanner) -> None:
        sshd = "PasswordAuthentication no\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_password_auth()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_password_auth_yes(self, local_scanner: LinuxScanner) -> None:
        sshd = "PasswordAuthentication yes\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_password_auth()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"


class TestCheckFirewallEnabled:
    def test_pass_when_ufw_active(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner,
            "_run_command",
            return_value=("Status: active\nTo Action From", "", 0),
        ):
            result = local_scanner.check_firewall_enabled()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_no_firewall(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("Status: inactive", "", 0),  # ufw inactive
            ("Chain INPUT (policy ACCEPT)\ntarget", "", 0),  # minimal iptables
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_firewall_enabled()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckSudoConfiguration:
    def test_pass_when_no_nopasswd(self, local_scanner: LinuxScanner) -> None:
        sudoers = "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n"
        with (
            patch.object(local_scanner, "_read_file", return_value=sudoers),
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
        ):
            result = local_scanner.check_sudo_configuration()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_nopasswd_present(self, local_scanner: LinuxScanner) -> None:
        sudoers = "deployer ALL=(ALL) NOPASSWD: ALL\n"
        with (
            patch.object(local_scanner, "_read_file", return_value=sudoers),
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
        ):
            result = local_scanner.check_sudo_configuration()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckWorldWritableFiles:
    def test_pass_when_no_writable_files(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", return_value=("", "", 0)):
            result = local_scanner.check_world_writable_files()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_writable_files_found(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner,
            "_run_command",
            return_value=("/opt/app/config.py\n/srv/data/script.sh", "", 0),
        ):
            result = local_scanner.check_world_writable_files()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert "2" in result["description"]


class TestCheckSUIDbinaries:
    def test_pass_when_only_expected_suid(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner,
            "_run_command",
            return_value=("/usr/bin/sudo\n/usr/bin/passwd", "", 0),
        ):
            result = local_scanner.check_suid_binaries()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_unexpected_suid(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner,
            "_run_command",
            return_value=("/usr/bin/sudo\n/tmp/evil_suid_binary", "", 0),
        ):
            result = local_scanner.check_suid_binaries()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert "/tmp/evil_suid_binary" in result["description"]


class TestCheckFilePermissions:
    def test_pass_when_permissions_ok(self, local_scanner: LinuxScanner) -> None:
        # 644 /etc/passwd, 640 /etc/shadow, 640 /etc/gshadow, 440 /etc/sudoers
        responses = [
            ("644 /etc/passwd", "", 0),
            ("640 /etc/shadow", "", 0),
            ("640 /etc/gshadow", "", 0),
            ("440 /etc/sudoers", "", 0),
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_file_permissions()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_shadow_world_readable(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("644 /etc/passwd", "", 0),
            ("644 /etc/shadow", "", 0),  # world-readable shadow!
            ("640 /etc/gshadow", "", 0),
            ("440 /etc/sudoers", "", 0),
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_file_permissions()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckKernelHardening:
    def test_pass_when_all_hardened(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("2", "", 0),  # randomize_va_space
            ("1", "", 0),  # dmesg_restrict
            ("0", "", 0),  # ip_forward
            ("0", "", 0),  # accept_redirects
            ("2", "", 0),  # kptr_restrict
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_kernel_hardening()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_aslr_disabled(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("0", "", 0),  # randomize_va_space = 0 (disabled)
            ("1", "", 0),
            ("0", "", 0),
            ("0", "", 0),
            ("2", "", 0),
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_kernel_hardening()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckSELinuxAppArmor:
    def test_pass_when_selinux_enforcing(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", return_value=("Enforcing", "", 0)
        ):
            result = local_scanner.check_selinux_apparmor()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_selinux_permissive(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("Permissive", "", 0),  # getenforce
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_selinux_apparmor()
        assert_finding(result)
        assert result["status"] == "FAIL"

    def test_fail_when_neither_mac_active(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("", "", 1),  # getenforce fails
            ("", "", 1),  # aa-status fails
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_selinux_apparmor()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckPackageUpdates:
    def test_pass_when_no_apt_updates(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", return_value=("Listing... Done", "", 0)
        ):
            result = local_scanner.check_package_updates()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_updates_available(self, local_scanner: LinuxScanner) -> None:
        apt_output = (
            "Listing... Done\n"
            "curl/focal-updates 7.68.0-1ubuntu2.20 amd64 [upgradable from: 7.68.0-1ubuntu2.18]\n"
            "openssl/focal-updates 1.1.1f-1ubuntu2.20 amd64 [upgradable from: 1.1.1f-1ubuntu2.19]\n"
        )
        with patch.object(
            local_scanner, "_run_command", return_value=(apt_output, "", 0)
        ):
            result = local_scanner.check_package_updates()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckSSLCertificates:
    def test_warning_when_no_certs_found(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", return_value=("", "", 1)):
            result = local_scanner.check_ssl_certificates()
        assert_finding(result)
        assert result["status"] == "WARNING"

    def test_pass_when_all_certs_valid(self, local_scanner: LinuxScanner) -> None:
        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "find" in command:
                return ("/etc/ssl/certs/server.crt", "", 0)
            if "enddate" in command:
                return ("notAfter=Dec 31 00:00:00 2099 GMT", "", 0)
            if "checkend 2592000" in command:
                return ("Certificate will not expire", "", 0)
            return ("", "", 0)

        with patch.object(local_scanner, "_run_command", side_effect=cmd_side):
            result = local_scanner.check_ssl_certificates()
        assert_finding(result)
        assert result["status"] == "PASS"


class TestCheckOpenPorts:
    def test_pass_when_only_expected_ports(self, local_scanner: LinuxScanner) -> None:
        ss_output = (
            "Netid State  Recv-Q Send-Q Local Address:Port\n"
            "tcp   LISTEN 0      128    0.0.0.0:22   0.0.0.0:*\n"
            "tcp   LISTEN 0      128    0.0.0.0:443  0.0.0.0:*\n"
        )
        with patch.object(
            local_scanner, "_run_command", return_value=(ss_output, "", 0)
        ):
            result = local_scanner.check_open_ports()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_warning_when_unexpected_ports(self, local_scanner: LinuxScanner) -> None:
        ss_output = (
            "Netid State  Recv-Q Send-Q Local Address:Port\n"
            "tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*\n"
            'tcp   LISTEN 0      128    0.0.0.0:31337 0.0.0.0:* users:(("nc",pid=1234))\n'
        )
        with patch.object(
            local_scanner, "_run_command", return_value=(ss_output, "", 0)
        ):
            result = local_scanner.check_open_ports()
        assert_finding(result)
        assert result["status"] == "WARNING"


class TestCheckUserAccounts:
    def test_pass_with_normal_accounts(self, local_scanner: LinuxScanner) -> None:
        passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        )
        with (patch.object(local_scanner, "_read_file", return_value=passwd),):
            result = local_scanner.check_user_accounts()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_hidden_root_uid(self, local_scanner: LinuxScanner) -> None:
        passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "backdoor:x:0:0::/root:/bin/bash\n"  # UID 0, not root!
        )
        with patch.object(local_scanner, "_read_file", return_value=passwd):
            result = local_scanner.check_user_accounts()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert "backdoor" in result["description"]


class TestCheckFailedLogins:
    def test_pass_when_few_failures(self, local_scanner: LinuxScanner) -> None:
        lastb_output = "ubuntu   ssh:notty  192.168.1.1  Fri Mar 20 10:00:00\n" * 5
        with patch.object(
            local_scanner, "_run_command", return_value=(lastb_output, "", 0)
        ):
            result = local_scanner.check_failed_logins()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_many_failures(self, local_scanner: LinuxScanner) -> None:
        lastb_output = "ubuntu   ssh:notty  192.168.1.1  Fri Mar 20 10:00:00\n" * 60
        with patch.object(
            local_scanner, "_run_command", return_value=(lastb_output, "", 0)
        ):
            result = local_scanner.check_failed_logins()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckCronJobs:
    def test_pass_when_no_writable_scripts(self, local_scanner: LinuxScanner) -> None:
        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "crontab" in command:
                return ("0 2 * * * /usr/bin/backup.sh", "", 0)
            if "ls /etc/cron" in command:
                return ("", "", 0)
            if "stat" in command:
                return ("755 /usr/bin/backup.sh", "", 0)
            return ("", "", 0)

        with (
            patch.object(local_scanner, "_run_command", side_effect=cmd_side),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            result = local_scanner.check_cron_jobs()
        assert_finding(result)

    def test_fail_when_world_writable_cron_script(
        self, local_scanner: LinuxScanner
    ) -> None:
        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "crontab" in command:
                return ("0 2 * * * /tmp/backup.sh", "", 0)
            if "ls /etc/cron" in command:
                return ("", "", 0)
            if "stat" in command and "/tmp/backup.sh" in command:
                return ("777 /tmp/backup.sh", "", 0)  # world-writable!
            return ("", "", 0)

        with (
            patch.object(local_scanner, "_run_command", side_effect=cmd_side),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            result = local_scanner.check_cron_jobs()
        assert_finding(result)
        assert result["status"] == "FAIL"


class TestCheckWeakCiphers:
    def test_pass_when_no_weak_ciphers(self, local_scanner: LinuxScanner) -> None:
        sshd = (
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
            "MACs hmac-sha2-512-etm@openssh.com\n"
        )
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_weak_ciphers()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_weak_cipher_configured(
        self, local_scanner: LinuxScanner
    ) -> None:
        sshd = "Ciphers 3des-cbc,aes256-ctr\nMACs hmac-md5,hmac-sha2-256\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_weak_ciphers()
        assert_finding(result)
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"


class TestCheckLogRotation:
    def test_pass_when_logrotate_configured(self, local_scanner: LinuxScanner) -> None:
        logrotate_conf = "weekly\nrotate 4\ncompress\n"

        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "ls /etc/logrotate.d" in command:
                return ("syslog\nnginx\nssh", "", 0)
            if "systemctl is-active logrotate" in command:
                return ("active", "", 0)
            return ("", "", 0)

        with (
            patch.object(local_scanner, "_read_file", return_value=logrotate_conf),
            patch.object(local_scanner, "_run_command", side_effect=cmd_side),
        ):
            result = local_scanner.check_log_rotation()
        assert_finding(result)
        assert result["status"] == "PASS"

    def test_fail_when_no_logrotate(self, local_scanner: LinuxScanner) -> None:
        with (
            patch.object(local_scanner, "_read_file", return_value=""),
            patch.object(local_scanner, "_run_command", return_value=("", "", 1)),
        ):
            result = local_scanner.check_log_rotation()
        assert_finding(result)
        assert result["status"] == "FAIL"


# ---------------------------------------------------------------------------
# Integration: run_scan schema
# ---------------------------------------------------------------------------


class TestRunScan:
    def test_run_scan_returns_correct_schema(self, local_scanner: LinuxScanner) -> None:
        """run_scan() must return the documented result dict structure."""
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()

        required_keys = {
            "server",
            "os",
            "timestamp",
            "scan_duration_seconds",
            "findings",
            "total_checks",
            "summary",
        }
        assert required_keys.issubset(results.keys())
        assert results["os"] == "linux"
        assert results["server"] == "localhost"
        assert isinstance(results["findings"], list)
        assert results["total_checks"] == len(results["findings"])
        assert set(results["summary"].keys()) == {"PASS", "FAIL", "WARNING"}

    def test_run_scan_returns_18_findings(self, local_scanner: LinuxScanner) -> None:
        """All 18 checks should produce exactly 18 findings."""
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()

        assert (
            results["total_checks"] == 18
        ), f"Expected 18 findings, got {results['total_checks']}"

    def test_run_scan_all_findings_valid_schema(
        self, local_scanner: LinuxScanner
    ) -> None:
        """Every individual finding must conform to FindingDict schema."""
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()

        for finding in results["findings"]:
            assert_finding(finding)


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------


class TestCheckSSHKeyAuthEdgeCases:
    def test_commented_pubkey_no_is_ignored(self, local_scanner: LinuxScanner) -> None:
        """Commented-out 'no' lines must not cause a FAIL."""
        sshd = "# PubkeyAuthentication no\nPubkeyAuthentication yes\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_key_auth()
        assert result["status"] == "PASS"

    def test_no_setting_defaults_to_pass(self, local_scanner: LinuxScanner) -> None:
        """When PubkeyAuthentication is absent, modern OpenSSH defaults to yes."""
        sshd = "# empty config\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_key_auth()
        assert result["status"] == "PASS"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_read_file", side_effect=RuntimeError("disk error")
        ):
            result = local_scanner.check_ssh_key_auth()
        assert result["status"] == "WARNING"
        assert_finding(result)


class TestCheckSSHRootLoginEdgeCases:
    def test_empty_config_defaults_to_risky(self, local_scanner: LinuxScanner) -> None:
        """When PermitRootLogin is absent, default permit_root='yes' → FAIL."""
        sshd = "# no settings here\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_root_login()
        assert result["status"] == "FAIL"

    def test_forced_commands_only_is_fail(self, local_scanner: LinuxScanner) -> None:
        sshd = "PermitRootLogin forced-commands-only\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_root_login()
        assert result["status"] == "FAIL"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_read_file", side_effect=OSError("no file")):
            result = local_scanner.check_ssh_root_login()
        assert result["status"] == "WARNING"
        assert_finding(result)


class TestCheckSSHPasswordAuthEdgeCases:
    def test_no_setting_defaults_to_fail(self, local_scanner: LinuxScanner) -> None:
        """When PasswordAuthentication is absent, default is 'yes' → FAIL."""
        sshd = "# no explicit setting\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_ssh_password_auth()
        assert result["status"] == "FAIL"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_read_file", side_effect=RuntimeError("err")):
            result = local_scanner.check_ssh_password_auth()
        assert result["status"] == "WARNING"


class TestCheckFirewallEnabledEdgeCases:
    def test_pass_when_iptables_has_many_rules(
        self, local_scanner: LinuxScanner
    ) -> None:
        """iptables with >10 lines → PASS (rules present)."""
        iptables_output = "\n".join(
            ["Chain INPUT (policy DROP)"]
            + [f"ACCEPT tcp -- 0.0.0.0/0 dpt:{p}" for p in range(15)]
        )
        responses = [
            ("Status: inactive", "", 0),  # ufw inactive
            (iptables_output, "", 0),  # iptables has rules
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_firewall_enabled()
        assert result["status"] == "PASS"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", side_effect=OSError("no ufw")):
            result = local_scanner.check_firewall_enabled()
        assert result["status"] == "WARNING"


class TestCheckSudoConfigurationEdgeCases:
    def test_sudoers_d_nopasswd_detected(self, local_scanner: LinuxScanner) -> None:
        """NOPASSWD in a /etc/sudoers.d/ file must be flagged."""

        def read_side(path: str) -> str:
            if path == "/etc/sudoers":
                return "root ALL=(ALL:ALL) ALL\n"
            if "90-deploy" in path:
                return "deploy ALL=(ALL) NOPASSWD: /usr/bin/rsync\n"
            return ""

        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "ls /etc/sudoers.d" in command:
                return ("90-deploy", "", 0)
            return ("", "", 0)

        with (
            patch.object(local_scanner, "_read_file", side_effect=read_side),
            patch.object(local_scanner, "_run_command", side_effect=cmd_side),
        ):
            result = local_scanner.check_sudo_configuration()
        assert result["status"] == "FAIL"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_read_file", side_effect=PermissionError("denied")
        ):
            result = local_scanner.check_sudo_configuration()
        assert result["status"] == "WARNING"


class TestCheckWorldWritableFilesEdgeCases:
    def test_single_file_found(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", return_value=("/opt/app/insecure.py", "", 0)
        ):
            result = local_scanner.check_world_writable_files()
        assert result["status"] == "FAIL"
        assert "1" in result["description"]

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=TimeoutError("timeout")
        ):
            result = local_scanner.check_world_writable_files()
        assert result["status"] == "WARNING"


class TestCheckSUIDBinariesEdgeCases:
    def test_empty_output_is_pass(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", return_value=("", "", 0)):
            result = local_scanner.check_suid_binaries()
        assert result["status"] == "PASS"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=RuntimeError("err")
        ):
            result = local_scanner.check_suid_binaries()
        assert result["status"] == "WARNING"


class TestCheckFilePermissionsEdgeCases:
    def test_fail_when_passwd_world_writable(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("646 /etc/passwd", "", 0),  # world-writable passwd!
            ("640 /etc/shadow", "", 0),
            ("640 /etc/gshadow", "", 0),
            ("440 /etc/sudoers", "", 0),
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_file_permissions()
        assert result["status"] == "FAIL"
        assert "/etc/passwd" in result["description"]

    def test_stat_failure_is_skipped(self, local_scanner: LinuxScanner) -> None:
        """Files that can't be stat'd should not raise an exception."""
        with patch.object(local_scanner, "_run_command", return_value=("", "", 1)):
            result = local_scanner.check_file_permissions()
        assert_finding(result)

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", side_effect=OSError("perm")):
            result = local_scanner.check_file_permissions()
        assert result["status"] == "WARNING"


class TestCheckKernelHardeningEdgeCases:
    def test_fail_when_kptr_restrict_zero(self, local_scanner: LinuxScanner) -> None:
        responses = [
            ("2", "", 0),  # randomize_va_space OK
            ("1", "", 0),  # dmesg_restrict OK
            ("0", "", 0),  # ip_forward OK
            ("0", "", 0),  # accept_redirects OK
            ("0", "", 0),  # kptr_restrict = 0 → issue
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_kernel_hardening()
        assert result["status"] == "FAIL"
        assert "kptr_restrict" in result["description"]

    def test_fail_when_param_not_readable(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", return_value=("", "", 1)):
            result = local_scanner.check_kernel_hardening()
        assert result["status"] == "FAIL"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=RuntimeError("err")
        ):
            result = local_scanner.check_kernel_hardening()
        assert result["status"] == "WARNING"


class TestCheckSELinuxAppArmorEdgeCases:
    def test_pass_when_apparmor_enabled(self, local_scanner: LinuxScanner) -> None:
        """When getenforce fails but aa-status succeeds, should be PASS."""
        responses = [
            ("", "", 1),  # getenforce not found
            ("", "", 0),  # aa-status --enabled succeeds
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_selinux_apparmor()
        assert result["status"] == "PASS"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=OSError("no tools")
        ):
            result = local_scanner.check_selinux_apparmor()
        assert result["status"] == "WARNING"


class TestCheckPackageUpdatesEdgeCases:
    def test_pass_when_yum_up_to_date(self, local_scanner: LinuxScanner) -> None:
        """yum check-update rc=0 → all up to date."""
        responses = [
            ("", "", 1),  # apt not found
            ("", "", 0),  # yum: no updates
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_package_updates()
        assert result["status"] == "PASS"

    def test_fail_when_yum_updates_available(self, local_scanner: LinuxScanner) -> None:
        """yum check-update rc=100 → updates available."""
        yum_out = (
            "openssl.x86_64  1.1.1k-5.el8  baseos\ncurl.x86_64  7.61.1-25.el8  baseos\n"
        )
        responses = [
            ("", "", 1),  # apt not found
            (yum_out, "", 100),  # yum: updates available
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_package_updates()
        assert result["status"] == "FAIL"

    def test_warning_when_neither_apt_nor_yum(
        self, local_scanner: LinuxScanner
    ) -> None:
        with patch.object(local_scanner, "_run_command", return_value=("", "", 127)):
            result = local_scanner.check_package_updates()
        assert result["status"] == "WARNING"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=RuntimeError("err")
        ):
            result = local_scanner.check_package_updates()
        assert result["status"] == "WARNING"


class TestCheckSSLCertificatesEdgeCases:
    def test_fail_when_certificate_expired(self, local_scanner: LinuxScanner) -> None:
        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "find" in command:
                return ("/etc/ssl/certs/old.crt", "", 0)
            if "enddate" in command:
                return ("notAfter=Jan  1 00:00:00 2020 GMT", "", 0)
            if "checkend 2592000" in command:
                return ("", "", 1)  # expiring within 30 days
            if "checkend 0" in command:
                return ("", "", 1)  # already expired
            return ("", "", 0)

        with patch.object(local_scanner, "_run_command", side_effect=cmd_side):
            result = local_scanner.check_ssl_certificates()
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"

    def test_warning_when_cert_expiring_soon(self, local_scanner: LinuxScanner) -> None:
        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "find" in command:
                return ("/etc/ssl/certs/soon.crt", "", 0)
            if "enddate" in command:
                return ("notAfter=Apr 10 00:00:00 2026 GMT", "", 0)
            if "checkend 2592000" in command:
                return ("", "", 1)  # will expire within 30 days
            if "checkend 0" in command:
                return ("Certificate will not expire", "", 0)  # not yet expired
            return ("", "", 0)

        with patch.object(local_scanner, "_run_command", side_effect=cmd_side):
            result = local_scanner.check_ssl_certificates()
        assert result["status"] == "WARNING"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=RuntimeError("err")
        ):
            result = local_scanner.check_ssl_certificates()
        assert result["status"] == "WARNING"


class TestCheckOpenPortsEdgeCases:
    def test_pass_with_netstat_fallback(self, local_scanner: LinuxScanner) -> None:
        """When ss fails, netstat fallback with only expected ports → PASS."""
        netstat_output = (
            "Active Internet connections (only servers)\n"
            "tcp  0  0 0.0.0.0:22   0.0.0.0:*  LISTEN\n"
        )
        responses = [
            ("", "", 1),  # ss fails
            (netstat_output, "", 0),  # netstat succeeds
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_open_ports()
        assert_finding(result)

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_run_command", side_effect=OSError("no ss")):
            result = local_scanner.check_open_ports()
        assert result["status"] == "WARNING"


class TestCheckUserAccountsEdgeCases:
    def test_fail_when_system_account_has_interactive_shell(
        self, local_scanner: LinuxScanner
    ) -> None:
        passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "mysql:x:999:999:MySQL:/var/lib/mysql:/bin/bash\n"  # UID 999 with bash shell
        )
        with patch.object(local_scanner, "_read_file", return_value=passwd):
            result = local_scanner.check_user_accounts()
        assert result["status"] == "FAIL"
        assert "mysql" in result["description"]

    def test_fail_when_empty_password_in_shadow(
        self, local_scanner: LinuxScanner
    ) -> None:
        passwd = "ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n"
        shadow = "ubuntu::19500:0:99999:7:::\n"  # empty password field

        def read_side(path: str) -> str:
            if "passwd" in path:
                return passwd
            if "shadow" in path:
                return shadow
            return ""

        with patch.object(local_scanner, "_read_file", side_effect=read_side):
            result = local_scanner.check_user_accounts()
        assert result["status"] == "FAIL"
        assert "ubuntu" in result["description"]

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_read_file", side_effect=PermissionError("denied")
        ):
            result = local_scanner.check_user_accounts()
        assert result["status"] == "WARNING"


class TestCheckFailedLoginsEdgeCases:
    def test_fail_at_threshold_50(self, local_scanner: LinuxScanner) -> None:
        """Exactly 50 failures should trigger FAIL."""
        lastb_output = "ubuntu ssh:notty 192.168.1.1 Fri Mar 20 10:00:00\n" * 50
        with patch.object(
            local_scanner, "_run_command", return_value=(lastb_output, "", 0)
        ):
            result = local_scanner.check_failed_logins()
        assert result["status"] == "FAIL"

    def test_fail_via_journalctl_path(self, local_scanner: LinuxScanner) -> None:
        """When lastb fails but journalctl shows 50+ failures → FAIL."""
        responses = [
            ("", "", 1),  # lastb fails
            ("75", "", 0),  # journalctl count
        ]
        with patch.object(local_scanner, "_run_command", side_effect=responses):
            result = local_scanner.check_failed_logins()
        assert result["status"] == "FAIL"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=RuntimeError("err")
        ):
            result = local_scanner.check_failed_logins()
        assert result["status"] == "WARNING"


class TestCheckCronJobsEdgeCases:
    def test_pass_with_empty_crontab(self, local_scanner: LinuxScanner) -> None:
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 1)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            result = local_scanner.check_cron_jobs()
        assert result["status"] == "PASS"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=RuntimeError("err")
        ):
            result = local_scanner.check_cron_jobs()
        assert result["status"] == "WARNING"


class TestCheckWeakCiphersEdgeCases:
    def test_pass_when_no_explicit_ciphers(self, local_scanner: LinuxScanner) -> None:
        """Config with no Ciphers/MACs directives should be PASS (use defaults)."""
        sshd = "Port 22\nMaxAuthTries 3\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_weak_ciphers()
        assert_finding(result)

    def test_fail_when_md5_mac_configured(self, local_scanner: LinuxScanner) -> None:
        sshd = "Ciphers aes256-ctr\nMACs hmac-md5\n"
        with patch.object(local_scanner, "_read_file", return_value=sshd):
            result = local_scanner.check_weak_ciphers()
        assert result["status"] == "FAIL"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_read_file", side_effect=OSError("err")):
            result = local_scanner.check_weak_ciphers()
        assert result["status"] == "WARNING"


class TestCheckLogRotationEdgeCases:
    def test_pass_when_logrotate_timer_active(
        self, local_scanner: LinuxScanner
    ) -> None:
        logrotate_conf = "daily\nrotate 7\ncompress\n"

        def cmd_side(command: str, timeout: int = 30) -> tuple[str, str, int]:
            if "ls /etc/logrotate.d" in command:
                return ("nginx\nsyslog", "", 0)
            if "systemctl is-active" in command:
                return ("active", "", 0)
            return ("", "", 0)

        with (
            patch.object(local_scanner, "_read_file", return_value=logrotate_conf),
            patch.object(local_scanner, "_run_command", side_effect=cmd_side),
        ):
            result = local_scanner.check_log_rotation()
        assert result["status"] == "PASS"

    def test_exception_returns_warning(self, local_scanner: LinuxScanner) -> None:
        with patch.object(local_scanner, "_read_file", side_effect=RuntimeError("err")):
            result = local_scanner.check_log_rotation()
        assert result["status"] == "WARNING"


# ---------------------------------------------------------------------------
# Additional run_scan tests
# ---------------------------------------------------------------------------


class TestRunScanAdditional:
    def test_run_scan_duration_is_positive(self, local_scanner: LinuxScanner) -> None:
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()
        assert results["scan_duration_seconds"] >= 0

    def test_run_scan_summary_counts_match_findings(
        self, local_scanner: LinuxScanner
    ) -> None:
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()
        summary = results["summary"]
        findings = results["findings"]
        assert summary["PASS"] == sum(1 for f in findings if f["status"] == "PASS")
        assert summary["FAIL"] == sum(1 for f in findings if f["status"] == "FAIL")
        assert summary["WARNING"] == sum(
            1 for f in findings if f["status"] == "WARNING"
        )

    def test_run_scan_timestamp_is_iso_format(
        self, local_scanner: LinuxScanner
    ) -> None:
        from datetime import datetime

        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()
        # Should parse without raising
        datetime.fromisoformat(results["timestamp"].replace("Z", "+00:00"))

    def test_run_scan_server_matches_target(self, local_scanner: LinuxScanner) -> None:
        with (
            patch.object(local_scanner, "_run_command", return_value=("", "", 0)),
            patch.object(local_scanner, "_read_file", return_value=""),
        ):
            results = local_scanner.run_scan()
        assert results["server"] == local_scanner.target


# ---------------------------------------------------------------------------
# _read_file and _run_command internal tests
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_read_file_returns_empty_on_nonzero_rc(
        self, local_scanner: LinuxScanner
    ) -> None:
        with patch.object(local_scanner, "_run_command", return_value=("", "", 1)):
            result = local_scanner._read_file("/nonexistent/path")
        assert result == ""

    def test_read_file_returns_empty_on_exception(
        self, local_scanner: LinuxScanner
    ) -> None:
        with patch.object(
            local_scanner, "_run_command", side_effect=OSError("permission denied")
        ):
            result = local_scanner._read_file("/etc/shadow")
        assert result == ""

    def test_read_file_returns_content_on_success(
        self, local_scanner: LinuxScanner
    ) -> None:
        with patch.object(
            local_scanner, "_run_command", return_value=("file content", "", 0)
        ):
            result = local_scanner._read_file("/etc/hostname")
        assert result == "file content"

    def test_remote_run_command_raises_without_ssh(
        self, remote_scanner: LinuxScanner
    ) -> None:
        """_run_command on remote scanner with no SSH client raises RuntimeError."""
        remote_scanner._ssh_client = None
        remote_scanner._is_local = False
        with pytest.raises(RuntimeError, match="SSH session not initialised"):
            remote_scanner._run_command("echo test")
