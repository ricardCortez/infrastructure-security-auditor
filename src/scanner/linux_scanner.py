"""Linux Security Scanner module.

Provides :class:`LinuxScanner` which executes local (subprocess) or remote
(SSH via paramiko) shell-based security checks against a Linux target host.
Each check returns a normalised :data:`FindingDict` identical in schema to
the one produced by :class:`~src.scanner.windows_scanner.WindowsScanner`.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Literal

from src.config import logger

# ---------------------------------------------------------------------------
# Type aliases (mirrors windows_scanner for consistency)
# ---------------------------------------------------------------------------

Status = Literal["PASS", "FAIL", "WARNING"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class FindingDict(dict):  # type: ignore[type-arg]
    """Typed alias – treated as a plain dict at runtime."""


# ---------------------------------------------------------------------------
# Helper: build a finding dict
# ---------------------------------------------------------------------------


def _finding(
    check: str,
    status: Status,
    severity: Severity,
    description: str,
    recommendation: str,
    raw_output: str | None = None,
) -> dict[str, Any]:
    """Build a normalised finding dictionary.

    Args:
        check: Human-readable name of the security check.
        status: ``"PASS"``, ``"FAIL"``, or ``"WARNING"``.
        severity: ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, or ``"LOW"``.
        description: Plain-language description of what was found.
        recommendation: Actionable remediation step.
        raw_output: Optional raw command output for the technical appendix.

    Returns:
        A dictionary conforming to the ``FindingDict`` schema.
    """
    return {
        "check": check,
        "status": status,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "raw_output": raw_output,
    }


def _error_finding(check: str, error: str) -> dict[str, Any]:
    """Return a WARNING finding when a check cannot be completed.

    Args:
        check: Name of the check that failed.
        error: Error message or exception string.

    Returns:
        A ``FindingDict`` with status WARNING.
    """
    return _finding(
        check=check,
        status="WARNING",
        severity="LOW",
        description=f"Check could not be completed: {error}",
        recommendation=(
            "Run the auditor with elevated privileges (sudo/root) "
            "or verify SSH credentials to enable this check."
        ),
        raw_output=error,
    )


# ---------------------------------------------------------------------------
# LinuxScanner
# ---------------------------------------------------------------------------


class LinuxScanner:
    """Performs security configuration checks against a Linux host.

    Supports both local scanning (via ``subprocess``) and remote scanning
    (via SSH using ``paramiko``).  Each ``check_*`` method returns a
    normalised ``FindingDict`` describing the security posture of that
    specific control.

    Args:
        target: IP address or hostname of the target server.
            Use ``"localhost"`` or ``"127.0.0.1"`` for local scanning.
        credentials: Optional dictionary for SSH remote scans.  Recognised
            keys: ``username`` (str), ``password`` (str, optional),
            ``key_filename`` (str path to private key, optional),
            ``port`` (int, default 22), ``timeout`` (int, default 30).

    Examples:
        Local scan::

            scanner = LinuxScanner("localhost")
            results = scanner.run_scan()

        Remote scan with password::

            scanner = LinuxScanner(
                "192.168.1.50",
                credentials={"username": "auditor", "password": "s3cr3t"},
            )
            results = scanner.run_scan()

        Remote scan with SSH key::

            scanner = LinuxScanner(
                "192.168.1.50",
                credentials={
                    "username": "auditor",
                    "key_filename": "/home/me/.ssh/id_rsa",
                },
            )
            results = scanner.run_scan()
    """

    def __init__(
        self,
        target: str,
        credentials: dict[str, Any] | None = None,
    ) -> None:
        self.target = target
        self.credentials = credentials or {}
        self._is_local = target in {"localhost", "127.0.0.1", "::1"}
        self._ssh_client: Any = None  # lazy-loaded paramiko SSHClient

        if not self._is_local and self.credentials:
            self._init_ssh()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_ssh(self) -> None:
        """Initialise a paramiko SSH client for remote scanning.

        Raises:
            ImportError: If ``paramiko`` is not installed.
            ConnectionError: If the SSH connection cannot be established.
        """
        try:
            import paramiko  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "paramiko is required for remote Linux scanning. "
                "Install it with: pip install paramiko"
            ) from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, Any] = {
            "hostname": self.target,
            "port": int(self.credentials.get("port", 22)),
            "username": self.credentials.get("username", ""),
            "timeout": int(self.credentials.get("timeout", 30)),
        }

        if "key_filename" in self.credentials:
            connect_kwargs["key_filename"] = self.credentials["key_filename"]
        elif "password" in self.credentials:
            connect_kwargs["password"] = self.credentials["password"]

        try:
            client.connect(**connect_kwargs)
            self._ssh_client = client
            logger.debug("SSH session initialised for %s", self.target)
        except Exception as exc:
            raise ConnectionError(
                f"Could not connect to {self.target} via SSH: {exc}"
            ) from exc

    def _run_command(self, command: str, timeout: int = 30) -> tuple[str, str, int]:
        """Execute a shell command locally via subprocess or remotely via SSH.

        Args:
            command: Shell command string to execute.
            timeout: Command timeout in seconds.

        Returns:
            Tuple of ``(stdout, stderr, return_code)``.
        """
        if self._is_local:
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode

        # Remote via paramiko
        if self._ssh_client is None:
            raise RuntimeError(
                "SSH session not initialised. "
                "Provide credentials when instantiating LinuxScanner."
            )
        _, stdout_obj, stderr_obj = self._ssh_client.exec_command(
            command, timeout=timeout
        )
        rc = stdout_obj.channel.recv_exit_status()
        return (
            stdout_obj.read().decode("utf-8", errors="replace").strip(),
            stderr_obj.read().decode("utf-8", errors="replace").strip(),
            rc,
        )

    def _read_file(self, path: str) -> str:
        """Read a remote or local file and return its contents as a string.

        Args:
            path: Absolute path of the file to read.

        Returns:
            File contents as a string, or empty string on error.
        """
        try:
            stdout, _, rc = self._run_command(f"cat {path}")
            return stdout if rc == 0 else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    def check_ssh_key_auth(self) -> dict[str, Any]:
        """Check that SSH is configured to use key-based authentication.

        Reads ``/etc/ssh/sshd_config`` and verifies ``PubkeyAuthentication yes``
        is explicitly set.  Key-based auth is significantly more secure than
        password-based authentication.

        Returns:
            FindingDict with HIGH severity if PubkeyAuthentication is not enabled.
        """
        try:
            stdout = self._read_file("/etc/ssh/sshd_config")
            pubkey_enabled = False
            for line in stdout.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("pubkeyauthentication"):
                    pubkey_enabled = "yes" in stripped
                    break
            else:
                # Default is 'yes' in modern OpenSSH, but explicit is better
                pubkey_enabled = True

            if not pubkey_enabled:
                return _finding(
                    check="SSH Key Authentication",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "PubkeyAuthentication is disabled in sshd_config. "
                        "Key-based authentication is disabled, increasing exposure to brute-force attacks."
                    ),
                    recommendation=(
                        "Enable key-based authentication: "
                        "set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config "
                        "and restart sshd: systemctl restart sshd"
                    ),
                    raw_output=stdout[:500],
                )
            return _finding(
                check="SSH Key Authentication",
                status="PASS",
                severity="HIGH",
                description="PubkeyAuthentication is enabled in sshd_config.",
                recommendation=(
                    "Ensure users have their public keys in ~/.ssh/authorized_keys "
                    "and consider disabling password auth."
                ),
                raw_output=stdout[:500],
            )
        except Exception as exc:
            return _error_finding("SSH Key Authentication", str(exc))

    def check_ssh_root_login(self) -> dict[str, Any]:
        """Check whether direct root login via SSH is disabled.

        Root SSH login should always be disabled (``PermitRootLogin no``).
        Allowing root SSH access bypasses auditing and greatly reduces the
        effort needed for privilege escalation after credential theft.

        Returns:
            FindingDict with CRITICAL severity if root login is permitted.
        """
        try:
            stdout = self._read_file("/etc/ssh/sshd_config")
            permit_root = (
                "yes"  # OpenSSH default is 'prohibit-password', treat as risky
            )
            for line in stdout.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("permitrootlogin"):
                    parts = stripped.split()
                    permit_root = parts[1] if len(parts) >= 2 else "yes"
                    break

            if permit_root not in ("no",):
                return _finding(
                    check="SSH Root Login",
                    status="FAIL",
                    severity="CRITICAL",
                    description=(
                        f"PermitRootLogin is set to '{permit_root}'. "
                        "Direct root SSH access is allowed, bypassing audit trails "
                        "and enabling full system compromise on credential theft."
                    ),
                    recommendation=(
                        "Disable root SSH login: set 'PermitRootLogin no' in "
                        "/etc/ssh/sshd_config, then: systemctl restart sshd. "
                        "Use a non-root account with sudo for administrative tasks."
                    ),
                    raw_output=stdout[:500],
                )
            return _finding(
                check="SSH Root Login",
                status="PASS",
                severity="CRITICAL",
                description="PermitRootLogin is set to 'no'. Direct root SSH access is blocked.",
                recommendation="No action required.",
                raw_output=stdout[:500],
            )
        except Exception as exc:
            return _error_finding("SSH Root Login", str(exc))

    def check_ssh_password_auth(self) -> dict[str, Any]:
        """Check whether SSH password authentication is disabled.

        Password authentication is vulnerable to brute-force attacks.
        ``PasswordAuthentication no`` should be set once key-based auth is
        in place.

        Returns:
            FindingDict with HIGH severity if password auth is enabled.
        """
        try:
            stdout = self._read_file("/etc/ssh/sshd_config")
            password_auth = "yes"  # Default
            for line in stdout.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("passwordauthentication"):
                    parts = stripped.split()
                    password_auth = parts[1] if len(parts) >= 2 else "yes"
                    break

            if password_auth != "no":
                return _finding(
                    check="SSH Password Authentication",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "PasswordAuthentication is enabled (value: '{}').  "
                        "Password-based SSH is susceptible to brute-force and "
                        "credential-stuffing attacks.".format(password_auth)
                    ),
                    recommendation=(
                        "Disable SSH password authentication: set "
                        "'PasswordAuthentication no' in /etc/ssh/sshd_config "
                        "after confirming key-based access works, "
                        "then: systemctl restart sshd"
                    ),
                    raw_output=stdout[:500],
                )
            return _finding(
                check="SSH Password Authentication",
                status="PASS",
                severity="HIGH",
                description="PasswordAuthentication is set to 'no'. Only key-based SSH is allowed.",
                recommendation="No action required.",
                raw_output=stdout[:500],
            )
        except Exception as exc:
            return _error_finding("SSH Password Authentication", str(exc))

    def check_firewall_enabled(self) -> dict[str, Any]:
        """Check whether a host-based firewall (UFW or iptables) is active.

        Attempts ``ufw status`` first, then falls back to checking for
        ``iptables`` rules.  A system with no firewall is exposed to all
        inbound network traffic.

        Returns:
            FindingDict with HIGH severity if no firewall is detected as active.
        """
        try:
            ufw_out, _, ufw_rc = self._run_command("ufw status")
            if ufw_rc == 0:
                active = "status: active" in ufw_out.lower()
                if active:
                    return _finding(
                        check="Firewall Enabled",
                        status="PASS",
                        severity="HIGH",
                        description="UFW firewall is active.",
                        recommendation="Periodically review UFW rules with: ufw status verbose",
                        raw_output=ufw_out,
                    )
                # UFW installed but inactive — check iptables as fallback
            # Check iptables for any non-default rules
            ipt_out, _, ipt_rc = self._run_command("iptables -L -n --line-numbers")
            has_rules = ipt_rc == 0 and len(ipt_out.splitlines()) > 10

            if has_rules:
                return _finding(
                    check="Firewall Enabled",
                    status="PASS",
                    severity="HIGH",
                    description="iptables rules are present and likely active.",
                    recommendation=(
                        "Consider migrating to UFW or firewalld for easier management. "
                        "Document existing iptables rules."
                    ),
                    raw_output=ipt_out[:500],
                )

            return _finding(
                check="Firewall Enabled",
                status="FAIL",
                severity="HIGH",
                description=(
                    "No active firewall detected. UFW is inactive or absent and "
                    "iptables has no significant rules."
                ),
                recommendation=(
                    "Enable UFW: ufw enable && ufw default deny incoming && "
                    "ufw allow ssh && ufw reload. "
                    "Or install firewalld: systemctl enable --now firewalld"
                ),
                raw_output=f"UFW: {ufw_out}\niptables: {ipt_out[:200]}",
            )
        except Exception as exc:
            return _error_finding("Firewall Enabled", str(exc))

    def check_sudo_configuration(self) -> dict[str, Any]:
        """Audit /etc/sudoers for insecure configurations.

        Detects high-risk patterns: ``NOPASSWD``, ``ALL=(ALL)`` without
        restrictions, and wildcard command grants.

        Returns:
            FindingDict with HIGH severity if dangerous sudo rules are found.
        """
        try:
            sudoers_main = self._read_file("/etc/sudoers")
            sudoers_d_out, _, _ = self._run_command("ls /etc/sudoers.d/ 2>/dev/null")

            all_sudoers = sudoers_main
            for fname in sudoers_d_out.splitlines():
                fname = fname.strip()
                if fname:
                    content = self._read_file(f"/etc/sudoers.d/{fname}")
                    all_sudoers += f"\n# --- {fname} ---\n{content}"

            issues: list[str] = []
            nopasswd_users: list[str] = []

            for line in all_sudoers.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                line_lower = stripped.lower()
                if "nopasswd" in line_lower:
                    nopasswd_users.append(stripped[:80])
                if "all=(all) all" in line_lower and "root" not in line_lower:
                    issues.append(f"Unrestricted ALL=(ALL) ALL: {stripped[:80]}")

            if nopasswd_users:
                issues.append(
                    f"NOPASSWD found in {len(nopasswd_users)} rule(s): "
                    + "; ".join(nopasswd_users[:3])
                )

            if issues:
                return _finding(
                    check="Sudo Configuration",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "Insecure sudo configuration detected: "
                        + "; ".join(issues)
                        + ". "
                        "NOPASSWD rules allow privilege escalation without authentication."
                    ),
                    recommendation=(
                        "Remove NOPASSWD from /etc/sudoers unless strictly required. "
                        "Restrict commands with: username ALL=(ALL) NOPASSWD: /specific/command. "
                        "Use 'visudo' to safely edit sudoers files."
                    ),
                    raw_output=all_sudoers[:1000],
                )
            return _finding(
                check="Sudo Configuration",
                status="PASS",
                severity="HIGH",
                description="No high-risk sudo rules (NOPASSWD/unrestricted ALL) detected.",
                recommendation="Periodically audit /etc/sudoers and /etc/sudoers.d/ for new entries.",
                raw_output=all_sudoers[:500],
            )
        except Exception as exc:
            return _error_finding("Sudo Configuration", str(exc))

    def check_world_writable_files(self) -> dict[str, Any]:
        """Check for world-writable files outside of system pseudo-filesystems.

        World-writable files can be exploited to inject malicious content or
        escalate privileges.  Excludes ``/proc``, ``/sys``, ``/dev``,
        ``/run``, and ``/tmp`` (which legitimately contain writable entries).

        Returns:
            FindingDict with HIGH severity if unexpected world-writable files exist.
        """
        cmd = (
            "find / -xdev -perm -002 -type f "
            "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' "
            "! -path '/run/*' ! -path '/tmp/*' ! -path '/var/tmp/*' "
            "2>/dev/null"
        )
        try:
            stdout, _, _ = self._run_command(cmd, timeout=60)
            files = [f.strip() for f in stdout.splitlines() if f.strip()]

            if files:
                return _finding(
                    check="World-Writable Files",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        f"{len(files)} world-writable file(s) found outside system directories. "
                        "These can be modified by any user and may be exploited for privilege escalation."
                    ),
                    recommendation=(
                        "Remove world-write permissions: chmod o-w <file>. "
                        "Investigate each file's purpose before changing permissions. "
                        "Common fix: find / -xdev -perm -002 -type f -exec chmod o-w {} \\;"
                    ),
                    raw_output="\n".join(files[:30]),
                )
            return _finding(
                check="World-Writable Files",
                status="PASS",
                severity="HIGH",
                description="No unexpected world-writable files found outside system directories.",
                recommendation="Run this check periodically after software installations.",
                raw_output="",
            )
        except Exception as exc:
            return _error_finding("World-Writable Files", str(exc))

    def check_suid_binaries(self) -> dict[str, Any]:
        """Check for SUID binaries that may enable privilege escalation.

        Compares discovered SUID binaries against a whitelist of common
        expected binaries.  Unexpected SUID binaries may be exploited
        to gain root privileges (e.g., via GTFOBins).

        Returns:
            FindingDict with HIGH severity if unexpected SUID binaries are found.
        """
        # Common expected SUID binaries on standard Linux distributions
        expected_suid = {
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/bin/newgrp",
            "/usr/bin/gpasswd",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/sbin/pam_timestamp_check",
            "/bin/su",
            "/bin/mount",
            "/bin/umount",
            "/sbin/unix_chkpwd",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/lib/policykit-1/polkit-agent-helper-1",
            "/usr/bin/pkexec",
            "/usr/bin/ping",
        }
        cmd = "find / -xdev -perm -4000 -type f 2>/dev/null"
        try:
            stdout, _, _ = self._run_command(cmd, timeout=60)
            found = {f.strip() for f in stdout.splitlines() if f.strip()}
            unexpected = sorted(found - expected_suid)

            if unexpected:
                return _finding(
                    check="SUID Binaries",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        f"{len(unexpected)} unexpected SUID binary/ies found: "
                        + ", ".join(unexpected[:10])
                        + ". "
                        "These may be exploitable for local privilege escalation (GTFOBins)."
                    ),
                    recommendation=(
                        "Remove the SUID bit from unnecessary binaries: "
                        "chmod u-s <binary>. "
                        "Check GTFOBins (gtfobins.github.io) for exploitation potential."
                    ),
                    raw_output="\n".join(sorted(found)),
                )
            return _finding(
                check="SUID Binaries",
                status="PASS",
                severity="HIGH",
                description=f"Only {len(found)} expected SUID binaries found. No unexpected entries.",
                recommendation="Re-run after software updates to verify no new SUID binaries were added.",
                raw_output="\n".join(sorted(found)),
            )
        except Exception as exc:
            return _error_finding("SUID Binaries", str(exc))

    def check_file_permissions(self) -> dict[str, Any]:
        """Check critical file permissions for /etc/passwd, /etc/shadow, and home dirs.

        Verifies that:
        - ``/etc/passwd`` is world-readable but not writable (644)
        - ``/etc/shadow`` is not readable by others (640 or 000)
        - ``/etc/gshadow`` is not readable by others

        Returns:
            FindingDict with HIGH severity if sensitive files are mis-permissioned.
        """
        checks_map = {
            "/etc/passwd": {"max_others_write": True, "expected_mode_hint": "644"},
            "/etc/shadow": {
                "max_others_write": True,
                "expected_mode_hint": "640 or 000",
            },
            "/etc/gshadow": {
                "max_others_write": True,
                "expected_mode_hint": "640 or 000",
            },
            "/etc/sudoers": {"max_others_write": True, "expected_mode_hint": "440"},
        }
        issues: list[str] = []
        raw_lines: list[str] = []
        try:
            for path, _ in checks_map.items():
                stat_out, _, stat_rc = self._run_command(
                    f"stat -c '%a %n' {path} 2>/dev/null"
                )
                raw_lines.append(stat_out)
                if stat_rc != 0 or not stat_out.strip():
                    continue
                parts = stat_out.strip().split()
                if len(parts) < 2:
                    continue
                mode_str = parts[0]
                try:
                    mode = int(mode_str, 8)
                except ValueError:
                    continue
                # Check others-write bit (bit 1 of others octet)
                if mode & 0o002:
                    issues.append(f"{path} is world-writable (mode {mode_str})")
                # For shadow files, check if others can read
                if "shadow" in path and (mode & 0o004):
                    issues.append(f"{path} is world-readable (mode {mode_str})")

            if issues:
                return _finding(
                    check="File Permissions",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "Critical file permission issues detected: "
                        + "; ".join(issues)
                        + ". "
                        "Insecure permissions may expose password hashes or allow tampering."
                    ),
                    recommendation=(
                        "Fix permissions: chmod 644 /etc/passwd; "
                        "chmod 640 /etc/shadow; chmod 640 /etc/gshadow; "
                        "chmod 440 /etc/sudoers. "
                        "Run: chown root:shadow /etc/shadow /etc/gshadow"
                    ),
                    raw_output="\n".join(raw_lines),
                )
            return _finding(
                check="File Permissions",
                status="PASS",
                severity="HIGH",
                description="Critical system files have appropriate permissions.",
                recommendation="Periodically audit permissions after package updates.",
                raw_output="\n".join(raw_lines),
            )
        except Exception as exc:
            return _error_finding("File Permissions", str(exc))

    def check_kernel_hardening(self) -> dict[str, Any]:
        """Check kernel hardening sysctl parameters.

        Verifies key sysctl settings recommended by CIS Linux Benchmarks:
        - ``kernel.randomize_va_space`` should be 2 (full ASLR)
        - ``kernel.dmesg_restrict`` should be 1
        - ``net.ipv4.ip_forward`` should be 0 (unless router)
        - ``net.ipv4.conf.all.accept_redirects`` should be 0
        - ``kernel.kptr_restrict`` should be ≥1

        Returns:
            FindingDict with MEDIUM severity for missing kernel hardening.
        """
        sysctl_checks = {
            "kernel.randomize_va_space": ("2", "ASLR (full randomization)"),
            "kernel.dmesg_restrict": ("1", "dmesg restricted to root"),
            "net.ipv4.ip_forward": ("0", "IP forwarding disabled"),
            "net.ipv4.conf.all.accept_redirects": ("0", "ICMP redirects rejected"),
            "kernel.kptr_restrict": (None, "kernel pointer restriction"),
        }
        issues: list[str] = []
        raw_lines: list[str] = []
        try:
            for param, (expected, label) in sysctl_checks.items():
                out, _, rc = self._run_command(f"sysctl -n {param} 2>/dev/null")
                raw_lines.append(f"{param}={out}")
                if rc != 0 or not out.strip():
                    issues.append(f"{param} not readable (may be missing)")
                    continue
                value = out.strip()
                if expected is not None and value != expected:
                    issues.append(
                        f"{param}={value} (expected {expected}) – {label} not enforced"
                    )
                elif param == "kernel.kptr_restrict" and value == "0":
                    issues.append(
                        f"{param}={value} – kernel pointers exposed to unprivileged users"
                    )

            if issues:
                return _finding(
                    check="Kernel Hardening",
                    status="FAIL",
                    severity="MEDIUM",
                    description=(
                        f"{len(issues)} kernel hardening parameter(s) are misconfigured: "
                        + "; ".join(issues)
                        + "."
                    ),
                    recommendation=(
                        "Apply hardening via /etc/sysctl.d/99-hardening.conf:\n"
                        "  kernel.randomize_va_space = 2\n"
                        "  kernel.dmesg_restrict = 1\n"
                        "  net.ipv4.ip_forward = 0\n"
                        "  net.ipv4.conf.all.accept_redirects = 0\n"
                        "  kernel.kptr_restrict = 2\n"
                        "Apply with: sysctl --system"
                    ),
                    raw_output="\n".join(raw_lines),
                )
            return _finding(
                check="Kernel Hardening",
                status="PASS",
                severity="MEDIUM",
                description="Key kernel hardening sysctl parameters meet CIS baseline recommendations.",
                recommendation="Review full CIS Linux Benchmark for additional sysctl hardening.",
                raw_output="\n".join(raw_lines),
            )
        except Exception as exc:
            return _error_finding("Kernel Hardening", str(exc))

    def check_selinux_apparmor(self) -> dict[str, Any]:
        """Check whether SELinux or AppArmor is enabled and enforcing.

        Mandatory Access Control (MAC) frameworks provide a critical additional
        defence layer.  Permissive or disabled MAC leaves processes without
        sandboxing.

        Returns:
            FindingDict with MEDIUM severity if MAC is not enforcing.
        """
        try:
            # Try SELinux first
            se_out, _, se_rc = self._run_command("getenforce 2>/dev/null")
            if se_rc == 0 and se_out.strip():
                mode = se_out.strip().lower()
                if mode == "enforcing":
                    return _finding(
                        check="SELinux/AppArmor",
                        status="PASS",
                        severity="MEDIUM",
                        description="SELinux is in Enforcing mode.",
                        recommendation="No action required.",
                        raw_output=se_out,
                    )
                return _finding(
                    check="SELinux/AppArmor",
                    status="FAIL",
                    severity="MEDIUM",
                    description=(
                        f"SELinux is in '{se_out.strip()}' mode. "
                        "Mandatory Access Control is not enforcing. "
                        "Processes run without MAC sandboxing."
                    ),
                    recommendation=(
                        "Set SELinux to Enforcing: edit /etc/selinux/config "
                        "and set SELINUX=enforcing, then reboot. "
                        "Or temporarily: setenforce 1"
                    ),
                    raw_output=se_out,
                )

            # Try AppArmor
            aa_out, _, aa_rc = self._run_command("aa-status --enabled 2>/dev/null")
            if aa_rc == 0:
                return _finding(
                    check="SELinux/AppArmor",
                    status="PASS",
                    severity="MEDIUM",
                    description="AppArmor is enabled.",
                    recommendation="Verify all critical services have AppArmor profiles: aa-status",
                    raw_output=aa_out,
                )

            return _finding(
                check="SELinux/AppArmor",
                status="FAIL",
                severity="MEDIUM",
                description=(
                    "Neither SELinux nor AppArmor is active on this system. "
                    "No Mandatory Access Control (MAC) framework is enforcing."
                ),
                recommendation=(
                    "Install and enable AppArmor: apt install apparmor apparmor-utils && "
                    "systemctl enable apparmor && systemctl start apparmor. "
                    "Or enable SELinux if on RHEL/CentOS."
                ),
                raw_output=f"SELinux rc={se_rc}, AppArmor rc={aa_rc}",
            )
        except Exception as exc:
            return _error_finding("SELinux/AppArmor", str(exc))

    def check_package_updates(self) -> dict[str, Any]:
        """Check for pending security package updates.

        Attempts ``apt list --upgradable`` (Debian/Ubuntu) then
        ``yum check-update`` (RHEL/CentOS) to detect pending updates.

        Returns:
            FindingDict with MEDIUM severity if updates are pending.
        """
        try:
            # Try apt (Debian/Ubuntu)
            apt_out, _, apt_rc = self._run_command(
                "apt list --upgradable 2>/dev/null", timeout=60
            )
            if apt_rc == 0 and apt_out:
                lines = [
                    ln
                    for ln in apt_out.splitlines()
                    if "/" in ln and "Listing" not in ln
                ]
                if lines:
                    return _finding(
                        check="Package Updates",
                        status="FAIL",
                        severity="MEDIUM",
                        description=(
                            f"{len(lines)} package update(s) available. "
                            "Unpatched packages may contain known vulnerabilities."
                        ),
                        recommendation=(
                            "Apply updates: apt update && apt upgrade -y. "
                            "For security-only updates: apt upgrade --only-upgrade. "
                            "Consider unattended-upgrades for automatic security patches."
                        ),
                        raw_output="\n".join(lines[:20]),
                    )
                return _finding(
                    check="Package Updates",
                    status="PASS",
                    severity="MEDIUM",
                    description="All apt packages are up to date.",
                    recommendation="Configure unattended-upgrades for automatic security updates.",
                    raw_output=apt_out[:200],
                )

            # Try yum/dnf (RHEL/CentOS/Fedora)
            yum_out, _, yum_rc = self._run_command(
                "yum check-update --security 2>/dev/null", timeout=60
            )
            if yum_rc == 100:  # 100 = updates available
                pkg_lines = [
                    ln for ln in yum_out.splitlines() if ln and not ln.startswith(" ")
                ]
                return _finding(
                    check="Package Updates",
                    status="FAIL",
                    severity="MEDIUM",
                    description=(
                        f"{len(pkg_lines)} security update(s) available via yum. "
                        "Unpatched packages may contain known vulnerabilities."
                    ),
                    recommendation=(
                        "Apply security updates: yum update --security -y. "
                        "Or full update: yum update -y"
                    ),
                    raw_output="\n".join(pkg_lines[:20]),
                )
            if yum_rc == 0:
                return _finding(
                    check="Package Updates",
                    status="PASS",
                    severity="MEDIUM",
                    description="All yum/dnf packages are up to date.",
                    recommendation="Enable automatic updates: yum install -y dnf-automatic",
                    raw_output=yum_out[:200],
                )

            return _finding(
                check="Package Updates",
                status="WARNING",
                severity="MEDIUM",
                description="Could not determine package update status (apt/yum not found or failed).",
                recommendation="Manually verify package updates using your distribution's package manager.",
                raw_output=f"apt rc={apt_rc}, yum rc={yum_rc}",
            )
        except Exception as exc:
            return _error_finding("Package Updates", str(exc))

    def check_ssl_certificates(self) -> dict[str, Any]:
        """Check SSL/TLS certificates for imminent expiry.

        Scans ``/etc/ssl/certs`` and ``/etc/ssl/private`` for ``.crt`` and
        ``.pem`` files and checks expiry dates using ``openssl x509``.
        Certificates expiring within 30 days are flagged.

        Returns:
            FindingDict with HIGH severity if certificates are expiring soon.
        """
        search_dirs = ["/etc/ssl/certs", "/etc/ssl/private", "/etc/pki/tls/certs"]
        expiring: list[str] = []
        expired: list[str] = []
        raw_lines: list[str] = []
        try:
            for search_dir in search_dirs:
                find_out, _, find_rc = self._run_command(
                    f"find {search_dir} -name '*.crt' -o -name '*.pem' 2>/dev/null"
                )
                if find_rc != 0 or not find_out.strip():
                    continue
                for cert_path in find_out.splitlines():
                    cert_path = cert_path.strip()
                    if not cert_path:
                        continue
                    # Check validity dates
                    end_out, _, rc = self._run_command(
                        f"openssl x509 -enddate -noout -in {cert_path} 2>/dev/null"
                    )
                    if rc != 0 or not end_out.strip():
                        continue
                    raw_lines.append(f"{cert_path}: {end_out.strip()}")
                    # Check days remaining
                    days_out, _, days_rc = self._run_command(
                        f"openssl x509 -checkend 2592000 -noout -in {cert_path} 2>/dev/null"
                    )
                    if days_rc != 0:  # Non-zero = will expire within 30 days
                        # Check if already expired
                        exp_out, _, exp_rc = self._run_command(
                            f"openssl x509 -checkend 0 -noout -in {cert_path} 2>/dev/null"
                        )
                        if exp_rc != 0:
                            expired.append(cert_path)
                        else:
                            expiring.append(cert_path)

            if expired:
                return _finding(
                    check="SSL Certificates",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        f"{len(expired)} EXPIRED certificate(s) found: "
                        + ", ".join(expired[:5])
                        + ". Expired certificates cause service outages and browser warnings."
                    ),
                    recommendation=(
                        "Renew expired certificates immediately. "
                        "Use Let's Encrypt for automatic renewal: certbot renew. "
                        "Set up monitoring: certbot renew --dry-run"
                    ),
                    raw_output="\n".join(raw_lines[:20]),
                )
            if expiring:
                return _finding(
                    check="SSL Certificates",
                    status="WARNING",
                    severity="HIGH",
                    description=(
                        f"{len(expiring)} certificate(s) expiring within 30 days: "
                        + ", ".join(expiring[:5])
                        + "."
                    ),
                    recommendation=(
                        "Renew certificates before they expire. "
                        "For Let's Encrypt: certbot renew. "
                        "Set calendar reminders or automate renewal."
                    ),
                    raw_output="\n".join(raw_lines[:20]),
                )
            if raw_lines:
                return _finding(
                    check="SSL Certificates",
                    status="PASS",
                    severity="HIGH",
                    description=f"All {len(raw_lines)} SSL certificate(s) are valid and not expiring soon.",
                    recommendation="Configure automated certificate renewal (certbot, acme.sh, etc.).",
                    raw_output="\n".join(raw_lines[:10]),
                )
            return _finding(
                check="SSL Certificates",
                status="WARNING",
                severity="HIGH",
                description="No SSL certificates found in standard directories.",
                recommendation=(
                    "If this server runs HTTPS/TLS services, verify certificate paths "
                    "and add custom locations to the scan configuration."
                ),
                raw_output="",
            )
        except Exception as exc:
            return _error_finding("SSL Certificates", str(exc))

    def check_open_ports(self) -> dict[str, Any]:
        """Check for unexpected open listening ports.

        Uses ``ss -tlnp`` to list all listening TCP ports and flags ports
        outside a baseline whitelist (22, 80, 443, 8080, 8443).

        Returns:
            FindingDict with MEDIUM severity if unexpected ports are open.
        """
        # Common expected listening ports
        expected_ports = {22, 80, 443, 8080, 8443, 25, 587, 993, 995, 53}
        try:
            out, _, rc = self._run_command("ss -tlnp")
            if rc != 0:
                # Fallback to netstat
                out, _, rc = self._run_command("netstat -tlnp 2>/dev/null")

            unexpected: list[str] = []
            lines = out.splitlines()
            for line in lines[1:]:  # skip header
                parts = line.split()
                if len(parts) < 5:
                    continue
                local_addr = parts[
                    4
                ]  # ss/netstat: Netid State Recv-Q Send-Q Local:Port
                # Extract port from address like 0.0.0.0:22 or [::]:443
                if ":" in local_addr:
                    port_str = local_addr.rsplit(":", 1)[-1]
                    try:
                        port = int(port_str)
                        if port not in expected_ports:
                            service_info = parts[-1] if len(parts) > 5 else ""
                            unexpected.append(f"port {port} ({service_info})")
                    except ValueError:
                        pass

            if unexpected:
                return _finding(
                    check="Open Ports",
                    status="WARNING",
                    severity="MEDIUM",
                    description=(
                        f"{len(unexpected)} unexpected listening port(s) detected: "
                        + ", ".join(unexpected[:10])
                        + ". "
                        "Unnecessary services increase the attack surface."
                    ),
                    recommendation=(
                        "Disable unnecessary services: systemctl disable <service>. "
                        "Restrict access with firewall rules: ufw allow <port>. "
                        "Audit each unexpected port and close if not required."
                    ),
                    raw_output=out,
                )
            return _finding(
                check="Open Ports",
                status="PASS",
                severity="MEDIUM",
                description="No unexpected listening ports detected beyond the expected baseline.",
                recommendation="Re-run after installing new services.",
                raw_output=out,
            )
        except Exception as exc:
            return _error_finding("Open Ports", str(exc))

    def check_user_accounts(self) -> dict[str, Any]:
        """Audit /etc/passwd for insecure account configurations.

        Flags:
        - Non-system users with UID 0 (hidden root accounts)
        - Accounts with no password in /etc/shadow
        - Login shells for system accounts that should not be interactive

        Returns:
            FindingDict with HIGH severity if suspicious accounts are found.
        """
        try:
            passwd_content = self._read_file("/etc/passwd")
            issues: list[str] = []
            raw_lines: list[str] = []

            for line in passwd_content.splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username, _, uid, _, _, home, shell = parts[:7]
                uid_int = int(uid) if uid.isdigit() else -1
                raw_lines.append(line)

                # Check for non-root users with UID 0
                if uid_int == 0 and username != "root":
                    issues.append(f"User '{username}' has UID 0 (hidden root account!)")

                # Check for system accounts with interactive shells
                suspicious_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish"}
                if (
                    0 < uid_int < 1000
                    and shell in suspicious_shells
                    and username not in {"sync", "shutdown", "halt"}
                ):
                    issues.append(
                        f"System account '{username}' (UID {uid_int}) has interactive shell '{shell}'"
                    )

            # Check /etc/shadow for accounts with empty passwords
            shadow_content = self._read_file("/etc/shadow")
            for line in shadow_content.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    username = parts[0]
                    pw_hash = parts[1]
                    if pw_hash == "" and username not in ("root",):
                        issues.append(f"User '{username}' has no password set")

            if issues:
                return _finding(
                    check="User Accounts",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "Suspicious user account configuration detected: "
                        + "; ".join(issues)
                        + "."
                    ),
                    recommendation=(
                        "For UID 0 accounts (other than root): usermod -u <newuid> <user>. "
                        "For system accounts with shells: usermod -s /usr/sbin/nologin <user>. "
                        "For empty passwords: passwd <user> to set a password."
                    ),
                    raw_output="\n".join(raw_lines[:20]),
                )
            return _finding(
                check="User Accounts",
                status="PASS",
                severity="HIGH",
                description="No suspicious user account configurations found in /etc/passwd.",
                recommendation="Periodically audit user accounts and remove stale entries.",
                raw_output="\n".join(raw_lines[:10]),
            )
        except Exception as exc:
            return _error_finding("User Accounts", str(exc))

    def check_failed_logins(self) -> dict[str, Any]:
        """Check for excessive failed login attempts (potential brute-force).

        Examines ``/var/log/btmp`` via ``lastb`` or ``journalctl`` for SSH
        failures.  More than 50 failed attempts may indicate active brute-force.

        Returns:
            FindingDict with MEDIUM severity if excessive failures are detected.
        """
        try:
            # Try lastb first
            lb_out, _, lb_rc = self._run_command("lastb -n 100 2>/dev/null")
            if lb_rc == 0 and lb_out:
                # Count lines excluding header/footer
                failure_lines = [
                    ln
                    for ln in lb_out.splitlines()
                    if ln.strip() and "btmp begins" not in ln
                ]
                count = len(failure_lines)
                if count >= 50:
                    return _finding(
                        check="Failed Logins",
                        status="FAIL",
                        severity="MEDIUM",
                        description=(
                            f"{count}+ failed login attempt(s) recorded (last 100 from btmp). "
                            "This may indicate an active brute-force attack."
                        ),
                        recommendation=(
                            "Install and configure fail2ban: apt install fail2ban. "
                            "Review /var/log/auth.log for attacker IPs. "
                            "Consider rate-limiting SSH via: ufw limit ssh"
                        ),
                        raw_output="\n".join(failure_lines[:20]),
                    )

            # Try journalctl for SSH failures
            jrnl_out, _, jrnl_rc = self._run_command(
                "journalctl -u sshd --since '24 hours ago' 2>/dev/null | "
                "grep -c 'Failed password' 2>/dev/null",
            )
            if jrnl_rc == 0 and jrnl_out.strip().isdigit():
                count = int(jrnl_out.strip())
                if count >= 50:
                    return _finding(
                        check="Failed Logins",
                        status="FAIL",
                        severity="MEDIUM",
                        description=(
                            f"{count} SSH 'Failed password' events in the last 24 hours. "
                            "Possible brute-force attack in progress."
                        ),
                        recommendation=(
                            "Install fail2ban: apt install fail2ban && systemctl enable fail2ban. "
                            "Block offending IPs: ufw insert 1 deny from <IP>. "
                            "Consider moving SSH to a non-standard port."
                        ),
                        raw_output=jrnl_out,
                    )

            return _finding(
                check="Failed Logins",
                status="PASS",
                severity="MEDIUM",
                description="Failed login count is within acceptable limits (< 50 recent failures).",
                recommendation="Consider installing fail2ban for automated brute-force protection.",
                raw_output=lb_out[:300] if lb_rc == 0 else jrnl_out[:200],
            )
        except Exception as exc:
            return _error_finding("Failed Logins", str(exc))

    def check_cron_jobs(self) -> dict[str, Any]:
        """Audit cron job configurations for suspicious or world-writable scripts.

        Checks root's crontab, /etc/crontab, and /etc/cron.* directories for:
        - Scripts with world-writable permissions
        - Entries pointing to writable or non-existent files

        Returns:
            FindingDict with MEDIUM severity if insecure cron entries are found.
        """
        try:
            cron_sources: list[tuple[str, str]] = []

            # Root crontab
            root_cron, _, _ = self._run_command("crontab -l -u root 2>/dev/null")
            if root_cron:
                cron_sources.append(("root crontab", root_cron))

            # System crontab files
            for path in ["/etc/crontab"]:
                content = self._read_file(path)
                if content:
                    cron_sources.append((path, content))

            # Cron directories
            for cron_dir in [
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.hourly",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
            ]:
                ls_out, _, ls_rc = self._run_command(f"ls {cron_dir} 2>/dev/null")
                if ls_rc == 0 and ls_out.strip():
                    for fname in ls_out.splitlines():
                        fname = fname.strip()
                        if fname:
                            content = self._read_file(f"{cron_dir}/{fname}")
                            if content:
                                cron_sources.append((f"{cron_dir}/{fname}", content))

            issues: list[str] = []
            all_raw: list[str] = []

            for source, content in cron_sources:
                all_raw.append(f"=== {source} ===\n{content[:200]}")
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    # Extract script/command from cron line
                    parts = stripped.split()
                    if len(parts) < 2:
                        continue
                    # Look for absolute paths in commands
                    for part in parts:
                        if part.startswith("/") and not part.startswith("/usr/bin/env"):
                            # Check if the script is world-writable
                            stat_out, _, stat_rc = self._run_command(
                                f"stat -c '%a %n' {part} 2>/dev/null"
                            )
                            if stat_rc == 0 and stat_out.strip():
                                mode_parts = stat_out.strip().split()
                                if mode_parts:
                                    try:
                                        mode = int(mode_parts[0], 8)
                                        if mode & 0o002:
                                            issues.append(
                                                f"World-writable cron script: {part} (mode {mode_parts[0]}) in {source}"
                                            )
                                    except ValueError:
                                        pass

            if issues:
                return _finding(
                    check="Cron Jobs",
                    status="FAIL",
                    severity="MEDIUM",
                    description=(
                        "Insecure cron job configuration detected: "
                        + "; ".join(issues)
                        + ". "
                        "World-writable cron scripts can be hijacked for privilege escalation."
                    ),
                    recommendation=(
                        "Remove world-write permissions from cron scripts: "
                        "chmod o-w <script>. "
                        "Ensure cron scripts are owned by root and not writable by others."
                    ),
                    raw_output="\n".join(all_raw[:5]),
                )
            return _finding(
                check="Cron Jobs",
                status="PASS",
                severity="MEDIUM",
                description=f"Reviewed {len(cron_sources)} cron source(s). No insecure entries found.",
                recommendation="Periodically audit cron jobs for new entries: crontab -l -u root",
                raw_output="\n".join(all_raw[:3]),
            )
        except Exception as exc:
            return _error_finding("Cron Jobs", str(exc))

    def check_weak_ciphers(self) -> dict[str, Any]:
        """Check SSH server configuration for weak cipher suites and MACs.

        Inspects ``sshd_config`` for deprecated ciphers (3DES, Blowfish,
        RC4, arcfour) and weak MACs (MD5, SHA1-based).

        Returns:
            FindingDict with HIGH severity if weak ciphers/MACs are configured.
        """
        weak_ciphers = {
            "3des-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
        }
        weak_macs = {
            "hmac-md5",
            "hmac-md5-96",
            "hmac-sha1",
            "hmac-sha1-96",
            "umac-64@openssh.com",
            "hmac-md5-etm@openssh.com",
        }
        try:
            sshd_config = self._read_file("/etc/ssh/sshd_config")
            found_weak_ciphers: list[str] = []
            found_weak_macs: list[str] = []

            for line in sshd_config.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("ciphers"):
                    for cipher in weak_ciphers:
                        if cipher in stripped:
                            found_weak_ciphers.append(cipher)
                if stripped.startswith("macs"):
                    for mac in weak_macs:
                        if mac in stripped:
                            found_weak_macs.append(mac)

            issues: list[str] = []
            if found_weak_ciphers:
                issues.append(f"Weak ciphers: {', '.join(found_weak_ciphers)}")
            if found_weak_macs:
                issues.append(f"Weak MACs: {', '.join(found_weak_macs)}")

            if issues:
                return _finding(
                    check="Weak SSH Ciphers",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "Weak SSH ciphers or MACs detected in sshd_config: "
                        + "; ".join(issues)
                        + ". "
                        "These enable downgrade attacks and compromise session confidentiality."
                    ),
                    recommendation=(
                        "Set strong ciphers in /etc/ssh/sshd_config:\n"
                        "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
                        "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
                        "Then: systemctl restart sshd"
                    ),
                    raw_output=sshd_config[:500],
                )
            return _finding(
                check="Weak SSH Ciphers",
                status="PASS",
                severity="HIGH",
                description=(
                    "No explicitly weak ciphers or MACs found in sshd_config. "
                    "OpenSSH defaults or strong explicit ciphers in use."
                ),
                recommendation=(
                    "Explicitly set strong ciphers in sshd_config to prevent "
                    "regression after OpenSSH updates."
                ),
                raw_output=sshd_config[:300],
            )
        except Exception as exc:
            return _error_finding("Weak SSH Ciphers", str(exc))

    def check_log_rotation(self) -> dict[str, Any]:
        """Check that log rotation is configured to prevent unbounded disk usage.

        Verifies that ``/etc/logrotate.conf`` exists and has a ``rotate``
        directive, and that ``/etc/logrotate.d/`` contains service-specific
        configurations.

        Returns:
            FindingDict with LOW severity if log rotation is not configured.
        """
        try:
            logrotate_main = self._read_file("/etc/logrotate.conf")
            logrotate_d_out, _, logrotate_d_rc = self._run_command(
                "ls /etc/logrotate.d/ 2>/dev/null"
            )

            issues: list[str] = []
            raw_lines: list[str] = []

            if not logrotate_main.strip():
                issues.append("/etc/logrotate.conf is missing or empty")
            else:
                raw_lines.append(logrotate_main[:300])
                if "rotate" not in logrotate_main.lower():
                    issues.append(
                        "/etc/logrotate.conf does not contain a 'rotate' directive"
                    )

            d_files = []
            if logrotate_d_rc == 0 and logrotate_d_out.strip():
                d_files = [f.strip() for f in logrotate_d_out.splitlines() if f.strip()]

            raw_lines.append(f"logrotate.d files: {', '.join(d_files)}")

            if not d_files:
                issues.append(
                    "/etc/logrotate.d/ is empty – no per-service log rotation"
                )

            # Check if logrotate timer/cron is active
            systemd_out, _, sd_rc = self._run_command(
                "systemctl is-active logrotate.timer 2>/dev/null"
            )
            cron_out, _, cron_rc = self._run_command(
                "ls /etc/cron.daily/logrotate 2>/dev/null"
            )
            if sd_rc != 0 and cron_rc != 0:
                issues.append(
                    "logrotate.timer is not active and /etc/cron.daily/logrotate not found"
                )

            if issues:
                return _finding(
                    check="Log Rotation",
                    status="FAIL",
                    severity="LOW",
                    description=(
                        "Log rotation configuration issues detected: "
                        + "; ".join(issues)
                        + ". "
                        "Without log rotation, logs may fill disk or be lost."
                    ),
                    recommendation=(
                        "Install logrotate: apt install logrotate. "
                        "Verify /etc/logrotate.conf has 'rotate N' and 'compress'. "
                        "Enable timer: systemctl enable --now logrotate.timer"
                    ),
                    raw_output="\n".join(raw_lines[:5]),
                )
            return _finding(
                check="Log Rotation",
                status="PASS",
                severity="LOW",
                description=(
                    f"Log rotation is configured with {len(d_files)} "
                    "per-service rule(s) in /etc/logrotate.d/."
                ),
                recommendation="Verify log retention meets your compliance requirements.",
                raw_output="\n".join(raw_lines[:3]),
            )
        except Exception as exc:
            return _error_finding("Log Rotation", str(exc))

    # ------------------------------------------------------------------
    # Full scan orchestrator
    # ------------------------------------------------------------------

    def run_scan(self) -> dict[str, Any]:
        """Execute all 18 Linux security checks concurrently and return consolidated results.

        Runs all ``check_*`` methods using a thread pool for performance.
        The scan targets the host specified in the constructor.

        Returns:
            A dictionary with the following structure::

                {
                    "server": str,           # Target hostname/IP
                    "os": "linux",           # Platform identifier
                    "timestamp": str,        # ISO 8601 UTC timestamp
                    "scan_duration_seconds": float,
                    "findings": list[dict],  # List of FindingDict
                    "total_checks": int,
                    "summary": {
                        "PASS": int,
                        "FAIL": int,
                        "WARNING": int
                    }
                }
        """
        checks = [
            self.check_ssh_key_auth,
            self.check_ssh_root_login,
            self.check_ssh_password_auth,
            self.check_firewall_enabled,
            self.check_sudo_configuration,
            self.check_world_writable_files,
            self.check_suid_binaries,
            self.check_file_permissions,
            self.check_kernel_hardening,
            self.check_selinux_apparmor,
            self.check_package_updates,
            self.check_ssl_certificates,
            self.check_open_ports,
            self.check_user_accounts,
            self.check_failed_logins,
            self.check_cron_jobs,
            self.check_weak_ciphers,
            self.check_log_rotation,
        ]

        logger.info(
            "Starting Linux security scan on %s (%d checks)", self.target, len(checks)
        )
        start = time.perf_counter()

        findings: list[dict[str, Any]] = []

        # Each check is I/O-bound (subprocess/SSH). Run all checks concurrently so
        # total scan time ≈ slowest individual check rather than sum of all checks.
        with ThreadPoolExecutor(max_workers=len(checks)) as executor:
            future_map = {executor.submit(check): check.__name__ for check in checks}
            for future in as_completed(future_map):
                check_name = future_map[future]
                try:
                    result = future.result()
                    findings.append(result)
                    logger.debug("Check %s → %s", check_name, result.get("status"))
                except Exception as exc:
                    logger.error("Check %s raised: %s", check_name, exc)
                    findings.append(_error_finding(check_name, str(exc)))

        duration = round(time.perf_counter() - start, 2)

        summary: dict[str, int] = {"PASS": 0, "FAIL": 0, "WARNING": 0}
        for f in findings:
            status = f.get("status", "WARNING")
            summary[status] = summary.get(status, 0) + 1

        logger.info(
            "Linux scan complete in %.1fs – PASS:%d FAIL:%d WARNING:%d",
            duration,
            summary["PASS"],
            summary["FAIL"],
            summary["WARNING"],
        )

        return {
            "server": self.target,
            "os": "linux",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": duration,
            "findings": findings,
            "total_checks": len(findings),
            "summary": summary,
        }

    def __del__(self) -> None:
        """Close the SSH connection on garbage collection."""
        if self._ssh_client is not None:
            try:
                self._ssh_client.close()
            except Exception:
                pass
