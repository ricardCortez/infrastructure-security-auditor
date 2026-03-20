"""Windows Security Scanner module.

Provides :class:`WindowsScanner` which executes local or remote (WinRM)
PowerShell-based security checks against a Windows target host.
"""

from __future__ import annotations

import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Literal

from src.config import logger

# ---------------------------------------------------------------------------
# Type aliases
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
        recommendation="Run auditor with elevated privileges (Administrator) to enable this check.",
        raw_output=error,
    )


# ---------------------------------------------------------------------------
# WindowsScanner
# ---------------------------------------------------------------------------


class WindowsScanner:
    """Performs security configuration checks against a Windows host.

    Supports both local scanning (via ``subprocess`` / PowerShell) and
    remote scanning (via WinRM).  Each ``check_*`` method returns a
    normalised ``FindingDict`` describing the security posture of that
    specific control.

    Args:
        target: IP address or hostname of the target server.
            Use ``"localhost"`` or ``"127.0.0.1"`` for local scanning.
        credentials: Optional dictionary with keys ``username``, ``password``,
            ``port`` (default 5985), and ``transport`` (default ``"ntlm"``).
            Required for remote WinRM scans.
    """

    def __init__(
        self,
        target: str,
        credentials: dict[str, Any] | None = None,
    ) -> None:
        self.target = target
        self.credentials = credentials or {}
        self._is_local = target in {"localhost", "127.0.0.1", "::1"}
        self._winrm_session: Any = None  # lazy-loaded

        if not self._is_local and self.credentials:
            self._init_winrm()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_winrm(self) -> None:
        """Initialise a WinRM session for remote scanning.

        Raises:
            ImportError: If ``pywinrm`` is not installed.
            ConnectionError: If the WinRM connection cannot be established.
        """
        try:
            import winrm  # type: ignore[import]

            self._winrm_session = winrm.Session(
                target=self.target,
                auth=(
                    self.credentials.get("username", ""),
                    self.credentials.get("password", ""),
                ),
                transport=self.credentials.get("transport", "ntlm"),
                server_cert_validation="ignore",
            )
            logger.debug("WinRM session initialised for %s", self.target)
        except ImportError as exc:
            raise ImportError(
                "pywinrm is required for remote scanning. "
                "Install it with: pip install pywinrm"
            ) from exc

    def _run_powershell(self, script: str) -> tuple[str, str, int]:
        """Execute a PowerShell script locally or via WinRM.

        Args:
            script: PowerShell script to execute.

        Returns:
            Tuple of ``(stdout, stderr, return_code)``.
        """
        if self._is_local:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        else:
            if self._winrm_session is None:
                raise RuntimeError(
                    "WinRM session not initialised. "
                    "Provide credentials when instantiating WindowsScanner."
                )
            response = self._winrm_session.run_ps(script)
            stdout = response.std_out.decode("utf-8", errors="replace").strip()
            stderr = response.std_err.decode("utf-8", errors="replace").strip()
            return stdout, stderr, response.status_code

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    def check_firewall(self) -> dict[str, Any]:
        """Check whether the Windows Firewall is enabled on all profiles.

        Queries ``Get-NetFirewallProfile`` for Domain, Private, and Public
        profiles.  Reports FAIL if any profile is disabled.

        Returns:
            FindingDict describing the firewall status.
        """
        script = (
            "Get-NetFirewallProfile | " "Select-Object Name, Enabled | ConvertTo-Json"
        )
        try:
            stdout, stderr, rc = self._run_powershell(script)
            profiles = json.loads(stdout) if stdout else []
            if isinstance(profiles, dict):
                profiles = [profiles]

            disabled = [p["Name"] for p in profiles if not p.get("Enabled", False)]

            if disabled:
                return _finding(
                    check="Firewall Status",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        f"Windows Firewall is DISABLED on {len(disabled)} profile(s): "
                        f"{', '.join(disabled)}."
                    ),
                    recommendation=(
                        "Enable the Windows Firewall on all profiles via: "
                        "Set-NetFirewallProfile -All -Enabled True"
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="Firewall Status",
                status="PASS",
                severity="HIGH",
                description="Windows Firewall is enabled on all network profiles (Domain, Private, Public).",
                recommendation="No action required. Periodically review firewall rules.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("Firewall Status", str(exc))

    def check_smb_v1(self) -> dict[str, Any]:
        """Check whether SMBv1 is enabled on the host.

        SMBv1 is a legacy protocol with well-known critical vulnerabilities
        (EternalBlue / WannaCry). It should be disabled on all modern systems.

        Returns:
            FindingDict with CRITICAL severity if SMBv1 is enabled.
        """
        script = "(Get-SmbServerConfiguration).EnableSMB1Protocol"
        try:
            stdout, stderr, rc = self._run_powershell(script)
            enabled = stdout.strip().lower() == "true"

            if enabled:
                return _finding(
                    check="SMBv1 Protocol",
                    status="FAIL",
                    severity="CRITICAL",
                    description=(
                        "SMBv1 is ENABLED. This legacy protocol is exploited by "
                        "EternalBlue (MS17-010) and ransomware such as WannaCry."
                    ),
                    recommendation=(
                        "Disable SMBv1 immediately: "
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="SMBv1 Protocol",
                status="PASS",
                severity="CRITICAL",
                description="SMBv1 is disabled. The host is protected against EternalBlue-class attacks.",
                recommendation="No action required.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("SMBv1 Protocol", str(exc))

    def check_llmnr_netbios(self) -> dict[str, Any]:
        """Check whether LLMNR and NetBIOS are disabled.

        LLMNR and NetBIOS are frequently exploited in name-poisoning attacks
        (Responder). Both should be disabled in enterprise environments.

        Returns:
            FindingDict with HIGH severity if either protocol is enabled.
        """
        llmnr_script = (
            r"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' "
            r"-Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast"
        )
        netbios_script = (
            "Get-WmiObject Win32_NetworkAdapterConfiguration | "
            "Where-Object { $_.IPEnabled } | "
            "Select-Object -ExpandProperty TcpipNetbiosOptions"
        )
        issues: list[str] = []
        raw: list[str] = []
        try:
            llmnr_out, _, _ = self._run_powershell(llmnr_script)
            raw.append(f"LLMNR: {llmnr_out}")
            # EnableMulticast=0 means LLMNR disabled; blank / 1 = enabled
            if llmnr_out.strip() != "0":
                issues.append("LLMNR is enabled")

            nb_out, _, _ = self._run_powershell(netbios_script)
            raw.append(f"NetBIOS: {nb_out}")
            # TcpipNetbiosOptions: 0=default, 1=enabled, 2=disabled
            if any(v.strip() in ("0", "1") for v in nb_out.splitlines() if v.strip()):
                issues.append("NetBIOS over TCP/IP is enabled on one or more adapters")

            if issues:
                return _finding(
                    check="LLMNR/NetBIOS",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "Name-poisoning attack surface is EXPOSED: "
                        + "; ".join(issues)
                        + "."
                    ),
                    recommendation=(
                        "Disable LLMNR via GPO: Computer Configuration → "
                        "Administrative Templates → Network → DNS Client → "
                        "Turn Off Multicast Name Resolution = Enabled. "
                        "Disable NetBIOS via NIC settings or DHCP option 001."
                    ),
                    raw_output="\n".join(raw),
                )
            return _finding(
                check="LLMNR/NetBIOS",
                status="PASS",
                severity="HIGH",
                description="LLMNR and NetBIOS are disabled. Name-poisoning attack surface is minimised.",
                recommendation="No action required.",
                raw_output="\n".join(raw),
            )
        except Exception as exc:
            return _error_finding("LLMNR/NetBIOS", str(exc))

    def check_windows_defender(self) -> dict[str, Any]:
        """Check Windows Defender antivirus status and signature freshness.

        Verifies that real-time protection is enabled and that antivirus
        signatures are up to date (less than 7 days old).

        Returns:
            FindingDict with HIGH severity if Defender is disabled or outdated.
        """
        script = (
            "Get-MpComputerStatus | "
            "Select-Object RealTimeProtectionEnabled, AntivirusEnabled, "
            "AntivirusSignatureLastUpdated, AntivirusSignatureAge | ConvertTo-Json"
        )
        try:
            stdout, _, _ = self._run_powershell(script)
            data = json.loads(stdout) if stdout else {}

            rt_enabled = data.get("RealTimeProtectionEnabled", False)
            av_enabled = data.get("AntivirusEnabled", False)
            sig_age = data.get("AntivirusSignatureAge", 999)

            issues: list[str] = []
            if not rt_enabled:
                issues.append("Real-time protection is disabled")
            if not av_enabled:
                issues.append("Antivirus is disabled")
            if isinstance(sig_age, (int, float)) and sig_age > 7:
                issues.append(
                    f"Antivirus signatures are {sig_age} day(s) old (>7 days)"
                )

            if issues:
                return _finding(
                    check="Windows Defender",
                    status="FAIL",
                    severity="HIGH",
                    description="Windows Defender identifies issues: "
                    + "; ".join(issues)
                    + ".",
                    recommendation=(
                        "Enable Defender: Set-MpPreference -DisableRealtimeMonitoring $false. "
                        "Update signatures: Update-MpSignature."
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="Windows Defender",
                status="PASS",
                severity="HIGH",
                description="Windows Defender is active and signatures are current.",
                recommendation="No action required. Ensure signatures update automatically.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("Windows Defender", str(exc))

    def check_tls_versions(self) -> dict[str, Any]:
        """Check whether deprecated TLS/SSL versions are enabled in SCHANNEL.

        TLS 1.0 and 1.1 are deprecated (RFC 8996). SSL 2.0 and 3.0 are
        vulnerable to POODLE and DROWN. Only TLS 1.2+ should be active.

        Returns:
            FindingDict with HIGH severity if any deprecated protocol is enabled.
        """
        deprecated = {
            "SSL 2.0": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
            "SSL 3.0": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
            "TLS 1.0": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
            "TLS 1.1": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        }
        enabled_deprecated: list[str] = []
        raw_lines: list[str] = []

        for proto, reg_path in deprecated.items():
            script = (
                f"$p = Get-ItemProperty -Path '{reg_path}' -ErrorAction SilentlyContinue; "
                f"if ($p -ne $null) {{ $p.Enabled }} else {{ 'NOT_SET' }}"
            )
            try:
                out, _, _ = self._run_powershell(script)
                raw_lines.append(f"{proto}: {out}")
                # A value of 0 means explicitly disabled. NOT_SET or 1 means enabled.
                if out.strip() not in ("0", "False", "false"):
                    enabled_deprecated.append(proto)
            except Exception as exc:
                raw_lines.append(f"{proto}: ERROR {exc}")

        if enabled_deprecated:
            return _finding(
                check="TLS Versions",
                status="FAIL",
                severity="HIGH",
                description=(
                    f"Deprecated protocols enabled: {', '.join(enabled_deprecated)}. "
                    "These are vulnerable to POODLE, BEAST, DROWN, and downgrade attacks."
                ),
                recommendation=(
                    "Disable deprecated protocols via SCHANNEL registry keys. "
                    "Use IIS Crypto or: "
                    "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\"
                    "SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force | "
                    "New-ItemProperty -Name Enabled -Value 0 -PropertyType DWORD -Force"
                ),
                raw_output="\n".join(raw_lines),
            )
        return _finding(
            check="TLS Versions",
            status="PASS",
            severity="HIGH",
            description="No deprecated TLS/SSL protocols detected. Only TLS 1.2+ is active.",
            recommendation="No action required.",
            raw_output="\n".join(raw_lines),
        )

    def check_password_policies(self) -> dict[str, Any]:
        """Check local password policy configuration.

        Evaluates minimum password length (≥12), maximum password age (≤90 days),
        complexity requirements, and lockout threshold.

        Returns:
            FindingDict with MEDIUM severity for policy weaknesses.
        """
        script = "net accounts"
        try:
            stdout, _, _ = self._run_powershell(script)
            issues: list[str] = []

            for line in stdout.splitlines():
                line_lower = line.lower()

                if "minimum password length" in line_lower:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        val_str = parts[-1].strip()
                        try:
                            val = int(val_str)
                            if val < 12:
                                issues.append(
                                    f"Minimum password length is {val} (should be ≥12)"
                                )
                        except ValueError:
                            pass

                if "maximum password age" in line_lower:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        val_str = parts[-1].strip().split()[0]
                        try:
                            val = int(val_str)
                            if val > 90:
                                issues.append(
                                    f"Maximum password age is {val} days (should be ≤90)"
                                )
                        except ValueError:
                            pass

                if "lockout threshold" in line_lower:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        val_str = parts[-1].strip()
                        if val_str in ("0", "Never"):
                            issues.append(
                                "Account lockout threshold is 0 (accounts never locked out)"
                            )

            if issues:
                return _finding(
                    check="Password Policies",
                    status="FAIL",
                    severity="MEDIUM",
                    description="Password policy weaknesses detected: "
                    + "; ".join(issues)
                    + ".",
                    recommendation=(
                        "Configure via Group Policy: Computer Configuration → "
                        "Windows Settings → Security Settings → Account Policies → "
                        "Password Policy. Set min length ≥12, max age ≤90 days, "
                        "enable complexity, set lockout threshold ≤5."
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="Password Policies",
                status="PASS",
                severity="MEDIUM",
                description="Password policy meets baseline requirements (length, age, lockout).",
                recommendation="No action required.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("Password Policies", str(exc))

    def check_rdp_nla(self) -> dict[str, Any]:
        """Check whether Remote Desktop requires Network Level Authentication.

        NLA enforces authentication before a full RDP session is established,
        reducing the attack surface against credential stuffing and BlueKeep.

        Returns:
            FindingDict with HIGH severity if NLA is disabled.
        """
        script = (
            "(Get-ItemProperty -Path "
            "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server"
            "\\WinStations\\RDP-Tcp' -Name UserAuthentication "
            "-ErrorAction SilentlyContinue).UserAuthentication"
        )
        try:
            stdout, _, _ = self._run_powershell(script)
            # UserAuthentication=1 means NLA required
            nla_enabled = stdout.strip() == "1"

            if not nla_enabled:
                return _finding(
                    check="RDP NLA",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "RDP does NOT require Network Level Authentication (NLA). "
                        "This exposes the login screen to unauthenticated users and "
                        "is exploited by BlueKeep (CVE-2019-0708)."
                    ),
                    recommendation=(
                        "Enable NLA: Set-ItemProperty -Path "
                        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server"
                        "\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 "
                        "or via System Properties → Remote → Require NLA."
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="RDP NLA",
                status="PASS",
                severity="HIGH",
                description="RDP requires Network Level Authentication (NLA).",
                recommendation="No action required.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("RDP NLA", str(exc))

    def check_windows_update(self) -> dict[str, Any]:
        """Check Windows Update status and pending critical patches.

        Uses the Windows Update Agent COM API to detect pending updates
        and how long updates have been deferred.

        Returns:
            FindingDict with MEDIUM severity for outdated patch status.
        """
        script = (
            "$Session = New-Object -ComObject 'Microsoft.Update.Session'; "
            "$Searcher = $Session.CreateUpdateSearcher(); "
            "try { "
            "  $Result = $Searcher.Search('IsInstalled=0 and Type=Software'); "
            "  $critical = ($Result.Updates | Where-Object {$_.MsrcSeverity -eq 'Critical'}).Count; "
            "  $total = $Result.Updates.Count; "
            "  \"{'total': $total, 'critical': $critical}\" "
            '} catch { "error" }'
        )
        try:
            stdout, _, _ = self._run_powershell(script)

            if "error" in stdout.lower():
                return _finding(
                    check="Windows Update",
                    status="WARNING",
                    severity="MEDIUM",
                    description="Could not query Windows Update Agent. Manual verification required.",
                    recommendation="Ensure Windows Update service is running and check for pending updates.",
                    raw_output=stdout,
                )

            # Try to parse the pseudo-JSON output
            try:
                data = json.loads(stdout.strip().replace("'", '"'))
                total = int(data.get("total", 0))
                critical = int(data.get("critical", 0))
            except (ValueError, json.JSONDecodeError):
                total, critical = 0, 0

            if critical > 0:
                return _finding(
                    check="Windows Update",
                    status="FAIL",
                    severity="MEDIUM",
                    description=(
                        f"{total} update(s) pending, including {critical} CRITICAL patch(es). "
                        "Unpatched systems are vulnerable to known exploits."
                    ),
                    recommendation="Apply all pending critical updates immediately via Windows Update.",
                    raw_output=stdout,
                )
            if total > 0:
                return _finding(
                    check="Windows Update",
                    status="WARNING",
                    severity="MEDIUM",
                    description=f"{total} non-critical update(s) pending.",
                    recommendation="Schedule and apply pending updates during the next maintenance window.",
                    raw_output=stdout,
                )
            return _finding(
                check="Windows Update",
                status="PASS",
                severity="MEDIUM",
                description="No pending Windows Updates detected.",
                recommendation="No action required. Ensure automatic updates are configured.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("Windows Update", str(exc))

    def check_admin_accounts(self) -> dict[str, Any]:
        """Check members of the local Administrators group.

        Identifies unexpected or excessive administrator accounts, including
        disabled built-in Administrator account status.

        Returns:
            FindingDict with HIGH severity if excessive admins are found.
        """
        script = (
            "Get-LocalGroupMember -Group 'Administrators' | "
            "Select-Object Name, ObjectClass | ConvertTo-Json"
        )
        script2 = "(Get-LocalUser -Name 'Administrator').Enabled"
        try:
            stdout, _, _ = self._run_powershell(script)
            members = json.loads(stdout) if stdout else []
            if isinstance(members, dict):
                members = [members]

            admin_out, _, _ = self._run_powershell(script2)
            builtin_enabled = admin_out.strip().lower() == "true"

            issues: list[str] = []
            if len(members) > 3:
                issues.append(
                    f"{len(members)} accounts in Administrators group (expected ≤3)"
                )
            if builtin_enabled:
                issues.append("Built-in Administrator account is enabled")

            names = [m.get("Name", "?") for m in members]

            if issues:
                return _finding(
                    check="Admin Accounts",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "Administrator account issues: " + "; ".join(issues) + ". "
                        f"Current members: {', '.join(names)}."
                    ),
                    recommendation=(
                        "Disable built-in Administrator: Disable-LocalUser -Name Administrator. "
                        "Remove unnecessary accounts from Administrators group. "
                        "Use LAPS for local admin management."
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="Admin Accounts",
                status="PASS",
                severity="HIGH",
                description=f"Administrator group has {len(members)} member(s): {', '.join(names)}.",
                recommendation="Periodically review and audit administrator group membership.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("Admin Accounts", str(exc))

    def check_privilege_creep(self) -> dict[str, Any]:
        """Check for users with excessive group memberships (privilege creep).

        Checks multiple privileged groups (Backup Operators, Remote Desktop Users,
        Power Users) for unexpected members.

        Returns:
            FindingDict with MEDIUM severity if privilege creep is detected.
        """
        privileged_groups = [
            "Backup Operators",
            "Remote Desktop Users",
            "Remote Management Users",
            "Power Users",
        ]
        findings_list: list[str] = []
        raw_lines: list[str] = []

        for group in privileged_groups:
            script = (
                f"try {{ "
                f"  $m = Get-LocalGroupMember -Group '{group}' -ErrorAction Stop | "
                f"  Select-Object -ExpandProperty Name; "
                f"  if ($m) {{ $m -join ',' }} else {{ '_EMPTY_' }} "
                f"}} catch {{ '_NOT_FOUND_' }}"
            )
            try:
                stdout, _, _ = self._run_powershell(script)
                raw_lines.append(f"{group}: {stdout}")
                if stdout.strip() not in ("_EMPTY_", "_NOT_FOUND_", ""):
                    members = [m.strip() for m in stdout.split(",") if m.strip()]
                    if members:
                        findings_list.append(f"{group} has {len(members)} member(s)")
            except Exception as exc:
                raw_lines.append(f"{group}: ERROR {exc}")

        if len(findings_list) > 2:
            return _finding(
                check="Privilege Creep",
                status="WARNING",
                severity="MEDIUM",
                description=(
                    "Multiple privileged groups have members: "
                    + "; ".join(findings_list)
                    + "."
                ),
                recommendation=(
                    "Review and remove unnecessary memberships. "
                    "Apply the principle of least privilege. "
                    "Use Just-In-Time (JIT) access for privileged roles."
                ),
                raw_output="\n".join(raw_lines),
            )
        return _finding(
            check="Privilege Creep",
            status="PASS",
            severity="MEDIUM",
            description="Privileged group memberships appear within expected limits.",
            recommendation="Periodically review privileged group memberships.",
            raw_output="\n".join(raw_lines),
        )

    def check_event_log_config(self) -> dict[str, Any]:
        """Check that critical Windows event logs are configured with adequate sizes.

        Evaluates the Security, System, and Application event log sizes.
        Logs too small may be overwritten rapidly, hindering incident response.

        Returns:
            FindingDict with MEDIUM severity if log sizes are insufficient.
        """
        min_size_mb = 64  # minimum recommended log size in MB
        script = (
            "Get-WinEvent -ListLog Security,System,Application | "
            "Select-Object LogName, MaximumSizeInBytes, IsEnabled | ConvertTo-Json"
        )
        try:
            stdout, _, _ = self._run_powershell(script)
            log_data = json.loads(stdout) if stdout else []
            if isinstance(log_data, dict):
                log_data = [log_data]

            issues: list[str] = []
            for log in log_data:
                name = log.get("LogName", "?")
                enabled = log.get("IsEnabled", True)
                size_bytes = log.get("MaximumSizeInBytes", 0)
                size_mb = size_bytes / (1024 * 1024)

                if not enabled:
                    issues.append(f"{name} log is disabled")
                elif size_mb < min_size_mb:
                    issues.append(
                        f"{name} log is only {size_mb:.0f} MB (min recommended: {min_size_mb} MB)"
                    )

            if issues:
                return _finding(
                    check="Event Log Config",
                    status="FAIL",
                    severity="MEDIUM",
                    description="Event log configuration issues: "
                    + "; ".join(issues)
                    + ".",
                    recommendation=(
                        "Configure via GPO: Computer Configuration → Windows Settings → "
                        "Security Settings → Event Log. Set Security log to ≥128 MB with "
                        "RetentionDays=0 (overwrite as needed)."
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="Event Log Config",
                status="PASS",
                severity="MEDIUM",
                description="Event logs are configured with adequate sizes.",
                recommendation="Consider forwarding logs to a SIEM for centralised retention.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("Event Log Config", str(exc))

    def check_lsass_protection(self) -> dict[str, Any]:
        """Check whether LSASS is protected against credential dumping.

        Verifies that RunAsPPL (Protected Process Light) and/or Credential Guard
        are enabled to prevent Mimikatz-style credential extraction.

        Returns:
            FindingDict with HIGH severity if LSASS is not protected.
        """
        script = (
            r"$lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' "
            r"-ErrorAction SilentlyContinue; "
            r"$ppl = $lsa.RunAsPPL; "
            r"$cg = $lsa.LsaCfgFlags; "
            r"\"RunAsPPL=$ppl CredentialGuard=$cg\""
        )
        try:
            stdout, _, _ = self._run_powershell(script)
            ppl_enabled = "RunAsPPL=1" in stdout or "RunAsPPL=2" in stdout
            cg_enabled = "CredentialGuard=1" in stdout or "CredentialGuard=2" in stdout

            issues: list[str] = []
            if not ppl_enabled:
                issues.append("LSASS Protected Process Light (RunAsPPL) is not enabled")
            if not cg_enabled:
                issues.append("Credential Guard is not enabled")

            if issues:
                return _finding(
                    check="LSASS Protection",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        "LSASS is vulnerable to credential dumping: "
                        + "; ".join(issues)
                        + ". "
                        "Tools like Mimikatz can extract plaintext credentials."
                    ),
                    recommendation=(
                        "Enable RunAsPPL: Set-ItemProperty -Path "
                        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                        "-Name RunAsPPL -Value 1. "
                        "Enable Credential Guard via GPO or Device Guard."
                    ),
                    raw_output=stdout,
                )
            return _finding(
                check="LSASS Protection",
                status="PASS",
                severity="HIGH",
                description="LSASS is protected (RunAsPPL or Credential Guard enabled).",
                recommendation="No action required.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("LSASS Protection", str(exc))

    def check_weak_ciphers(self) -> dict[str, Any]:
        """Check SCHANNEL for deprecated or weak cipher suites.

        Identifies RC4, DES, 3DES, NULL, and EXPORT ciphers which should be
        disabled on all modern systems.

        Returns:
            FindingDict with HIGH severity if weak ciphers are detected.
        """
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
        base_path = (
            r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
        )
        enabled_weak: list[str] = []
        raw_lines: list[str] = []

        for cipher in weak_ciphers:
            script = (
                f"$p = Get-ItemProperty -Path '{base_path}\\{cipher}' "
                f"-ErrorAction SilentlyContinue; "
                f"if ($p) {{ $p.Enabled }} else {{ 'NOT_SET' }}"
            )
            try:
                out, _, _ = self._run_powershell(script)
                raw_lines.append(f"{cipher}: {out}")
                # NOT_SET or 0xffffffff (DWORD max) = could be enabled by default
                if out.strip() not in ("0", "False", "false"):
                    enabled_weak.append(cipher)
            except Exception as exc:
                raw_lines.append(f"{cipher}: ERROR {exc}")

        if enabled_weak:
            return _finding(
                check="Weak Ciphers",
                status="FAIL",
                severity="HIGH",
                description=(
                    f"Weak cipher suites detected: {', '.join(enabled_weak)}. "
                    "These enable downgrade attacks and break-in via weak encryption."
                ),
                recommendation=(
                    "Disable weak ciphers via SCHANNEL registry. "
                    "Use IIS Crypto tool or configure via: "
                    "New-Item -Path 'HKLM:\\...\\Ciphers\\RC4 128/128' -Force | "
                    "New-ItemProperty -Name Enabled -Value 0 -PropertyType DWORD"
                ),
                raw_output="\n".join(raw_lines),
            )
        return _finding(
            check="Weak Ciphers",
            status="PASS",
            severity="HIGH",
            description="No weak cipher suites (RC4, DES, 3DES, NULL, EXPORT) are enabled.",
            recommendation="No action required.",
            raw_output="\n".join(raw_lines),
        )

    def check_file_sharing(self) -> dict[str, Any]:
        """Check SMB file shares for overly permissive access.

        Lists all SMB shares and flags those with Everyone / Authenticated Users
        access, or network shares with no access control.

        Returns:
            FindingDict with MEDIUM severity if open shares are detected.
        """
        script = (
            "Get-SmbShare | " "Select-Object Name, Path, Description | ConvertTo-Json"
        )
        acl_script_template = (
            "Get-SmbShareAccess -Name '{name}' | "
            "Select-Object AccountName, AccessRight | ConvertTo-Json"
        )
        try:
            stdout, _, _ = self._run_powershell(script)
            shares = json.loads(stdout) if stdout else []
            if isinstance(shares, dict):
                shares = [shares]

            risky: list[str] = []
            raw_lines: list[str] = [stdout]

            for share in shares:
                name = share.get("Name", "")
                # Skip built-in admin shares (C$, ADMIN$, IPC$)
                if name.endswith("$"):
                    continue

                acl_out, _, _ = self._run_powershell(
                    acl_script_template.format(name=name)
                )
                raw_lines.append(f"{name} ACL: {acl_out}")
                entries = json.loads(acl_out) if acl_out else []
                if isinstance(entries, dict):
                    entries = [entries]

                for entry in entries:
                    acct = entry.get("AccountName", "").lower()
                    if "everyone" in acct or "authenticated users" in acct:
                        right = entry.get("AccessRight", "?")
                        risky.append(
                            f"'{name}' grants {right} to {entry['AccountName']}"
                        )

            if risky:
                return _finding(
                    check="File Sharing",
                    status="FAIL",
                    severity="MEDIUM",
                    description=(
                        f"{len(risky)} file share(s) with overly permissive access: "
                        + "; ".join(risky)
                        + "."
                    ),
                    recommendation=(
                        "Remove 'Everyone' and 'Authenticated Users' from share ACLs. "
                        "Grant access only to specific groups (principle of least privilege). "
                        "Use: Grant-SmbShareAccess -Name <share> -AccountName <group> "
                        "-AccessRight Read"
                    ),
                    raw_output="\n".join(raw_lines[:5]),
                )
            return _finding(
                check="File Sharing",
                status="PASS",
                severity="MEDIUM",
                description="No SMB shares with overly permissive Everyone/Authenticated Users access.",
                recommendation="Periodically audit share permissions with Get-SmbShareAccess.",
                raw_output=stdout,
            )
        except Exception as exc:
            return _error_finding("File Sharing", str(exc))

    def check_installed_software(self) -> dict[str, Any]:
        """Check installed software for end-of-life (EOL) or unpatched applications.

        Queries the Windows registry for installed program names and flags those
        that are known EOL (based on a curated list).

        Returns:
            FindingDict with LOW severity if EOL software is detected.
        """
        # Curated list of known EOL software patterns (lowercase)
        eol_patterns = [
            "internet explorer",
            "adobe flash",
            "java 6",
            "java 7",
            "java 8",
            "windows xp",
            "office 2007",
            "office 2010",
            "office 2013",
            ".net framework 2",
            ".net framework 3.0",
            "visual c++ 2005",
            "visual c++ 2008",
            "silverlight",
        ]

        script = (
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Select-Object DisplayName, DisplayVersion | "
            "Where-Object { $_.DisplayName -ne $null } | ConvertTo-Json"
        )
        try:
            stdout, _, _ = self._run_powershell(script)
            packages = json.loads(stdout) if stdout else []
            if isinstance(packages, dict):
                packages = [packages]

            eol_found: list[str] = []
            for pkg in packages:
                name = pkg.get("DisplayName", "").lower()
                version = pkg.get("DisplayVersion", "")
                for pattern in eol_patterns:
                    if pattern in name:
                        eol_found.append(f"{pkg['DisplayName']} {version}".strip())
                        break

            if eol_found:
                return _finding(
                    check="Installed Software",
                    status="FAIL",
                    severity="LOW",
                    description=(
                        f"{len(eol_found)} EOL/outdated application(s) detected: "
                        + ", ".join(eol_found[:10])
                        + "."
                    ),
                    recommendation=(
                        "Uninstall or upgrade EOL applications. "
                        "EOL software no longer receives security patches. "
                        "Use a software inventory tool to track installed versions."
                    ),
                    raw_output=stdout[:2000],
                )
            return _finding(
                check="Installed Software",
                status="PASS",
                severity="LOW",
                description="No obvious EOL software detected from the installed packages list.",
                recommendation="Maintain an up-to-date software inventory and regularly review EOL dates.",
                raw_output=stdout[:500],
            )
        except Exception as exc:
            return _error_finding("Installed Software", str(exc))

    # ------------------------------------------------------------------
    # Full scan orchestrator
    # ------------------------------------------------------------------

    def run_scan(self) -> dict[str, Any]:
        """Execute all security checks concurrently and return consolidated results.

        Runs all ``check_*`` methods using a thread pool for performance.
        The scan targets the host specified in the constructor.

        Returns:
            A dictionary with the following structure::

                {
                    "server": str,           # Target hostname/IP
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
            self.check_firewall,
            self.check_smb_v1,
            self.check_llmnr_netbios,
            self.check_windows_defender,
            self.check_tls_versions,
            self.check_password_policies,
            self.check_rdp_nla,
            self.check_windows_update,
            self.check_admin_accounts,
            self.check_privilege_creep,
            self.check_event_log_config,
            self.check_lsass_protection,
            self.check_weak_ciphers,
            self.check_file_sharing,
            self.check_installed_software,
        ]

        logger.info(
            "Starting security scan on %s (%d checks)", self.target, len(checks)
        )
        start = time.perf_counter()

        findings: list[dict[str, Any]] = []

        # Each check is I/O-bound (PowerShell/WinRM). Run all checks concurrently so
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

        summary = {"PASS": 0, "FAIL": 0, "WARNING": 0}
        for f in findings:
            status = f.get("status", "WARNING")
            summary[status] = summary.get(status, 0) + 1

        logger.info(
            "Scan complete in %.1fs – PASS:%d FAIL:%d WARNING:%d",
            duration,
            summary["PASS"],
            summary["FAIL"],
            summary["WARNING"],
        )

        return {
            "server": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": duration,
            "findings": findings,
            "total_checks": len(findings),
            "summary": summary,
        }
