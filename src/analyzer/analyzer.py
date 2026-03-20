"""Analyzer module for Infrastructure Security Auditor.

Provides :class:`Analyzer` which processes scanner findings to produce
a comprehensive security analysis including risk scores, compliance mappings,
and AI-powered recommendations via the Anthropic Claude API.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.analyzer.risk_scorer import RiskScorer
from src.config import (
    CLAUDE_API_KEY,
    CLAUDE_MODEL,
    COMPLIANCE_CONTROLS,
    SEVERITY_ORDER,
    TOTAL_CONTROLS,
)

# ---------------------------------------------------------------------------
# Static fallback recommendations (used when Claude API is unavailable)
# ---------------------------------------------------------------------------

_STATIC_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "SMBv1 Protocol": {
        "action": "Disable SMBv1 immediately",
        "command": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        "effort": "Low",
        "timeline": "Immediate",
    },
    "LSASS Protection": {
        "action": "Enable LSASS Protected Process Light",
        "command": (
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name RunAsPPL -Value 1"
        ),
        "effort": "Low",
        "timeline": "Within 24 hours",
    },
    "Firewall Status": {
        "action": "Enable Windows Firewall on all profiles",
        "command": "Set-NetFirewallProfile -All -Enabled True",
        "effort": "Low",
        "timeline": "Immediate",
    },
    "RDP NLA": {
        "action": "Enable Network Level Authentication for RDP",
        "command": (
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\"
            "Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"
        ),
        "effort": "Low",
        "timeline": "Within 24 hours",
    },
    "TLS Versions": {
        "action": "Disable deprecated TLS/SSL protocols via SCHANNEL registry",
        "command": "Use IIS Crypto tool or configure SCHANNEL registry keys manually.",
        "effort": "Medium",
        "timeline": "Within 1 week",
    },
    "Windows Defender": {
        "action": "Enable Windows Defender and update signatures",
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature"
        ),
        "effort": "Low",
        "timeline": "Immediate",
    },
    "Password Policies": {
        "action": "Enforce password complexity, minimum length ≥12, max age ≤90 days",
        "command": "Configure via Group Policy: Account Policies → Password Policy",
        "effort": "Medium",
        "timeline": "Within 1 week",
    },
    "LLMNR/NetBIOS": {
        "action": "Disable LLMNR and NetBIOS via GPO and NIC settings",
        "command": "GPO: Turn Off Multicast Name Resolution = Enabled",
        "effort": "Medium",
        "timeline": "Within 1 week",
    },
    "Admin Accounts": {
        "action": "Disable built-in Administrator and remove unnecessary admins",
        "command": "Disable-LocalUser -Name Administrator",
        "effort": "Medium",
        "timeline": "Within 48 hours",
    },
    "Windows Update": {
        "action": "Apply all pending critical patches",
        "command": "Start Windows Update and install all critical updates",
        "effort": "Medium",
        "timeline": "Within 48 hours",
    },
    "Weak Ciphers": {
        "action": "Disable RC4, DES, 3DES cipher suites via SCHANNEL",
        "command": "Use IIS Crypto to disable weak ciphers",
        "effort": "Medium",
        "timeline": "Within 1 week",
    },
    "Event Log Config": {
        "action": "Increase event log sizes and enable all critical logs",
        "command": "GPO: Computer Configuration → Security Settings → Event Log → 128MB+",
        "effort": "Low",
        "timeline": "Within 1 week",
    },
    "Privilege Creep": {
        "action": "Review and reduce privileged group memberships",
        "command": "Remove-LocalGroupMember for unnecessary accounts",
        "effort": "High",
        "timeline": "Within 2 weeks",
    },
    "File Sharing": {
        "action": "Remove Everyone/Authenticated Users from share ACLs",
        "command": "Revoke-SmbShareAccess -Name <share> -AccountName Everyone -Force",
        "effort": "Medium",
        "timeline": "Within 1 week",
    },
    "Installed Software": {
        "action": "Uninstall or upgrade EOL applications",
        "command": "Use Add/Remove Programs or winget to remove obsolete software",
        "effort": "High",
        "timeline": "Within 1 month",
    },
}


class Analyzer:
    """Analyzes security scanner findings to produce a comprehensive risk report.

    Combines rule-based risk scoring with optional Claude AI analysis to
    generate prioritized remediation recommendations and compliance mappings.

    Args:
        findings: List of FindingDict objects returned by :class:`WindowsScanner`.

    Example:
        >>> from src.analyzer.analyzer import Analyzer
        >>> analyzer = Analyzer(scan_results["findings"])
        >>> analysis = analyzer.analyze()
        >>> print(analysis["risk_score"])
        7.4
    """

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        self._logger = logging.getLogger("auditor.analyzer")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calculate_risk_score(self) -> float:
        """Calculate a weighted risk score (0–10) from the current findings.

        Only FAIL and WARNING findings contribute to the score, weighted by
        severity: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1.

        Returns:
            Float in ``[0.0, 10.0]``.
        """
        return RiskScorer.calculate_score(self.findings)

    def assign_severity_distribution(self) -> dict[str, int]:
        """Count findings per severity level.

        Returns:
            Dict ``{"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n}``.
        """
        return RiskScorer.severity_distribution(self.findings)

    def map_to_compliance(self) -> dict[str, float]:
        """Map findings to compliance framework percentages.

        Returns:
            Dict with float values (0.0–1.0) for each standard::

                {
                    "ISO_27001": 0.85,
                    "CIS_Benchmarks": 0.78,
                    "PCI_DSS": 0.72,
                }
        """
        standards = ["ISO_27001", "CIS_Benchmarks", "PCI_DSS"]
        return {
            std: RiskScorer.compliance_percentage(
                self.findings,
                std,
                COMPLIANCE_CONTROLS,
                TOTAL_CONTROLS,
            )
            for std in standards
        }

    def generate_recommendations(self) -> list[dict[str, Any]]:
        """Generate prioritized remediation recommendations.

        Attempts to use the Claude API for AI-powered analysis.  Falls back
        to the built-in static recommendations if the API is unavailable or
        the key is not configured.

        Returns:
            List of recommendation dicts ordered by severity (CRITICAL first)::

                [
                    {
                        "check": str,
                        "severity": str,
                        "action": str,
                        "command": str,
                        "effort": str,      # Low / Medium / High
                        "timeline": str,
                    },
                    ...
                ]
        """
        failing = [f for f in self.findings if f.get("status") in ("FAIL", "WARNING")]

        if not failing:
            return []

        if CLAUDE_API_KEY:
            try:
                return self._claude_recommendations(failing)
            except Exception as exc:
                self._logger.warning(
                    "Claude API call failed (%s). Using static recommendations.", exc
                )

        return self._static_recommendations(failing)

    def analyze(self) -> dict[str, Any]:
        """Orchestrate all analysis methods and return a full analysis report.

        Returns:
            Dictionary containing the complete analysis::

                {
                    "risk_score": float,
                    "risk_label": str,
                    "severity_distribution": dict,
                    "compliance": dict,
                    "recommendations": list,
                    "findings": list,
                    "total_checks": int,
                    "summary": {"PASS": int, "FAIL": int, "WARNING": int},
                }
        """
        self._logger.info("Analyzing %d findings...", len(self.findings))

        risk_score = self.calculate_risk_score()
        risk_label = RiskScorer.risk_label(risk_score)
        distribution = self.assign_severity_distribution()
        compliance = self.map_to_compliance()
        recommendations = self.generate_recommendations()

        summary = {"PASS": 0, "FAIL": 0, "WARNING": 0}
        for f in self.findings:
            status = f.get("status", "WARNING")
            summary[status] = summary.get(status, 0) + 1

        return {
            "risk_score": risk_score,
            "risk_label": risk_label,
            "severity_distribution": distribution,
            "compliance": compliance,
            "recommendations": recommendations,
            "findings": self.findings,
            "total_checks": len(self.findings),
            "summary": summary,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _claude_recommendations(
        self, failing_findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Call the Anthropic Claude API to generate contextual recommendations.

        Args:
            failing_findings: Subset of findings with FAIL/WARNING status.

        Returns:
            List of recommendation dicts as described in :meth:`generate_recommendations`.

        Raises:
            anthropic.APIError: If the API call fails.
            json.JSONDecodeError: If the response is not valid JSON.
        """
        import anthropic  # lazy import – only needed when API is available

        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)

        # Build a concise prompt to avoid excessive token usage
        findings_summary = [
            {
                "check": f.get("check"),
                "status": f.get("status"),
                "severity": f.get("severity"),
                "description": f.get("description"),
            }
            for f in failing_findings[:10]  # limit to top 10
        ]

        prompt = (
            "You are a Windows security expert. Below are security findings from an "
            "automated infrastructure audit. For each finding, provide a concise "
            "remediation recommendation.\n\n"
            "Return ONLY a JSON array with this structure (no extra text):\n"
            "[\n"
            "  {\n"
            '    "check": "<finding name>",\n'
            '    "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",\n'
            '    "action": "<one-line action>",\n'
            '    "command": "<PowerShell command or GPO path>",\n'
            '    "effort": "<Low|Medium|High>",\n'
            '    "timeline": "<Immediate|Within 24 hours|Within 1 week|etc>"\n'
            "  }\n"
            "]\n\n"
            f"Findings:\n{json.dumps(findings_summary, indent=2)}"
        )

        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        content = message.content[0].text.strip()
        recommendations: list[dict[str, Any]] = json.loads(content)

        # Sort by severity order
        severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
        recommendations.sort(
            key=lambda r: severity_rank.get(r.get("severity", "LOW"), 99)
        )
        return recommendations

    def _static_recommendations(
        self, failing_findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Generate recommendations from the static lookup table.

        Args:
            failing_findings: Subset of findings with FAIL/WARNING status.

        Returns:
            List of recommendation dicts ordered by severity.
        """
        recs: list[dict[str, Any]] = []
        severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}

        for finding in failing_findings:
            check = finding.get("check", "")
            severity = finding.get("severity", "LOW")
            static = _STATIC_RECOMMENDATIONS.get(check, {})

            recs.append(
                {
                    "check": check,
                    "severity": severity,
                    "action": static.get(
                        "action",
                        finding.get(
                            "recommendation", "Review and remediate this finding."
                        ),
                    ),
                    "command": static.get("command", "See documentation."),
                    "effort": static.get("effort", "Medium"),
                    "timeline": static.get("timeline", "Within 2 weeks"),
                }
            )

        recs.sort(key=lambda r: severity_rank.get(r.get("severity", "LOW"), 99))
        return recs
