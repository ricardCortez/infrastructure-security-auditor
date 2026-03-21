from typing import List
from .schema import Finding, Severity
import logging

logger = logging.getLogger(__name__)


class ResultParser:
    """Parses raw scanner output into normalized Finding objects."""

    @staticmethod
    def parse_nessus_results(raw_results: list, asset_id: int) -> List[Finding]:
        """Parse Nessus vulnerability results into Finding objects.

        Args:
            raw_results: List of raw Nessus vulnerability dictionaries.
            asset_id: Asset ID to associate findings with.

        Returns:
            List of normalized Finding objects.
        """
        findings = []
        for vuln in raw_results:
            severity_map = {4: Severity.CRITICAL, 3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW, 0: Severity.INFO}
            severity = severity_map.get(vuln.get('severity', 0), Severity.INFO)
            findings.append(Finding(
                asset_id=asset_id,
                title=vuln.get('plugin_name', 'Unknown'),
                severity=severity,
                cvss_score=vuln.get('cvss_base_score'),
                plugin_id=str(vuln.get('plugin_id')),
                source='nessus',
            ))
        return findings

    @staticmethod
    def parse_openvas_results(raw_results: list, asset_id: int) -> List[Finding]:
        """Parse OpenVAS vulnerability results into Finding objects.

        Args:
            raw_results: List of raw OpenVAS result dictionaries.
            asset_id: Asset ID to associate findings with.

        Returns:
            List of normalized Finding objects.
        """
        findings = []
        for result in raw_results:
            findings.append(Finding(
                asset_id=asset_id,
                title=result.get('name', 'Unknown'),
                severity=Severity.MEDIUM,
                source='openvas',
            ))
        return findings
