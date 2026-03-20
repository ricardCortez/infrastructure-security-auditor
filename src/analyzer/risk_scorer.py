"""Risk Scorer module for Infrastructure Security Auditor.

Provides :class:`RiskScorer` with stateless methods for computing
weighted risk scores from a list of security findings.
"""

from __future__ import annotations

from typing import Any

from src.config import SEVERITY_ORDER, SEVERITY_WEIGHTS


class RiskScorer:
    """Stateless helper for computing risk metrics from security findings.

    All methods are static to facilitate unit testing in isolation
    without requiring an instance.
    """

    @staticmethod
    def calculate_score(findings: list[dict[str, Any]]) -> float:
        """Compute a risk score between 0 and 10 from a list of findings.

        Only findings with status ``"FAIL"`` or ``"WARNING"`` contribute to the
        score.  The score is a weighted average where weights reflect severity:
        ``CRITICAL=10``, ``HIGH=7``, ``MEDIUM=4``, ``LOW=1``.

        Args:
            findings: List of FindingDict objects returned by the scanner.

        Returns:
            Float in the range ``[0.0, 10.0]``.  Returns ``0.0`` for an empty
            list or if all checks pass.

        Example:
            >>> findings = [
            ...     {"status": "FAIL", "severity": "HIGH"},
            ...     {"status": "PASS", "severity": "CRITICAL"},
            ... ]
            >>> RiskScorer.calculate_score(findings)
            7.0
        """
        active = [f for f in findings if f.get("status") in ("FAIL", "WARNING")]
        if not active:
            return 0.0

        total_weight = sum(
            SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 1) for f in active
        )
        max_possible = len(active) * 10  # if every active finding were CRITICAL

        raw_score = (total_weight / max_possible) * 10 if max_possible > 0 else 0.0
        return round(min(raw_score, 10.0), 2)

    @staticmethod
    def severity_distribution(findings: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings per severity level.

        Args:
            findings: List of FindingDict objects.

        Returns:
            Dictionary mapping severity label to count, ordered
            ``CRITICAL → HIGH → MEDIUM → LOW``.

        Example:
            >>> RiskScorer.severity_distribution([
            ...     {"severity": "HIGH", "status": "FAIL"},
            ...     {"severity": "CRITICAL", "status": "FAIL"},
            ... ])
            {'CRITICAL': 1, 'HIGH': 1, 'MEDIUM': 0, 'LOW': 0}
        """
        dist: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in dist:
                dist[sev] += 1
        return dist

    @staticmethod
    def risk_label(score: float) -> str:
        """Convert a numeric score to a human-readable risk label.

        Args:
            score: Numeric risk score in ``[0.0, 10.0]``.

        Returns:
            One of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``,
            or ``"MINIMAL"``.
        """
        if score >= 8.5:
            return "CRITICAL"
        if score >= 6.5:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 1.5:
            return "LOW"
        return "MINIMAL"

    @staticmethod
    def compliance_percentage(
        findings: list[dict[str, Any]],
        standard: str,
        compliance_controls: dict[str, dict[str, list[str]]],
        total_controls: dict[str, int],
    ) -> float:
        """Estimate compliance percentage for a given standard.

        Counts how many controls from ``standard`` are covered by PASS findings,
        then divides by the total control count for that standard.

        Args:
            findings: List of FindingDict objects.
            standard: Standard key, e.g. ``"ISO_27001"``, ``"CIS_Benchmarks"``,
                ``"PCI_DSS"``.
            compliance_controls: Mapping of check name → standard → control IDs.
            total_controls: Total number of controls per standard.

        Returns:
            Float in ``[0.0, 1.0]`` representing compliance percentage.
        """
        failing_controls: set[str] = set()
        for finding in findings:
            if finding.get("status") == "PASS":
                continue
            check_name = finding.get("check", "")
            controls = compliance_controls.get(check_name, {}).get(standard, [])
            failing_controls.update(controls)

        total = total_controls.get(standard, 1)
        failed_count = len(failing_controls)
        passed_count = max(0, total - failed_count)
        return round(passed_count / total, 4)
