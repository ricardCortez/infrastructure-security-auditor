"""Analyzer package – risk scoring and compliance mapping.

Processes WindowsScanner findings to produce a comprehensive security
analysis: CVSS-inspired risk scores, ISO 27001 / CIS / PCI-DSS compliance
percentages, and prioritised remediation recommendations via Claude AI.

Classes:
    Analyzer:    Orchestrates analysis from a list of FindingDict objects.
    RiskScorer:  Stateless helper with @staticmethod scoring methods.

Example:
    >>> from src.analyzer import Analyzer
    >>> analyzer = Analyzer(scan_results["findings"])
    >>> analysis = analyzer.analyze()
    >>> print(f"{analysis['risk_score']}/10 ({analysis['risk_label']})")
    6.8/10 (HIGH)
"""

from src.analyzer.analyzer import Analyzer
from src.analyzer.risk_scorer import RiskScorer

__all__ = ["Analyzer", "RiskScorer"]
