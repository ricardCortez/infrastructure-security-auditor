"""Infrastructure Security Auditor – src package.

Automated Windows security auditing tool that scans hosts for
misconfigurations, scores risk, maps findings to compliance frameworks,
and generates standalone HTML reports with AI-powered recommendations.

Modules:
    scanner:    PowerShell-based security checks (WindowsScanner)
    analyzer:   Risk scoring and compliance mapping (Analyzer, RiskScorer)
    reporter:   Standalone HTML report generation (HTMLReporter)
    remediator: Automated remediation playbook generation (Phase 2)
    cli:        Click CLI commands (scan, analyze, report, version)
    config:     Environment variables and application constants
"""

__version__ = "0.1.0"
__author__ = "Infrastructure Security Auditor Team"
