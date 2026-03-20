"""Comprehensive tests for Analyzer and RiskScorer.

Covers:
- RiskScorer.calculate_score: weights, edge cases, PASS vs FAIL
- RiskScorer.severity_distribution: counting per severity
- RiskScorer.risk_label: all threshold bands
- RiskScorer.compliance_percentage: known controls, unknown standard
- Analyzer.analyze: full orchestration, key presence, summary counts
- Analyzer._static_recommendations: ordering, keys, fallback
- Analyzer.generate_recommendations: API key present/absent, exception fallback
- Analyzer._claude_recommendations: mocked API call
"""

from __future__ import annotations

from src.analyzer.analyzer import Analyzer
from src.analyzer.risk_scorer import RiskScorer
from src.config import COMPLIANCE_CONTROLS, TOTAL_CONTROLS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_finding(
    check: str = "Test Check",
    status: str = "FAIL",
    severity: str = "HIGH",
) -> dict:
    return {
        "check": check,
        "status": status,
        "severity": severity,
        "description": f"{check} is {status}",
        "recommendation": "Fix it.",
        "raw_output": None,
    }


# ---------------------------------------------------------------------------
# RiskScorer.calculate_score
# ---------------------------------------------------------------------------


class TestRiskScorerCalculateScore:

    def test_empty_list_returns_zero(self) -> None:
        assert RiskScorer.calculate_score([]) == 0.0

    def test_all_pass_returns_zero(self) -> None:
        findings = [
            make_finding(status="PASS", severity="CRITICAL"),
            make_finding(status="PASS", severity="HIGH"),
        ]
        assert RiskScorer.calculate_score(findings) == 0.0

    def test_single_critical_fail_returns_ten(self) -> None:
        assert RiskScorer.calculate_score([make_finding(severity="CRITICAL")]) == 10.0

    def test_single_high_fail_score(self) -> None:
        # weight=7, max_possible=10 → 7/10*10 = 7.0
        assert RiskScorer.calculate_score([make_finding(severity="HIGH")]) == 7.0

    def test_single_medium_fail_score(self) -> None:
        # weight=4 → 4.0
        assert RiskScorer.calculate_score([make_finding(severity="MEDIUM")]) == 4.0

    def test_single_low_fail_score(self) -> None:
        # weight=1 → 1.0
        assert RiskScorer.calculate_score([make_finding(severity="LOW")]) == 1.0

    def test_warning_status_contributes_to_score(self) -> None:
        findings = [make_finding(status="WARNING", severity="HIGH")]
        assert RiskScorer.calculate_score(findings) == 7.0

    def test_pass_ignored_in_weighted_score(self) -> None:
        findings = [
            make_finding(status="FAIL", severity="HIGH"),
            make_finding(status="PASS", severity="CRITICAL"),
            make_finding(status="PASS", severity="MEDIUM"),
        ]
        # Only the FAIL HIGH contributes: weight=7, max_possible=10 → 7.0
        assert RiskScorer.calculate_score(findings) == 7.0

    def test_score_always_in_0_to_10_range(self) -> None:
        findings = [make_finding(status="FAIL", severity="CRITICAL") for _ in range(20)]
        score = RiskScorer.calculate_score(findings)
        assert 0.0 <= score <= 10.0

    def test_score_is_float(self) -> None:
        score = RiskScorer.calculate_score([make_finding(severity="HIGH")])
        assert isinstance(score, float)

    def test_score_rounded_to_two_decimals(self) -> None:
        findings = [
            make_finding(severity="HIGH"),
            make_finding(severity="MEDIUM"),
            make_finding(severity="LOW"),
        ]
        score = RiskScorer.calculate_score(findings)
        assert score == round(score, 2)

    def test_mixed_active_statuses_contribute(self) -> None:
        findings = [
            make_finding(status="FAIL", severity="CRITICAL"),
            make_finding(status="WARNING", severity="LOW"),
        ]
        score = RiskScorer.calculate_score(findings)
        # (10+1)/(2*10)*10 = 5.5
        assert score == 5.5


# ---------------------------------------------------------------------------
# RiskScorer.severity_distribution
# ---------------------------------------------------------------------------


class TestRiskScorerSeverityDistribution:

    def test_empty_findings_all_zeros(self) -> None:
        dist = RiskScorer.severity_distribution([])
        assert dist == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def test_all_four_severity_keys_always_present(self) -> None:
        dist = RiskScorer.severity_distribution([])
        assert set(dist.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_counts_each_severity_correctly(self) -> None:
        findings = [
            make_finding(severity="CRITICAL"),
            make_finding(severity="HIGH"),
            make_finding(severity="HIGH"),
            make_finding(severity="MEDIUM"),
        ]
        dist = RiskScorer.severity_distribution(findings)
        assert dist["CRITICAL"] == 1
        assert dist["HIGH"] == 2
        assert dist["MEDIUM"] == 1
        assert dist["LOW"] == 0

    def test_unknown_severity_not_counted(self) -> None:
        findings = [{"status": "FAIL", "severity": "EXTREME"}]
        dist = RiskScorer.severity_distribution(findings)
        assert sum(dist.values()) == 0

    def test_counts_pass_findings_too(self) -> None:
        """Distribution counts ALL findings, not just FAIL."""
        findings = [
            make_finding(status="PASS", severity="CRITICAL"),
            make_finding(status="FAIL", severity="CRITICAL"),
        ]
        dist = RiskScorer.severity_distribution(findings)
        assert dist["CRITICAL"] == 2


# ---------------------------------------------------------------------------
# RiskScorer.risk_label
# ---------------------------------------------------------------------------


class TestRiskScorerRiskLabel:

    def test_critical_at_8_5(self) -> None:
        assert RiskScorer.risk_label(8.5) == "CRITICAL"

    def test_critical_at_10(self) -> None:
        assert RiskScorer.risk_label(10.0) == "CRITICAL"

    def test_high_just_below_critical(self) -> None:
        assert RiskScorer.risk_label(8.4) == "HIGH"

    def test_high_at_6_5(self) -> None:
        assert RiskScorer.risk_label(6.5) == "HIGH"

    def test_medium_just_below_high(self) -> None:
        assert RiskScorer.risk_label(6.4) == "MEDIUM"

    def test_medium_at_4_0(self) -> None:
        assert RiskScorer.risk_label(4.0) == "MEDIUM"

    def test_low_just_below_medium(self) -> None:
        assert RiskScorer.risk_label(3.9) == "LOW"

    def test_low_at_1_5(self) -> None:
        assert RiskScorer.risk_label(1.5) == "LOW"

    def test_minimal_just_below_low(self) -> None:
        assert RiskScorer.risk_label(1.4) == "MINIMAL"

    def test_minimal_at_zero(self) -> None:
        assert RiskScorer.risk_label(0.0) == "MINIMAL"


# ---------------------------------------------------------------------------
# RiskScorer.compliance_percentage
# ---------------------------------------------------------------------------


class TestRiskScorerCompliancePercentage:

    def test_no_failures_full_compliance(self) -> None:
        findings = [make_finding(status="PASS", severity="HIGH")]
        pct = RiskScorer.compliance_percentage(
            findings, "ISO_27001", COMPLIANCE_CONTROLS, TOTAL_CONTROLS
        )
        assert pct == 1.0

    def test_failing_firewall_reduces_iso27001(self) -> None:
        findings = [
            make_finding(check="Firewall Status", status="FAIL", severity="HIGH")
        ]
        pct = RiskScorer.compliance_percentage(
            findings, "ISO_27001", COMPLIANCE_CONTROLS, TOTAL_CONTROLS
        )
        assert 0.0 <= pct < 1.0

    def test_compliance_in_range_for_all_standards(self) -> None:
        findings = [
            make_finding(check="SMBv1 Protocol", status="FAIL", severity="CRITICAL"),
            make_finding(check="Windows Defender", status="FAIL", severity="HIGH"),
        ]
        for std in ("ISO_27001", "CIS_Benchmarks", "PCI_DSS"):
            pct = RiskScorer.compliance_percentage(
                findings, std, COMPLIANCE_CONTROLS, TOTAL_CONTROLS
            )
            assert 0.0 <= pct <= 1.0

    def test_unknown_standard_returns_one(self) -> None:
        findings = [make_finding(status="FAIL", severity="HIGH")]
        pct = RiskScorer.compliance_percentage(
            findings, "NIST_800_53", COMPLIANCE_CONTROLS, TOTAL_CONTROLS
        )
        # total_controls.get("NIST_800_53", 1) → total=1, failed_count=0 → 1.0
        assert pct == 1.0

    def test_multiple_failing_controls_reduce_percentage(self) -> None:
        findings = [
            make_finding(check="Firewall Status", status="FAIL", severity="HIGH"),
            make_finding(check="SMBv1 Protocol", status="FAIL", severity="CRITICAL"),
            make_finding(check="Windows Defender", status="FAIL", severity="HIGH"),
            make_finding(check="TLS Versions", status="FAIL", severity="HIGH"),
        ]
        pct_one = RiskScorer.compliance_percentage(
            findings[:1], "CIS_Benchmarks", COMPLIANCE_CONTROLS, TOTAL_CONTROLS
        )
        pct_four = RiskScorer.compliance_percentage(
            findings, "CIS_Benchmarks", COMPLIANCE_CONTROLS, TOTAL_CONTROLS
        )
        assert pct_four <= pct_one


# ---------------------------------------------------------------------------
# Analyzer.analyze – integration
# ---------------------------------------------------------------------------


class TestAnalyzerAnalyze:

    def test_returns_all_required_keys(self) -> None:
        result = Analyzer([]).analyze()
        expected = {
            "risk_score",
            "risk_label",
            "severity_distribution",
            "compliance",
            "recommendations",
            "findings",
            "total_checks",
            "summary",
        }
        assert expected.issubset(result.keys())

    def test_empty_findings_zero_score(self) -> None:
        result = Analyzer([]).analyze()
        assert result["risk_score"] == 0.0
        assert result["risk_label"] == "MINIMAL"
        assert result["recommendations"] == []
        assert result["total_checks"] == 0

    def test_critical_finding_produces_critical_label(self) -> None:
        findings = [make_finding(check="SMBv1 Protocol", severity="CRITICAL")]
        result = Analyzer(findings).analyze()
        assert result["risk_score"] == 10.0
        assert result["risk_label"] == "CRITICAL"

    def test_summary_counts_correct(self) -> None:
        findings = [
            make_finding(status="PASS"),
            make_finding(status="FAIL"),
            make_finding(status="WARNING"),
        ]
        result = Analyzer(findings).analyze()
        assert result["summary"]["PASS"] == 1
        assert result["summary"]["FAIL"] == 1
        assert result["summary"]["WARNING"] == 1

    def test_compliance_has_all_three_standards(self) -> None:
        result = Analyzer([]).analyze()
        assert "ISO_27001" in result["compliance"]
        assert "CIS_Benchmarks" in result["compliance"]
        assert "PCI_DSS" in result["compliance"]

    def test_compliance_values_in_range(self) -> None:
        result = Analyzer([]).analyze()
        for val in result["compliance"].values():
            assert 0.0 <= val <= 1.0

    def test_findings_list_preserved(self) -> None:
        findings = [make_finding(), make_finding(check="Other")]
        result = Analyzer(findings).analyze()
        assert result["findings"] is findings
        assert result["total_checks"] == 2

    def test_severity_distribution_counts(self) -> None:
        findings = [
            make_finding(severity="CRITICAL"),
            make_finding(severity="HIGH"),
            make_finding(severity="HIGH"),
        ]
        result = Analyzer(findings).analyze()
        dist = result["severity_distribution"]
        assert dist["CRITICAL"] == 1
        assert dist["HIGH"] == 2


# ---------------------------------------------------------------------------
# Analyzer._static_recommendations
# ---------------------------------------------------------------------------


class TestAnalyzerStaticRecommendations:

    def test_known_check_produces_recommendation(self) -> None:
        findings = [make_finding(check="Firewall Status", severity="HIGH")]
        recs = Analyzer(findings)._static_recommendations(findings)
        assert len(recs) == 1
        assert recs[0]["check"] == "Firewall Status"

    def test_multiple_findings_produce_multiple_recommendations(self) -> None:
        findings = [
            make_finding(check="SMBv1 Protocol", severity="CRITICAL"),
            make_finding(check="Firewall Status", severity="HIGH"),
        ]
        recs = Analyzer(findings)._static_recommendations(findings)
        assert len(recs) == 2

    def test_recommendations_sorted_critical_first(self) -> None:
        findings = [
            make_finding(check="Event Log Config", severity="MEDIUM"),
            make_finding(check="SMBv1 Protocol", severity="CRITICAL"),
            make_finding(check="Password Policies", severity="MEDIUM"),
        ]
        recs = Analyzer(findings)._static_recommendations(findings)
        assert recs[0]["severity"] == "CRITICAL"

    def test_recommendation_has_all_required_keys(self) -> None:
        findings = [make_finding(check="Firewall Status", severity="HIGH")]
        rec = Analyzer(findings)._static_recommendations(findings)[0]
        for key in ("check", "severity", "action", "command", "effort", "timeline"):
            assert key in rec, f"Missing key: {key}"

    def test_unknown_check_uses_fallback_values(self) -> None:
        findings = [make_finding(check="Unknown Security Check", severity="HIGH")]
        recs = Analyzer(findings)._static_recommendations(findings)
        assert len(recs) == 1
        assert recs[0]["check"] == "Unknown Security Check"
        assert recs[0]["action"] != ""  # has some fallback

    def test_all_15_known_checks_produce_specific_recommendations(self) -> None:
        known_checks = [
            "Firewall Status",
            "SMBv1 Protocol",
            "LLMNR/NetBIOS",
            "Windows Defender",
            "TLS Versions",
            "Password Policies",
            "RDP NLA",
            "Windows Update",
            "Admin Accounts",
            "Privilege Creep",
            "Event Log Config",
            "LSASS Protection",
            "Weak Ciphers",
            "File Sharing",
            "Installed Software",
        ]
        for check in known_checks:
            findings = [make_finding(check=check, severity="HIGH")]
            recs = Analyzer(findings)._static_recommendations(findings)
            assert recs[0]["check"] == check


# ---------------------------------------------------------------------------
# Analyzer.generate_recommendations – API key logic and fallback
# ---------------------------------------------------------------------------


class TestAnalyzerGenerateRecommendations:

    def test_all_pass_returns_empty_list(self) -> None:
        findings = [make_finding(status="PASS"), make_finding(status="PASS")]
        recs = Analyzer(findings).generate_recommendations()
        assert recs == []

    def test_no_api_key_uses_static(self, mocker) -> None:
        mocker.patch("src.analyzer.analyzer.CLAUDE_API_KEY", "")
        findings = [make_finding(check="Firewall Status", severity="HIGH")]
        recs = Analyzer(findings).generate_recommendations()
        assert isinstance(recs, list)
        assert len(recs) > 0

    def test_api_key_present_calls_claude(self, mocker) -> None:
        mocker.patch("src.analyzer.analyzer.CLAUDE_API_KEY", "sk-fake-key")
        findings = [make_finding(check="SMBv1 Protocol", severity="CRITICAL")]
        analyzer = Analyzer(findings)
        expected = [
            {
                "check": "SMBv1 Protocol",
                "severity": "CRITICAL",
                "action": "Disable SMBv1",
                "command": "cmd",
                "effort": "Low",
                "timeline": "Immediate",
            }
        ]
        mock_claude = mocker.patch.object(
            analyzer, "_claude_recommendations", return_value=expected
        )
        recs = analyzer.generate_recommendations()
        mock_claude.assert_called_once()
        assert recs == expected

    def test_claude_api_exception_falls_back_to_static(self, mocker) -> None:
        mocker.patch("src.analyzer.analyzer.CLAUDE_API_KEY", "sk-fake-key")
        findings = [make_finding(check="Firewall Status", severity="HIGH")]
        analyzer = Analyzer(findings)
        mocker.patch.object(
            analyzer,
            "_claude_recommendations",
            side_effect=Exception("API rate limit"),
        )
        recs = analyzer.generate_recommendations()
        assert isinstance(recs, list)
        assert len(recs) > 0  # static fallback produced recommendations

    def test_empty_findings_no_claude_call(self, mocker) -> None:
        mocker.patch("src.analyzer.analyzer.CLAUDE_API_KEY", "sk-fake-key")
        findings = [make_finding(status="PASS")]
        analyzer = Analyzer(findings)
        mock_claude = mocker.patch.object(analyzer, "_claude_recommendations")
        recs = analyzer.generate_recommendations()
        mock_claude.assert_not_called()
        assert recs == []


# ---------------------------------------------------------------------------
# Analyzer._claude_recommendations (mocked anthropic client)
# ---------------------------------------------------------------------------


class TestAnalyzerClaudeRecommendations:

    def test_claude_response_parsed_and_returned(self, mocker) -> None:
        import json as _json

        api_response = [
            {
                "check": "Firewall Status",
                "severity": "HIGH",
                "action": "Enable firewall",
                "command": "Set-NetFirewallProfile -All -Enabled True",
                "effort": "Low",
                "timeline": "Immediate",
            }
        ]

        mock_message = mocker.MagicMock()
        mock_message.content = [mocker.MagicMock(text=_json.dumps(api_response))]

        mock_client = mocker.MagicMock()
        mock_client.messages.create.return_value = mock_message

        mocker.patch("anthropic.Anthropic", return_value=mock_client)
        mocker.patch("src.analyzer.analyzer.CLAUDE_API_KEY", "sk-fake")

        findings = [make_finding(check="Firewall Status", severity="HIGH")]
        analyzer = Analyzer(findings)
        recs = analyzer._claude_recommendations(findings)

        assert len(recs) == 1
        assert recs[0]["check"] == "Firewall Status"

    def test_claude_response_sorted_by_severity(self, mocker) -> None:
        import json as _json

        api_response = [
            {
                "check": "Low Check",
                "severity": "LOW",
                "action": "x",
                "command": "x",
                "effort": "Low",
                "timeline": "x",
            },
            {
                "check": "Critical Check",
                "severity": "CRITICAL",
                "action": "x",
                "command": "x",
                "effort": "Low",
                "timeline": "x",
            },
            {
                "check": "High Check",
                "severity": "HIGH",
                "action": "x",
                "command": "x",
                "effort": "Low",
                "timeline": "x",
            },
        ]

        mock_message = mocker.MagicMock()
        mock_message.content = [mocker.MagicMock(text=_json.dumps(api_response))]

        mock_client = mocker.MagicMock()
        mock_client.messages.create.return_value = mock_message

        mocker.patch("anthropic.Anthropic", return_value=mock_client)
        mocker.patch("src.analyzer.analyzer.CLAUDE_API_KEY", "sk-fake")

        findings = [
            make_finding(check="Low Check", severity="LOW"),
            make_finding(check="Critical Check", severity="CRITICAL"),
            make_finding(check="High Check", severity="HIGH"),
        ]
        analyzer = Analyzer(findings)
        recs = analyzer._claude_recommendations(findings)
        assert recs[0]["severity"] == "CRITICAL"
