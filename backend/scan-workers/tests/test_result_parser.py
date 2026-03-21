from scan_workers.result_parser import ResultParser
from scan_workers.schema import Severity


def test_parse_nessus_results():
    raw = [{"plugin_name": "Test Vuln", "severity": 3, "cvss_base_score": 7.0, "plugin_id": 123}]
    findings = ResultParser.parse_nessus_results(raw, asset_id=1)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == "nessus"


def test_parse_empty_results():
    findings = ResultParser.parse_nessus_results([], asset_id=1)
    assert findings == []
