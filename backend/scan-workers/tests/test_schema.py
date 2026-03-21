from scan_workers.schema import Finding, Severity


def test_finding_creation():
    finding = Finding(
        asset_id=1,
        title="Test Vulnerability",
        severity=Severity.HIGH,
        cvss_score=7.5,
    )
    assert finding.asset_id == 1
    assert finding.severity == Severity.HIGH


def test_severity_enum():
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.HIGH == "HIGH"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.LOW == "LOW"
    assert Severity.INFO == "INFO"
