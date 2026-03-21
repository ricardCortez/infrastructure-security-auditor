"""Shared pytest fixtures for PSI CLI tests."""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ── isolated database ────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Every test gets its own empty SQLite database."""
    import cli.local_db as local_db
    db_file = tmp_path / "test_psi.db"
    monkeypatch.setattr(local_db, "DB_PATH", db_file)
    local_db.init_db()
    yield db_file


# ── seed helpers ─────────────────────────────────────────────────────

@pytest.fixture
def seed_asset(temp_db):
    """Insert one asset and return its DB row."""
    import cli.local_db as db
    return db.insert("assets", {
        "hostname": "test-server",
        "ip_address": "192.168.1.100",
        "asset_type": "server",
        "criticality": "high",
    })


@pytest.fixture
def seed_finding(seed_asset):
    """Insert one finding linked to seed_asset and return its DB row."""
    import cli.local_db as db
    return db.insert("findings", {
        "asset_id": seed_asset["id"],
        "title": "Test Vulnerability",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "status": "OPEN",
        "source": "manual",
    })


@pytest.fixture
def seed_findings(seed_asset):
    """Insert four mixed-severity findings and return their rows."""
    import cli.local_db as db
    data = [
        {"title": "Test Vulnerability",  "severity": "HIGH",     "cvss_score": 7.5},
        {"title": "RCE via SMBv1",       "severity": "CRITICAL", "cvss_score": 9.8},
        {"title": "Weak TLS cipher",     "severity": "MEDIUM",   "cvss_score": 5.3},
        {"title": "Banner disclosure",   "severity": "LOW",      "cvss_score": 2.1},
    ]
    rows = []
    for d in data:
        rows.append(db.insert("findings", {
            **d,
            "asset_id": seed_asset["id"],
            "status": "OPEN",
            "source": "manual",
        }))
    return rows


@pytest.fixture
def seed_job(seed_asset):
    """Insert one scan job and return its DB row."""
    import cli.local_db as db
    return db.insert("scan_jobs", {
        "asset_id": seed_asset["id"],
        "job_type": "auditor_scan",
        "status": "completed",
        "target": "192.168.1.100",
    })


# ── legacy shape fixtures (kept for backward compat) ─────────────────

@pytest.fixture
def mock_asset(seed_asset):
    return seed_asset


@pytest.fixture
def mock_finding(seed_finding):
    return seed_finding


@pytest.fixture
def mock_findings_list(seed_findings):
    return seed_findings
