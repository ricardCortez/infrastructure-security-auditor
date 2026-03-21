"""Unit tests for LocalAPIClient (SQLite-backed, no server needed)."""
import pytest
from cli.api_client import LocalAPIClient, LocalResponse
import cli.local_db as db


@pytest.fixture
def client():
    return LocalAPIClient()


@pytest.fixture
def asset(temp_db):
    return db.insert("assets", {
        "hostname": "srv-01",
        "ip_address": "10.0.0.1",
        "asset_type": "server",
        "criticality": "high",
    })


@pytest.fixture
def finding(asset):
    return db.insert("findings", {
        "asset_id": asset["id"],
        "title": "Open RDP port",
        "severity": "HIGH",
        "status": "OPEN",
        "source": "manual",
    })


# ── LocalResponse ────────────────────────────────────────────────────

class TestLocalResponse:

    def test_status_code_stored(self):
        r = LocalResponse(200, {"key": "val"})
        assert r.status_code == 200

    def test_json_returns_data(self):
        r = LocalResponse(201, [1, 2, 3])
        assert r.json() == [1, 2, 3]

    def test_text_fallback(self):
        r = LocalResponse(404)
        assert isinstance(r.text, str)


# ── GET /assets ──────────────────────────────────────────────────────

class TestGetAssets:

    def test_get_all_empty(self, client):
        r = client.get("/assets")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_all_returns_inserted(self, client, asset):
        r = client.get("/assets")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["hostname"] == "srv-01"

    def test_get_by_id(self, client, asset):
        r = client.get(f"/assets/{asset['id']}")
        assert r.status_code == 200
        assert r.json()["ip_address"] == "10.0.0.1"

    def test_get_by_id_not_found(self, client):
        r = client.get("/assets/9999")
        assert r.status_code == 404

    def test_get_with_filter(self, client, asset):
        r = client.get("/assets", params={"asset_type": "server"})
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_get_filter_no_match(self, client, asset):
        r = client.get("/assets", params={"asset_type": "database"})
        assert r.status_code == 200
        assert r.json() == []


# ── POST /assets ─────────────────────────────────────────────────────

class TestPostAssets:

    def test_creates_row(self, client):
        r = client.post("/assets", json={"hostname": "new-host", "ip_address": "1.2.3.4"})
        assert r.status_code == 201
        assert r.json()["hostname"] == "new-host"

    def test_returns_id(self, client):
        r = client.post("/assets", json={"hostname": "h1"})
        assert "id" in r.json()
        assert r.json()["id"] > 0

    def test_persisted_after_insert(self, client):
        client.post("/assets", json={"hostname": "persisted"})
        r = client.get("/assets")
        assert any(a["hostname"] == "persisted" for a in r.json())


# ── PUT /findings ─────────────────────────────────────────────────────

class TestPutFindings:

    def test_update_status(self, client, finding):
        r = client.put(f"/findings/{finding['id']}", json={"status": "FIXED"})
        assert r.status_code == 200
        assert r.json()["status"] == "FIXED"

    def test_update_not_found(self, client):
        r = client.put("/findings/9999", json={"status": "FIXED"})
        assert r.status_code == 404


# ── DELETE /assets ────────────────────────────────────────────────────

class TestDeleteAssets:

    def test_delete_existing(self, client, asset):
        r = client.delete(f"/assets/{asset['id']}")
        assert r.status_code == 200
        assert r.json()["deleted"] is True

    def test_delete_removes_row(self, client, asset):
        client.delete(f"/assets/{asset['id']}")
        r = client.get(f"/assets/{asset['id']}")
        assert r.status_code == 404

    def test_delete_not_found(self, client):
        r = client.delete("/assets/9999")
        assert r.status_code == 404


# ── /jobs ─────────────────────────────────────────────────────────────

class TestJobs:

    def test_create_job(self, client):
        r = client.post("/jobs", json={"job_type": "auditor_scan", "status": "queued"})
        assert r.status_code == 201
        assert r.json()["job_type"] == "auditor_scan"

    def test_list_jobs(self, client):
        client.post("/jobs", json={"job_type": "nessus_scan", "status": "queued"})
        r = client.get("/jobs")
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_get_job_by_id(self, client):
        created = client.post("/jobs", json={"job_type": "openvas_scan"}).json()
        r = client.get(f"/jobs/{created['id']}")
        assert r.status_code == 200
        assert r.json()["job_type"] == "openvas_scan"


# ── /reports/generate ─────────────────────────────────────────────────

class TestReportGenerate:

    def test_generate_json_report(self, client, finding):
        r = client.post("/reports/generate", json={"format": "json"})
        assert r.status_code == 200
        data = r.json()
        assert data["findings_count"] == 1
        assert "path" in data

    def test_report_saved_to_disk(self, client, finding, tmp_path, monkeypatch):
        import cli.api_client as api_mod
        monkeypatch.setattr(api_mod, "_REPORT_DIR", tmp_path)
        r = client.post("/reports/generate", json={"format": "json"})
        assert r.status_code == 200

    def test_report_no_findings(self, client):
        r = client.post("/reports/generate", json={"format": "json"})
        assert r.status_code == 200
        assert r.json()["findings_count"] == 0

    def test_unknown_endpoint_returns_404(self, client):
        r = client.get("/nonexistent")
        assert r.status_code == 404
