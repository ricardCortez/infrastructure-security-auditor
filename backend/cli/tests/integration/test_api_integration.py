"""Integration tests against the live PSI API."""
import pytest
import requests


@pytest.mark.integration
class TestAPIIntegration:
    """Requires API running at http://localhost:8000."""

    def test_health_live(self, api_url) -> None:
        r = requests.get(f"{api_url}/api/v1/health/live", timeout=5)
        assert r.status_code == 200

    def test_health_ready(self, api_url) -> None:
        r = requests.get(f"{api_url}/api/v1/health/ready", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "healthy"

    def test_assets_endpoint_exists(self, api_url) -> None:
        r = requests.get(f"{api_url}/api/v1/assets", timeout=5)
        assert r.status_code in [200, 401, 403]

    def test_findings_endpoint_exists(self, api_url) -> None:
        r = requests.get(f"{api_url}/api/v1/findings", timeout=5)
        assert r.status_code in [200, 401, 403]

    def test_login_with_real_credentials(self, api_url) -> None:
        r = requests.post(
            f"{api_url}/api/v1/users/login",
            params={"username": "ricardo", "password": "admin123"},
            timeout=5,
        )
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_login_bad_credentials(self, api_url) -> None:
        r = requests.post(
            f"{api_url}/api/v1/users/login",
            params={"username": "invalid_xyz", "password": "badpass"},
            timeout=5,
        )
        assert r.status_code == 401

    def test_authenticated_assets_list(self, api_url) -> None:
        # Login first
        login = requests.post(
            f"{api_url}/api/v1/users/login",
            params={"username": "ricardo", "password": "admin123"},
            timeout=5,
        )
        token = login.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        r = requests.get(f"{api_url}/api/v1/assets", headers=headers, timeout=5)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_authenticated_findings_list(self, api_url) -> None:
        login = requests.post(
            f"{api_url}/api/v1/users/login",
            params={"username": "ricardo", "password": "admin123"},
            timeout=5,
        )
        token = login.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        r = requests.get(f"{api_url}/api/v1/findings", headers=headers, timeout=5)
        assert r.status_code == 200

    def test_create_and_delete_asset(self, api_url) -> None:
        login = requests.post(
            f"{api_url}/api/v1/users/login",
            params={"username": "ricardo", "password": "admin123"},
            timeout=5,
        )
        token = login.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Create
        r = requests.post(
            f"{api_url}/api/v1/assets",
            json={"hostname": "integration-test-host", "ip_address": "10.99.99.1",
                  "asset_type": "server", "criticality": "low"},
            headers=headers, timeout=5,
        )
        assert r.status_code in [200, 201]
        asset_id = r.json()["id"]

        # Delete
        r2 = requests.delete(f"{api_url}/api/v1/assets/{asset_id}", headers=headers, timeout=5)
        assert r2.status_code == 200
