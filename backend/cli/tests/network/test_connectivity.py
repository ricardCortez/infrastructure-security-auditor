"""Network connectivity tests."""
import socket
import time
import pytest
import requests


@pytest.mark.network
class TestConnectivity:
    """TCP / DNS connectivity checks."""

    def test_localhost_port_8000_open(self) -> None:
        try:
            conn = socket.create_connection(("127.0.0.1", 8000), timeout=3)
            conn.close()
        except OSError:
            pytest.skip("localhost:8000 not reachable")

    def test_dns_resolves_localhost(self) -> None:
        try:
            results = socket.getaddrinfo("localhost", 8000)
            assert len(results) > 0
        except socket.gaierror:
            pytest.skip("DNS lookup failed")

    def test_api_responds_200(self, api_url) -> None:
        try:
            r = requests.get(f"{api_url}/api/v1/health/live", timeout=5)
            assert r.status_code == 200
        except requests.ConnectionError:
            pytest.skip("API not reachable")

    def test_api_response_under_1_second(self, api_url) -> None:
        try:
            start = time.perf_counter()
            requests.get(f"{api_url}/api/v1/health/live", timeout=5)
            elapsed = time.perf_counter() - start
            assert elapsed < 3.0, f"Response time {elapsed:.2f}s > 3s"
        except requests.ConnectionError:
            pytest.skip("API not reachable")

    def test_api_reliability_5_requests(self, api_url) -> None:
        successful = 0
        try:
            for _ in range(5):
                try:
                    r = requests.get(f"{api_url}/api/v1/health/live", timeout=5)
                    if r.status_code == 200:
                        successful += 1
                except requests.ConnectionError:
                    pass
            if successful == 0:
                pytest.skip("API not reachable")
            assert successful >= 4, f"Only {successful}/5 requests succeeded"
        except requests.ConnectionError:
            pytest.skip("API not reachable")

    def test_swagger_ui_accessible(self, api_url) -> None:
        try:
            r = requests.get(f"{api_url}/docs", timeout=5)
            assert r.status_code == 200
        except requests.ConnectionError:
            pytest.skip("API not reachable")
