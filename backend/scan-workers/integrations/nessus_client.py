import requests
import logging
from .base_client import BaseScanClient

logger = logging.getLogger(__name__)


class NessusClient(BaseScanClient):
    """Client for interacting with the Nessus vulnerability scanner API."""

    def __init__(self, host: str, credentials: dict) -> None:
        super().__init__(host, credentials)
        self.session = requests.Session()
        self.api_url = f"https://{host}:8834"

    def authenticate(self) -> None:
        """Authenticate with Nessus API using username/password credentials."""
        url = f"{self.api_url}/session"
        data = {
            "username": self.credentials.get("username"),
            "password": self.credentials.get("password"),
        }
        response = self.session.post(url, json=data, verify=False)
        response.raise_for_status()
        token = response.json().get("token")
        self.session.headers.update({"X-Cookie": f"token={token}"})
        logger.info("Nessus authentication successful")

    def create_scan(self, target: str, template: str = "basic") -> str:
        """Create a new Nessus scan for the target host.

        Args:
            target: IP address or hostname to scan.
            template: Nessus scan template name.

        Returns:
            Scan ID as a string.
        """
        url = f"{self.api_url}/scans"
        payload = {
            "uuid": template,
            "settings": {"name": f"PSI-Scan-{target}", "text_targets": target},
        }
        response = self.session.post(url, json=payload, verify=False)
        response.raise_for_status()
        return str(response.json()["scan"]["id"])

    def start_scan(self, scan_id: str) -> None:
        """Launch a previously created Nessus scan.

        Args:
            scan_id: Nessus scan ID to launch.
        """
        url = f"{self.api_url}/scans/{scan_id}/launch"
        response = self.session.post(url, verify=False)
        response.raise_for_status()

    def get_status(self, scan_id: str) -> str:
        """Get the current status of a Nessus scan.

        Args:
            scan_id: Nessus scan ID to query.

        Returns:
            Scan status string (running, completed, etc.).
        """
        url = f"{self.api_url}/scans/{scan_id}"
        response = self.session.get(url, verify=False)
        response.raise_for_status()
        return response.json()["info"]["status"]

    def get_results(self, scan_id: str) -> list:
        """Retrieve vulnerability findings from a completed Nessus scan.

        Args:
            scan_id: Nessus scan ID to get results from.

        Returns:
            List of vulnerability finding dictionaries.
        """
        url = f"{self.api_url}/scans/{scan_id}"
        response = self.session.get(url, verify=False)
        response.raise_for_status()
        return response.json().get("vulnerabilities", [])
