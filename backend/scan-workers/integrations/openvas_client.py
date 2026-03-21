import paramiko
import logging
from .base_client import BaseScanClient

logger = logging.getLogger(__name__)


class OpenVASClient(BaseScanClient):
    """Client for interacting with OpenVAS via SSH and OMP protocol."""

    def __init__(self, host: str, credentials: dict) -> None:
        super().__init__(host, credentials)
        self.ssh_client = paramiko.SSHClient()

    def authenticate(self) -> None:
        """Connect to OpenVAS host via SSH."""
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(
            self.host,
            username=self.credentials.get("username"),
            password=self.credentials.get("password"),
        )
        logger.info("OpenVAS SSH authentication successful")

    def create_scan(self, target: str) -> str:
        """Create an OpenVAS scan task for the target.

        Args:
            target: IP address or hostname to scan.

        Returns:
            OMP task ID.
        """
        cmd = f"omp -u {self.credentials['username']} -w {self.credentials['password']} --xml='<create_task><name>PSI-{target}</name></create_task>'"
        _, stdout, _ = self.ssh_client.exec_command(cmd)
        return stdout.read().decode().strip()

    def start_scan(self, scan_id: str) -> None:
        """Start an OpenVAS scan task.

        Args:
            scan_id: OMP task ID to start.
        """
        cmd = f"omp -u {self.credentials['username']} -w {self.credentials['password']} --xml='<start_task task_id=\"{scan_id}\"/>'"
        self.ssh_client.exec_command(cmd)

    def get_status(self, scan_id: str) -> str:
        """Get the current status of an OpenVAS scan task.

        Args:
            scan_id: OMP task ID to query.

        Returns:
            Task status string.
        """
        cmd = f"omp -u {self.credentials['username']} -w {self.credentials['password']} --xml='<get_tasks task_id=\"{scan_id}\"/>'"
        _, stdout, _ = self.ssh_client.exec_command(cmd)
        return stdout.read().decode()

    def get_results(self, scan_id: str) -> list:
        """Get vulnerability results from a completed OpenVAS scan.

        Args:
            scan_id: OMP task ID to retrieve results from.

        Returns:
            List of vulnerability finding dictionaries.
        """
        cmd = f"omp -u {self.credentials['username']} -w {self.credentials['password']} --xml='<get_results task_id=\"{scan_id}\"/>'"
        _, stdout, _ = self.ssh_client.exec_command(cmd)
        return [{"raw": stdout.read().decode()}]
