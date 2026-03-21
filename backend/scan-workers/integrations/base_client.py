from abc import ABC, abstractmethod
from typing import Any


class BaseScanClient(ABC):
    """Abstract base class for vulnerability scanner integrations."""

    def __init__(self, host: str, credentials: dict) -> None:
        """Initialize the scan client.

        Args:
            host: Hostname or IP of the scanner.
            credentials: Authentication credentials dictionary.
        """
        self.host = host
        self.credentials = credentials

    @abstractmethod
    def authenticate(self) -> None:
        """Authenticate with the scanner."""
        pass

    @abstractmethod
    def create_scan(self, target: str) -> str:
        """Create a new scan for the target.

        Args:
            target: Target IP or hostname to scan.

        Returns:
            Scan ID string.
        """
        pass

    @abstractmethod
    def start_scan(self, scan_id: str) -> None:
        """Start a previously created scan.

        Args:
            scan_id: Scan ID to start.
        """
        pass

    @abstractmethod
    def get_status(self, scan_id: str) -> str:
        """Get the current status of a scan.

        Args:
            scan_id: Scan ID to query.

        Returns:
            Status string.
        """
        pass

    @abstractmethod
    def get_results(self, scan_id: str) -> list:
        """Get the results of a completed scan.

        Args:
            scan_id: Scan ID to get results for.

        Returns:
            List of finding dictionaries.
        """
        pass
