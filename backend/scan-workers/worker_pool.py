import logging
from typing import Optional
from .integrations.nessus_client import NessusClient
from .integrations.openvas_client import OpenVASClient

logger = logging.getLogger(__name__)


class WorkerPool:
    """Manages a pool of scanner worker clients."""

    def __init__(self) -> None:
        self._nessus_client: Optional[NessusClient] = None
        self._openvas_client: Optional[OpenVASClient] = None

    def get_nessus_client(self, host: str, credentials: dict) -> NessusClient:
        """Get or create a Nessus client instance.

        Args:
            host: Nessus server hostname.
            credentials: Nessus authentication credentials.

        Returns:
            Authenticated NessusClient instance.
        """
        if not self._nessus_client:
            self._nessus_client = NessusClient(host, credentials)
            self._nessus_client.authenticate()
        return self._nessus_client

    def get_openvas_client(self, host: str, credentials: dict) -> OpenVASClient:
        """Get or create an OpenVAS client instance.

        Args:
            host: OpenVAS server hostname.
            credentials: OpenVAS authentication credentials.

        Returns:
            Authenticated OpenVASClient instance.
        """
        if not self._openvas_client:
            self._openvas_client = OpenVASClient(host, credentials)
            self._openvas_client.authenticate()
        return self._openvas_client
