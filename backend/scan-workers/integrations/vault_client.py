import hvac
import logging

logger = logging.getLogger(__name__)


class VaultClient:
    """Client for retrieving secrets from HashiCorp Vault."""

    def __init__(self, vault_addr: str, vault_token: str) -> None:
        """Initialize the Vault client.

        Args:
            vault_addr: URL of the Vault server.
            vault_token: Authentication token for Vault.
        """
        self.client = hvac.Client(url=vault_addr, token=vault_token)

    def get_credentials(self, path: str) -> dict:
        """Retrieve credentials from Vault KV store.

        Args:
            path: Vault secret path (e.g., 'secret/nessus').

        Returns:
            Dictionary of credential key-value pairs.
        """
        secret = self.client.secrets.kv.read_secret_version(path=path)
        return secret['data']['data']

    def store_credentials(self, path: str, credentials: dict) -> None:
        """Store credentials in Vault KV store.

        Args:
            path: Vault secret path to write to.
            credentials: Dictionary of credentials to store.
        """
        self.client.secrets.kv.create_or_update_secret(
            path=path,
            secret=credentials,
        )
        logger.info(f"Credentials stored at {path}")
