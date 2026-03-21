"""Authentication client for PSI CLI."""
import requests
import click
from .config import config


class AuthClient:
    """Handles JWT authentication against the PSI API."""

    def __init__(self) -> None:
        self.api_url = config.get("api_url")
        self.api_version = config.get("api_version")

    def login(self, username: str, password: str) -> tuple[bool, str]:
        """Authenticate and store JWT token in config.

        Args:
            username: PSI account username.
            password: PSI account password.

        Returns:
            Tuple of (success, message).
        """
        url = f"{self.api_url}/api/{self.api_version}/users/login"
        try:
            response = requests.post(
                url,
                params={"username": username, "password": password},
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                token = data.get("access_token")
                config.set("username", username)
                config.set("token", token)
                return True, f"Login successful. Welcome, {username}!"
            else:
                return False, f"Login failed: {response.status_code} {response.text}"
        except requests.ConnectionError:
            return False, f"Connection error: is the API running at {self.api_url}?"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def logout(self) -> tuple[bool, str]:
        """Remove stored credentials from config.

        Returns:
            Tuple of (success, message).
        """
        config.set("token", None)
        config.set("username", None)
        return True, "Logged out successfully."

    def is_authenticated(self) -> bool:
        """Check whether a JWT token is stored."""
        return config.get("token") is not None

    def get_headers(self) -> dict:
        """Build Authorization headers for API requests.

        Returns:
            Dict with Authorization and Content-Type headers.
        """
        token = config.get("token")
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }


auth = AuthClient()
