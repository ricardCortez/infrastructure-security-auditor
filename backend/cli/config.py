"""CLI configuration management using ~/.psi/config.yaml."""
import yaml
from pathlib import Path


class Config:
    """Manages persistent CLI configuration stored in ~/.psi/config.yaml."""

    CONFIG_DIR = Path.home() / ".psi"
    CONFIG_FILE = CONFIG_DIR / "config.yaml"

    def __init__(self) -> None:
        self.CONFIG_DIR.mkdir(exist_ok=True)
        self.data: dict = {}
        self.load()

    def load(self) -> None:
        """Load config from file, creating defaults if not found."""
        if self.CONFIG_FILE.exists():
            with open(self.CONFIG_FILE) as f:
                self.data = yaml.safe_load(f) or {}
        else:
            self.data = {
                "api_url": "http://localhost:8000",
                "api_version": "v1",
                "username": None,
                "token": None,
            }
            self.save()

    def save(self) -> None:
        """Persist config to file."""
        with open(self.CONFIG_FILE, "w") as f:
            yaml.dump(self.data, f)

    def get(self, key: str, default=None):
        """Get config value by key."""
        return self.data.get(key, default)

    def set(self, key: str, value) -> None:
        """Set config value and persist."""
        self.data[key] = value
        self.save()

    def __repr__(self) -> str:
        return f"Config(api_url={self.get('api_url')}, username={self.get('username')})"


config = Config()
