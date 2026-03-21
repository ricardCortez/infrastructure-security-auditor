"""Unit tests for CLI config management."""
import pytest
from pathlib import Path
from cli.config import Config


class TestConfig:
    """Test the Config class."""

    def test_config_creates_dir(self) -> None:
        """Config dir is created on instantiation."""
        cfg = Config()
        assert cfg.CONFIG_DIR.exists()

    def test_config_has_default_api_url(self) -> None:
        """Default api_url is set."""
        cfg = Config()
        assert cfg.get("api_url") is not None
        assert "http" in cfg.get("api_url")

    def test_config_has_default_api_version(self) -> None:
        """Default api_version is set."""
        cfg = Config()
        assert cfg.get("api_version") == "v1"

    def test_config_set_and_get(self) -> None:
        """set() persists, get() retrieves."""
        cfg = Config()
        cfg.set("_test_key", "hello")
        assert cfg.get("_test_key") == "hello"
        # Reload from file to verify persistence
        cfg2 = Config()
        assert cfg2.get("_test_key") == "hello"
        # Cleanup
        cfg.data.pop("_test_key", None)
        cfg.save()

    def test_config_get_default(self) -> None:
        """get() returns default when key missing."""
        cfg = Config()
        result = cfg.get("nonexistent_key_xyz", "fallback")
        assert result == "fallback"

    def test_config_repr(self) -> None:
        """repr includes api_url and username."""
        cfg = Config()
        r = repr(cfg)
        assert "api_url" in r

    def test_config_file_is_yaml(self) -> None:
        """Config file is readable as YAML."""
        import yaml
        cfg = Config()
        with open(cfg.CONFIG_FILE) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)
        assert "api_url" in data
