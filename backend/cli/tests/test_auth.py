"""Unit tests for CLI authentication client."""
import pytest
from unittest.mock import patch, MagicMock
from cli.auth import AuthClient
from cli.config import config as _cfg


class TestAuthClient:
    """Tests for AuthClient. Uses the shared config singleton."""

    def setup_method(self) -> None:
        _cfg.set("token", None)
        _cfg.set("username", None)
        self.auth = AuthClient()

    # ── is_authenticated ──────────────────────────────────────────

    def test_not_authenticated_when_no_token(self) -> None:
        assert not self.auth.is_authenticated()

    def test_authenticated_when_token_present(self) -> None:
        _cfg.set("token", "sometoken")
        assert self.auth.is_authenticated()

    def test_not_authenticated_after_token_cleared(self) -> None:
        _cfg.set("token", "sometoken")
        _cfg.set("token", None)
        assert not self.auth.is_authenticated()

    # ── logout ────────────────────────────────────────────────────

    def test_logout_clears_token(self) -> None:
        _cfg.set("token", "mytoken")
        success, msg = self.auth.logout()
        assert success
        assert _cfg.get("token") is None

    def test_logout_clears_username(self) -> None:
        _cfg.set("username", "ricardo")
        self.auth.logout()
        assert _cfg.get("username") is None

    def test_logout_returns_success_message(self) -> None:
        success, msg = self.auth.logout()
        assert success
        assert len(msg) > 0

    # ── get_headers ───────────────────────────────────────────────

    def test_get_headers_contains_authorization(self) -> None:
        _cfg.set("token", "abc123")
        headers = self.auth.get_headers()
        assert "Authorization" in headers
        assert "abc123" in headers["Authorization"]

    def test_get_headers_contains_content_type(self) -> None:
        _cfg.set("token", "abc123")
        headers = self.auth.get_headers()
        assert headers.get("Content-Type") == "application/json"

    def test_get_headers_bearer_prefix(self) -> None:
        _cfg.set("token", "mytoken")
        headers = self.auth.get_headers()
        assert headers["Authorization"].startswith("Bearer ")

    # ── login (mocked) ────────────────────────────────────────────

    @patch("requests.post")
    def test_login_success_stores_token(self, mock_post) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "test_token_abc"},
        )
        success, msg = self.auth.login("ricardo", "pass")
        assert success
        assert _cfg.get("token") == "test_token_abc"

    @patch("requests.post")
    def test_login_success_stores_username(self, mock_post) -> None:
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "test_token_abc"},
        )
        self.auth.login("ricardo", "pass")
        assert _cfg.get("username") == "ricardo"

    @patch("requests.post")
    def test_login_failure_401(self, mock_post) -> None:
        mock_post.return_value = MagicMock(status_code=401, text="Unauthorized")
        success, msg = self.auth.login("wrong", "pass")
        assert not success

    @patch("requests.post")
    def test_login_failure_does_not_store_token(self, mock_post) -> None:
        mock_post.return_value = MagicMock(status_code=401, text="Unauthorized")
        self.auth.login("wrong", "pass")
        assert _cfg.get("token") is None

    @patch("requests.post", side_effect=Exception("timeout"))
    def test_login_connection_error(self, mock_post) -> None:
        success, msg = self.auth.login("user", "pass")
        assert not success
        assert "Error" in msg or "error" in msg
