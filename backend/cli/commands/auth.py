"""Authentication CLI commands."""
import click
from ..auth import auth
from ..config import config
from ..formatters import Formatters


@click.group("auth")
def auth_group() -> None:
    """Authentication commands."""
    pass


@auth_group.command()
@click.option("--username", prompt="Username")
@click.option("--password", prompt="Password", hide_input=True)
def login(username: str, password: str) -> None:
    """Login to PSI and store JWT token."""
    success, message = auth.login(username, password)
    if success:
        Formatters.success(message)
    else:
        Formatters.error(message)
        raise SystemExit(1)


@auth_group.command()
def logout() -> None:
    """Logout and remove stored credentials."""
    success, message = auth.logout()
    Formatters.success(message)


@auth_group.command()
def status() -> None:
    """Show current authentication status."""
    if auth.is_authenticated():
        username = config.get("username")
        api_url = config.get("api_url")
        Formatters.success(f"Logged in as [bold]{username}[/bold] -> {api_url}")
    else:
        Formatters.info("Not authenticated. Run: psi auth login")
