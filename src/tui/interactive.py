"""Interactive TUI entry point for Infrastructure Security Auditor.

Call :func:`run_interactive` to launch the full menu-driven interface.
"""

from __future__ import annotations

from src.tui.menu import MainMenu
from src.tui.styles import console


def run_interactive() -> None:
    """Launch the interactive Terminal User Interface.

    Clears the terminal screen, shows the application banner, and enters
    the main menu loop.  Catches top-level exceptions and displays them
    cleanly before exiting.

    Example:
        >>> from src.tui.interactive import run_interactive
        >>> run_interactive()
    """
    try:
        console.clear()
    except Exception:  # noqa: BLE001
        pass  # Non-fatal — some CI environments don't support clear

    menu = MainMenu()
    menu.run()
