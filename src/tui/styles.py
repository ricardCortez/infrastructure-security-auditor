"""Styles and theme constants for the TUI.

Centralises all colour and style strings used across TUI modules so that
the visual identity can be adjusted from a single location.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

PRIMARY = "bold cyan"
HEADER = "bold cyan"
SUBHEADER = "dim cyan"
SUCCESS = "bold green"
ERROR = "bold red"
WARNING = "bold yellow"
INFO = "dim white"
MUTED = "dim"

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "N/A": "dim",
}

STATUS_COLORS: dict[str, str] = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "WARNING": "bold yellow",
    "success": "bold green",
    "error": "bold red",
    "timeout": "bold yellow",
}

RISK_COLORS: list[tuple[float, str]] = [
    (8.0, "bold red"),
    (6.0, "bold dark_orange"),
    (4.0, "bold yellow"),
    (2.0, "bold green"),
    (0.0, "bold cyan"),
]

# ---------------------------------------------------------------------------
# Rich Theme + shared console
# ---------------------------------------------------------------------------

AUDITOR_THEME = Theme(
    {
        "primary": PRIMARY,
        "success": SUCCESS,
        "error": ERROR,
        "warning": WARNING,
        "muted": MUTED,
        "info": INFO,
    }
)

# Module-level console shared across TUI modules
console = Console(theme=AUDITOR_THEME)


def risk_color(score: float) -> str:
    """Return a Rich markup color string appropriate for *score*.

    Args:
        score: Numeric risk score 0–10.

    Returns:
        Rich markup color string (e.g. ``"bold red"``).
    """
    for threshold, color in RISK_COLORS:
        if score >= threshold:
            return color
    return "dim"


def severity_color(severity: str) -> str:
    """Return a Rich markup color string for *severity*.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM, LOW, N/A.

    Returns:
        Rich markup color string.
    """
    return SEVERITY_COLORS.get(severity.upper(), "white")


def status_color(status: str) -> str:
    """Return a Rich markup color string for *status*.

    Args:
        status: One of PASS, FAIL, WARNING, success, error, timeout.

    Returns:
        Rich markup color string.
    """
    return STATUS_COLORS.get(status, "white")
