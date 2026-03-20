"""Configuration module for Infrastructure Security Auditor.

Loads environment variables, defines constants, and sets up the application logger.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Environment loading
# ---------------------------------------------------------------------------

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_FILE, override=False)

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------

APP_NAME: Final[str] = "infrastructure-security-auditor"
APP_VERSION: Final[str] = "0.1.0"

# ---------------------------------------------------------------------------
# API keys & credentials (read from environment)
# ---------------------------------------------------------------------------

CLAUDE_API_KEY: str = os.getenv("CLAUDE_API_KEY", "")
CLAUDE_MODEL: Final[str] = "claude-sonnet-4-5"

WINRM_USERNAME: str = os.getenv("WINRM_USERNAME", "")
WINRM_PASSWORD: str = os.getenv("WINRM_PASSWORD", "")
WINRM_PORT: int = int(os.getenv("WINRM_PORT", "5985"))
WINRM_TRANSPORT: str = os.getenv("WINRM_TRANSPORT", "ntlm")

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

REPORT_OUTPUT_DIR: Path = Path(os.getenv("REPORT_OUTPUT_DIR", "./reports")).resolve()

# ---------------------------------------------------------------------------
# Severity weights (used by risk scorer)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Final[dict[str, int]] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

SEVERITY_ORDER: Final[list[str]] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# ---------------------------------------------------------------------------
# Compliance control mappings
# Each entry maps a scanner check name to the compliance controls it covers.
# ---------------------------------------------------------------------------

COMPLIANCE_CONTROLS: Final[dict[str, dict[str, list[str]]]] = {
    "Firewall Status": {
        "ISO_27001": ["A.13.1.1"],
        "CIS_Benchmarks": ["9.1", "9.2", "9.3"],
        "PCI_DSS": ["1.2", "1.3"],
    },
    "SMBv1 Protocol": {
        "ISO_27001": ["A.12.6.1"],
        "CIS_Benchmarks": ["18.3.1"],
        "PCI_DSS": ["6.2"],
    },
    "LLMNR/NetBIOS": {
        "ISO_27001": ["A.13.1.2"],
        "CIS_Benchmarks": ["18.5.4", "18.5.5"],
        "PCI_DSS": ["1.1.7"],
    },
    "Windows Defender": {
        "ISO_27001": ["A.12.2.1"],
        "CIS_Benchmarks": ["8.1", "8.2"],
        "PCI_DSS": ["5.1", "5.2"],
    },
    "TLS Versions": {
        "ISO_27001": ["A.14.1.2"],
        "CIS_Benchmarks": ["17.8"],
        "PCI_DSS": ["4.1"],
    },
    "Password Policies": {
        "ISO_27001": ["A.9.4.3"],
        "CIS_Benchmarks": ["1.1", "1.2"],
        "PCI_DSS": ["8.2", "8.3"],
    },
    "RDP NLA": {
        "ISO_27001": ["A.6.2.2"],
        "CIS_Benchmarks": ["18.9.65"],
        "PCI_DSS": ["8.2.1"],
    },
    "Windows Update": {
        "ISO_27001": ["A.12.6.1"],
        "CIS_Benchmarks": ["19.1", "19.2"],
        "PCI_DSS": ["6.3"],
    },
    "Admin Accounts": {
        "ISO_27001": ["A.9.2.3"],
        "CIS_Benchmarks": ["4.1", "4.2"],
        "PCI_DSS": ["8.1.1"],
    },
    "Privilege Creep": {
        "ISO_27001": ["A.9.2.2"],
        "CIS_Benchmarks": ["4.3"],
        "PCI_DSS": ["7.1"],
    },
    "Event Log Config": {
        "ISO_27001": ["A.12.4.1"],
        "CIS_Benchmarks": ["17.1", "17.2"],
        "PCI_DSS": ["10.1", "10.2"],
    },
    "LSASS Protection": {
        "ISO_27001": ["A.9.4.4"],
        "CIS_Benchmarks": ["18.8.28"],
        "PCI_DSS": ["8.6"],
    },
    "Weak Ciphers": {
        "ISO_27001": ["A.14.1.3"],
        "CIS_Benchmarks": ["17.9"],
        "PCI_DSS": ["4.1"],
    },
    "File Sharing": {
        "ISO_27001": ["A.13.2.1"],
        "CIS_Benchmarks": ["18.1"],
        "PCI_DSS": ["7.2"],
    },
    "Installed Software": {
        "ISO_27001": ["A.12.5.1"],
        "CIS_Benchmarks": ["2.1", "2.2"],
        "PCI_DSS": ["6.2"],
    },
}

# Total controls per standard (used to compute compliance %)
TOTAL_CONTROLS: Final[dict[str, int]] = {
    "ISO_27001": 114,
    "CIS_Benchmarks": 356,
    "PCI_DSS": 251,
}

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def setup_logger(
    name: str = "auditor",
    level: str | None = None,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        name: Logger name (default: "auditor").
        level: Log level string (default: from $LOG_LEVEL env var or INFO).
        log_file: Optional path to write logs to a file.

    Returns:
        Configured :class:`logging.Logger` instance.
    """
    _level_str = level or os.getenv("LOG_LEVEL", "INFO")
    _level = getattr(logging, _level_str.upper(), logging.INFO)

    logger = logging.getLogger(name)
    logger.setLevel(_level)

    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

        # Console handler
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        logger.addHandler(console)

        # Optional file handler
        _log_file = log_file or os.getenv("LOG_FILE")
        if _log_file:
            file_handler = logging.FileHandler(_log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


# Module-level logger instance
logger: logging.Logger = setup_logger()
