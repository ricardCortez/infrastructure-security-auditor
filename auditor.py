"""Root entry point for Infrastructure Security Auditor.

Usage:
    python auditor.py scan --target localhost
    python auditor.py report --input scan.json --output report.html
    python auditor.py version
    python auditor.py --help
"""

from src.cli import cli

if __name__ == "__main__":
    cli()
