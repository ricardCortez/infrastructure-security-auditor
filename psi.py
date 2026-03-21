"""PSI CLI launcher. Run: python psi.py <command>"""
import sys
import os

# Force UTF-8 output on Windows so Rich Unicode chars don't crash cp1252
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from cli.main import cli

if __name__ == "__main__":
    cli()
