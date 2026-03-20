"""Scanner package – host-level security checks.

Provides WindowsScanner (15 PowerShell-based checks via subprocess/WinRM)
and LinuxScanner (18 shell-based checks via subprocess/SSH).  Both classes
return normalised FindingDict objects with a common schema.

Classes:
    WindowsScanner: Windows scanner. Supports local and remote (WinRM) targets.
    LinuxScanner: Linux scanner. Supports local and remote (SSH) targets.

Example:
    >>> from src.scanner import WindowsScanner, LinuxScanner
    >>> scanner = LinuxScanner("localhost")
    >>> results = scanner.run_scan()
    >>> print(results["summary"])
    {'PASS': 14, 'FAIL': 3, 'WARNING': 1}
"""

from src.scanner.linux_scanner import LinuxScanner
from src.scanner.windows_scanner import WindowsScanner

__all__ = ["WindowsScanner", "LinuxScanner"]
