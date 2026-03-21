"""Infrastructure Security Auditor integration as PSI Scanner worker."""
import json
import logging
import os
import socket
import subprocess

from celery import shared_task

from ..schema import Finding, Severity

logger = logging.getLogger(__name__)

_AUDITOR_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "auditor.py")
)


@shared_task(bind=True)
def infrastructure_auditor_scan(self, asset_id: int, target: str, scan_type: str = "full") -> dict:
    """Execute an infrastructure security auditor scan.

    Args:
        asset_id: PSI asset ID.
        target: Target to scan (IP address or hostname).
        scan_type: Type of scan — ``full``, ``quick``, or ``network``.

    Returns:
        Dictionary with status, asset_id, target, findings_count, and findings list.

    Raises:
        Exception: If the auditor subprocess exits with a non-zero return code.
    """
    try:
        os_type = _detect_os(target)
        logger.info(f"Starting infrastructure auditor scan for {target} ({os_type})")
        self.update_state(state="PROGRESS", meta={"status": "Starting auditor scan"})

        cmd = _build_command(target, os_type, scan_type)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        if result.returncode != 0:
            logger.error(f"Auditor scan failed: {result.stderr}")
            raise RuntimeError(f"Auditor execution failed: {result.stderr}")

        findings_data = _parse_output(result.stdout, result.stderr)

        findings = [
            Finding(
                asset_id=asset_id,
                title=item.get("title", "Unknown vulnerability"),
                severity=_map_severity(item.get("severity", "MEDIUM")),
                cvss_score=item.get("cvss_score"),
                cwe=item.get("cwe"),
                description=item.get("description"),
                remediation=item.get("remediation"),
                plugin_id=item.get("plugin_id"),
                source="infrastructure-auditor",
            )
            for item in findings_data.get("findings", [])
        ]

        logger.info(f"Auditor scan completed: {len(findings)} findings for {target}")
        self.update_state(state="PROGRESS", meta={"findings_count": len(findings)})

        return {
            "status": "completed",
            "asset_id": asset_id,
            "target": target,
            "findings_count": len(findings),
            "findings": [f.__dict__ for f in findings],
        }

    except Exception as exc:
        logger.error(f"Infrastructure auditor scan failed: {exc}")
        self.update_state(state="FAILURE", meta={"error": str(exc)})
        raise


# ─────────────────────────── helpers ────────────────────────────────

def _build_command(target: str, os_type: str, scan_type: str) -> list:
    """Build the auditor subprocess command.

    Args:
        target: Target host to scan.
        os_type: Detected OS type (``windows`` or ``linux``).
        scan_type: Scan type (``full``, ``quick``, or ``network``).

    Returns:
        List of command-line tokens ready for :func:`subprocess.run`.
    """
    if scan_type == "quick":
        return ["python", _AUDITOR_PATH, "scan", "--target", target, "--quick"]
    if scan_type == "network":
        return ["python", _AUDITOR_PATH, "scan", "--target", target, "--type", "network"]
    return ["python", _AUDITOR_PATH, "scan", "--target", target, "--type", os_type]


def _parse_output(stdout: str, stderr: str) -> dict:
    """Parse auditor subprocess output into a findings dict.

    Args:
        stdout: Captured standard output from the auditor process.
        stderr: Captured standard error from the auditor process.

    Returns:
        Dictionary with a ``findings`` key (list of finding dicts).
    """
    if stdout.strip().startswith("{"):
        return json.loads(stdout)
    # Fall back to last non-empty stderr line (auditor may emit JSON there)
    lines = [l for l in (stderr or "").splitlines() if l.strip()]
    if lines:
        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            pass
    return {}


def _detect_os(target: str) -> str:
    """Detect the OS type of a remote target using port probing.

    Args:
        target: Hostname or IP address to probe.

    Returns:
        ``'windows'`` if Windows-specific ports are reachable, otherwise ``'linux'``.
    """
    for port in (3389, 445, 139):  # common Windows ports
        try:
            socket.create_connection((target, port), timeout=1).close()
            return "windows"
        except OSError:
            pass
    for port in (22, 111):  # common Linux ports
        try:
            socket.create_connection((target, port), timeout=1).close()
            return "linux"
        except OSError:
            pass
    return "linux"


def _map_severity(severity: str) -> Severity:
    """Map an auditor severity string to a PSI :class:`Severity` enum value.

    Args:
        severity: Auditor severity string (e.g. ``'CRITICAL'``, ``'HIGH'``).

    Returns:
        Corresponding :class:`~backend.scan_workers.schema.Severity` member.
    """
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "WARNING": Severity.HIGH,
    }
    return mapping.get(severity.upper(), Severity.MEDIUM)
