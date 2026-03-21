"""Scan management CLI commands."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import click

from ..api_client import api
from ..formatters import Formatters
from .. import local_db as db

# auditor.py is at the project root (3 levels above this file)
_AUDITOR = Path(__file__).resolve().parents[3] / "auditor.py"


@click.group("scans")
def scans_group() -> None:
    """Vulnerability scan management commands."""
    pass


@scans_group.command("start")
@click.option("--asset-id", type=int, required=True, prompt="Asset ID")
@click.option(
    "--scanner",
    type=click.Choice(["auditor", "nessus", "openvas"]),
    required=True,
    prompt="Scanner (auditor runs locally; nessus/openvas require external tools)",
)
@click.option("--target", default=None, help="IP or hostname (required for auditor)")
@click.option(
    "--os-type", "os_type",
    type=click.Choice(["windows", "linux", "auto"]),
    default="auto",
    show_default=True,
    help="OS type for auditor scanner.",
)
def start_scan(asset_id: int, scanner: str, target: str, os_type: str) -> None:
    """Queue or run a vulnerability scan for an asset."""
    if scanner == "auditor":
        _run_auditor_scan(asset_id, target, os_type)
    else:
        response = api.post("/jobs", json={
            "asset_id": asset_id,
            "job_type": f"{scanner}_scan",
            "status": "queued",
        })
        if response.status_code in [200, 201]:
            job = response.json()
            Formatters.success(f"Scan queued. Job ID: {job.get('id', 'N/A')}")
        else:
            Formatters.error(f"Failed to queue scan: {response.status_code}")


def _run_auditor_scan(asset_id: int, target: str, os_type: str) -> None:
    """Run the infrastructure auditor directly and import findings into local DB."""
    if not target:
        target = click.prompt("Target (IP or hostname)")

    # Resolve OS type
    if os_type == "auto":
        os_type = _detect_os(target)
        Formatters.info(f"Auto-detected OS: {os_type}")

    # Create job record
    job = db.insert("scan_jobs", {
        "asset_id": asset_id,
        "job_type": "auditor_scan",
        "status": "running",
        "target": target,
        "scan_type": os_type,
        "started_at": datetime.now().isoformat(),
    })
    job_id = job["id"]
    Formatters.info(f"Job {job_id} started - scanning {target} ({os_type})...")

    # Run auditor subprocess — force plain output (no Rich spinners in subprocess)
    out_file = Path(f"{target}_scan.json")
    cmd = [sys.executable, str(_AUDITOR), "scan", "--target", target, "--os", os_type]
    env = os.environ.copy()
    env["TERM"] = "dumb"           # disables Rich color/spinner in child process
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=600, env=env, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        db.update("scan_jobs", job_id, {"status": "timeout",
                                         "completed_at": datetime.now().isoformat()})
        Formatters.error("Scan timed out after 10 minutes.")
        return
    except Exception as exc:
        db.update("scan_jobs", job_id, {"status": "failed",
                                         "completed_at": datetime.now().isoformat()})
        Formatters.error(f"Scan failed: {exc}")
        return

    if result.returncode != 0:
        db.update("scan_jobs", job_id, {"status": "failed",
                                         "completed_at": datetime.now().isoformat()})
        # Extract the actual error message from stderr/stdout (skip Rich tracebacks)
        err_text = (result.stderr or result.stdout or "").strip()
        # Show last meaningful line instead of full traceback
        lines = [l for l in err_text.splitlines() if l.strip() and not l.strip().startswith(("File ", "Traceback", "^"))]
        short_err = lines[-1] if lines else "unknown error"
        Formatters.error(f"Auditor fallo en {target}: {short_err}")
        return

    # Import findings from the generated JSON file
    findings_imported = 0
    if out_file.exists():
        try:
            scan_data = json.loads(out_file.read_text(encoding="utf-8"))
            for item in scan_data.get("findings", []):
                if item.get("status") is False:   # failing check = a real finding
                    db.insert("findings", {
                        "asset_id": asset_id,
                        "title": item.get("check", "Unknown check").replace("_", " ").title(),
                        "severity": item.get("severity", "MEDIUM"),
                        "description": item.get("description", ""),
                        "remediation": item.get("recommendation", ""),
                        "source": "auditor",
                        "status": "OPEN",
                    })
                    findings_imported += 1
        except (json.JSONDecodeError, KeyError) as exc:
            Formatters.warn(f"Could not parse scan output: {exc}")

    db.update("scan_jobs", job_id, {
        "status": "completed",
        "completed_at": datetime.now().isoformat(),
    })
    Formatters.success(
        f"Job {job_id} completed - {findings_imported} finding(s) imported "
        f"(raw scan saved to {out_file})"
    )


def _detect_os(target: str) -> str:
    """Probe common ports to guess the target OS."""
    import socket
    for port in (3389, 445, 139):
        try:
            socket.create_connection((target, port), timeout=1).close()
            return "windows"
        except OSError:
            pass
    return "linux"


@scans_group.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def list_scans(fmt: str) -> None:
    """List all scan jobs."""
    response = api.get("/jobs")
    jobs = response.json() if response.status_code == 200 else []

    if fmt == "json":
        Formatters.json_output(jobs)
        return

    if not jobs:
        Formatters.info("No scan jobs yet. Run: psi scans start")
        return

    rows = [
        [j.get("id"), j.get("job_type"), j.get("target", "-"),
         j.get("status"), j.get("started_at", "-"), j.get("completed_at", "-")]
        for j in jobs
    ]
    Formatters.table(rows,
                     headers=["ID", "Type", "Target", "Status", "Started", "Completed"],
                     title=f"Scan Jobs ({len(jobs)})")


@scans_group.command("status")
@click.argument("job_id", type=int)
def scan_status(job_id: int) -> None:
    """Check the status of a specific scan job."""
    response = api.get(f"/jobs/{job_id}")
    if response.status_code == 200:
        job = response.json()
        rows = [[k, str(v)] for k, v in job.items()]
        Formatters.table(rows, headers=["Field", "Value"], title=f"Job {job_id}")
    else:
        Formatters.error(f"Job {job_id} not found.")
