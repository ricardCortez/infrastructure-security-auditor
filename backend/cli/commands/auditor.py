"""Infrastructure Auditor CLI commands for PSI platform."""
import click
from ..formatters import Formatters
from .. import local_db as db


@click.group()
def auditor_group() -> None:
    """Infrastructure Auditor - local Windows/Linux security scanning."""
    pass


def _get_or_create_asset_id(target: str) -> int:
    """Return asset ID for *target*, creating a new asset if one doesn't exist."""
    for field in ("ip_address", "hostname"):
        rows = db.get_all("assets", {field: target})
        if rows:
            Formatters.info(f"Asset encontrado: ID={rows[0]['id']} ({target})")
            return rows[0]["id"]
    row = db.insert("assets", {
        "hostname": target,
        "ip_address": target,
        "asset_type": "server",
        "criticality": "medium",
    })
    Formatters.success(f"Asset creado automaticamente: ID={row['id']} ({target})")
    return row["id"]


@auditor_group.command("scan")
@click.option("--target", default=None, help="IP or hostname to scan")
@click.option(
    "--os-type", "os_type",
    type=click.Choice(["windows", "linux", "auto"]),
    default="auto",
    show_default=True,
)
def scan(target: str, os_type: str) -> None:
    """Run an infrastructure security auditor scan on a target."""
    from .scans import _run_auditor_scan

    if not target:
        target = click.prompt("Target (IP or hostname)")

    asset_id = _get_or_create_asset_id(target)
    _run_auditor_scan(asset_id, target, os_type)


@auditor_group.command("results")
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
def results(output_format: str) -> None:
    """View findings imported from infrastructure auditor scans."""
    findings = db.get_all("findings", {"source": "auditor"})
    if not findings:
        Formatters.info("No auditor findings yet. Run: Infrastructure Auditor -> Run scan (quick)")
        return
    if output_format == "json":
        Formatters.json_output(findings)
    else:
        headers = ["ID", "Asset", "Severity", "Title", "Status"]
        rows = [
            [
                f.get("id"),
                f.get("asset_id", "-"),
                f.get("severity"),
                (f.get("title") or "")[:45],
                f.get("status"),
            ]
            for f in findings
        ]
        Formatters.table(rows, headers=headers, title=f"Auditor Findings ({len(findings)})")
