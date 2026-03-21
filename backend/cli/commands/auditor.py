"""Infrastructure Auditor CLI commands for PSI platform."""
import click
from ..api_client import api
from ..formatters import Formatters


@click.group()
def auditor_group() -> None:
    """Infrastructure Auditor - local Windows/Linux security scanning."""
    pass


@auditor_group.command("scan")
@click.option("--asset-id", type=int, required=True, prompt="Asset ID")
@click.option("--target", required=True, prompt="Target (IP or hostname)")
@click.option(
    "--scan-type",
    type=click.Choice(["full", "quick", "network"]),
    default="full",
    show_default=True,
)
def scan(asset_id: int, target: str, scan_type: str) -> None:
    """Run an infrastructure security auditor scan on a target."""
    Formatters.info(f"Queuing infrastructure auditor scan on {target} (type={scan_type})...")
    response = api.post(
        "/jobs",
        json={
            "asset_id": asset_id,
            "job_type": "infrastructure_auditor_scan",
            "target": target,
            "scan_type": scan_type,
            "status": "queued",
        },
    )
    if response.status_code in [200, 201]:
        job = response.json()
        Formatters.success(f"Scan job queued: {job.get('id')}")
    else:
        Formatters.error(f"Failed to start scan: {response.status_code}")


@auditor_group.command("results")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
def results(output_format: str) -> None:
    """View latest infrastructure auditor scan results."""
    response = api.get("/findings", params={"source": "infrastructure-auditor"})
    if response.status_code == 200:
        findings = response.json()
        if output_format == "json":
            Formatters.json_output(findings)
        else:
            headers = ["ID", "Title", "Severity", "Description"]
            table_data = [
                [
                    f.get("id"),
                    (f.get("title") or "")[:40],
                    f.get("severity"),
                    (f.get("description") or "")[:40],
                ]
                for f in findings
            ]
            Formatters.table(table_data, headers=headers, title=f"Auditor Results ({len(findings)})")
    else:
        Formatters.error(f"Failed to fetch results: {response.status_code}")
