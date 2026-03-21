"""Findings management CLI commands."""
import click
from ..api_client import api
from ..formatters import Formatters


@click.group("findings")
def findings_group() -> None:
    """Vulnerability findings management commands."""
    pass


@findings_group.command("list")
@click.option("--status", type=click.Choice(["OPEN", "IN_PROGRESS", "FIXED", "CLOSED"]), default=None)
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), default=None)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def list_findings(status, severity, fmt: str) -> None:
    """List findings, optionally filtered by status or severity."""
    params = {}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity

    response = api.get("/findings", params=params)
    if response.status_code != 200:
        Formatters.error(f"Failed to fetch findings: {response.status_code}")
        return

    findings = response.json()

    if fmt == "json":
        Formatters.json_output(findings)
        return

    severity_style = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green", "INFO": "dim"}

    rows = []
    for f in findings:
        sev = f.get("severity", "")
        style = severity_style.get(sev, "")
        rows.append([
            f.get("id"),
            (f.get("title") or "")[:35],
            f"[{style}]{sev}[/{style}]" if style else sev,
            f.get("cvss_score", "-"),
            f.get("status"),
            f.get("asset_id"),
        ])

    Formatters.table(rows, headers=["ID", "Title", "Severity", "CVSS", "Status", "Asset"], title=f"Findings ({len(findings)})")


@findings_group.command("create")
@click.option("--asset-id", type=int, required=True, prompt="Asset ID")
@click.option("--title", required=True, prompt="Vulnerability Title")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), required=True, prompt="Severity")
@click.option("--cvss", type=float, default=None, prompt="CVSS Score (Enter to skip)", prompt_required=False)
def create_finding(asset_id: int, title: str, severity: str, cvss) -> None:
    """Create a new vulnerability finding."""
    response = api.post("/findings", json={
        "asset_id": asset_id,
        "title": title,
        "severity": severity,
        "cvss_score": cvss,
        "status": "OPEN",
    })
    if response.status_code in [200, 201]:
        f = response.json()
        Formatters.success(f"Finding created: ID={f['id']} [{severity}] {title}")
    else:
        Formatters.error(f"Failed: {response.status_code} {response.text}")


@findings_group.command("update")
@click.option("--id", "finding_id", type=int, required=True, prompt="Finding ID")
@click.option("--status", type=click.Choice(["OPEN", "IN_PROGRESS", "FIXED", "CLOSED"]), required=True, prompt="New Status")
def update_finding(finding_id: int, status: str) -> None:
    """Update the status of a finding."""
    response = api.put(f"/findings/{finding_id}", json={"status": status})
    if response.status_code == 200:
        Formatters.success(f"Finding {finding_id} -> {status}")
    else:
        Formatters.error(f"Failed: {response.status_code} {response.text}")


@findings_group.command("show")
@click.argument("finding_id", type=int)
def show_finding(finding_id: int) -> None:
    """Show details for a specific finding."""
    response = api.get(f"/findings/{finding_id}")
    if response.status_code == 200:
        f = response.json()
        rows = [[k, str(v)] for k, v in f.items()]
        Formatters.table(rows, headers=["Field", "Value"], title=f"Finding {finding_id}")
    else:
        Formatters.error(f"Finding {finding_id} not found.")


@findings_group.command("summary")
def summary() -> None:
    """Show findings summary by severity."""
    response = api.get("/findings")
    if response.status_code != 200:
        Formatters.error("Failed to fetch findings.")
        return

    findings = response.json()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    statuses = {"OPEN": 0, "IN_PROGRESS": 0, "FIXED": 0, "CLOSED": 0}

    for f in findings:
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1
        st = f.get("status", "")
        if st in statuses:
            statuses[st] += 1

    rows = [
        ["[red]CRITICAL[/red]", counts["CRITICAL"]],
        ["[yellow]HIGH[/yellow]", counts["HIGH"]],
        ["[cyan]MEDIUM[/cyan]", counts["MEDIUM"]],
        ["[green]LOW[/green]", counts["LOW"]],
        ["[dim]INFO[/dim]", counts["INFO"]],
    ]
    Formatters.table(rows, headers=["Severity", "Count"], title=f"Findings Summary (total: {len(findings)})")

    status_rows = [[k, v] for k, v in statuses.items()]
    Formatters.table(status_rows, headers=["Status", "Count"], title="By Status")
