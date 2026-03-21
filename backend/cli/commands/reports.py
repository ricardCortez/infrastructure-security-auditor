"""Report generation CLI commands."""
from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ..api_client import api
from ..formatters import Formatters
from .. import local_db as db

console = Console()


@click.group("reports")
def reports_group() -> None:
    """Security report generation commands."""
    pass


@reports_group.command("generate")
@click.option(
    "--format", "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    show_default=True,
    help="'terminal' prints to screen; 'json' saves to ~/.psi/reports/.",
)
def generate_report(fmt: str) -> None:
    """Generate a security findings report."""
    if fmt == "terminal":
        _terminal_report()
        return

    Formatters.info("Generating JSON report...")
    response = api.post("/reports/generate", json={"format": fmt})
    if response.status_code == 200:
        data = response.json()
        Formatters.success(
            f"Report saved -> {data.get('path')}  "
            f"({data.get('findings_count', 0)} findings)"
        )
    else:
        Formatters.error(f"Failed: {response.status_code}")


def _terminal_report() -> None:
    """Render a full findings report inside the terminal using Rich."""
    findings = db.get_all("findings")
    assets = db.get_all("assets")
    asset_map = {a["id"]: a for a in assets}

    from datetime import datetime
    console.rule("[bold cyan]PSI Security Report[/bold cyan]")
    console.print(f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}[/dim]\n")

    # ── Summary panel ──────────────────────────────────────────────
    sev_counts: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    status_counts: dict = {"OPEN": 0, "IN_PROGRESS": 0, "FIXED": 0, "CLOSED": 0}
    for f in findings:
        sev = f.get("severity", "")
        if sev in sev_counts:
            sev_counts[sev] += 1
        st = f.get("status", "")
        if st in status_counts:
            status_counts[st] += 1

    summary = (
        f"[bold]Total findings:[/bold]  {len(findings)}\n"
        f"[bold]Assets:[/bold]          {len(assets)}\n\n"
        f"[red][bold]CRITICAL:[/bold][/red]        {sev_counts['CRITICAL']}\n"
        f"[yellow][bold]HIGH:[/bold][/yellow]            {sev_counts['HIGH']}\n"
        f"[cyan][bold]MEDIUM:[/bold][/cyan]          {sev_counts['MEDIUM']}\n"
        f"[green][bold]LOW:[/bold][/green]             {sev_counts['LOW']}\n\n"
        f"[bold]Open:[/bold]            {status_counts['OPEN']}\n"
        f"[bold]In progress:[/bold]     {status_counts['IN_PROGRESS']}\n"
        f"[bold]Fixed:[/bold]           {status_counts['FIXED']}"
    )
    console.print(Panel(summary, title="[bold cyan]Executive Summary[/bold cyan]",
                        expand=False, width=40))
    console.print()

    if not findings:
        console.print("[green]No findings recorded.[/green]")
        console.rule("[dim]End of Report[/dim]")
        return

    # ── Findings table (sorted by severity) ───────────────────────
    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    _SEV_STYLE = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan",
                  "LOW": "green", "INFO": "dim"}

    sorted_findings = sorted(findings,
                             key=lambda f: _SEV_ORDER.get(f.get("severity", ""), 5))

    tbl = Table(title="All Findings", box=box.ROUNDED, header_style="bold cyan",
                show_lines=False)
    tbl.add_column("ID",         width=5,  style="dim")
    tbl.add_column("Severity",   width=10)
    tbl.add_column("Title",      min_width=30)
    tbl.add_column("Asset",      width=18)
    tbl.add_column("CVSS",       width=6)
    tbl.add_column("Status",     width=12)

    for f in sorted_findings:
        sev = f.get("severity", "?")
        style = _SEV_STYLE.get(sev, "")
        asset = asset_map.get(f.get("asset_id"))
        asset_label = asset.get("hostname", str(f.get("asset_id", "-"))) if asset else "-"
        tbl.add_row(
            str(f.get("id")),
            f"[{style}]{sev}[/{style}]",
            (f.get("title") or "")[:45],
            asset_label[:18],
            str(f.get("cvss_score") or "-"),
            f.get("status", "-"),
        )
    console.print(tbl)
    console.print()

    # ── Remediation section (OPEN critical/high) ───────────────────
    urgent = [f for f in findings
              if f.get("severity") in ("CRITICAL", "HIGH") and f.get("status") == "OPEN"]
    if urgent:
        console.rule("[red]Urgent Remediation[/red]")
        for f in urgent:
            rem = f.get("remediation") or "No remediation guidance recorded."
            console.print(
                f"[red]>>[/red] [bold]{f.get('title')}[/bold]  "
                f"[dim](ID {f.get('id')})[/dim]\n"
                f"   {rem}\n"
            )

    console.rule("[dim]End of Report[/dim]")


@reports_group.command("list")
def list_reports() -> None:
    """List previously generated reports."""
    response = api.get("/reports")
    if response.status_code == 200:
        reports = response.json()
        if not reports:
            Formatters.info("No reports yet. Run: psi reports generate")
        else:
            rows = [[r.get("id"), r.get("format"), r.get("findings_count"),
                     r.get("path", ""), r.get("created_at")]
                    for r in reports]
            Formatters.table(rows,
                             headers=["ID", "Format", "Findings", "Path", "Created"],
                             title=f"Reports ({len(reports)})")
    else:
        Formatters.error(f"Failed: {response.status_code}")
