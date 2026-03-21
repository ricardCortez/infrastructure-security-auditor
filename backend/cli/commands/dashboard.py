"""Dashboard CLI commands."""
import click
from ..api_client import api
from ..formatters import Formatters, console
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich.table import Table
from rich import box
from datetime import datetime


@click.group("dashboard")
def dashboard_group() -> None:
    """Security dashboard commands."""
    pass


@dashboard_group.command("view")
def view() -> None:
    """Display the security overview dashboard."""
    assets_r = api.get("/assets")
    findings_r = api.get("/findings")

    assets = assets_r.json() if assets_r.status_code == 200 else []
    findings = findings_r.json() if findings_r.status_code == 200 else []

    # Count by severity and status
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    status_counts = {"OPEN": 0, "IN_PROGRESS": 0, "FIXED": 0, "CLOSED": 0}
    for f in findings:
        sev = f.get("severity", "")
        if sev in sev_counts:
            sev_counts[sev] += 1
        st = f.get("status", "")
        if st in status_counts:
            status_counts[st] += 1

    # Header
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    console.rule(f"[bold cyan]PSI - Security Dashboard[/bold cyan]  [dim]{now}[/dim]")
    console.print()

    # Stats panels
    stats_text = (
        f"[bold]Assets:[/bold]         {len(assets)}\n"
        f"[bold]Findings:[/bold]       {len(findings)}\n"
        f"[red][bold]Critical:[/bold][/red]       {sev_counts['CRITICAL']}\n"
        f"[yellow][bold]High:[/bold][/yellow]           {sev_counts['HIGH']}\n"
        f"[cyan][bold]Medium:[/bold][/cyan]         {sev_counts['MEDIUM']}\n"
        f"[green][bold]Low:[/bold][/green]            {sev_counts['LOW']}\n"
        f"\n[bold]Open Issues:[/bold]    {status_counts['OPEN']}\n"
        f"[bold]In Progress:[/bold]    {status_counts['IN_PROGRESS']}\n"
        f"[bold]Fixed:[/bold]          {status_counts['FIXED']}"
    )
    console.print(Panel(stats_text, title="[bold cyan]Summary[/bold cyan]", expand=False, width=35))
    console.print()

    # Assets table
    if assets:
        asset_table = Table(title="Registered Assets", box=box.SIMPLE, show_header=True, header_style="bold cyan")
        asset_table.add_column("ID", style="dim", width=5)
        asset_table.add_column("Hostname")
        asset_table.add_column("IP Address")
        asset_table.add_column("Type")
        asset_table.add_column("Criticality")
        for a in assets[:10]:
            crit = a.get("criticality", "")
            crit_style = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}.get(crit.lower(), "")
            asset_table.add_row(
                str(a.get("id")), a.get("hostname"), a.get("ip_address"),
                a.get("asset_type"), f"[{crit_style}]{crit}[/{crit_style}]" if crit_style else crit
            )
        console.print(asset_table)
        console.print()

    # Critical findings
    critical = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical:
        find_table = Table(title="[red]Critical & High Findings[/red]", box=box.SIMPLE, header_style="bold red")
        find_table.add_column("ID", width=5)
        find_table.add_column("Title")
        find_table.add_column("Severity")
        find_table.add_column("CVSS")
        find_table.add_column("Status")
        for f in critical[:8]:
            sev = f.get("severity")
            style = "red" if sev == "CRITICAL" else "yellow"
            find_table.add_row(
                str(f.get("id")), (f.get("title") or "")[:40],
                f"[{style}]{sev}[/{style}]", str(f.get("cvss_score") or "-"), f.get("status")
            )
        console.print(find_table)
    else:
        console.print("[green]No critical or high findings.[/green]")

    console.print()
    console.rule("[dim]End of Dashboard[/dim]")
