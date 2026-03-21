"""Reusable Rich UI components for the TUI.

All display functions print directly to the shared
:data:`~src.tui.styles.console` instance.
"""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table

from src.tui.styles import (
    HEADER,
    MUTED,
    console,
    risk_color,
    severity_color,
    status_color,
)

# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------


def print_header(title: str, subtitle: str = "") -> None:
    """Print a styled cyan header panel.

    Args:
        title: Main heading text.
        subtitle: Optional secondary text displayed below the title.
    """
    body = f"[{HEADER}]{title}[/{HEADER}]"
    if subtitle:
        body += f"\n[{MUTED}]{subtitle}[/{MUTED}]"
    console.print(Panel(body, border_style="cyan", padding=(0, 2)))


def print_banner() -> None:
    """Print the application ASCII banner to the console."""
    banner = (
        "[bold cyan]╔══════════════════════════════════════════════════╗[/]\n"
        "[bold cyan]║[/]  [bold white]Infrastructure Security Auditor[/]              "
        "[bold cyan]║[/]\n"
        "[bold cyan]║[/]  [dim]Professional automated security assessment tool[/]  "
        "[bold cyan]║[/]\n"
        "[bold cyan]╚══════════════════════════════════════════════════╝[/]"
    )
    console.print(banner, justify="center")
    console.print()


def print_menu(options: list[str], title: str = "Select an option") -> int:
    """Display a numbered menu and block until a valid option is selected.

    Args:
        options: List of option labels (displayed 1-based).
        title: Panel title shown above the numbered list.

    Returns:
        Zero-based index of the selected option.

    Raises:
        KeyboardInterrupt: Propagated when the user presses Ctrl-C.
    """
    table = Table(show_header=False, box=None, padding=(0, 1), show_edge=False)
    table.add_column("num", style="bold cyan", width=4)
    table.add_column("label", style="white")

    for i, opt in enumerate(options, start=1):
        table.add_row(f"[{i}]", opt)

    console.print(Panel(table, title=f"[bold cyan]{title}[/]", border_style="cyan"))

    while True:
        try:
            raw = console.input("[bold cyan]  Enter choice:[/] ").strip()
            idx = int(raw)
            if 1 <= idx <= len(options):
                return idx - 1
            console.print(
                f"[red]  Please enter a number between 1 and {len(options)}.[/]"
            )
        except ValueError:
            console.print("[red]  Invalid input — enter the number of your choice.[/]")
        except KeyboardInterrupt:
            raise


def confirm(prompt: str, default: bool = False) -> bool:
    """Prompt the user for a yes/no confirmation.

    Args:
        prompt: Question text shown to the user.
        default: Default answer when the user presses Enter without typing.

    Returns:
        ``True`` if the user confirmed, ``False`` otherwise.
    """
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            raw = console.input(f"[yellow]  {prompt} {hint}:[/] ").strip().lower()
            if raw == "":
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            console.print("[red]  Enter y or n.[/]")
        except KeyboardInterrupt:
            return False


def prompt_ip(label: str = "Server IP or hostname") -> str:
    """Prompt for a non-empty IP address or hostname string.

    Args:
        label: Prompt label text.

    Returns:
        Non-empty string entered by the user.

    Raises:
        KeyboardInterrupt: When the user presses Ctrl-C.
    """
    while True:
        value = console.input(f"[cyan]  {label}:[/] ").strip()
        if value:
            return value
        console.print("[red]  Cannot be empty.[/]")


def prompt_network(label: str = "Network CIDR or range") -> str:
    """Prompt for a network CIDR block or IP range.

    Displays usage examples before prompting.

    Args:
        label: Prompt label text.

    Returns:
        Non-empty network range string.

    Raises:
        KeyboardInterrupt: When the user presses Ctrl-C.
    """
    console.print("[dim]  Examples: 192.168.0.0/24  |  10.0.0.1-50[/]")
    return prompt_ip(label)


# ---------------------------------------------------------------------------
# Result display components
# ---------------------------------------------------------------------------


def print_findings_table(
    findings: list[dict[str, Any]], title: str = "Findings"
) -> None:
    """Print a colour-coded findings table.

    Args:
        findings: List of FindingDict objects with ``check``, ``status``,
            ``severity``, and ``description`` keys.
        title: Table title string.
    """
    table = Table(title=title, border_style="blue", show_lines=False)
    table.add_column("Check", style="cyan", min_width=20)
    table.add_column("Status", width=9)
    table.add_column("Severity", width=10)
    table.add_column("Description", style="dim", max_width=60)

    for f in findings:
        sc = status_color(f.get("status", ""))
        sevc = severity_color(f.get("severity", ""))
        table.add_row(
            f.get("check", ""),
            f"[{sc}]{f.get('status', '')}[/]",
            f"[{sevc}]{f.get('severity', '')}[/]",
            f.get("description", ""),
        )
    console.print(table)


def print_scan_summary(scan_result: dict[str, Any]) -> None:
    """Print a single-server scan result as a summary panel and findings table.

    Args:
        scan_result: Raw scan dict from ``WindowsScanner.run_scan()`` or
            ``LinuxScanner.run_scan()`` with ``findings``, ``server``,
            ``timestamp``, and ``summary`` keys.
    """
    findings = scan_result.get("findings", [])
    raw_summary = scan_result.get("summary", {})

    fail_count = raw_summary.get("FAIL", 0) + raw_summary.get("WARNING", 0)
    pass_count = raw_summary.get("PASS", 0)
    critical = sum(
        1 for f in findings
        if f.get("severity") == "CRITICAL" and f.get("status") != "PASS"
    )
    high = sum(
        1 for f in findings
        if f.get("severity") == "HIGH" and f.get("status") != "PASS"
    )

    body = (
        f"[bold]Server:[/] [cyan]{scan_result.get('server', 'unknown')}[/]\n"
        f"[bold]Checks:[/] {len(findings)}  "
        f"[green]PASS: {pass_count}[/]  [red]FAIL/WARN: {fail_count}[/]\n"
        f"[red]Critical: {critical}[/]  [dark_orange]High: {high}[/]"
    )
    console.print(Panel(body, title="[bold]Scan Summary[/]", border_style="cyan"))

    if findings:
        print_findings_table(findings)


def print_network_summary_table(servers: list[dict[str, Any]]) -> None:
    """Print a table of all scanned servers sorted by risk score.

    Args:
        servers: List of server result dicts from ``BatchScanner``.
    """
    table = Table(
        title="Network Scan Summary", border_style="cyan", show_lines=True
    )
    table.add_column("IP", style="cyan", width=15)
    table.add_column("Hostname", style="white", width=20)
    table.add_column("OS", width=8)
    table.add_column("Risk", width=7, justify="right")
    table.add_column("Status", width=9)
    table.add_column("Findings", justify="right", width=10)

    for s in sorted(servers, key=lambda x: x.get("risk_score", 0), reverse=True):
        rc = risk_color(s.get("risk_score", 0))
        sc = status_color(s.get("status", ""))
        fail_count = sum(
            1 for f in s.get("findings", []) if f.get("status") in ("FAIL", "WARNING")
        )
        table.add_row(
            s.get("ip", ""),
            s.get("hostname", "unknown")[:19],
            s.get("os", "")[:7],
            f"[{rc}]{s.get('risk_score', 0):.1f}[/]",
            f"[{sc}]{s.get('status', '')}[/]",
            str(fail_count) if s.get("status") == "success" else "-",
        )
    console.print(table)


def print_network_stats(batch_result: dict[str, Any]) -> None:
    """Print key network-wide statistics as a summary panel.

    Args:
        batch_result: Full ``BatchScanner`` output dict with
            ``network``, ``scan_duration_seconds``, and
            ``network_summary`` keys.
    """
    ns = batch_result.get("network_summary", {})
    body = (
        f"[bold]Network:[/] [cyan]{batch_result.get('network', 'unknown')}[/]\n"
        f"[bold]Servers:[/] {ns.get('total_servers_scanned', 0)}  "
        f"[green]✓ {ns.get('successful_scans', 0)}[/]  "
        f"[red]✗ {ns.get('failed_scans', 0)}[/]\n"
        f"[bold]Findings:[/] "
        f"[red]CRIT: {ns.get('critical_findings', 0)}[/]  "
        f"[dark_orange]HIGH: {ns.get('high_findings', 0)}[/]  "
        f"[yellow]MED: {ns.get('medium_findings', 0)}[/]  "
        f"[green]LOW: {ns.get('low_findings', 0)}[/]\n"
        f"[bold]Compliance:[/] "
        f"ISO 27001: {ns.get('compliance_iso27001', 0) * 100:.0f}%  "
        f"CIS: {ns.get('compliance_cis_benchmarks', 0) * 100:.0f}%  "
        f"PCI-DSS: {ns.get('compliance_pci_dss', 0) * 100:.0f}%\n"
        f"[bold]Duration:[/] {batch_result.get('scan_duration_seconds', 0):.1f}s"
    )
    console.print(Panel(body, title="[bold]Network Audit Results[/]", border_style="cyan"))
