"""CLI interface for Infrastructure Security Auditor.

Provides command-line commands for scanning, reporting, and version information
via the Click framework.

Commands
--------
scan            Scan a single server (Windows or Linux).
analyze         Analyze scan results JSON.
report          Generate HTML report from scan results.
discover        Discover live hosts in a network range.
scan-network    Discover + scan an entire network.
report-network  Generate consolidated HTML network report.
interactive     Launch interactive TUI dashboard.
version         Print application version.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.config import APP_VERSION, logger

console = Console()


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group(
    help=(
        "Infrastructure Security Auditor – automated Windows security scanning "
        "with AI-powered analysis and HTML reporting.\n\n"
        "  python auditor.py scan --target 192.168.1.100 --os windows\n\n"
        "  python auditor.py report --input scan.json --output report.html"
    ),
    invoke_without_command=False,
)
@click.version_option(version=APP_VERSION, prog_name="auditor")
def cli() -> None:
    """Infrastructure Security Auditor CLI."""
    pass


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command("scan")
@click.option(
    "--target",
    "-t",
    required=True,
    help="Server IP address or hostname to scan. Use 'localhost' for local scan.",
)
@click.option(
    "--os",
    "os_type",
    type=click.Choice(["windows", "linux"], case_sensitive=False),
    default="windows",
    show_default=True,
    help="Target operating system.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Path to save the JSON scan results. Defaults to <target>_scan.json.",
)
@click.option(
    "--username",
    default=None,
    envvar="WINRM_USERNAME",
    help=(
        "Username for remote scans. "
        "Used as WinRM username (Windows) or SSH username (Linux). "
        "Can also be set via WINRM_USERNAME env var."
    ),
)
@click.option(
    "--password",
    default=None,
    envvar="WINRM_PASSWORD",
    help=(
        "Password for remote scans. "
        "Used as WinRM password (Windows) or SSH password (Linux). "
        "Can also be set via WINRM_PASSWORD env var."
    ),
)
@click.option(
    "--ssh-key",
    "ssh_key",
    default=None,
    envvar="SSH_KEY_PATH",
    help=(
        "Path to SSH private key for remote Linux scans. "
        "Overrides --password when both are provided. "
        "Can also be set via SSH_KEY_PATH env var."
    ),
)
@click.option(
    "--analyze/--no-analyze",
    default=False,
    help="Automatically run analysis after scanning.",
)
def scan(
    target: str,
    os_type: str,
    output: str | None,
    username: str | None,
    password: str | None,
    ssh_key: str | None,
    analyze: bool,
) -> None:
    """Scan a server for security misconfigurations.

    Executes all security checks against the specified target and saves
    the results as JSON.  Use --analyze to also run the Analyzer.

    Examples:\n
        python auditor.py scan --target localhost --os windows\n
        python auditor.py scan --target localhost --os linux\n
        python auditor.py scan --target 192.168.1.100 --os linux --username admin --ssh-key ~/.ssh/id_rsa\n
        python auditor.py scan --target 192.168.1.100 --os windows --username admin --password s3cr3t
    """
    console.print(
        Panel.fit(
            f"[bold cyan]Infrastructure Security Auditor[/bold cyan]\n"
            f"Target: [yellow]{target}[/yellow]  OS: [yellow]{os_type}[/yellow]",
            border_style="cyan",
        )
    )

    credentials: dict[str, str] = {}

    if os_type.lower() == "linux":
        if username:
            credentials["username"] = username
        if ssh_key:
            credentials["key_filename"] = ssh_key
        elif password:
            credentials["password"] = password

        try:
            from src.scanner.linux_scanner import LinuxScanner

            scanner = LinuxScanner(
                target=target, credentials=credentials if credentials else None
            )
        except Exception as exc:
            console.print(f"[red]✗ Failed to initialise Linux scanner: {exc}[/red]")
            logger.exception("LinuxScanner init error")
            sys.exit(1)

    else:
        if username and password:
            credentials = {"username": username, "password": password}

        try:
            from src.scanner.windows_scanner import WindowsScanner

            scanner = WindowsScanner(  # type: ignore[assignment]
                target=target, credentials=credentials if credentials else None
            )
        except Exception as exc:
            console.print(f"[red]✗ Failed to initialise Windows scanner: {exc}[/red]")
            logger.exception("WindowsScanner init error")
            sys.exit(1)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running security checks...", total=None)
            scan_results = scanner.run_scan()
            progress.update(task, description="Scan complete ✓")

    except Exception as exc:
        console.print(f"[red]✗ Scan failed: {exc}[/red]")
        logger.exception("Scan error")
        sys.exit(1)

    # Determine output path
    out_path = Path(output) if output else Path(f"{target.replace('.', '_')}_scan.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(scan_results, indent=2, default=str), encoding="utf-8"
    )

    # Print summary table
    _print_scan_summary(scan_results)
    console.print(f"\n[green]✓ Scan results saved to:[/green] [bold]{out_path}[/bold]")

    # Optionally run analysis inline
    if analyze:
        _run_analysis(scan_results)


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


@cli.command("report")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True, readable=True),
    help="Path to scan results JSON (from `auditor scan`) or analysis JSON.",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Output path for the HTML report file.",
)
@click.option(
    "--no-ai",
    is_flag=True,
    default=False,
    help="Skip Claude AI recommendations and use static ones.",
)
def report(input_file: str, output: str, no_ai: bool) -> None:
    """Generate an HTML security report from scan results.

    Reads a JSON file produced by `auditor scan`, runs the analyzer, and
    outputs a standalone HTML report.

    Examples:\n
        python auditor.py report --input scan.json --output report.html
    """
    console.print(
        Panel.fit(
            "[bold cyan]🛡 Generating Security Report[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        raw = Path(input_file).read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        console.print(f"[red]✗ Could not read input file: {exc}[/red]")
        sys.exit(1)

    # The input might be a raw scan (has "findings" key) or already analysed
    if "findings" not in data:
        console.print(
            "[red]✗ Input JSON does not contain 'findings'. Run `auditor scan` first.[/red]"
        )
        sys.exit(1)

    findings = data["findings"]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        t1 = progress.add_task("Analysing findings...", total=None)
        from src.analyzer.analyzer import Analyzer

        if no_ai:
            import os

            os.environ["CLAUDE_API_KEY"] = ""

        analyzer = Analyzer(findings)
        analysis = analyzer.analyze()

        # Carry over scan metadata
        analysis["server"] = data.get("server", "Unknown")
        analysis["timestamp"] = data.get("timestamp", "")
        analysis["scan_duration_seconds"] = data.get("scan_duration_seconds", 0)

        progress.update(t1, description="Analysis complete ✓")

        t2 = progress.add_task("Rendering HTML report...", total=None)
        from src.reporter.html_generator import HTMLReporter

        reporter = HTMLReporter(analysis)
        out_path = reporter.save(output)
        progress.update(t2, description="Report rendered ✓")

    console.print(f"\n[green]✓ Report saved to:[/green] [bold]{out_path}[/bold]")
    console.print(
        f"  Risk Score: [{'red' if analysis['risk_score'] >= 7 else 'yellow' if analysis['risk_score'] >= 4 else 'green'}]"  # noqa: E501
        f"{analysis['risk_score']}/10 ({analysis['risk_label']})[/]\n"
    )


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


@cli.command("version")
def version() -> None:
    """Display the application version."""
    console.print(f"[bold]Infrastructure Security Auditor[/bold] v{APP_VERSION}")


# ---------------------------------------------------------------------------
# analyze command (bonus)
# ---------------------------------------------------------------------------


@cli.command("analyze")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True, readable=True),
    help="Path to scan results JSON.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Save analysis JSON to file (optional).",
)
def analyze(input_file: str, output: str | None) -> None:
    """Analyze scan results and display a risk summary.

    Reads a scan JSON file and prints the risk score, severity distribution,
    and compliance percentages to the console.

    Examples:\n
        python auditor.py analyze --input scan.json
    """
    try:
        data = json.loads(Path(input_file).read_text(encoding="utf-8"))
        findings = data["findings"]
    except Exception as exc:
        console.print(f"[red]✗ Error reading input: {exc}[/red]")
        sys.exit(1)

    from src.analyzer.analyzer import Analyzer

    analyzer = Analyzer(findings)
    result = analyzer.analyze()
    result["server"] = data.get("server", "Unknown")
    result["timestamp"] = data.get("timestamp", "")
    result["scan_duration_seconds"] = data.get("scan_duration_seconds", 0)

    _print_analysis_summary(result)

    if output:
        out = Path(output)
        out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        console.print(f"\n[green]✓ Analysis saved to:[/green] [bold]{out}[/bold]")


# ---------------------------------------------------------------------------
# Internal display helpers
# ---------------------------------------------------------------------------


def _print_scan_summary(results: dict) -> None:
    """Print a rich summary table of scan results.

    Args:
        results: Scan results dict from :meth:`WindowsScanner.run_scan`.
    """
    summary = results.get("summary", {})
    dist: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in results.get("findings", []):
        if f.get("status") in ("FAIL", "WARNING"):
            sev = f.get("severity", "LOW")
            dist[sev] = dist.get(sev, 0) + 1

    table = Table(title="Scan Summary", border_style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[green]PASS[/green]", str(summary.get("PASS", 0)))
    table.add_row("[red]FAIL[/red]", str(summary.get("FAIL", 0)))
    table.add_row("[yellow]WARNING[/yellow]", str(summary.get("WARNING", 0)))
    console.print(table)

    if any(v > 0 for v in dist.values()):
        sev_table = Table(title="Findings by Severity", border_style="red")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        colors = {
            "CRITICAL": "red",
            "HIGH": "dark_orange",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        for sev, count in dist.items():
            if count > 0:
                sev_table.add_row(f"[{colors[sev]}]{sev}[/]", str(count))
        console.print(sev_table)


def _print_analysis_summary(analysis: dict) -> None:
    """Print rich analysis output to console.

    Args:
        analysis: Analysis dict from :meth:`Analyzer.analyze`.
    """
    score = analysis.get("risk_score", 0)
    label = analysis.get("risk_label", "MINIMAL")
    color = "red" if score >= 7 else "yellow" if score >= 4 else "green"

    console.print(
        Panel(
            f"Risk Score: [{color}]{score}/10 ({label})[/]\n"
            f"Checks: {analysis.get('total_checks', '?')}  "
            f"FAIL: [red]{analysis.get('summary', {}).get('FAIL', 0)}[/]  "
            f"WARN: [yellow]{analysis.get('summary', {}).get('WARNING', 0)}[/]  "
            f"PASS: [green]{analysis.get('summary', {}).get('PASS', 0)}[/]",
            title="Analysis Results",
            border_style=color,
        )
    )

    # Compliance table
    compliance = analysis.get("compliance", {})
    if compliance:
        ct = Table(title="Compliance Estimates", border_style="blue")
        ct.add_column("Standard")
        ct.add_column("Score", justify="right")
        for std, val in compliance.items():
            pct = int(val * 100)
            c = "green" if pct >= 80 else "yellow" if pct >= 60 else "red"
            ct.add_row(std.replace("_", " "), f"[{c}]{pct}%[/]")
        console.print(ct)


def _run_analysis(scan_results: dict) -> None:
    """Run inline analysis after scan (used by --analyze flag).

    Args:
        scan_results: Raw scan results dict.
    """
    from src.analyzer.analyzer import Analyzer

    with console.status("Analysing findings..."):
        analyzer = Analyzer(scan_results["findings"])
        analysis = analyzer.analyze()
        analysis["server"] = scan_results.get("server", "Unknown")
        analysis["timestamp"] = scan_results.get("timestamp", "")
        analysis["scan_duration_seconds"] = scan_results.get("scan_duration_seconds", 0)

    _print_analysis_summary(analysis)


# ---------------------------------------------------------------------------
# discover command  (Phase 5)
# ---------------------------------------------------------------------------


@cli.command("discover")
@click.option(
    "--network",
    "-n",
    required=True,
    help="Network range: CIDR (192.168.0.0/24) or IP range (192.168.1.1-100).",
)
@click.option(
    "--timeout",
    default=3,
    show_default=True,
    help="Ping timeout per host in seconds.",
)
@click.option(
    "--max-workers",
    "max_workers",
    default=100,
    show_default=True,
    help="Parallel discovery threads.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Save discovery results to JSON (default: discovery_<network>.json).",
)
def discover(
    network: str,
    timeout: int,
    max_workers: int,
    output: str | None,
) -> None:
    """Discover all live hosts in a network range.

    Performs a parallel ping sweep followed by port-based OS detection.
    Saves discovered hosts as JSON for use with ``scan-network``.

    Examples:\n
        python auditor.py discover --network 192.168.0.0/24\n
        python auditor.py discover --network 10.0.0.1-50 --timeout 2 --output hosts.json
    """
    console.print(
        Panel.fit(
            f"[bold cyan]Network Discovery[/bold cyan]\n"
            f"Range: [yellow]{network}[/yellow]  "
            f"Timeout: [yellow]{timeout}s[/yellow]  "
            f"Workers: [yellow]{max_workers}[/yellow]",
            border_style="cyan",
        )
    )

    try:
        from src.scanner.network_discovery import NetworkDiscovery

        nd = NetworkDiscovery(network, timeout=timeout, max_workers=max_workers)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {network}...", total=None)
            hosts = nd.discover_hosts()
            progress.update(task, description=f"Discovery complete — {len(hosts)} hosts ✓")

    except ValueError as exc:
        console.print(f"[red]✗ Invalid network range: {exc}[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]✗ Discovery failed: {exc}[/red]")
        logger.exception("Discovery error")
        sys.exit(1)

    info = nd.get_network_info()

    # Pretty table
    tbl = Table(title=f"Discovered Hosts — {network}", border_style="cyan")
    tbl.add_column("IP", style="cyan", width=15)
    tbl.add_column("Hostname", style="white", width=25)
    tbl.add_column("OS Hint", width=10)
    tbl.add_column("Open Ports", style="dim", width=20)
    tbl.add_column("RTT ms", justify="right", width=8)
    for h in hosts:
        ports_str = ", ".join(str(p) for p in h.get("ports_open", []))
        tbl.add_row(
            h["ip"],
            h.get("hostname", "unknown")[:24],
            h.get("os_hint", "unknown"),
            ports_str or "-",
            str(h.get("response_time_ms", 0)),
        )
    console.print(tbl)
    console.print(
        f"\n[green]✓ {info['discovered_hosts']} live hosts in "
        f"{info['discovery_duration_seconds']:.1f}s[/green]  "
        f"(Windows: {info['windows_hosts']}, Linux: {info['linux_hosts']}, "
        f"Unknown: {info['unknown_os']})"
    )

    # Save
    safe = network.replace("/", "_").replace(".", "_")
    out_path = Path(output) if output else Path(f"discovery_{safe}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"network_info": info, "discovered_hosts": hosts}, indent=2, default=str),
        encoding="utf-8",
    )
    console.print(f"[green]✓ Saved:[/green] [bold]{out_path}[/bold]")


# ---------------------------------------------------------------------------
# scan-network command  (Phase 5)
# ---------------------------------------------------------------------------


@cli.command("scan-network")
@click.option(
    "--network",
    "-n",
    default=None,
    help="Network range (auto-discovers hosts first).",
)
@click.option(
    "--file",
    "-f",
    "hosts_file",
    default=None,
    type=click.Path(exists=True, readable=True),
    help="JSON file with discovered hosts (from ``discover`` command).",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Save batch scan results JSON (default: network_scan_<network>.json).",
)
@click.option(
    "--max-workers",
    "max_workers",
    default=10,
    show_default=True,
    help="Parallel scan workers.",
)
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Per-host scan timeout in seconds.",
)
@click.option(
    "--username",
    default=None,
    envvar="WINRM_USERNAME",
    help="Credential username forwarded to each scanner.",
)
@click.option(
    "--password",
    default=None,
    envvar="WINRM_PASSWORD",
    help="Credential password forwarded to each scanner.",
)
def scan_network(
    network: str | None,
    hosts_file: str | None,
    output: str | None,
    max_workers: int,
    timeout: int,
    username: str | None,
    password: str | None,
) -> None:
    """Scan an entire network in parallel.

    Provide either ``--network`` (auto-discovers hosts first) or
    ``--file`` (JSON from ``auditor discover``).  Results are saved
    as a JSON file consumable by ``report-network``.

    Examples:\n
        python auditor.py scan-network --network 192.168.0.0/24\n
        python auditor.py scan-network --file discovery.json --max-workers 20
    """
    if not network and not hosts_file:
        console.print("[red]✗ Provide --network or --file.[/red]")
        sys.exit(1)

    console.print(
        Panel.fit(
            "[bold cyan]Network Security Scan[/bold cyan]\n"
            + (f"Network: [yellow]{network}[/yellow]" if network else f"File: [yellow]{hosts_file}[/yellow]")
            + f"  Workers: [yellow]{max_workers}[/yellow]",
            border_style="cyan",
        )
    )

    # --- Gather hosts ---
    hosts: list[dict] = []
    net_label = network or "network"

    if hosts_file:
        try:
            raw = json.loads(Path(hosts_file).read_text(encoding="utf-8"))
            hosts = raw.get("discovered_hosts", raw) if isinstance(raw, dict) else raw
            console.print(f"[green]✓ Loaded {len(hosts)} hosts from {hosts_file}[/green]")
        except Exception as exc:
            console.print(f"[red]✗ Cannot read hosts file: {exc}[/red]")
            sys.exit(1)
    else:
        try:
            from src.scanner.network_discovery import NetworkDiscovery

            nd = NetworkDiscovery(str(network), timeout=5, max_workers=100)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(f"Discovering {network}...", total=None)
                hosts = nd.discover_hosts()
                progress.update(task, description=f"Found {len(hosts)} hosts ✓")
        except Exception as exc:
            console.print(f"[red]✗ Discovery failed: {exc}[/red]")
            logger.exception("Discovery error")
            sys.exit(1)

    if not hosts:
        console.print("[yellow]No live hosts found — nothing to scan.[/yellow]")
        sys.exit(0)

    console.print(f"[cyan]Scanning {len(hosts)} hosts with {max_workers} workers...[/cyan]")

    # --- Batch scan ---
    credentials: dict[str, str] = {}
    if username and password:
        credentials = {"username": username, "password": password}

    try:
        from src.scanner.batch_scanner import BatchScanner

        batch = BatchScanner(hosts, max_workers=max_workers, timeout=timeout,
                             credentials=credentials or None)
        results = batch.scan_with_progress()
    except Exception as exc:
        console.print(f"[red]✗ Batch scan failed: {exc}[/red]")
        logger.exception("Batch scan error")
        sys.exit(1)

    ns = results.get("network_summary", {})
    summary_tbl = Table(title="Network Scan Summary", border_style="cyan")
    summary_tbl.add_column("Metric")
    summary_tbl.add_column("Value", justify="right")
    summary_tbl.add_row("Servers scanned", str(ns.get("total_servers_scanned", 0)))
    summary_tbl.add_row("[green]Successful[/green]", str(ns.get("successful_scans", 0)))
    summary_tbl.add_row("[red]Failed[/red]", str(ns.get("failed_scans", 0)))
    summary_tbl.add_row("[red]Critical findings[/red]", str(ns.get("critical_findings", 0)))
    summary_tbl.add_row("[dark_orange]High findings[/dark_orange]", str(ns.get("high_findings", 0)))
    console.print(summary_tbl)

    safe = net_label.replace("/", "_").replace(".", "_")
    out_path = Path(output) if output else Path(f"network_scan_{safe}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    console.print(f"\n[green]✓ Results saved:[/green] [bold]{out_path}[/bold]")


# ---------------------------------------------------------------------------
# report-network command  (Phase 5)
# ---------------------------------------------------------------------------


@cli.command("report-network")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True, readable=True),
    help="JSON file from ``scan-network`` command.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output directory (default: reports/network_<network>/).",
)
@click.option(
    "--summary-only",
    is_flag=True,
    default=False,
    help="Generate lightweight summary page only.",
)
def report_network(
    input_file: str,
    output: str | None,
    summary_only: bool,
) -> None:
    """Generate a consolidated HTML report from a network scan.

    Reads the JSON produced by ``scan-network`` and renders a
    professional HTML report with per-server details, compliance heatmap,
    and remediation roadmap.

    Examples:\n
        python auditor.py report-network --input network_scan.json\n
        python auditor.py report-network --input network_scan.json --summary-only
    """
    console.print(
        Panel.fit(
            "[bold cyan]Network Report Generator[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        data = json.loads(Path(input_file).read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]✗ Cannot read input file: {exc}[/red]")
        sys.exit(1)

    if "servers" not in data:
        console.print("[red]✗ Input is not a network scan (missing 'servers' key).[/red]")
        sys.exit(1)

    net_label = data.get("network", "network")
    safe = net_label.replace("/", "_").replace(".", "_")
    out_dir = output or f"reports/network_{safe}"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Rendering HTML reports...", total=None)
        try:
            from src.reporter.network_reporter import NetworkReporter

            reporter = NetworkReporter(data)
            if summary_only:
                out = Path(out_dir)
                out.mkdir(parents=True, exist_ok=True)
                p = out / "network_summary.html"
                p.write_text(reporter.generate_network_summary(), encoding="utf-8")
                progress.update(task, description="Summary rendered ✓")
                console.print(f"\n[green]✓ Summary:[/green] [bold]{p}[/bold]")
            else:
                paths = reporter.save_reports(out_dir)
                progress.update(task, description="Reports rendered ✓")
                console.print(
                    f"\n[green]✓ Consolidated:[/green] [bold]{paths['consolidated_path']}[/bold]\n"
                    f"[green]✓ Summary:     [/green] [bold]{paths['summary_path']}[/bold]"
                )
        except Exception as exc:
            console.print(f"[red]✗ Report generation failed: {exc}[/red]")
            logger.exception("Network report error")
            sys.exit(1)


# ---------------------------------------------------------------------------
# interactive command  (Phase 6)
# ---------------------------------------------------------------------------


@cli.command("interactive")
def interactive() -> None:
    """Launch the interactive TUI dashboard.

    Presents a menu-driven interface for scanning servers, discovering
    networks, and generating reports — no flags required.

    Examples:\n
        python auditor.py interactive
    """
    try:
        from src.tui.interactive import run_interactive

        run_interactive()
    except ImportError as exc:
        console.print(f"[red]✗ TUI unavailable: {exc}[/red]")
        sys.exit(1)
