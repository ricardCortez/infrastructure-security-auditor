"""Scanner UI flows for the TUI.

Provides interactive flows for:
- Single server scan (:func:`single_server_scan_ui`)
- Network host discovery (:func:`network_discovery_ui`)
- Full network batch scan (:func:`network_scan_ui`)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.tui.components import (
    confirm,
    console,
    print_header,
    print_menu,
    print_network_stats,
    print_network_summary_table,
    print_scan_summary,
    prompt_ip,
    prompt_network,
)
from src.tui.styles import ERROR, SUCCESS


# ---------------------------------------------------------------------------
# Single server scan
# ---------------------------------------------------------------------------


def single_server_scan_ui() -> None:
    """Interactive flow for scanning a single server.

    Prompts for IP, OS, optional credentials; runs the scan with a progress
    spinner; displays results; and optionally saves JSON and HTML report.
    """
    console.print()
    print_header("Single Server Security Audit", "Scan one server for misconfigurations")

    try:
        target = prompt_ip("Server IP or hostname")
        os_idx = print_menu(["Windows", "Linux"], "Target OS")
        os_type = "windows" if os_idx == 0 else "linux"

        username: str | None = None
        password: str | None = None
        ssh_key: str | None = None

        if confirm("Provide credentials for remote scan?", default=False):
            username = prompt_ip("Username")
            if os_type == "linux":
                console.print(
                    "[dim]  Authentication method: SSH key file OR password.\n"
                    "  If you use a PASSWORD, just press Enter here.[/dim]"
                )
                key_path = console.input(
                    "[cyan]  SSH key file path (e.g. C:/Users/you/.ssh/id_rsa) — Enter to skip:[/] "
                ).strip()
                if key_path:
                    ssh_key = key_path
                else:
                    password = console.input("[cyan]  SSH Password:[/] ").strip() or None
            else:
                password = console.input("[cyan]  Password:[/] ").strip() or None

        if not confirm(f"Scan [{os_type}] {target}?", default=True):
            console.print("[yellow]  Cancelled.[/]")
            return

        credentials: dict[str, str] = {}
        if os_type == "linux":
            if username:
                credentials["username"] = username
            if ssh_key:
                credentials["key_filename"] = ssh_key
            elif password:
                credentials["password"] = password
            from src.scanner.linux_scanner import LinuxScanner

            # ── connection test ───────────────────────────────────────
            is_remote = target not in {"localhost", "127.0.0.1", "::1"}
            if is_remote and credentials:
                console.print(f"[dim]  Connecting to {target}...[/dim]", end=" ")
                try:
                    scanner = LinuxScanner(target=target, credentials=credentials)
                    console.print(f"[{SUCCESS}]Connected[/]")
                except (ConnectionError, ImportError) as exc:
                    console.print(f"[{ERROR}]Failed[/]")
                    console.print(f"[{ERROR}]  {exc}[/]")
                    return
            else:
                scanner = LinuxScanner(target=target, credentials=credentials or None)
        else:
            if username and password:
                credentials = {"username": username, "password": password}
            from src.scanner.windows_scanner import WindowsScanner

            # ── connection test ───────────────────────────────────────
            is_remote = target not in {"localhost", "127.0.0.1", "::1"}
            if is_remote and credentials:
                console.print(f"[dim]  Connecting to {target}...[/dim]", end=" ")
                try:
                    scanner: Any = WindowsScanner(target=target, credentials=credentials)
                    console.print(f"[{SUCCESS}]Connected[/]")
                except (ConnectionError, ImportError) as exc:
                    console.print(f"[{ERROR}]Failed[/]")
                    console.print(f"[{ERROR}]  {exc}[/]")
                    return
            else:
                scanner = WindowsScanner(  # type: ignore[assignment]
                    target=target, credentials=credentials or None
                )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {target}...", total=None)
            scan_result = scanner.run_scan()
            progress.update(task, description=f"Scan complete - {target} OK")

        console.print()
        print_scan_summary(scan_result)

        if confirm("Save results to JSON?", default=False):
            safe_target = target.replace(".", "_")
            out_path = Path(f"{safe_target}_scan.json")
            out_path.write_text(
                json.dumps(scan_result, indent=2, default=str), encoding="utf-8"
            )
            console.print(f"[{SUCCESS}]  Saved: {out_path}[/]")

        if confirm("Generate HTML report?", default=False):
            _generate_single_report(scan_result, target)

    except KeyboardInterrupt:
        console.print(f"\n[{ERROR}]  Scan cancelled.[/]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Scan failed: {exc}[/]")


# ---------------------------------------------------------------------------
# Network discovery
# ---------------------------------------------------------------------------


def network_discovery_ui() -> None:
    """Interactive flow for discovering live hosts in a network range.

    Prompts for CIDR/range, runs a ping sweep, displays a host table, and
    optionally saves discovery results to JSON.
    """
    console.print()
    print_header("Network Host Discovery", "Find all live hosts in a subnet")

    try:
        network = prompt_network()

        raw_timeout = console.input(
            "[cyan]  Ping timeout per host in seconds [3]:[/] "
        ).strip()
        timeout = int(raw_timeout) if raw_timeout.isdigit() else 3

        if not confirm(f"Discover hosts in {network}?", default=True):
            console.print("[yellow]  Cancelled.[/]")
            return

        from src.scanner.network_discovery import NetworkDiscovery

        nd = NetworkDiscovery(network, timeout=timeout, max_workers=100)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {network}...", total=None)
            hosts = nd.discover_hosts()
            progress.update(
                task, description=f"Discovery complete — {len(hosts)} hosts found ✓"
            )

        info = nd.get_network_info()
        console.print()

        table = Table(title=f"Discovered Hosts — {network}", border_style="cyan")
        table.add_column("IP", style="cyan", width=15)
        table.add_column("Hostname", style="white", width=25)
        table.add_column("OS Hint", width=10)
        table.add_column("Open Ports", style="dim", width=20)
        table.add_column("RTT (ms)", justify="right", width=9)

        for h in hosts:
            ports_str = ", ".join(str(p) for p in h.get("ports_open", []))
            table.add_row(
                h["ip"],
                h.get("hostname", "unknown")[:24],
                h.get("os_hint", "unknown"),
                ports_str or "-",
                str(h.get("response_time_ms", 0)),
            )

        console.print(table)
        console.print(
            f"\n[green]  Discovered {info['discovered_hosts']} live hosts "
            f"in {info['discovery_duration_seconds']:.1f}s[/]  "
            f"(Windows: {info['windows_hosts']}, Linux: {info['linux_hosts']}, "
            f"Unknown: {info['unknown_os']})"
        )

        if confirm("Save discovery results to JSON?", default=False):
            out = {"network_info": info, "discovered_hosts": hosts}
            safe = network.replace("/", "_").replace(".", "_")
            path = Path(f"discovery_{safe}.json")
            path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
            console.print(f"[{SUCCESS}]  Saved: {path}[/]")

    except KeyboardInterrupt:
        console.print(f"\n[{ERROR}]  Discovery cancelled.[/]")
    except ValueError as exc:
        console.print(f"[{ERROR}]  Invalid network range: {exc}[/]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Discovery failed: {exc}[/]")


# ---------------------------------------------------------------------------
# Full network scan
# ---------------------------------------------------------------------------


def network_scan_ui() -> None:
    """Interactive flow for a full network discovery + parallel batch scan.

    Discovers hosts first (or loads from a JSON file), confirms with the user,
    then scans all hosts in parallel with a live progress bar.
    """
    console.print()
    print_header("Full Network Security Audit", "Discover and scan all hosts in a subnet")

    try:
        network = prompt_network()

        src_choice = print_menu(
            [
                "Discover automatically (recommended)",
                "Load hosts from discovery JSON file",
            ],
            "Host source",
        )

        hosts: list[dict] = []

        if src_choice == 0:
            from src.scanner.network_discovery import NetworkDiscovery

            nd = NetworkDiscovery(network, timeout=3, max_workers=100)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(f"Discovering {network}...", total=None)
                hosts = nd.discover_hosts()
                progress.update(task, description=f"Found {len(hosts)} hosts ✓")
        else:
            file_path = console.input(
                "[cyan]  Path to discovery JSON file:[/] "
            ).strip()
            data = json.loads(Path(file_path).read_text(encoding="utf-8"))
            hosts = (
                data.get("discovered_hosts", data)
                if isinstance(data, dict)
                else data
            )

        if not hosts:
            console.print("[yellow]  No hosts to scan.[/]")
            return

        console.print(f"\n[cyan]  {len(hosts)} hosts ready to scan.[/]")
        workers_raw = console.input("[cyan]  Max parallel workers [10]:[/] ").strip()
        max_workers = int(workers_raw) if workers_raw.isdigit() else 10

        # ── credentials for remote hosts ─────────────────────────────
        batch_credentials: dict[str, str] | None = None
        if confirm("Provide SSH/WinRM credentials for remote hosts?", default=False):
            b_user = console.input("[cyan]  Username:[/] ").strip()
            console.print(
                "[dim]  SSH key file path OR leave blank to use password.[/dim]"
            )
            b_key = console.input(
                "[cyan]  SSH key file (Enter to skip):[/] "
            ).strip()
            if b_key:
                batch_credentials = {"username": b_user, "key_filename": b_key}
            else:
                b_pass = console.input("[cyan]  Password:[/] ").strip()
                if b_pass:
                    batch_credentials = {"username": b_user, "password": b_pass}
                else:
                    batch_credentials = {"username": b_user}

        if not confirm(
            f"Scan {len(hosts)} hosts with {max_workers} workers?", default=True
        ):
            console.print("[yellow]  Cancelled.[/]")
            return

        from src.scanner.batch_scanner import BatchScanner

        batch = BatchScanner(
            hosts, max_workers=max_workers, timeout=300, credentials=batch_credentials
        )
        results = batch.scan_with_progress()

        console.print()
        print_network_stats(results)
        print_network_summary_table(results.get("servers", []))

        safe = network.replace("/", "_").replace(".", "_")
        json_path = Path(f"network_scan_{safe}.json").resolve()
        json_path.write_text(
            json.dumps(results, indent=2, default=str), encoding="utf-8"
        )
        console.print(f"\n[{SUCCESS}]  Scan data saved: {json_path}[/]")

        if confirm("Generate HTML network report?", default=True):
            _generate_network_report(results, network, safe)

    except KeyboardInterrupt:
        console.print(f"\n[{ERROR}]  Network scan cancelled.[/]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Network scan failed: {exc}[/]")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _generate_single_report(scan_result: dict, target: str) -> None:
    """Run Analyzer + HTMLReporter on a single scan result and save HTML.

    Args:
        scan_result: Raw scanner output dict with ``findings`` key.
        target: Server IP/hostname string (used for the output filename).
    """
    try:
        from src.analyzer.analyzer import Analyzer
        from src.reporter.html_generator import HTMLReporter

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            t1 = progress.add_task("Analysing...", total=None)
            analyzer = Analyzer(scan_result.get("findings", []))
            analysis = analyzer.analyze()
            analysis["server"] = scan_result.get("server", target)
            analysis["timestamp"] = scan_result.get("timestamp", "")
            analysis["scan_duration_seconds"] = scan_result.get(
                "scan_duration_seconds", 0
            )
            progress.update(t1, description="Analysis complete ✓")

            t2 = progress.add_task("Rendering report...", total=None)
            reporter = HTMLReporter(analysis)
            safe = target.replace(".", "_")
            out_path = reporter.save(f"{safe}_report.html")
            progress.update(t2, description="Report saved ✓")

        console.print(f"[{SUCCESS}]  Report: {out_path}[/]")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Report generation failed: {exc}[/]")


def _generate_network_report(results: dict, network: str, safe: str | None = None) -> None:
    """Run NetworkReporter on batch scan results and save HTML files.

    Args:
        results: ``BatchScanner`` output dict.
        network: Network range label used in the output directory name.
    """
    try:
        from src.reporter.network_reporter import NetworkReporter

        if safe is None:
            safe = network.replace("/", "_").replace(".", "_")
        out_dir = (Path.cwd() / "reports" / f"network_{safe}").resolve()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Rendering network report...", total=None)
            reporter = NetworkReporter(results)
            paths = reporter.save_reports(str(out_dir))
            progress.update(task, description="Report saved OK")

        console.print(
            f"[{SUCCESS}]  HTML report:  {paths['consolidated_path']}[/]\n"
            f"[{SUCCESS}]  HTML summary: {paths['summary_path']}[/]"
        )

    except Exception as exc:  # noqa: BLE001
        import traceback
        console.print(f"[{ERROR}]  Report generation failed: {exc}[/]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
