"""PSI CLI - Interactive menu + direct command interface."""
import os
import sys
from pathlib import Path
import click
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from . import __version__
from .auth import auth
from .config import config
from .formatters import Formatters
from .commands.auth import auth_group
from .commands.assets import assets_group
from .commands.findings import findings_group
from .commands.scans import scans_group
from .commands.reports import reports_group
from .commands.dashboard import dashboard_group
from .commands.auditor import auditor_group

console = Console()

MENU_OPTIONS = {
    "1": ("Assets Management",       "Create, list, and manage security assets"),
    "2": ("Findings Management",     "Triage vulnerabilities, track remediation"),
    "3": ("Scans & Jobs",            "Initiate and monitor vulnerability scans"),
    "4": ("Infrastructure Auditor",  "Run local security audits (Windows/Linux)"),
    "5": ("Reports & Dashboard",     "Generate reports, view real-time dashboards"),
    "6": ("Settings",                "Configure API URL and authentication"),
    "7": ("Help & Documentation",    "View docs and command examples"),
    "0": ("Exit",                    "Quit PSI CLI"),
}


class PSICLIApp:
    """Interactive TUI application for PSI."""

    def __init__(self) -> None:
        self.running = True

    # ─────────────────────────── helpers ────────────────────────────

    def _pause(self) -> None:
        console.input("\n[dim]Press Enter to continue...[/dim]")

    def _get_or_create_asset(self, target: str) -> int:
        """Return asset ID for *target* IP/hostname, creating one if it doesn't exist."""
        from . import local_db as db
        existing = db.get_all("assets", {"ip_address": target})
        if existing:
            Formatters.info(f"Asset existente encontrado: ID={existing[0]['id']} ({existing[0]['hostname']})")
            return existing[0]["id"]
        # Also try by hostname
        existing = db.get_all("assets", {"hostname": target})
        if existing:
            Formatters.info(f"Asset existente encontrado: ID={existing[0]['id']} ({existing[0]['ip_address']})")
            return existing[0]["id"]
        # Create new asset automatically
        row = db.insert("assets", {
            "hostname": target,
            "ip_address": target,
            "asset_type": "server",
            "criticality": "medium",
        })
        Formatters.success(f"Asset creado automaticamente: ID={row['id']} ({target})")
        return row["id"]

    def _expand_range(self, target: str) -> list:
        """Expand a CIDR range or return a single-item list."""
        import ipaddress
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 256:
                Formatters.warn(f"Rango grande ({net.num_addresses} hosts). Limitando a los primeros 256.")
                hosts = list(net.hosts())[:256]
            else:
                hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
            return [str(h) for h in hosts]
        except ValueError:
            return [target]  # single hostname or IP

    def _discover_hosts(self, targets: list) -> list:
        """Return only reachable hosts from the list (quick port probe)."""
        import socket
        alive = []
        _PROBE_PORTS = [22, 80, 135, 443, 445, 3389, 8080]
        console.print(f"[dim]Descubriendo hosts activos ({len(targets)} IPs)...[/dim]")
        for ip in targets:
            reachable = False
            for port in _PROBE_PORTS:
                try:
                    s = socket.create_connection((ip, port), timeout=0.5)
                    s.close()
                    reachable = True
                    break
                except OSError:
                    pass
            if reachable:
                alive.append(ip)
                console.print(f"  [green]VIVO[/green] {ip}")
        if not alive:
            Formatters.warn("No se encontraron hosts activos en ese rango.")
        else:
            Formatters.info(f"{len(alive)} host(s) activos encontrados.")
        return alive

    def _clear(self) -> None:
        """Reliably clear the terminal on any OS."""
        if sys.platform == "win32":
            os.system("cls")
        else:
            os.system("clear")

    def _header(self, title: str) -> None:
        self._clear()
        console.print(Panel(f"[bold cyan]{title}[/bold cyan]", expand=False))
        console.print()

    def _run(self, cmd_group, subcommand: str, *args) -> None:
        """Invoke a Click subcommand directly so Rich output and prompts use the real terminal."""
        try:
            cmd_group([subcommand] + list(args), standalone_mode=False)
        except click.Abort:
            console.print("\n[yellow]Cancelled.[/yellow]")
        except click.ClickException as e:
            Formatters.error(e.format_message())
        except SystemExit:
            pass
        except Exception as e:
            Formatters.error(str(e))
        self._pause()

    # ──────────────────────────── menus ─────────────────────────────

    def show_main_menu(self) -> None:
        self._clear()
        console.print(Align.center(f"[bold cyan]PSI - Plataforma de Seguridad Integrada[/bold cyan]"))
        console.print(Align.center(f"[dim]Enterprise Security Platform CLI v{__version__}[/dim]\n"))

        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column(style="bold cyan", width=4)
        tbl.add_column(style="white", width=25)
        tbl.add_column(style="dim")
        for key, (title, desc) in MENU_OPTIONS.items():
            tbl.add_row(f"[{key}]", title, desc)
        console.print(tbl)
        console.print()

    # ── assets ──

    def show_assets_menu(self) -> None:
        while True:
            self._header("ASSETS MANAGEMENT")
            console.print(
                "[bold]  1.[/bold] List all assets       [dim]Muestra todos los servidores/hosts registrados[/dim]\n"
                "[bold]  2.[/bold] Create new asset      [dim]Registra un nuevo host (pide hostname, IP, tipo, criticidad)[/dim]\n"
                "[bold]  3.[/bold] Show asset details    [dim]Ver todos los campos de un asset por ID[/dim]\n"
                "[bold]  4.[/bold] Delete asset          [dim]Elimina un asset por ID (pide confirmacion)[/dim]\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            if choice == "1":
                self._run(assets_group, "list")
            elif choice == "2":
                self._run(assets_group, "create")
            elif choice == "3":
                aid = console.input("Asset ID: ").strip()
                self._run(assets_group, "show", aid)
            elif choice == "4":
                aid = console.input("Asset ID: ").strip()
                self._run(assets_group, "delete", "--id", aid)
            elif choice == "0":
                break

    # ── findings ──

    def show_findings_menu(self) -> None:
        while True:
            self._header("FINDINGS MANAGEMENT")
            console.print(
                "[bold]  1.[/bold] List all findings     [dim]Tabla con ID, titulo, severidad, estado de todas las vulnerabilidades[/dim]\n"
                "[bold]  2.[/bold] Critical only         [dim]Filtra y muestra solo findings CRITICAL[/dim]\n"
                "[bold]  3.[/bold] Create new finding    [dim]Registra vulnerabilidad (pide asset-id, titulo, severidad)[/dim]\n"
                "[bold]  4.[/bold] Update status         [dim]Cambia estado: OPEN / IN_PROGRESS / FIXED / CLOSED (pide ID)[/dim]\n"
                "[bold]  5.[/bold] Summary stats         [dim]Conteo por severidad y estado de todos los findings[/dim]\n"
                "[bold]  6.[/bold] Filter findings       [dim]Filtra por severidad y/o estado a eleccion[/dim]\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            if choice == "1":
                self._run(findings_group, "list")
            elif choice == "2":
                self._run(findings_group, "list", "--severity", "CRITICAL")
            elif choice == "3":
                self._run(findings_group, "create")
            elif choice == "4":
                fid = console.input("Finding ID: ").strip()
                st = console.input("New status (OPEN/IN_PROGRESS/FIXED/CLOSED): ").strip()
                self._run(findings_group, "update", "--id", fid, "--status", st)
            elif choice == "5":
                self._run(findings_group, "summary")
            elif choice == "6":
                sev = console.input("Severity (or Enter to skip): ").strip()
                st = console.input("Status (or Enter to skip): ").strip()
                extra = []
                if sev:
                    extra += ["--severity", sev]
                if st:
                    extra += ["--status", st]
                self._run(findings_group, "list", *extra)
            elif choice == "0":
                break

    # ── scans ──

    def show_scans_menu(self) -> None:
        while True:
            self._header("SCANS & JOBS")
            console.print(
                "[bold]  1.[/bold] Scan por IP / rango   [dim]Solo da la IP o rango CIDR (ej: 192.168.1.10 o 192.168.1.0/24)[/dim]\n"
                "                       [dim]El asset se crea automaticamente si no existe[/dim]\n"
                "[bold]  2.[/bold] List scan jobs        [dim]Muestra todos los jobs con estado y timestamps[/dim]\n"
                "[bold]  3.[/bold] Check scan status     [dim]Ver detalle de un job por ID[/dim]\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            if choice == "1":
                tgt = console.input("Target IP / hostname / rango CIDR: ").strip()
                if not tgt:
                    continue
                os_ = console.input("OS type [windows/linux/auto] (Enter=auto): ").strip() or "auto"
                targets = self._expand_range(tgt)
                if len(targets) > 1:
                    targets = self._discover_hosts(targets)
                if not targets:
                    self._pause()
                    continue
                for host in targets:
                    aid = self._get_or_create_asset(host)
                    self._run(scans_group, "start",
                              "--asset-id", str(aid), "--scanner", "auditor",
                              "--target", host, "--os-type", os_)
            elif choice == "2":
                self._run(scans_group, "list")
            elif choice == "3":
                jid = console.input("Job ID: ").strip()
                self._run(scans_group, "status", jid)
            elif choice == "0":
                break

    # ── reports ──

    def show_reports_menu(self) -> None:
        while True:
            self._header("REPORTS & DASHBOARD")
            console.print(
                "[bold]  1.[/bold] Live dashboard        [dim]Resumen en tiempo real: assets, findings por severidad[/dim]\n"
                "[bold]  2.[/bold] Full findings report  [dim]Reporte completo en terminal: resumen + tabla + remediaciones urgentes[/dim]\n"
                "[bold]  3.[/bold] Export JSON           [dim]Guarda findings en ~/.psi/reports/psi_report_FECHA.json[/dim]\n"
                "[bold]  4.[/bold] List saved reports    [dim]Muestra reportes JSON generados anteriormente[/dim]\n"
                "[bold]  5.[/bold] Export assets CSV     [dim]Exporta lista de assets en formato CSV[/dim]\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            if choice == "1":
                self._run(dashboard_group, "view")
            elif choice == "2":
                self._run(reports_group, "generate", "--format", "terminal")
            elif choice == "3":
                self._run(reports_group, "generate", "--format", "json")
            elif choice == "4":
                self._run(reports_group, "list")
            elif choice == "5":
                self._run(assets_group, "list", "--format", "csv")
            elif choice == "0":
                break

    # ── auditor ──

    def show_auditor_menu(self) -> None:
        while True:
            self._header("INFRASTRUCTURE AUDITOR")
            console.print(
                "[cyan]Escaneo de seguridad local Windows/Linux (sin servidor externo)[/cyan]\n\n"
                "[bold]  1.[/bold] Open Auditor TUI      [dim]Lanza el menu interactivo completo del auditor[/dim]\n"
                "                       [dim]Opciones: scan unico, descubrir red, scan de red, generar reporte[/dim]\n"
                "[bold]  2.[/bold] Run scan (quick)      [dim]Lanza scan rapido via CLI (pide target y OS)[/dim]\n"
                "[bold]  3.[/bold] View results          [dim]Muestra findings importados desde el ultimo scan[/dim]\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            if choice == "1":
                self._launch_auditor_tui()
            elif choice == "2":
                self._run(auditor_group, "scan")
            elif choice == "3":
                self._run(auditor_group, "results")
            elif choice == "0":
                break

    def _launch_auditor_tui(self) -> None:
        """Launch the full auditor interactive TUI as a subprocess."""
        import subprocess
        _AUDITOR = Path(__file__).resolve().parents[3] / "auditor.py"
        if not _AUDITOR.exists():
            Formatters.error(f"auditor.py not found at {_AUDITOR}")
            self._pause()
            return
        try:
            subprocess.run(
                [sys.executable, str(_AUDITOR), "interactive"],
                check=False,
            )
        except Exception as exc:
            Formatters.error(f"Could not launch auditor TUI: {exc}")
            self._pause()

    # ── settings ──

    def show_settings_menu(self) -> None:
        while True:
            self._header("SETTINGS")
            console.print(
                f"  [dim]API URL:[/dim]     {config.get('api_url')}\n"
                f"  [dim]Username:[/dim]    {config.get('username') or 'Not set'}\n"
                f"  [dim]Config:[/dim]      ~/.psi/config.yaml\n"
            )
            console.print(
                "[bold]  1.[/bold] Change API URL\n"
                "[bold]  2.[/bold] Re-authenticate\n"
                "[bold]  3.[/bold] View full config (JSON)\n"
                "[bold]  4.[/bold] Reset to defaults\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            if choice == "1":
                new_url = console.input("New API URL: ").strip()
                if new_url:
                    config.set("api_url", new_url)
                    Formatters.success(f"API URL set to {new_url}")
                self._pause()
            elif choice == "2":
                self._run(auth_group, "login")
            elif choice == "3":
                Formatters.json_output(config.data)
                self._pause()
            elif choice == "4":
                if console.input("Reset config? (y/n): ").strip().lower() == "y":
                    config.data = {
                        "api_url": "http://localhost:8000",
                        "api_version": "v1",
                        "username": None,
                        "token": None,
                    }
                    config.save()
                    Formatters.success("Config reset to defaults.")
                self._pause()
            elif choice == "0":
                break

    # ── help ──

    def show_help_menu(self) -> None:
        while True:
            self._header("HELP & DOCUMENTATION")
            console.print(
                "[bold]  1.[/bold] Getting Started\n"
                "[bold]  2.[/bold] Authentication\n"
                "[bold]  3.[/bold] Asset Management\n"
                "[bold]  4.[/bold] Vulnerability Management\n"
                "[bold]  5.[/bold] Scanning\n"
                "[bold]  6.[/bold] Reporting\n"
                "[bold]  7.[/bold] Full Command Reference\n"
                "[bold]  8.[/bold] Troubleshooting\n"
                "[bold]  0.[/bold] Back\n"
            )
            choice = console.input("[cyan]> [/cyan]").strip()
            topics = {
                "1": self._help_getting_started,
                "2": self._help_auth,
                "3": self._help_assets,
                "4": self._help_findings,
                "5": self._help_scans,
                "6": self._help_reporting,
                "7": self._help_reference,
                "8": self._help_troubleshooting,
            }
            if choice in topics:
                topics[choice]()
            elif choice == "0":
                break

    def _help_getting_started(self) -> None:
        self._header("GETTING STARTED")
        console.print("""[bold]Step 1:[/bold] Login
  psi auth login

[bold]Step 2:[/bold] View assets
  psi assets list

[bold]Step 3:[/bold] Check vulnerabilities
  psi findings list

[bold]Step 4:[/bold] Remediate issues
  psi findings update --id 1 --status IN_PROGRESS

[bold]Step 5:[/bold] Generate report
  psi reports generate --format pdf""")
        self._pause()

    def _help_auth(self) -> None:
        self._header("AUTHENTICATION")
        console.print("""[green]psi auth login[/green]    Login (JWT token stored in ~/.psi/config.yaml)
[green]psi auth logout[/green]   Clear token
[green]psi auth status[/green]   Check current login status""")
        self._pause()

    def _help_assets(self) -> None:
        self._header("ASSET MANAGEMENT")
        console.print("""[green]psi assets list[/green]                  List all assets
[green]psi assets list --format json[/green]    Export JSON
[green]psi assets list --format csv[/green]     Export CSV
[green]psi assets create[/green]                Create asset (interactive)
[green]psi assets show <id>[/green]             View asset details
[green]psi assets delete --id <id>[/green]      Delete asset

[bold]Criticality levels:[/bold] low | medium | high | critical
[bold]Asset types:[/bold] server | database | network-device | web-server""")
        self._pause()

    def _help_findings(self) -> None:
        self._header("VULNERABILITY MANAGEMENT")
        console.print("""[green]psi findings list[/green]                         All findings
[green]psi findings list --severity CRITICAL[/green]    Critical only
[green]psi findings list --status OPEN[/green]          Open issues
[green]psi findings create --asset-id 1[/green]         Log manually
[green]psi findings update --id 1 --status FIXED[/green] Mark resolved
[green]psi findings summary[/green]                     Stats overview

[bold]Severity:[/bold] CRITICAL > HIGH > MEDIUM > LOW > INFO
[bold]Workflow:[/bold] OPEN -> IN_PROGRESS -> FIXED -> CLOSED""")
        self._pause()

    def _help_scans(self) -> None:
        self._header("VULNERABILITY SCANNING")
        console.print("""[green]psi scans start --asset-id 1 --scanner nessus[/green]
[green]psi scans start --asset-id 2 --scanner openvas[/green]
[green]psi scans list[/green]
[green]psi scans status <job_id>[/green]

[bold]Supported scanners:[/bold] nessus | openvas""")
        self._pause()

    def _help_reporting(self) -> None:
        self._header("REPORTING")
        console.print("""[green]psi reports generate --format pdf[/green]
[green]psi reports generate --format excel[/green]
[green]psi reports generate --format json[/green]
[green]psi reports list[/green]
[green]psi dashboard view[/green]

[bold]Data export:[/bold]
  psi assets list --format csv > assets.csv
  psi findings list --format json > findings.json""")
        self._pause()

    def _help_reference(self) -> None:
        self._header("COMMAND REFERENCE")
        console.print("""[bold cyan]auth[/bold cyan]      login | logout | status
[bold cyan]assets[/bold cyan]    list | create | show | delete
[bold cyan]findings[/bold cyan]  list | create | update | show | summary
[bold cyan]scans[/bold cyan]     start | list | status
[bold cyan]reports[/bold cyan]   generate | list
[bold cyan]dashboard[/bold cyan] view

[bold]Global options:[/bold]  --version   --help
[bold]Formats:[/bold]         --format table | json | csv""")
        self._pause()

    def _help_troubleshooting(self) -> None:
        self._header("TROUBLESHOOTING")
        console.print("""[bold]Local database:[/bold]
  Location: ~/.psi/psi.db  (SQLite, no server needed)
  Reset:    rm ~/.psi/psi.db

[bold]Config corruption:[/bold]
  rm ~/.psi/config.yaml  (will recreate on next run)

[bold]Auditor scan fails:[/bold]
  Check target is reachable: ping <target>
  For Windows: ensure WinRM is enabled on target
  For Linux:   ensure SSH access is available

[bold]Debug:[/bold]
  DB location  -> ~/.psi/psi.db
  Config       -> ~/.psi/config.yaml
  Reports      -> ~/.psi/reports/""")
        self._pause()

    # ─────────────────────────── main loop ──────────────────────────

    def run(self) -> None:
        """Start the interactive menu loop (local SQLite mode - no server needed)."""

        handlers = {
            "1": self.show_assets_menu,
            "2": self.show_findings_menu,
            "3": self.show_scans_menu,
            "4": self.show_auditor_menu,
            "5": self.show_reports_menu,
            "6": self.show_settings_menu,
            "7": self.show_help_menu,
        }

        while self.running:
            self.show_main_menu()
            choice = console.input("[cyan]Choose option: [/cyan]").strip()
            if choice in handlers:
                handlers[choice]()
            elif choice == "0":
                Formatters.success("Goodbye!")
                self.running = False
            else:
                console.print("[red]Invalid option.[/red]")
                self._pause()


# ─────────────────────── Click commands ─────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="psi")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PSI - Plataforma de Seguridad Integrada

    \b
    Interactive mode:  python psi.py menu
    Direct commands:   python psi.py assets list
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("menu")
def interactive_menu() -> None:
    """Launch interactive TUI menu."""
    app = PSICLIApp()
    app.run()


cli.add_command(auth_group,      name="auth")
cli.add_command(assets_group,    name="assets")
cli.add_command(findings_group,  name="findings")
cli.add_command(scans_group,     name="scans")
cli.add_command(reports_group,   name="reports")
cli.add_command(dashboard_group, name="dashboard")
cli.add_command(auditor_group,   name="auditor")

if __name__ == "__main__":
    cli()
