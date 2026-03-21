"""Results display UI flow for the TUI.

Provides :func:`generate_report_ui` which guides the user through loading
an existing JSON scan file and generating a professional HTML report.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, TextColumn

from src.tui.components import confirm, console, print_header, print_menu
from src.tui.styles import ERROR, SUCCESS


def generate_report_ui() -> None:
    """Interactive flow for generating an HTML report from a saved JSON file.

    Auto-detects whether the JSON is a single-server scan (``findings`` key)
    or a network batch scan (``servers`` key) and routes accordingly.
    """
    console.print()
    print_header("Generate Report", "Produce an HTML report from saved scan data")

    try:
        file_path = console.input("[cyan]  Path to JSON scan file:[/] ").strip()
        path = Path(file_path)
        if not path.exists():
            console.print(f"[{ERROR}]  File not found: {file_path}[/]")
            return

        data = json.loads(path.read_text(encoding="utf-8"))

        if "servers" in data:
            _network_report_flow(data)
        elif "findings" in data:
            _single_report_flow(data, path.stem)
        else:
            console.print(
                f"[{ERROR}]  Unrecognised JSON format. "
                "Expected 'findings' (single scan) or 'servers' (network scan).[/]"
            )

    except KeyboardInterrupt:
        console.print("\n[yellow]  Cancelled.[/]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Failed: {exc}[/]")


# ---------------------------------------------------------------------------
# Private flow helpers
# ---------------------------------------------------------------------------


def _single_report_flow(data: dict, stem: str) -> None:
    """Generate an HTML report for a single-server scan.

    Args:
        data: Parsed scan JSON with ``findings`` key.
        stem: Filename stem used for the default output filename.
    """
    out_name = (
        console.input(
            f"[cyan]  Output HTML file [{stem}_report.html]:[/] "
        ).strip()
        or f"{stem}_report.html"
    )

    use_ai = confirm("Use Claude AI for recommendations?", default=False)
    if not use_ai:
        import os

        os.environ.setdefault("CLAUDE_API_KEY", "")

    try:
        from src.analyzer.analyzer import Analyzer
        from src.reporter.html_generator import HTMLReporter

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            t1 = progress.add_task("Analysing findings...", total=None)
            analyzer = Analyzer(data["findings"])
            analysis = analyzer.analyze()
            analysis["server"] = data.get("server", "Unknown")
            analysis["timestamp"] = data.get("timestamp", "")
            analysis["scan_duration_seconds"] = data.get("scan_duration_seconds", 0)
            progress.update(t1, description="Analysis complete ✓")

            t2 = progress.add_task("Rendering HTML...", total=None)
            reporter = HTMLReporter(analysis)
            saved_path = reporter.save(out_name)
            progress.update(t2, description="Report saved ✓")

        console.print(f"[{SUCCESS}]  Report saved: {saved_path}[/]")
        score = analysis.get("risk_score", 0)
        label = analysis.get("risk_label", "")
        console.print(f"[cyan]  Risk Score: {score}/10 ({label})[/]")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Report generation failed: {exc}[/]")


def _network_report_flow(data: dict) -> None:
    """Generate HTML reports for a network batch scan.

    Args:
        data: Parsed batch scan JSON with ``servers`` key.
    """
    out_dir = (
        console.input(
            "[cyan]  Output directory [reports/network]:[/] "
        ).strip()
        or "reports/network"
    )

    report_type = print_menu(
        [
            "Consolidated report + summary (recommended)",
            "Summary page only",
        ],
        "Report type",
    )

    try:
        from src.reporter.network_reporter import NetworkReporter

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Rendering network report...", total=None)
            reporter = NetworkReporter(data)

            if report_type == 0:
                paths = reporter.save_reports(out_dir)
                progress.update(task, description="Reports saved ✓")
                console.print(
                    f"[{SUCCESS}]  Consolidated: {paths['consolidated_path']}[/]\n"
                    f"[{SUCCESS}]  Summary:      {paths['summary_path']}[/]"
                )
            else:
                out = Path(out_dir)
                out.mkdir(parents=True, exist_ok=True)
                summary_path = out / "network_summary.html"
                summary_path.write_text(
                    reporter.generate_network_summary(), encoding="utf-8"
                )
                progress.update(task, description="Summary saved ✓")
                console.print(f"[{SUCCESS}]  Summary: {summary_path}[/]")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[{ERROR}]  Report generation failed: {exc}[/]")
