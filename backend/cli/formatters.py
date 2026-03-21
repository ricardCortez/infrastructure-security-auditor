"""Output formatters using Rich for styled terminal output."""
import csv
import io
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class Formatters:
    """Collection of display formatters for CLI output."""

    console = console

    @staticmethod
    def table(data: list, headers: list = None, title: str = None) -> None:
        """Render a Rich table from a list of rows or dicts.

        Args:
            data: List of lists (rows) or list of dicts.
            headers: Column header labels.
            title: Optional table title.
        """
        if not data:
            console.print("[yellow]No data to display[/yellow]")
            return

        table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold cyan")

        if headers:
            for header in headers:
                table.add_column(str(header))
            for row in data:
                if isinstance(row, dict):
                    table.add_row(*[str(row.get(h, "")) for h in headers])
                else:
                    table.add_row(*[str(cell) for cell in row])
        else:
            if data and isinstance(data[0], dict):
                for k in data[0].keys():
                    table.add_column(str(k), style="cyan")
                for row in data:
                    table.add_row(*[str(v) for v in row.values()])

        console.print(table)

    @staticmethod
    def json_output(data) -> None:
        """Pretty-print JSON data."""
        console.print_json(data=data)

    @staticmethod
    def csv_output(data: list, headers: list) -> None:
        """Print data as CSV to stdout."""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)
        console.print(output.getvalue())

    @staticmethod
    def success(message: str) -> None:
        """Print a green success message."""
        console.print(f"[green]OK[/green] {message}")

    @staticmethod
    def error(message: str) -> None:
        """Print a red error message."""
        console.print(f"[red]ERROR[/red] {message}")

    @staticmethod
    def info(message: str) -> None:
        """Print a blue informational message."""
        console.print(f"[blue]INFO[/blue] {message}")

    @staticmethod
    def warn(message: str) -> None:
        """Print a yellow warning message."""
        console.print(f"[yellow]WARN[/yellow] {message}")

    @staticmethod
    def panel(content: str, title: Optional[str] = None, style: str = "cyan") -> None:
        """Render content inside a Rich panel box."""
        console.print(Panel(content, title=title, style=style, expand=False))
