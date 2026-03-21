"""Main menu logic for the TUI.

Provides :class:`MainMenu` which presents the top-level navigation and
routes user choices to the appropriate UI flows.
"""

from __future__ import annotations

from src.tui.components import console, print_banner, print_menu
from src.tui.styles import MUTED


class MainMenu:
    """Top-level interactive menu for the security auditor.

    Presents five options and routes to the appropriate handler function.

    Example:
        >>> menu = MainMenu()
        >>> menu.run()
    """

    OPTIONS: list[str] = [
        "Scan Single Server",
        "Discover Network Hosts",
        "Scan Entire Network",
        "Generate Report from JSON",
        "Exit",
    ]

    def show(self) -> int:
        """Display the main menu and return the selected option index.

        Returns:
            Zero-based index of the selected option (0–4).
        """
        console.print()
        return print_menu(self.OPTIONS, "Infrastructure Security Auditor")

    def handle_choice(self, choice: int) -> bool:
        """Route a menu choice to the appropriate handler.

        Args:
            choice: Zero-based option index from :meth:`show`.

        Returns:
            ``False`` when the user selects Exit, ``True`` otherwise.
        """
        if choice == 0:
            self._run_single_scan()
        elif choice == 1:
            self._run_discovery()
        elif choice == 2:
            self._run_network_scan()
        elif choice == 3:
            self._run_report()
        elif choice == 4:
            return False
        return True

    def run(self) -> None:
        """Enter the main menu loop until the user chooses to exit.

        Catches :class:`KeyboardInterrupt` (Ctrl-C) and exits gracefully.
        """
        print_banner()
        while True:
            try:
                choice = self.show()
                should_continue = self.handle_choice(choice)
                if not should_continue:
                    console.print(f"\n[{MUTED}]Goodbye![/]\n")
                    break
            except KeyboardInterrupt:
                console.print(f"\n[{MUTED}]Interrupted. Goodbye![/]\n")
                break

    # ------------------------------------------------------------------
    # Private route methods
    # ------------------------------------------------------------------

    def _run_single_scan(self) -> None:
        """Launch the single-server scan UI flow."""
        from src.tui.scanner_ui import single_server_scan_ui

        single_server_scan_ui()

    def _run_discovery(self) -> None:
        """Launch the network host discovery UI flow."""
        from src.tui.scanner_ui import network_discovery_ui

        network_discovery_ui()

    def _run_network_scan(self) -> None:
        """Launch the full network batch scan UI flow."""
        from src.tui.scanner_ui import network_scan_ui

        network_scan_ui()

    def _run_report(self) -> None:
        """Launch the report generation UI flow."""
        from src.tui.results_ui import generate_report_ui

        generate_report_ui()
