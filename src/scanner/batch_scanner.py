"""Batch Scanner module for Infrastructure Security Auditor.

Scans multiple hosts in parallel using existing WindowsScanner and
LinuxScanner, then aggregates findings into a consolidated network-wide
result dictionary.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from src.config import logger

_console = Console()

# ---------------------------------------------------------------------------
# Type helpers
# ---------------------------------------------------------------------------

ServerResult = dict[str, Any]
BatchResult = dict[str, Any]


class BatchScanner:
    """Scan multiple hosts in parallel and return a consolidated result.

    Routes each host to :class:`~src.scanner.windows_scanner.WindowsScanner`
    or :class:`~src.scanner.linux_scanner.LinuxScanner` based on the
    ``os_hint`` field, then aggregates findings into network-wide metrics.

    Args:
        hosts: List of host dicts as returned by
            :meth:`~src.scanner.network_discovery.NetworkDiscovery.discover_hosts`.
        max_workers: Number of parallel scan threads (default: 10).
        timeout: Per-host scan timeout in seconds (default: 300).
        credentials: Optional mapping forwarded to each scanner.
            Keys: ``username``, ``password``, ``key_filename``.

    Example:
        >>> batch = BatchScanner(hosts, max_workers=5)
        >>> results = batch.scan_with_progress()
    """

    def __init__(
        self,
        hosts: list[dict[str, Any]],
        max_workers: int = 10,
        timeout: int = 300,
        credentials: dict[str, str] | None = None,
    ) -> None:
        self.hosts = hosts
        self.max_workers = max_workers
        self.timeout = timeout
        self.credentials = credentials or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_all(self) -> BatchResult:
        """Scan all hosts without a progress bar.

        Returns:
            Consolidated batch result dict — see :meth:`scan_with_progress`
            for the full schema.
        """
        return self._run_batch(show_progress=False)

    def scan_with_progress(self) -> BatchResult:
        """Scan all hosts with a Rich progress bar.

        Displays a live progress bar showing completed/total servers.

        Returns:
            Consolidated batch result dict with keys:
            ``network``, ``scan_timestamp``, ``scan_duration_seconds``,
            ``servers``, ``network_summary``.
        """
        return self._run_batch(show_progress=True)

    # ------------------------------------------------------------------
    # Private implementation
    # ------------------------------------------------------------------

    def _run_batch(self, show_progress: bool = True) -> BatchResult:
        """Execute parallel scans and build the consolidated result.

        Args:
            show_progress: Whether to render a Rich progress bar.

        Returns:
            Full BatchResult dict.
        """
        t_start = time.monotonic()
        scan_timestamp = datetime.now(tz=timezone.utc).isoformat()
        total = len(self.hosts)

        logger.info(
            "BatchScanner: starting %d host scans (%d workers)", total, self.max_workers
        )

        server_results: list[ServerResult] = []
        workers = min(self.max_workers, total) if total else 1

        if show_progress:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Scanning network[/bold cyan]"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TextColumn("[cyan]{task.completed}/{task.total}[/cyan] servers"),
                console=_console,
            )
            task_id = progress.add_task("scan", total=total)
            progress.start()
        else:
            progress = None
            task_id = None

        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(self._scan_host, host): host
                    for host in self.hosts
                }
                for future in future_map:
                    try:
                        result = future.result(timeout=self.timeout)
                        server_results.append(result)
                    except FuturesTimeout:
                        host = future_map[future]
                        server_results.append(self._error_result(host, "timeout"))
                        logger.warning(
                            "Host %s timed out after %ds", host["ip"], self.timeout
                        )
                    except Exception as exc:  # noqa: BLE001
                        host = future_map[future]
                        server_results.append(self._error_result(host, str(exc)))
                        logger.error("Host %s scan error: %s", host["ip"], exc)
                    finally:
                        if progress is not None and task_id is not None:
                            progress.advance(task_id)
        finally:
            if progress is not None:
                progress.stop()

        duration = round(time.monotonic() - t_start, 2)
        network_summary = self._aggregate_network_metrics(server_results)
        network_str = self._infer_network_label()

        logger.info(
            "BatchScanner complete: %d/%d successful in %.1fs",
            network_summary["successful_scans"],
            total,
            duration,
        )

        return {
            "network": network_str,
            "scan_timestamp": scan_timestamp,
            "scan_duration_seconds": duration,
            "servers": server_results,
            "network_summary": network_summary,
        }

    def _scan_host(self, host: dict[str, Any]) -> ServerResult:
        """Scan a single host with the appropriate scanner.

        Args:
            host: Host dict with at least ``ip`` and ``os_hint`` keys.

        Returns:
            ServerResult dict with findings, risk_score, status, etc.
        """
        ip = host["ip"]
        os_hint = host.get("os_hint", "unknown")
        hostname = host.get("hostname", "unknown")

        t0 = time.monotonic()
        logger.info("Scanning %s (%s) as %s", ip, hostname, os_hint)

        try:
            if os_hint == "linux":
                from src.scanner.linux_scanner import LinuxScanner

                scanner = LinuxScanner(target=ip, credentials=self.credentials or None)
            else:
                from src.scanner.windows_scanner import WindowsScanner

                scanner = WindowsScanner(  # type: ignore[assignment]
                    target=ip, credentials=self.credentials or None
                )

            scan_data = scanner.run_scan()
            findings = scan_data.get("findings", [])
            risk_score = self._calculate_risk_score(findings)
            duration = round(time.monotonic() - t0, 2)

            return {
                "ip": ip,
                "os": os_hint if os_hint != "unknown" else "windows",
                "hostname": hostname,
                "status": "success",
                "error_message": "",
                "findings": findings,
                "risk_score": risk_score,
                "scan_duration_seconds": duration,
            }

        except Exception as exc:  # noqa: BLE001
            duration = round(time.monotonic() - t0, 2)
            logger.error("Scan failed for %s: %s", ip, exc)
            return self._error_result(host, str(exc), duration)

    def _error_result(
        self,
        host: dict[str, Any],
        error_msg: str,
        duration: float = 0.0,
    ) -> ServerResult:
        """Build a failed-scan result dict.

        Args:
            host: Host dict.
            error_msg: Error or timeout description.
            duration: Elapsed scan time in seconds.

        Returns:
            ServerResult with ``status != "success"``.
        """
        status = "timeout" if "timeout" in error_msg.lower() else "error"
        return {
            "ip": host.get("ip", "unknown"),
            "os": host.get("os_hint", "unknown"),
            "hostname": host.get("hostname", "unknown"),
            "status": status,
            "error_message": error_msg,
            "findings": [],
            "risk_score": 0.0,
            "scan_duration_seconds": duration,
        }

    def _calculate_risk_score(self, findings: list[dict[str, Any]]) -> float:
        """Compute a 0–10 risk score from a list of findings.

        Uses severity weights: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1.
        Normalises by the maximum possible score for the finding set.

        Args:
            findings: List of FindingDict objects.

        Returns:
            Float risk score 0.0–10.0 (rounded to 1 decimal).
        """
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        total_weight = 0
        max_possible = 0
        for f in findings:
            w = weights.get(f.get("severity", "LOW"), 1)
            max_possible += w
            if f.get("status") in ("FAIL", "WARNING"):
                total_weight += w

        if max_possible == 0:
            return 0.0
        score = min(10.0, (total_weight / max_possible) * 10)
        return round(score, 1)

    def _aggregate_network_metrics(
        self, results: list[ServerResult]
    ) -> dict[str, Any]:
        """Aggregate findings and metrics across all servers.

        Args:
            results: List of individual server scan results.

        Returns:
            Dict with totals, averages, compliance scores, and top servers.
        """
        total = len(results)
        successful = [r for r in results if r["status"] == "success"]
        failed = [r for r in results if r["status"] != "success"]

        sev_counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        compliance_sums: dict[str, float] = {
            "ISO_27001": 0.0, "CIS_Benchmarks": 0.0, "PCI_DSS": 0.0
        }
        total_findings = 0

        for server in successful:
            for finding in server.get("findings", []):
                if finding.get("status") in ("FAIL", "WARNING"):
                    sev = finding.get("severity", "LOW")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    total_findings += 1

            findings = server.get("findings", [])
            if findings:
                pass_count = sum(
                    1 for f in findings if f.get("status") == "PASS"
                )
                pass_rate = pass_count / len(findings)
                for std in compliance_sums:
                    compliance_sums[std] += pass_rate

        n = len(successful) or 1
        compliance_avg = {
            std: round(v / n, 3) for std, v in compliance_sums.items()
        }

        top_critical = sorted(
            successful, key=lambda r: r["risk_score"], reverse=True
        )[:5]
        top_critical_out = [
            {
                "ip": s["ip"],
                "hostname": s.get("hostname", "unknown"),
                "risk_score": s["risk_score"],
                "critical_count": sum(
                    1 for f in s.get("findings", [])
                    if f.get("severity") == "CRITICAL"
                    and f.get("status") != "PASS"
                ),
            }
            for s in top_critical
        ]

        return {
            "total_servers_scanned": total,
            "successful_scans": len(successful),
            "failed_scans": len(failed),
            "total_findings": total_findings,
            "critical_findings": sev_counts["CRITICAL"],
            "high_findings": sev_counts["HIGH"],
            "medium_findings": sev_counts["MEDIUM"],
            "low_findings": sev_counts["LOW"],
            "compliance_iso27001": compliance_avg.get("ISO_27001", 0.0),
            "compliance_cis_benchmarks": compliance_avg.get("CIS_Benchmarks", 0.0),
            "compliance_pci_dss": compliance_avg.get("PCI_DSS", 0.0),
            "top_critical_servers": top_critical_out,
        }

    def _infer_network_label(self) -> str:
        """Derive a best-effort CIDR label from the scanned hosts list.

        Returns:
            A /24 CIDR string based on the first host IP, or ``"unknown"``.
        """
        if not self.hosts:
            return "unknown"
        first_ip = self.hosts[0].get("ip", "")
        if first_ip:
            parts = first_ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "unknown"
