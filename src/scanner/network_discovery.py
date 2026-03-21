"""Network Discovery module for Infrastructure Security Auditor.

Discovers live hosts in a network range (CIDR or IP-range notation),
detects OS hints via port probing and TTL heuristics, and returns
structured host dictionaries ready for BatchScanner consumption.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from src.config import logger

# ---------------------------------------------------------------------------
# Type helpers
# ---------------------------------------------------------------------------

HostDict = dict[str, Any]


class NetworkDiscovery:
    """Discover live hosts in a network range with OS auto-detection.

    Supports CIDR notation (``192.168.0.0/24``) and hyphenated IP ranges
    (``192.168.1.1-100``).  Uses ICMP ping sweep (no root required) as the
    primary discovery mechanism, with optional port probing for OS detection.

    Args:
        network_range: CIDR block or hyphenated range string.
        timeout: Per-host timeout in seconds (default: 3).
        max_workers: Thread-pool size (default: 50).

    Example:
        >>> nd = NetworkDiscovery("192.168.1.0/24", timeout=2)
        >>> hosts = nd.discover_hosts()
        >>> info  = nd.get_network_info()
    """

    # Ports probed for OS fingerprinting
    _OS_PORTS: list[int] = [22, 445, 3389, 80, 443]

    def __init__(
        self,
        network_range: str,
        timeout: int = 3,
        max_workers: int = 50,
    ) -> None:
        self.network_range = network_range
        self.timeout = timeout
        self.max_workers = max_workers
        self._hosts: list[HostDict] = []
        self._start_time: float = 0.0
        self._discovery_duration: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_hosts(self) -> list[HostDict]:
        """Discover all live hosts in the configured network range.

        Performs a parallel ping sweep; live hosts are further probed for
        hostname resolution and OS fingerprinting.

        Returns:
            Sorted list of host dicts, each containing:
            ``ip``, ``hostname``, ``os_hint``, ``ports_open``,
            ``is_alive``, ``response_time_ms``.
        """
        ips = self._parse_network_range(self.network_range)
        logger.info("Starting discovery of %d IPs in %s", len(ips), self.network_range)
        self._start_time = time.monotonic()

        results: list[HostDict] = []
        workers = min(self.max_workers, len(ips)) if ips else 1
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._check_host, ip): ip for ip in ips}
            for future in as_completed(futures):
                try:
                    host = future.result(timeout=self.timeout + 2)
                    if host["is_alive"]:
                        results.append(host)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Host check error: %s", exc)

        self._discovery_duration = time.monotonic() - self._start_time

        try:
            results.sort(key=lambda h: socket.inet_aton(h["ip"]))
        except OSError:
            results.sort(key=lambda h: h["ip"])

        self._hosts = results
        logger.info(
            "Discovery complete: %d live hosts found in %.1fs",
            len(results),
            self._discovery_duration,
        )
        return results

    def detect_os(self, ip: str) -> str:
        """Detect the operating system of a host via port probing and TTL.

        Tries (in order):
        1. Port presence: 3389/445 → ``"windows"``, 22 alone → ``"linux"``
        2. TTL heuristic: ~128 → ``"windows"``, ~64 → ``"linux"``

        Args:
            ip: Target IP address string.

        Returns:
            ``"windows"``, ``"linux"``, or ``"unknown"``.
        """
        ports = self._probe_ports(ip, self._OS_PORTS)
        return self._detect_os_from_ports(ports, ip)

    def get_network_info(self) -> dict[str, Any]:
        """Return aggregated statistics from the last ``discover_hosts()`` call.

        Returns:
            Dict with network metadata and host counts.  Returns zeros if
            ``discover_hosts()`` has not been called yet.
        """
        windows_count = sum(1 for h in self._hosts if h.get("os_hint") == "windows")
        linux_count = sum(1 for h in self._hosts if h.get("os_hint") == "linux")
        unknown_count = sum(1 for h in self._hosts if h.get("os_hint") == "unknown")

        try:
            net = ipaddress.ip_network(self.network_range, strict=False)
            total_possible = net.num_addresses - 2  # exclude network + broadcast
            subnet_mask = str(net.netmask)
        except ValueError:
            total_possible = 0
            subnet_mask = "unknown"

        discovered = len(self._hosts)
        success_rate = discovered / total_possible if total_possible else 0.0

        return {
            "network": self.network_range,
            "subnet_mask": subnet_mask,
            "total_possible_hosts": total_possible,
            "discovered_hosts": discovered,
            "windows_hosts": windows_count,
            "linux_hosts": linux_count,
            "unknown_os": unknown_count,
            "discovery_duration_seconds": round(self._discovery_duration, 2),
            "success_rate": round(success_rate, 4),
            "scan_timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_network_range(self, network_range: str) -> list[str]:
        """Parse a CIDR block or hyphenated range into a flat list of IP strings.

        Args:
            network_range: ``"192.168.0.0/24"`` or ``"192.168.1.1-100"``.

        Returns:
            List of IP address strings (excludes network/broadcast for CIDR).

        Raises:
            ValueError: If the range format is unrecognisable.
        """
        network_range = network_range.strip()

        if "/" in network_range:
            try:
                net = ipaddress.ip_network(network_range, strict=False)
                return [str(h) for h in net.hosts()]
            except ValueError as exc:
                raise ValueError(
                    f"Invalid CIDR range '{network_range}': {exc}"
                ) from exc

        if "-" in network_range:
            parts = network_range.split("-")
            if len(parts) == 2:
                base_ip = parts[0].strip()
                end_octet_str = parts[1].strip()
                try:
                    base_parts = base_ip.split(".")
                    start_octet = int(base_parts[-1])
                    end_octet = int(end_octet_str)
                    prefix = ".".join(base_parts[:-1])
                    return [
                        f"{prefix}.{i}"
                        for i in range(start_octet, end_octet + 1)
                    ]
                except (ValueError, IndexError) as exc:
                    raise ValueError(
                        f"Invalid IP range '{network_range}': {exc}"
                    ) from exc

        try:
            ipaddress.ip_address(network_range)
            return [network_range]
        except ValueError as exc:
            raise ValueError(
                f"Unrecognised network range format: '{network_range}'"
            ) from exc

    def _check_host(self, ip: str) -> HostDict:
        """Ping a host and, if alive, resolve hostname and detect OS.

        Args:
            ip: IP address to check.

        Returns:
            HostDict with ``is_alive`` flag and associated metadata.
        """
        t0 = time.monotonic()
        is_alive = self._ping(ip)
        response_time_ms = int((time.monotonic() - t0) * 1000)

        hostname = "unknown"
        ports_open: list[int] = []
        os_hint = "unknown"

        if is_alive:
            hostname = self._resolve_hostname(ip)
            ports_open = self._probe_ports(ip, self._OS_PORTS)
            os_hint = self._detect_os_from_ports(ports_open, ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "os_hint": os_hint,
            "ports_open": ports_open,
            "is_alive": is_alive,
            "response_time_ms": response_time_ms,
        }

    def _ping(self, ip: str) -> bool:
        """Send a single ICMP ping to *ip* and return True if it responds.

        Uses the platform-appropriate ``ping`` command with a short timeout.

        Args:
            ip: Target IP address.

        Returns:
            ``True`` if the host is reachable, ``False`` otherwise.
        """
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(self.timeout), ip]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 1,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _probe_ports(self, ip: str, ports: list[int]) -> list[int]:
        """Attempt TCP connections to a list of ports and return open ones.

        Args:
            ip: Target IP address.
            ports: Port numbers to probe.

        Returns:
            List of open port numbers.
        """
        open_ports: list[int] = []
        probe_timeout = min(self.timeout, 2)
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=probe_timeout):
                    open_ports.append(port)
            except (OSError, socket.timeout):
                pass
        return open_ports

    def _detect_os_from_ports(self, open_ports: list[int], ip: str) -> str:
        """Infer OS from open port set and optional TTL heuristic.

        Priority:
        1. Port 3389 (RDP) or 445 (SMB) → ``"windows"``
        2. Port 22 (SSH) without 3389/445 → ``"linux"``
        3. TTL probe → ``"windows"`` (TTL ~128) or ``"linux"`` (TTL ~64)
        4. Fallback → ``"unknown"``

        Args:
            open_ports: List of open port numbers already probed.
            ip: IP for TTL fallback probe.

        Returns:
            OS hint string.
        """
        if 3389 in open_ports or 445 in open_ports:
            return "windows"
        if 22 in open_ports and 3389 not in open_ports and 445 not in open_ports:
            return "linux"

        ttl = self._get_ttl(ip)
        if ttl is not None:
            if 100 <= ttl <= 130:
                return "windows"
            if 50 <= ttl <= 70:
                return "linux"

        return "unknown"

    def _get_ttl(self, ip: str) -> int | None:
        """Extract TTL value from a single ping response.

        Args:
            ip: Target IP address.

        Returns:
            TTL integer or ``None`` if unavailable.
        """
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "2000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", ip]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=4,
            )
            output = result.stdout + result.stderr
            for token in output.split():
                token_lower = token.lower()
                if token_lower.startswith("ttl="):
                    try:
                        return int(token_lower.split("=")[1])
                    except (IndexError, ValueError):
                        pass
        except Exception:  # noqa: BLE001
            pass
        return None

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse-DNS lookup for *ip*.

        Args:
            ip: IP address string.

        Returns:
            Hostname string or ``"unknown"`` on failure.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return "unknown"
