"""Tests for NetworkDiscovery module."""

from __future__ import annotations

import socket
import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

from src.scanner.network_discovery import NetworkDiscovery


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def nd() -> NetworkDiscovery:
    return NetworkDiscovery("192.168.1.0/24", timeout=1, max_workers=5)


@pytest.fixture
def nd_range() -> NetworkDiscovery:
    return NetworkDiscovery("192.168.1.1-10", timeout=1, max_workers=5)


# ---------------------------------------------------------------------------
# _parse_network_range
# ---------------------------------------------------------------------------


class TestParseNetworkRange:
    def test_cidr_24_returns_254_ips(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("192.168.1.0/24")
        assert len(ips) == 254

    def test_cidr_24_first_and_last_ip(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("192.168.1.0/24")
        assert ips[0] == "192.168.1.1"
        assert ips[-1] == "192.168.1.254"

    def test_cidr_30_returns_2_ips(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("192.168.1.0/30")
        assert len(ips) == 2

    def test_cidr_32_returns_single_ip(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("192.168.1.5/32")
        assert ips == ["192.168.1.5"]

    def test_hyphenated_range_10_ips(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("192.168.1.1-10")
        assert len(ips) == 10
        assert ips[0] == "192.168.1.1"
        assert ips[-1] == "192.168.1.10"

    def test_hyphenated_range_single_ip(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("10.0.0.5-5")
        assert ips == ["10.0.0.5"]

    def test_single_ip_returns_list_of_one(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("10.0.0.1")
        assert ips == ["10.0.0.1"]

    def test_invalid_cidr_raises_value_error(self, nd: NetworkDiscovery) -> None:
        with pytest.raises(ValueError):
            nd._parse_network_range("999.999.999.0/24")

    def test_invalid_range_raises_value_error(self, nd: NetworkDiscovery) -> None:
        with pytest.raises(ValueError):
            nd._parse_network_range("192.168.1.abc-xyz")

    def test_strips_whitespace(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("  10.0.0.1  ")
        assert ips == ["10.0.0.1"]

    def test_unrecognised_format_raises_value_error(self, nd: NetworkDiscovery) -> None:
        with pytest.raises(ValueError, match="Unrecognised"):
            nd._parse_network_range("not_an_ip_or_range")

    def test_cidr_different_prefix(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("10.0.0.0/28")
        assert len(ips) == 14

    def test_hyphenated_50_ips(self, nd: NetworkDiscovery) -> None:
        ips = nd._parse_network_range("192.168.0.1-50")
        assert len(ips) == 50
        assert ips[0] == "192.168.0.1"
        assert ips[-1] == "192.168.0.50"


# ---------------------------------------------------------------------------
# _ping
# ---------------------------------------------------------------------------


class TestPing:
    @patch("platform.system", return_value="Windows")
    @patch("subprocess.run")
    def test_windows_ping_returns_true_on_zero(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        assert nd._ping("192.168.1.1") is True

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_linux_ping_returns_true_on_zero(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        assert nd._ping("192.168.1.1") is True

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_nonzero_returns_false(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        assert nd._ping("192.168.1.1") is False

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=1))
    def test_timeout_returns_false(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._ping("192.168.1.1") is False

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_file_not_found_returns_false(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._ping("192.168.1.1") is False

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run", side_effect=OSError)
    def test_os_error_returns_false(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._ping("192.168.1.1") is False

    @patch("platform.system", return_value="Windows")
    @patch("subprocess.run")
    def test_windows_uses_n_flag(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        nd._ping("1.2.3.4")
        cmd = mock_run.call_args[0][0]
        assert "-n" in cmd

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_linux_uses_c_flag(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        nd._ping("1.2.3.4")
        cmd = mock_run.call_args[0][0]
        assert "-c" in cmd


# ---------------------------------------------------------------------------
# _probe_ports
# ---------------------------------------------------------------------------


class TestProbePorts:
    @patch("socket.create_connection")
    def test_open_port_in_result(self, mock_conn: MagicMock, nd: NetworkDiscovery) -> None:
        mock_conn.return_value.__enter__ = MagicMock(return_value=None)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        result = nd._probe_ports("1.2.3.4", [22])
        assert 22 in result

    @patch("socket.create_connection", side_effect=OSError)
    def test_closed_port_not_in_result(
        self, mock_conn: MagicMock, nd: NetworkDiscovery
    ) -> None:
        result = nd._probe_ports("1.2.3.4", [22])
        assert 22 not in result

    def test_empty_ports_list_returns_empty(self, nd: NetworkDiscovery) -> None:
        result = nd._probe_ports("1.2.3.4", [])
        assert result == []

    @patch("socket.create_connection")
    def test_multiple_ports_mixed(self, mock_conn: MagicMock, nd: NetworkDiscovery) -> None:
        def side_effect(addr, timeout):
            if addr[1] == 22:
                m = MagicMock()
                m.__enter__ = MagicMock(return_value=None)
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError

        mock_conn.side_effect = side_effect
        result = nd._probe_ports("1.2.3.4", [22, 80, 443])
        assert result == [22]

    @patch("socket.create_connection", side_effect=socket.timeout)
    def test_socket_timeout_port_excluded(
        self, mock_conn: MagicMock, nd: NetworkDiscovery
    ) -> None:
        result = nd._probe_ports("1.2.3.4", [3389])
        assert 3389 not in result


# ---------------------------------------------------------------------------
# _detect_os_from_ports
# ---------------------------------------------------------------------------


class TestDetectOsFromPorts:
    @patch.object(NetworkDiscovery, "_get_ttl", return_value=None)
    def test_port_3389_returns_windows(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([3389], "1.2.3.4") == "windows"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=None)
    def test_port_445_returns_windows(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([445], "1.2.3.4") == "windows"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=None)
    def test_port_22_only_returns_linux(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([22], "1.2.3.4") == "linux"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=None)
    def test_port_22_and_3389_returns_windows(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([22, 3389], "1.2.3.4") == "windows"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=128)
    def test_empty_ports_ttl_128_returns_windows(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([], "1.2.3.4") == "windows"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=64)
    def test_empty_ports_ttl_64_returns_linux(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([], "1.2.3.4") == "linux"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=None)
    def test_empty_ports_ttl_none_returns_unknown(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([], "1.2.3.4") == "unknown"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=255)
    def test_ttl_255_returns_unknown(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([], "1.2.3.4") == "unknown"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=100)
    def test_ttl_100_returns_windows(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([], "1.2.3.4") == "windows"

    @patch.object(NetworkDiscovery, "_get_ttl", return_value=50)
    def test_ttl_50_returns_linux(
        self, mock_ttl: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._detect_os_from_ports([], "1.2.3.4") == "linux"


# ---------------------------------------------------------------------------
# _get_ttl
# ---------------------------------------------------------------------------


class TestGetTtl:
    @patch("platform.system", return_value="Windows")
    @patch("subprocess.run")
    def test_windows_output_ttl_128(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="Reply from 1.2.3.4: bytes=32 time=1ms TTL=128\n", stderr=""
        )
        assert nd._get_ttl("1.2.3.4") == 128

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_linux_output_ttl_64(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.3 ms\n", stderr=""
        )
        assert nd._get_ttl("1.2.3.4") == 64

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run")
    def test_no_ttl_in_output_returns_none(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_run.return_value = MagicMock(stdout="Request timeout\n", stderr="")
        assert nd._get_ttl("1.2.3.4") is None

    @patch("platform.system", return_value="Linux")
    @patch("subprocess.run", side_effect=Exception("boom"))
    def test_subprocess_error_returns_none(
        self, mock_run: MagicMock, mock_sys: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._get_ttl("1.2.3.4") is None


# ---------------------------------------------------------------------------
# _resolve_hostname
# ---------------------------------------------------------------------------


class TestResolveHostname:
    @patch("socket.gethostbyaddr", return_value=("myserver.local", [], ["192.168.1.1"]))
    def test_returns_hostname(
        self, mock_gha: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._resolve_hostname("192.168.1.1") == "myserver.local"

    @patch("socket.gethostbyaddr", side_effect=socket.herror)
    def test_herror_returns_unknown(
        self, mock_gha: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._resolve_hostname("192.168.1.1") == "unknown"

    @patch("socket.gethostbyaddr", side_effect=socket.gaierror)
    def test_gaierror_returns_unknown(
        self, mock_gha: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._resolve_hostname("192.168.1.1") == "unknown"

    @patch("socket.gethostbyaddr", side_effect=OSError)
    def test_oserror_returns_unknown(
        self, mock_gha: MagicMock, nd: NetworkDiscovery
    ) -> None:
        assert nd._resolve_hostname("192.168.1.1") == "unknown"


# ---------------------------------------------------------------------------
# _check_host
# ---------------------------------------------------------------------------


class TestCheckHost:
    @patch.object(NetworkDiscovery, "_ping", return_value=True)
    @patch.object(NetworkDiscovery, "_resolve_hostname", return_value="server1")
    @patch.object(NetworkDiscovery, "_probe_ports", return_value=[22])
    @patch.object(NetworkDiscovery, "_detect_os_from_ports", return_value="linux")
    def test_alive_host_returns_correct_dict(
        self,
        mock_os: MagicMock,
        mock_ports: MagicMock,
        mock_hostname: MagicMock,
        mock_ping: MagicMock,
        nd: NetworkDiscovery,
    ) -> None:
        result = nd._check_host("192.168.1.1")
        assert result["ip"] == "192.168.1.1"
        assert result["is_alive"] is True
        assert result["hostname"] == "server1"
        assert result["os_hint"] == "linux"
        assert result["ports_open"] == [22]
        assert "response_time_ms" in result

    @patch.object(NetworkDiscovery, "_ping", return_value=False)
    def test_dead_host_returns_is_alive_false(
        self, mock_ping: MagicMock, nd: NetworkDiscovery
    ) -> None:
        result = nd._check_host("192.168.1.99")
        assert result["is_alive"] is False
        assert result["hostname"] == "unknown"
        assert result["os_hint"] == "unknown"
        assert result["ports_open"] == []


# ---------------------------------------------------------------------------
# discover_hosts
# ---------------------------------------------------------------------------


class TestDiscoverHosts:
    @patch.object(NetworkDiscovery, "_check_host")
    def test_all_alive_returned(
        self, mock_check: MagicMock, nd: NetworkDiscovery
    ) -> None:
        mock_check.return_value = {
            "ip": "192.168.1.1", "hostname": "h", "os_hint": "linux",
            "ports_open": [], "is_alive": True, "response_time_ms": 5
        }
        nd_small = NetworkDiscovery("192.168.1.1-3", timeout=1, max_workers=3)
        with patch.object(nd_small, "_check_host", return_value={
            "ip": "192.168.1.1", "hostname": "h", "os_hint": "linux",
            "ports_open": [], "is_alive": True, "response_time_ms": 5
        }):
            hosts = nd_small.discover_hosts()
        assert all(h["is_alive"] for h in hosts)

    @patch.object(NetworkDiscovery, "_check_host")
    def test_dead_hosts_excluded(
        self, mock_check: MagicMock
    ) -> None:
        nd_small = NetworkDiscovery("10.0.0.1-5", timeout=1, max_workers=5)
        mock_check.return_value = {
            "ip": "10.0.0.1", "hostname": "unknown", "os_hint": "unknown",
            "ports_open": [], "is_alive": False, "response_time_ms": 3000
        }
        hosts = nd_small.discover_hosts()
        assert hosts == []

    def test_host_dict_schema(self) -> None:
        nd_single = NetworkDiscovery("127.0.0.1", timeout=1, max_workers=1)
        with patch.object(nd_single, "_ping", return_value=True), \
             patch.object(nd_single, "_resolve_hostname", return_value="localhost"), \
             patch.object(nd_single, "_probe_ports", return_value=[22]), \
             patch.object(nd_single, "_detect_os_from_ports", return_value="linux"):
            hosts = nd_single.discover_hosts()
        assert len(hosts) == 1
        h = hosts[0]
        for key in ("ip", "hostname", "os_hint", "ports_open", "is_alive", "response_time_ms"):
            assert key in h


# ---------------------------------------------------------------------------
# get_network_info
# ---------------------------------------------------------------------------


class TestGetNetworkInfo:
    def test_returns_correct_structure(self, nd: NetworkDiscovery) -> None:
        info = nd.get_network_info()
        for key in (
            "network", "subnet_mask", "total_possible_hosts", "discovered_hosts",
            "windows_hosts", "linux_hosts", "unknown_os",
            "discovery_duration_seconds", "success_rate", "scan_timestamp",
        ):
            assert key in info

    def test_zeros_before_discover(self, nd: NetworkDiscovery) -> None:
        info = nd.get_network_info()
        assert info["discovered_hosts"] == 0
        assert info["windows_hosts"] == 0

    def test_counts_correct_after_mock_discover(self) -> None:
        nd_small = NetworkDiscovery("192.168.0.1-10", timeout=1, max_workers=5)
        nd_small._hosts = [
            {"os_hint": "windows", "is_alive": True},
            {"os_hint": "linux", "is_alive": True},
            {"os_hint": "unknown", "is_alive": True},
        ]
        info = nd_small.get_network_info()
        assert info["discovered_hosts"] == 3
        assert info["windows_hosts"] == 1
        assert info["linux_hosts"] == 1
        assert info["unknown_os"] == 1

    def test_total_possible_hosts_cidr_24(self, nd: NetworkDiscovery) -> None:
        info = nd.get_network_info()
        assert info["total_possible_hosts"] == 254

    def test_success_rate_calculation(self) -> None:
        nd_small = NetworkDiscovery("10.0.0.0/24", timeout=1, max_workers=5)
        nd_small._hosts = [{"os_hint": "linux"}] * 127
        info = nd_small.get_network_info()
        assert abs(info["success_rate"] - 0.5) < 0.01
