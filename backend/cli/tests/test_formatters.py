"""Unit tests for CLI output formatters."""
import pytest
from io import StringIO
from unittest.mock import patch
from cli.formatters import Formatters


class TestFormatters:
    """Tests for Formatters static methods."""

    def test_table_empty_data(self, capsys) -> None:
        """Empty data prints a 'No data' message without raising."""
        Formatters.table([], headers=["A", "B"])
        # Should not raise

    def test_table_with_rows(self) -> None:
        """Table renders without raising for valid data."""
        rows = [[1, "server-01", "192.168.1.1"], [2, "db-01", "10.0.0.1"]]
        Formatters.table(rows, headers=["ID", "Hostname", "IP"])

    def test_table_with_dicts(self) -> None:
        """Table accepts list of dicts."""
        data = [{"id": 1, "name": "test"}]
        Formatters.table(data)

    def test_success_does_not_raise(self) -> None:
        Formatters.success("Everything is fine")

    def test_error_does_not_raise(self) -> None:
        Formatters.error("Something went wrong")

    def test_info_does_not_raise(self) -> None:
        Formatters.info("For your information")

    def test_warn_does_not_raise(self) -> None:
        Formatters.warn("Heads up")

    def test_panel_does_not_raise(self) -> None:
        Formatters.panel("Panel content", title="Test Panel")

    def test_json_output_does_not_raise(self) -> None:
        Formatters.json_output({"key": "value", "list": [1, 2, 3]})

    def test_csv_output_does_not_raise(self) -> None:
        data = [{"id": 1, "hostname": "server-01"}, {"id": 2, "hostname": "db-01"}]
        Formatters.csv_output(data, headers=["id", "hostname"])
