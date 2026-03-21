import pytest


def test_nessus_scan_task_exists():
    from tasks import nessus_scan
    assert nessus_scan is not None


def test_openvas_scan_task_exists():
    from tasks import openvas_scan
    assert openvas_scan is not None


def test_status_tracker():
    from status_tracker import StatusTracker
    assert StatusTracker is not None
