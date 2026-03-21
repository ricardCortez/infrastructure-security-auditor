"""Root conftest for PSI CLI test suite."""
import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "integration: requires running API")
    config.addinivalue_line("markers", "network: requires network access")
    config.addinivalue_line("markers", "slow: long-running tests")
    config.addinivalue_line("markers", "unit: pure unit tests")
