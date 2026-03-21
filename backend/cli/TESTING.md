# PSI CLI - Testing Guide

## Quick Run

```bash
cd ~/security-platform/backend/cli
pip install pytest pytest-cov pytest-timeout
```

### Unit tests only (no API needed)
```bash
pytest tests/test_*.py -v
```

### Integration tests (API must be running)
```bash
pytest tests/integration/ -v -m integration
```

### Network tests
```bash
pytest tests/network/ -v -m network
```

### All tests + coverage
```bash
pytest tests/ --cov=cli --cov-report=html --cov-report=term-missing \
  --ignore=tests/integration --ignore=tests/network
open htmlcov/index.html
```

### Specific test
```bash
pytest tests/test_auth.py::TestAuthClient::test_login_success -v
```

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures (mock_asset, mock_finding, etc.)
├── test_config.py           # Config class (7 tests)
├── test_auth.py             # AuthClient (11 tests)
├── test_api_client.py       # APIClient HTTP methods (12 tests)
├── test_formatters.py       # Output formatters (10 tests)
├── test_commands.py         # Click commands via CliRunner (25 tests)
├── integration/
│   └── test_api_integration.py   # Live API tests (9 tests)
└── network/
    └── test_connectivity.py      # TCP/DNS/latency tests (6 tests)
```

## Markers

| Marker | Description | Requires |
|--------|-------------|----------|
| `unit` | Pure unit, no I/O | Nothing |
| `integration` | Calls live API | `python psi.py` running |
| `network` | TCP checks | localhost:8000 open |
| `slow` | Long-running | — |

## Coverage Target: 75%+
