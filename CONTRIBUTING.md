# Contributing Guide

How to extend, fix, and improve Infrastructure Security Auditor.

---

## Development Setup

```bash
# Clone and enter the repo
git clone https://github.com/your-org/infrastructure-security-auditor.git
cd infrastructure-security-auditor

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate     # Windows
source venv/bin/activate  # macOS/Linux

# Install runtime + dev dependencies
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock flake8 black isort mypy
```

---

## Adding a New Security Check

1. **Open** `src/scanner/windows_scanner.py`

2. **Add** a `check_<name>(self) -> dict[str, Any]` method following the existing pattern:

   ```python
   def check_my_control(self) -> dict[str, Any]:
       """Check for XYZ misconfiguration.

       Verifies that [explain what the check does and why it matters].

       Returns:
           FindingDict with [SEVERITY] severity if XYZ is misconfigured.
       """
       script = "Get-Something | ConvertTo-Json"
       try:
           stdout, _, _ = self._run_powershell(script)
           if _is_problematic(stdout):
               return _finding(
                   check="My Control",
                   status="FAIL",
                   severity="HIGH",          # CRITICAL | HIGH | MEDIUM | LOW
                   description="XYZ is misconfigured because ...",
                   recommendation="Fix it with: Set-Something ...",
                   raw_output=stdout,
               )
           return _finding(
               check="My Control",
               status="PASS",
               severity="HIGH",
               description="XYZ is correctly configured.",
               recommendation="No action required.",
               raw_output=stdout,
           )
       except Exception as exc:
           return _error_finding("My Control", str(exc))
   ```

3. **Register** the check in `run_scan()`:

   ```python
   checks = [
       self.check_firewall,
       ...
       self.check_my_control,   # ← add here
   ]
   ```

4. **Add compliance mappings** in `src/config.py`:

   ```python
   COMPLIANCE_CONTROLS = {
       ...
       "My Control": {
           "ISO_27001":      ["A.x.y.z"],
           "CIS_Benchmarks": ["x.y"],
           "PCI_DSS":        ["x.z"],
       },
   }
   ```

5. **Add a static recommendation** in `src/analyzer/analyzer.py`:

   ```python
   _STATIC_RECOMMENDATIONS = {
       ...
       "My Control": {
           "action":   "Fix XYZ immediately",
           "command":  "Set-Something -Value $true",
           "effort":   "Low",
           "timeline": "Immediate",
       },
   }
   ```

6. **Write tests** in `tests/test_scanner.py`:

   ```python
   def test_check_my_control_fail(scanner, mock_powershell):
       mock_powershell.return_value = ("bad_output", "", 0)
       result = scanner.check_my_control()
       assert result["status"] == "FAIL"
       assert result["severity"] == "HIGH"
       assert "My Control" in result["check"]

   def test_check_my_control_pass(scanner, mock_powershell):
       mock_powershell.return_value = ("good_output", "", 0)
       result = scanner.check_my_control()
       assert result["status"] == "PASS"
   ```

---

## Adding a New Compliance Standard

1. Add control IDs to each relevant check in `COMPLIANCE_CONTROLS` in `src/config.py`
2. Add the total control count: `TOTAL_CONTROLS["MY_STANDARD"] = 200`
3. Add the standard key to `Analyzer.map_to_compliance()` in `src/analyzer/analyzer.py`

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanner.py -v

# Run a specific test
pytest tests/test_scanner.py::test_check_firewall_fail -v
```

**Coverage target: ≥ 80%**

All new code must include tests. Aim for:

- Happy path (PASS result)
- Failure path (FAIL result)
- Exception / error handling
- Edge cases (empty output, None values, Unicode)

---

## Code Style

This project uses PEP 8 with enforced formatting.

```bash
# Lint
flake8 src/ tests/

# Auto-format
black src/ tests/

# Sort imports
isort src/ tests/

# Type checking
mypy src/
```

**Style rules:**

- Max line length: 88 (Black default)
- Type hints on all function arguments and return values
- Google-style docstrings on all public functions and classes
- No bare `except:` — always catch specific exception types

---

## Docstring Format

Use Google style:

```python
def my_function(arg1: str, arg2: int = 0) -> dict[str, Any]:
    """One-line summary of what the function does.

    More detailed description if needed. Explain the algorithm,
    edge cases, or non-obvious behaviour.

    Args:
        arg1: Description of arg1.
        arg2: Description of arg2. Defaults to 0.

    Returns:
        Description of the return value and its structure.

    Raises:
        ValueError: If arg1 is empty.
        RuntimeError: If something unexpected happens.

    Example:
        >>> result = my_function("hello", 42)
        >>> result["key"]
        "value"
    """
```

---

## Commit Message Format

```
[AgentN] short imperative description

Optional longer explanation if needed.
```

Examples:
```
[Agent1] add check_bitlocker security check
[Agent2] fix Unicode decoding error in _run_powershell
[Agent3] update API.md with PlaybookGenerator reference
```

---

## Pull Request Process

1. Fork the repository and create a feature branch: `git checkout -b feat/my-check`
2. Implement your change following the guidelines above
3. Run the full test suite: `pytest tests/ --cov=src` — must be ≥ 80%
4. Run lint: `flake8 src/ tests/` — must be zero errors
5. Format: `black src/ tests/ && isort src/ tests/`
6. Commit with the message format above
7. Open a PR against `main` with a description of what changed and why

**PR checklist:**

- [ ] Tests added / updated
- [ ] Coverage ≥ 80%
- [ ] `flake8` clean
- [ ] `black` formatted
- [ ] Docstrings on all new public functions
- [ ] Type hints on all new functions
- [ ] `CLAUDE.md` coordination rules followed (Agente 1 approves architecture changes)

---

## Project Roles (Multi-Agent)

Per `CLAUDE.md`:

| Agent | Role | Can Work Without Coordination |
|---|---|---|
| Agent 1 (Sonnet) | Architecture, new features, technical decisions | Architectural changes require Agent 1 approval |
| Agent 2 (Haiku) | Refactoring, bug fixes, testing, optimisation | Bug fixes, refactoring within a module, additional tests |
| Agent 3 (Haiku) | Documentation, docstrings, README, examples | All documentation changes |

Coordination required for: new dependencies, interface changes, cross-module refactoring.
