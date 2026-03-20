# Architecture

Technical design of Infrastructure Security Auditor.

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     auditor.py  (entry point)                   │
│                          Click CLI                              │
└────────────┬────────────────────────────────────────────────────┘
             │ commands: scan | analyze | report | version
             ▼
┌─────────────────────────────────────────────────────────────────┐
│                         src/cli.py                              │
│    scan()        analyze()        report()        version()     │
└────────┬─────────────────────────────────────────┬─────────────┘
         │                                         │
         ▼                                         ▼
┌─────────────────┐                  ┌─────────────────────────┐
│  WindowsScanner │                  │  Analyzer               │
│  (scanner/)     │ ──scan_results──▶│  (analyzer/)            │
│                 │                  │                         │
│  15 PowerShell  │                  │  RiskScorer             │
│  checks via     │                  │  Claude API (optional)  │
│  subprocess or  │                  │  Compliance mapping     │
│  WinRM          │                  └──────────┬──────────────┘
└─────────────────┘                             │ analysis_data
                                                ▼
                                  ┌─────────────────────────┐
                                  │  HTMLReporter           │
                                  │  (reporter/)            │
                                  │                         │
                                  │  Jinja2 template        │
                                  │  Standalone HTML output │
                                  └─────────────────────────┘
```

---

## Data Flow

```
1. User runs:  python auditor.py scan --target <host>
               │
               ▼
2. WindowsScanner.run_scan()
   ├── ThreadPoolExecutor(max_workers=6)
   ├── Executes 15 check_* methods concurrently
   │   └── Each calls _run_powershell(script)
   │       ├── Local: subprocess.run(["powershell", ...])
   │       └── Remote: winrm.Session.run_ps(script)
   └── Returns: scan_results.json
               │
               ▼
3. User runs:  python auditor.py report --input scan.json --output report.html
               │
               ▼
4. Analyzer.analyze()
   ├── RiskScorer.calculate_score(findings)   → float [0–10]
   ├── RiskScorer.risk_label(score)           → "HIGH" etc.
   ├── RiskScorer.severity_distribution()     → {"CRITICAL": n, ...}
   ├── RiskScorer.compliance_percentage()     → {"ISO_27001": 0.85, ...}
   └── Analyzer.generate_recommendations()
       ├── Claude API (if CLAUDE_API_KEY set)  → AI recommendations
       └── Static fallback                    → built-in recommendations
               │
               ▼
5. HTMLReporter.generate()
   ├── Jinja2 template: src/reporter/templates/report.html
   ├── Sections: Executive Summary, Risk Dashboard, Findings,
   │            Compliance, Recommendations, Technical Appendix
   └── Returns: standalone HTML string (no external CDN deps)
               │
               ▼
6. report.html  → distribute / open in browser
```

---

## Module Descriptions

### `src/cli.py` — Command Interface

Implements the Click CLI with four commands:

| Command | Description |
|---|---|
| `scan` | Runs WindowsScanner and saves JSON results |
| `analyze` | Reads scan JSON, runs Analyzer, prints to console |
| `report` | Reads scan JSON, runs Analyzer + HTMLReporter, saves HTML |
| `version` | Prints version string |

The `scan` command accepts `--analyze` to pipeline analysis inline. All commands use `rich` for console output (progress spinners, coloured tables).

### `src/scanner/windows_scanner.py` — Security Checks

`WindowsScanner` executes PowerShell scripts via:

- **Local:** `subprocess.run(["powershell", "-NonInteractive", "-Command", ...])`
- **Remote:** `pywinrm` WinRM session (`winrm.Session.run_ps()`)

Each `check_*` method is independent and returns a `FindingDict`:

```python
{
    "check":          str,   # Human-readable check name
    "status":         str,   # "PASS" | "FAIL" | "WARNING"
    "severity":       str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "description":    str,   # What was found
    "recommendation": str,   # How to fix it
    "raw_output":     str,   # Raw PowerShell output (for appendix)
}
```

`run_scan()` uses `ThreadPoolExecutor(max_workers=6)` to run all 15 checks concurrently, then aggregates into a scan result dict.

### `src/analyzer/analyzer.py` — Analysis Engine

`Analyzer` accepts a list of `FindingDict` objects and orchestrates:

1. **Risk scoring** — delegates to `RiskScorer.calculate_score()`
2. **Compliance mapping** — delegates to `RiskScorer.compliance_percentage()` for each standard
3. **Recommendation generation** — tries Claude API first, falls back to static table

The Claude integration sends a compact JSON prompt to `claude-sonnet-4-5` and parses the response as a structured list of recommendations.

### `src/analyzer/risk_scorer.py` — Scoring Algorithm

`RiskScorer` contains only `@staticmethod` methods to enable unit testing in isolation:

```
score = (sum_of_weights_for_failing_checks / max_possible_weight) × 10

max_possible = len(active_findings) × 10   (if every failing check were CRITICAL)
```

Weights: `CRITICAL=10`, `HIGH=7`, `MEDIUM=4`, `LOW=1`

### `src/reporter/html_generator.py` — Report Renderer

`HTMLReporter` uses Jinja2 to render `src/reporter/templates/report.html`. The template is a single HTML file with:

- Inline CSS (no Bootstrap, Tailwind, or CDN)
- Risk score gauge visualised with CSS
- Findings grouped by severity
- Compliance bar charts in pure CSS
- Recommendations roadmap table
- Raw JSON appendix (collapsible)

`save(path)` writes the rendered HTML to disk and creates parent directories if needed.

### `src/remediator/playbook_gen.py` — Playbook Generator (Phase 2)

`PlaybookGenerator` is a stub reserved for Phase 2. It will generate:

- PowerShell remediation scripts
- Ansible playbooks (YAML)

Both methods currently raise `NotImplementedError`.

### `src/config.py` — Configuration

Loads `.env` via `python-dotenv` and exposes:

- `CLAUDE_API_KEY`, `CLAUDE_MODEL`
- `WINRM_USERNAME`, `WINRM_PASSWORD`, `WINRM_PORT`, `WINRM_TRANSPORT`
- `SEVERITY_WEIGHTS`, `SEVERITY_ORDER`
- `COMPLIANCE_CONTROLS` — maps each check name to control IDs per standard
- `TOTAL_CONTROLS` — denominator for compliance % calculation
- `logger` — pre-configured `logging.Logger` instance

---

## Data Structures

### `FindingDict` (scanner output)

```python
{
    "check":          "Firewall Status",
    "status":         "FAIL",          # PASS | FAIL | WARNING
    "severity":       "HIGH",          # CRITICAL | HIGH | MEDIUM | LOW
    "description":    "Windows Firewall is DISABLED on 2 profile(s): ...",
    "recommendation": "Set-NetFirewallProfile -All -Enabled True",
    "raw_output":     "..."            # Raw PowerShell stdout
}
```

### `ScanResult` (from `run_scan()`)

```python
{
    "server":                "192.168.1.100",
    "timestamp":             "2026-03-20T14:30:00+00:00",
    "scan_duration_seconds": 12.4,
    "findings":              [FindingDict, ...],   # list of 15 findings
    "total_checks":          15,
    "summary":               {"PASS": 10, "FAIL": 4, "WARNING": 1}
}
```

### `AnalysisResult` (from `Analyzer.analyze()`)

```python
{
    "risk_score":             7.4,
    "risk_label":             "HIGH",
    "severity_distribution":  {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 0},
    "compliance": {
        "ISO_27001":      0.85,
        "CIS_Benchmarks": 0.78,
        "PCI_DSS":        0.72,
    },
    "recommendations": [
        {
            "check":    "SMBv1 Protocol",
            "severity": "CRITICAL",
            "action":   "Disable SMBv1 immediately",
            "command":  "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "effort":   "Low",
            "timeline": "Immediate",
        },
        ...
    ],
    "findings":       [FindingDict, ...],
    "total_checks":   15,
    "summary":        {"PASS": 10, "FAIL": 4, "WARNING": 1},
    # Also present after CLI processing:
    "server":                "192.168.1.100",
    "timestamp":             "2026-03-20T14:30:00+00:00",
    "scan_duration_seconds": 12.4,
}
```

---

## Compliance Mapping

`COMPLIANCE_CONTROLS` in `src/config.py` maps each check to control IDs:

```python
"Firewall Status": {
    "ISO_27001":      ["A.13.1.1"],
    "CIS_Benchmarks": ["9.1", "9.2", "9.3"],
    "PCI_DSS":        ["1.2", "1.3"],
},
```

`TOTAL_CONTROLS` provides the denominator:

```python
{
    "ISO_27001":      114,   # Annex A controls
    "CIS_Benchmarks": 356,
    "PCI_DSS":        251,
}
```

**Compliance % formula:**

```
failing_controls = set of control IDs from any FAIL/WARNING finding
passed_count     = total_controls - len(failing_controls)
compliance_pct   = passed_count / total_controls
```

---

## Performance Considerations

| Consideration | Detail |
|---|---|
| Parallel checks | `ThreadPoolExecutor(max_workers=6)` runs all 15 checks concurrently |
| PowerShell timeout | Each subprocess call has a 30-second timeout |
| Claude API | Called once per `analyze`; token usage is capped at top-10 findings |
| Report size | `raw_output` fields are truncated in the HTML appendix to limit file size |
| Remote scan | WinRM session is initialised once and reused across all checks |

Typical scan durations:

- Local scan (no WinRM): **5–15 seconds**
- Remote scan (LAN): **15–45 seconds**
- Remote scan (WAN): **30–90 seconds**

---

## Extension Points

### Adding a new security check

1. Add a `check_<name>(self) -> dict[str, Any]` method to `WindowsScanner`
2. The method must return a `FindingDict` (use `_finding()` or `_error_finding()` helpers)
3. Register it in the `checks` list inside `run_scan()`
4. Add compliance mappings to `COMPLIANCE_CONTROLS` in `src/config.py`
5. Add a static recommendation to `_STATIC_RECOMMENDATIONS` in `src/analyzer/analyzer.py`
6. Write tests in `tests/test_scanner.py`

Example skeleton:

```python
def check_my_control(self) -> dict[str, Any]:
    """Check for XYZ misconfiguration.

    Returns:
        FindingDict with HIGH severity if XYZ is misconfigured.
    """
    script = "Get-Something | ConvertTo-Json"
    try:
        stdout, _, _ = self._run_powershell(script)
        if _is_bad(stdout):
            return _finding(
                check="My Control",
                status="FAIL",
                severity="HIGH",
                description="XYZ is misconfigured.",
                recommendation="Fix XYZ with: ...",
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

### Adding a new compliance standard

1. Add control IDs to each check entry in `COMPLIANCE_CONTROLS`
2. Add the total control count to `TOTAL_CONTROLS`
3. Add the standard key to `Analyzer.map_to_compliance()`

### Customising the report template

The Jinja2 template is at `src/reporter/templates/report.html`. Template variables are documented in `HTMLReporter._build_context()`. The template uses no external CDN — all CSS is inline.
