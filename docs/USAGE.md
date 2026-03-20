# Usage Guide

How to use Infrastructure Security Auditor in practice.

---

## Command Reference

```
python auditor.py [COMMAND] [OPTIONS]

Commands:
  scan      Scan a server for security misconfigurations
  analyze   Analyze scan results and display risk summary
  report    Generate an HTML security report from scan results
  version   Display the application version
```

Run `python auditor.py --help` or `python auditor.py COMMAND --help` for full option details.

---

### `scan`

```
python auditor.py scan --target <HOST> [OPTIONS]

Options:
  -t, --target TEXT            Target IP address or hostname (required)
  --os [windows|linux]         Target OS (default: windows)
  -o, --output TEXT            Output path for scan results JSON
  --username TEXT              WinRM username for remote scans
  --password TEXT              WinRM password for remote scans
  --analyze / --no-analyze     Run analysis immediately after scan
```

**Examples:**

```bash
# Scan localhost
python auditor.py scan --target localhost

# Scan with custom output path
python auditor.py scan --target localhost --output /tmp/server01_scan.json

# Scan remote host
python auditor.py scan --target 10.0.1.50 --username admin --password P@ss123

# Scan and analyze in one step
python auditor.py scan --target localhost --analyze
```

**Output:** Saves `<target>_scan.json` (or `--output` path) and prints a summary table:

```
┌──────────────────────┐
│     Scan Summary     │
├──────────┬───────────┤
│ PASS     │        10 │
│ FAIL     │         4 │
│ WARNING  │         1 │
└──────────┴───────────┘

┌─────────────────────────────┐
│    Findings by Severity     │
├─────────────┬───────────────┤
│ CRITICAL    │             1 │
│ HIGH        │             2 │
│ MEDIUM      │             1 │
└─────────────┴───────────────┘
```

---

### `analyze`

```
python auditor.py analyze --input <SCAN_JSON> [--output <ANALYSIS_JSON>]
```

**Examples:**

```bash
# Print analysis to console
python auditor.py analyze --input localhost_scan.json

# Save analysis JSON
python auditor.py analyze --input localhost_scan.json --output localhost_analysis.json
```

**Output:**

```
╭──────────────────────────────────────────────────────────╮
│                    Analysis Results                      │
│  Risk Score: 6.8/10 (HIGH)                               │
│  Checks: 15  FAIL: 4  WARN: 1  PASS: 10                 │
╰──────────────────────────────────────────────────────────╯

┌───────────────────────────────┐
│      Compliance Estimates     │
├──────────────────┬────────────┤
│ ISO 27001        │        82% │
│ CIS Benchmarks   │        76% │
│ PCI DSS          │        71% │
└──────────────────┴────────────┘
```

---

### `report`

```
python auditor.py report --input <SCAN_JSON> --output <REPORT_HTML> [--no-ai]
```

**Examples:**

```bash
# Generate report with AI recommendations
python auditor.py report --input localhost_scan.json --output report.html

# Generate report without Claude API (static recommendations only)
python auditor.py report --input localhost_scan.json --output report.html --no-ai
```

**Output:** Saves `report.html` — a standalone HTML file. Open it in any browser.

---

### `version`

```bash
python auditor.py version
# → Infrastructure Security Auditor v0.1.0
```

---

## Common Workflows

### Workflow 1 — Single server audit (end-to-end)

```bash
# Step 1: Scan
python auditor.py scan --target 192.168.1.100 \
  --username "CORP\svc-auditor" \
  --password "SecurePass"

# Step 2: Review scan summary in terminal

# Step 3: Generate HTML report
python auditor.py report \
  --input 192_168_1_100_scan.json \
  --output reports/server01_$(date +%Y%m%d).html

# Step 4: Open report
start reports/server01_20260320.html
```

---

### Workflow 2 — Batch scan multiple servers

Use a shell loop or Python script to scan multiple targets:

**PowerShell batch script:**

```powershell
$servers = @("10.0.1.10", "10.0.1.11", "10.0.1.12")
$date = Get-Date -Format "yyyyMMdd"

foreach ($server in $servers) {
    Write-Host "Scanning $server..."
    python auditor.py scan --target $server `
        --username "CORP\svc-auditor" `
        --password "SecurePass" `
        --output "scans\${server}_${date}.json"

    python auditor.py report `
        --input "scans\${server}_${date}.json" `
        --output "reports\${server}_${date}.html" `
        --no-ai
}

Write-Host "All scans complete."
```

**Python batch script:**

```python
import subprocess
from pathlib import Path
from datetime import date

targets = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
today = date.today().strftime("%Y%m%d")

for target in targets:
    scan_path = f"scans/{target}_{today}.json"
    report_path = f"reports/{target}_{today}.html"

    subprocess.run([
        "python", "auditor.py", "scan",
        "--target", target,
        "--username", "CORP\\svc-auditor",
        "--password", "SecurePass",
        "--output", scan_path,
    ], check=True)

    subprocess.run([
        "python", "auditor.py", "report",
        "--input", scan_path,
        "--output", report_path,
        "--no-ai",
    ], check=True)

print("Batch scan complete.")
```

---

### Workflow 3 — Compliance audit (ISO 27001)

```bash
# Scan the server
python auditor.py scan --target prod-dc01 --output prod_dc01_scan.json

# Analyze to see compliance percentages
python auditor.py analyze --input prod_dc01_scan.json

# Generate detailed HTML report for the auditor
python auditor.py report \
  --input prod_dc01_scan.json \
  --output "ISO_27001_audit_$(date +%Y%m%d).html"
```

The HTML report includes an ISO 27001 compliance section with percentage scores and the specific Annex A controls that failed.

---

### Workflow 4 — Use as a Python library

You can import and call the modules directly in your own scripts:

```python
import json
from src.scanner.windows_scanner import WindowsScanner
from src.analyzer.analyzer import Analyzer
from src.reporter.html_generator import HTMLReporter

# Scan
scanner = WindowsScanner("localhost")
scan_results = scanner.run_scan()

# Analyze
analyzer = Analyzer(scan_results["findings"])
analysis = analyzer.analyze()

# Add scan metadata
analysis["server"] = scan_results["server"]
analysis["timestamp"] = scan_results["timestamp"]
analysis["scan_duration_seconds"] = scan_results["scan_duration_seconds"]

# Report
reporter = HTMLReporter(analysis)
out = reporter.save("my_report.html")
print(f"Report: {out}")
print(f"Risk: {analysis['risk_score']}/10 ({analysis['risk_label']})")
```

---

## Interpreting Reports

### Risk Score (0–10)

The risk score is a CVSS-inspired weighted average based on failing checks:

| Score | Label | Meaning |
|---|---|---|
| 8.5 – 10.0 | CRITICAL | Immediate action required. High probability of exploitation. |
| 6.5 – 8.4 | HIGH | Significant risk. Remediate within 24–48 hours. |
| 4.0 – 6.4 | MEDIUM | Moderate risk. Remediate within 1–2 weeks. |
| 1.5 – 3.9 | LOW | Minor risk. Remediate in next maintenance window. |
| 0.0 – 1.4 | MINIMAL | No significant findings. |

### Severity Levels

Each check has a **severity** that represents impact if exploited (independent of whether it passed):

| Severity | Examples |
|---|---|
| CRITICAL | SMBv1 enabled (EternalBlue), LSASS unprotected (Mimikatz) |
| HIGH | Firewall disabled, RDP without NLA, weak ciphers |
| MEDIUM | Weak password policies, event log too small, Windows Update behind |
| LOW | EOL software present |

### Check Status

| Status | Meaning |
|---|---|
| PASS | Check passed — no issue found |
| FAIL | Issue detected — remediation recommended |
| WARNING | Check could not be completed (e.g., insufficient privileges) |

### Compliance Percentages

Compliance percentages show the estimated proportion of controls in each framework that are being met based on the checks that passed. They are **estimates** — not formal audit results.

| Percentage | Interpretation |
|---|---|
| ≥ 80% | Good baseline compliance |
| 60–79% | Several gaps — review recommendations |
| < 60% | Significant gaps — prioritise remediation |

Controls mapped: ISO 27001 Annex A (114), CIS Benchmarks (356), PCI DSS (251).

### Recommendations Prioritisation

Recommendations in the report are ordered by severity (CRITICAL → HIGH → MEDIUM → LOW). Each recommendation includes:

- **Action** — one-line description
- **Command** — PowerShell command or GPO path
- **Effort** — Low / Medium / High
- **Timeline** — Immediate / 24h / 1 week / 2 weeks / 1 month

---

## Advanced Options

### Remote scanning via WinRM

**Prerequisites on the target host (run as Administrator):**

```powershell
Enable-PSRemoting -Force
winrm quickconfig
```

**Scan the remote host:**

```bash
python auditor.py scan \
  --target 10.0.1.50 \
  --username "CORP\svc-auditor" \
  --password "P@ssword1"
```

**Using environment variables (preferred for scripts):**

```bash
export WINRM_USERNAME="CORP\svc-auditor"
export WINRM_PASSWORD="P@ssword1"
python auditor.py scan --target 10.0.1.50
```

### Adjusting log verbosity

```bash
# Debug mode (verbose output)
LOG_LEVEL=DEBUG python auditor.py scan --target localhost

# Log to file
LOG_FILE=audit.log python auditor.py scan --target localhost
```

Or set in `.env`:
```ini
LOG_LEVEL=DEBUG
LOG_FILE=auditor.log
```

### Custom output paths

```bash
python auditor.py scan \
  --target localhost \
  --output /opt/audits/server01/2026-03-20_scan.json

python auditor.py report \
  --input /opt/audits/server01/2026-03-20_scan.json \
  --output /opt/audits/server01/2026-03-20_report.html
```

### Scheduling periodic scans (Windows Task Scheduler)

Create a PowerShell script `run_audit.ps1`:

```powershell
$date = Get-Date -Format "yyyy-MM-dd"
$scan  = "D:\audits\$date`_scan.json"
$report = "D:\audits\$date`_report.html"

python D:\infrastructure-security-auditor\auditor.py scan `
    --target localhost --output $scan

python D:\infrastructure-security-auditor\auditor.py report `
    --input $scan --output $report --no-ai

Write-EventLog -LogName Application -Source "SecurityAuditor" `
    -EventId 1000 -EntryType Information `
    -Message "Weekly audit complete: $report"
```

Schedule it weekly via Task Scheduler pointing to `powershell.exe -File D:\run_audit.ps1`.
