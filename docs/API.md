# API Reference

Complete class and method reference for Infrastructure Security Auditor.

---

## Table of Contents

- [WindowsScanner](#windowsscanner)
- [Analyzer](#analyzer)
- [RiskScorer](#riskscorer)
- [HTMLReporter](#htmlreporter)
- [PlaybookGenerator](#playbookgenerator)
- [Configuration Constants](#configuration-constants)
- [CLI Commands](#cli-commands)

---

## WindowsScanner

`src.scanner.windows_scanner.WindowsScanner`

Performs security configuration checks against a Windows host via PowerShell (local or remote WinRM).

### Constructor

```python
WindowsScanner(target: str, credentials: dict[str, Any] | None = None)
```

**Args:**

| Parameter | Type | Description |
|---|---|---|
| `target` | `str` | IP address or hostname of the target. Use `"localhost"` or `"127.0.0.1"` for local scanning. |
| `credentials` | `dict \| None` | WinRM credentials for remote scanning. Keys: `username`, `password`, `port` (default 5985), `transport` (default `"ntlm"`). |

**Example:**
```python
from src.scanner.windows_scanner import WindowsScanner

# Local scan
scanner = WindowsScanner(target="localhost")

# Remote scan
scanner = WindowsScanner(
    target="192.168.1.100",
    credentials={
        "username": "DOMAIN\\Administrator",
        "password": "SecurePass",
    }
)
```

---

### Security Check Methods

All check methods share the same signature and return format:

```python
def check_<name>(self) -> dict[str, Any]
```

**Returns:** A `FindingDict` with keys:

```python
{
    "check":          str,   # Check name
    "status":         str,   # "PASS" | "FAIL" | "WARNING"
    "severity":       str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "description":    str,   # Human-readable finding description
    "recommendation": str,   # Actionable remediation step
    "raw_output":     str,   # Raw PowerShell stdout
}
```

---

#### `check_firewall()`

Checks whether the Windows Firewall is enabled on all network profiles (Domain, Private, Public).

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | `Get-NetFirewallProfile \| Select-Object Name, Enabled` |
| **FAIL when** | Any profile is disabled |

---

#### `check_smb_v1()`

Checks whether the SMBv1 protocol is enabled. SMBv1 is exploited by EternalBlue (MS17-010) and WannaCry ransomware.

| | |
|---|---|
| **Severity** | CRITICAL |
| **PowerShell** | `(Get-SmbServerConfiguration).EnableSMB1Protocol` |
| **FAIL when** | SMBv1 is enabled |

---

#### `check_llmnr_netbios()`

Checks whether LLMNR and NetBIOS over TCP/IP are disabled. Both protocols enable Responder-style name-poisoning attacks.

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | Registry query + `Get-WmiObject Win32_NetworkAdapterConfiguration` |
| **FAIL when** | LLMNR or NetBIOS is not explicitly disabled |

---

#### `check_windows_defender()`

Checks Windows Defender real-time protection status and signature freshness (threshold: 7 days).

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | `Get-MpComputerStatus` |
| **FAIL when** | Real-time protection is off, AV is disabled, or signatures >7 days old |

---

#### `check_tls_versions()`

Checks SCHANNEL registry for deprecated TLS/SSL protocols: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1.

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | Registry query under `HKLM:\SYSTEM\...\SCHANNEL\Protocols` |
| **FAIL when** | Any deprecated protocol is not explicitly set to `Enabled=0` |

---

#### `check_password_policies()`

Checks local password policy: minimum length (≥12), maximum age (≤90 days), lockout threshold.

| | |
|---|---|
| **Severity** | MEDIUM |
| **PowerShell** | `net accounts` |
| **FAIL when** | Min length <12, max age >90, or lockout threshold = 0 |

---

#### `check_rdp_nla()`

Checks whether Remote Desktop requires Network Level Authentication (NLA). Lack of NLA exposes the login screen to BlueKeep (CVE-2019-0708).

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | Registry: `HKLM:\System\...\RDP-Tcp` → `UserAuthentication` |
| **FAIL when** | `UserAuthentication != 1` |

---

#### `check_windows_update()`

Checks for pending Windows Updates using the Windows Update Agent COM API.

| | |
|---|---|
| **Severity** | MEDIUM |
| **PowerShell** | `Microsoft.Update.Session` COM object |
| **FAIL when** | Critical patches are pending |
| **WARNING when** | Non-critical patches are pending |

---

#### `check_admin_accounts()`

Checks the local Administrators group for excessive membership and whether the built-in Administrator account is enabled.

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | `Get-LocalGroupMember -Group 'Administrators'` |
| **FAIL when** | >3 members or built-in Administrator is enabled |

---

#### `check_privilege_creep()`

Checks Backup Operators, Remote Desktop Users, Remote Management Users, and Power Users for unexpected members.

| | |
|---|---|
| **Severity** | MEDIUM |
| **PowerShell** | `Get-LocalGroupMember` per privileged group |
| **WARNING when** | >2 of the 4 privileged groups have members |

---

#### `check_event_log_config()`

Checks that the Security, System, and Application event logs are enabled and ≥64 MB in size.

| | |
|---|---|
| **Severity** | MEDIUM |
| **PowerShell** | `Get-WinEvent -ListLog Security,System,Application` |
| **FAIL when** | Any log is disabled or <64 MB |

---

#### `check_lsass_protection()`

Checks whether LSASS is protected against credential dumping via RunAsPPL or Credential Guard.

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | Registry: `HKLM:\SYSTEM\...\Lsa` → `RunAsPPL`, `LsaCfgFlags` |
| **FAIL when** | Neither RunAsPPL nor Credential Guard is enabled |

---

#### `check_weak_ciphers()`

Checks SCHANNEL for weak cipher suites: RC4, DES, 3DES, NULL, EXPORT.

| | |
|---|---|
| **Severity** | HIGH |
| **PowerShell** | Registry under `HKLM:\SYSTEM\...\SCHANNEL\Ciphers` |
| **FAIL when** | Any weak cipher is not explicitly set to `Enabled=0` |

---

#### `check_file_sharing()`

Lists SMB shares and checks for overly permissive access (Everyone / Authenticated Users).

| | |
|---|---|
| **Severity** | MEDIUM |
| **PowerShell** | `Get-SmbShare` + `Get-SmbShareAccess` |
| **FAIL when** | Any non-admin share grants access to Everyone or Authenticated Users |

---

#### `check_installed_software()`

Queries the Windows registry for installed software and flags known EOL applications.

| | |
|---|---|
| **Severity** | LOW |
| **PowerShell** | `Get-ItemProperty HKLM:\...\Uninstall\*` |
| **FAIL when** | EOL software is detected (Internet Explorer, Flash, Java 6-8, Office 2007-2013, etc.) |

---

### `run_scan()`

Executes all 15 security checks concurrently using `ThreadPoolExecutor`.

```python
def run_scan(self) -> dict[str, Any]
```

**Returns:**

```python
{
    "server":                str,          # Target hostname/IP
    "timestamp":             str,          # ISO 8601 UTC
    "scan_duration_seconds": float,        # Wall-clock time
    "findings":              list[dict],   # 15 FindingDict objects
    "total_checks":          int,          # Always 15
    "summary": {
        "PASS":    int,
        "FAIL":    int,
        "WARNING": int,
    }
}
```

**Example:**
```python
scanner = WindowsScanner("localhost")
results = scanner.run_scan()
print(f"Risk findings: {results['summary']['FAIL']} failures")
```

---

## Analyzer

`src.analyzer.analyzer.Analyzer`

Processes scanner findings to produce a comprehensive security analysis.

### Constructor

```python
Analyzer(findings: list[dict[str, Any]])
```

**Args:**

| Parameter | Type | Description |
|---|---|---|
| `findings` | `list[dict]` | List of `FindingDict` objects returned by `WindowsScanner.run_scan()["findings"]` |

---

### `analyze()`

Orchestrates all analysis and returns the complete analysis report.

```python
def analyze(self) -> dict[str, Any]
```

**Returns:** See `AnalysisResult` structure in [ARCHITECTURE.md](ARCHITECTURE.md#data-structures).

**Example:**
```python
from src.analyzer.analyzer import Analyzer

analyzer = Analyzer(scan_results["findings"])
analysis = analyzer.analyze()
print(f"Risk score: {analysis['risk_score']}/10 ({analysis['risk_label']})")
```

---

### `calculate_risk_score()`

```python
def calculate_risk_score(self) -> float
```

**Returns:** Float in `[0.0, 10.0]`.

---

### `assign_severity_distribution()`

```python
def assign_severity_distribution(self) -> dict[str, int]
```

**Returns:** `{"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n}`

---

### `map_to_compliance()`

```python
def map_to_compliance(self) -> dict[str, float]
```

**Returns:** `{"ISO_27001": 0.85, "CIS_Benchmarks": 0.78, "PCI_DSS": 0.72}`

---

### `generate_recommendations()`

```python
def generate_recommendations(self) -> list[dict[str, Any]]
```

Attempts Claude API first, falls back to static recommendations.

**Returns:**
```python
[
    {
        "check":    str,   # Finding name
        "severity": str,   # CRITICAL | HIGH | MEDIUM | LOW
        "action":   str,   # One-line action
        "command":  str,   # PowerShell command or GPO path
        "effort":   str,   # Low | Medium | High
        "timeline": str,   # Immediate | Within 24 hours | etc.
    },
    ...
]
```

---

## RiskScorer

`src.analyzer.risk_scorer.RiskScorer`

Stateless helper for risk metrics. All methods are `@staticmethod`.

### `RiskScorer.calculate_score(findings)`

```python
@staticmethod
def calculate_score(findings: list[dict[str, Any]]) -> float
```

**Args:** List of `FindingDict` objects.

**Returns:** Float in `[0.0, 10.0]`.

**Formula:**
```
score = (sum(severity_weights for FAIL/WARNING) / (n_active × 10)) × 10
```

**Example:**
```python
from src.analyzer.risk_scorer import RiskScorer

findings = [
    {"status": "FAIL", "severity": "CRITICAL"},
    {"status": "FAIL", "severity": "HIGH"},
    {"status": "PASS", "severity": "MEDIUM"},
]
score = RiskScorer.calculate_score(findings)  # → 8.5
```

---

### `RiskScorer.severity_distribution(findings)`

```python
@staticmethod
def severity_distribution(findings: list[dict[str, Any]]) -> dict[str, int]
```

**Returns:** `{"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n}`

---

### `RiskScorer.risk_label(score)`

```python
@staticmethod
def risk_label(score: float) -> str
```

**Returns:** `"CRITICAL"` | `"HIGH"` | `"MEDIUM"` | `"LOW"` | `"MINIMAL"`

| Score Range | Label |
|---|---|
| 8.5 – 10.0 | CRITICAL |
| 6.5 – 8.4 | HIGH |
| 4.0 – 6.4 | MEDIUM |
| 1.5 – 3.9 | LOW |
| 0.0 – 1.4 | MINIMAL |

---

### `RiskScorer.compliance_percentage(findings, standard, compliance_controls, total_controls)`

```python
@staticmethod
def compliance_percentage(
    findings: list[dict[str, Any]],
    standard: str,
    compliance_controls: dict[str, dict[str, list[str]]],
    total_controls: dict[str, int],
) -> float
```

**Args:**

| Parameter | Description |
|---|---|
| `findings` | Scanner findings |
| `standard` | `"ISO_27001"`, `"CIS_Benchmarks"`, or `"PCI_DSS"` |
| `compliance_controls` | From `src.config.COMPLIANCE_CONTROLS` |
| `total_controls` | From `src.config.TOTAL_CONTROLS` |

**Returns:** Float in `[0.0, 1.0]`.

---

## HTMLReporter

`src.reporter.html_generator.HTMLReporter`

Renders a standalone HTML report from analysis data.

### Constructor

```python
HTMLReporter(analysis_data: dict[str, Any])
```

**Args:**

| Parameter | Type | Description |
|---|---|---|
| `analysis_data` | `dict` | Full analysis dict from `Analyzer.analyze()`, with `server`, `timestamp`, `scan_duration_seconds` added |

---

### `generate()`

```python
def generate(self) -> str
```

**Returns:** Complete HTML string.

**Raises:** `jinja2.TemplateNotFound` if `report.html` template is missing.

---

### `save(output_path)`

```python
def save(output_path: str | Path) -> Path
```

Renders and writes the report to disk. Creates parent directories if needed.

**Args:** `output_path` — destination file path.

**Returns:** Resolved `pathlib.Path` to the written file.

**Example:**
```python
from src.reporter.html_generator import HTMLReporter
from pathlib import Path

reporter = HTMLReporter(analysis_data)
out = reporter.save("reports/server01_report.html")
print(f"Report saved to: {out}")
```

---

## PlaybookGenerator

`src.remediator.playbook_gen.PlaybookGenerator`

*Phase 2 stub — not yet implemented.*

### Constructor

```python
PlaybookGenerator(findings: list[dict[str, Any]])
```

### `generate_powershell()`

```python
def generate_powershell(self) -> str
```

**Raises:** `NotImplementedError` — reserved for Phase 2.

### `generate_ansible()`

```python
def generate_ansible(self) -> str
```

**Raises:** `NotImplementedError` — reserved for Phase 2.

---

## Configuration Constants

`src.config`

| Constant | Type | Description |
|---|---|---|
| `APP_VERSION` | `str` | Application version string (e.g., `"0.1.0"`) |
| `CLAUDE_API_KEY` | `str` | Anthropic API key (from `$CLAUDE_API_KEY` env var) |
| `CLAUDE_MODEL` | `str` | Claude model ID (default: `"claude-sonnet-4-5"`) |
| `WINRM_USERNAME` | `str` | WinRM username (from env) |
| `WINRM_PASSWORD` | `str` | WinRM password (from env) |
| `WINRM_PORT` | `int` | WinRM port (default: 5985) |
| `SEVERITY_WEIGHTS` | `dict[str, int]` | `{"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}` |
| `SEVERITY_ORDER` | `list[str]` | `["CRITICAL", "HIGH", "MEDIUM", "LOW"]` |
| `COMPLIANCE_CONTROLS` | `dict` | Maps check names → standard → control IDs |
| `TOTAL_CONTROLS` | `dict[str, int]` | `{"ISO_27001": 114, "CIS_Benchmarks": 356, "PCI_DSS": 251}` |
| `logger` | `logging.Logger` | Pre-configured `"auditor"` logger |

### `setup_logger(name, level, log_file)`

```python
def setup_logger(
    name: str = "auditor",
    level: str | None = None,
    log_file: str | None = None,
) -> logging.Logger
```

Configures and returns a logger. Called automatically at module import to create the module-level `logger`.

---

## CLI Commands

`src.cli`

### `scan`

```
python auditor.py scan [OPTIONS]

Options:
  -t, --target TEXT         Target IP or hostname (required)
  --os [windows|linux]      Target OS (default: windows)
  -o, --output TEXT         Output JSON path
  --username TEXT           WinRM username (or $WINRM_USERNAME)
  --password TEXT           WinRM password (or $WINRM_PASSWORD)
  --analyze / --no-analyze  Run analysis after scan (default: off)
```

### `analyze`

```
python auditor.py analyze [OPTIONS]

Options:
  -i, --input TEXT    Path to scan JSON (required)
  -o, --output TEXT   Save analysis JSON to file (optional)
```

### `report`

```
python auditor.py report [OPTIONS]

Options:
  -i, --input TEXT    Path to scan JSON (required)
  -o, --output TEXT   Output HTML path (required)
  --no-ai             Skip Claude API, use static recommendations
```

### `version`

```
python auditor.py version
```

Prints `Infrastructure Security Auditor v0.1.0`.
