# Installation Guide

Complete setup instructions for Infrastructure Security Auditor.

---

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Python | 3.11 | 3.12+ |
| OS (controller) | Windows 10, macOS, Linux | Windows 10 / Server 2019+ |
| OS (target host) | Windows 10 / Server 2019 | Windows Server 2022 |
| PowerShell (target) | 5.0 | 7.0+ |
| RAM | 512 MB | 2 GB |
| Disk | 100 MB | 500 MB |

> **Privilege note:** Some checks (e.g. `Get-LocalGroupMember`, `Get-MpComputerStatus`) require the scanning process to run with **Administrator** privileges on the target host. Checks that cannot be completed due to insufficient permissions return a WARNING finding rather than failing silently.

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/your-org/infrastructure-security-auditor.git
cd infrastructure-security-auditor
```

---

## Step 2 — Create a Virtual Environment

Using a virtual environment keeps project dependencies isolated.

**Windows (PowerShell):**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

After activation your prompt should show `(venv)`.

---

## Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:

| Package | Purpose |
|---|---|
| `click` | CLI framework |
| `jinja2` | HTML templating |
| `anthropic` | Claude AI API client |
| `pywinrm` | Remote Windows management (WinRM) |
| `python-dotenv` | `.env` file loading |
| `rich` | Console formatting and progress |
| `requests` | HTTP utilities |

---

## Step 4 — Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` in a text editor and fill in the values:

```ini
# Required for AI-powered recommendations
CLAUDE_API_KEY=sk-ant-api03-...

# Required only for remote WinRM scans
WINRM_USERNAME=DOMAIN\Administrator
WINRM_PASSWORD=YourSecurePassword
WINRM_PORT=5985
WINRM_TRANSPORT=ntlm

# Logging
LOG_LEVEL=INFO
LOG_FILE=auditor.log

# Where HTML reports are saved
REPORT_OUTPUT_DIR=./reports
```

### Getting a Claude API Key

1. Sign up at [console.anthropic.com](https://console.anthropic.com/)
2. Navigate to **API Keys** → **Create Key**
3. Copy the key (it starts with `sk-ant-`)
4. Paste it into your `.env` file

> The Claude API key is **optional**. If not configured, the tool falls back to static remediation recommendations that are built into the codebase.

---

## Step 5 — Verify Installation

```bash
# Check CLI is available
python auditor.py --help

# Check version
python auditor.py version

# Run the test suite
python -m pytest tests/ -v
```

Expected output:
```
Infrastructure Security Auditor v0.1.0

============== 207 passed in 3.42s ==============
```

---

## Step 6 — Run Your First Scan

```bash
# Scan the local machine
python auditor.py scan --target localhost

# Generate a report
python auditor.py report --input localhost_scan.json --output report.html

# Open the report
start report.html   # Windows
open report.html    # macOS
```

---

## Remote Scanning Setup (WinRM)

To scan a remote Windows host, WinRM must be enabled on the target.

### Enable WinRM on the target host

Run the following on the **target server** (as Administrator):

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Allow NTLM authentication
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Open firewall (HTTP port 5985)
New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound `
  -Protocol TCP -LocalPort 5985 -Action Allow

# Verify
winrm quickconfig
```

### Test connectivity from the controller

```powershell
Test-WSMan -ComputerName 192.168.1.100
```

### Scan the remote host

```bash
python auditor.py scan \
  --target 192.168.1.100 \
  --username "DOMAIN\Administrator" \
  --password "SecurePass123"
```

---

## Development Dependencies

To run tests and use linting/formatting tools:

```bash
pip install pytest pytest-cov pytest-mock flake8 black isort mypy
```

Run the full test suite with coverage:

```bash
pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html
```

---

## Troubleshooting

### `python` command not found

Ensure Python 3.11+ is installed and on your `PATH`:

```bash
python --version   # Should show Python 3.11.x or higher
```

If not found, download Python from [python.org](https://www.python.org/downloads/) and check "Add Python to PATH" during installation.

### PowerShell execution policy error

If you see `cannot be loaded because running scripts is disabled`:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### `pywinrm` import error for remote scans

Ensure `pywinrm` is installed in your active virtual environment:

```bash
pip install pywinrm
```

### WinRM connection refused

1. Verify WinRM is running on the target: `Get-Service WinRM`
2. Check firewall allows TCP 5985 (HTTP) or 5986 (HTTPS)
3. Test with: `Test-WSMan -ComputerName <TARGET>`
4. On domain networks, NTLM may require enabling: `Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true`

### Claude API errors

- **401 Unauthorized:** API key is invalid or expired — regenerate at `console.anthropic.com`
- **429 Rate Limited:** Too many requests — the tool will automatically fall back to static recommendations
- **Timeout:** Network issue — the tool falls back to static recommendations after a timeout

### Insufficient privileges warning

Some checks require Administrator access. Run your terminal as Administrator, or accept WARNING findings for checks that could not be completed.

### Import errors (`src` not found)

Run `auditor.py` from the project root directory (where `auditor.py` is located):

```bash
cd infrastructure-security-auditor
python auditor.py scan --target localhost
```
