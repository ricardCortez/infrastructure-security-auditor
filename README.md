# Infrastructure Security Auditor

> Automated Windows & Linux infrastructure security scanning with AI-powered analysis and professional HTML reporting.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-362%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-82%25-yellowgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

---

## What It Does

**Infrastructure Security Auditor** scans your servers in minutes, not hours. Point it at any Windows or Linux host and it will:

1. Execute **33 security checks** (15 Windows + 18 Linux) concurrently
2. Score the overall risk **0–10** using a CVSS-inspired algorithm
3. Map findings to **ISO 27001, CIS Benchmarks, and PCI-DSS** compliance percentages
4. Generate a **standalone HTML report** ready to share with clients or management

No agent installation on the target. No cloud dependency. Runs fully local or air-gapped.

---

## Quick Start

Get your first audit in 5 minutes:

```bash
# 1. Clone and install
git clone https://github.com/your-org/infrastructure-security-auditor.git
cd infrastructure-security-auditor
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

# 2. (Optional) Add your Claude API key for AI-powered recommendations
cp .env.example .env
# Edit .env → CLAUDE_API_KEY=sk-ant-...

# 3. Scan
python auditor.py scan --target localhost --os windows
python auditor.py scan --target localhost --os linux

# 4. Generate HTML report
python auditor.py report --input localhost_scan.json --output report.html

# 5. Open the report
start report.html          # Windows
xdg-open report.html       # Linux
```

> Full setup instructions (virtual environment, remote access, troubleshooting): [INSTALLATION.md](INSTALLATION.md)

---

## Usage Examples

### Windows: local scan

```bash
python auditor.py scan --target localhost --os windows
```

### Windows: remote server via WinRM

```bash
python auditor.py scan \
    --target 192.168.1.100 \
    --os windows \
    --username DOMAIN\Administrator \
    --password "YourPassword"
```

### Linux: local scan

```bash
python auditor.py scan --target localhost --os linux
```

### Linux: remote server via SSH key

```bash
python auditor.py scan \
    --target 10.0.1.50 \
    --os linux \
    --username auditor \
    --ssh-key ~/.ssh/id_rsa
```

### Linux: remote server via SSH password

```bash
python auditor.py scan \
    --target 10.0.1.50 \
    --os linux \
    --username auditor \
    --password "YourPassword"
```

### Scan and analyze in one step

```bash
python auditor.py scan --target localhost --os linux --analyze
```

### Generate a report (with AI recommendations)

```bash
python auditor.py report --input localhost_scan.json --output report.html
```

### Generate a report (no API key required)

```bash
python auditor.py report --input localhost_scan.json --output report.html --no-ai
```

### Interactive TUI (no flags needed)

```bash
python auditor.py interactive
```

Launches a menu-driven interface — select options by number, no command memorisation required.

---

## Network-Wide Auditing (Phase 5)

Scan entire subnets automatically. Discover hosts, detect OS, scan all servers in parallel,
and generate a consolidated network report.

### Step 1 — Discover hosts in a network

```bash
# CIDR notation
python auditor.py discover --network 192.168.0.0/24

# IP range notation
python auditor.py discover --network 10.0.0.1-50 --timeout 2 --output hosts.json
```

Output: JSON with IP, hostname, OS hint (windows/linux/unknown), open ports, RTT.

### Step 2 — Scan discovered hosts

```bash
# Auto-discover then scan
python auditor.py scan-network --network 192.168.0.0/24

# Scan from a saved discovery file
python auditor.py scan-network --file hosts.json --max-workers 20
```

Output: `network_scan_192_168_0_0_24.json` with findings for every host.

### Step 3 — Generate consolidated network report

```bash
# Full report (all servers + remediation roadmap)
python auditor.py report-network --input network_scan_192_168_0_0_24.json

# Lightweight summary page only
python auditor.py report-network --input network_scan_192_168_0_0_24.json --summary-only
```

Output: `reports/network_*/network_consolidated_report.html` + `network_summary.html`

### Full pipeline (one liner)

```bash
python auditor.py scan-network --network 192.168.0.0/24 --output net.json && \
python auditor.py report-network --input net.json --output reports/audit/
```

> Full command reference and workflow examples: [docs/USAGE.md](docs/USAGE.md)

---

## Features

- **33 security checks** — 15 Windows (PowerShell/WinRM) + 18 Linux (shell/SSH)
- **Network-wide auditing** — discover + scan entire subnets (50–150+ servers) automatically
- **Interactive TUI** — menu-driven terminal interface, no flags required
- **AI-powered analysis** via Claude (Anthropic) — falls back gracefully to static recommendations
- **Professional HTML reports** — standalone files, no external CDN, suitable for air-gap environments
- **Consolidated network reports** — per-server details, compliance heatmap, unified roadmap
- **Risk scoring (0–10)** using a CVSS-inspired weighted algorithm
- **Compliance mapping** against ISO 27001, CIS Benchmarks, and PCI-DSS
- **Local and remote scanning** — localhost, WinRM (Windows), SSH key or password (Linux)
- **Parallel execution** — ThreadPoolExecutor runs all checks concurrently
- **Rich CLI output** — colour-coded tables and progress spinners
- **Extensible architecture** — add new checks without touching existing code

---

## Report Contents

Every generated HTML report includes:

| Section | Audience |
|---------|----------|
| Executive Summary | C-level, non-technical stakeholders |
| Risk Dashboard (0–10 score) | Management, auditors |
| Findings by Severity | Security engineers |
| Compliance Status (ISO 27001 / CIS / PCI-DSS %) | Compliance teams |
| Detailed Recommendations | System administrators |
| Remediation Roadmap (prioritised) | Project managers |
| Technical Appendix (raw data) | Forensics, penetration testers |

---

## Security Checks

### Windows Server (15 checks)

| Check | Severity | CVEs / Standards |
|-------|----------|-----------------|
| Firewall Status | HIGH | ISO A.13.1.1, CIS 9.x |
| SMBv1 Protocol | **CRITICAL** | MS17-010 (EternalBlue/WannaCry) |
| LLMNR / NetBIOS | HIGH | Responder attack surface |
| Windows Defender | HIGH | ISO A.12.2.1, PCI DSS 5.x |
| TLS Versions | HIGH | POODLE, BEAST, DROWN (RFC 8996) |
| Password Policies | MEDIUM | CIS 1.x, PCI DSS 8.x |
| RDP NLA | HIGH | CVE-2019-0708 (BlueKeep) |
| Windows Update | MEDIUM | CIS 19.x, PCI DSS 6.3 |
| Admin Accounts | HIGH | ISO A.9.2.3, PCI DSS 8.1.1 |
| Privilege Creep | MEDIUM | ISO A.9.2.2, PCI DSS 7.1 |
| Event Log Config | MEDIUM | ISO A.12.4.1, PCI DSS 10.x |
| LSASS Protection | HIGH | Mimikatz / credential dumping |
| Weak Ciphers | HIGH | RC4, DES, 3DES, NULL, EXPORT |
| File Sharing | MEDIUM | ISO A.13.2.1, PCI DSS 7.2 |
| Installed Software | LOW | EOL software risk |

### Linux Server (18 checks)

| Check | Severity | What It Detects |
|-------|----------|----------------|
| SSH Key Authentication | HIGH | PubkeyAuthentication disabled |
| SSH Root Login | **CRITICAL** | PermitRootLogin not set to `no` |
| SSH Password Auth | HIGH | PasswordAuthentication enabled |
| Firewall Enabled | HIGH | UFW inactive, no iptables rules |
| Sudo Configuration | HIGH | NOPASSWD rules, unrestricted ALL |
| World-Writable Files | HIGH | Files any user can overwrite |
| SUID Binaries | HIGH | Unexpected SUID bits (GTFOBins) |
| File Permissions | HIGH | /etc/shadow readable, /etc/passwd writable |
| Kernel Hardening | MEDIUM | ASLR disabled, ip_forward, sysctl gaps |
| SELinux / AppArmor | MEDIUM | MAC framework not enforcing |
| Package Updates | MEDIUM | Pending apt/yum security patches |
| SSL Certificates | HIGH | Expired or expiring-within-30-days certs |
| Open Ports | MEDIUM | Unexpected listening services |
| User Accounts | HIGH | Hidden UID-0 accounts, system shells |
| Failed Logins | MEDIUM | Brute-force activity (50+ failures) |
| Cron Jobs | MEDIUM | World-writable scripts in crontabs |
| Weak SSH Ciphers | HIGH | 3DES, arcfour, hmac-md5 in sshd_config |
| Log Rotation | LOW | logrotate not configured or inactive |

---

## Risk Scoring

A CVSS-inspired weighted algorithm normalised to `[0.0, 10.0]`:

| Severity | Weight |
|----------|--------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |

| Score | Label |
|-------|-------|
| 8.5–10.0 | CRITICAL |
| 6.5–8.4 | HIGH |
| 4.0–6.4 | MEDIUM |
| 1.5–3.9 | LOW |
| 0.0–1.4 | MINIMAL |

---

## Compliance Mapping

| Standard | Controls Tracked |
|----------|-----------------|
| ISO/IEC 27001:2013 | 114 controls (Annex A) |
| CIS Benchmarks (Windows + Linux) | 356+ controls |
| PCI DSS v3.2.1 | 251 requirements |

Compliance percentages reflect the proportion of mapped controls passing on the target host.

---

## Case Studies

### Financial Services Firm
- **Environment:** 25 Windows servers
- **Challenge:** ISO 27001 compliance audit with 4-week deadline
- **Result:** 72% → 90% compliance in 2 weeks; audit passed with no major findings
- **Key findings resolved:** SMBv1 on 6 servers, LLMNR enabled enterprise-wide, 3 expired TLS certs

### E-Commerce Platform
- **Environment:** 10 Linux servers (Ubuntu 22.04)
- **Challenge:** CIS Benchmarks Level 2 assessment before Black Friday
- **Result:** Risk score 8.1 → 1.4 after 3-day hardening sprint
- **Key findings resolved:** Root SSH enabled on 4 servers, NOPASSWD sudo on deploy user, AppArmor disabled

### Enterprise Mixed Infrastructure
- **Environment:** 35 servers (20 Windows + 15 Linux)
- **Challenge:** Unified compliance audit for SOC 2 Type II preparation
- **Result:** Single comprehensive report, clear 3-month hardening roadmap, SOC 2 audit passed
- **Key findings resolved:** Consistent policy applied across OS boundaries

---

## Pricing (Consulting Use)

| Service | Price | Delivery |
|---------|-------|----------|
| Single Server Audit | $500–800 | 2–3 hours |
| Small Infrastructure (1–10 servers) | $1,000–1,500 | 4–6 hours |
| Medium Infrastructure (10–25 servers) | $1,500–2,500 | 1 business day |
| Large Infrastructure (25+ servers) | Custom quote | 2–3 business days |
| Compliance Assessment (ISO/CIS/PCI) | $1,000–3,000 | 1 business day |
| Hardening Implementation | $100–150/hr | Variable |

Includes: scan execution, HTML report, executive summary, prioritised remediation roadmap.

---

## Code Quality

```
362 tests passing   •   82% coverage   •   0 flake8 errors
PEP 8 compliant   •   Type hints throughout   •   Comprehensive docstrings
```

```bash
# Run tests
pytest tests/ -v --cov=src --cov-report=term-missing

# Lint
flake8 src/ tests/

# Format
black src/ tests/
isort src/ tests/
```

---

## Architecture

```
infrastructure-security-auditor/
├── auditor.py                     ← Entry point
├── src/
│   ├── cli.py                     ← Click CLI (scan, analyze, report, version)
│   ├── config.py                  ← Environment variables, constants, mappings
│   ├── scanner/
│   │   ├── windows_scanner.py     ← 15 PowerShell-based checks (local/WinRM)
│   │   └── linux_scanner.py       ← 18 shell-based checks (local/SSH)
│   ├── analyzer/
│   │   ├── analyzer.py            ← Risk scoring + Claude AI integration
│   │   └── risk_scorer.py         ← Weighted CVSS-like algorithm
│   ├── reporter/
│   │   ├── html_generator.py      ← Jinja2 HTML report renderer
│   │   └── templates/report.html  ← Standalone HTML template
│   └── remediator/
│       └── playbook_gen.py        ← Ansible/PowerShell playbook generation
├── tests/                         ← pytest suite (362 tests, 82% coverage)
├── docs/                          ← Technical documentation
└── examples/                      ← Case studies and sample data
```

**Data flow:**

```
Target Host
    │
    ▼
WindowsScanner / LinuxScanner     executes checks concurrently
    │  scan_results.json
    ▼
Analyzer.analyze()                 risk score + compliance % + AI recs
    │  analysis_data
    ▼
HTMLReporter.generate()            renders standalone HTML report
    │  report.html
    ▼
Browser / Distribution
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed module descriptions and extension points.

---

## Requirements

- Python 3.11+
- **Windows targets:** PowerShell 5.0+, Administrator privileges
- **Linux targets:** SSH access with sudo/root (for full coverage)
- Anthropic API key (optional — enables AI-powered recommendations)

---

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALLATION.md](INSTALLATION.md) | Step-by-step setup, virtual environment, remote access, troubleshooting |
| [docs/USAGE.md](docs/USAGE.md) | Command reference, Windows vs Linux workflows, report interpretation |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data structures, extension points |
| [docs/API.md](docs/API.md) | Full class/method reference with examples |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Developer guide, adding checks, PR process |
| [examples/](examples/) | Case studies and sample scan data |

---

## Contributing

```bash
# Install dev dependencies
pip install pytest pytest-cov pytest-mock flake8 black isort mypy

# Run tests
pytest tests/ -v --cov=src --cov-report=term-missing

# Add a new check — see CONTRIBUTING.md for the 5-step process
```

To add a new security check, see [CONTRIBUTING.md](CONTRIBUTING.md).

**Commit format:** `[AgentN] descriptive message`

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Support

- Open an issue on GitHub for bug reports and feature requests
- See [docs/USAGE.md](docs/USAGE.md) for common troubleshooting steps
- For security vulnerabilities, please disclose responsibly via GitHub Security Advisories
