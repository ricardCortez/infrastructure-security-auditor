# Infrastructure Security Auditor

> Automated Windows & Linux infrastructure security scanning with AI-powered analysis, network-wide batch auditing, and professional HTML reporting.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-484%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-83%25-yellowgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

---

## What It Does

**Infrastructure Security Auditor** scans your servers in minutes, not hours. Point it at a single host or an entire subnet and it will:

1. Execute **33 security checks** (15 Windows + 18 Linux) concurrently
2. Score overall risk **0–10** using a CVSS-inspired algorithm
3. Map findings to **ISO 27001, CIS Benchmarks, and PCI-DSS** compliance percentages
4. Generate a **standalone HTML report** ready to share with clients or management

No agent installation on the target. No cloud dependency. Runs fully local or air-gapped.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/ricardCortez/infrastructure-security-auditor.git
cd infrastructure-security-auditor
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

# 2. (Optional) Add your Claude API key for AI-powered recommendations
cp .env.example .env
# Edit .env → CLAUDE_API_KEY=sk-ant-...

# 3. Scan a single server
python auditor.py scan --target localhost --os windows
python auditor.py scan --target localhost --os linux

# 4. Generate HTML report
python auditor.py report --input localhost_scan.json --output report.html

# 5. Or launch the interactive TUI (no flags needed)
python auditor.py interactive
```

> Full setup instructions: [INSTALLATION.md](INSTALLATION.md)

---

## Usage Examples

### Single Server Scans

```bash
# Windows — local
python auditor.py scan --target localhost --os windows

# Windows — remote via WinRM
python auditor.py scan --target 192.168.1.100 --os windows \
    --username DOMAIN\Administrator --password "YourPassword"

# Linux — local
python auditor.py scan --target localhost --os linux

# Linux — remote via SSH key
python auditor.py scan --target 10.0.1.50 --os linux \
    --username auditor --ssh-key ~/.ssh/id_rsa

# Scan and analyze in one step
python auditor.py scan --target localhost --os linux --analyze

# Generate HTML report (AI recommendations)
python auditor.py report --input localhost_scan.json --output report.html

# Generate HTML report (no API key needed)
python auditor.py report --input localhost_scan.json --output report.html --no-ai
```

### Interactive TUI

```bash
python auditor.py interactive
```

Launches a menu-driven interface — select options by number, no command memorisation required.

---

## Network-Wide Auditing

Scan entire subnets automatically. Discover all live hosts, detect OS, scan in parallel, and get a consolidated network report.

### Step 1 — Discover hosts

```bash
# CIDR notation
python auditor.py discover --network 192.168.0.0/24

# IP range notation
python auditor.py discover --network 10.0.0.1-50 --timeout 2 --output hosts.json
```

Output: JSON with IP, hostname, OS hint (windows/linux/unknown), open ports, response time.

### Step 2 — Scan all discovered hosts

```bash
# Auto-discover then scan
python auditor.py scan-network --network 192.168.0.0/24

# Scan from a saved discovery file (faster)
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

### One-liner full pipeline

```bash
python auditor.py scan-network --network 192.168.0.0/24 --output net.json && \
python auditor.py report-network --input net.json
```

> Full command reference: [docs/USAGE.md](docs/USAGE.md)

---

## Features

| Feature | Detail |
|---------|--------|
| **33 security checks** | 15 Windows (PowerShell/WinRM) + 18 Linux (shell/SSH) |
| **Network-wide auditing** | Discover + scan entire subnets (50–150+ servers) automatically |
| **Interactive TUI** | Menu-driven terminal interface — no flags required |
| **AI-powered analysis** | Claude (Anthropic) recommendations; falls back to static rules if no key |
| **Professional HTML reports** | Standalone files, no CDN, air-gap safe |
| **Consolidated network reports** | Per-server details, compliance heatmap, unified remediation roadmap |
| **Risk scoring (0–10)** | CVSS-inspired weighted algorithm |
| **Compliance mapping** | ISO 27001, CIS Benchmarks, PCI-DSS percentages |
| **Local + remote scanning** | localhost, WinRM (Windows), SSH key or password (Linux) |
| **Parallel execution** | ThreadPoolExecutor for all checks and all hosts concurrently |
| **Rich CLI output** | Colour-coded tables, progress spinners, severity badges |
| **Extensible** | Add new checks without touching existing code |

---

## Report Contents

### Single-Server Report (7 sections)

| Section | Audience |
|---------|----------|
| Executive Summary | C-level, non-technical stakeholders |
| Risk Dashboard (0–10 score) | Management, auditors |
| Findings by Severity | Security engineers |
| Compliance Status (ISO 27001 / CIS / PCI-DSS %) | Compliance teams |
| Detailed Recommendations | System administrators |
| Remediation Roadmap (prioritised) | Project managers |
| Technical Appendix (raw data) | Forensics, penetration testers |

### Network Report (additional sections)

| Section | Detail |
|---------|--------|
| Network Overview | CIDR scope, scan metadata, total hosts |
| Risk Dashboard | Network-average risk score (0–10) |
| Server Matrix | IP, hostname, OS, risk score, status for every host |
| Compliance Heatmap | ISO / CIS / PCI bars per server |
| Top Critical Servers | Ranked by risk score |
| Common Findings | Issues appearing on 3+ servers (systemic risks) |
| Per-Server Details | Collapsible finding sections for each host |

---

## Security Checks

### Windows Server (15 checks)

| Check | Severity | CVEs / Standards |
|-------|----------|-----------------|
| Firewall Status | HIGH | ISO A.13.1.1, CIS 9.x |
| SMBv1 Protocol | **CRITICAL** | MS17-010 (EternalBlue / WannaCry) |
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
| SSH Root Login | **CRITICAL** | PermitRootLogin not `no` |
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

## Architecture

```
infrastructure-security-auditor/
├── auditor.py                          ← Entry point
├── src/
│   ├── cli.py                          ← Click CLI (8 commands)
│   ├── config.py                       ← Environment variables, constants, mappings
│   ├── scanner/
│   │   ├── windows_scanner.py          ← 15 PowerShell-based checks (local/WinRM)
│   │   ├── linux_scanner.py            ← 18 shell-based checks (local/SSH)
│   │   ├── network_discovery.py        ← Ping sweep + OS detection
│   │   └── batch_scanner.py            ← Parallel multi-host scanning
│   ├── analyzer/
│   │   ├── analyzer.py                 ← Risk scoring + Claude AI integration
│   │   └── risk_scorer.py              ← Weighted CVSS-like algorithm
│   ├── reporter/
│   │   ├── html_generator.py           ← Single-server HTML report renderer
│   │   ├── network_reporter.py         ← Network-wide HTML report renderer
│   │   └── templates/                  ← Jinja2 HTML templates
│   ├── tui/
│   │   ├── interactive.py              ← TUI entry point
│   │   ├── menu.py                     ← Main menu navigation
│   │   ├── scanner_ui.py               ← Scan + discovery flows
│   │   ├── results_ui.py               ← Report generation flow
│   │   ├── components.py               ← Reusable Rich panels/tables
│   │   └── styles.py                   ← Colors + theme
│   └── remediator/
│       └── playbook_gen.py             ← Ansible/PowerShell playbook generation
├── tests/                              ← pytest suite (484 tests, 83% coverage)
├── docs/                               ← Technical documentation
└── examples/                           ← Case studies and sample data
```

**Data flow — single server:**

```
Target Host
    │
    ▼
WindowsScanner / LinuxScanner      executes checks concurrently
    │  scan_results.json
    ▼
Analyzer.analyze()                 risk score + compliance % + AI recs
    │  analysis_data
    ▼
HTMLReporter.generate()            renders standalone HTML report
```

**Data flow — network audit:**

```
Network CIDR / IP range
    │
    ▼
NetworkDiscovery.discover_hosts()  ping sweep + OS detection
    │  [HostDict list]
    ▼
BatchScanner.scan_with_progress()  parallel WindowsScanner/LinuxScanner
    │  network_scan.json
    ▼
NetworkReporter.save_reports()     summary + consolidated HTML
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed module descriptions.

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

---

## Case Studies

### Financial Services Firm
- **Environment:** 25 Windows servers
- **Challenge:** ISO 27001 audit with 4-week deadline
- **Result:** 72% → 90% compliance in 2 weeks; audit passed with no major findings
- **Key findings:** SMBv1 on 6 servers, LLMNR enabled enterprise-wide, 3 expired TLS certs

### E-Commerce Platform
- **Environment:** 10 Linux servers (Ubuntu 22.04)
- **Challenge:** CIS Benchmarks Level 2 before Black Friday
- **Result:** Risk score 8.1 → 1.4 after 3-day hardening sprint
- **Key findings:** Root SSH on 4 servers, NOPASSWD sudo on deploy user, AppArmor disabled

### Enterprise Mixed Infrastructure
- **Environment:** 35 servers (20 Windows + 15 Linux)
- **Challenge:** Unified compliance for SOC 2 Type II preparation
- **Result:** Single consolidated report, clear 3-month roadmap, SOC 2 passed
- **Key findings:** Policy inconsistencies across OS boundaries resolved

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

---

## Code Quality

```
484 tests passing   •   83% coverage   •   0 flake8 errors
PEP 8 compliant   •   Type hints throughout   •   Google-style docstrings
```

```bash
# Run tests
pytest tests/ -v --cov=src --cov-report=term-missing

# Lint
flake8 src/

# Format
black src/ tests/
isort src/ tests/
```

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

# Add a new check — see CONTRIBUTING.md for the step-by-step process
```

**Commit format:** `[AgentN] descriptive message`

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## PSI Platform (Enterprise Mode)

This repo also includes **PSI – Plataforma de Seguridad Integrada**, a full enterprise security platform built on top of the auditor.

| Component | Description |
|-----------|-------------|
| `backend/core-api/` | FastAPI REST API + PostgreSQL + Elasticsearch |
| `backend/job-orchestrator/` | Celery + Redis task queue (Nessus, OpenVAS, auditor) |
| `backend/scan-workers/` | Scan worker pool + auditor integration |
| `backend/cli/` | Interactive PSI TUI (`psi.py`) |
| `docker/` | Docker Compose stack (API + workers + DB + monitoring) |
| `monitoring/` | Prometheus + Grafana dashboards |

### Start the full platform

```bash
# Copy and configure environment
cp .env.example .env          # add API keys

# Start all services via Docker
docker-compose -f docker/docker-compose.yml up -d

# PSI CLI (interactive TUI)
python psi.py menu

# PSI CLI direct commands
python psi.py auditor scan --asset-id 1 --target 192.168.1.100
python psi.py findings list --severity CRITICAL
python psi.py reports generate --format pdf
```

Or run the automated setup:

```bash
bash setup.sh
```

---

## Support

- Open an issue on GitHub for bug reports and feature requests
- See [docs/USAGE.md](docs/USAGE.md) for common troubleshooting steps
- For security vulnerabilities, please disclose responsibly via GitHub Security Advisories
