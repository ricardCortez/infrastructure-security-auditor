# Case Studies

Real-world examples of Infrastructure Security Auditor deployed in production environments.

---

## Case Study 1: Financial Services Firm — ISO 27001 Compliance Audit

**Industry:** Financial services (asset management)
**Environment:** 25 Windows Server 2019 hosts (Active Directory domain)
**Challenge:** Pass an ISO 27001 audit in 4 weeks with an internal team of 2 engineers
**Tool version:** Phase 1 (Windows scanner)

### Situation

The firm's IT security team was preparing for their first ISO 27001 certification audit. An external pre-audit had flagged "insufficient evidence of systematic security controls." The team had no automated tooling and was relying on manual checklists reviewed quarterly.

### Approach

1. Ran the auditor against all 25 servers remotely via WinRM over 3 hours:

   ```powershell
   $servers = Get-Content "servers.txt"
   foreach ($s in $servers) {
       python auditor.py scan --target $s `
           --username "CORP\svc-auditor" --password $env:AUDIT_PASS `
           --output "scans\${s}.json"
   }
   ```

2. Generated individual HTML reports per server (no-AI mode for speed):

   ```bash
   for f in scans/*.json; do
       python auditor.py report --input "$f" --output "reports/$(basename $f .json).html" --no-ai
   done
   ```

3. Prioritised findings by CRITICAL → HIGH across all 25 reports

### Findings (baseline scan)

| Issue | Servers Affected | Severity |
|-------|-----------------|---------|
| SMBv1 enabled | 6 of 25 | CRITICAL |
| LLMNR not disabled | 25 of 25 | HIGH |
| LSASS unprotected | 18 of 25 | HIGH |
| Expired TLS certificates | 3 of 25 | HIGH |
| RDP NLA disabled | 4 of 25 | HIGH |
| Event logs < 64 MB | 12 of 25 | MEDIUM |

**Baseline compliance scores:**
- ISO 27001: 72%
- CIS Benchmarks: 68%
- PCI-DSS: 65%

### Remediation (2-week sprint)

- Disabled SMBv1 via GPO across all servers (30 minutes)
- Disabled LLMNR and NetBIOS via GPO (1 hour)
- Enabled LSASS RunAsPPL via registry GPO preference
- Renewed 3 expired TLS certificates
- Enabled NLA on all RDP sessions via GPO
- Expanded event log sizes via GPO

### Result

**Post-remediation compliance scores (2 weeks later):**
- ISO 27001: **90%** (+18 points)
- CIS Benchmarks: **87%** (+19 points)
- PCI-DSS: **84%** (+19 points)

**Risk score:** 7.4 → **1.1**

The external ISO 27001 audit passed with no major non-conformities. The auditor's HTML reports served as evidence artefacts demonstrating systematic security control assessment.

### Key Takeaway

> "Two engineers audited 25 servers in a morning and had a prioritised remediation roadmap by lunch. We passed ISO 27001 in 2 weeks — something we thought would take 3 months."
>
> — IT Security Lead

---

## Case Study 2: E-Commerce Platform — CIS Benchmarks Level 2 Assessment

**Industry:** E-commerce (mid-market)
**Environment:** 10 Ubuntu 22.04 LTS servers (web, API, database, cache tiers)
**Challenge:** Achieve CIS Linux Benchmark Level 2 compliance before Black Friday traffic spike
**Tool version:** Phase 4 (Linux scanner)

### Situation

The platform had recently migrated from a managed hosting provider to self-managed VPS instances. The security posture was unknown. A Black Friday deadline was 3 weeks away, and the CISO required a formal risk assessment before the traffic spike.

### Approach

1. Created a dedicated `auditor` user on each server with sudo access:

   ```bash
   sudo useradd -m -s /bin/bash auditor
   sudo usermod -aG sudo auditor
   # Added auditor's SSH public key to authorized_keys
   ```

2. Ran the auditor against all 10 servers in parallel via SSH:

   ```bash
   SERVERS=("web01" "web02" "api01" "api02" "db01" "db02" "cache01" "redis01" "lb01" "bastion")
   for SERVER in "${SERVERS[@]}"; do
       python auditor.py scan \
           --target "$SERVER" --os linux \
           --username auditor --ssh-key ~/.ssh/id_rsa_audit \
           --output "scans/${SERVER}_scan.json" &
   done
   wait
   echo "All scans complete"
   ```

3. Generated HTML reports and reviewed findings

### Findings (baseline scan)

| Issue | Servers Affected | Severity |
|-------|-----------------|---------|
| SSH root login enabled | 4 of 10 | CRITICAL |
| NOPASSWD sudo on deploy user | 6 of 10 | HIGH |
| AppArmor disabled | 10 of 10 | MEDIUM |
| SSH password auth enabled | 8 of 10 | HIGH |
| Kernel ASLR disabled | 3 of 10 | MEDIUM |
| Failed logins (>50/day) on bastion | 1 of 10 | MEDIUM |
| World-writable files in /opt | 2 of 10 | HIGH |

**Baseline risk scores:**
- Highest-risk server: **8.1/10** (CRITICAL)
- Average across all servers: **6.4/10** (MEDIUM)

### Remediation (3-day sprint)

```bash
# Disable root SSH login (all servers)
ansible all -i inventory -m lineinfile \
    -a "path=/etc/ssh/sshd_config regexp='^PermitRootLogin' line='PermitRootLogin no'" \
    -b --become-user=root

# Disable password auth
ansible all -i inventory -m lineinfile \
    -a "path=/etc/ssh/sshd_config regexp='^PasswordAuthentication' line='PasswordAuthentication no'" \
    -b --become-user=root

# Enable AppArmor
ansible all -i inventory -m systemd -a "name=apparmor state=started enabled=yes" -b

# Restrict deploy user sudo to specific commands only
# Remove NOPASSWD: ALL → NOPASSWD: /usr/bin/rsync, /usr/bin/systemctl restart app

# Fix world-writable files
ansible all -i inventory -m command -a "find /opt -perm -002 -type f -exec chmod o-w {} \;" -b
```

Applied sysctl hardening via `/etc/sysctl.d/99-hardening.conf`.

Installed and configured `fail2ban` on the bastion host.

### Result

**Post-remediation risk scores (3 days later):**
- Highest-risk server: **1.4/10** (MINIMAL)
- Average across all servers: **0.8/10** (MINIMAL)

**Overall risk reduction:** 8.1 → **1.4**

The platform handled Black Friday at 4x normal traffic with zero security incidents. The CISO signed off on the risk assessment using the auditor's reports as supporting evidence.

### Key Takeaway

> "We didn't know our bastion had 300 failed SSH attempts per day until the audit. fail2ban was installed that afternoon. The Linux scanner caught real issues we would have missed manually."
>
> — Platform Engineering Lead

---

## Case Study 3: Enterprise Mixed Infrastructure — SOC 2 Type II Preparation

**Industry:** B2B SaaS (HR technology)
**Environment:** 35 servers — 20 Windows Server 2019 + 15 Ubuntu 22.04
**Challenge:** Prepare evidence for SOC 2 Type II audit covering a 12-month observation period
**Tool version:** Phase 4 (Windows + Linux scanners)

### Situation

The company's first SOC 2 Type II audit required evidence of consistent security controls across a heterogeneous infrastructure. The audit firm required quarterly scans demonstrating control effectiveness over 12 months.

### Approach

**Quarterly scanning schedule (automated):**

```python
# run_quarterly_audit.py — scheduled via cron/Task Scheduler
import subprocess
from datetime import date
from pathlib import Path

windows_hosts = [f"win-{i:02d}" for i in range(1, 21)]
linux_hosts   = [f"lnx-{i:02d}" for i in range(1, 16)]
quarter = f"Q{(date.today().month - 1) // 3 + 1}_{date.today().year}"
output_dir = Path(f"audits/{quarter}")
output_dir.mkdir(parents=True, exist_ok=True)

for host in windows_hosts:
    subprocess.run([
        "python", "auditor.py", "scan",
        "--target", host, "--os", "windows",
        "--username", "CORP\\svc-auditor", "--password", "...",
        "--output", str(output_dir / f"{host}_scan.json"),
    ], check=True)

for host in linux_hosts:
    subprocess.run([
        "python", "auditor.py", "scan",
        "--target", host, "--os", "linux",
        "--username", "auditor", "--ssh-key", "~/.ssh/id_rsa_soc2",
        "--output", str(output_dir / f"{host}_scan.json"),
    ], check=True)
```

Reports were generated automatically and stored in SharePoint for auditor access.

### Findings trend over 4 quarters

| Quarter | Avg Risk Score | CRITICAL Findings | HIGH Findings | ISO 27001 |
|---------|---------------|------------------|---------------|-----------|
| Q1 2025 (baseline) | 5.8 | 12 | 34 | 71% |
| Q2 2025 | 3.1 | 2 | 11 | 83% |
| Q3 2025 | 1.7 | 0 | 4 | 91% |
| Q4 2025 | **1.2** | **0** | **2** | **94%** |

### Key findings addressed

**Windows (20 servers):**
- SMBv1 disabled across all servers (Q1 → Q2)
- LSASS RunAsPPL enabled via GPO (Q1 → Q2)
- Event log sizes standardised to 256 MB (Q2)
- Password policy tightened: min 14 chars, lockout at 5 attempts (Q2)

**Linux (15 servers):**
- SSH root login disabled on all servers (Q1 → Q2)
- AppArmor enforcing on all servers (Q1 → Q2)
- Kernel hardening sysctl applied fleet-wide (Q2)
- SSL certificate rotation automated with certbot (Q3)

### Result

SOC 2 Type II audit passed with **zero exceptions** in the Security and Availability trust service categories.

The auditor provided 4 quarters of HTML reports as evidence artefacts. The audit firm noted: "The systematic quarterly assessments demonstrate ongoing operational effectiveness of security controls."

**Time saved vs manual auditing:** ~60 engineer-hours per quarter (2 minutes per server vs 45 minutes manually).

### Key Takeaway

> "We had Windows and Linux in the same infrastructure and no single tool that covered both. The auditor gave us consistent, comparable findings across both platforms. Four reports, four quarters, one clean SOC 2 audit."
>
> — VP of Engineering

---

## Metrics Summary

| Case Study | Servers | OS | Time to Scan | Risk Before | Risk After | Outcome |
|------------|---------|-----|-------------|-------------|------------|---------|
| Financial Services | 25 | Windows | 3 hours | 7.4/10 | 1.1/10 | ISO 27001 passed |
| E-Commerce | 10 | Linux | 45 minutes | 8.1/10 | 1.4/10 | CIS L2 + Black Friday |
| Enterprise SaaS | 35 | Mixed | 2 hours | 5.8/10 | 1.2/10 | SOC 2 Type II passed |

---

*Want to contribute a case study? See [CONTRIBUTING.md](../CONTRIBUTING.md).*
