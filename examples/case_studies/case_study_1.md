# Case Study 1 — Financial Services ISO 27001 Compliance Audit

**Sector:** Financial Services (investment management firm)
**Environment:** 25 Windows Server 2019 hosts across 3 data centres
**Objective:** Prepare for ISO 27001 certification audit
**Timeline:** 2-week assessment

---

## Background

A mid-sized investment management firm with approximately 400 employees was preparing for their first ISO 27001 certification. Their IT team had recently migrated from Windows Server 2012 R2 to Windows Server 2019 but had not performed a structured security baseline review of the new environment.

Their primary concerns were:

1. Identifying misconfigurations introduced during the migration
2. Quantifying ISO 27001 Annex A compliance gaps
3. Producing evidence-grade documentation for their auditors

---

## Challenge

Manual auditing of 25 servers by a 3-person IT security team would have taken approximately 2 weeks of effort. The team had no existing baseline documentation for the Windows 2019 environment, and their external auditors required consistent, reproducible evidence of checks performed.

Key risk areas identified before the scan:

- Unknown status of SMBv1 (had been enabled on the old 2012 R2 environment)
- No centralised patch management — WSUS had been decommissioned during migration
- Firewall policy had been managed manually per server
- No formal LSASS protection policy

---

## Solution

The team deployed Infrastructure Security Auditor on a dedicated jump host with read-only WinRM access to all 25 servers. Scans were scheduled via Windows Task Scheduler to run overnight.

**Scan configuration:**

```bash
# Script run against each server
python auditor.py scan \
  --target $SERVER_IP \
  --username "CORP\svc-auditor" \
  --password $WINRM_PASSWORD \
  --output "scans/${SERVER_NAME}_$(date +%Y%m%d).json"

python auditor.py report \
  --input "scans/${SERVER_NAME}_$(date +%Y%m%d).json" \
  --output "reports/${SERVER_NAME}_$(date +%Y%m%d).html"
```

---

## Findings Summary (Aggregate Across 25 Servers)

| Check | Servers Failing | Severity |
|---|---|---|
| SMBv1 Protocol | 8 / 25 | CRITICAL |
| LSASS Protection | 22 / 25 | HIGH |
| Windows Update | 15 / 25 | MEDIUM |
| TLS Versions | 11 / 25 | HIGH |
| RDP NLA | 3 / 25 | HIGH |
| Password Policies | 6 / 25 | MEDIUM |
| Event Log Config | 19 / 25 | MEDIUM |
| LLMNR/NetBIOS | 25 / 25 | HIGH |
| Windows Defender | 0 / 25 | — |
| Firewall Status | 2 / 25 | HIGH |
| Admin Accounts | 7 / 25 | HIGH |
| Weak Ciphers | 14 / 25 | HIGH |
| File Sharing | 4 / 25 | MEDIUM |
| Privilege Creep | 3 / 25 | MEDIUM |
| Installed Software | 5 / 25 | LOW |

**Worst server risk score:** 8.4 / 10 (HIGH)
**Best server risk score:** 1.2 / 10 (MINIMAL)
**Average risk score across fleet:** 5.6 / 10 (MEDIUM)

---

## ISO 27001 Compliance Results

| Control Domain | Before Remediation | After Remediation (Week 2) |
|---|---|---|
| A.9 — Access Control | 68% | 91% |
| A.12 — Operations Security | 71% | 89% |
| A.13 — Communications Security | 55% | 88% |
| A.14 — System Acquisition | 74% | 85% |
| **Overall ISO 27001** | **72%** | **90%** |

---

## Remediation Actions Taken

The Claude AI recommendations identified the following prioritised actions:

**Immediate (Day 1–2):**
- Disable SMBv1 on all 8 affected servers
- Enable firewall on 2 servers with disabled profiles
- Enable NLA for RDP on 3 servers

**Within 1 Week:**
- Deploy LSASS RunAsPPL via Group Policy (GPO) to all 25 servers
- Disable LLMNR via GPO (domain-wide policy)
- Disable deprecated TLS protocols via IIS Crypto tool across all servers
- Disable weak cipher suites (RC4, 3DES)

**Within 2 Weeks:**
- Apply all pending Windows Updates (critical patches first)
- Increase event log sizes to 128 MB via GPO
- Tighten password policies (min length 14, 90-day max age)

---

## Results

After the 2-week remediation sprint:

- Average risk score dropped from **5.6 to 1.8** (MEDIUM → LOW)
- ISO 27001 compliance improved from **72% to 90%**
- Zero CRITICAL findings remaining across the entire fleet
- Audit-ready HTML reports served as formal evidence for the certification auditors

**Time saved vs. manual audit:** Estimated 6 person-days saved in the initial scan phase.

The ISO 27001 certification audit passed without major non-conformances related to Windows infrastructure configuration.

---

## Lessons Learned

- LLMNR was enabled on **every** server — it had never been addressed as part of the Windows 2019 migration build standard
- Event log sizes were all at the default 20 MB, which is insufficient for any meaningful forensic retention
- LSASS RunAsPPL requires a registry change plus a reboot — schedule maintenance windows in advance
- The AI-generated recommendations correctly prioritised SMBv1 and LLMNR above patching, aligning with the actual risk profile

---

## Sample Report Extract

```
Server: FIN-DC01.corp.example.com
Scan Date: 2026-03-05 02:14:37 UTC
Risk Score: 7.2 / 10 (HIGH)

Critical Findings (1):
  ✗ SMBv1 Protocol [CRITICAL]
    SMBv1 is ENABLED. Exploited by EternalBlue (MS17-010) and WannaCry.
    Fix: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

High Findings (4):
  ✗ LSASS Protection [HIGH]
  ✗ LLMNR/NetBIOS [HIGH]
  ✗ Weak Ciphers [HIGH]
  ✗ TLS Versions [HIGH]

Compliance: ISO 27001: 74%  |  CIS Benchmarks: 68%  |  PCI DSS: 71%
```
