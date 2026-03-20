# Case Study 2 — E-Commerce Platform CIS Benchmarks Assessment

**Sector:** E-Commerce (online retail)
**Environment:** 8 Windows servers (mix of Server 2019 and Server 2022) running IIS, SQL Server, and file services
**Objective:** CIS Benchmarks Level 1 assessment ahead of PCI DSS re-certification
**Timeline:** 3-day assessment

---

## Background

An online retail company processing approximately €2M/month in card transactions was due for their annual PCI DSS assessment. Their payment processing infrastructure ran on Windows Server IIS and SQL Server. Their previous QSA (Qualified Security Assessor) had flagged weak TLS configuration and insufficient access controls as open findings from the prior year.

The team needed to:

1. Verify that last year's open findings had been remediated
2. Identify any new gaps introduced by recent infrastructure changes (new IIS server deployed 3 months prior)
3. Produce evidence for the upcoming PCI DSS re-assessment

---

## Challenge

The team had applied fixes manually after the previous QSA assessment but had not re-tested systematically. A new IIS server added to handle peak season traffic had been provisioned from a base image that had not been reviewed against the security baseline. They suspected the new server might have gaps.

---

## Approach

**Day 1 — Discovery scan (all 8 servers)**

```bash
# Scan all servers without AI (fast baseline)
for server in web01 web02 web03 iis-new sql01 sql02 fs01 fs02; do
    python auditor.py scan \
      --target $server \
      --username "RETAIL\svc-sec" \
      --password $WINRM_PASSWORD \
      --output "scans/${server}_baseline.json"
done
```

**Day 2 — Deep analysis with AI recommendations**

```bash
# Generate reports with Claude recommendations for servers with FAIL findings
for server in web01 iis-new sql01; do
    python auditor.py report \
      --input "scans/${server}_baseline.json" \
      --output "reports/${server}_report.html"
done
```

**Day 3 — Remediation verification re-scan**

Re-ran scans on the 3 servers with the highest risk scores after applying fixes.

---

## Findings: New IIS Server (iis-new) — Before Remediation

The new server provisioned 3 months prior had the most concerning findings:

| Check | Status | Severity |
|---|---|---|
| SMBv1 Protocol | PASS | — |
| TLS Versions | **FAIL** | HIGH |
| Weak Ciphers | **FAIL** | HIGH |
| LSASS Protection | **FAIL** | HIGH |
| RDP NLA | **FAIL** | HIGH |
| Windows Defender | **FAIL** | HIGH |
| LLMNR/NetBIOS | **FAIL** | HIGH |
| Firewall Status | PASS | — |
| Password Policies | **FAIL** | MEDIUM |
| Windows Update | **FAIL** | MEDIUM |
| Event Log Config | PASS | — |
| Admin Accounts | **FAIL** | HIGH |
| Privilege Creep | PASS | — |
| File Sharing | PASS | — |
| Installed Software | PASS | — |

**Risk score: 8.1 / 10 (HIGH)**

The Windows Defender finding was unexpected — the AV definitions were 31 days old. The server had been provisioned without a WSUS connection, meaning signatures had never updated.

---

## Comparison: Existing Servers vs. New Server

| Check | web01 (existing) | iis-new (new server) |
|---|---|---|
| TLS Versions | PASS ✓ | FAIL ✗ |
| Weak Ciphers | PASS ✓ | FAIL ✗ |
| LSASS Protection | PASS ✓ | FAIL ✗ |
| Windows Defender | PASS ✓ | FAIL ✗ (31d old) |
| LLMNR/NetBIOS | PASS ✓ | FAIL ✗ |

This confirmed the new server had been provisioned without applying the security baseline used for existing servers. The provisioning runbook was missing the post-build hardening steps.

---

## PCI DSS Compliance Results

| Requirement | iis-new (before) | iis-new (after) | web01 (existing) |
|---|---|---|---|
| Req 1 — Network protection | 75% | 100% | 100% |
| Req 4 — Encryption in transit | 62% | 95% | 95% |
| Req 5 — Anti-malware | 60% | 100% | 100% |
| Req 6 — Vulnerability management | 70% | 88% | 88% |
| Req 8 — Identity management | 65% | 90% | 90% |
| Req 10 — Logging & monitoring | 80% | 80% | 88% |
| **Overall PCI DSS** | **68%** | **92%** | **93%** |

---

## Remediation Actions

AI-generated recommendations (Claude) for `iis-new`:

**Immediate:**
```powershell
# Enable Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Update AV signatures
Update-MpSignature

# Enable NLA for RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name UserAuthentication -Value 1
```

**Within 24 hours:**
```powershell
# Enable LSASS RunAsPPL
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
  -Name RunAsPPL -Value 1
# (requires reboot)

# Disable LLMNR (via GPO or registry)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
  -Name EnableMulticast -Value 0
```

**Within 1 week:**
- Apply IIS Crypto to disable TLS 1.0, TLS 1.1, SSL 2.0/3.0
- Disable RC4, DES, 3DES via IIS Crypto
- Connect server to WSUS for ongoing patch management
- Tighten local Administrator group membership

---

## Results After Remediation

**iis-new — Day 3 re-scan:**

- Risk score: 8.1 → **1.4 / 10 (MINIMAL)**
- PCI DSS compliance: 68% → **92%**
- All HIGH severity findings resolved
- Windows Defender definitions: 31 days old → **current**

**Fleet summary (all 8 servers after remediation):**

- Maximum risk score: 1.8 / 10
- Average risk score: 0.9 / 10
- Zero CRITICAL or HIGH findings remaining

---

## Key Outcome

The assessment uncovered that the server provisioning process had no security hardening checklist for new builds. As a direct result, the team:

1. Created a formal **Windows Server Build Standard** document incorporating all checks from the auditor
2. Added the auditor scan to the **server commissioning checklist** — new servers must achieve risk score < 2.0 before going live
3. Scheduled **monthly automated scans** on all payment-zone servers with reports sent to the CISO

The PCI DSS re-assessment passed without any findings related to the previously open TLS and access control gaps.

---

## Lessons Learned

- New servers provisioned without a security baseline scan are a recurring risk — automate baseline checks before go-live
- AV signature age is an often-overlooked check — `Get-MpComputerStatus` should be part of every operations runbook
- Comparing existing vs. new server reports side-by-side instantly revealed build consistency issues
- 3-day assessment timeline was achievable because scanning was fully automated (vs. estimated 1 week manual)
