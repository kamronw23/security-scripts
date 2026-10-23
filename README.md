# 🛡️ security-scripts

Defensive security tools I wrote to automate everyday **SOC analyst** tasks: log triage, brute-force detection, phishing analysis, IOC extraction, file integrity monitoring, and exposure checks.

Every Python script uses **only the standard library** (Python 3.8+, nothing to `pip install`), and most of them ship with sample data, so you can clone the repo and see results in seconds.

> ⚠️ **Ethical use:** These tools are for learning and for defending systems you own or are authorized to test. Don't scan or probe anything you don't have permission to touch.

---

## 📂 Tools

| Folder | Script | What it does | MITRE ATT&CK |
|---|---|---|---|
| `log-analysis/` | [`ssh_bruteforce_detector.py`](log-analysis/ssh_bruteforce_detector.py) | Parses Linux `auth.log`, ranks IPs by failed SSH logins, and raises a **CRITICAL** alert when a login *succeeds* after failures | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| `log-analysis/` | [`Get-FailedLogons.ps1`](log-analysis/Get-FailedLogons.ps1) | Summarizes Windows **Event ID 4625** by source IP and account, decodes failure reasons, and flags spraying patterns | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| `phishing/` | [`email_header_analyzer.py`](phishing/email_header_analyzer.py) | Triages a reported `.eml`: SPF/DKIM/DMARC, From/Reply-To mismatches, hop chain, lookalike domains, risky attachments, risk score | [T1566](https://attack.mitre.org/techniques/T1566/) Phishing |
| `threat-intel/` | [`ioc_extractor.py`](threat-intel/ioc_extractor.py) | Extracts IPs, domains, URLs, emails, hashes, and CVEs from any text; handles defanged input; outputs defanged text or JSON | n/a (supports investigation) |
| `integrity/` | [`file_integrity_monitor.py`](integrity/file_integrity_monitor.py) | SHA-256 baseline of a directory, then detects added, removed, and modified files and permission changes | [T1565.001](https://attack.mitre.org/techniques/T1565/001/), [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| `password/` | [`password_audit.py`](password/password_audit.py) | Scores password strength and checks Have I Been Pwned using **k-anonymity** (the password never leaves your machine) | [T1110](https://attack.mitre.org/techniques/T1110/) (prevention) |
| `network/` | [`port_scanner.py`](network/port_scanner.py) | Multithreaded TCP connect scanner with banner grabbing that flags risky services (SMB, RDP, Telnet…) on **your own** lab hosts | [T1046](https://attack.mitre.org/techniques/T1046/) (seen from the defender's side) |

---

## 🚀 Quick Start

```bash
git clone https://github.com/kamronw23/security-scripts.git
cd security-scripts
```

### 1. Detect SSH brute force
```bash
python3 log-analysis/ssh_bruteforce_detector.py log-analysis/sample_auth.log
```
```
[CRITICAL] 198.51.100.23: 8 failures, 1 usernames tried (Oct 21 03:22:00 -> Oct 21 03:22:35)
         users: kamron
         !!! SUCCESSFUL LOGIN after failures: kamron @ Oct 21 03:22:50  -> investigate now
[HIGH] 203.0.113.45: 24 failures, 8 usernames tried (Oct 21 02:10:00 -> Oct 21 02:12:41)
         users: admin, guest, oracle, pi, postgres, root, test, ubuntu
```

### 2. Triage a phishing email
```bash
python3 phishing/email_header_analyzer.py phishing/sample_phish.eml
```
```
[Authentication]
  [BAD] SPF   = softfail
  [BAD] DKIM  = none
  [BAD] DMARC = fail
...
[Findings] risk score 20 -> LIKELY PHISHING
  !!! Risky attachment type: Account_Statement.html
  !!! Reply-To domain (protonmail.com) differs from From domain (paypa1-support.com): replies go elsewhere
  !!! Display name mentions 'paypal' but sender domain is paypa1-support.com
```

### 3. Pull IOCs out of that same email
```bash
python3 threat-intel/ioc_extractor.py phishing/sample_phish.eml --defang
python3 threat-intel/ioc_extractor.py phishing/sample_phish.eml --json > iocs.json
```

### 4. Monitor file integrity
```bash
python3 integrity/file_integrity_monitor.py baseline /etc/ssh
python3 integrity/file_integrity_monitor.py check /etc/ssh
```
```
[!] Integrity changes detected since 2026-10-23T12:25:16:
    MODIFIED     sshd_config
    ADDED        shell.php
    PERMISSIONS  index.php (0o644 -> 0o777)
```

### 5. Audit a password
```bash
python3 password/password_audit.py
```

### 6. Scan your own lab VM
```bash
python3 network/port_scanner.py 192.168.56.101 -p 1-1024
```

### 7. Windows failed logons (elevated PowerShell)
```powershell
.\log-analysis\Get-FailedLogons.ps1 -Hours 48 -Threshold 10 -CsvPath .\failed_logons.csv
```

---

## 🧠 What I Learned Building These

- **Logs tell a story:** one failed login is noise, 24 from one IP is an attack, and a *success* afterwards is an incident. Severity has to reflect that.
- **Email authentication is layered.** SPF, DKIM, and DMARC each catch different things, and display-name spoofing gets past users who only glance at the sender name.
- **Defanging matters.** IOCs pasted into tickets and chat should never be clickable.
- **Baselines are everything.** You can't detect change without a known-good state, which is the core idea behind FIM and EDR.
- **Privacy-preserving design:** k-anonymity lets you check a password against breach data without disclosing it.

## 🗺️ Roadmap

- [ ] Send output to a SIEM (Splunk / Elastic) as JSON
- [ ] VirusTotal / AbuseIPDB enrichment for extracted IOCs (API key via environment variable)
- [ ] Sysmon log parser for suspicious process creation (Event ID 1)
- [ ] Unit tests with `pytest` and a GitHub Actions workflow

---

Part of my [cybersecurity portfolio](https://github.com/kamronw23/Portfolio) · Built by **Kam'ron Washington**, CompTIA Security+ · Network+ · Linux+
