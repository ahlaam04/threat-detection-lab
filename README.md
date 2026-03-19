# Threat Detection Engineering Lab
### Splunk SIEM × MITRE ATT&CK Framework

---

## Project Objective

The goal of this project is to simulate a real SOC analyst 
and Detection Engineer workflow :

- Analyze real attack logs from a simulated enterprise breach
- Identify suspicious behaviors and map them to MITRE ATT&CK
- Build detection rules (SPL queries) based on real observations
- Create professional SOC dashboards for threat visibility
- Document findings in a structured and reproducible way

This project demonstrates end-to-end detection engineering skills :
from raw log analysis to actionable alerts mapped to a threat framework.

---

##  Dataset — Boss of the SOC v3 (BOTS v3)

### What is BOTS v3 ?

**Boss of the SOC (BOTS) v3** is a professional-grade attack 
simulation dataset created by **Splunk**. It was originally 
used in the Splunk .conf2018 Security competition.

### What does it simulate ?

The dataset simulates a **real cyberattack against a fictional 
company called Frothly** — a craft beer company with a hybrid 
infrastructure (on-premise Windows machines + AWS cloud).

The simulated attack covers a full kill chain :
```
Phase 1 → Initial Reconnaissance
          Attacker gathers information about the target

Phase 2 → Initial Access
          Phishing email or exploitation to gain first foothold

Phase 3 → Execution
          Malicious code executed on compromised machines

Phase 4 → Privilege Escalation
          Attacker gains higher privileges (SYSTEM level)

Phase 5 → Discovery
          Internal reconnaissance — network, software, users

Phase 6 → Lateral Movement
          Moving from machine to machine inside the network

Phase 7 → Exfiltration
          Sensitive data stolen from the compromised environment
```

### Infrastructure simulated
```
On-Premise Windows machines :
  BSTOLL-L    → Most active machine (6387 DNS queries)
  BGIST-L     → Windows workstation
  MKRAEUS-L   → MalloryKraeusen's workstation
  PCERF-L     → Windows workstation
  FYODOR-L    → Windows workstation

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

---

## ️ Lab Architecture
```
Kali Linux
│
├── Splunk Enterprise 10.2 (localhost:8000)
│     │
│     ├── BOTS v3 Dataset (300,000+ events / Aug 2018)
│     │     ├── Windows Security Logs (EventCode 4688/4672/4673)
│     │     ├── DNS Logs (stream:dns)
│     │     ├── Network Logs (stream:ip / stream:tcp)
│     │     └── AWS CloudTrail Logs
│     │
│     ├── 6 Custom SPL Detection Rules
│     ├── 6 Scheduled Alerts (15-60 min intervals)
│     └── 2 SOC Dashboards
│
└── GitHub Documentation
      ├── Detection rules (YAML format)
      ├── Alert configurations
      └── Dashboard configurations
```

---

##  Investigation & Identification

Before writing any detection rule, I followed a structured 
investigation process :
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
Before looking for attacks, I first mapped the environment
to understand what I was working with.

**Query used** :
```spl
index=botsv3 | stats count by sourcetype | sort -count
```


**What I found** :
- 300,000+ events across 15+ data sources
- Mix of Windows endpoints, Linux servers, and AWS cloud
- Data covering a full attack scenario from August 2018

**Key observation** :
The dataset contains logs from a hybrid infrastructure on-premise Windows machines AND AWS cloud services.
This means the attacker had to compromise both environments.

### Step 2 — Identifying Suspicious Hosts

**Query used** :
```spl
index=botsv3 | stats count by host | sort -count
```

**What I found** :

| Host | Event Count | Suspicion Level |
|------|-------------|-----------------|
| BSTOLL-L | Highest | 🔴 Very High |
| BGIST-L | High | 🟠 High |
| MKRAEUS-L | Medium | 🟡 Medium |
| PCERF-L | Medium | 🟡 Medium |

**Key observation** :
BSTOLL-L generated significantly more events than any other machine — this became my primary investigation target.

### Step 3 — Analyzing Windows Event Codes

**Query used** :
```spl
index=botsv3 sourcetype="WinEventLog"
| stats count by EventCode
| sort -count
```

**What I found** :

| EventCode | Count | Meaning |
|-----------|-------|---------|
| 4689 | 23,885 | Process terminated |
| 4688 | 2,419 | Process created |
| 4672 | 8,497 | Special privileges assigned |
| 4673 | 1,120 | Privileged service called |
| 5156 | 2,256 | Network connection allowed |

**Key observation** :
EventCode 4672 (Special Privileges) appeared 8,497 times abnormally high. This was my first real indicator of privilege abuse.

### Step 4 — Identifying Suspicious Processes

After noticing the high volume of privilege events, I investigated which processes were responsible.

**Query used** :
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673)
| eval process=lower(coalesce(Process_Name, process_name))
| stats count by process, host
| sort -count
```

**Key finding — The smoking gun** :
`RuntimeBroker.exe` and `explorer.exe` were the top processes requesting critical privileges.

**Why this is suspicious** :
- `RuntimeBroker.exe` is a Windows process that manages permissions for apps from the Microsoft Store. It should NEVER need SeTcbPrivilege.
- `explorer.exe` is the Windows file manager/desktop. Same it has no legitimate reason to request operating system level privileges.

This was the clearest indicator of compromise found during the investigation.

### Step 5 — Confirming with Timeline Analysis

To understand when the attack happened, I analyzed the event timeline.

**Query used** :
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| timechart span=1h count by EventCode
```

**What I found** :
- Attack activity concentrated between 03:00 and 12:00 AM
  on August 20, 2018
- Multiple EventCodes spiking simultaneously across
  different machines
- This simultaneous pattern suggests an attacker
  controlling multiple machines at the same time

**Key observation** :
The synchronized spikes across different hosts indicate lateral movement  the attacker had already compromised multiple machines and was executing commands on all of them simultaneously.

### Step 6 — False Positive Analysis

During investigation I discovered an important lesson about false positives.

**The EventCode 4625 case** :
When I searched for failed logins (EventCode 4625), I found events in TWO different log sources :

| Source | EventCode 4625 | Meaning |
|--------|----------------|---------|
| WinEventLog:Security | Real auth failure | ✅ Relevant |
| WinEventLog:Application | System message | ❌ False positive |

The Application log EventCode 4625 is generated by the Windows EventSystem service suppressing duplicate log entries completely unrelated to authentication.

**Lesson learned** :
Always filter by `source="WinEventLog:Security"` when looking for authentication failures. The same EventCode can have completely different meanings depending on the log source.

---

##  Key Findings

During the investigation of BOTS v3 logs, I identified 
the following suspicious behaviors :

### Finding 1 — Privilege Abuse (Critical)
**Host** : Multiple Windows machines
**Observation** :  `RuntimeBroker.exe` and `explorer.exe` 
using `SeTcbPrivilege`  a critical Windows privilege 
normally reserved for SYSTEM-level processes only.
**Volume** :729 occurrences
**Why suspicious** : These are user-space processes that 
should never need this privilege level.

### Finding 2 — Massive Registry Enumeration (Medium)
**Host** :  Multiple machines
**Observation** : `reg.exe` and `cmd.exe` querying 
Uninstall keys to enumerate installed software.
**Volume** :  1,037 occurrences
**Why suspicious** : Attackers enumerate installed software to identify vulnerable applications.

### Finding 3 — Abnormal Process Creation Burst (High)
**Host** : Multiple machines
**Observation** : Over 7,724 process creation events 
with bursts exceeding 20 processes per minute.
**Why suspicious** : Indicates possible automation, 
malware activity, or scripted execution.

### Finding 4 — WMIC System Reconnaissance (Medium)
**Volume** : 536 occurrences
**Why suspicious** :  WMIC used for system fingerprinting  collecting OS version, hardware info, local datetime.

### Finding 5 — Netstat Network Discovery (Medium)
**Volume** : 78 occurrences
**Why suspicious** : Local port scanning to identify active connections and listening services.

---

## ️ MITRE ATT&CK Coverage

![Dashboard](screenshots/dashboard-mitre-coverage.png)

| Tactic | ID | Technique | Detections | Severity | Status |
|--------|----|-----------|------------|----------|--------|
| Privilege Escalation | T1134 | Access Token Manipulation | 729 | Critical | ✅ |
| Privilege Escalation | T1055 | Process Injection | 729 | High | ✅ |
| Discovery | T1082 | System Information Discovery | 536 | Medium | ✅ |
| Discovery | T1049 | Network Connections Discovery | 78 | Medium | ✅ |
| Discovery | T1012 | Query Registry | 1037 | Medium | ✅ |
| Execution | T1059 | Command and Scripting | 7724 | High | ✅ |

---

## 📊 SOC Dashboards

### Dashboard 1 — SOC Threat Overview
![SOC Overview](screenshots/dashboard-soc-overview.png)

Panels included :
- Detections by ATT&CK Technique (Bar Chart)
- Suspicious Events Timeline (Line Chart)
- Top Affected Hosts (Bar Chart)
- Top Suspicious Users (Table)
- Alerts by Severity (Pie Chart)

### Dashboard 2 — MITRE ATT&CK Coverage
![MITRE Coverage](screenshots/dashboard-mitre-coverage.png)

Panels included :
- ATT&CK Technique Coverage Table
- Rules Coverage by Tactic (Bar Chart)
- Detection Volume by Tactic (Pie Chart)

---

## ⚙️ Detection Rules

See [detections/](detections/) folder for all YAML-documented rules.

| File | Technique | Description |
|------|-----------|-------------|
| T1134-token-abuse.yml | T1134 | SeTcbPrivilege abuse |
| T1055-process-injection.yml | T1055 | Token manipulation |
| T1082-wmic-recon.yml | T1082 | WMIC reconnaissance |
| T1049-netstat-recon.yml | T1049 | Network discovery |
| T1012-registry-enum.yml | T1012 | Registry enumeration |
| T1059-process-burst.yml | T1059 | Process creation burst |

---

## 🔧 Setup & Configuration

- [Installation Guide](docs/INSTALL.md)
- [Alert Configuration](docs/ALERTS.md)
- [Dashboard Configuration](docs/DASHBOARDS.md)

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

## 👤 Author

**Ahlam Boumehdi**
Cybersecurity Student | Security Enthusiast
LinkedIn : www.linkedin.com/in/ahlam-boumehdi