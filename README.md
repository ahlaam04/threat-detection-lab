# Threat Detection Engineering Lab
### Splunk SIEM × MITRE ATT&CK Framework

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

##  Dataset — Boss of the SOC v3 (BOTS v3)

### What is BOTS v3 ?

**Boss of the SOC (BOTS) v3** is a professional grade attack simulation dataset created by **Splunk**. It was originally used in the Splunk .conf2018 Security competition.

### What does it simulate ?

The dataset simulates a **real cyberattack against a fictional company called Frothly** a craft beer company with a hybrid 
infrastructure (on-premise Windows machines + AWS cloud).

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
<img width="1908" height="655" alt="image" src="https://github.com/user-attachments/assets/cc90b67b-fd3f-44cd-b513-5286bfc3d5f8" />

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
<img width="1919" height="738" alt="image" src="https://github.com/user-attachments/assets/28f15e13-c632-4e8d-a58e-48b366951358" />


**What I found** :
- 2,000,000+ events across 15+ data sources
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
<img width="1919" height="739" alt="image" src="https://github.com/user-attachments/assets/2453f0d7-eb81-413c-9cdf-ace4627f7b45" />


**What I found** :

| Host | Event Count | Suspicion Level |
|------|-------------|-----------------|
| BSTOLL-L | Highest | 🔴 Very High |
| BGIST-L | High | 🟠 High |
| MKRAEUS-L | Medium | 🟡 Medium |
| PCERF-L | Medium | 🟡 Medium |

**Key observation** :
BSTOLL-L generated significantly more events than any other machine, this became my primary investigation target.
<img width="1400" height="727" alt="image" src="https://github.com/user-attachments/assets/6d97f8fe-1475-4296-ab49-dc82051f06ab" />



### Step 3 — Analyzing Windows Event Codes

**Query used** :
```spl
index=botsv3 sourcetype="WinEventLog"
| stats count by EventCode
| sort -count
```
<img width="1596" height="521" alt="image" src="https://github.com/user-attachments/assets/842ec4c6-5de4-43da-a2e7-ed2379d48246" />


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
<img width="927" height="518" alt="image" src="https://github.com/user-attachments/assets/a011ea16-47a9-45b2-adfa-fe6f112e7eff" />


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
<img width="1919" height="718" alt="image" src="https://github.com/user-attachments/assets/7e6fd8c9-f0c6-45da-85dc-1d8102f69d60" />

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
<img width="1918" height="718" alt="image" src="https://github.com/user-attachments/assets/c515f858-6b4a-45d6-8851-0dc2baa7a443" />

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

During the investigation of BOTS v3 logs, I identified the following suspicious behaviors :

### Finding 1 — Privilege Abuse (Critical)
**Host** : Multiple Windows machines
**Observation** :  `RuntimeBroker.exe` and `explorer.exe` using `SeTcbPrivilege`  a critical Windows privilege normally reserved for SYSTEM-level processes only.
**Volume** :729 occurrences
**Why suspicious** : These are user-space processes that 
should never need this privilege level.

<img width="1915" height="418" alt="Capture d&#39;écran 2026-03-19 181718" src="https://github.com/user-attachments/assets/7018fdda-e7b2-41d1-8a0c-890eaf2f0bcb" />


### Finding 2 — Massive Registry Enumeration (Medium)
**Host** :  Multiple machines
**Observation** : `reg.exe` and `cmd.exe` querying Uninstall keys to enumerate installed software.
**Volume** :  1,037 occurrences
**Why suspicious** : Attackers enumerate installed software to identify vulnerable applications.
<img width="1918" height="640" alt="Capture d&#39;écran 2026-03-19 181004" src="https://github.com/user-attachments/assets/4dc86745-5770-4ae7-aadd-2be0b5a6f066" />


### Finding 3 — Abnormal Process Creation Burst (High)
**Host** : Multiple machines
**Observation** : Over 1,000 process creation events with bursts exceeding 20 processes per minute.
**Why suspicious** : Indicates possible automation, malware activity, or scripted execution.
<img width="1917" height="732" alt="Capture d&#39;écran 2026-03-19 180227" src="https://github.com/user-attachments/assets/0497c97c-3e27-4afc-b282-22b06d616da2" />


### Finding 4 — WMIC System Reconnaissance (Medium)
**Volume** : 536 occurrences
**Why suspicious** :  WMIC used for system fingerprinting  collecting OS version, hardware info, local datetime.
<img width="1917" height="119" alt="Capture d&#39;écran 2026-03-19 180802" src="https://github.com/user-attachments/assets/17d3cf96-f438-4cb4-9553-58be045d59ef" />


### Finding 5 — Netstat Network Discovery (Medium)
**Volume** : 78 occurrences
**Why suspicious** : Local port scanning to identify active connections and listening services.
<img width="1917" height="99" alt="Capture d&#39;écran 2026-03-19 180852" src="https://github.com/user-attachments/assets/b35b88b0-91cf-4220-b7ae-c1a96c643584" />


---

## ️ MITRE ATT&CK Coverage

| Tactic | ID | Technique | Detections | Severity | Status |
|--------|----|-----------|------------|----------|--------|
| Privilege Escalation | T1134 | Access Token Manipulation | 729 | Critical | ✅ |
| Privilege Escalation | T1055 | Process Injection | 729 | High | ✅ |
| Discovery | T1082 | System Information Discovery | 536 | Medium | ✅ |
| Discovery | T1049 | Network Connections Discovery | 78 | Medium | ✅ |
| Discovery | T1012 | Query Registry | 1037 | Medium | ✅ |
| Execution | T1059 | Command and Scripting | 7724 | High | ✅ |

---

##  SOC Dashboards

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


### Dashboard 2 — MITRE ATT&CK Coverage
Panels included :
- ATT&CK Technique Coverage Table
<img width="935" height="248" alt="Capture d&#39;écran 2026-03-19 232450" src="https://github.com/user-attachments/assets/ef4118d5-f9bf-4b09-9530-f5712176cf2a" />

- Rules Coverage by Tactic (Bar Chart)
<img width="949" height="179" alt="Capture d&#39;écran 2026-03-19 232621" src="https://github.com/user-attachments/assets/169a7b77-9c13-4e38-8d54-dc09fc02d5e6" />

- Detection Volume by Tactic (Pie Chart)
<img width="575" height="173" alt="Capture d&#39;écran 2026-03-19 232648" src="https://github.com/user-attachments/assets/2a03e802-07c7-4a87-a619-22cec3352171" />

---

##  Detection Rules

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

##  Setup & Configuration

- [Installation Guide](docs/INSTALL.md)
- [Alert Configuration](docs/ALERTS.md)
- [Dashboard Configuration](docs/DASHBOARDS.md)

---

##  Key Lessons Learned

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

## Tools Used

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
✅ 6 detection rules created and documented
✅ 2 SOC dashboards built
✅ Full GitHub documentation
🔄 Investigation section in progress
⬜ MITRE ATT&CK Navigator export
⬜ Additional detection rules
⬜ Sigma rules conversion
⬜ Incident response playbooks
```

### Why this project exists

This lab was built to :
- Learn detection engineering from real attack data
- Understand how attackers operate across the kill chain
- Practice writing SPL queries based on real observations
- Build a portfolio that demonstrates SOC analyst skills

Every time I learn something new a new technique, a new tool, a new concept, I come back to this lab and add it. This makes it a growing reference rather than a one-time exercise.

### What's coming next
- More detection rules based on other BOTS v3 findings
- Sigma rules format for each detection
- Incident response playbook for each alert
- MITRE ATT&CK Navigator coverage map export


## 👤 Author

**Ahlam Boumehdi**
Cybersecurity Engineering Student
LinkedIn : www.linkedin.com/in/ahlam-boumehdi
