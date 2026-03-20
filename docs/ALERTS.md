# Alert Configuration Guide

## Overview

This document describes the 6 detection alerts created in 
Splunk based on real observations from the BOTS v3 dataset.
Each alert is mapped to a MITRE ATT&CK technique.

---

## How to Create an Alert in Splunk

1. Go to `http://localhost:8000`
2. Click **Search & Reporting**
3. Set time range to **All time**
4. Paste the SPL query
5. Click **Save As → Alert**
6. Fill in the configuration below
7. Click **Save**

---

## Alert 1 — T1134 SeTcbPrivilege Abuse

**Why this alert matters** : `RuntimeBroker.exe` and `explorer.exe` are user-space processes that should never request `SeTcbPrivilege`. This privilege allows acting as part of the operating system — only SYSTEM processes need it. Any user process requesting it indicates token abuse
or privilege escalation attempt.

**Configuration** : 
```
Title       : [T1134] SeTcbPrivilege Abuse by User Process
Severity    : Critical
Schedule    : Every 30 minutes
Time range  : Last 30 minutes
Trigger     : Number of results > 0
```
<img width="1804" height="253" alt="Capture d&#39;écran 2026-03-20 202125" src="https://github.com/user-attachments/assets/3317ae70-da8b-4ab6-af2c-fafe3f688331" />

**SPL Query** :
```spl
index=botsv3 sourcetype="WinEventLog" 
(EventCode=4672 OR EventCode=4673)
| eval process=lower(coalesce(Process_Name, process_name))
| where match(process, "runtimebroker\.exe|explorer\.exe")
| eval technique="T1134 - Access Token Manipulation"
| eval tactic="Privilege Escalation"
| eval severity="Critical"
| eval reason="User process abusing SeTcbPrivilege"
| table _time, host, Account_Name, process, 
  Keywords, reason, severity, technique
| sort -_time
```

**Results in BOTS v3** :  729 detections
<img width="1919" height="743" alt="Capture d&#39;écran 2026-03-20 202332" src="https://github.com/user-attachments/assets/5e0a4bf1-2b8a-4978-ad90-be35b9b1742b" />


---

## Alert 2 — T1055 Repeated Privilege Requests

**Why this alert matters** :
A burst of privilege requests from the same process in a short time window indicates active exploitation or token manipulation.
Normal processes request privileges once at startup, not repeatedly throughout execution.

**Configuration** : 
```
Title       : [T1055] Repeated Privilege Requests by User Process
Severity    : High
Schedule    : Every 30 minutes
Time range  : Last 30 minutes
Trigger     : Number of results > 0
```
<img width="1794" height="260" alt="Capture d&#39;écran 2026-03-20 201904" src="https://github.com/user-attachments/assets/6da88ed0-00d6-4bd7-99ba-e4b85c249796" />

**SPL Query** :
```spl
index=botsv3 sourcetype="WinEventLog" EventCode=4673
| eval process=lower(coalesce(Process_Name, process_name))
| where match(process, "explorer\.exe|runtimebroker\.exe")
| bucket _time span=5m
| stats count as priv_requests,
  values(Keywords) as privileges_used
  by host, Account_Name, process, _time
| where priv_requests > 5
| eval technique="T1055 - Process Injection"
| eval tactic="Privilege Escalation"
| eval severity="High"
| table _time, host, Account_Name, process, 
  priv_requests, privileges_used, severity, technique
| sort -priv_requests
```

**Results in BOTS v3** : 729 detections
<img width="1907" height="737" alt="Capture d&#39;écran 2026-03-20 202030" src="https://github.com/user-attachments/assets/4c5bbfdf-1ac8-4cf4-bd20-333c1a02fbb8" />

---

## Alert 3 — T1082 WMIC Reconnaissance

**Why this alert matters** :
WMIC (Windows Management Instrumentation Command) is a legitimate tool abused by attackers to collect system information silently. Commands like `os get LocalDateTime` or `computersystem get` are classic fingerprinting techniques used before lateral movement.

**Configuration** :
```
Title       : [T1082] System Reconnaissance via WMIC
Severity    : Medium
Schedule    : Every 60 minutes
Time range  : Last 60 minutes
Trigger     : Number of results > 0
```
<img width="1819" height="285" alt="Capture d&#39;écran 2026-03-20 201647" src="https://github.com/user-attachments/assets/9f94df1c-4091-48ac-b7f9-dfc7d85f6fb8" />

**SPL Query** : 
```spl
index=botsv3 sourcetype="WinEventLog" EventCode=4688
| eval process=lower(coalesce(Process_Name, process_name))
| eval cmdline=lower(coalesce(Process_Command_Line, CommandLine))
| where match(process, "wmic\.exe")
| eval technique="T1047/T1082 - WMI System Reconnaissance"
| eval tactic="Discovery"
| eval severity="Medium"
| table _time, host, Account_Name, process, 
  cmdline, severity, technique
| sort -_time
```

**Results in BOTS v3** : 536 detections
<img width="1911" height="737" alt="Capture d&#39;écran 2026-03-20 201813" src="https://github.com/user-attachments/assets/889a218b-435f-48f8-84ae-3858ac267334" />

---

## Alert 4 — T1049 Netstat Network Discovery

**Why this alert matters** : 
`netstat -nao` lists all active connections and listening ports.
Attackers use this to understand the network topology before moving laterally. This command is rarely used in normal business operations.

**Configuration** :
```
Title       : [T1049] Network Discovery via Netstat
Severity    : Medium
Schedule    : Every 60 minutes
Time range  : Last 60 minutes
Trigger     : Number of results > 0
```
<img width="1808" height="288" alt="Capture d&#39;écran 2026-03-20 201434" src="https://github.com/user-attachments/assets/2d1ffd09-b7db-4db5-9aee-d2762d700181" />

**SPL Query** : 
```spl
index=botsv3 sourcetype="WinEventLog" EventCode=4688
| eval process=lower(coalesce(Process_Name, process_name))
| eval cmdline=lower(coalesce(Process_Command_Line, CommandLine))
| where match(process, "netstat\.exe")
  OR (match(cmdline, "netstat") 
  AND match(cmdline, "-nao|-an|listening"))
| eval technique="T1049 - Network Connections Discovery"
| eval tactic="Discovery"
| eval severity="Medium"
| table _time, host, Account_Name, process, 
  cmdline, severity, technique
| sort -_time
```

**Results in BOTS v3** : 78 detections
<img width="1917" height="732" alt="Capture d&#39;écran 2026-03-20 201544" src="https://github.com/user-attachments/assets/31756506-9f54-4763-8736-a81b24cc9985" />

---

## Alert 5 — T1012 Registry Enumeration

**Why this alert matters** : 
Querying `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` lists all installed software. Attackers use this to identify vulnerable applications to exploit for privilege escalation or persistence.

**Configuration** : 
```
Title       : [T1012] Software Enumeration via Registry
Severity    : Medium
Schedule    : Every 60 minutes
Time range  : Last 60 minutes
Trigger     : Number of results > 0
```
<img width="1834" height="278" alt="Capture d&#39;écran 2026-03-20 201146" src="https://github.com/user-attachments/assets/fdb09335-83a5-4e6a-9da3-ee523f91ad41" />

**SPL Query** :
```spl
index=botsv3 sourcetype="WinEventLog" EventCode=4688
| eval process=lower(coalesce(Process_Name, process_name))
| eval cmdline=lower(coalesce(Process_Command_Line, CommandLine))
| where match(process, "reg\.exe|cmd\.exe")
  AND match(cmdline, "uninstall|currentversion")
| eval technique="T1012 - Query Registry"
| eval tactic="Discovery"
| eval severity="Medium"
| table _time, host, Account_Name, process, 
  cmdline, severity, technique
| sort -_time
```
**Results in BOTS v3** : 1,037 detections
<img width="1919" height="737" alt="Capture d&#39;écran 2026-03-20 200856" src="https://github.com/user-attachments/assets/2d0ab743-0ff2-4c95-b2b6-2db45a722850" />

---

## Alert 6 — T1059 Process Creation Burst

**Why this alert matters** : 
More than 20 process creations per minute from a single host is abnormal in a business environment. This pattern indicates possible malware automation, scripted attacks, or lateral movement tools running on the compromised machine.

**Configuration** :
```
Title       : [T1059] Abnormal Process Creation Burst
Severity    : High
Schedule    : Every 15 minutes (cron: */15 * * * *)
Time range  : Last 15 minutes
Trigger     : Number of results > 0
```
<img width="1813" height="298" alt="Capture d&#39;écran 2026-03-20 201218" src="https://github.com/user-attachments/assets/75a01a5b-a8d4-4dc0-9d9b-9b96d8ff84a8" />

**SPL Query** : 
```spl
index=botsv3 sourcetype="WinEventLog" EventCode=4688
| bucket _time span=1m
| stats count as process_count,
  dc(Process_Name) as unique_processes,
  values(Process_Name) as processes_launched
  by host, Account_Name, _time
| where process_count > 20
| eval risk=case(
    process_count > 100, "Critical - Possible Malware",
    process_count > 50,  "High - Abnormal Burst",
    true(),              "Medium - Elevated Activity")
| eval technique="T1059/T1106 - Mass Process Creation"
| eval tactic="Execution"
| table _time, host, Account_Name, process_count,
  unique_processes, risk, technique
| sort -process_count
```
<img width="1919" height="736" alt="Capture d&#39;écran 2026-03-20 201301" src="https://github.com/user-attachments/assets/5383ae23-e37c-4527-b0ea-7402d52bac56" />

**Results in BOTS v3** : 7,724 detections

---

## Alerts Summary

| Alert | Technique | Detections | Severity | Schedule |
|-------|-----------|------------|----------|----------|
| T1134 SeTcbPrivilege | T1134 | 729 | Critical | 30 min |
| T1055 Priv Requests | T1055 | 729 | High | 30 min |
| T1082 WMIC Recon | T1082 | 536 | Medium | 60 min |
| T1049 Netstat | T1049 | 78 | Medium | 60 min |
| T1012 Registry | T1012 | 1037 | Medium | 60 min |
| T1059 Process Burst | T1059 | 7724 | High | 15 min |
