# Dashboard Configuration Guide

## Overview

Two dashboards were created in Splunk to visualize the detection results and ATT&CK coverage.

---

## How to Create a Dashboard in Splunk

1. Go to `http://localhost:8000`
2. Click **Dashboards** in the top menu
3. Click **Create New Dashboard**
4. Choose **Classic Dashboard**
5. Add panels using **Add Panel → New → Search**
6. Paste the SPL query for each panel
7. Choose the visualization type
8. Click **Save**

---

## Dashboard 1 — SOC Lab Threat Overview

**Purpose** : Give a complete overview of all suspicious activities detected in the environment.

![SOC Overview](../screenshots/dashboard-soc-overview.png)

### Panel 1 — Detections by ATT&CK Technique
**Visualization** : Bar Chart
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| eval technique=case(
    (EventCode=4672 OR EventCode=4673) AND 
    match(lower(coalesce(Process_Name,process_name)), 
    "runtimebroker|explorer"), 
    "T1134 - Token Abuse",
    EventCode=4688 AND 
    match(lower(coalesce(Process_Name,process_name)),"wmic"), 
    "T1082 - WMIC Recon",
    EventCode=4688 AND 
    match(lower(coalesce(Process_Name,process_name)),"netstat"), 
    "T1049 - Netstat Recon",
    EventCode=4688 AND 
    match(lower(coalesce(Process_Command_Line,CommandLine,"")),
    "uninstall|currentversion"), 
    "T1012 - Registry Enum",
    EventCode=4688, 
    "T1059 - Process Execution",
    true(), "Other")
| where technique!="Other"
| stats count by technique
| sort -count
```

### Panel 2 — Suspicious Events Timeline
**Visualization** : Line Chart
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| timechart span=1h count by EventCode
```

### Panel 3 — Top Affected Hosts
**Visualization** : Bar Chart
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| stats count by host
| sort -count
| head 10
```

### Panel 4 — Top Suspicious Users
**Visualization** : Table
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| stats count by Account_Name
| sort -count
| where Account_Name!="SYSTEM" 
  AND Account_Name!="LOCAL SERVICE"
  AND Account_Name!="-"
| head 10
```

### Panel 5 — Alerts by Severity
**Visualization** : Pie Chart
```spl
index=botsv3 sourcetype="WinEventLog"
(EventCode=4672 OR EventCode=4673 OR EventCode=4688)
| eval severity=case(
    (EventCode=4672 OR EventCode=4673), "Critical",
    EventCode=4688 AND 
    match(lower(coalesce(Process_Name,process_name)),
    "wmic|netstat"), "Medium",
    EventCode=4688, "High",
    true(), "Low")
| stats count by severity
```

---

## Dashboard 2 — MITRE ATT&CK Coverage

**Purpose** : Show which ATT&CK techniques are covered by the detection rules and visualize coverage gaps.

![MITRE Coverage](../screenshots/dashboard-mitre-coverage.png)

### Panel 1 — ATT&CK Technique Coverage Table
**Visualization** : Table
```spl
| makeresults
| eval data=split(
"T1134:Privilege Escalation:Token Manipulation:729:Critical,
T1055:Privilege Escalation:Process Injection:729:High,
T1082:Discovery:System Info Discovery:536:Medium,
T1049:Discovery:Network Connections:78:Medium,
T1012:Discovery:Query Registry:1037:Medium,
T1059:Execution:Command Scripting:7724:High", ",")
| mvexpand data
| eval technique_id=mvindex(split(data,":"),0)
| eval tactic=mvindex(split(data,":"),1)
| eval technique_name=mvindex(split(data,":"),2)
| eval detections=mvindex(split(data,":"),3)
| eval severity=mvindex(split(data,":"),4)
| eval status="Covered"
| table tactic, technique_id, technique_name, 
  detections, severity, status
| sort tactic
```

### Panel 2 — Rules Coverage by Tactic
**Visualization** : Bar Chart
```spl
| makeresults
| eval data=split(
"Privilege Escalation:2,Discovery:3,Execution:1", ",")
| mvexpand data
| eval tactic=mvindex(split(data,":"),0)
| eval rules_count=mvindex(split(data,":"),1)
| table tactic, rules_count
```

### Panel 3 — Detection Volume by Tactic
**Visualization** : Pie Chart
```spl
| makeresults
| eval data=split(
"Privilege Escalation:1458,Discovery:1651,Execution:7724",",")
| mvexpand data
| eval tactic=mvindex(split(data,":"),0)
| eval total_detections=mvindex(split(data,":"),1)
| table tactic, total_detections
| sort -total_detections
```