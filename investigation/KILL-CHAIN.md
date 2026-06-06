## Complete Attack Timeline

| Time | Host | Event | MITRE |
|------|------|-------|-------|
| 07:05 | HOTH | First OGNL POST to saveGangster.action | T1190 |
| 07:05-07:34 | HOTH | RCE commands : cat /etc/passwd, sudo bash | T1059.004 |
| ~07:34 | HOTH | Reverse shell established via /tmp/backpipe | T1071.001 |
| ~22:00 | FYODOR-L | PowerShell obfuscated -enc executed | T1059.001 |
| ~22:00 | FYODOR-L | AMSI bypass + RC4 payload downloaded | T1562.001 |
| ~22:00 | FYODOR-L | iexeplorer.exe dropped in Temp | T1036 |
| ~22:00 | FYODOR-L | Registry modified for UAC bypass | T1112 |
| ~22:00 | FYODOR-L | fodhelper.exe launched → UAC bypassed | T1548.002 |
| 22:08:17 | FYODOR-L | svcvnc account created (EventCode 4720) | T1136.001 |
| 22:08:17 | FYODOR-L | svcvnc added to Users (EventCode 4732) | T1098 |
| 22:08:35 | FYODOR-L | svcvnc added to Administrators (EventCode 4732) | T1098 |
| 20/08 | FYODOR-L | SMB scanning port 139 toward internal hosts | T1021.002 |
| 20/08 | Multiple | WMIC recon, Netstat, Registry enumeration | T1082/T1049/T1012 |

## Complete Attack Chain

```
ATTACKER (192.168.8.103)
        |
        |   POST saveGangster.action
        |   OGNL payload → #cmd='cat /etc/passwd'
        v
HOTH (Apache Struts Server)
        |
        |   RCE confirmed
        |   Commands executed on Linux
        |   Reverse shell → 45.77.53.176:8088
        v
FYODOR-L.froth.ly
        |
        |   powershell.exe -NoP -NonI -W Hidden -enc
        |   → AMSI bypass
        |   → RC4 payload download
        |   → iexeplorer.exe dropped
        |
        |   Registry modification (ms-settings)
        |   fodhelper.exe → UAC bypass
        |
        |   net.exe /add svcvnc Password123!
        |   net.exe localgroup administrators svcvnc /add
        v
PERSISTENCE ESTABLISHED
        |
        |   SMB scanning → 192.168.70.186
        |                → 192.168.8.103
        |                → 192.168.8.116
        v
LATERAL MOVEMENT ATTEMPTED
```
