# DNS Analysis — BOTS v3 Investigation

## Suspicious Domains Identified

During log analysis, several suspicious DNS queries
were identified targeting subdomains of brewertalk.com :

- koko10.brewertalk.com
- forumtest.brewertalk.com
- email5.brewertalk.com

All returned NXDOMAIN (domain does not exist).

## Why This Is Suspicious

A normal user does not generate hundreds of requests
toward non-existent subdomains. This behavior is
consistent with :
- DNS scanning
- Malware activity
- DGA (Domain Generation Algorithm)
- Automated reconnaissance

## MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1595 | Active Scanning |
| T1046 | Network Service Discovery |
| T1071.004 | C2 over DNS |
| T1568 | Dynamic Resolution / DGA |

## Splunk Queries Used

**Find all NXDOMAIN responses :**
```spl
index=botsv3 sourcetype="stream:dns" reply_code="NXDomain"
| stats count by query, host
| sort -count
```

<img width="1919" height="734" alt="image" src="https://github.com/user-attachments/assets/377a76b2-d1f4-4b28-9de2-d0d2f5867403" />

**the analysis of the DNS logs :
```spl
index=botsv3 host=serverless source="lambda: DNS" NXDOMAIN
```
"During the analysis of the DNS logs, I noticed several NXDOMAIN requests to unusual subdomains.
This behavior may indicate automated activity such as DNS reconnaissance or malware using auto-generated domains.
I then used Splunk to count the requests, identify the most frequent domains, and search for the relevant hosts."

A normal user doesn't make hundreds of requests to:
koko10.brewertalk.com 
forumtest.brewertalk.com 
email5.brewertalk.com

<img width="1919" height="754" alt="Capture d&#39;écran 2026-05-23 204050" src="https://github.com/user-attachments/assets/570d04e2-9c4c-4110-9786-83356dda27d9" />


**Find brewertalk domain queries :**
```spl
index=botsv3 sourcetype="stream:dns" query="*brewertalk*"
| table _time, host, query, src_ip
| sort _time
```
<img width="1918" height="747" alt="image" src="https://github.com/user-attachments/assets/ceee4817-750c-4f64-a07e-f4cdc844ebce" />


## Status
🔄 Investigation in progress — correlating DNS timeline
with C2 connection timeline.
