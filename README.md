# Incident Response Report- Azuki Export/ Import Incident
**System:** azuki-sl  
**Incident Date Range:** 2025-11-19 – 2025-11-20  
**Author:** Daniel Tsang 

---

## EXECUTIVE SUMMARY  
On November 19, 2025, an external threat actor gained unauthorized access to the user account **kenji.sato** from IP address **88.97.178.12**. After initial access, the attacker conducted command execution, created hidden directories, downloaded malware, established persistence, performed credential theft, staged data, and exfiltrated information via Discord. Command and control communications were identified and blocked. The system has been **contained** and requires additional eradication and cleanup activities.

**Impact Level:** High  
**Status:** Contained  

---

## INCIDENT DETAILS

### Timeline
- **First Malicious Activity:** 2025-11-19T18:36:21.0262386Z — RDP unlock of `kenji.sato` from 88.97.178.12  
- **Last Observed Activity:**  2025-11-19T19:10:41.372526Z - "mstsc.exe" /v:10.1.0.188  by  `kenji.sato` 
---

### Attack Overview

| Category | Details |
|---------|---------|
| **Initial Access Method** | Remote Desktop Protocol login (LogonUnlock) |
| **Compromised Account** | `kenji.sato` |
| **Affected System** | azuki-sl |
| **Attacker IP Address** | 88.97.178.12 |

---

### Attack Chain (MITRE ATT&CK)

| Tactic | Description |
|--------|-------------|
| **Initial Access (TA0001)** | Attacker unlocked user account `kenji.sato` via RDP from IP **88.97.178.12** |
| **Execution (TA0002)** | Executed commands to create directories and modify attributes (`mkdir`, `attrib`) |
| **Persistence (TA0003)** | Created scheduled task **“Windows Update Check”** |
| **Defense Evasion (TA0005)** | Hid staged folders, added Defender exclusions (3 extensions + Temp folder), used `certutil.exe` for download |
| **Discovery (TA0007)** | Ran network reconnaissance via `arp.exe -a` |
| **Credential Access (TA0006)** | Used credential dumping tool **mm.exe** with module `sekurlsa::logonpasswords` |
| **Lateral Movement (TA0008)** | _None observed_ |
| **Collection (TA0009)** | Staged exfil data into **export-data.zip** |
| **Command & Control (TA0011)** | C2 connection to **78.141.196.6:443** |
| **Exfiltration (TA0010)** | Exfiltrated via **Discord** |
| **Impact (TA0040)** | Log tampering attempts (wevtutil.exe events) |

---

## KEY FINDINGS

### Primary IOCs

| IOC Type | Value |
|----------|-------|
| **Malicious IPs** | 88.97.178.12 (initial access), 78.141.196.6 (C2) |
| **Malicious Files** | `mm.exe`, `svchost.exe` (malicious), `export-data.zip` |
| **Compromised Accounts** | `kenji.sato` |
| **C2 Infrastructure** | 78.141.196.6 over port 443 |

---

## RECOMMENDATIONS

### Immediate Actions (Do Now)
- Disable and reset credentials for `kenji.sato`.
- Quarantine `azuki-sl` from the network.
- Remove scheduled task: **Windows Update Check**.
- Delete malicious staging directory: `C:\ProgramData\WindowsCache`.
- Remove Windows Defender exclusions (extensions + Temp path).
- Block IPs **88.97.178.12** and **78.141.196.6** at firewall.
- Collect full memory image for offline analysis.

### Short-term (1–30 days)
- Review all RDP configurations and enforce MFA.
- Deploy updated EDR signatures.
- Audit scheduled tasks, startup folders, and registry run keys.
- Rotate all privileged credentials.
- Review network logs for lateral movement attempts.

### Long-term (Security Improvements)
- Enforce least privilege for all local users.
- Implement network segmentation and strict outbound filtering.
- Deploy centralized logging with long-term retention.
- Conduct regular adversary simulation and endpoint hardening.
- Enforce conditional access and modern authentication policies.

---

## APPENDIX

### A. Key Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|--------|-------------|
| **IP Address** | 88.97.178.12 | Initial attacker RDP access |
| **IP Address** | 78.141.196.6 | Command & Control |
| **File** | mm.exe | Credential theft utility |
| **File** | C:\ProgramData\WindowsCache\svchost.exe | Malicious binary run for persistence/C2 |
| **Account** | kenji.sato | Compromised user |
| **Domain** | discord | Exfiltration channel |
| **Hash** | _TBD_ | (Add once available) |

---

### B. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence | 
|-------|---------------|----------------|----------|
| Initial Access | T1078 | Valid Accounts | RDP unlock from 88.97.178.12 |
| Execution | T1059 | Command-Line Execution | mkdir, attrib | — |
| Persistence | T1053.005 | Scheduled Task | “Windows Update Check” | 
| Defense Evasion | T1562 | Modify System Configuration | Defender exclusions + hidden directory | 
| Discovery | T1016 | Network Discovery | `arp.exe -a` | 3 |
| Credential Access | T1003.001 | LSASS Memory Dumping | mm.exe + sekurlsa::logonpasswords | 
| Collection | T1560 | Archive Collected Data | export-data.zip | 
| C2 | T1071.001 | Web Protocols | 78.141.196.6:443 | 10–11 |
| Exfiltration | T1567.002 | Exfiltration over Web Service | Discord |
| Impact | T1070.001 | Clear Windows Event Logs | wevtutil.exe | 

---

### C. Investigation Timeline  

| Time (UTC) | Event | Source |
|------------|--------|--------|
| 2025-11-19T18:36:21Z | Initial RDP Unlock | DeviceLogonEvents |
| 2025-11-19T19:05:33Z | Malware staging directory created | DeviceProcessEvents |
| 2025-11-19T13:10:09Z | Scheduled task persistence created | DeviceProcessEvents |
| 2025-11-19T19:06:58Z | Download Utility Abuse | DeviceProcessEvents |
| 2025-11-19T19:11:04Z | Command and Control - Server Address |DeviceNetworkEvents |
| 2025-11-19T19:08:26Z| Credential Access - Credential Theft Tool | DeviceProcessEvents|
| 2025-11-19T19:08:58Z | Data Staging Archive | DeviceFileEvents |
| 2025-11-19T19:11:39Z| ANTI-FORENSICS - Log Tampering | DeviceProcessEvents|
| 2025-11-19T19:09:53Z | Remove Persistence Account | DeviceProcessEvents |
| 2025-11-19T18:49:48Z| Malicious Script Identification | DeviceFileEvents|
| 2025-11-19T19:10:41Z| LATERAL MOVEMENT - Remote Access Tool| DeviceProcessEvents|


---

### D. Evidence – KQL Queries & Screenshots [Major Events / Points]
**Query 1 – Initial Access**   
 _Shows initial RDP unlock event._   
 _Attacker IP: 88.97.178.12._   

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, AccountName, ActionType, LogonType, RemoteIP
| sort by Timestamp asc
```
<img width="945" height="606" alt="image" src="https://github.com/user-attachments/assets/dba0e422-7573-48cd-adaf-2ac53289ba99" />



**Query 2 – Malicious Execution**  
 _Shows creation of hidden staging directory._   

 ```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "md ", "New-Item", "attrib")
| where AccountName contains "kenji"
| project Timestamp, ProcessCommandLine, AccountName, FileName, FolderPath, ActionType
| sort by Timestamp asc
```
<img width="1075" height="210" alt="image" src="https://github.com/user-attachments/assets/dc911453-9aee-41c0-95ea-b59babd7e055" />



**Query 3 – Network Reconnaissance**

_Shows the enumeration of network topology to identify lateral movement opportunities and high-value targets._  

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in ("arp.exe", "ipconfig.exe", "net.exe", "nbtstat.exe", "netstat.exe", "wmic.exe")
      or ProcessCommandLine contains "arp"
      or ProcessCommandLine contains "ifconfig"
      or ProcessCommandLine contains "net "
      or ProcessCommandLine contains "nbtstat"
      or ProcessCommandLine contains "netstat"
      or ProcessCommandLine contains "wmic"
| where AccountName contains "kenji"
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessAccountName
| sort by Timestamp asc
```
<img width="1083" height="281" alt="image" src="https://github.com/user-attachments/assets/9ad14307-571f-4670-b947-08fb4df2f8dd" />



**Query 4 – Persistence**  

_Scheduled task created: “Windows Update Check”._   

```kql
DeviceProcessEvents
| where AccountName contains "kenji"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, AccountName, FileName, ActionType, ProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp
```
 <img width="1082" height="338" alt="image" src="https://github.com/user-attachments/assets/ca2c0fa4-d075-49a8-8a0c-ebbbb8b07cd8" />



**Query 5 – Malware Staging Directory**

_Shows the attacker has establish staging locations to organise tools and stolen data._  

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "md ", "New-Item", "attrib")
| where AccountName contains "kenji"
| project Timestamp, ProcessCommandLine, AccountName, FileName, FolderPath, ActionType
| sort by Timestamp asc
```
<img width="1071" height="513" alt="image" src="https://github.com/user-attachments/assets/2aa99497-7490-4312-887e-679d29c1b518" />


**Query 6 – COMMAND & CONTROL - C2 Server Address**

_Shows Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking._  

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains "svchost.exe" 
      or InitiatingProcessCommandLine contains "ProgramData"
      or InitiatingProcessCommandLine contains "WindowsCache"
      or InitiatingProcessCommandLine contains "certutil"
| project Timestamp,InitiatingProcessAccountName ,InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalPort
| order by Timestamp asc
```


<img width="1075" height="232" alt="image" src="https://github.com/user-attachments/assets/7d1e6349-43be-4c7e-8080-c719b1867e12" />



**Query 6 – CREDENTIAL ACCESS - Credential Theft Tool**

_Shows Credential dumping tools extract authentication secrets from system memory._ 

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "WindowsCache"
| project Timestamp, AccountName,FolderPath,FileName, ActionType, ProcessCommandLine
| order by Timestamp asc
```
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "WindowsCache"
| project Timestamp, AccountName,FolderPath,FileName, ActionType, ProcessCommandLine
| order by Timestamp asc
```
<img width="1072" height="507" alt="image" src="https://github.com/user-attachments/assets/3abacac6-3de8-4cae-aa59-03b115c1c959" />



**Query 7 - COLLECTION - Data Staging Archive**

_Shows attackers compress stolen data for efficient exfiltration._ 


```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName  contains "kenji"
| where FileName contains "zip"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, InitiatingProcessAccountName, ActionType, FileName
| sort by Timestamp asc

```

<img width="1070" height="162" alt="image" src="https://github.com/user-attachments/assets/f8eccf61-b718-4c5e-b0a8-3cf010efdf2a" />


**Query 8  ANTI-FORENSICS - Log Tampering**

_Shows order of log clearing can indicate attacker priorities and sophistication._

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| project Timestamp, InitiatingProcessAccountName, ProcessCommandLine
| sort by Timestamp asc
```

<img width="1072" height="377" alt="image" src="https://github.com/user-attachments/assets/be0a0552-e7c4-496b-bc5a-3549fd8fed2a" />


**Query 9  IMPACT - Persistence Account**

_Shows hidden administrator accounts provide alternative access for future operations._

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName contains "kenji"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/add"
| project Timestamp, AccountName, ProcessCommandLine
| sort by Timestamp asc
```


<img width="1072" height="283" alt="image" src="https://github.com/user-attachments/assets/05f730ac-befe-4e75-85a2-e91f216d8b72" />


**Query 10  EXECUTION - Malicious Script**

_Shows the initial attack script reveals the entry point and automation method used in the compromise._


```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where FolderPath contains "temp"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, InitiatingProcessAccountName,InitiatingProcessCommandLine, ActionType, FileName, FolderPath
| order by Timestamp asc

```

<img width="1070" height="552" alt="image" src="https://github.com/user-attachments/assets/a888af12-c853-4d02-914b-50a06d3d56b1" />


**Query 11 LATERAL MOVEMENT - Secondary Target**

_Shows the lateral movement targets are selected based on their access to sensitive data or network privileges._

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where InitiatingProcessFileName contains "mstsc.exe"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1071" height="435" alt="image" src="https://github.com/user-attachments/assets/63d7a3ee-7230-4dc7-8f8b-c94bff41e064" />


**Query 12  LATERAL MOVEMENT - Remote Access Tool**

_Shows the built-in remote access tools._

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mstsc", "cmdkey", "psexec", "wmic", "winrs", "ssh", "remote")
| project Timestamp, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1071" height="270" alt="image" src="https://github.com/user-attachments/assets/ddec35ed-654c-4728-9ed7-af7fa4f33452" />
