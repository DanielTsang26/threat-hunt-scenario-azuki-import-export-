# Threat Hunt Incident Response Report: Azuki Export/ Import Incident
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

 This is essentially where everything all started. The main table was used to investigate what was going on in the range of the particular time period. The information that was found that gave way
 suspicious actions was basically "unlock" from the account that was considered as a malicious intent. This followed the basis of unwanted access.

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

 From here, the investigation continued over on what was the malicious intent was and where would it be: Of course, this took a little bit of time and it turns out that checking the DeviceProcessEvent table will give a lot of  information away. The discovery phase revealed that there was a directory that was being created and it was hidden from any of the users that may have access to the machine. 

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

Of course, following the bad actor's attack pattern, they most likely would want to figure out more information of what the machine was like in terms of what is on their network. This was the next phase, gather information, so the table that was investigated was to dive further into the DeviceProcessEvent. This showed that there was lateral movement and it showed a lot of information that was being gathered. This was executed by: ARP.exe -a.

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

At this point, the information was gathered, so "smoke" and "mirrors" was the main intent of what the bad actor would do here. They want to not be noticed immediately and would require some distraction. This led me to believe that there would be some sort of persistence of a "distraction" for the intruder to get what they want from the machine. This was gather further more into what the device was doing. A deeper dive into the current table DeviceProcessEvent showed that a persistent event continued more frequently than any other event. This was the distraction from the bad actor. 

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

"Where was the bad actor trying to get the information and leave quickly?" was the main point of concern. So, following the same pattern, it most likely falls into the DeviceProcessEvents that most likely
was from the last query. From there "mkdir", "attrib", "md", and "New-Item", were a few targets after taking a look at what was found in the table. 


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

At this point, looking into infrastructure,this is mostly following the bad actor's attack pattern from an attack framework perspective (MITRE ATT&CK). This again, looking into what the general list of programs 
to see what was going on in the network structure. Figuring out where the bad actor is coming from and how they are residing in the infrastructure in that time range was important. This can be observed from the list of
commandlines that were occuring. At this point, knowing the RemoteIP and the RemotePort were the most crucial parts of the information, but more or less there was a pattern - persistence and utility abuse from download. 
That leads to only one IP: 78.141.196.6

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

Moving back to DeviceProcessEvents to evaluate what information was being moved around and what tool (.exe) was being used. Again, more attack patterns being followed by the standard framework (MITRE ATT&CK). After investigating the information from a general standpoint, more evaluation was needed and there was a deepdive. The deepdive was to investigate what folder path was evaluated and the discovery showed that there was only two particular files, but on closer view that made this more suspicious was the processcommandline: "mm.exe" privileger:debug sekurlsalogonpasswords exit. This essentially was the tool that was the problematic issue: mm.exe.

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



**Query 7 - COLLECTION - Data Staging Archive | Exfilitration Channel** 

_Shows attackers compress stolen data for efficient exfiltration._ 

At this point, the bad actor will most likely create a zip file to steal data and that was where I had to look elsewhere from another table being DeviceFileEvents. So, it was a simple search
where having specific information gather throughout the investigation and what the time range was, account name, and now it was just the file name.  Discovery was "export-data.zip." It was sent to a 
communication platform: "Discord."



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



```kql
DeviceNetworkEvents
| where InitiatingProcessAccountName contains "kenji"
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contains "zip"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp,InitiatingProcessAccountName, RemoteUrl, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalPort 
| order by Timestamp asc

```




<img width="1043" height="166" alt="image" src="https://github.com/user-attachments/assets/6c9c603b-ade1-4b52-a5e2-8f920621496b" />


**Query 8  ANTI-FORENSICS - Log Tampering**

_Shows order of log clearing can indicate attacker priorities and sophistication._

Throughout this investigation, the bad actor seems to be leaving a trail of information and the thought of that was most likely not the case to keep that trail around. So, following that thought process, they most likely
tamper with the information by removing/ clearing the logs. So, DeviceProcessEvents was the table to investigate as it seems to be the majority of where the investigation was. From a general perspective, it was not too difficult to locate where the logs would be erased. Using a specific file name "wevtutil.exe" showed that "Security" was the first to go.



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

Again, bad actors don't normally close the system, so there's usually a backdoor. This was how the attack pattern was playing out when following the MITRE ATT&CK framework. At this point, as the investigation was coming to an end and
most of this was just cleanup. Looking into DeviceProcessEvents and diving into what account was added into the list of accounts that was part of the machine was pretty much what was needed to see what was done to the machine and the account was: Support.

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

This was more clean up, the bad actor left some lingering/existing programs from previous actions that were implemented from earlier in the investigation. This shows by looking into what was done from an earlier part of the timeline. 
From here we notice that the scripts were: wsupdate.ps1. This also is related to svchost.exe proving the persistance of the windows update still existing in the machine.


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

Moving further into this part of the investigation was to examine who they were attacking. With all the necessary information that was noted, the bad actor was mainly attacking an IP: 10.1.0.188. This was 
mainly from a deduction from what file name was being used and from the record that was shown from that file.

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

The tool was simply found from the IP address and it showed that it was called the " mstsc.exe"


```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mstsc", "cmdkey", "psexec", "wmic", "winrs", "ssh", "remote")
| project Timestamp, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1071" height="270" alt="image" src="https://github.com/user-attachments/assets/ddec35ed-654c-4728-9ed7-af7fa4f33452" />
