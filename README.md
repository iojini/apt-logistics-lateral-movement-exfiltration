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

### 6. Discovery: Network Configuration Command

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

### 7. Defense Evasion: Directory Hiding Command & Staging Directory Path

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

### 8. Command & Control: C2 Server Address & C2 Communication Port

Searched for a command and control server since attackers typically utilize command and control infrastructure to remotely control compromised systems. A command and control server at 78.141.196.6 was contacted by malicious svchost.exe from multiple machines. In addition, command and control communications utilized port 443 (HTTPS) to blend in with legitimate encrypted web traffic, making network-based detection more difficult and allowing for the evasion of basic firewall rules.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath has "WindowsCache" 
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc

```
<img width="2390" height="394" alt="POE_QR10B" src="https://github.com/user-attachments/assets/f8cd25f7-ac3c-4945-958f-e1dc6aa771a1" />

---

### 9. Credential Access: Credential Theft Tool

Searched for executables downloaded to the staging directory since credential dumping tools are typically used to extract authentication secrets from system memory and dicovered a credential dumping tool with the filename mm.exe.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "WindowsCache"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```
<img width="2649" height="809" alt="POE_QR12" src="https://github.com/user-attachments/assets/ec341bc9-d013-4018-a73d-124968bf3465" />

---

### 10. Credential Access: Memory Extraction Module 

Searched for command line arguments passed to the credential dumping tool to identify the specific module used to extract passwords from memory and discovered that the Mimikatz module "sekurlsa::logonpasswords" was used by the attacker to extract credentials from LSASS (Local Security Authority Subsystem Service) memory.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "mm.exe"
| project TimeGenerated, ProcessCommandLine

```
<img width="1948" height="330" alt="POE_QR13" src="https://github.com/user-attachments/assets/68801ab9-e4f7-4af6-b358-05a3104f9bed" />

---
### 11. Collection & Exfiltration: Data Staging Archive & Exfiltration Channel

Searched for evidence of ZIP file creation in the staging directory during the collection phase since attackers compress stolen data for efficient exfiltration. The compressed archive export-data.zip was created in the staging directory and prepared for exfiltration via the curl upload command. In addition, the attacker utilized Discord's webhook API to exfiltrate the compressed archive. Discord is a legitimate communication platform commonly allowed through firewalls, making this exfiltration technique effective for bypassing network security controls.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "WindowsCache" and ProcessCommandLine has ".zip"
| project TimeGenerated, ProcessCommandLine

```
<img width="2476" height="295" alt="POE_QR14" src="https://github.com/user-attachments/assets/67ec2819-d3c6-44a3-a555-7eb03abc7f03" />

---

### 12. Anti-Forensics: Log Tampering

Searched for event log clearing commands since attackers clear event logs in order to destroy forensic evidence and impede investigation efforts. In this case, the attacker cleared event logs in sequence, starting with the Security log (which contains logon events and credential access evidence), followed by System and Application logs.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2209" height="398" alt="POE_QR15" src="https://github.com/user-attachments/assets/2331376e-d9b6-47d6-97b2-86eb63556def" />

---

### 13. Impact: Persistence Account

Searched for evidence of account creation since hidden administrator accounts provide alternative access for future campaigns. The backdoor account "support" was created and added to the local Administrators group. It's clear that the account name was chosen to blend in with legitimate IT support accounts, providing persistent administrative access for future operations.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "/add" 
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1766" height="464" alt="POE_QR17" src="https://github.com/user-attachments/assets/d10608a1-c7bf-4d0e-815d-735fbb1c3da1" />

---

### 14. Execution: Malicious Script

Searched for script files created in temporary directories since attackers often use scripting languages to automate their attack chain and identifying the initial attack script reveals the entry point and automation method used in the compromise. The PowerShell script wupdate.ps1 was created in the user's temporary directory and used to automate the attack chain. The filename was disguised to resemble a Windows update utility, enabling execution without raising suspicion.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| where ActionType == "FileCreated"
| where FolderPath !contains "Windows Defender" 
| where FolderPath !contains "__PSScriptPolicyTest"
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc

```
<img width="2535" height="474" alt="POE_QR18" src="https://github.com/user-attachments/assets/eded8066-aa1a-4ffe-9994-78a573bb347f" />

---

### 15. Lateral Movement: Secondary Target & Remote Access Tool

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
