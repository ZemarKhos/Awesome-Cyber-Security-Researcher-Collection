# 🛡️ Active Directory Defense & Detection

**Author**: Zemarkhos | **Last Updated**: 2025-01-09
**Scope**: Enterprise Active Directory Hardening, Detection, and Response

---

## 🎯 Quick Wins Checklist

Implement these high-impact, low-effort defenses **immediately**:

- [ ] **Enable PowerShell logging** (Script Block, Module, Transcription)
- [ ] **Deploy Sysmon** with SwiftOnSecurity config
- [ ] **Audit AdminSDHolder** for unauthorized modifications
- [ ] **Disable LLMNR and NetBIOS** via GPO
- [ ] **Enable SMB signing** (require on all systems)
- [ ] **Enable LDAP signing and channel binding**
- [ ] **Disable RC4-HMAC** encryption for Kerberos
- [ ] **Flag Tier 0 accounts** with "Account is sensitive and cannot be delegated"
- [ ] **Remove unconstrained delegation** from all non-DC systems
- [ ] **Deploy Microsoft Defender for Identity** (MDI)
- [ ] **Enable Advanced Audit Policy** for critical events
- [ ] **Create honey admin accounts** for detection
- [ ] **Implement PAW** for Domain Admins (at minimum)
- [ ] **Audit Certificate Templates** for ESC1/ESC2 vulnerabilities
- [ ] **Deploy Protected Users Group** for Tier 0 accounts
- [ ] **Implement LAPS** for local administrator passwords
- [ ] **Remove GPP passwords** from SYSVOL
- [ ] **Enable Command Line Process Auditing**
- [ ] **Create BloodHound baselines** for attack path monitoring
- [ ] **Implement MFA** for all administrative access

---

## 1. 🏰 Hardening Fundamentals

### 1.1 Tier Model Implementation

The **Tier Model** provides administrative isolation to prevent credential theft escalation.

#### Tier Structure

| Tier | Scope | Assets | Admin Accounts |
|------|-------|--------|----------------|
| **Tier 0** | Domain/Forest Control | Domain Controllers, AD CS, Azure AD Connect, Backup systems | Domain Admins, Enterprise Admins, Schema Admins |
| **Tier 1** | Server Management | Application servers, file servers, database servers | Server administrators |
| **Tier 2** | Workstation Management | User workstations, laptops, BYOD | Help desk, desktop support |

#### Critical Rules

1. **No credential reuse across tiers** (downward access only)
2. **Tier 0 admins NEVER log into Tier 1/2 systems**
3. **Separate admin accounts per tier**
4. **Dedicated jump boxes/PAWs per tier**

#### Implementation via GPO

```powershell
# Deny Tier 0 accounts from logging into Tier 1/2 systems
# Computer Configuration > Windows Settings > Security Settings > User Rights Assignment
# Deny log on locally: Tier0-Admins group
# Deny log on through Remote Desktop Services: Tier0-Admins group

# Create Tier-specific security groups
New-ADGroup -Name "Tier0-Admins" -GroupScope Global -GroupCategory Security -Path "OU=Tier0,OU=Admin,DC=corp,DC=local"
New-ADGroup -Name "Tier1-Admins" -GroupScope Global -GroupCategory Security -Path "OU=Tier1,OU=Admin,DC=corp,DC=local"
New-ADGroup -Name "Tier2-Admins" -GroupScope Global -GroupCategory Security -Path "OU=Tier2,OU=Admin,DC=corp,DC=local"
```

#### MITRE D3FEND Mapping
- **D3-ILA** (Isolation by Logical Access Control)
- **D3-ACH** (Account Context Hardening)

---

### 1.2 Privileged Access Workstations (PAW)

PAWs are **dedicated, hardened systems** for Tier 0 administration.

#### PAW Requirements

- **Dedicated hardware** (no dual-use)
- **Restricted internet access** (only Microsoft services)
- **Application whitelisting** (AppLocker/WDAC)
- **Device Guard/Credential Guard** enabled
- **Full disk encryption** (BitLocker)
- **No email, browsing, or productivity applications**
- **Separate network segment** (VLAN isolation)

#### PAW GPO Baseline

```powershell
# Disable unnecessary services
Set-Service -Name "W32Time" -StartupType Manual
Set-Service -Name "Themes" -StartupType Disabled

# Enable Windows Defender Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f

# AppLocker whitelist for tools
<RuleCollection Type="Exe">
  <FilePathRule Id="Allow-AdminTools" Name="Allow Admin Tools" UserOrGroupSid="S-1-5-32-544" Action="Allow">
    <Conditions>
      <FilePathCondition Path="C:\Windows\System32\*.exe"/>
      <FilePathCondition Path="C:\Program Files\AdminTools\*.exe"/>
    </Conditions>
  </FilePathRule>
  <FilePathRule Id="Deny-All" Name="Deny All Others" UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
      <FilePathCondition Path="*"/>
    </Conditions>
  </FilePathRule>
</RuleCollection>
```

#### Detection: Unauthorized PAW Usage

```kql
// KQL for Sentinel: Detect non-PAW admin logons to DCs
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where Computer has "DC"
| where TargetUserName in (Tier0AdminsList)
| where WorkstationName !in (PAWList)
| project TimeGenerated, TargetUserName, WorkstationName, IpAddress, LogonType
```

---

### 1.3 Least Privilege Enforcement (RBAC)

#### Just Enough Administration (JEA)

JEA restricts PowerShell sessions to specific cmdlets/parameters.

```powershell
# Create JEA role capability for DNS management
New-PSRoleCapabilityFile -Path "C:\JEA\DNSAdmin.psrc" -VisibleCmdlets @{
    Name = 'Add-DnsServerResourceRecord'
    Parameters = @{ Name = 'Name'; ValidateSet = 'A','CNAME','PTR' }
}

# Create JEA session configuration
New-PSSessionConfigurationFile -Path "C:\JEA\DNSAdmin.pssc" `
    -SessionType RestrictedRemoteServer `
    -RoleDefinitions @{ 'CORP\DNSAdmins' = @{ RoleCapabilities = 'DNSAdmin' } }

# Register the JEA endpoint
Register-PSSessionConfiguration -Name DNSAdmin -Path "C:\JEA\DNSAdmin.pssc"
```

#### Just-in-Time (JIT) Administration

Temporary privilege elevation via Privileged Identity Management (PIM) or PAM (Privileged Access Management).

**Microsoft Identity Manager (MIM) PAM**:
- Admins request elevated access
- Time-limited group membership (1-8 hours)
- Approval workflow
- Full audit trail

```powershell
# Azure AD PIM example (requires Azure AD P2)
# Request Domain Admin role for 2 hours
New-AzureADMSPrivilegedRoleAssignmentRequest `
    -ProviderId "aadRoles" `
    -ResourceId "tenant-id" `
    -RoleDefinitionId "role-id" `
    -SubjectId "user-id" `
    -Type "UserAdd" `
    -AssignmentState "Active" `
    -Schedule @{ StartDateTime = (Get-Date); EndDateTime = (Get-Date).AddHours(2) }
```

---

### 1.4 Protected Users Group

**Protected Users** is a built-in security group (Server 2012 R2+) that enforces:
- No NTLM authentication
- No DES/RC4 in Kerberos pre-auth
- No Kerberos delegation (constrained or unconstrained)
- TGT lifetime reduced to 4 hours (non-renewable beyond)
- No credential caching

#### Implementation

```powershell
# Add Tier 0 accounts to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "DA-Admin1","DA-Admin2","EA-Admin1"

# Verify membership
Get-ADGroupMember -Identity "Protected Users" | Select Name,SamAccountName
```

#### ⚠️ Compatibility Warning
- **Legacy applications** requiring NTLM will fail
- **Test thoroughly** before adding service accounts
- **Monitor Event ID 4625** for authentication failures

#### Detection: Attempted NTLM from Protected Users

```xml
<!-- Sigma rule for Protected Users NTLM attempt -->
<rule>
  <title>Protected Users Group NTLM Authentication Attempt</title>
  <logsource>
    <product>windows</product>
    <service>security</service>
  </logsource>
  <detection>
    <selection>
      <EventID>4625</EventID>
      <LogonType>3</LogonType>
      <Status>0xC000006D</Status>
      <TargetUserName>*</TargetUserName>
    </selection>
    <condition>selection AND user in ProtectedUsersGroup</condition>
  </detection>
  <level>high</level>
</rule>
```

---

### 1.5 Authentication Policies and Silos

**Authentication Policies** (Server 2012 R2+) enforce TGT lifetime, device access restrictions, and require MFA.

#### Create Authentication Policy

```powershell
# Create policy for Domain Admins
New-ADAuthenticationPolicy -Name "Tier0-AuthPolicy" `
    -UserTGTLifetimeMins 240 `
    -Enforce

# Apply to Tier 0 accounts
Set-ADUser -Identity "DA-Admin1" -AuthenticationPolicy "Tier0-AuthPolicy"

# Create Authentication Policy Silo
New-ADAuthenticationPolicySilo -Name "Tier0-Silo" `
    -UserAuthenticationPolicy "Tier0-AuthPolicy" `
    -Enforce

# Add accounts to silo
Grant-ADAuthenticationPolicySiloAccess -Identity "Tier0-Silo" -Account "DA-Admin1"
```

#### Device Restriction via Policy

```powershell
# Restrict Tier 0 admins to PAWs only
New-ADAuthenticationPolicy -Name "Tier0-DeviceRestriction" `
    -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"Tier0-Silo`"))"
```

---

## 2. 🔐 Kerberos Hardening

### 2.1 Disable RC4-HMAC Encryption

RC4 is **cryptographically weak** and vulnerable to offline cracking.

#### Domain-Wide RC4 Disable

```powershell
# Via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Configure encryption types allowed for Kerberos
# Enable: AES128_HMAC_SHA1, AES256_HMAC_SHA1
# Disable: DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5

# Via PowerShell (requires reboot)
Set-ADDomainController -Identity "DC01" -SupportedEncryptionTypes "AES128,AES256"
```

#### Per-Account RC4 Disable

```powershell
# Disable RC4 for specific account
Set-ADAccountControl -Identity "ServiceAccount1" -DoesNotRequirePreAuth $false
Set-ADUser -Identity "ServiceAccount1" -Replace @{
    "msDS-SupportedEncryptionTypes" = 24  # 24 = AES128 + AES256
}
```

#### Detection: RC4 Usage Monitoring

```kql
// Detect RC4 ticket requests (Event 4768/4769)
SecurityEvent
| where EventID in (4768, 4769)
| where TicketEncryptionType == "0x17"  // RC4-HMAC
| project TimeGenerated, Account, ServiceName, IpAddress, TicketEncryptionType
| summarize Count=count() by Account, bin(TimeGenerated, 1h)
```

---

### 2.2 Kerberos Armoring (FAST)

**Flexible Authentication Secure Tunneling** prevents offline password cracking by encrypting pre-authentication data.

#### Enable FAST via GPO

```powershell
# Computer Configuration > Policies > Administrative Templates > System > KDC
# KDC support for claims, compound authentication and Kerberos armoring: Supported

# Client-side enforcement
# Computer Configuration > Policies > Administrative Templates > System > Kerberos
# Kerberos client support for claims, compound authentication and Kerberos armoring: Enabled
# Kerberos client support for claims, compound authentication and Kerberos armoring: Always provide claims
```

#### Verify FAST Deployment

```powershell
# Check if FAST is supported on DC
Get-ADDomainController -Filter * | Select Name,OperatingSystem | ForEach-Object {
    Test-NetConnection -ComputerName $_.Name -Port 88
}

# Verify client FAST configuration
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name SupportedEncryptionTypes
```

---

### 2.3 PAC Validation Enforcement

The **Privilege Attribute Certificate (PAC)** contains user authorization data. Enforce PAC validation to prevent Golden Ticket attacks.

#### Enable PAC Validation

```powershell
# Via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Force logoff when logon hours expire: Enabled

# Registry setting for KDC
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v ValidateKdcPacSignature /t REG_DWORD /d 1 /f
```

#### Detection: Invalid PAC Signature

```xml
<!-- Event ID 4675: SIDs were filtered -->
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4675</EventID>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="OriginalUserName">FakeAdmin</Data>
  </EventData>
</Event>
```

---

### 2.4 Ticket Lifetime Reduction

Default TGT lifetime is **10 hours**. Reduce for high-value accounts.

```powershell
# Set domain-wide maximum TGT lifetime to 4 hours
Set-ADDomain -Identity "corp.local" -MaxTicketAge "04:00:00"

# Set maximum service ticket lifetime to 1 hour
Set-ADDomain -Identity "corp.local" -MaxServiceAge "01:00:00"

# Set maximum ticket renewal to 1 day
Set-ADDomain -Identity "corp.local" -MaxRenewAge "1.00:00:00"
```

---

### 2.5 Service Account Management (gMSA, sMSA)

**Group Managed Service Accounts (gMSA)** auto-rotate passwords (120 characters, every 30 days).

#### Create gMSA

```powershell
# Create KDS Root Key (one-time, domain-wide)
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# Create gMSA for SQL Server
New-ADServiceAccount -Name "svc-SQL" `
    -DNSHostName "svc-SQL.corp.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "SQL-Servers$" `
    -ServicePrincipalNames "MSSQLSvc/sql01.corp.local:1433"

# Install gMSA on server
Install-ADServiceAccount -Identity "svc-SQL"

# Configure service to use gMSA
sc.exe config MSSQLSERVER obj= "CORP\svc-SQL$" password= ""
```

#### Audit Service Accounts

```powershell
# Find all non-gMSA service accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet |
    Where-Object {$_.DistinguishedName -notlike "*Managed Service Accounts*"} |
    Select Name,ServicePrincipalName,PasswordLastSet |
    Export-Csv "C:\Audit\NonGMSA_Accounts.csv"
```

---

### 2.6 SPN Auditing

**Service Principal Names (SPNs)** are targets for **Kerberoasting**.

#### Detect Weak SPNs

```powershell
# Find accounts with SPNs and weak passwords
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet,AdminCount |
    Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-180)} |
    Select Name,ServicePrincipalName,PasswordLastSet,AdminCount

# Detect non-gMSA service accounts with administrative privileges
Get-ADUser -Filter {ServicePrincipalName -like "*" -and AdminCount -eq 1} |
    Select Name,ServicePrincipalName
```

#### Detection: Kerberoasting Activity

```kql
// Detect TGS requests for RC4 service tickets (Kerberoasting indicator)
SecurityEvent
| where EventID == 4769
| where ServiceName !endswith "$"  // Exclude computer accounts
| where TicketEncryptionType == "0x17"  // RC4
| where ServiceName !in ("krbtgt", "kadmin")
| summarize RequestCount=count() by Account, ServiceName, IpAddress, bin(TimeGenerated, 1h)
| where RequestCount > 5
```

---

## 3. 🚫 Delegation Controls

Kerberos delegation allows services to impersonate users. **Unconstrained delegation** is highly dangerous.

### 3.1 Eliminate Unconstrained Delegation

#### Find Unconstrained Delegation

```powershell
# Find all accounts with unconstrained delegation (exclude DCs)
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} -Properties TrustedForDelegation,OperatingSystem |
    Select Name,OperatingSystem,TrustedForDelegation

Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select Name,SamAccountName,TrustedForDelegation
```

#### Remove Unconstrained Delegation

```powershell
# Remove unconstrained delegation from computer
Set-ADComputer -Identity "WEBSERVER01" -TrustedForDelegation $false

# Remove from user account
Set-ADUser -Identity "svc-Web" -TrustedForDelegation $false
```

#### Detection: Unconstrained Delegation Abuse

```kql
// Detect TGT requests to servers with unconstrained delegation (potential PrinterBug/PetitPotam)
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where TargetLogonId != "0x3e7"  // Exclude SYSTEM
| where Computer in (UnconstrainedDelegationServers)
| join kind=inner (
    SecurityEvent
    | where EventID == 4768
) on $left.TargetUserName == $right.TargetUserName
| project TimeGenerated, TargetUserName, Computer, IpAddress, TicketOptions
```

---

### 3.2 Audit Constrained Delegation

Constrained delegation is safer but still requires monitoring.

```powershell
# Find all constrained delegation configurations
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo |
    Select Name,@{N='DelegatesTo';E={$_."msDS-AllowedToDelegateTo"}}

Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo |
    Select Name,@{N='DelegatesTo';E={$_."msDS-AllowedToDelegateTo"}}
```

---

### 3.3 RBCD Monitoring (Resource-Based Constrained Delegation)

RBCD abuse is a common post-exploitation technique (e.g., **S4U2Self/S4U2Proxy** attacks).

#### Detect RBCD Modifications

```powershell
# Monitor msDS-AllowedToActOnBehalfOfOtherIdentity attribute
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object {$_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null} |
    Select Name,@{N='AllowedToAct';E={$_."msDS-AllowedToActOnBehalfOfOtherIdentity"}}
```

#### Detection: RBCD Abuse

```kql
// Event ID 5136: Directory Service Object Modified (RBCD attribute change)
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "msDS-AllowedToActOnBehalfOfOtherIdentity"
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeValue, Computer
```

```xml
<!-- Sigma rule for RBCD modification -->
<rule>
  <title>Resource-Based Constrained Delegation Modification</title>
  <logsource>
    <product>windows</product>
    <service>security</service>
  </logsource>
  <detection>
    <selection>
      <EventID>5136</EventID>
      <AttributeLDAPDisplayName>msDS-AllowedToActOnBehalfOfOtherIdentity</AttributeLDAPDisplayName>
    </selection>
    <condition>selection</condition>
  </detection>
  <level>high</level>
</rule>
```

---

### 3.4 "Account is Sensitive and Cannot be Delegated" Flag

This flag prevents **any delegation** for the account (unconstrained, constrained, RBCD).

```powershell
# Set flag for Tier 0 accounts
Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {
    Set-ADAccountControl -Identity $_ -AccountNotDelegated $true
}

# Verify
Get-ADUser -Filter {AdminCount -eq 1} -Properties AccountNotDelegated |
    Select Name,AccountNotDelegated
```

---

### 3.5 Regular Delegation Audits

**Automated monthly audit**:

```powershell
# Comprehensive delegation audit script
$Report = @()

# Unconstrained delegation
$Unconstrained = Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} -Properties TrustedForDelegation
$Report += $Unconstrained | Select @{N='Type';E={'Unconstrained'}},Name,DistinguishedName

# Constrained delegation
$Constrained = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo
$Report += $Constrained | Select @{N='Type';E={'Constrained'}},Name,DistinguishedName,@{N='Target';E={$_."msDS-AllowedToDelegateTo"}}

# RBCD
$RBCD = Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
$Report += $RBCD | Select @{N='Type';E={'RBCD'}},Name,DistinguishedName

$Report | Export-Csv "C:\Audit\Delegation-Audit-$(Get-Date -Format 'yyyy-MM-dd').csv" -NoTypeInformation
```

---

## 4. 🔍 ACL/Permission Auditing

### 4.1 AdminSDHolder Monitoring

**AdminSDHolder** is a protected object that serves as a template for privileged accounts. The **SDProp** process resets permissions hourly.

#### Audit AdminSDHolder ACL

```powershell
# Get AdminSDHolder ACL
$AdminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -Properties ntSecurityDescriptor
$AdminSDHolder.ntSecurityDescriptor.Access |
    Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\*" -and $_.IdentityReference -notlike "BUILTIN\*"} |
    Select IdentityReference,ActiveDirectoryRights,AccessControlType

# Alert on unauthorized modifications
# Monitor Event ID 5136 for AdminSDHolder changes
```

#### Detection: AdminSDHolder Modification

```kql
SecurityEvent
| where EventID == 5136
| where ObjectDN contains "CN=AdminSDHolder,CN=System"
| project TimeGenerated, SubjectUserName, AttributeLDAPDisplayName, AttributeValue, Computer
```

---

### 4.2 Dangerous ACEs Detection

**GenericAll, WriteDacl, WriteOwner** on privileged objects = path to Domain Admin.

#### Scan for Dangerous ACEs

```powershell
# Using PowerView (offensive tool for defensive purposes)
Import-Module .\PowerView.ps1

# Find GenericAll permissions on Domain Admins group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
    Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"} |
    Select SecurityIdentifier,ActiveDirectoryRights,ObjectDN

# Convert SID to username
ConvertFrom-SID <SID>
```

#### Using Native PowerShell

```powershell
# Find dangerous ACEs on Tier 0 groups
$DangerousRights = @("GenericAll","WriteDacl","WriteOwner","GenericWrite","WriteProperty")
$Tier0Groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")

foreach ($Group in $Tier0Groups) {
    $ACL = Get-ACL "AD:\CN=$Group,CN=Users,DC=corp,DC=local"
    $ACL.Access | Where-Object {
        $_.ActiveDirectoryRights -match ($DangerousRights -join "|") -and
        $_.IdentityReference -notlike "NT AUTHORITY\*" -and
        $_.IdentityReference -notlike "BUILTIN\*"
    } | Select @{N='Group';E={$Group}},IdentityReference,ActiveDirectoryRights,AccessControlType
}
```

---

### 4.3 PingCastle Regular Assessments

**PingCastle** is a free AD security assessment tool with a risk scoring system.

#### Running PingCastle

```powershell
# Download from: https://www.pingcastle.com/download/
.\PingCastle.exe --healthcheck --server dc01.corp.local

# Generate report
.\PingCastle.exe --healthcheck --server dc01.corp.local --no-enum-limit

# Automated monthly scan
$Task = {
    C:\Tools\PingCastle\PingCastle.exe --healthcheck --server dc01.corp.local --level Full
}
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "PingCastle-Monthly" -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\PingCastle-Scan.ps1") -Trigger $Trigger
```

#### Key PingCastle Indicators

| Risk | Description | Severity |
|------|-------------|----------|
| **A-AdminSDHolder** | Unauthorized AdminSDHolder modifications | Critical |
| **A-LAPS** | LAPS not deployed | High |
| **P-Delegated** | Unconstrained delegation present | Critical |
| **P-UnprotectedOU** | No Deny ACEs on OUs | Medium |
| **S-DC-SubnetMissing** | DCs without subnet assignment | Low |

---

### 4.4 BloodHound Community Edition for Defense

**BloodHound** visualizes attack paths. Use defensively to eliminate escalation routes.

#### Defensive BloodHound Workflow

1. **Collect data** with SharpHound from a privileged account
2. **Identify attack paths** to Domain Admins
3. **Break the paths** by removing ACLs, group memberships, or delegation
4. **Re-scan monthly** to verify paths remain broken

```powershell
# Run SharpHound collector
.\SharpHound.exe --CollectionMethod All --Domain corp.local --LdapUsername admin --LdapPassword P@ssw0rd

# Import into BloodHound and run queries:
# - "Shortest Paths to Domain Admins from Owned Principals"
# - "Find Principals with DCSync Rights"
# - "Shortest Paths to Unconstrained Delegation Systems"
```

#### Critical BloodHound Queries for Defense

```cypher
// Find all paths to Domain Admins from non-admin users
MATCH p=shortestPath((u:User {admincount:false})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// Find users with DCSync rights
MATCH p=(u)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain)
RETURN p

// Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name
```

---

### 4.5 AdminCount Attribute Tracking

The **AdminCount** attribute marks accounts as protected by AdminSDHolder.

```powershell
# Find all AdminCount=1 accounts
Get-ADUser -LDAPFilter "(adminCount=1)" -Properties AdminCount,WhenChanged |
    Select Name,SamAccountName,AdminCount,WhenChanged

# Find orphaned AdminCount accounts (no longer in privileged groups)
$PrivilegedGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators")
$AdminCountUsers = Get-ADUser -LDAPFilter "(adminCount=1)"

foreach ($User in $AdminCountUsers) {
    $IsMember = $false
    foreach ($Group in $PrivilegedGroups) {
        if (Get-ADGroupMember -Identity $Group -Recursive | Where-Object {$_.SamAccountName -eq $User.SamAccountName}) {
            $IsMember = $true
            break
        }
    }
    if (-not $IsMember) {
        Write-Host "Orphaned AdminCount: $($User.SamAccountName)" -ForegroundColor Yellow
    }
}
```

---

### 4.6 Privileged Group Membership Monitoring

**Real-time alerting** on privileged group changes.

#### GPO Audit Configuration

```powershell
# Enable auditing for privileged groups via GPO
# Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy
# Account Management > Audit Security Group Management: Success, Failure

# Monitor Event IDs: 4728, 4732, 4756 (member added to group)
# Monitor Event IDs: 4729, 4733, 4757 (member removed from group)
```

#### Detection: Privileged Group Modification

```kql
SecurityEvent
| where EventID in (4728, 4732, 4756, 4729, 4733, 4757)
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| project TimeGenerated, EventID, SubjectUserName, TargetUserName, MemberName, MemberSid, Computer
```

```xml
<!-- Sigma rule for Domain Admins group modification -->
<rule>
  <title>Domain Admins Group Modification</title>
  <logsource>
    <product>windows</product>
    <service>security</service>
  </logsource>
  <detection>
    <selection>
      <EventID>
        - 4728
        - 4732
        - 4756
      </EventID>
      <TargetUserName>Domain Admins</TargetUserName>
    </selection>
    <condition>selection</condition>
  </detection>
  <level>critical</level>
</rule>
```

---

## 5. 🛠️ GPO Security

### 5.1 GPO Creation/Modification Restrictions

**Default**: Any authenticated user can read GPOs. Restrict **creation/modification** to dedicated admin groups.

```powershell
# Create GPO Admin group
New-ADGroup -Name "GPO-Admins" -GroupScope Global -GroupCategory Security

# Delegate GPO creation rights (remove default permissions)
# Group Policy Management > Forest > Domains > corp.local > Group Policy Objects
# Right-click > Delegate Control > Add "GPO-Admins" with "Create GPOs"

# Remove Authenticated Users from default GPO permissions
$GPOs = Get-GPO -All
foreach ($GPO in $GPOs) {
    Set-GPPermissions -Name $GPO.DisplayName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel None
}
```

---

### 5.2 GPO Link Permissions

Linking GPOs to OUs requires **separate permissions** from creating GPOs.

```powershell
# Delegate GPO linking for specific OU
$OU = "OU=Workstations,DC=corp,DC=local"
$Group = "GPO-Admins"

dsacls $OU /G "$Group:GR;groupPolicyContainer"
dsacls $OU /G "$Group:WP;gpLink"
dsacls $OU /G "$Group:WP;gpOptions"
```

---

### 5.3 Loopback Processing Security

**Loopback processing** applies user GPO settings based on computer location (not user location). Can be abused for privilege escalation.

#### Audit Loopback GPOs

```powershell
# Find GPOs with loopback processing enabled
Get-GPO -All | ForEach-Object {
    [xml]$Report = Get-GPOReport -Name $_.DisplayName -ReportType Xml
    if ($Report.GPO.Computer.ExtensionData.Extension.Policy | Where-Object {$_.Name -eq "Loopback"}) {
        [PSCustomObject]@{
            GPOName = $_.DisplayName
            LoopbackMode = $Report.GPO.Computer.ExtensionData.Extension.Policy.State
        }
    }
}
```

---

### 5.4 GPO Versioning and Change Tracking

**GPO versioning** tracks changes (AD version vs SYSVOL version mismatch indicates replication issues).

```powershell
# Check GPO version consistency
Get-GPO -All | Select DisplayName,
    @{N='AD-Version';E={$_.User.DSVersion}},
    @{N='SYSVOL-Version';E={$_.User.SysvolVersion}},
    @{N='Match';E={$_.User.DSVersion -eq $_.User.SysvolVersion}}
```

#### GPO Change Auditing

```powershell
# Enable GPO change auditing
# Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy
# Policy Change > Audit Policy Change: Success, Failure

# Monitor Event ID 5136 for GPO modifications
```

---

### 5.5 GPO Backup and Recovery

```powershell
# Backup all GPOs
Backup-GPO -All -Path "C:\GPO-Backups\$(Get-Date -Format 'yyyy-MM-dd')"

# Backup specific GPO
Backup-GPO -Name "Default Domain Policy" -Path "C:\GPO-Backups"

# Restore GPO
Restore-GPO -Name "Default Domain Policy" -Path "C:\GPO-Backups\{GUID}"

# Automated daily backup
$Task = {
    Backup-GPO -All -Path "\\fileserver\GPO-Backups\$(Get-Date -Format 'yyyy-MM-dd')"
}
$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "GPO-Backup" -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\Backup-GPOs.ps1") -Trigger $Trigger
```

---

### 5.6 Remove Legacy GPP Passwords

**Group Policy Preferences (GPP)** stored passwords in SYSVOL (encrypted with published AES key - **MS14-025**).

```powershell
# Find GPP passwords in SYSVOL
Get-ChildItem -Path "\\corp.local\SYSVOL\corp.local\Policies" -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" |
    Select-String -Pattern "cpassword"

# Manually review and remove GPPs with passwords
# Replace with LAPS or gMSA
```

---

## 6. 🔒 AD CS Hardening

**Active Directory Certificate Services (AD CS)** is a common attack vector (ESC1-ESC13 vulnerabilities).

### 6.1 Certificate Template Hardening

#### Vulnerable Template Indicators

- **ESC1**: Subject Alternative Name (SAN) enabled + low-privilege enrollment
- **ESC2**: Any Purpose EKU or No EKU + low-privilege enrollment
- **ESC3**: Enrollment agent templates + low-privilege enrollment
- **ESC4**: Vulnerable ACLs on templates (GenericWrite, WriteProperty)

#### Audit Certificate Templates

```powershell
# List all certificate templates
certutil -Template

# Detailed template analysis with Certify (offensive tool, defensive use)
.\Certify.exe find /vulnerable

# Check for ESC1 (SAN enabled)
Get-ADObject -Filter {objectClass -eq "pKICertificateTemplate"} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Properties msPKI-Certificate-Name-Flag |
    Where-Object {$_."msPKI-Certificate-Name-Flag" -band 1} |  # ENROLLEE_SUPPLIES_SUBJECT
    Select Name,DistinguishedName
```

#### Harden Certificate Templates

```powershell
# Disable SAN for vulnerable templates
# Certificate Templates Console > Right-click template > Properties > Subject Name
# Uncheck "Supply in the request"

# Require Manager Approval
# Certificate Templates Console > Right-click template > Properties > Issuance Requirements
# Check "CA certificate manager approval"

# Restrict enrollment to specific groups
# Certificate Templates Console > Right-click template > Properties > Security
# Remove "Domain Users" and add specific groups
```

---

### 6.2 Manager Approval Requirements

```powershell
# Enable manager approval for high-risk templates
certutil -SetCAtemplateApproval <TemplateName> +ManagerApproval

# Verify
certutil -Template <TemplateName>
```

---

### 6.3 Certificate Issuance Policies

**Issuance policies** require additional verification before issuing certificates.

```powershell
# Create issuance policy
New-ADObject -Name "High-Assurance-Policy" -Type msPKI-Enterprise-Oid -Path "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -OtherAttributes @{
    'DisplayName'='High Assurance Policy';
    'msPKI-Cert-Template-OID'='1.3.6.1.4.1.311.21.8.1234567.1'
}

# Apply to certificate template
# Certificate Templates Console > Right-click template > Properties > Issuance Requirements
# Select "This number of authorized signatures: 2"
```

---

### 6.4 Detection: Certify/Certipy Usage

```kql
// Detect certutil.exe usage (certificate enumeration)
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("template", "-TCAInfo", "-CAInfo", "Certificate Templates")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine

// Detect suspicious certificate requests
SecurityEvent
| where EventID == 4886  // Certificate Services received a certificate request
| where CertificateTemplate in (VulnerableTemplates)  // Define list of sensitive templates
| project TimeGenerated, RequesterName, CertificateTemplate, Computer
```

---

### 6.5 ESC1-ESC13 Mitigation Summary

| Escalation | Description | Mitigation |
|------------|-------------|------------|
| **ESC1** | SAN abuse | Disable "Supply in request" for Subject Alternative Name |
| **ESC2** | Any Purpose EKU | Restrict EKU to specific purposes |
| **ESC3** | Enrollment agent abuse | Remove enrollment agent templates or restrict enrollment |
| **ESC4** | Template ACL abuse | Audit ACLs on templates, remove GenericWrite/WriteProperty |
| **ESC5** | CA object ACL abuse | Restrict WriteDACL/WriteOwner on CA object |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 flag | Disable flag: `certutil -config "CA\Server" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` |
| **ESC7** | CA permissions abuse | Restrict ManageCA and ManageCertificates rights |
| **ESC8** | NTLM relay to AD CS HTTP endpoints | Enable EPA (Extended Protection for Authentication) on CA |
| **ESC9** | No security extension in certificate | Enable security extension via template settings |
| **ESC10** | Weak certificate mappings | Enforce strong certificate mappings (KB5014754) |
| **ESC11** | IF_ENFORCEENCRYPTICERTREQUEST not set | Enable flag to require encrypted certificate requests |
| **ESC13** | Issuance policy bypass | Properly configure issuance policies and approval workflows |

---

### 6.6 CA Security and Monitoring

```powershell
# Enable CA auditing
certutil -setreg CA\AuditFilter 127  # Enable all auditing

# Monitor critical CA events
# Event ID 4886: Certificate request received
# Event ID 4887: Certificate approved and issued
# Event ID 4888: Certificate request denied
# Event ID 4890: Certificate Services property changed
```

---

## 7. 🚷 NTLM Mitigation

**NTLM is legacy and vulnerable** to relay, cracking, and pass-the-hash attacks. Transition to Kerberos.

### 7.1 NTLM Usage Auditing

#### Enable NTLM Auditing

```powershell
# Via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Restrict NTLM: Audit NTLM authentication in this domain: Enable all
# Network security: Restrict NTLM: Audit Incoming NTLM Traffic: Enable auditing for all accounts

# Monitor Event ID 8004 (NTLM authentication audit)
```

#### Identify NTLM Usage

```powershell
# Parse NTLM audit events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NTLM/Operational'; ID=8004} |
    Select TimeCreated,@{N='User';E={$_.Properties[0].Value}},@{N='Domain';E={$_.Properties[1].Value}},@{N='Workstation';E={$_.Properties[2].Value}} |
    Group-Object User,Workstation | Sort Count -Descending
```

---

### 7.2 Gradual NTLM Blocking

**Phase 1: Audit** → **Phase 2: Deny specific accounts** → **Phase 3: Block domain-wide**

```powershell
# Phase 1: Audit mode (already enabled above)

# Phase 2: Deny NTLM for Tier 0 accounts
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Restrict NTLM: NTLM authentication in this domain: Deny for domain accounts to domain servers

# Phase 3: Block NTLM domain-wide
# GPO: Network security: Restrict NTLM: NTLM authentication in this domain: Deny all
```

---

### 7.3 SMB Signing Enforcement

**SMB signing** prevents SMB relay attacks (e.g., PetitPotam, PrinterBug).

```powershell
# Enable SMB signing via GPO (both client and server)
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Microsoft network client: Digitally sign communications (always): Enabled
# Microsoft network server: Digitally sign communications (always): Enabled

# Verify SMB signing status
Get-SmbServerConfiguration | Select EnableSecuritySignature,RequireSecuritySignature
Get-SmbClientConfiguration | Select EnableSecuritySignature,RequireSecuritySignature
```

---

### 7.4 LDAP Signing and Channel Binding

**LDAP signing** prevents LDAP relay attacks. **Channel binding** ties LDAP session to TLS channel.

```powershell
# Enable LDAP signing on Domain Controllers
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Domain controller: LDAP server signing requirements: Require signature

# Enable LDAP channel binding
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name LdapEnforceChannelBinding
```

---

### 7.5 EPA (Extended Protection for Authentication)

EPA prevents NTLM relay to AD CS HTTP enrollment endpoints.

```powershell
# Enable EPA on CA web enrollment
# IIS Manager > Sites > Default Web Site > CertSrv
# Authentication > Windows Authentication > Advanced Settings
# Extended Protection: Required

# Verify via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" /v EnableCertificateChainBinding /t REG_DWORD /d 1 /f
```

---

### 7.6 Disable LM Hash Storage

**LM hashes** are extremely weak (max 14 chars, case-insensitive, DES-based).

```powershell
# Disable LM hash storage via GPO
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Do not store LAN Manager hash value on next password change: Enabled

# Force password change to clear existing LM hashes
Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true
```

---

## 8. 🍯 Detection Strategies (Deception)

**Deception** creates high-fidelity alerts by detecting access to honeypot resources.

### 8.1 Honey Accounts

**Honey admin accounts** appear privileged but are monitored for any usage.

```powershell
# Create honey Domain Admin account
New-ADUser -Name "DA-Backup" -SamAccountName "da-backup" -AccountPassword (ConvertTo-SecureString "NeverUsedPassword123!" -AsPlainText -Force) -Enabled $true

# Add to Domain Admins (but never use!)
Add-ADGroupMember -Identity "Domain Admins" -Members "da-backup"

# Set description to look legitimate
Set-ADUser -Identity "da-backup" -Description "Legacy backup account - DO NOT USE"

# Alert on ANY authentication
# Monitor Event ID 4624 for this account
```

#### Detection: Honey Account Usage

```kql
SecurityEvent
| where EventID == 4624
| where TargetUserName =~ "da-backup"
| project TimeGenerated, TargetUserName, IpAddress, WorkstationName, LogonType, Computer
| extend Severity = "Critical"
```

---

### 8.2 Honey Tokens (Canary Credentials)

**Honey tokens** are fake credentials embedded in files, scripts, or registry.

#### Example: Fake Credentials in Registry

```powershell
# Create fake RDP credentials in registry
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v FakeUsername /t REG_SZ /d "corp\svc-admin" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v FakePassword /t REG_SZ /d "P@ssw0rd123!" /f

# Create honey token user account
New-ADUser -Name "svc-admin" -SamAccountName "svc-admin" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true

# Alert on ANY usage
```

#### Example: Fake AWS Credentials

```powershell
# Create fake AWS config file on servers
$FakeAWS = @"
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"@

Set-Content -Path "C:\Users\Administrator\.aws\credentials" -Value $FakeAWS

# Monitor AWS CloudTrail for usage of fake credentials
```

---

### 8.3 Deception Objects (Fake Admin Accounts)

```powershell
# Create fake admin accounts in "Domain Admins" OU
New-ADUser -Name "Administrator-Backup" -SamAccountName "admin-bak" -Path "CN=Users,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "Decoy123!" -AsPlainText -Force) -Enabled $true

# Set AdminCount to make it look protected
Set-ADUser -Identity "admin-bak" -Replace @{AdminCount=1}

# Do NOT add to any groups (just looks privileged)
```

---

### 8.4 Canary Files (Monitored Sensitive Documents)

**Canary files** are fake sensitive documents monitored for access.

```powershell
# Create fake "passwords.txt" file
$FakePasswords = @"
Domain Admin Credentials
========================
Username: administrator
Password: Summer2024!

SQL SA Password: SQLAdmin2024!
"@

Set-Content -Path "\\fileserver\IT-Share\Passwords.txt" -Value $FakePasswords

# Enable SACL auditing on file
$ACL = Get-Acl "\\fileserver\IT-Share\Passwords.txt"
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "Read", "Success")
$ACL.AddAuditRule($AuditRule)
Set-Acl "\\fileserver\IT-Share\Passwords.txt" -AclObject $ACL

# Monitor Event ID 4663 (object access attempt)
```

---

### 8.5 Fake SPNs for Detection

**Fake SPNs** with enticing names trigger alerts when Kerberoasted.

```powershell
# Create fake service account with weak password
New-ADUser -Name "svc-SQLProd" -SamAccountName "svc-sqlprod" -AccountPassword (ConvertTo-SecureString "WeakPassword1" -AsPlainText -Force) -Enabled $true

# Set fake SPN
Set-ADUser -Identity "svc-sqlprod" -ServicePrincipalNames @{Add="MSSQLSvc/sqlprod.corp.local:1433"}

# Alert on TGS requests for this SPN (Event ID 4769)
```

#### Detection: Kerberoasting Honey SPN

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName =~ "MSSQLSvc/sqlprod.corp.local"
| project TimeGenerated, Account, IpAddress, ServiceName, TicketEncryptionType
| extend Severity = "Critical", Alert = "Kerberoasting detected on honey SPN"
```

---

## 9. 📊 Logging & Monitoring

### 9.1 Advanced Audit Policy Configuration

**Default audit policies are insufficient.** Use Advanced Audit Policies.

#### Enable via GPO

```powershell
# Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration

# Account Logon
Audit Credential Validation: Success, Failure
Audit Kerberos Authentication Service: Success, Failure
Audit Kerberos Service Ticket Operations: Success, Failure

# Account Management
Audit Computer Account Management: Success, Failure
Audit Security Group Management: Success, Failure
Audit User Account Management: Success, Failure

# DS Access
Audit Directory Service Access: Success, Failure
Audit Directory Service Changes: Success, Failure

# Logon/Logoff
Audit Logon: Success, Failure
Audit Logoff: Success
Audit Special Logon: Success, Failure

# Object Access
Audit File Share: Success, Failure
Audit File System: Success, Failure (only on sensitive files with SACL)

# Policy Change
Audit Audit Policy Change: Success, Failure
Audit Authentication Policy Change: Success, Failure

# Privilege Use
Audit Sensitive Privilege Use: Success, Failure

# System
Audit Security State Change: Success, Failure
Audit Security System Extension: Success, Failure
```

---

### 9.2 Critical Event IDs Monitoring

#### 9.2.1 Logon Events (4624/4625)

```kql
// Detect brute-force attacks (multiple 4625 failures)
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts=count() by IpAddress, TargetUserName, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| project TimeGenerated, IpAddress, TargetUserName, FailedAttempts
```

#### 9.2.2 Kerberos Events (4768/4769)

```kql
// Detect Golden Ticket usage (TGT request outside business hours)
SecurityEvent
| where EventID == 4768
| where TimeGenerated > ago(24h)
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 6 or Hour > 22  // Outside 6am-10pm
| where TargetUserName !endswith "$"  // Exclude computer accounts
| project TimeGenerated, TargetUserName, IpAddress, TicketEncryptionType
```

#### 9.2.3 NTLM Authentication (4776)

```kql
// Detect NTLM usage from Tier 0 accounts (should be Kerberos only)
SecurityEvent
| where EventID == 4776
| where TargetUserName in (Tier0Accounts)
| project TimeGenerated, TargetUserName, Workstation, Status
```

#### 9.2.4 Special Privileges Assigned (4672)

```kql
// Detect privilege escalation (4672 without corresponding 4624)
let Logons = SecurityEvent
    | where EventID == 4624
    | project LogonTime=TimeGenerated, LogonId=TargetLogonId;
SecurityEvent
| where EventID == 4672
| where PrivilegeList has "SeDebugPrivilege" or PrivilegeList has "SeTcbPrivilege"
| join kind=leftanti Logons on $left.SubjectLogonId == $right.LogonId
| project TimeGenerated, SubjectUserName, PrivilegeList, Computer
```

#### 9.2.5 Account Created/Deleted (4720/4726)

```kql
// Detect account creation outside change window
SecurityEvent
| where EventID == 4720
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 8 or Hour > 18  // Outside business hours
| project TimeGenerated, SubjectUserName, TargetUserName, Computer
```

#### 9.2.6 User Account Changed (4738)

```kql
// Detect privilege escalation via AdminCount modification
SecurityEvent
| where EventID == 4738
| where TargetUserName !endswith "$"
| extend Changes = parse_json(AdditionalInfo)
| where Changes contains "AdminCount"
| project TimeGenerated, SubjectUserName, TargetUserName, Changes, Computer
```

#### 9.2.7 Directory Service Object Modified (5136)

```kql
// Detect ACL modifications on sensitive objects
SecurityEvent
| where EventID == 5136
| where ObjectDN has_any ("CN=Domain Admins", "CN=Enterprise Admins", "CN=AdminSDHolder")
| where AttributeLDAPDisplayName in ("nTSecurityDescriptor", "member", "msDS-AllowedToActOnBehalfOfOtherIdentity")
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue, Computer
```

---

### 9.3 SACL (System Access Control List) Monitoring

**SACLs** enable object-level auditing (files, folders, registry keys, AD objects).

#### Enable SACL on Sensitive AD Objects

```powershell
# Enable auditing on Domain Admins group
$Group = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
$ACL = Get-Acl "AD:\$Group"
$AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-1-0",  # Everyone
    [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty,GenericWrite,WriteDacl,WriteOwner",
    [System.Security.AccessControl.AuditFlags]"Success,Failure",
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
)
$ACL.AddAuditRule($AuditRule)
Set-Acl "AD:\$Group" -AclObject $ACL
```

#### Enable SACL on Sensitive Files

```powershell
# Enable auditing on sensitive file
$File = "\\fileserver\IT-Share\Domain-Admin-Passwords.xlsx"
$ACL = Get-Acl $File
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Read,Write,Delete",
    "Success,Failure"
)
$ACL.AddAuditRule($AuditRule)
Set-Acl $File -AclObject $ACL
```

---

### 9.4 PowerShell Logging

**PowerShell is the #1 post-exploitation tool.** Comprehensive logging is critical.

#### Enable All PowerShell Logging

```powershell
# Via GPO: Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell

# Script Block Logging
Turn on PowerShell Script Block Logging: Enabled
Log script block invocation start / stop events: Enabled

# Module Logging
Turn on Module Logging: Enabled
Module Names: * (all modules)

# Transcription
Turn on PowerShell Transcription: Enabled
Transcript output directory: \\fileserver\PSTranscripts
Include invocation headers: Enabled
```

#### Detection: Malicious PowerShell Activity

```kql
// Detect PowerShell obfuscation
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID in (4103, 4104)
| where EventData has_any ("FromBase64String", "Invoke-Expression", "DownloadString", "EncodedCommand", "-enc", "-e ", "bypass", "hidden")
| project TimeGenerated, Computer, UserName, EventData
```

```xml
<!-- Sigma rule for PowerShell download cradle -->
<rule>
  <title>PowerShell Download Cradle</title>
  <logsource>
    <product>windows</product>
    <service>powershell</service>
  </logsource>
  <detection>
    <selection>
      <EventID>4104</EventID>
      <ScriptBlockText>
        - "*DownloadString*"
        - "*DownloadFile*"
        - "*WebClient*"
        - "*Invoke-WebRequest*"
        - "*Invoke-RestMethod*"
      </ScriptBlockText>
    </selection>
    <condition>selection</condition>
  </detection>
  <level>high</level>
</rule>
```

---

### 9.5 Command-Line Process Auditing

**Command-line logging** captures full command executed (critical for detecting lateral movement).

```powershell
# Enable via GPO: Computer Configuration > Policies > Administrative Templates > System > Audit Process Creation
# Include command line in process creation events: Enabled

# Monitor Event ID 4688 (Process Creation)
```

#### Detection: Credential Dumping Tools

```kql
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "procdump.exe", "dumpert.exe", "sqldumper.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName

// Detect lsass.exe dumping
DeviceProcessEvents
| where ProcessCommandLine has_any ("lsass", "lsass.exe", "lsass.dmp")
| where FileName in~ ("procdump.exe", "procdump64.exe", "taskmgr.exe", "rundll32.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## 10. 🔬 Sysmon Configuration

**Sysmon** provides detailed endpoint telemetry (process creation, network connections, registry modifications, etc.).

### 10.1 Sysmon Installation

```powershell
# Download Sysmon from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with SwiftOnSecurity config (widely used baseline)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\sysmon-config.xml"

sysmon64.exe -accepteula -i C:\sysmon-config.xml

# Update configuration
sysmon64.exe -c C:\sysmon-config-updated.xml
```

---

### 10.2 Critical Sysmon Event IDs

| Event ID | Description | Use Case |
|----------|-------------|----------|
| **1** | Process Creation | Detect malicious executables, living-off-the-land binaries (LOLBins) |
| **2** | File Creation Time Changed | Detect timestomping (anti-forensics) |
| **3** | Network Connection | Detect C2 beacons, lateral movement |
| **5** | Process Terminated | Track process lifecycle |
| **7** | Image Loaded | Detect DLL injection, reflective loading |
| **8** | CreateRemoteThread | Detect process injection |
| **10** | Process Access | Detect credential dumping (lsass.exe access) |
| **11** | File Created | Detect malware dropping files |
| **12/13/14** | Registry Events | Detect persistence mechanisms |
| **15** | File Stream Created | Detect Alternate Data Streams (ADS) |
| **17/18** | Pipe Events | Detect named pipe usage (Cobalt Strike, Meterpreter) |
| **19/20/21** | WMI Events | Detect WMI persistence |
| **22** | DNS Query | Detect C2 DNS beacons |
| **23** | File Delete | Detect log deletion, evidence destruction |

---

### 10.3 Process Creation (Event ID 1)

```kql
// Detect LOLBins (Living Off the Land Binaries)
DeviceProcessEvents
| where FileName in~ ("regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "cscript.exe", "wscript.exe", "powershell.exe", "cmd.exe")
| where ProcessCommandLine has_any ("http://", "https://", "\\\\", "copy", "download", "-enc", "bypass", "FromBase64")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

### 10.4 Network Connections (Event ID 3)

```kql
// Detect C2 beaconing (regular intervals)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| extend DestinationIp = tostring(EventData.DestinationIp)
| summarize ConnectionCount=count() by DestinationIp, bin(TimeGenerated, 1m)
| where ConnectionCount > 5  // More than 5 connections per minute
| project TimeGenerated, DestinationIp, ConnectionCount
```

---

### 10.5 Registry Modifications (Event ID 13)

```kql
// Detect persistence via registry Run keys
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend TargetObject = tostring(EventData.TargetObject)
| where TargetObject has_any ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
| project TimeGenerated, Computer, ProcessName, TargetObject, Details
```

---

### 10.6 File Creation Time (Event ID 2)

**Timestomping** is an anti-forensics technique to hide malware.

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 2
| extend TargetFilename = tostring(EventData.TargetFilename)
| extend CreationUtcTime = tostring(EventData.CreationUtcTime)
| extend PreviousCreationUtcTime = tostring(EventData.PreviousCreationUtcTime)
| where PreviousCreationUtcTime != CreationUtcTime
| project TimeGenerated, Computer, ProcessName, TargetFilename, CreationUtcTime, PreviousCreationUtcTime
```

---

### 10.7 DNS Queries (Event ID 22)

```kql
// Detect DNS tunneling or C2 via DNS
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 22
| extend QueryName = tostring(EventData.QueryName)
| extend QueryResults = tostring(EventData.QueryResults)
| where strlen(QueryName) > 50  // Unusually long DNS queries (potential tunneling)
| project TimeGenerated, Computer, ProcessName, QueryName, QueryResults
```

---

### 10.8 Sysmon for AD-Specific Monitoring

**Custom Sysmon rules** for AD attack detection:

```xml
<!-- Sysmon config snippet for AD attacks -->
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Detect Mimikatz execution -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">mimikatz</Image>
      <CommandLine condition="contains">sekurlsa</CommandLine>
      <CommandLine condition="contains">lsadump</CommandLine>
    </ProcessCreate>

    <!-- Detect DCSync attack (replication) -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">lsadump::dcsync</CommandLine>
    </ProcessCreate>

    <!-- Detect BloodHound/SharpHound execution -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">SharpHound</Image>
      <CommandLine condition="contains">-c All</CommandLine>
      <CommandLine condition="contains">--CollectionMethod</CommandLine>
    </ProcessCreate>

    <!-- Detect NTDS.dit extraction -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">ntds.dit</TargetFilename>
      <TargetFilename condition="contains">SYSTEM.hive</TargetFilename>
    </FileCreate>

    <!-- Detect Kerberoasting (certutil, Add-Type) -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">-encodedCommand</CommandLine>
      <CommandLine condition="contains">Kerberos</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 11. 🛡️ EDR/XDR Deployment

### 11.1 Microsoft Defender for Identity (MDI)

**MDI** monitors AD traffic and detects:
- Pass-the-Hash, Pass-the-Ticket
- Golden Ticket, Silver Ticket
- DCSync, DCShadow
- Skeleton Key
- Reconnaissance (BloodHound, SharpHound, Invoke-UserHunter)
- Lateral movement (Remote Execution, WMI, PSRemoting)

#### Deployment

```powershell
# Install MDI sensor on Domain Controllers
# Download from: https://portal.atp.azure.com

# Install silently
Azure ATP sensor Setup.exe /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<YourAccessKey>"

# Verify installation
Get-Service -Name "AATPSensor"

# Configure Directory Service Account (DSA) for event log reading
# MDI Portal > Configuration > Directory Services > Add account with "Read" permissions
```

#### MDI Alert Categories

| Alert | Description | Severity |
|-------|-------------|----------|
| **Reconnaissance** | Network mapping, user enumeration, BloodHound | Medium |
| **Compromised Credentials** | Brute-force, password spray | High |
| **Lateral Movement** | Pass-the-Hash, Pass-the-Ticket, Over-pass-the-Hash | High |
| **Domain Dominance** | Golden Ticket, DCSync, DCShadow, Skeleton Key | Critical |

---

### 11.2 Microsoft Defender for Endpoint (MDE)

**MDE** provides endpoint detection and response (EDR).

```powershell
# Onboard devices via Group Policy
# Download onboarding package from: https://security.microsoft.com
# GPO: Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Defender ATP
# Onboarding: Enabled, upload onboarding blob

# Verify onboarding
sc query sense

# Check MDE status
Get-MpComputerStatus
```

#### MDE Advanced Hunting Queries for AD Attacks

```kql
// Detect Pass-the-Hash via lateral movement
DeviceLogonEvents
| where LogonType == "Network"
| where AccountName !endswith "$"
| summarize UniqueDevices=dcount(DeviceName) by AccountName, bin(TimeGenerated, 1h)
| where UniqueDevices > 5

// Detect credential dumping tools
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "procdump.exe", "dumpert.exe", "pypykatz.exe", "nanodump.exe")
    or ProcessCommandLine has_any ("sekurlsa", "lsadump", "lsass", "comsvcs.dll MiniDump")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256

// Detect DCSync attack
DeviceEvents
| where ActionType == "DcSyncAttempt"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, AdditionalFields
```

---

### 11.3 Azure AD Identity Protection

**Azure AD Identity Protection** detects risky sign-ins and users (cloud-focused).

- Anonymous IP addresses
- Atypical travel
- Leaked credentials
- Password spray
- Impossible travel

```powershell
# Enable via Azure Portal
# Azure AD > Security > Identity Protection > User risk policy / Sign-in risk policy

# Require MFA for medium/high risk
# Block access for high-risk users
```

---

### 11.4 Third-Party EDR Integration

**CrowdStrike, SentinelOne, Carbon Black** provide advanced detection capabilities.

#### CrowdStrike Falcon IOAs for AD Attacks

- **DCSync Detection**: Replication requests from non-DC sources
- **Golden Ticket**: Abnormal TGT encryption types or lifetimes
- **Kerberoasting**: Excessive TGS requests for SPNs
- **Pass-the-Hash**: NTLM authentication from privileged accounts

---

### 11.5 SIEM Integration

**Centralized logging** via Splunk, ELK, QRadar, or Azure Sentinel.

```powershell
# Forward Windows Event Logs to Splunk via Universal Forwarder
# Install Splunk Universal Forwarder
# Configure inputs.conf:

[WinEventLog://Security]
disabled = false
index = windows_security

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = sysmon

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = false
index = powershell
```

#### Azure Sentinel Data Connectors

- Windows Security Events
- Microsoft Defender for Identity
- Microsoft Defender for Endpoint
- Azure Active Directory
- Office 365
- Sysmon

---

## 12. 🔎 Threat Hunting

### 12.1 BloodHound Community Edition Attack Paths

**Regular BloodHound scans** identify new attack paths before adversaries do.

```powershell
# Monthly BloodHound scan from privileged account
.\SharpHound.exe --CollectionMethod All --Domain corp.local --LdapUsername admin --LdapPassword P@ssw0rd --OutputDirectory C:\BH-Output

# Compare with previous month's scan
# Look for new edges to Domain Admins
# Investigate newly granted ACLs (GenericAll, WriteDacl, WriteOwner)
```

#### Defensive BloodHound Queries

```cypher
// Find shortest paths to Domain Admins
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
WHERE NOT u.name = g.name
RETURN p
ORDER BY length(p)

// Find users with DCSync rights
MATCH p=(u)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain)
RETURN p

// Find Tier 0 accounts without "Cannot be delegated" flag
MATCH (u:User)
WHERE u.admincount = true AND u.sensitive = false
RETURN u.name

// Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name
```

---

### 12.2 Purple Knight AD Security Assessment

**Purple Knight** (Semperis) provides AD security posture scoring.

```powershell
# Download from: https://www.purple-knight.com/

# Run assessment
.\PurpleKnight.exe

# Review HTML report for:
# - Delegation risks
# - Privileged account exposure
# - GPO vulnerabilities
# - Replication issues
# - Certificate Services risks
```

---

### 12.3 PingCastle Risk Scoring

**PingCastle** generates a maturity score (0-100) based on:
- **Stale objects** (inactive accounts, old passwords)
- **Privileged accounts** (over-privileged users, weak passwords)
- **Trusts** (external trusts, SID history)
- **Anomalies** (pre-Windows 2000 groups, AdminSDHolder misconfigurations)

#### Automated Remediation Tracking

```powershell
# Run monthly PingCastle scans
# Track score improvement over time
# Prioritize "Critical" and "High" findings

# Example remediation workflow:
# 1. Run PingCastle
# 2. Export findings to CSV
# 3. Create tickets in ITSM system
# 4. Remediate
# 5. Re-scan to verify
# 6. Repeat monthly
```

---

### 12.4 IOC Hunting for Known Tools

**Indicator of Compromise (IOC)** hunting for common AD attack tools.

```kql
// Hunt for Mimikatz, Rubeus, SharpHound, Certify
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "rubeus.exe", "sharphound.exe", "certify.exe", "pypykatz.exe")
    or SHA256 in ("<Mimikatz-SHA256>", "<Rubeus-SHA256>", "<SharpHound-SHA256>")
    or ProcessCommandLine has_any ("sekurlsa", "kerberos", "asktgt", "asktgs", "ptt", "dcsync", "lsadump", "CollectionMethod")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256

// Hunt for Impacket tools (secretsdump, GetNPUsers, GetUserSPNs)
DeviceProcessEvents
| where ProcessCommandLine has_any ("secretsdump.py", "GetNPUsers.py", "GetUserSPNs.py", "ntlmrelayx.py", "smbexec.py", "psexec.py")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine

// Hunt for PowerView/PowerSploit
DeviceProcessEvents
| where ProcessCommandLine has_any ("Invoke-UserHunter", "Invoke-ShareFinder", "Get-DomainUser", "Get-NetUser", "Get-DomainComputer", "Find-LocalAdminAccess", "Invoke-Kerberoast")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

---

### 12.5 Behavioral Anomaly Detection

**Machine learning-based anomaly detection** for:
- Abnormal logon times
- Abnormal logon locations
- Abnormal resource access
- Lateral movement patterns

```kql
// Detect abnormal logon times for users
let UserBaseline = SecurityEvent
    | where TimeGenerated > ago(30d)
    | where EventID == 4624
    | extend Hour = datetime_part("hour", TimeGenerated)
    | summarize TypicalHours=make_set(Hour) by TargetUserName;
SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(1d)
| extend Hour = datetime_part("hour", TimeGenerated)
| join kind=inner UserBaseline on TargetUserName
| where not(set_has_element(TypicalHours, Hour))
| project TimeGenerated, TargetUserName, IpAddress, Hour, TypicalHours
```

---

### 12.6 Sigma Rules for AD Attacks

**Sigma** is a generic signature format for SIEM rules.

#### Example: DCSync Attack Detection

```yaml
title: DCSync Attack Detected
id: 82e55d48-e4e0-4f3d-a7e2-7c4e3b2f6a1d
status: stable
description: Detects DCSync attack via replication permissions abuse
references:
    - https://attack.mitre.org/techniques/T1003/006/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        AccessMask: '0x100'
        Properties:
            - '*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*'  # DS-Replication-Get-Changes
            - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'  # DS-Replication-Get-Changes-All
            - '*89e95b76-444d-4c62-991a-0facbeda640c*'  # DS-Replication-Get-Changes-In-Filtered-Set
    filter:
        SubjectUserName: '*$'  # Exclude computer accounts (DCs)
    condition: selection and not filter
falsepositives:
    - Legitimate AD replication monitoring tools
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006
```

---

## 13. 🚨 Incident Response

### 13.1 Containment Strategies

#### Immediate Actions (First 15 minutes)

1. **Isolate compromised systems** (disable network adapter or firewall block)
2. **Disable compromised accounts** (not delete - preserves evidence)
3. **Reset krbtgt password** (if Golden Ticket suspected)
4. **Block attacker IP addresses** at firewall
5. **Snapshot running systems** for forensics

```powershell
# Disable compromised user account
Disable-ADAccount -Identity "compromised-user"

# Disable computer account
Disable-ADAccount -Identity "WORKSTATION01$"

# Block network access via Windows Firewall (remotely)
Invoke-Command -ComputerName "WORKSTATION01" -ScriptBlock {
    New-NetFirewallRule -DisplayName "Block-All-Inbound" -Direction Inbound -Action Block
    New-NetFirewallRule -DisplayName "Block-All-Outbound" -Direction Outbound -Action Block
}

# Snapshot VM (if virtualized)
Checkpoint-VM -Name "WORKSTATION01" -SnapshotName "IR-$(Get-Date -Format 'yyyy-MM-dd-HHmm')"
```

---

### 13.2 Mass Credential Reset Procedures

**When domain compromise is suspected**, reset all credentials in phases.

#### Phase 1: Tier 0 Accounts (Immediate)

```powershell
# Reset all Tier 0 admin passwords
$Tier0Admins = Get-ADGroupMember -Identity "Domain Admins" -Recursive
foreach ($Admin in $Tier0Admins) {
    $NewPassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
    Set-ADAccountPassword -Identity $Admin -NewPassword $NewPassword -Reset
    Set-ADUser -Identity $Admin -ChangePasswordAtLogon $true
    Write-Host "Reset password for: $($Admin.SamAccountName)"
}
```

#### Phase 2: Service Accounts (within 24 hours)

```powershell
# Reset all non-gMSA service accounts
$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
    Where-Object {$_.DistinguishedName -notlike "*Managed Service Accounts*"}

foreach ($Account in $ServiceAccounts) {
    # Coordinate with application owners before resetting!
    Write-Host "Service account requires reset: $($Account.SamAccountName) - SPN: $($Account.ServicePrincipalName)"
}
```

#### Phase 3: Regular User Accounts (within 48 hours)

```powershell
# Force password change for all users
Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true
```

---

### 13.3 Golden Ticket Detection and Remediation

**Golden Ticket** attacks forge TGTs by compromising the `krbtgt` account hash.

#### Detection Indicators

- **TGT lifetime exceeds policy** (Event ID 4768 with unusual TicketOptions)
- **TGT encrypted with RC4** (should be AES if enforced)
- **TGT from non-existent user** or disabled account
- **TGT outside normal business hours** for specific user

```kql
// Detect Golden Ticket usage
SecurityEvent
| where EventID == 4768
| extend TicketOptions = tostring(TicketOptions)
| extend TicketEncryptionType = tostring(TicketEncryptionType)
| where TicketEncryptionType == "0x17"  // RC4 (Golden Tickets often use RC4)
    or TicketOptions == "0x40810000"  // Forwardable, Renewable, Initial flags
| where TargetUserName !endswith "$"
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | extend LogonTime = TimeGenerated
) on $left.TargetUserName == $right.TargetUserName
| where TimeGenerated < LogonTime  // TGT issued before logon
| project TimeGenerated, TargetUserName, IpAddress, TicketEncryptionType, TicketOptions
```

#### Remediation: krbtgt Password Reset (TWICE!)

**Critical**: Reset `krbtgt` password **twice** to invalidate all existing TGTs.

```powershell
# Reset krbtgt password (first time)
$NewPassword1 = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
Set-ADAccountPassword -Identity "krbtgt" -NewPassword $NewPassword1 -Reset

# Wait for replication to complete (check with repadmin)
repadmin /syncall /AeD

# Wait 10 hours (maximum TGT lifetime) OR reduce TGT lifetime temporarily
Set-ADDomain -Identity "corp.local" -MaxTicketAge "00:10:00"  # 10 minutes

# Reset krbtgt password (second time)
$NewPassword2 = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
Set-ADAccountPassword -Identity "krbtgt" -NewPassword $NewPassword2 -Reset

# Wait for replication again
repadmin /syncall /AeD

# Restore original TGT lifetime
Set-ADDomain -Identity "corp.local" -MaxTicketAge "10:00:00"  # 10 hours
```

---

### 13.4 NTDS.dit Forensics

**NTDS.dit** is the AD database containing all password hashes. If exfiltrated, the domain is compromised.

#### Detection: NTDS.dit Access

```kql
// Detect NTDS.dit file access
DeviceFileEvents
| where FileName =~ "ntds.dit"
| where ActionType in ("FileCreated", "FileModified", "FileCopied")
| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, ActionType, InitiatingProcessFileName

// Detect VSS (Volume Shadow Copy) creation for NTDS.dit extraction
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin create shadow", "wmic shadowcopy call create", "ntdsutil snapshot")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

#### Forensic Analysis

```powershell
# Extract password hashes from NTDS.dit (forensic workstation only!)
# Use impacket-secretsdump:
secretsdump.py -ntds ntds.dit -system SYSTEM.hive LOCAL

# Analyze extracted hashes:
# - Identify weak passwords (compare against common password lists)
# - Identify privileged accounts with weak hashes
# - Determine scope of compromise
```

---

### 13.5 Timeline Reconstruction

**Event correlation** across multiple log sources (DC, workstations, network devices).

```kql
// Reconstruct attacker timeline
union SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents
| where TimeGenerated between (datetime(2025-01-08 14:00) .. datetime(2025-01-08 18:00))
| where AccountName == "compromised-user" or InitiatingProcessAccountName == "compromised-user"
| project TimeGenerated, EventType=Type, EventID, DeviceName, AccountName, ProcessCommandLine, RemoteIP, LogonType
| order by TimeGenerated asc
```

---

### 13.6 Evidence Preservation

**Chain of custody** for legal/compliance requirements.

```powershell
# Collect memory dump
procdump.exe -ma lsass.exe lsass_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss').dmp

# Collect event logs
wevtutil epl Security "C:\IR\Security_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\IR\Sysmon_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"

# Hash all evidence files
Get-ChildItem C:\IR\*.* | Get-FileHash -Algorithm SHA256 | Export-Csv C:\IR\evidence-hashes.csv

# Document collection in chain-of-custody log
```

---

## 14. 💾 Backup & Recovery

### 14.1 System State Backups (AD Database)

**Daily System State backups** of all Domain Controllers.

```powershell
# Install Windows Server Backup feature
Install-WindowsFeature Windows-Server-Backup

# Create System State backup
wbadmin start systemstatebackup -backupTarget:E:\AD-Backups -quiet

# Schedule daily backups
$Action = New-ScheduledTaskAction -Execute "wbadmin.exe" -Argument "start systemstatebackup -backupTarget:E:\AD-Backups -quiet"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "AD-SystemState-Backup" -Action $Action -Trigger $Trigger -User "SYSTEM"
```

---

### 14.2 Offline Backups (Secure Storage)

**Offline, immutable backups** protect against ransomware.

```powershell
# Backup to offline media (tape, air-gapped NAS, S3 Glacier)
# Use Azure Backup for cloud-based immutable backups

# Enable Azure Backup for AD
# Azure Portal > Recovery Services Vault > Backup > On-Premises > Active Directory
```

---

### 14.3 Forest Recovery Procedures

**Catastrophic forest recovery** (all DCs compromised or destroyed).

#### Forest Recovery Steps

1. **Isolate forest** (disconnect from network)
2. **Restore one DC per domain** from System State backup
3. **Seize FSMO roles** to restored DC
4. **Reset krbtgt password** (twice)
5. **Metadata cleanup** for destroyed DCs
6. **Rebuild remaining DCs**
7. **Validate replication**
8. **Restore trusts**

```powershell
# Seize all FSMO roles (on recovered DC)
Move-ADDirectoryServerOperationMasterRole -Identity "DC01" -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster -Force

# Metadata cleanup for destroyed DCs
ntdsutil
metadata cleanup
connections
connect to server DC01
quit
select operation target
list sites
select site 0
list servers in site
select server 1  # Destroyed DC
quit
remove selected server
quit
quit
```

---

### 14.4 DSRM Password Management

**Directory Services Restore Mode (DSRM)** password is the local admin password for DCs.

```powershell
# Reset DSRM password
ntdsutil
set dsrm password
reset password on server null
<new password>
<confirm password>
quit
quit

# Document DSRM password in secure vault (not in AD!)
```

---

### 14.5 Tombstone Lifetime Awareness

**Tombstone lifetime** determines how long deleted objects are retained (default: 180 days).

```powershell
# Check tombstone lifetime
(Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local" -Properties tombstoneLifetime).tombstoneLifetime

# Extend if necessary (for longer backup retention)
Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local" -Replace @{tombstoneLifetime=365}
```

**Warning**: Restoring backups older than tombstone lifetime causes **lingering objects** and replication issues.

---

### 14.6 Regular Restore Testing

**Test restores quarterly** to verify backup integrity.

```powershell
# Restore System State to lab environment
wbadmin start systemstaterecovery -version:01/08/2025-02:00 -backupTarget:E:\AD-Backups -machine:DC01

# Verify AD database integrity
ntdsutil
activate instance ntds
files
integrity
quit
quit

# Verify replication
repadmin /replsummary
```

---

## 15. 🔐 Zero Trust Architecture

### 15.1 Conditional Access Policies

**Azure AD Conditional Access** enforces context-based access controls.

```powershell
# Example: Require MFA for admins from untrusted locations
# Azure Portal > Azure AD > Security > Conditional Access > New Policy

# Policy settings:
# - Users: Domain Admins group
# - Cloud apps: All cloud apps
# - Conditions: Locations = Not trusted
# - Grant: Require multi-factor authentication
```

---

### 15.2 MFA Everywhere Enforcement

**Multi-Factor Authentication (MFA)** for ALL accounts (no exceptions).

```powershell
# Enable MFA for all users via Azure AD
# Azure Portal > Azure AD > Security > MFA > Additional cloud-based MFA settings
# Service settings > Verification options: Select all (Text message, Mobile app, etc.)

# Enforce MFA via Conditional Access
# New Policy > Grant > Require multi-factor authentication
```

---

### 15.3 JIT (Just-in-Time) Administration

**Privileged Identity Management (PIM)** provides time-limited admin access.

```powershell
# Enable Azure AD PIM
# Azure Portal > Azure AD > Privileged Identity Management > Azure AD roles

# Configure role settings:
# - Maximum activation duration: 2 hours
# - Require approval: Yes
# - Require MFA on activation: Yes
# - Require justification: Yes

# Request admin access (user experience)
# Azure Portal > PIM > My roles > Activate > Domain Admins (2 hours)
```

---

### 15.4 JEA (Just Enough Administration)

**JEA** restricts PowerShell sessions to specific cmdlets.

```powershell
# Example: Allow DNS admins to only manage DNS records
New-PSRoleCapabilityFile -Path "C:\JEA\DNSAdmin.psrc" -VisibleCmdlets @{
    Name = 'Add-DnsServerResourceRecord'
    Parameters = @{ Name = 'Name'; ValidateSet = 'A','CNAME','PTR' }
}, 'Remove-DnsServerResourceRecord', 'Get-DnsServerResourceRecord'

New-PSSessionConfigurationFile -Path "C:\JEA\DNSAdmin.pssc" `
    -SessionType RestrictedRemoteServer `
    -RoleDefinitions @{ 'CORP\DNSAdmins' = @{ RoleCapabilities = 'DNSAdmin' } }

Register-PSSessionConfiguration -Name DNSAdmin -Path "C:\JEA\DNSAdmin.pssc" -Force
```

---

### 15.5 Network Segmentation

**VLANs and firewall rules** isolate Tier 0 assets.

```
Tier 0 VLAN (10.0.0.0/24):
- Domain Controllers
- AD CS Servers
- Azure AD Connect Server
- PAWs

Tier 1 VLAN (10.1.0.0/24):
- Application Servers
- Database Servers
- Jump Servers

Tier 2 VLAN (10.2.0.0/24):
- User Workstations
```

**Firewall Rules**:
- Tier 2 → Tier 1: Allowed (specific ports)
- Tier 2 → Tier 0: **DENIED** (except Kerberos, LDAP from workstations)
- Tier 1 → Tier 0: Allowed (specific ports)
- Tier 0 → Tier 1/2: Allowed (management traffic)

---

### 15.6 Micro-Segmentation

**Application-level segmentation** via Windows Defender Firewall with Advanced Security.

```powershell
# Allow only specific IPs to access DC LDAP
New-NetFirewallRule -DisplayName "Allow-LDAP-from-JumpServers" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 389,636 `
    -RemoteAddress 10.1.0.10,10.1.0.11 `
    -Action Allow

# Block all other LDAP traffic
New-NetFirewallRule -DisplayName "Block-LDAP-Others" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 389,636 `
    -Action Block
```

---

## 16. 📏 Security Baselines

### 16.1 Microsoft Security Compliance Toolkit

**SCT** provides Group Policy baselines for Windows and Office.

```powershell
# Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319

# Extract and import baselines
# Group Policy Management > Import Settings

# Apply baselines:
# - Windows Server 2022 Domain Controller
# - Windows Server 2022 Member Server
# - Windows 11 Enterprise
```

---

### 16.2 CIS Benchmarks for AD

**CIS Microsoft Windows Server 2022 Benchmark** (Level 1 and Level 2).

**Key Recommendations**:
- Disable SMBv1
- Enable SMB signing
- Disable LLMNR/NetBIOS
- Enable PowerShell logging
- Restrict anonymous access
- Enable LSA protection

```powershell
# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable LSA protection (Credential Guard)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

---

### 16.3 STIG (Security Technical Implementation Guides)

**DoD STIGs** for Windows Server and Active Directory.

```powershell
# Download from: https://public.cyber.mil/stigs/

# STIG Viewer: https://public.cyber.mil/stigs/srg-stig-tools/
# Apply STIG GPOs via Group Policy Management
```

---

### 16.4 ANSSI Recommendations

**French National Cybersecurity Agency** AD security guide.

**Key Controls**:
- Tier Model enforcement
- Disable NTLM domain-wide
- Eliminate unconstrained delegation
- Kerberos Armoring (FAST)
- PAW deployment

---

### 16.5 NIST Guidelines

**NIST SP 800-53** (Security and Privacy Controls) and **NIST CSF** (Cybersecurity Framework).

**Relevant Controls**:
- **AC-6**: Least Privilege
- **IA-5**: Authenticator Management
- **AU-2**: Audit Events
- **CM-6**: Configuration Settings
- **SI-4**: Information System Monitoring

---

## 17. 🚨 Proactive Detection Rules

### 17.1 Sigma Rules for AD Attacks

#### DCSync Attack

```yaml
title: DCSync Attack via Replication
id: f7e6d5c8-9b4a-4d3e-8f1a-2c6b3a4d5e6f
status: stable
description: Detects DCSync attack by monitoring replication rights usage
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        AccessMask: '0x100'
        Properties:
            - '*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*'
            - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
    filter:
        SubjectUserName: '*$'
    condition: selection and not filter
level: critical
```

#### Kerberoasting

```yaml
title: Kerberoasting Attack
id: a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6
status: stable
description: Detects Kerberoasting via excessive TGS requests
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'  # RC4
        ServiceName: '*'
    filter:
        ServiceName:
            - 'krbtgt'
            - '*$'  # Computer accounts
    timeframe: 1m
    condition: selection and not filter | count() by Account > 5
level: high
```

---

### 17.2 Splunk SPL Queries

#### Detect Pass-the-Hash

```spl
index=windows EventCode=4624 LogonType=3 LogonProcessName=NtLmSsp
| stats dc(Computer) as UniqueComputers by Account_Name
| where UniqueComputers > 5
| table Account_Name, UniqueComputers
```

#### Detect Golden Ticket

```spl
index=windows EventCode=4768 TicketEncryptionType=0x17
| eval Hour=strftime(_time, "%H")
| where Hour < 6 OR Hour > 22
| search NOT Account_Name="*$"
| table _time, Account_Name, IpAddress, TicketEncryptionType
```

---

### 17.3 ELK (Elasticsearch) Queries

#### Detect Shadow Credentials Attack

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.code": "5136" } },
        { "match": { "event.data.AttributeLDAPDisplayName": "msDS-KeyCredentialLink" } }
      ]
    }
  }
}
```

---

### 17.4 KQL (Kusto Query Language) for Sentinel

#### Detect BloodHound/SharpHound Execution

```kql
DeviceProcessEvents
| where FileName in~ ("SharpHound.exe", "BloodHound.exe", "azurehound.exe")
    or ProcessCommandLine has_any ("Invoke-BloodHound", "SharpHound.ps1", "-CollectionMethod All", "--CollectionMethod")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256
```

#### Detect Mimikatz Execution

```kql
DeviceProcessEvents
| where FileName =~ "mimikatz.exe"
    or ProcessCommandLine has_any ("sekurlsa::logonpasswords", "lsadump::sam", "lsadump::secrets", "lsadump::dcsync", "kerberos::golden", "kerberos::ptt")
    or SHA256 in ("<Mimikatz-SHA256-Hash>")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

### 17.5 YARA Rules for AD Attack Tools

```yara
rule Mimikatz_Memory {
    meta:
        description = "Detects Mimikatz in memory"
        author = "Zemarkhos"
        date = "2025-01-09"
    strings:
        $str1 = "sekurlsa::logonpasswords" ascii wide
        $str2 = "lsadump::sam" ascii wide
        $str3 = "privilege::debug" ascii wide
        $str4 = "gentilkiwi" ascii wide
        $hex1 = { 4D 69 6D 69 6B 61 74 7A }  // "Mimikatz"
    condition:
        2 of them
}

rule SharpHound {
    meta:
        description = "Detects SharpHound/BloodHound collector"
        author = "Zemarkhos"
    strings:
        $str1 = "SharpHound" ascii wide
        $str2 = "BloodHound" ascii wide
        $str3 = "CollectionMethod" ascii wide
        $str4 = "DCOnly" ascii wide
    condition:
        2 of them
}
```

---

## 18. 🟣 Purple Team Exercises

**Purple teaming** combines red team (offensive) and blue team (defensive) to improve detection capabilities.

### 18.1 Exercise 1: Kerberoasting Detection

**Red Team Action**:
```powershell
# Request TGS for all SPNs
Add-Type -AssemblyName System.IdentityModel
$SPNs = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
foreach ($SPN in $SPNs.ServicePrincipalName) {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
}
```

**Blue Team Verification**:
- Monitor Event ID 4769 for RC4 service tickets
- Alert triggers within 5 minutes
- Investigate source IP and account

**Success Criteria**:
- Alert generated within 5 minutes
- Analyst investigates within 15 minutes
- Account disabled within 30 minutes (if confirmed malicious)

---

### 18.2 Exercise 2: DCSync Attack

**Red Team Action**:
```powershell
# Simulate DCSync (requires replication rights)
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /user:krbtgt"'
```

**Blue Team Verification**:
- Monitor Event ID 4662 with replication GUIDs
- MDI alert: "Suspected DCSync attack"
- Investigate replication permissions

**Success Criteria**:
- MDI alert within 2 minutes
- SOC escalation within 10 minutes
- Replication rights audited and remediated

---

### 18.3 Exercise 3: Golden Ticket Usage

**Red Team Action**:
```powershell
# Create Golden Ticket (requires krbtgt hash)
kerberos::golden /domain:corp.local /sid:S-1-5-21-... /rc4:<krbtgt-hash> /user:FakeAdmin /ptt
```

**Blue Team Verification**:
- Detect abnormal TGT lifetime
- Detect TGT for non-existent user
- MDI alert: "Suspected Golden Ticket usage"

**Success Criteria**:
- Detection within 10 minutes
- Incident response initiated
- krbtgt password reset procedure executed

---

### 18.4 Exercise 4: Pass-the-Hash Lateral Movement

**Red Team Action**:
```powershell
# Use stolen NTLM hash for lateral movement
Invoke-WMIExec -Target 10.0.0.50 -Username Administrator -Hash <NTLM-Hash> -Command "whoami"
```

**Blue Team Verification**:
- Detect NTLM logon from privileged account
- Detect lateral movement pattern (multiple systems)
- EDR alert: "Suspected Pass-the-Hash"

**Success Criteria**:
- Alert within 5 minutes
- Compromised account disabled
- Affected systems isolated

---

### 18.5 Exercise 5: AD CS ESC1 Exploitation

**Red Team Action**:
```powershell
# Request certificate with SAN for Domain Admin
.\Certify.exe request /ca:CA01.corp.local\Corp-CA /template:VulnerableTemplate /altname:Administrator
```

**Blue Team Verification**:
- Monitor Event ID 4886 for vulnerable templates
- Detect certificate requests with SAN
- Harden certificate template

**Success Criteria**:
- Certificate request detected
- Template hardened within 1 hour
- ESC1 vulnerability eliminated

---

## 19. 📊 Prioritization Matrix

### 19.1 Quick Wins (High Impact, Low Effort)

| Control | Impact | Effort | Timeline | MITRE Techniques Mitigated |
|---------|--------|--------|----------|----------------------------|
| **Enable PowerShell logging** | High | Low | 1 day | T1059.001 (PowerShell) |
| **Deploy MDI** | High | Low | 1 week | T1003, T1558, T1078 |
| **Disable LLMNR/NetBIOS** | High | Low | 1 day | T1557.001 (LLMNR/NBT-NS Poisoning) |
| **Enable SMB signing** | High | Low | 1 week | T1557.001 (SMB Relay) |
| **Flag Tier 0 "Cannot be delegated"** | High | Low | 1 day | T1558.003 (Kerberoasting) |
| **Remove unconstrained delegation** | High | Medium | 1 week | T1558.003 (Unconstrained Delegation) |
| **Deploy Sysmon** | High | Low | 3 days | Multiple (visibility) |
| **Create honey admin accounts** | High | Low | 1 day | T1078 (Valid Accounts) |
| **Audit AdminSDHolder** | Medium | Low | 1 day | T1098 (Account Manipulation) |
| **Remove GPP passwords** | High | Low | 1 day | T1552.006 (GPP Passwords) |

---

### 19.2 Medium-Term Hardening (High Impact, Medium Effort)

| Control | Impact | Effort | Timeline | MITRE Techniques Mitigated |
|---------|--------|--------|----------|----------------------------|
| **Implement Tier Model** | Critical | High | 3 months | Multiple (lateral movement) |
| **Deploy PAW** | Critical | High | 2 months | T1078, T1021 (Remote Services) |
| **Disable RC4 Kerberos** | High | Medium | 1 month | T1558 (Kerberos attacks) |
| **Implement LAPS** | High | Low | 1 week | T1078.003 (Local Accounts) |
| **Enable LDAP signing** | High | Medium | 2 weeks | T1557 (LDAP Relay) |
| **Deploy Protected Users group** | High | Medium | 1 month | T1558 (Kerberos attacks) |
| **Harden AD CS templates** | High | Medium | 2 weeks | T1649 (AD CS attacks) |
| **Migrate to gMSA** | High | High | 3 months | T1558.003 (Kerberoasting) |
| **Implement JIT/PIM** | High | Medium | 1 month | T1078 (Privileged accounts) |
| **Enable Advanced Audit Policy** | High | Low | 1 week | Multiple (visibility) |

---

### 19.3 Long-Term Strategic Initiatives (Critical Impact, High Effort)

| Control | Impact | Effort | Timeline | MITRE Techniques Mitigated |
|---------|--------|--------|----------|----------------------------|
| **Zero Trust Architecture** | Critical | Very High | 12+ months | Multiple (holistic defense) |
| **NTLM elimination** | Critical | Very High | 12+ months | T1557, T1187 (NTLM attacks) |
| **Network micro-segmentation** | Critical | Very High | 6 months | T1021 (Lateral Movement) |
| **Full MFA deployment** | Critical | High | 6 months | T1078 (Valid Accounts) |
| **Conditional Access policies** | High | Medium | 3 months | T1078 (Valid Accounts) |
| **SIEM/SOAR deployment** | High | Very High | 6 months | Multiple (detection/response) |
| **Purple team program** | High | High | Ongoing | Multiple (continuous improvement) |

---

## 20. 📚 References and Resources

### Official Microsoft Documentation

- [Active Directory Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Privileged Access Deployment](https://docs.microsoft.com/en-us/security/compass/privileged-access-deployment)
- [Microsoft Defender for Identity](https://docs.microsoft.com/en-us/defender-for-identity/)
- [Kerberos Armoring (FAST)](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/kerberos-policy)
- [Protected Users Security Group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)

### Security Frameworks

- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ANSSI AD Security Guide](https://www.ssi.gouv.fr/en/guide/active-directory-security-assessment/)

### Tools

- [PingCastle](https://www.pingcastle.com/) - AD security assessment
- [Purple Knight](https://www.purple-knight.com/) - Semperis AD security indicator scanner
- [BloodHound Community Edition](https://github.com/BloodHoundAD/BloodHound) - AD attack path analysis
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)

### Training Resources

- [SANS SEC660: Advanced Penetration Testing](https://www.sans.org/cyber-security-courses/advanced-penetration-testing-exploits-ethical-hacking/)
- [SANS SEC505: Securing Windows](https://www.sans.org/cyber-security-courses/securing-windows/)
- [SpecterOps BloodHound Training](https://www.specterops.io/how-we-help/training-offerings)
- [Microsoft Learn: Secure Windows Server](https://learn.microsoft.com/en-us/training/paths/implement-windows-server-security/)

### Books

- **"Active Directory Security Risk 101"** by Sean Metcalf
- **"Evading EDR"** by Matt Hand
- **"Operator Handbook: Red Team + OSINT + Blue Team"** by Joshua Picolet

---

## 🎓 Continuous Improvement Cycle

1. **Assess** (Monthly): PingCastle, Purple Knight, BloodHound
2. **Harden** (Ongoing): Implement controls from prioritization matrix
3. **Monitor** (24/7): SIEM, EDR, MDI alerts
4. **Hunt** (Weekly): Proactive threat hunting with KQL/Sigma
5. **Test** (Quarterly): Purple team exercises
6. **Review** (Quarterly): Update baselines, review incidents
7. **Repeat**: Continuous security posture improvement

---

## ✅ Defense-in-Depth Summary

**Active Directory defense requires layered controls**:

- **Preventive**: Hardening, least privilege, segmentation
- **Detective**: Logging, monitoring, EDR, deception
- **Responsive**: Incident response, containment, recovery
- **Administrative**: Policies, baselines, training

**No single control is sufficient.** Combine technical, procedural, and organizational measures for enterprise-grade AD security.

---

**Document Version**: 1.0
**Last Updated**: 2025-01-09
**Next Review**: 2025-04-09
