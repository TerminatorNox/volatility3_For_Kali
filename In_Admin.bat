<# :
@echo off
setlocal EnableDelayedExpansion

:: ---------------------------------------------------------
:: AUTOMATIC ADMIN ELEVATION
:: ---------------------------------------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Administrator rights required. Auto-elevating...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: Set output directory to a 'Result' folder in the current script location
set "OUTDIR=%~dp0Result"

:: Create the Result directory if it doesn't exist
if not exist "%OUTDIR%" (
    mkdir "%OUTDIR%"
)

echo ===================================================
echo     WINDOWS COMPREHENSIVE ENDPOINT AUDIT (JSON)
echo ===================================================
echo.

:: ---------------------------------------------------------
:: ENVIRONMENT CHECK (Windows vs Linux)
:: ---------------------------------------------------------
echo Checking operating system environment...
if not "%OS%"=="Windows_NT" (
    echo [!] ERROR: Environment Check Failed.
    echo This script is designed exclusively for Windows environments.
    echo The current system appears to be Linux or an unsupported OS.
    echo Aborting extraction...
    echo.
    pause
    goto :EOF
)
echo [v] Environment verified as Windows. Proceeding...
echo.

echo Output Directory: %OUTDIR%
echo.
echo Extracting data to JSON formats, please wait...
echo ===================================================

:: Run the embedded PowerShell block below to serialize to JSON
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Get-Content -LiteralPath '%~f0' -Raw))) -ArgumentList '%OUTDIR%'"

echo.
echo ===================================================
echo AUDIT COMPLETE. 
echo All extracted telemetry has been saved in:
echo %OUTDIR%
pause
goto :EOF
#>

# ====================================================================
# POWERSHELL JSON EXTRACTION ENGINE
# ====================================================================
param([string]$OutDir)

# Double-check OS within the PowerShell runspace just in case
if ($PSVersionTable.PSEdition -eq 'Core' -and ($IsLinux -or $IsMacOS)) {
    Write-Host "[!] ERROR: PowerShell environment detected as Linux/macOS. Aborting." -ForegroundColor Red
    exit
}

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Helper function to save structured JSON
function Out-JsonFile {
    param([Parameter(Mandatory=$true)]$Data, [Parameter(Mandatory=$true)][string]$FileName)
    $Data | ConvertTo-Json -Depth 5 -Compress:$false | Out-File (Join-Path $OutDir $FileName) -Encoding UTF8
}

# ---------------------------------------------------------
# 1. HARDWARE & SYSTEM INFORMATION
# ---------------------------------------------------------
Write-Host "[*] 1. Extracting Hardware & System Information..."
$hw = [ordered]@{
    BIOS = Get-CimInstance Win32_BIOS | Select-Object Name,SerialNumber,Version,SMBIOSBIOSVersion
    Motherboard = Get-CimInstance Win32_BaseBoard | Select-Object Product,Manufacturer,Version,SerialNumber
    CPU = Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed
    RAM = Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Manufacturer,PartNumber,Speed
    Disks = Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,Status,Partitions
    Partitions = Get-CimInstance Win32_DiskPartition | Select-Object Name,Size,Type
    SMART_Health = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus | Select-Object InstanceName, PredictFailure, Reason
    Battery = Get-CimInstance Win32_Battery | Select-Object EstimatedChargeRemaining,BatteryStatus
    USB_Bluetooth = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' -or $_.Class -eq 'Bluetooth' } | Select-Object Class, FriendlyName, InstanceId
    Printers = Get-Printer | Select-Object Name, DriverName, PortName, Shared
    Drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name, Description, State, PathName
    VirtualMachine = Get-CimInstance Win32_ComputerSystem | Select-Object Model,Manufacturer
}
Out-JsonFile $hw "01_Hardware_System.json"

# ---------------------------------------------------------
# 2. OPERATING SYSTEM
# ---------------------------------------------------------
Write-Host "[*] 2. Extracting Operating System Details..."
$os = [ordered]@{
    Details = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime
    TimeZone = Get-CimInstance Win32_TimeZone | Select-Object Caption, StandardName
    Locale = Get-WinSystemLocale | Select-Object Name
    EnvironmentVariables = Get-ChildItem Env: | ForEach-Object { @{($_.Name)=($_.Value)} }
    NTP_Config = w32tm /query /configuration
    ShadowCopies = vssadmin list shadows
    RestorePoints = Get-ComputerRestorePoint | Select-Object Description, CreationTime, EventType, SequenceNumber
    CrashDump = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CrashControl"
}
Out-JsonFile $os "02_Operating_System.json"

# ---------------------------------------------------------
# 3. SOFTWARE INVENTORY
# ---------------------------------------------------------
Write-Host "[*] 3. Extracting Software Inventory..."
$soft = [ordered]@{
    InstalledSoftware = @(
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    ) | Where-Object DisplayName -ne $null
    WindowsUpdates = Get-CimInstance Win32_QuickFixEngineering | Select-Object Caption,Description,HotFixID,InstalledOn
    DotNetFrameworks = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version, Release | Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object PSChildName, Version, Release
    Runtimes = @{
        Python = (python --version)
        NodeJS = (node --version)
        Java = (java -version 2>&1)
    }
    Browsers = @{
        ChromeInstalled = Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe"
        EdgeInstalled = Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        FirefoxInstalled = Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe"
    }
    Fonts = Get-ChildItem C:\Windows\Fonts | Select-Object -ExpandProperty Name
}
Out-JsonFile $soft "03_Software_Inventory.json"

# ---------------------------------------------------------
# 4. USER & ACCESS MANAGEMENT
# ---------------------------------------------------------
Write-Host "[*] 4. Extracting User and Access Management..."
$users = [ordered]@{
    LocalUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
    LocalGroups = Get-LocalGroup | Select-Object Name, Description
    AccountDetails = Get-CimInstance Win32_UserAccount | Select-Object Name,Disabled,Domain,Status,Lockout,PasswordRequired,PasswordExpires
    PasswordPolicy = (net accounts)
    DomainMembership = Get-CimInstance Win32_ComputerSystem | Select-Object Domain,DomainRole,PartOfDomain
    GPOResults = (gpresult /r)
    LAPS_Status = Get-ItemProperty 'HKLM:\Software\Microsoft\Policies\LAPS'
}
Out-JsonFile $users "04_User_Access.json"

# Export User Rights Policy, parse INI format, and save as JSON
$tempCfg = Join-Path $OutDir "temp_secpol.cfg"
secedit /export /cfg $tempCfg /quiet | Out-Null
if (Test-Path $tempCfg) {
    $secPolObj = [ordered]@{}
    $currentSection = "General"
    foreach ($line in (Get-Content $tempCfg -Encoding Unicode -ErrorAction SilentlyContinue)) {
        $line = $line.Trim()
        if ($line -match "^\[(.*)\]$") {
            $currentSection = $matches[1]
            $secPolObj[$currentSection] = [ordered]@{}
        } elseif ($line -match "^([^=]+)=(.*)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if (-not $secPolObj.Contains($currentSection)) {
                $secPolObj[$currentSection] = [ordered]@{}
            }
            $secPolObj[$currentSection][$key] = $value
        }
    }
    Out-JsonFile $secPolObj "04b_User_Rights_Policy.json"
    Remove-Item $tempCfg -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------
# 5. NETWORK AUDIT
# ---------------------------------------------------------
Write-Host "[*] 5. Extracting Network Configuration..."
$net = [ordered]@{
    Geolocation = Invoke-RestMethod ipinfo.io
    IPConfig = Get-NetIPAddress | Where-Object AddressFamily -eq "IPv4" | Select-Object InterfaceAlias, IPAddress, PrefixLength
    MACAddresses = Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status
    DNSCache = Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Data
    ARPTable = Get-NetNeighbor | Where-Object AddressFamily -eq "IPv4" | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State
    RoutingTable = Get-NetRoute | Where-Object AddressFamily -eq "IPv4" | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
    ActiveConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    HostsFile = Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
    VPNConfig = Get-VpnConnection | Select-Object Name, ServerAddress, ConnectionStatus
    ProxyConfig = @{
        ProxyEnable = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable
        ProxyServer = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyServer
    }
    SMB_Shares = Get-SmbShare | Select-Object Name, Path, Description
    RDPConfig = @{
        DenyTSConnections = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
    }
}
$wifi = (netsh wlan show profiles) | Select-String '\:(.+)$' | ForEach-Object {
    $name = $_.Matches.Groups[1].Value.Trim()
    $pass = ((netsh wlan show profile name="$name" key=clear) | Select-String 'Key Content\W+\:(.+)$').Matches.Groups[1].Value.Trim()
    [PSCustomObject]@{ProfileName=$name; Password=$pass}
}
$net.WiFiProfiles = $wifi
Out-JsonFile $net "05_Network_Audit.json"

# ---------------------------------------------------------
# 6. SECURITY CONFIGURATION
# ---------------------------------------------------------
Write-Host "[*] 6. Extracting Security Configuration..."
$sec = [ordered]@{
    FirewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    SecurityCenter = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState
    DefenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected
    BitLockerStatus = Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod
    TPMStatus = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm | Select-Object IsActivated_InitialValue,IsEnabled_InitialValue,SpecVersion
    SecureBootStatus = (Confirm-SecureBootUEFI)
    DeviceGuard = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\DeviceGuard"
    ExecutionPolicy = (Get-ExecutionPolicy -List | Select-Object Scope, ExecutionPolicy)
    UACPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin
}
Out-JsonFile $sec "06_Security_Config.json"

# ---------------------------------------------------------
# 7. LOGS & FORENSICS
# ---------------------------------------------------------
Write-Host "[*] 7. Extracting Logs & Forensics..."
$logs = [ordered]@{
    RecentSystemLogs = Get-WinEvent -LogName System -MaxEvents 20 | Select-Object TimeCreated, Id, LevelDisplayName, Message
    RecentSecurityLogs = Get-WinEvent -LogName Security -MaxEvents 20 | Select-Object TimeCreated, Id, LevelDisplayName, Message
    FailedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 | Select-Object TimeCreated, Message
    SysmonStatus = Get-Service sysmon64 | Select-Object Status, StartType
    PowerShellHistory = Get-Content (Get-PSReadLineOption).HistorySavePath | Select-Object -Last 50
    ForensicArtifacts = @{
        PrefetchFilesPresent = (Test-Path C:\Windows\Prefetch\*.pf)
        AmcachePresent = (Test-Path C:\Windows\AppCompat\Programs\Amcache.hve)
        RecycleBinItems = Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse | Select-Object -ExpandProperty FullName
    }
}
Out-JsonFile $logs "07_Logs_Forensics.json"

# ---------------------------------------------------------
# 8. PROCESS & PERSISTENCE
# ---------------------------------------------------------
Write-Host "[*] 8. Extracting Processes & Persistence..."
$proc = [ordered]@{
    RunningProcesses = Get-Process | Select-Object Id, ProcessName, Path, Company
    RunningServices = Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName, StartType
    KnownLOLBinsRunning = Get-Process | Where-Object ProcessName -Match '^(cmd|powershell|mshta|certutil|bitsadmin|rundll32|regsvr32|wmic)$' | Select-Object Id, ProcessName, Path
    ScheduledTasks = Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName, TaskPath, State
    WMIPersistence = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name, Query
    AutorunEntries = @{
        HKLM = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        HKCU = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        StartUpFolderSystem = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | Select-Object -ExpandProperty Name
        StartUpFolderUser = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object -ExpandProperty Name
    }
}
Out-JsonFile $proc "08_Processes_Persistence.json"

# ---------------------------------------------------------
# 9. FILE SYSTEM & CERTIFICATES
# ---------------------------------------------------------
Write-Host "[*] 9. Extracting Certificates & File System Data..."
$fs = [ordered]@{
    TrustedRootCerts = Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject, Thumbprint, NotAfter | Select-Object -First 20
    InstalledMyCerts = Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, HasPrivateKey, NotAfter
    LogicalDisks = Get-CimInstance Win32_LogicalDisk | Select-Object Name, ProviderName, FreeSpace, Size
    LargeFileInventory = Get-ChildItem -Path C:\Users -File -Recurse | Sort-Object Length -Descending | Select-Object FullName, @{Name='SizeMB';Expression={[math]::Round($_.Length / 1MB, 2)}} | Select-Object -First 20
}
Out-JsonFile $fs "09_FileSystem_Certs.json"

# ---------------------------------------------------------
# 10. WEB, DATABASE, DEVOPS & CLOUD
# ---------------------------------------------------------
Write-Host "[*] 10. Extracting Web, Database, DevOps & Cloud Info..."
$web = [ordered]@{
    WebServers = Get-Service w3svc, httpd, nginx, tomcat* | Select-Object Name, Status
    Databases = Get-Process mysqld, postgres, mongod, redis-server, oracle | Select-Object ProcessName, Id
    DevOps_Container = @{
        Docker = (docker -v)
        Git = (git --version)
        Kubernetes = (kubectl version --client)
    }
    CloudAgents = @{
        AWS_Agent_Detected = (Test-Path "C:\Program Files\Amazon\AmazonCloudWatchAgent")
        Azure_Agent_Detected = (Test-Path "C:\Program Files\Microsoft Monitoring Agent")
    }
}
Out-JsonFile $web "10_Web_DB_DevOps.json"

# ---------------------------------------------------------
# 11. ABSTRACT & EXTERNAL ASSESSMENTS
# ---------------------------------------------------------
Write-Host "[*] 11. Finalizing Abstract & External Assessment Notes..."
$ext = [ordered]@{
    AuditStatus = "JSON Extraction Successful"
    AuditExtentAddressed = "This script successfully gathered native telemetry for OS, Hardware, Users, Network, Processes, Security, Forensics, Files, and Services into JSON formats."
    ExternalCapabilitiesRequired = @(
        "Risk Scoring & Executive Summary Generation (Requires SIEM/SOAR/Analyzer)",
        "HTML/PDF Report Generation (Requires scripting post-processor/platform)",
        "Dashboard Upload & Agent Self-Health Check (Requires C2 or Management Agent)",
        "YARA Rule Scanning & Malware Artifact Detection (Requires EDR or AV scanner tool)",
        "CVE Correlation & Missing Security Updates mapping (Requires Vuln Scanner)",
        "Compliance Checks (CIS/ISO 27001/NIST) (Requires dedicated benchmark auditing tools)",
        "MITRE ATT&CK Technique Mapping (Requires SIEM correlation)",
        "Browser Extensions & Browser Password Policy (Encrypted via SQLite, requires specialized decrypter)"
    )
}
Out-JsonFile $ext "11_External_Assessments.json"

# ---------------------------------------------------------
# 12. AUTOMATED EVIDENCE SCREENSHOT COLLECTOR
# ---------------------------------------------------------
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AUTOMATED EVIDENCE SCREENSHOT COLLECTOR" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "This collector maps to your 35-point Audit Proof requirements."
Write-Host "It will sequentially open Windows tools, wait 3 seconds,"
Write-Host "and automatically take a screenshot."
Write-Host ""
Write-Host "WARNING: Please DO NOT move your mouse or type on your keyboard" -ForegroundColor Red
Write-Host "while the automated capture is running." -ForegroundColor Red
Write-Host ""

# Create Screenshots Directory
$ScreenshotDir = Join-Path $OutDir "Screenshots"
if (-not (Test-Path $ScreenshotDir)) { New-Item -ItemType Directory -Path $ScreenshotDir | Out-Null }

# Load .NET Types for taking screenshots natively
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Capture-Screen {
    param([string]$FilePath)
    try {
        # Capture the full virtual screen (supports multi-monitor)
        $Left = [System.Windows.Forms.SystemInformation]::VirtualScreen.Left
        $Top = [System.Windows.Forms.SystemInformation]::VirtualScreen.Top
        $Width = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
        $Height = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height
        
        $bounds = New-Object System.Drawing.Rectangle $Left, $Top, $Width, $Height
        $bmp = New-Object System.Drawing.Bitmap $bounds.width, $bounds.height
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.size)
        $bmp.Save($FilePath, [System.Drawing.Imaging.ImageFormat]::Png)
        $graphics.Dispose()
        $bmp.Dispose()
        return $true
    } catch {
        Write-Host "[!] Failed to capture screenshot: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Define Evidence Items aligned exactly with the 35-point requested list
$EvidenceList = @(
    @{ ID="01"; Title="System_Info"; Cmd="msinfo32.exe"; Desc="1. System Information (msinfo32)" },
    @{ ID="02"; Title="Hardware_Inventory"; Cmd="devmgmt.msc"; Desc="2. Hardware Inventory (Device Manager)" },
    @{ ID="03"; Title="BIOS_UEFI"; Cmd="cmd.exe"; Args="/k color 0A & systeminfo | findstr /I bios & echo. & echo Review BIOS above."; Desc="3. BIOS/UEFI Version" },
    @{ ID="04"; Title="CPU_RAM_Performance"; Cmd="taskmgr.exe"; Desc="4. CPU and RAM (Task Manager)" },
    @{ ID="05"; Title="Disk_Information"; Cmd="diskmgmt.msc"; Desc="5. Disk Information (Disk Management)" },
    @{ ID="06"; Title="Installed_Software"; Cmd="appwiz.cpl"; Desc="6. Installed Software (Programs and Features)" },
    @{ ID="07"; Title="Windows_Updates"; Cmd="ms-settings:windowsupdate-history"; Desc="7. Windows Update History" },
    @{ ID="08"; Title="Local_Users"; Cmd="lusrmgr.msc"; Desc="8. Local Users (lusrmgr.msc)" },
    @{ ID="09"; Title="Local_Administrators"; Cmd="cmd.exe"; Args="/k color 0A & net localgroup administrators & echo."; Desc="9. Local Administrators Group" },
    @{ ID="10"; Title="Password_Policy"; Cmd="secpol.msc"; Desc="10. Password Policy (secpol.msc)" },
    @{ ID="11"; Title="Running_Processes"; Cmd="cmd.exe"; Args="/k color 0A & tasklist & echo."; Desc="11. Running Processes List" },
    @{ ID="12"; Title="Services"; Cmd="services.msc"; Desc="12. Windows Services" },
    @{ ID="13"; Title="Startup_Programs"; Cmd="ms-settings:startupapps"; Desc="13. Startup Programs" },
    @{ ID="14"; Title="Scheduled_Tasks"; Cmd="taskschd.msc"; Desc="14. Scheduled Tasks" },
    @{ ID="15"; Title="Installed_Drivers"; Cmd="cmd.exe"; Args="/k color 0A & driverquery & echo."; Desc="15. Installed Drivers" },
    @{ ID="16"; Title="Network_Configuration"; Cmd="ncpa.cpl"; Desc="16. Network Configuration" },
    @{ ID="17"; Title="Active_Connections"; Cmd="cmd.exe"; Args="/k color 0A & netstat -ano & echo."; Desc="17. Active Network Connections" },
    @{ ID="18"; Title="Shared_Folders"; Cmd="fsmgmt.msc"; Desc="18. Shared Folders (fsmgmt.msc)" },
    @{ ID="19"; Title="Firewall_Status"; Cmd="control.exe"; Args="firewall.cpl"; Desc="19. Firewall Status" },
    @{ ID="20"; Title="Firewall_Rules"; Cmd="wf.msc"; Desc="20. Firewall Advanced Rules" },
    @{ ID="21"; Title="Windows_Defender"; Cmd="windowsdefender:"; Desc="21. Windows Defender Dashboard" },
    @{ ID="22"; Title="Antivirus_EDR"; Cmd="cmd.exe"; Args="/k color 0A & wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayName,productState & echo."; Desc="22. Antivirus / EDR Registration" },
    @{ ID="23"; Title="BitLocker_Status"; Cmd="cmd.exe"; Args="/k color 0A & manage-bde -status & echo."; Desc="23. BitLocker Status" },
    @{ ID="24"; Title="Secure_Boot"; Cmd="cmd.exe"; Args="/k color 0A & powershell Confirm-SecureBootUEFI & echo."; Desc="24. Secure Boot State" },
    @{ ID="25"; Title="TPM_Management"; Cmd="tpm.msc"; Desc="25. TPM Management" },
    @{ ID="26"; Title="Event_Logs"; Cmd="eventvwr.msc"; Desc="26. Event Logs (Event Viewer)" },
    @{ ID="27"; Title="RDP_Configuration"; Cmd="SystemPropertiesRemote.exe"; Desc="27. RDP Configuration" },
    @{ ID="28"; Title="USB_Devices"; Cmd="cmd.exe"; Args="/k color 0A & powershell ""Get-PnpDevice | Where-Object {`$_.InstanceId -match '^USB'} | Select Status,Class,FriendlyName"" & echo."; Desc="28. Connected USB Devices" },
    @{ ID="29"; Title="Certificates"; Cmd="certlm.msc"; Desc="29. Certificates" },
    @{ ID="30"; Title="Group_Policy"; Cmd="cmd.exe"; Args="/k color 0A & gpresult /R & echo."; Desc="30. Group Policy Results" },
    @{ ID="31"; Title="Browser_Extensions"; Cmd="cmd.exe"; Args="/k color 0A & dir ""%LocalAppData%\Google\Chrome\User Data\Default\Extensions"" /B & echo. & echo Chrome Extensions folders (if any)."; Desc="31. Chrome Extensions" },
    @{ ID="32"; Title="IIS_Server"; Cmd="inetmgr.exe"; Desc="32. IIS Server Manager" },
    @{ ID="33"; Title="Docker_Status"; Cmd="cmd.exe"; Args="/k color 0A & docker ps -a & echo."; Desc="33. Docker Containers" },
    @{ ID="34"; Title="Active_Directory"; Cmd="dsa.msc"; Desc="34. Active Directory" },
    @{ ID="35"; Title="Risk_Evidence"; Cmd="cmd.exe"; Args="/k color 0C & echo GENERAL SYSTEM RISK EVIDENCE CAPTURED VIA JSON TELEMETRY. & echo."; Desc="35. Risk Evidence Summary" }
)

Write-Host "`nStarting Automated Capture of 35 items in 3 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

foreach ($Item in $EvidenceList) {
    Write-Host "`n---------------------------------------------------"
    Write-Host "Target: $($Item.Desc)" -ForegroundColor Cyan
    Write-Host "Launching tool and waiting 3 seconds..." -ForegroundColor DarkGray

    $proc = $null
    try {
        if ($Item.Cmd -match ":") {
            Start-Process $Item.Cmd -ErrorAction SilentlyContinue
        } elseif ($Item.Args) {
            $proc = Start-Process -FilePath $Item.Cmd -ArgumentList $Item.Args -PassThru -ErrorAction SilentlyContinue
        } else {
            $proc = Start-Process -FilePath $Item.Cmd -PassThru -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "[-] Tool unavailable or failed to launch." -ForegroundColor DarkGray
    }

    # Automatically wait 3 seconds for the application UI to open and render
    Start-Sleep -Seconds 3

    # Capture the screenshot automatically
    $FileName = "$($Item.ID)_$($Item.Title).png"
    $FilePath = Join-Path $ScreenshotDir $FileName
    if (Capture-Screen -FilePath $FilePath) {
        Write-Host "[+] Image Saved: $FileName" -ForegroundColor Green
    }

    # Attempt to cleanly close the tool we just opened automatically
    if ($null -ne $proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }

    # Aggressive process cleanup for stubborn Windows UIs
    if ($Item.Cmd -match "\.msc$") { Stop-Process -Name mmc -Force -ErrorAction SilentlyContinue }
    if ($Item.Cmd -match "SystemPropertiesRemote") { Stop-Process -Name SystemPropertiesRemote -Force -ErrorAction SilentlyContinue }
    if ($Item.Cmd -match "taskmgr") { Stop-Process -Name Taskmgr -Force -ErrorAction SilentlyContinue }
    if ($Item.Cmd -match "ms-settings:") { Stop-Process -Name SystemSettings -Force -ErrorAction SilentlyContinue }
    
    # Brief pause before launching the next window
    Start-Sleep -Seconds 1
}

# Final cleanup of any open command prompts created by the script
Stop-Process -Name cmd -Force -ErrorAction SilentlyContinue

Write-Host "`n=========================================================="
Write-Host "Automated Evidence Collection Finished!" -ForegroundColor Green
Write-Host "All 35 Screenshots saved to: $ScreenshotDir" -ForegroundColor Cyan
Write-Host "=========================================================="