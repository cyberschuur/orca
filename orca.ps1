<#
.SYNOPSIS
Windows enumeration script with privilege-based execution.
.DESCRIPTION
This script performs Windows enumeration for privilege escalation and recon.
It allows running as either a standard user or with local admin privileges.
If the -localadmin flag is specified, admin-only checks will also run.
.EXAMPLE
PS > .\orca.ps1
Runs standard user enumeration checks.
.EXAMPLE
PS > .\orca.ps1 -localadmin
Runs both standard and admin-required checks.
.EXAMPLE
PS > .\orca.ps1 -OutputFileName results.txt
Writes results to results.txt.
#>

Param(
    [Switch]$localadmin,   # Runs admin-only checks if specified
    [String]$o = ""
)

# -------------------------------
# Standard User Checks
# -------------------------------
function Get-CertificateThumbprints {
    $output = "\n========== Certificate Thumbprints =========="
    $output += (Get-ChildItem -Path Cert:\LocalMachine\My | Select Subject, Thumbprint | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-ChromiumBookmarks {
    $output = "`n========== Chromium Bookmarks =========="
    $bookmarkPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"
    
    if (Test-Path $bookmarkPath) {
        $output += (Get-Content $bookmarkPath -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "`n[-] No bookmarks found."
    }
    
    return $output
}

function Get-ChromiumHistory {
    $output = "`n========== Chromium History =========="
    $historyPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"

    if (Test-Path $historyPath) {
        $output += "`n[!] History file detected but cannot be directly read. Consider using a database tool."
    } else {
        $output += "`n[-] No history found."
    }

    return $output
}

function Get-ChromiumPresence {
    $output = "`n========== Chromium Presence =========="
    
    if (Test-Path "$env:LOCALAPPDATA\Google\Chrome") {
        $output += "`n[+] Chromium-based browser detected."
    } else {
        $output += "`n[-] Chromium-based browser not found."
    }

    return $output
}

function Get-CloudSyncProviders {
    $output = "`n========== Cloud Sync Providers =========="
    $output += (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-CredEnum {
    $output = "`n========== Stored Credentials =========="
    $output += (cmdkey /list | Out-String)
    return $output
}

function Get-CredGuard {
    $output = "`n========== Credential Guard Status =========="
    $status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -ErrorAction SilentlyContinue
    if ($status.LsaCfgFlags -eq 1) {
        $output += "`n[+] Credential Guard is ENABLED"
    } else {
        $output += "`n[-] Credential Guard is DISABLED"
    }
    return $output
}

function Get-DNSCache {
    $output = "`n========== DNS Cache =========="
    $output += (ipconfig /displaydns | Out-String)
    return $output
}

function Get-DotNetVersion {
    $output = "`n========== .NET Version =========="
    $output += (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-EnvironmentPath {
    $output = "`n========== Environment Path Variables =========="
    $output += (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name Path -ErrorAction SilentlyContinue | Out-String)
    return $output
}

function Get-EnvironmentVariables {
    $output = "`n========== Environment Variables =========="
    $output += (Get-ChildItem Env: | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-ExplicitLogonEvents {
    $output = "`n========== Explicit Logon Events =========="
    $output += (Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4648 } | Format-Table TimeCreated, Message -AutoSize | Out-String)
    return $output
}

function Get-ExplorerMRUs {
    $output = "`n========== Explorer MRU (Most Recently Used) =========="
    $output += (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue | Out-String)
    return $output
}

function Get-ExplorerRunCommands {
    $output = "`n========== Explorer Run Commands =========="
    $output += (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue | Out-String)
    return $output
}

function Get-FileInfo {
    $output = "`n========== File Information =========="
    $output += (Get-ChildItem -Path "C:\Users\*\Documents" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-FileZilla {
    $output = "`n========== FileZilla Saved Credentials =========="
    $filezillaPath = "$env:APPDATA\FileZilla\recentservers.xml"

    if (Test-Path $filezillaPath) {
        $output += "`n[+] FileZilla config found, reading contents..."
        $output += (Get-Content $filezillaPath -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "`n[-] No FileZilla configuration found."
    }

    return $output
}

function Get-FirefoxHistory {
    $output = "`n========== Firefox Browsing History =========="
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"

    if (Test-Path $firefoxPath) {
        $output += "`n[!] Firefox history is stored in an SQLite database and cannot be directly read with PowerShell."
        $output += "`n[+] Path: $firefoxPath"
    } else {
        $output += "`n[-] Firefox not detected."
    }

    return $output
}

function Get-FirefoxPresence {
    $output = "`n========== Firefox Presence =========="
    if (Test-Path "$env:PROGRAMFILES\Mozilla Firefox") {
        $output += "`n[+] Firefox is installed."
    } else {
        $output += "`n[-] Firefox is not installed."
    }
    return $output
}

function Get-Hotfixes {
    $output = "`n========== Installed Windows Hotfixes =========="
    $output += (Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-IEFavorites {
    $output = "`n========== Internet Explorer Favorites =========="
    $favoritesPath = "$env:USERPROFILE\Favorites"

    if (Test-Path $favoritesPath) {
        $output += (Get-ChildItem -Path $favoritesPath -Recurse | Select-Object FullName, LastWriteTime | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No IE Favorites found."
    }

    return $output
}

function Get-IETabs {
    $output = "`n========== Internet Explorer Open Tabs =========="
    $registryPath = "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing\NewTabPage"

    if (Test-Path $registryPath) {
        $output += (Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No IE tabs information found."
    }

    return $output
}

function Get-IEUrls {
    $output = "`n========== Internet Explorer Recently Visited URLs =========="
    $registryPath = "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"

    if (Test-Path $registryPath) {
        $output += (Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No IE URL history found."
    }

    return $output
}

function Get-IdleTime {
    $output = "`n========== System Idle Time =========="
    $idleTime = (Get-Process winlogon).PrivilegedProcessorTime.TotalSeconds
    $output += "`n[+] System has been idle for $idleTime seconds."
    return $output
}

function Get-InstalledProducts {
    $output = "`n========== Installed Software Products =========="
    $output += (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallDate | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-InterestingFiles {
    $output = "`n========== Interesting Files =========="
    $searchPaths = @("C:\Users\*\Documents", "C:\Users\*\Desktop", "C:\Users\*\Downloads")

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $output += "`n[+] Scanning $path..."
            $output += (Get-ChildItem -Path $path -Recurse -Include *.txt, *.log, *.ini, *.conf, *.xml, *.rdp, *.kdbx -ErrorAction SilentlyContinue | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
        }
    }
    return $output
}

function Get-InterestingProcesses {
    $output = "`n========== Interesting Running Processes =========="
    $processes = Get-Process | Where-Object { $_.ProcessName -match "keepass|putty|winscp|outlook|chrome|firefox|edge" }
    
    if ($processes) {
        $output += ($processes | Select-Object ProcessName, Id, Path | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No interesting processes found."
    }
    
    return $output
}

function Get-InternetSettings {
    $output = "`n========== Internet Settings =========="
    $output += (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-KeePass {
    $output = "`n========== KeePass Database Files =========="
    $keepassFiles = Get-ChildItem -Path "C:\Users\*\Documents" -Recurse -Include *.kdbx -ErrorAction SilentlyContinue

    if ($keepassFiles) {
        $output += ($keepassFiles | Select-Object FullName, LastWriteTime | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No KeePass databases found."
    }

    return $output
}

function Get-LAPS {
    $output = "`n========== LAPS Configuration =========="
    $lapsPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS"

    if (Test-Path $lapsPath) {
        $output += (Get-ItemProperty -Path $lapsPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] LAPS not installed."
    }

    return $output
}

function Get-LSASettings {
    $output = "`n========== LSA Settings =========="
    $output += (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-LastShutdown {
    $output = "`n========== Last System Shutdown Time =========="
    $shutdownTime = Get-WinEvent -LogName System | Where-Object { $_.Id -eq 6006 } | Select-Object -First 1 TimeCreated
    if ($shutdownTime) {
        $output += "`n[+] Last shutdown was on: $($shutdownTime.TimeCreated)"
    } else {
        $output += "`n[-] No shutdown event found."
    }
    return $output
}

function Get-LocalGPOs {
    $output = "`n========== Local Group Policy Objects (GPOs) =========="
    $gpofile = "$env:TEMP\gpresult.txt"

    try {
        gpresult /H $gpofile /F
        $output += "`n[+] GPO report saved to: $gpofile"
    } catch {
        $output += "`n[-] Failed to retrieve GPO settings."
    }

    return $output
}


function Get-LocalGroups {
    $output = "`n========== Local Groups =========="
    $output += (Get-LocalGroup | Select-Object Name | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-LocalUsers {
    $output = "`n========== Local Users =========="
    $output += (Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-LogonEvents {
    $output = "`n========== Logon Events =========="
    $output += (Get-WinEvent -LogName Security | Where-Object { $_.Id -in 4624, 4634, 4647 } | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-LogonSessions {
    $output = "`n========== Active Logon Sessions =========="
    $output += (qwinsta | Out-String)
    return $output
}

function Get-MTPuTTY {
    $output = "`n========== MTPuTTY Configuration =========="
    $mtpPath = "$env:APPDATA\MTPuTTY\mtpuddy.xml"

    if (Test-Path $mtpPath) {
        $output += "`n[+] MTPuTTY configuration found. Potential stored sessions."
        $output += (Get-Content $mtpPath -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "`n[-] MTPuTTY not detected."
    }

    return $output
}

function Get-MappedDrives {
    $output = "`n========== Mapped Network Drives =========="
    $output += (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -like "\\*" } | Format-Table Name, Root, Used, Free | Out-String)
    return $output
}

function Get-McAfeeConfigs {
    $output = "`n========== McAfee Security Configuration =========="
    $mcAfeePath = "HKLM:\SOFTWARE\McAfee"

    if (Test-Path $mcAfeePath) {
        $output += (Get-ItemProperty -Path $mcAfeePath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] McAfee configurations not found."
    }

    return $output
}

function Get-McAfeeSiteList {
    $output = "`n========== McAfee Site List =========="
    $siteListPath = "C:\ProgramData\McAfee\Agent\SiteList.xml"

    if (Test-Path $siteListPath) {
        $output += "`n[+] McAfee SiteList.xml found. Displaying content..."
        $output += (Get-Content $siteListPath -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "`n[-] No McAfee SiteList.xml found."
    }

    return $output
}

function Get-MicrosoftUpdates {
    $output = "`n========== Microsoft Windows Updates =========="
    $output += (Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn, Description | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-NTLMSettings {
    $output = "`n========== NTLM Security Settings =========="
    $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    if (Test-Path $ntlmPath) {
        $output += (Get-ItemProperty -Path $ntlmPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No NTLM settings found."
    }

    return $output
}

function Get-NamedPipes {
    $output = "`n========== Named Pipes =========="
    $output += (Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Out-String)
    return $output
}

function Get-NetworkProfiles {
    $output = "`n========== Network Profiles =========="
    $output += (Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-NetworkShares {
    $output = "`n========== Network Shares =========="
    $output += (Get-SmbShare | Select-Object Name, Path, Description, ShareState | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-OSInfo {
    $output = "`n========== Operating System Information =========="
    $output += (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-OfficeMRUs {
    $output = "`n========== Office MRU (Most Recently Used) =========="
    $registryPaths = @(
        "HKCU:\Software\Microsoft\Office\16.0\Word\Place MRU",
        "HKCU:\Software\Microsoft\Office\16.0\Excel\Place MRU",
        "HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Place MRU"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $output += "`n[+] Office MRU found in: $path"
            $output += (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Out-String)
        }
    }

    return $output
}

function Get-OneNote {
    $output = "`n========== OneNote Files =========="
    $onenotePath = "$env:USERPROFILE\Documents\OneNote Notebooks"

    if (Test-Path $onenotePath) {
        $output += "`n[+] OneNote files found:"
        $output += (Get-ChildItem -Path $onenotePath -Recurse -Include *.one | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No OneNote files found."
    }

    return $output
}

function Get-OptionalFeatures {
    $output = "`n========== Optional Windows Features =========="
    $output += (Get-WindowsOptionalFeature -Online | Select-Object FeatureName, State | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-OracleSQLDeveloper {
    $output = "`n========== Oracle SQL Developer Configuration =========="
    $oraclePath = "$env:APPDATA\SQL Developer\system"

    if (Test-Path $oraclePath) {
        $output += "`n[+] Oracle SQL Developer configuration found."
        $output += (Get-ChildItem -Path $oraclePath -Recurse | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] Oracle SQL Developer not found."
    }

    return $output
}

function Get-OutlookDownloads {
    $output = "`n========== Outlook Downloaded Attachments =========="
    $outlookPath = "$env:USERPROFILE\Downloads"

    if (Test-Path $outlookPath) {
        $output += "`n[+] Searching for Outlook attachments..."
        $output += (Get-ChildItem -Path $outlookPath -Recurse -Include *.msg, *.eml -ErrorAction SilentlyContinue | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No Outlook downloads found."
    }

    return $output
}

function Get-PowerShell {
    $output = "`n========== PowerShell Execution Policy =========="
    $output += (Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-PSSessionSettings {
    $output = "`n========== PowerShell Remoting Settings =========="
    $output += (Get-Item WSMan:\localhost\Service | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-PowerShellEvents {
    $output = "`n========== PowerShell Event Logs =========="
    $output += (Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 20 | Format-Table TimeCreated, Id, Message -AutoSize | Out-String)
    return $output
}

function Get-PowerShellHistory {
    $output = "`n========== PowerShell Command History =========="
    $historyPath = (Get-PSReadlineOption).HistorySavePath

    if (Test-Path $historyPath) {
        $output += (Get-Content $historyPath -Tail 50 | Out-String)
    } else {
        $output += "`n[-] No PowerShell history file found."
    }

    return $output
}

function Get-PoweredOnEvents {
    $output = "`n========== System Power Events =========="
    $output += (Get-WinEvent -LogName System | Where-Object { $_.Id -in 1, 42, 1074, 109 } | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-Printers {
    $output = "`n========== Installed Printers =========="
    $output += (Get-Printer | Select-Object Name, DriverName, PortName | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-ProcessCreationEvents {
    $output = "`n========== Process Creation Events =========="
    $output += (Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 } | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-ProcessOwners {
    $output = "`n========== Process Owners =========="
    $output += (Get-WmiObject Win32_Process | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name Owner -Value ($_.GetOwner().User) -PassThru } | Select-Object ProcessId, Name, Owner | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-Processes {
    $output = "`n========== Running Processes =========="
    $output += (Get-Process | Select-Object Name, Id, CPU, WorkingSet | Sort-Object CPU -Descending | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-PuttyHostKeys {
    $output = "`n========== PuTTY SSH Host Keys =========="
    $puttyPath = "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys"

    if (Test-Path $puttyPath) {
        $output += (Get-ItemProperty -Path $puttyPath -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "`n[-] No PuTTY SSH host keys found."
    }

    return $output
}

function Get-PuttySessions {
    $output = "`n========== PuTTY Saved Sessions =========="
    $puttyPath = "HKCU:\Software\SimonTatham\PuTTY\Sessions"

    if (Test-Path $puttyPath) {
        $output += (Get-ChildItem -Path $puttyPath | Select-Object Name | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No PuTTY saved sessions found."
    }

    return $output
}

function Get-RDCManFiles {
    $output = "`n========== RDCMan Files =========="
    $rdcPath = "$env:APPDATA\Microsoft\Remote Desktop Connection Manager"

    if (Test-Path $rdcPath) {
        $output += (Get-ChildItem -Path $rdcPath -Recurse -Include *.rdg | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No RDCMan files found."
    }

    return $output
}

function Get-RDPSavedConnections {
    $output = "`n========== Saved RDP Connections =========="
    $rdpPath = "HKCU:\Software\Microsoft\Terminal Server Client\Default"

    if (Test-Path $rdpPath) {
        $output += (Get-ItemProperty -Path $rdpPath -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "`n[-] No saved RDP connections found."
    }

    return $output
}

function Get-RDPSessions {
    $output = "`n========== Active RDP Sessions =========="
    $output += (qwinsta | Out-String)
    return $output
}

function Get-RDPSettings {
    $output = "`n========== RDP Settings =========="
    $rdpConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

    if (Test-Path $rdpConfigPath) {
        $output += (Get-ItemProperty -Path $rdpConfigPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No RDP settings found."
    }

    return $output
}

function Get-RPCMappedEndpoints {
    $output = "`n========== RPC Mapped Endpoints =========="
    $output += (Get-ChildItem HKLM:\Software\Microsoft\Rpc -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-RecycleBin {
    $output = "`n========== Recycle Bin Contents =========="
    $recycleBinPath = "C:\$Recycle.Bin"

    if (Test-Path $recycleBinPath) {
        $output += (Get-ChildItem -Path $recycleBinPath -Recurse | Select-Object FullName, LastWriteTime | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No recycle bin items found."
    }

    return $output
}

function Get-SCCM {
    $output = "`n========== SCCM Configuration =========="
    $sccmPath = "HKLM:\Software\Microsoft\SMS"

    if (Test-Path $sccmPath) {
        $output += (Get-ItemProperty -Path $sccmPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] SCCM not installed."
    }

    return $output
}

function Get-ScheduledTasks {
    $output = "`n========== Scheduled Tasks =========="
    $output += (Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-SearchIndex {
    $output = "`n========== Search Index Configuration =========="
    $output += (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Search" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-SecPackageCreds {
    $output = "`n========== Security Package Credentials =========="
    $lsaSecretsPath = "HKLM:\SECURITY\Policy\Secrets"

    if (Test-Path $lsaSecretsPath) {
        $output += "`n[!] Accessing LSA secrets requires SYSTEM privileges."
    } else {
        $output += "`n[-] No access to LSA secrets."
    }

    return $output
}

function Get-SecurityPackages {
    $output = "`n========== Security Packages =========="
    $output += (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-Services {
    $output = "`n========== Running Windows Services =========="
    $output += (Get-Service | Select-Object DisplayName, Name, Status | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-SlackDownloads {
    $output = "`n========== Slack Downloaded Files =========="
    $slackPath = "$env:USERPROFILE\Downloads"

    if (Test-Path $slackPath) {
        $output += "`n[+] Checking for Slack downloads..."
        $output += (Get-ChildItem -Path $slackPath -Recurse -Include *.png, *.jpg, *.pdf, *.docx | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No Slack downloads found."
    }

    return $output
}

function Get-SlackPresence {
    $output = "`n========== Slack Presence =========="
    $slackPath = "$env:APPDATA\Slack"

    if (Test-Path $slackPath) {
        $output += "`n[+] Slack is installed."
    } else {
        $output += "`n[-] Slack not detected."
    }

    return $output
}

function Get-SlackWorkspaces {
    $output = "`n========== Slack Workspaces =========="
    $workspacePath = "$env:APPDATA\Slack\storage"

    if (Test-Path $workspacePath) {
        $output += "`n[+] Slack workspaces detected."
        $output += (Get-ChildItem -Path $workspacePath -Recurse | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No Slack workspaces found."
    }

    return $output
}

function Get-SuperPutty {
    $output = "`n========== SuperPuTTY Configurations =========="
    $superPuttyPath = "$env:APPDATA\SuperPuTTY"

    if (Test-Path $superPuttyPath) {
        $output += "`n[+] SuperPuTTY configuration found."
        $output += (Get-ChildItem -Path $superPuttyPath -Recurse | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No SuperPuTTY configuration found."
    }

    return $output
}

function Get-Sysmon {
    $output = "`n========== Sysmon Logs =========="
    $sysmonLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon"

    if (Test-Path $sysmonLogPath) {
        $output += "`n[+] Sysmon is installed. Checking configuration..."
        $output += (Get-ItemProperty -Path $sysmonLogPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] Sysmon not detected."
    }

    return $output
}

function Get-SysmonEvents {
    $output = "`n========== Sysmon Event Logs =========="
    if (Get-Service -Name Sysmon -ErrorAction SilentlyContinue) {
        $output += (Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Format-Table TimeCreated, Id, Message -AutoSize | Out-String)
    } else {
        $output += "`n[-] Sysmon is not installed or not running."
    }
    return $output
}

function Get-TcpConnections {
    $output = "`n========== Active TCP Connections =========="
    $output += (Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-UdpConnections {
    $output = "`n========== Active UDP Connections =========="
    $output += (Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-TokenGroups {
    $output = "`n========== Token Groups (User Memberships) =========="
    $output += (whoami /groups | Out-String)
    return $output
}

function Get-TokenPrivileges {
    $output = "`n========== Token Privileges =========="
    $output += (whoami /priv | Out-String)
    return $output
}

function Get-UAC {
    $output = "`n========== User Account Control (UAC) Settings =========="
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    if (Test-Path $uacPath) {
        $output += (Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue | Select-Object ConsentPromptBehaviorAdmin, EnableLUA | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No UAC settings found."
    }

    return $output
}

function Get-UserRightAssignments {
    $output = "`n========== User Right Assignments =========="
    $output += (secedit /export /cfg "$env:TEMP\secpolicy.inf" | Out-String)
    
    if (Test-Path "$env:TEMP\secpolicy.inf") {
        $output += (Get-Content "$env:TEMP\secpolicy.inf" | Out-String)
    } else {
        $output += "`n[-] Unable to retrieve security policies."
    }

    return $output
}

function Get-WMI {
    $output = "`n========== WMI Namespaces and Classes =========="
    $output += (Get-WmiObject -Namespace "root\cimv2" -List | Select-Object Name | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-WMIEventConsumer {
    $output = "`n========== WMI Event Consumers =========="
    $output += (Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer | Select-Object Name, CommandLineTemplate | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-WMIEventFilter {
    $output = "`n========== WMI Event Filters =========="
    $output += (Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Select-Object Name, Query | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-WMIFilterBinding {
    $output = "`n========== WMI Filter Bindings =========="
    $output += (Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-WSUS {
    $output = "`n========== WSUS (Windows Server Update Services) Settings =========="
    $wsusPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"

    if (Test-Path $wsusPath) {
        $output += (Get-ItemProperty -Path $wsusPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No WSUS configuration found."
    }

    return $output
}

function Get-WifiProfile {
    $output = "`n========== Saved WiFi Profiles =========="
    $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile"

    if ($wifiProfiles) {
        $output += "`n[+] Saved WiFi networks detected:"
        $output += ($wifiProfiles | Out-String)
    } else {
        $output += "`n[-] No WiFi profiles found."
    }

    return $output
}

function Get-WindowsAutoLogon {
    $output = "`n========== Windows AutoLogon Settings =========="
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    if (Test-Path $winlogonPath) {
        $output += (Get-ItemProperty -Path $winlogonPath -Name AutoAdminLogon, DefaultUserName, DefaultPassword -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] No autologon settings found."
    }

    return $output
}

function Get-WindowsCredentialFiles {
    $output = "`n========== Windows Credential Files =========="
    $credPath = "$env:APPDATA\Microsoft\Credentials"

    if (Test-Path $credPath) {
        $output += "`n[+] Credential files found:"
        $output += (Get-ChildItem -Path $credPath -Recurse | Format-Table FullName, LastWriteTime -AutoSize | Out-String)
    } else {
        $output += "`n[-] No stored credentials found."
    }

    return $output
}

function Get-WindowsDefender {
    $output = "`n========== Windows Defender Settings =========="
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $output += (Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] Windows Defender is not available on this system."
    }
    return $output
}

function Get-WindowsEventForwarding {
    $output = "`n========== Windows Event Forwarding (WEF) Settings =========="
    $wefPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector"

    if (Test-Path $wefPath) {
        $output += (Get-ItemProperty -Path $wefPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "`n[-] Windows Event Forwarding is not configured."
    }

    return $output
}

function Get-WindowsFirewall {
    $output = "`n========== Windows Firewall Rules =========="
    $output += (Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize | Out-String)
    return $output
}

function Get-WindowsVault {
    $output = "`n========== Windows Vault Stored Credentials =========="
    $vaultCreds = cmdkey /list

    if ($vaultCreds -match "Currently stored credentials") {
        $output += "`n[+] Stored credentials detected:"
        $output += ($vaultCreds | Out-String)
    } else {
        $output += "`n[-] No stored credentials found."
    }

    return $output
}

# -------------------------------
# Admin-Only Checks
# -------------------------------
function Get-AMSIProviders {
    $output = "\n========== AMSI Providers =========="
    if ($localadmin) {
        $output += (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)
    } else {
        $output += "\n[-] Skipping (Admin Required)"
    }
    return $output
}

function Get-ARPTable {
    $output = "\n========== ARP Table =========="
    if ($localadmin) {
        $output += (arp -a | Out-String)
    } else {
        $output += "\n[-] Skipping (Admin Required)"
    }
    return $output
}

function Get-AntiVirusStatus {
    $output = "\n========== Antivirus Status =========="
    if ($localadmin) {
        $output += (Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct | Select-Object displayName,productState | Format-Table | Out-String)
    } else {
        $output += "\n[-] Skipping (Admin Required)"
    }
    return $output
}

function Get-AppLocker {
    $output = "\n========== AppLocker Policies =========="
    if ($localadmin) {
        $output += (Get-AppLockerPolicy -Effective -Xml | Format-Table | Out-String)
    } else {
        $output += "\n[-] Skipping (Admin Required)"
    }
    return $output
}

function Get-AuditPolicies {
    $output = "\n========== Audit Policies =========="
    if ($localadmin) {
        $output += (auditpol /get /category:* | Out-String)
    } else {
        $output += "\n[-] Skipping (Admin Required)"
    }
    return $output
}

function Get-DpapiMasterKeys {
    $output = "\n========== DPAPI Master Keys =========="
    if ($localadmin) {
        $output += (Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Protect" -ErrorAction SilentlyContinue | Out-String)
    } else {
        $output += "\n[-] Skipping (Admin Required)"
    }
    return $output
}


# -------------------------------
# 🔹 Execution Based on Privileges
# -------------------------------
function ORCA {
    Write-Host "\nRunning O.R.C.A. (OS Recon & Configuration Auditor)"
    
    $output = @()
    $output += ""
    $output += "                                               @@@@                                                      "
    $output += "                                       @@@@@@@@@                                                    "
    $output += "                                    @@@@@@@@@@@                                                    "
    $output += "                                 @@@@@@@@@@@@@@                                                    "
    $output += "                              @@@@@@@@@@@@@@@@@                                                    "
    $output += "                            @@@@@@@@@@@@@@@@@@@@@@@@@                                              "
    $output += "                       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                      "
    $output += "                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                "
    $output += "             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                            "
    $output += "         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                       "
    $output += "      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                    "
    $output += "    @@@@@@@@@@%+=--*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 @"
    $output += "  @@@@@@@@@=..    ..%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        @@@@@@@@"
    $output += "@@@@@@@@@=     ..-%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#++++*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
    $output += "@@@@@@@@@@#:. .:*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-.     .  ..*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
    $output += "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=.          .    .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ "
    $output += "@@@@@@@@@@@@@@@@@#-.....:*%@@@@@@@@@@@@@@@@@@@@=.    .  ..::-*%@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@  "
    $output += "@#..+@@@@@@*:.        .       .-#@@@@@@@@@@@@@@#.  .=@@@                    @@@@@@@@@@@@@@@@@@@@    "
    $output += "  @%. ..       . .  .          .  *@@@@@@@@@@@@@@@                              @@@@@@@@@@@@        "
    $output += "     @%*.                  ..  . ..@@@@@@@@@@@@@@@@                              @@@@@@@@@@@        "
    $output += "         @@#**=..     .         .-+*@@@@@@@@@@@@@@@@@@                           @@@@@@@@@@@        "
    $output += "                  @@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@                           @@@@@@@@@@        "
    $output += "                                        @@@@@@@@@@@@@@                            @@@@@@@@@@        "
    $output += "                                             @@@@                                  @@@@@@@@@        "
    $output += "                                                                                    @@@@@@@         "
    $output += "                                                                                      @@@@          "
    $output += "                                                                                       @@           "
    $output += "    ############################################################"
    $output += "    ##     O.R.C.A (OS Recon & Configuration Auditor)        ##"
    $output += "    ##                                                        ##"
    $output += "    ############################################################"
    
    
    # Run Standard User Checks
    Write-Host "[*] Running Standard User Checks..."
    $output += Get-CertificateThumbprints
    $output += Get-ChromiumPresence
    $output += Get-ChromiumBookmarks
    $output += Get-ChromiumHistory
    $output += Get-CloudSyncProviders
    $output += Get-CredEnum
    $output += Get-CredGuard
    #$output += Get-DNSCache big
    $output += Get-DotNetVersion
    $output += Get-EnvironmentPath
    $output += Get-EnvironmentVariables
    #$output += Get-ExplicitLogonEvents slow
    #$output += Get-ExplorerMRUs looks unnecessary
    $output += Get-ExplorerRunCommands
    $output += Get-FileInfo
    $output += Get-FileZilla
    $output += Get-FirefoxPresence
    $output += Get-FirefoxHistory
    #$output += Get-Hotfixes slow but necessary
    $output += Get-IEFavorites
    $output += Get-IETabs
    $output += Get-IEUrls
    $output += Get-IdleTime
    $output += Get-InstalledProducts
    $output += Get-InterestingFiles
    # $output += Get-InterestingProcesses define interesting...
    # $output += Get-InternetSettings looks unneccessary
    $output += Get-KeePass
    $output += Get-LAPS
    $output += Get-LSASettings
    $output += Get-LastShutdown
    # $output += Get-LocalGPOs very unsure this works
    $output += Get-LocalGroups
    $output += Get-LocalUsers
    #$output += Get-LogonEvents slow
    $output += Get-LogonSessions
    $output += Get-MTPuTTY
    $output += Get-MappedDrives
    $output += Get-McAfeeConfigs
    $output += Get-McAfeeSiteList
    #$output += Get-MicrosoftUpdates slow
    $output += Get-NTLMSettings
    #$output += Get-NamedPipes no clue what this does
    $output += Get-NetworkShares
    $output += Get-OSInfo
    $output += Get-OfficeMRUs
    $output += Get-OneNote
    $output += Get-OracleSQLDeveloper
    $output += Get-OutlookDownloads
    $output += Get-PowerShell
    #$output += Get-PSSessionSettings does ask you to start winrm?
    $output += Get-PowerShellEvents
    $output += Get-PowerShellHistory
    $output += Get-PoweredOnEvents
    $output += Get-Printers
    #$output += Get-ProcessCreationEvents slow
    $output += Get-ProcessOwners
    $output += Get-Processes
    $output += Get-PuttyHostKeys
    $output += Get-PuttySessions
    $output += Get-RDCManFiles
    $output += Get-RDPSavedConnections
    $output += Get-RDPSessions
    $output += Get-RDPSettings
    $output += Get-RPCMappedEndpoints
    $output += Get-RecycleBin
    $output += Get-SCCM
    $output += Get-ScheduledTasks
    $output += Get-SearchIndex
    $output += Get-SecPackageCreds
    $output += Get-SecurityPackages
    $output += Get-Services
    $output += Get-SlackDownloads #really?
    $output += Get-SlackWorkspaces #really?
    $output += Get-SuperPuTTY
    $output += Get-Sysmon
    $output += Get-SysmonEvents
    $output += Get-TcpConnections
    $output += Get-UdpConnections
    $output += Get-TokenPrivileges
    $output += Get-UAC
    $output += Get-UserRightAssignments
    #$output += Get-WMI #needed?
    $output += Get-WMIEventConsumer
    $output += Get-WMIEventFilter
    $output += Get-WMIFilterBinding
    $output += Get-WSUS
    $output += Get-WindowsAutoLogon
    $output += Get-WindowsCredentialFiles
    $output += Get-WindowsDefender
    $output += Get-WindowsEventForwarding
    $output += Get-WindowsFirewall
    $output += Get-WindowsVault


    # Run Admin-Only Checks if -localadmin is provided
    if ($localadmin) {
        Write-Host "[*] Running Admin-Only Checks..."
        $output += Get-AMSIProviders
        $output += Get-ARPTable
        $output += Get-AntiVirusStatus
        $output += Get-AppLocker
        $output += Get-AuditPolicies
        $output += Get-DpapiMasterKeys
    }

    # Output Handling
    if ($o.Length -gt 0) {
        $output -join "`r`n" | Out-File -FilePath $o -Encoding utf8
    } else {
        Clear-Host
        Write-Output ($output -join "`r`n")
    }
}

# Run ORCA
ORCA
