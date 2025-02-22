# orca - a Windows Enumeration Script

orca (OS Recon & Configuration Auditor) is a PowerShell script that enumerates Windows system information for both standard and admin users. It can also run extended checks that are more time-consuming, but provide deeper insights.

## Usage

```
PS C:> .\orca.ps1 [-localadmin] [-extended] [-o <filename>]
```

### Parameters

- **-localadmin**  
  Runs admin-only checks in addition to standard checks.
- **-extended**  
  Includes extended (slower) checks.
- **-o <filename>**  
  Writes results to the specified file (e.g., `-o results.txt`).

## Checks

Following is a list of all the functions orca performs:

### Standard User Checks

- Get-CertificateThumbprints  
- Get-ChromiumPresence  
- Get-ChromiumBookmarks  
- Get-ChromiumHistory  
- Get-CloudSyncProviders  
- Get-CredEnum  
- Get-CredGuard  
- Get-DotNetVersion  
- Get-EnvironmentPath  
- Get-EnvironmentVariables  
- Get-ExplorerRunCommands  
- Get-FileInfo  
- Get-FileZilla  
- Get-FirefoxPresence  
- Get-FirefoxHistory  
- Get-IEFavorites  
- Get-IETabs  
- Get-IEUrls  
- Get-IdleTime  
- Get-InstalledProducts  
- Get-InterestingFiles  
- Get-KeePass  
- Get-LAPS  
- Get-LSASettings  
- Get-LastShutdown  
- Get-LocalGroups  
- Get-LocalUsers  
- Get-LogonSessions  
- Get-MTPuTTY  
- Get-MappedDrives  
- Get-McAfeeConfigs  
- Get-McAfeeSiteList  
- Get-NTLMSettings  
- Get-NamedPipes  
- Get-NetworkShares  
- Get-OSInfo  
- Get-OfficeMRUs  
- Get-OneNote  
- Get-OracleSQLDeveloper  
- Get-OutlookDownloads  
- Get-PowerShell  
- Get-PowerShellEvents  
- Get-PowerShellHistory  
- Get-PoweredOnEvents  
- Get-Printers  
- Get-ProcessOwners  
- Get-Processes  
- Get-PuttyHostKeys  
- Get-PuttySessions  
- Get-RDCManFiles  
- Get-RDPSavedConnections  
- Get-RDPSessions  
- Get-RDPSettings  
- Get-RPCMappedEndpoints  
- Get-RecycleBin  
- Get-SCCM  
- Get-ScheduledTasks  
- Get-SearchIndex  
- Get-SecPackageCreds  
- Get-SecurityPackages  
- Get-Services  
- Get-SlackDownloads  
- Get-SlackWorkspaces  
- Get-SuperPuTTY  
- Get-Sysmon  
- Get-SysmonEvents  
- Get-TcpConnections  
- Get-UdpConnections  
- Get-TokenPrivileges  
- Get-UAC  
- Get-UserRightAssignments  
- Get-WMIEventConsumer  
- Get-WMIEventFilter  
- Get-WMIFilterBinding  
- Get-WSUS  
- Get-WindowsAutoLogon  
- Get-WindowsCredentialFiles  
- Get-WindowsDefender  
- Get-WindowsEventForwarding  
- Get-WindowsFirewall  
- Get-WindowsVault  

### Admin-Only Checks (if -localadmin)

- Get-AMSIProviders  
- Get-ARPTable  
- Get-AntiVirusStatus  
- Get-AppLocker  
- Get-AuditPolicies  
- Get-DpapiMasterKeys  

### Extended Checks (if -extended)

- Get-ExplicitLogonEvents  
- Get-Hotfixes  
- Get-ProcessCreationEvents  
- Get-MicrosoftUpdates  
- Get-LogonEvents

