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
    [String]$OutputFilename = ""
)

# -------------------------------
# 📌 Module: Security & System Hardening
# -------------------------------
function Get-AMSIProviders {
    Write-Host "[*] Checking AMSI Providers (Admin Required)..."
    if ($localadmin) {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue | Format-Table -AutoSize
    } else {
        Write-Host "[-] Skipping (Admin Required)"
    }
}

function Get-ARPTable {
    Write-Host "[*] Enumerating ARP Table..."
    arp -a | Out-String
}

function Get-AppLocker {
    Write-Host "[*] Checking AppLocker Policies (Admin Required)..."
    if ($localadmin) {
        Get-AppLockerPolicy -Effective -Xml | Format-Table
    } else {
        Write-Host "[-] Skipping (Admin Required)"
    }
}

function Get-AntiVirusStatus {
    Write-Host "[*] Checking Antivirus Status (Admin Required)..."
    if ($localadmin) {
        Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct | Select-Object displayName,productState | Format-Table
    } else {
        Write-Host "[-] Skipping (Admin Required)"
    }
}

function Get-AuditPolicies {
    Write-Host "[*] Checking Audit Policies (Admin Required)..."
    if ($localadmin) {
        auditpol /get /category:* | Out-String
    } else {
        Write-Host "[-] Skipping (Admin Required)"
    }
}

# -------------------------------
# 📌 Module: System Certificates
# -------------------------------
function Get-Certificates {
    Write-Host "[*] Checking Installed Certificates..."
    Get-ChildItem -Path Cert:\LocalMachine\My | Select Subject, Thumbprint, NotAfter | Format-Table -AutoSize
}

# -------------------------------
# 📌 Module: User Artifacts
# -------------------------------
function Get-ChromiumBookmarks {
    Write-Host "[*] Checking Chromium Bookmarks..."
    Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks" -ErrorAction SilentlyContinue | Out-String
}

# -------------------------------
# 🔹 Execution Based on Privileges
# -------------------------------
function ORCA {
    Write-Host "\nRunning O.R.C.A. (OS Recon & Configuration Auditor)"
    
    $output = @()
    $output += "############################################################"
    $output += "##     O.R.C.A (OS Recon & Configuration Auditor)        ##"
    $output += "##                                                        ##"
    $output += "############################################################"
    
    # Run Non-Admin Checks
    Write-Host "[*] Running Standard User Checks..."
    $output += Get-ARPTable | Out-String
    $output += Get-Certificates | Out-String
    $output += Get-ChromiumBookmarks | Out-String
    
    # Run Admin-Only Checks if -localadmin is provided
    if ($localadmin) {
        Write-Host "[*] Running Admin-Only Checks..."
        $output += Get-AMSIProviders | Out-String
        $output += Get-AppLocker | Out-String
        $output += Get-AntiVirusStatus | Out-String
        $output += Get-AuditPolicies | Out-String
    }

    # Output Handling
    if ($OutputFilename.Length -gt 0) {
        $output -join "`r`n" | Out-File -FilePath $OutputFilename -Encoding utf8
    } else {
        Clear-Host
        Write-Output ($output -join "`r`n")
    }
}

# Run ORCA
ORCA
