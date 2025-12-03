# PKI Deployment Instructions

## 1 Domain Controller

### 1.1 SPN and Service Account

```powershell
<#
.SYNOPSIS
  Create/update PKI web service account, register SPNs, configure Resource-Based Constrained Delegation (RBCD)
  on target CA computers, and validate the ACLs.

.NOTES
  - Run elevated on a Domain Controller or an RSAT host with ActiveDirectory module.
  - Requires appropriate AD permissions: creating users/groups requires delegated rights; RBCD changes require Enterprise Admin or equivalent.
  - Edit $SvcSam, $GroupName, $HostNames, and $TargetComputers to match your environment before running.
#>

Import-Module ActiveDirectory -ErrorAction Stop

# -------------------------
# Configuration - edit these
# -------------------------
$SvcSam         = "PKIWebSvc"                # sAMAccountName for service account
$GroupName      = "PKI Web Servers"          # Group to contain web servers (optional)
$HostNames      = @("pki","req")             # Hostname(s) used by the service (short names)
$TargetComputers = @("subca1","subca2")      # CA computer names for RBCD (sAMAccountName)
# -------------------------

# Derive domain information
$adDomain = Get-ADDomain -ErrorAction Stop
$DomainDns = $adDomain.DNSRoot                # e.g. lab.local
$DomainNetBios = $adDomain.NetBIOSName        # e.g. LAB

Write-Host ( "Domain DNS: {0}   NetBIOS: {1}" -f $DomainDns, $DomainNetBios ) -ForegroundColor Cyan

# Prompt for password (secure)
$pwd = Read-Host -Prompt ( "Enter password for {0}\{1} (secure input)" -f $DomainNetBios, $SvcSam ) -AsSecureString

# -------------------------
# Create or update service account
# -------------------------
$existing = Get-ADUser -Filter "SamAccountName -eq '$SvcSam'" -ErrorAction SilentlyContinue

if (-not $existing) {
    Write-Host ( "Creating service account: {0}\{1}" -f $DomainNetBios, $SvcSam ) -ForegroundColor Green

    $display = "$SvcSam Service Account"
    $upn = "{0}@{1}" -f $SvcSam, $DomainDns

    New-ADUser -Name $display `
        -GivenName $SvcSam `
        -Surname "Service Account" `
        -DisplayName $display `
        -SamAccountName $SvcSam `
        -UserPrincipalName $upn `
        -AccountPassword $pwd `
        -Enabled $true `
        -PasswordNeverExpires $false `
        -Description "Service account for PKI Web Enrollment / ReqSite"

    Write-Host ( "Created: {0} (UPN: {1})" -f $display, $upn ) -ForegroundColor Green
} else {
    Write-Host ( "Service account {0} exists. Updating display/UPN fields." -f $SvcSam ) -ForegroundColor Yellow
    $display = "$SvcSam Service Account"
    $upn = "{0}@{1}" -f $SvcSam, $DomainDns

    Set-ADUser -Identity $SvcSam `
        -GivenName $SvcSam `
        -Surname "Service Account" `
        -DisplayName $display `
        -UserPrincipalName $upn `
        -Description "Service account for PKI Web Enrollment / ReqSite"

    Write-Host ( "Updated: {0} (UPN: {1})" -f $display, $upn ) -ForegroundColor Green
}

# -------------------------
# Create group and add membership
# -------------------------
if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Description "Group for PKI web servers"
    Write-Host ( "Created group: {0}" -f $GroupName ) -ForegroundColor Green
} else {
    Write-Host ( "Group {0} already exists." -f $GroupName ) -ForegroundColor Yellow
}

# Add service account to group (idempotent)
try {
    Add-ADGroupMember -Identity $GroupName -Members $SvcSam -ErrorAction Stop
    Write-Host ( "Added {0} to {1}" -f $SvcSam, $GroupName ) -ForegroundColor Green
} catch {
    $msg = $_.Exception.Message
    if ($msg -match "Some or all of the specified accounts are already members") {
        Write-Host ( "{0} already a member of {1}" -f $SvcSam, $GroupName ) -ForegroundColor Gray
    } else {
        Write-Warning ( "Could not add {0} to {1}: {2}" -f $SvcSam, $GroupName, $msg )
    }
}

# -------------------------
# Register SPNs
# -------------------------
# Build SPN list using hostnames (short + FQDN)
$spns = @()
foreach ($h in $HostNames) {
    $spns += "HTTP/$h.$DomainDns"
    $spns += "HTTP/$h"
}

Write-Host "`nChecking for duplicate SPNs in domain..." -ForegroundColor Cyan
try {
    & setspn -X 2>&1 | ForEach-Object { Write-Host $_ }
} catch {
    Write-Warning ( "setspn -X failed or not available in this environment: {0}" -f $_.Exception.Message )
}

# Register SPNs to the service account (use -S to avoid duplicates)
foreach ($spn in $spns) {
    Write-Host ( "Registering SPN: {0} -> {1}\{2}" -f $spn, $DomainNetBios, $SvcSam )
    try {
        & setspn -S $spn "$DomainNetBios\$SvcSam" 2>&1 | ForEach-Object { Write-Host $_ }
    } catch {
        Write-Warning ( "Failed to register SPN {0}: {1}" -f $spn, $_.Exception.Message )
    }
}

# -------------------------
# Configure Resource-Based Constrained Delegation (RBCD)
# -------------------------
Write-Host ( "" )  # newline separator
Write-Host ( "🚀 Configuring RBCD: {0}\{1} → {2}" -f $DomainNetBios, $SvcSam, ($TargetComputers -join ', ') ) -ForegroundColor Cyan

# RBCD GUID for msDS-AllowedToActOnBehalfOfOtherIdentity extended right
$RBCD_GUID = [guid]"cc05a6da-1a38-433b-b09c-9f4d07f55eaa"

# Build trustee NTAccount
$trusteeName = "$DomainNetBios\$SvcSam"
$trustee = [System.Security.Principal.NTAccount]$trusteeName

foreach ($computer in $TargetComputers) {
    Write-Host ( "`n📋 Processing {0}..." -f $computer ) -ForegroundColor Green
    try {
        $target = Get-ADComputer -Identity $computer -ErrorAction Stop

        # Create ACE granting ExtendedRight for RBCD
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $trustee,
            [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight",
            [System.Security.AccessControl.AccessControlType]::Allow,
            $RBCD_GUID
        )

        # Apply ACE onto computer object's ACL
        $adPath = "AD:$($target.DistinguishedName)"
        $acl = Get-Acl -Path $adPath
        $acl.AddAccessRule($ace)
        Set-Acl -Path $adPath -AclObject $acl

        Write-Host ( "  ✅ RBCD GRANTED: {0} → {1}" -f $trusteeName, $computer ) -ForegroundColor Green
    } catch {
        Write-Host ( "  ❌ FAILED {0}: {1}" -f $computer, $_.Exception.Message ) -ForegroundColor Red
    }
}

Write-Host ( "" )
Write-Host ( "🎉 RBCD CONFIGURATION COMPLETE!" ) -ForegroundColor Green
Write-Host ( "⏳ Replication: Allow time for AD replication if present." ) -ForegroundColor Yellow

# -------------------------
# Validate RBCD
# -------------------------
Write-Host ( "" )
Write-Host ( "🔍 RBCD VALIDATION REPORT" ) -ForegroundColor Cyan
$AllGood = $true

foreach ($computer in $TargetComputers) {
    try {
        $target = Get-ADComputer -Identity $computer -Properties DistinguishedName -ErrorAction Stop
        $adPath = "AD:$($target.DistinguishedName)"
        $acl = Get-Acl -Path $adPath

        $rbcdAce = $acl.Access | Where-Object {
            $_.ObjectType -eq $RBCD_GUID -and ($_.IdentityReference -like "*$SvcSam*" -or $_.IdentityReference -like "*$DomainNetBios*")
        }

        Write-Host ( "{0} :" -f $computer ) -NoNewline -ForegroundColor Cyan

        if ($rbcdAce) {
            Write-Host " ✅ VALID RBCD ACE" -ForegroundColor Green
            foreach ($ace in $rbcdAce) {
                Write-Host ( "  👤 User: {0}" -f $ace.IdentityReference ) -ForegroundColor White
                Write-Host ( "  ⚡ Right: {0}" -f $ace.ActiveDirectoryRights ) -ForegroundColor White
                Write-Host ( "  🔑 GUID: {0}" -f $ace.ObjectType ) -ForegroundColor Gray
            }
        } else {
            Write-Host " ❌ RBCD ACE MISSING!" -ForegroundColor Red
            $AllGood = $false
        }
    } catch {
        Write-Host ( "{0} : ❌ ERROR - {1}" -f $computer, $_.Exception.Message ) -ForegroundColor Red
        $AllGood = $false
    }
    Write-Host ""
}

# Final summary
Write-Host ( "📊 VALIDATION SUMMARY:" ) -ForegroundColor Yellow
if ($AllGood) {
    Write-Host ( "  🎉 ALL RBCD ACES VALIDATED SUCCESSFULLY!" ) -ForegroundColor Green
    Write-Host ( "  ✅ {0}\{1} can delegate to all target CAs" -f $DomainNetBios, $SvcSam ) -ForegroundColor Green
} else {
    Write-Host ( "  ⚠️  SOME RBCD ACES MISSING - Review output above and re-run configuration as needed." ) -ForegroundColor Red
}

Write-Host ( "" )
Write-Host ( "✅ EXPECTED STATE:" ) -ForegroundColor Gray
Write-Host ( "   • PKIWebSvc Delegation tab: 'Do not trust' (on PKIWebSvc account)" ) -ForegroundColor Gray
Write-Host ( "   • CA Servers Delegation tab: 'Do not trust' (on CA server objects)" ) -ForegroundColor Gray
Write-Host ( "   • RBCD ACE: Present in CA computer object's nTSecurityDescriptor only" ) -ForegroundColor Gray

# End of script
```

### 1.2 Script Output

<img title="a title" alt="Alt text" src="PKILab-1-DC-SPN-SVCAcct-Output.jpg"> 

## 2 File Server

### 2.1 PKIData Share and permissions
## Run this script on File1.lab.local and File2.lab.local
```powershell
<#
.SYNOPSIS
  Configures the PKIData share on a target file server.
  - Creates C:\PKIData if missing.
  - Creates SMB share 'PKIData' if missing.
  - Grants SMB and NTFS permissions to specified CA, web, OCSP machine accounts,
    and the PKIWebSvc service account.

.PARAMETER TargetServer
  The hostname (short name or FQDN) of the file server to configure.
  Defaults to the local computer's hostname if not specified.

.NOTES
  - Run elevated on the target file server or remotely with appropriate permissions.
  - Edit hostnames in the Configuration section if your environment differs.
#>

[CmdletBinding()]
param(
    [string]$TargetServer = $env:COMPUTERNAME
)

# -------------------------
# Configuration (edit if needed)
# -------------------------
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$PkiFolderName    = "PKIData" # This will also be the name of the SMB share

# Server hostnames used by share ACLs (FQDN)
# These are the *machine accounts* that need access to the share.
$SubCA1           = "subca1.lab.local"
$SubCA2           = "subca2.lab.local"
$WebServer1       = "web01.lab.local"
$WebServer2       = "web02.lab.local"
$OcspServer1      = "ocsp1.lab.local"
$OcspServer2      = "ocsp2.lab.local"

# Service account (must exist in AD)
$PkiWebSvcAccount = "PKIWebSvc"

# Derived path (auto-calculated)
# Using Join-Path for robust path construction
$LocalPkiFolder   = Join-Path -Path "C:\" -ChildPath $PkiFolderName
# -------------------------


Write-Host ( "Starting PKI share configuration on: {0}" -f $TargetServer ) -ForegroundColor Cyan
Write-Host ( "Local folder: {0}" -f $LocalPkiFolder ) -ForegroundColor Cyan
Write-Host ( "Share name: {0}" -f $PkiFolderName ) -ForegroundColor Cyan # Use $PkiFolderName directly

# 1) Create the local folder if missing
Write-Host ( "Checking for local folder: {0}" -f $LocalPkiFolder ) -ForegroundColor DarkGray
if (-not (Test-Path -Path $LocalPkiFolder)) {
    Write-Host ( "Creating folder: {0}" -f $LocalPkiFolder ) -ForegroundColor Green
    New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null
} else {
    Write-Host ( "Folder already exists: {0}" -f $LocalPkiFolder ) -ForegroundColor Gray
}

# 2) Create SMB share if missing
Write-Host ( "Checking for SMB share: {0}" -f $PkiFolderName ) -ForegroundColor DarkGray # Use $PkiFolderName directly
if (-not (Get-SmbShare -Name $PkiFolderName -ErrorAction SilentlyContinue)) { # Use $PkiFolderName directly
    Write-Host ( "Creating SMB share '{0}' -> {1}" -f $PkiFolderName, $LocalPkiFolder ) -ForegroundColor Green # Use $PkiFolderName directly
    New-SmbShare -Name $PkiFolderName -Path $LocalPkiFolder -FullAccess "Administrators","SYSTEM" -ErrorAction Stop # Use $PkiFolderName directly
} else {
    Write-Host ( "SMB share '{0}' already exists." -f $PkiFolderName ) -ForegroundColor Gray # Use $PkiFolderName directly
}

# 3) Extract short hostnames (machine account names) for ACLs
$SubCA1Short  = ($SubCA1 -split '\.')[0]
$SubCA2Short  = ($SubCA2 -split '\.')[0]
$Web1Short    = ($WebServer1 -split '\.')[0]
$Web2Short    = ($WebServer2 -split '\.')[0]
$Ocsp1Short   = ($OcspServer1 -split '\.')[0]
$Ocsp2Short   = ($OcspServer2 -split '\.')[0]

# Define all accounts that need access
$accountsForShareAccess = @(
    "$DomainNetBios\$SubCA1Short`$",
    "$DomainNetBios\$SubCA2Short`$",
    "$DomainNetBios\$Web1Short`$",
    "$DomainNetBios\$Web2Short`$",
    "$DomainNetBios\$Ocsp1Short`$",
    "$DomainNetBios\$Ocsp2Short`$",
    "$DomainNetBios\$PkiWebSvcAccount"
)

# 4) Grant SMB share access
Write-Host ( "Granting SMB share access to required accounts..." ) -ForegroundColor Cyan
foreach ($account in $accountsForShareAccess) {
    $accessRight = "Read"
    if ($account -like "*$SubCA1Short`$*" -or $account -like "*$SubCA2Short`$*") {
        $accessRight = "Change" # CAs need Change for publishing
    }
    Write-Host ( "  Granting '{0}' access to '{1}' on share '{2}'" -f $accessRight, $account, $PkiFolderName ) -ForegroundColor DarkGray # Use $PkiFolderName directly
    Grant-SmbShareAccess -Name $PkiFolderName -AccountName $account -AccessRight $accessRight -Force -ErrorAction SilentlyContinue # Use $PkiFolderName directly
}

# 5) NTFS Permissions
Write-Host ( "Applying NTFS permissions on {0}..." -f $LocalPkiFolder ) -ForegroundColor Cyan

# Base permissions for SYSTEM and Administrators
icacls $LocalPkiFolder /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T | Out-Null

# Permissions for machine accounts and service account
$accountsForNtfs = @(
    @{ Name = "$DomainNetBios\$SubCA1Short`$"; Rights = "(OI)(CI)M" }, # CAs need Modify
    @{ Name = "$DomainNetBios\$SubCA2Short`$"; Rights = "(OI)(CI)M" },
    @{ Name = "$DomainNetBios\$Web1Short`$"; Rights = "(OI)(CI)RX" }, # Web servers need Read/Execute
    @{ Name = "$DomainNetBios\$Web2Short`$"; Rights = "(OI)(CI)RX" },
    @{ Name = "$DomainNetBios\$Ocsp1Short`$"; Rights = "(OI)(CI)RX" }, # OCSP servers need Read/Execute
    @{ Name = "$DomainNetBios\$Ocsp2Short`$"; Rights = "(OI)(CI)RX" },
    @{ Name = "${DomainNetBios}\${PkiWebSvcAccount}"; Rights = "(OI)(CI)RX" } # PKIWebSvc needs Read/Execute
)

foreach ($aclEntry in $accountsForNtfs) {
    Write-Host ( "  Granting '{0}' to '{1}' on folder '{2}'" -f $aclEntry.Rights, $aclEntry.Name, $LocalPkiFolder ) -ForegroundColor DarkGray
    icacls $LocalPkiFolder /grant "$($aclEntry.Name):$($aclEntry.Rights)" /T | Out-Null
}

# --- New Section: Display Final Share Permissions ---
Write-Host "`nSMB Share Permissions for '$PkiFolderName':" -ForegroundColor Cyan
Get-SmbShareAccess -Name $PkiFolderName |
    Select-Object AccountName, AccessRight, AccessControlType |
    Format-Table -AutoSize

Write-Host ( "PKI share configuration complete on {0}!" -f $TargetServer ) -ForegroundColor Green
```

<img title="a title" alt="Alt text" src="PKILab-2-FileServer-PKIDataShare-Output.jpg"> 

## 3 DFS

### 3.1 DFS configuration

```text
DFS will be installed via Server Manager GUI on both File servers
The configuration is represented in the following diagrams
```

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config1.jpg">    

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config2.jpg">    

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config3.jpg">    

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config4.jpg">    

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config5.jpg">    

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config6.jpg">    

<img title="a title" alt="Alt text" src="PKILab-3-DFS-Config7.jpg">    
```

## 4 Web Server
### 4.1 pki.lab.local/pkidata

```text
This script will configure a dedicated IIS site for use with pki.lab.local/pkidata
```


```powershell
<#
.SYNOPSIS
  Configures a dedicated IIS site for PKI HTTP (/pkidata) publishing (CDP/AIA).
  - Creates a new IIS site bound to pki.lab.local.
  - Creates /pkidata application under this site, pointing to the DFS share.
  - Configures application pool, authentication, and MIME types.
  - Plain-text password prompt for LAB\PKIWebSvc (temporary).
  - Run elevated. Use -Verbose. Logs to %ProgramData%\PKI-Logs.
#>

param()

# Ensure elevated
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script elevated (Run as Administrator)." ; exit 1
}

# Start transcript/log
$logDir = Join-Path $env:ProgramData "PKI-Logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$logFile = Join-Path $logDir "PKIData-Setup-${env:COMPUTERNAME}-${timestamp}.log"
Start-Transcript -Path $logFile -Force
Write-Verbose "Transcript started: ${logFile}"

# CONFIG
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"
$DfsPkiPath       = Join-Path $DfsRoot $PkiFolderName
$PkiHttpHost      = "pki.lab.local"
$PKIHttpPool      = "PKIHttpPool"
$PkiWebSvcAccount = "PKIWebSvc"
$serviceAccount   = "${DomainNetBios}\${PkiWebSvcAccount}"

# New site specific variables
$PKIDataSiteName  = "PKIDataSite"
$PKIDataSiteRoot  = "C:\InetPub\PKIDataSiteRoot" # Placeholder physical path for the site root

# Prompt for plain-text password (temporary plaintext)
Write-Host "Enter plain-text password for ${serviceAccount} (will be used to set IIS app pool identity)." -ForegroundColor Yellow
$passwordPlain = Read-Host -Prompt "Password (plain text)"

# Required features
$requiredFeatures = @(
    "Web-Server",
    "Web-Static-Content",
    "Web-Default-Doc",
    "Web-ISAPI-Ext",
    "Web-ISAPI-Filter",
    "Web-Scripting-Tools"
)

foreach ($feature in $requiredFeatures) {
    try {
        $status = Get-WindowsFeature -Name $feature -ErrorAction Stop
        if (-not $status.Installed) {
            Write-Verbose "Installing feature: ${feature}"
            Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop | Out-Null
            Write-Host "Installed feature: ${feature}" -ForegroundColor Green
        } else {
            Write-Verbose "Feature already installed: ${feature}"
        }
    } catch {
        Write-Warning "Could not query/install feature ${feature}: $($_.Exception.Message)"
    }
}

# Import IIS module
Import-Module WebAdministration -ErrorAction Stop

try {
    # 1) Create PKIHttpPool and set identity
    if (-not (Test-Path "IIS:\AppPools\${PKIHttpPool}")) {
        New-WebAppPool -Name $PKIHttpPool | Out-Null
        Write-Verbose "Created app pool ${PKIHttpPool}"
    }
    Set-ItemProperty "IIS:\AppPools\${PKIHttpPool}" -Name processModel.identityType -Value 3
    Set-ItemProperty "IIS:\AppPools\${PKIHttpPool}" -Name processModel.userName -Value $serviceAccount
    Set-ItemProperty "IIS:\AppPools\${PKIHttpPool}" -Name processModel.password -Value $passwordPlain
    Restart-WebAppPool $PKIHttpPool
    Write-Host "Configured app pool ${PKIHttpPool} to run as ${serviceAccount}" -ForegroundColor Green

    # 2) Create PKIDataSite
    Write-Host "Creating dedicated IIS site: ${PKIDataSiteName} bound to ${PkiHttpHost}" -ForegroundColor Cyan
    if (-not (Test-Path $PKIDataSiteRoot)) { New-Item -Path $PKIDataSiteRoot -ItemType Directory -Force | Out-Null; Write-Verbose "Created ${PKIDataSiteRoot}" }

    $pkiDataSite = Get-Website -Name $PKIDataSiteName -ErrorAction SilentlyContinue
    if (-not $pkiDataSite) {
        New-Website -Name $PKIDataSiteName -Port 80 -HostHeader $PkiHttpHost -PhysicalPath $PKIDataSiteRoot -ApplicationPool $PKIHttpPool
        Write-Host "Created site ${PKIDataSiteName} with HTTP binding for ${PkiHttpHost}" -ForegroundColor Green
    } else {
        Write-Verbose "Site ${PKIDataSiteName} already exists."
        # Ensure the site is using the correct app pool
        Set-ItemProperty "IIS:\Sites\${PKIDataSiteName}" -Name applicationPool -Value $PKIHttpPool
        Write-Verbose "Set application pool for ${PKIDataSiteName} to ${PKIHttpPool}"
        # Ensure HTTP binding exists
        if (-not (Get-WebBinding -Name $PKIDataSiteName -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue)) {
            New-WebBinding -Name $PKIDataSiteName -Protocol http -Port 80 -HostHeader $PkiHttpHost
            Write-Host "Added HTTP binding for ${PkiHttpHost} to ${PKIDataSiteName}" -ForegroundColor Green
        }
    }
    Start-Website $PKIDataSiteName

    # 3) Create /pkidata application under the new site, pointing to DFS
    Write-Host "Configuring /pkidata application under ${PKIDataSiteName}..." -ForegroundColor Cyan
    if (-not (Test-Path $DfsPkiPath)) {
        Write-Warning "DFS path ${DfsPkiPath} not reachable. Check network/permissions for ${serviceAccount}."
    }

    $pkiApp = Get-WebApplication -Site $PKIDataSiteName -Name "pkidata" -ErrorAction SilentlyContinue
    if (-not $pkiApp) {
        New-WebApplication -Site $PKIDataSiteName -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
        Write-Host "Created application ${PKIDataSiteName}/pkidata -> ${DfsPkiPath} using ${PKIHttpPool}" -ForegroundColor Green
    } else {
        Set-WebApplication -Site $PKIDataSiteName -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
        Write-Verbose "Ensured application ${PKIDataSiteName}/pkidata uses ${PKIHttpPool} and points to ${DfsPkiPath}"
    }

    # 4) Configure authentication and directory browsing for /pkidata (anonymous enabled)
    # These settings are now applied specifically to the /pkidata application under PKIDataSite
    Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow -ErrorAction SilentlyContinue
    Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow -ErrorAction SilentlyContinue

    Set-WebConfigurationProperty -PSPath "IIS:\Sites\${PKIDataSiteName}\pkidata" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value $true
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\${PKIDataSiteName}\pkidata" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name userName -Value ""
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\${PKIDataSiteName}\pkidata" -Filter /system.webServer/security/authentication/windowsAuthentication -Name enabled -Value $false

    Set-WebConfigurationProperty -PSPath "IIS:\Sites\${PKIDataSiteName}\pkidata" -Filter /system.webServer/directoryBrowse -Name enabled -Value $true
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\${PKIDataSiteName}" -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true # Apply to the site

    # 5) Ensure mime types for crl/crt
    function Ensure-MimeType {
        param([string]$Extension,[string]$MimeType)
        $existing = Get-WebConfigurationProperty -pspath 'IIS:\' -filter 'system.webServer/staticContent/mimeMap' -name '.' |
            Where-Object { $_.fileExtension -eq $Extension }
        if (-not $existing) {
            Add-WebConfigurationProperty -pspath 'IIS:\' -filter 'system.webServer/staticContent' -name '.' -value @{ fileExtension = $Extension; mimeType = $MimeType }
            Write-Verbose "Added mime type ${Extension} -> ${MimeType}"
        } else {
            Write-Verbose "Mime type for ${Extension} already exists"
        }
    }
    Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
    Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'

    # Restart relevant pools and IIS to ensure changes take effect
    Restart-WebAppPool $PKIHttpPool
    Write-Host "`n[INFO] PKI HTTP (${PKIDataSiteName}/pkidata) configuration complete." -ForegroundColor Green

} catch {
    Write-Error "Error configuring PKI HTTP: $($_.Exception.Message)"
    throw
} finally {
    # Clear plaintext password variable from memory (best-effort)
    $passwordPlain = $null
    Stop-Transcript | Out-Null
}
```

### 4.2 pki.lab.local/pkidata Output

<img title="a title" alt="Alt text" src="PKILab-4-IIS-PKIData-Output1.jpg">    

<img title="a title" alt="Alt text" src="PKILab-4-IIS-PKIData-Output2.jpg">    


## 5 Root CA
### 5.1 Rooot CA initial Install

```powershell

### RUN THIS ENTIRE SCRIPT ON THE OFFLINE ROOT CA SERVER (elevated PowerShell)
### This script configures the CA and generates the cert/CRL.
### Manual steps are required afterward to move files and publish to AD.

### 1 - Common Variables
$DomainFqdn    = "lab.local"
$PkiHttpHost   = "pki.lab.local"
$RootCAName    = "Lab Root CA"

# Derived
$PkiHttpBase   = "http://$PkiHttpHost/pkidata"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"

### 2 - Create CAPolicy.inf
Write-Host "Creating CAPolicy.inf..." -ForegroundColor Cyan
$caPolicyContent = @"
[Version]
Signature=`$Windows NT`$

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@
Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
Write-Host "CAPolicy.inf created successfully." -ForegroundColor Green

### 3 - Install AD CS Role and Configure Root CA
Write-Host "Installing ADCS-Cert-Authority feature..." -ForegroundColor Cyan
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

Write-Host "Configuring Standalone Root CA..." -ForegroundColor Cyan
$vCaRootProperties = @{
  CACommonName              = $RootCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'StandaloneRootCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  ValidityPeriod            = 'Years'
  ValidityPeriodUnits       = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force
Write-Host "Root CA installed and configured." -ForegroundColor Green

### 4 - Configure Validity and CRL Settings
Write-Host "Setting CA validity, CRL periods, and audit filter..." -ForegroundColor Cyan
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod "Years"
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Years"
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod "Days"
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
Write-Host "CA settings configured and service restarted." -ForegroundColor Green

### 5 - Configure CDP and AIA locations
Write-Host "Configuring CDP and AIA locations..." -ForegroundColor Cyan
Import-Module ADCSAdministration

# ---- CDP (CRL Distribution Points) ----
Write-Host "  Setting CDP locations..." -ForegroundColor Gray
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACRLDistributionPoint -Uri "$CertEnrollDir\%3%8.crl" -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri "$PkiHttpBase/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force

# ---- AIA (Authority Information Access) ----
Write-Host "  Setting AIA locations..." -ForegroundColor Gray
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt"
Add-CAAuthorityInformationAccess -Uri "$PkiHttpBase/%3%4.crt" -AddToCertificateAia -Force

Restart-Service certsvc
Write-Host "CDP and AIA configured, service restarted." -ForegroundColor Green

### 6 - Finalize and Prepare for Manual Steps
Write-Host "Publishing initial CRL and renaming certificate file..." -ForegroundColor Cyan
certutil -CRL
Start-Sleep -Seconds 2
Rename-Item "$CertEnrollDir\caroot1_$RootCAName.crt" "$CertEnrollDir\$RootCAName.crt" -Force
Write-Host "Initial CRL published and certificate renamed." -ForegroundColor Green

# --- MANUAL STEPS FOR OFFLINE ROOT ---
Write-Host "`n`n=====================================================================================================" -ForegroundColor Red
Write-Host "                             *** MANUAL STEPS REQUIRED ***" -ForegroundColor Red
Write-Host "=====================================================================================================" -ForegroundColor Red
Write-Host "The Root CA is now configured. The following manual steps are CRITICAL:" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "1. MANUALLY COPY FILES FROM ROOT CA:" -ForegroundColor Cyan
Write-Host "   Location: C:\Windows\System32\CertSrv\CertEnroll\" -ForegroundColor Gray
Write-Host "   Files to Copy:" -ForegroundColor Gray
Write-Host "     - ${RootCAName}.crt" -ForegroundColor Gray
Write-Host "     - ${RootCAName}.crl" -ForegroundColor Gray
Write-Host "   Action: Copy these files to a removable media (e.g., USB drive)." -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "2. TRANSFER FILES TO A DOMAIN-JOINED MACHINE:" -ForegroundColor Cyan
Write-Host "   Action: Take the media to a domain-joined machine (e.g., DC, SubCA, or WEB server)." -ForegroundColor Gray
Write-Host "   Destination: \\${DomainFqdn}\share\PKIData\" -ForegroundColor Gray
Write-Host "   Action: Paste the .crt and .crl files into the above DFS share folder." -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "3. VERIFY HTTP ACCESS (ON DOMAIN-JOINED MACHINE):" -ForegroundColor Cyan
Write-Host "   Action: Run the following commands on the domain-joined machine to verify:" -ForegroundColor Gray
Write-Host "   ---------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "   `$PkiHttpBase = `"http://${PkiHttpHost}/pkidata`"" -ForegroundColor Gray
Write-Host "   `$RootCAName  = `"${RootCAName}`"" -ForegroundColor Gray
Write-Host "   Invoke-WebRequest -Uri `"`$PkiHttpBase/`$RootCAName.crt`" -UseBasicParsing" -ForegroundColor Gray
Write-Host "   Invoke-WebRequest -Uri `"`$PkiHttpBase/`$RootCAName.crl`" -UseBasicParsing" -ForegroundColor Gray
Write-Host "   Expected Result: Both commands should return StatusCode 200." -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "4. PUBLISH TO ACTIVE DIRECTORY (ON DOMAIN-JOINED MACHINE):" -ForegroundColor Cyan
Write-Host "   Action: Run the following commands on the domain-joined machine:" -ForegroundColor Gray
Write-Host "   ---------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "   `$DfsPkiPath = `"\\\\${DomainFqdn}\share\PKIData`"" -ForegroundColor Gray
Write-Host "   `$RootCAName = `"${RootCAName}`"" -ForegroundColor Gray
Write-Host "   certutil -dspublish -f `"`$DfsPkiPath\`$RootCAName.crt`" RootCA" -ForegroundColor Gray
Write-Host "   certutil -addstore -f root `"`$DfsPkiPath\`$RootCAName.crt`"" -ForegroundColor Gray
Write-Host "   Action: Optionally, run `gpupdate /force` on other domain members." -ForegroundColor Gray
Write-Host "=====================================================================================================" -ForegroundColor Red
Write-Host "DO NOT PROCEED WITH SUBCA INSTALLATION UNTIL THESE STEPS ARE COMPLETE!" -ForegroundColor Red
Write-Host "=====================================================================================================" -ForegroundColor Red

# Open folder for easy access to files needing manual copy
explorer.exe $CertEnrollDir
```

### 5.2 Root CA Initial Install Output

<img title="a title" alt="Alt text" src="PKILab-5-RootCA-Output1.jpg">    

<img title="a title" alt="Alt text" src="PKILab-5-RootCA-Output2.jpg">    

### 5.2 Root CA - pki.lab.local/pkidata Validation

```powershell
$PkiHttpBase = "http://pki.lab.local/pkidata"
   $RootCAName  = "Lab Root CA"
   Invoke-WebRequest -Uri "$PkiHttpBase/$RootCAName.crt" -UseBasicParsing
   Invoke-WebRequest -Uri "$PkiHttpBase/$RootCAName.crl" -UseBasicParsing
```
<img title="a title" alt="Alt text" src="PKILab-5-RootCA-PKIUrlValidation-Output1.jpg">

### 5.3 Root CA - DSPublish

```powershell
$DfsPkiPath = "\\lab.local\share\PKIData"
   $RootCAName = "Lab Root CA"
   certutil -dspublish -f "$DfsPkiPath\$RootCAName.crt" RootCA
   certutil -addstore -f root "$DfsPkiPath\$RootCAName.crt"
   Write-host "Action: Run gpupdate /force on servers in the PKI solution.
   This will ensure that the clients pick up the newly published root certificate.
   Installtion steps will fail for other servers if it doesnt have the root or Sub CAs availbe" -ForegroundColor Green
```

<img title="a title" alt="Alt text" src="PKILab-5-RootCA-DSPublish-Output2.jpg">

### 5.4 Root CA - Local Certificate Store

```text
To prove that the Root CA certificate has been published correctly, on the server that the DSPublish commans was run from, open the Certificate MMC, Certificates (Local Computer)/Trusted Root Certification Authorities/Certificates
"Lab Root CA" should be visable.
```
<img title="a title" alt="Alt text" src="PKILab-5-RootCA-Certificates-Output1.jpg">


## SubCAs
### SubCA1 Installation

```powershell
## 6 - Install SubCA1 (Lab Issuing CA 1)
### 6.1 SubCA1.lab.local - Part 1
### RUN THIS ENTIRE SCRIPT ON SUBCA1 SERVER (elevated PowerShell)
### This script configures SubCA1 and generates the certificate request.
### Manual steps are required afterward to process the request on Root CA.

### 1 - Common PKI Settings
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$OcspHttpBase   = "http://ocsp.lab.local/ocsp"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

Write-Host "Creating local PKI folder..." -ForegroundColor Cyan
New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null

### 2 - Create CAPolicy.inf
Write-Host "Creating CAPolicy.inf..." -ForegroundColor Cyan
$caPolicyContent = @"
[Version]
Signature=`$Windows NT`$

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096  
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
Write-Host "CAPolicy.inf created successfully." -ForegroundColor Green

### 3 - Install AD CS Role & Generate Request
Write-Host "Installing ADCS-Cert-Authority feature..." -ForegroundColor Cyan
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

Write-Host "Configuring Enterprise Subordinate CA and generating request..." -ForegroundColor Cyan
$vCaIssProperties = @{
  CACommonName              = $SubCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\Windows\System32\CertLog'
  LogDirectory              = 'C:\Windows\System32\CertLog'
  OutputCertRequestFile     = "$LocalPkiFolder\subca1_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force
Write-Host "SubCA1 role installed and request generated." -ForegroundColor Green

### 4 - Manual Steps for Offline Root CA Processing
Write-Host "`n`n=====================================================================================================" -ForegroundColor Red
Write-Host "                             *** MANUAL STEPS REQUIRED ***" -ForegroundColor Red
Write-Host "=====================================================================================================" -ForegroundColor Red
Write-Host "SubCA1 certificate request has been generated. The following manual steps are CRITICAL:" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "1. MANUALLY COPY REQUEST FILE FROM SUBCA1:" -ForegroundColor Cyan
Write-Host "   Location: C:\PKIData\subca1_request.req" -ForegroundColor Gray
Write-Host "   Action: Copy this file to a removable media (e.g., USB drive)." -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "2. PROCESS REQUEST ON OFFLINE ROOT CA:" -ForegroundColor Cyan
Write-Host "   Action: Take the media to the Offline Root CA server." -ForegroundColor Gray
Write-Host "   Location on Root CA: C:\PKIData\" -ForegroundColor Gray
Write-Host "   Action: Place the subca1_request.req file in the above folder." -ForegroundColor Gray
Write-Host "   Commands to run on Root CA:" -ForegroundColor Gray
Write-Host "   ---------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "   certreq -submit C:\PKIData\subca1_request.req C:\PKIData\subca1_issued.cer" -ForegroundColor Gray
Write-Host "   # If it goes pending:" -ForegroundColor Gray
Write-Host "   certutil -resubmit <REQUEST_ID>" -ForegroundColor Gray
Write-Host "   certreq -retrieve <REQUEST_ID> C:\PKIData\subca1_issued.cer" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "3. MANUALLY COPY ISSUED CERTIFICATE BACK TO SUBCA1:" -ForegroundColor Cyan
Write-Host "   Action: Copy C:\PKIData\subca1_issued.cer from Root CA to SubCA1 at:" -ForegroundColor Gray
Write-Host "   Location: C:\PKIData\subca1_issued.cer" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "4. COMPLETE SUBCA1 CONFIGURATION:" -ForegroundColor Cyan
Write-Host "   Action: After copying the issued certificate back, run PART 2 of this script on SubCA1." -ForegroundColor Gray
Write-Host "   File: Working-v2-6-SubCa1-Install-Part2.ps1" -ForegroundColor Gray
Write-Host "=====================================================================================================" -ForegroundColor Red
Write-Host "DO NOT PROCEED WITH PART 2 UNTIL THE ISSUED CERTIFICATE IS COPIED BACK!" -ForegroundColor Red
Write-Host "=====================================================================================================" -ForegroundColor Red

# Open folder for easy access to request file
explorer.exe $LocalPkiFolder
```

<img title="a title" alt="Alt text" src="PKILab-6-SubCA1-Installation-Output1.jpg">
<img title="a title" alt="Alt text" src="PKILab-6-SubCA1-Installation-Output2.jpg">
<img title="a title" alt="Alt text" src="PKILab-6-SubCA1-Installation-Output3.jpg">



### 6.2 Install SubCA1 (Lab Issuing CA 1) - PART 2

```powershell
### RUN THIS ENTIRE SCRIPT ON SUBCA1 SERVER (elevated PowerShell)
### This script completes the SubCA1 configuration after the certificate has been issued by the Root CA.

### 1 - Common PKI Settings
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$OcspHttpBase   = "http://ocsp.lab.local/ocsp"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

### 2 - Install Issued Cert and Start CA
Write-Host "Installing the issued SubCA certificate..." -ForegroundColor Cyan
certutil -installcert "$LocalPkiFolder\subca1_issued.cer"
Write-Host "Issued certificate installed." -ForegroundColor Green

Write-Host "Starting CA service..." -ForegroundColor Cyan
Start-Service certsvc
Write-Host "CA service started." -ForegroundColor Green

Write-Host "Performing basic health check..." -ForegroundColor Cyan
Get-Service certsvc
certutil -ping
Write-Host "Basic health check complete." -ForegroundColor Green

### 3 - Configure Validity, CDP, and AIA
Write-Host "Configuring Validity, CDP, and AIA settings..." -ForegroundColor Cyan
Import-Module ADCSAdministration

# ---- Validity & CRL settings ----
Write-Host "  Setting validity and CRL periods..." -ForegroundColor Gray
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod "Years"
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Weeks"
certutil -setreg CA\CRLDeltaPeriodUnits 1
certutil -setreg CA\CRLDeltaPeriod "Days"
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod "Days"
certutil -setreg CA\AuditFilter 127

# ---- CDP (CRL Distribution Points) ----
Write-Host "  Setting CDP locations..." -ForegroundColor Gray
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACRLDistributionPoint `
    -Uri "$DfsPkiPath\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8%9.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force

# ---- AIA (Authority Information Access) ----
Write-Host "  Setting AIA locations..." -ForegroundColor Gray
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt`n2:$DfsPkiPath\%3%4.crt"

Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Add-CAAuthorityInformationAccess `
    -Uri "$OcspHttpBase" `
    -AddToCertificateOcsp `
    -Force    

Restart-Service certsvc
Start-Sleep -Seconds 2
Write-Host "Validity, CDP, and AIA settings configured and service restarted." -ForegroundColor Green

### 4 - Publish Cert to AD and Copy to DFS
Write-Host "Publishing initial CRL..." -ForegroundColor Cyan
certutil -CRL
Write-Host "Initial CRL published." -ForegroundColor Green

Write-Host "Renaming SubCA certificate to a clean name..." -ForegroundColor Cyan
$cer = Get-ChildItem $CertEnrollDir -Filter "*.crt" | Select-Object -First 1
if ($cer -and $cer.Name -ne "$SubCAName.crt") {
    Rename-Item $cer.FullName "$CertEnrollDir\$SubCAName.crt" -Force
}
Write-Host "SubCA certificate renamed." -ForegroundColor Green

Write-Host "Publishing SubCA certificate to Active Directory (NTAuth and SubCA containers)..." -ForegroundColor Cyan
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" NTAuthCA
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" SubCA
Write-Host "SubCA certificate published to AD." -ForegroundColor Green

Write-Host "Copying SubCA certificate to DFS for HTTP AIA..." -ForegroundColor Cyan
Copy-Item "$CertEnrollDir\$SubCAName.crt" "$DfsPkiPath\$SubCAName.crt" -Force
Write-Host "SubCA certificate copied to DFS." -ForegroundColor Green

### 5 - Validation Checks (Run on SubCA1)
Write-Host "`n=== PKI Configuration Validation ===" -ForegroundColor Cyan

$expectedCDP_HTTP = $PkiHttpBase
$expectedAIA_HTTP = $PkiHttpBase
$expectedOCSP = $OcspHttpBase

$caName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active
Write-Host "`nCA Name: $caName" -ForegroundColor Yellow

Write-Host "`n--- CRL Distribution Points ---" -ForegroundColor Yellow
$crlOutput = certutil -getreg CA\CRLPublicationURLs
$crlOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$' ) {
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToCertCDP = ($flags -band 0x02) -ne 0

    if ($url -match [regex]::Escape($expectedCDP_HTTP) -and $addToCertCDP) {
    Write-Host "CDP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ldap://|file://' -and $addToCertCDP) {
    Write-Host "Legacy CDP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n--- Authority Information Access ---" -ForegroundColor Yellow
$aiaOutput = certutil -getreg CA\CACertPublicationURLs
$aiaOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$' ) {
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToAIA = ($flags -band 0x02) -ne 0
    $addToOCSP = ($flags -band 0x20) -ne 0

    if ($url -match [regex]::Escape($expectedAIA_HTTP) -and $addToAIA) {
    Write-Host "AIA OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match [regex]::Escape($expectedOCSP) -and $addToOCSP) {
    Write-Host "OCSP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ocsp' -and $addToOCSP -and $url -notmatch [regex]::Escape($expectedOCSP)) {
    Write-Host "OCSP Wrong Domain ⚠️ $url (should be $expectedOCSP)" -ForegroundColor Yellow
    } elseif ($url -match 'ldap://|file://' -and ($addToAIA -or $addToOCSP)) {
    Write-Host "Legacy AIA/OCSP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan

Write-Host "`n`n=====================================================================================================" -ForegroundColor Green
Write-Host "SubCA1 (Lab Issuing CA 1) configuration is complete!" -ForegroundColor Green
Write-Host "=====================================================================================================" -ForegroundColor Green
```

<img title="a title" alt="Alt text" src="PKILab-6-SubCA1-Installation-Part2-Output1.jpg">

<img title="a title" alt="Alt text" src="PKILab-6-SubCA1-Installation-Part2-Output2.jpg">

## 7 Templates
### 7.1 Web Server Template - req.lab.local.certsrv
### 7.2 OCSP Server Template 

## 8 Certificate Authority Web Enrollment

### 8.1 Web1 Certificate

```powershell
# EnrollCertOnly.ps1

# ----- CONFIG -----
$hostname = $env:COMPUTERNAME
$domain = "lab.local"
$fqdn = "$hostname.$domain"
$reqHost = "req.lab.local"
$pkiHost = "pki.lab.local"
$templateName = "Lab-WebServerCertsrv"

# ----- Create INF for 4096-bit cert request with SANs -----
$infContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$reqHost"
Exportable = TRUE
KeyLength = 4096
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = True
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$reqHost&dns=$fqdn"

[RequestAttributes]
CertificateTemplate = $templateName
"@

$infPath = "$env:TEMP\WebServerCert.inf"
$infContent | Out-File -FilePath $infPath -Encoding ASCII

# ----- Submit request -----
$requestPath = "$env:TEMP\WebServerCert.req"
$responsePath = "$env:TEMP\WebServerCert.cer"
Write-Host "Submitting certificate request for $fqdn..." -ForegroundColor Yellow
certreq -new $infPath $requestPath
certreq -submit -config "subca1.lab.local\Lab Issuing CA 1" $requestPath $responsePath

# ----- Accept cert -----
Write-Host "Accepting certificate for $fqdn..." -ForegroundColor Yellow
certreq -accept $responsePath

# ----- Clean up -----
Remove-Item $infPath, $requestPath, $responsePath -Force

Write-Host "✅ Certificate enrolled for $fqdn with SANs: $reqHost, $fqdn" -ForegroundColor Green
```

### 8.2 Web2 Certificate

```powershell
# EnrollCertOnly.ps1

# ----- CONFIG -----
$hostname = $env:COMPUTERNAME
$domain = "lab.local"
$fqdn = "$hostname.$domain"
$reqHost = "req.lab.local"
$pkiHost = "pki.lab.local"
$templateName = "Lab-WebServerCertsrv"

# ----- Create INF for 4096-bit cert request with SANs -----
$infContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$reqHost"
Exportable = TRUE
KeyLength = 4096
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = True
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$reqHost&dns=$fqdn"

[RequestAttributes]
CertificateTemplate = $templateName
"@

$infPath = "$env:TEMP\WebServerCert.inf"
$infContent | Out-File -FilePath $infPath -Encoding ASCII

# ----- Submit request -----
$requestPath = "$env:TEMP\WebServerCert.req"
$responsePath = "$env:TEMP\WebServerCert.cer"
Write-Host "Submitting certificate request for $fqdn..." -ForegroundColor Yellow
certreq -new $infPath $requestPath
certreq -submit -config "subca2.lab.local\Lab Issuing CA 2" $requestPath $responsePath

# ----- Accept cert -----
Write-Host "Accepting certificate for $fqdn..." -ForegroundColor Yellow
certreq -accept $responsePath

# ----- Clean up -----
Remove-Item $infPath, $requestPath, $responsePath -Force

Write-Host "✅ Certificate enrolled for $fqdn with SANs: $reqHost, $fqdn" -ForegroundColor Green
```

### 8.3 Certserv

```powershell
<#
Working-4-2b-reqsite-plain.ps1
Configure ReqSite and /certsrv (Web Enrollment).
Auto-detects local host (WEB01/WEB02) and sets $CAConfig accordingly.
Plain-text password prompt for LAB\PKIWebSvc (per request).
Run elevated. Use -Verbose. Logs to %ProgramData%\PKI-Logs.
#>

param()

# Ensure elevated
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script elevated (Run as Administrator)." ; exit 1
}

# Start transcript/log
$logDir = Join-Path $env:ProgramData "PKI-Logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$logFile = Join-Path $logDir "ReqSite-Setup-${env:COMPUTERNAME}-${timestamp}.log"
Start-Transcript -Path $logFile -Force
Write-Verbose "Transcript started: ${logFile}"

# CONFIG
$DomainNetBios    = "LAB"
$ReqHost          = "req.lab.local"
$ReqSiteName      = "ReqSite"
$ReqRoot          = "C:\InetPub\ReqSiteRoot"
$CertSrvPool      = "CertSrvPool"
$PkiWebSvcAccount = "PKIWebSvc"
$serviceAccount   = "${DomainNetBios}\${PkiWebSvcAccount}"

# Auto-detect local host and set CAConfig for WEB01/WEB02
$hostName = $env:COMPUTERNAME.ToUpper()
switch ($hostName) {
    "WEB01" {
        $CAConfig = "SubCA1.lab.local\Lab Issuing CA 1"
        Write-Host "Host detected: WEB01 -> setting CAConfig to ${CAConfig}" -ForegroundColor Cyan
    }
    "WEB02" {
        $CAConfig = "SubCA2.lab.local\Lab Issuing CA 2"
        Write-Host "Host detected: WEB02 -> setting CAConfig to ${CAConfig}" -ForegroundColor Cyan
    }
    default {
        Write-Warning "Unrecognized host name '${hostName}'."
        $CAConfig = Read-Host -Prompt "Enter CAConfig (format 'hostname\CA Name') or press Enter to skip Install-AdcsWebEnrollment"
        if (-not $CAConfig) {
            Write-Host "CAConfig left blank; skipping Install-AdcsWebEnrollment." -ForegroundColor Yellow
        } else {
            Write-Host "CAConfig set to: ${CAConfig}" -ForegroundColor Cyan
        }
    }
}

# Prompt for plain-text password (temporary plaintext)
Write-Host "Enter plain-text password for ${serviceAccount} (will be used to set IIS app pool identity and Connect As)." -ForegroundColor Yellow
$passwordPlain = Read-Host -Prompt "Password (plain text)"

# Required features
$requiredFeatures = @("Web-Server","Web-Windows-Auth","ADCS-Web-Enrollment")
foreach ($feature in $requiredFeatures) {
    try {
        $status = Get-WindowsFeature -Name $feature -ErrorAction Stop
        if (-not $status.Installed) {
            Write-Verbose "Installing feature: ${feature}"
            Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop | Out-Null
            Write-Host "Installed: ${feature}" -ForegroundColor Green
        } else {
            Write-Verbose "Feature present: ${feature}"
        }
    } catch {
        Write-Warning "Could not query/install feature ${feature}: $($_.Exception.Message)"
    }
}

# Import modules
Import-Module WebAdministration -ErrorAction Stop

$importedADCS = $false
try {
    Import-Module ADCSDeployment -ErrorAction Stop
    $importedADCS = $true
} catch {
    Write-Verbose "ADCSDeployment not importable: $($_.Exception.Message)"
}

try {
    # Install / reconfigure AD CS Web Enrollment to correct CA (if module available & CAConfig provided)
    if ($CAConfig) {
        if ($importedADCS) {
            try {
                Uninstall-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue
            } catch { Write-Verbose "Uninstall-AdcsWebEnrollment not available or failed." }
            try {
                Install-AdcsWebEnrollment -CAConfig $CAConfig -Force -ErrorAction Stop
                Write-Host "Web Enrollment installed and pointed to: ${CAConfig}" -ForegroundColor Green
            } catch {
                Write-Warning "Install-AdcsWebEnrollment failed: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "ADCSDeployment module not available; skipping Install-AdcsWebEnrollment."
        }
    } else {
        Write-Verbose "CAConfig not set; skipping Install-AdcsWebEnrollment."
    }

    # Create CertSrvPool and set identity
    if (-not (Test-Path "IIS:\AppPools\${CertSrvPool}")) {
        New-WebAppPool -Name $CertSrvPool | Out-Null
        Write-Verbose "Created app pool ${CertSrvPool}"
    }
    Set-ItemProperty "IIS:\AppPools\${CertSrvPool}" -Name processModel.identityType -Value 3
    Set-ItemProperty "IIS:\AppPools\${CertSrvPool}" -Name processModel.userName -Value $serviceAccount
    Set-ItemProperty "IIS:\AppPools\${CertSrvPool}" -Name processModel.password -Value $passwordPlain
    Set-ItemProperty "IIS:\AppPools\${CertSrvPool}" -Name managedPipelineMode -Value Classic
    Restart-WebAppPool $CertSrvPool
    Write-Host "Configured app pool ${CertSrvPool} to run as ${serviceAccount}" -ForegroundColor Green

    # Create ReqSite (HTTP)
    if (-not (Test-Path $ReqRoot)) { New-Item -Path $ReqRoot -ItemType Directory -Force | Out-Null; Write-Verbose "Created ${ReqRoot}" }
    $reqSite = Get-Website -Name $ReqSiteName -ErrorAction SilentlyContinue
    if (-not $reqSite) {
        New-Website -Name $ReqSiteName -Port 80 -HostHeader $ReqHost -PhysicalPath $ReqRoot -ApplicationPool $CertSrvPool
        Write-Host "Created site ${ReqSiteName}" -ForegroundColor Green
    } else {
        Set-ItemProperty "IIS:\Sites\${ReqSiteName}" -Name applicationPool -Value $CertSrvPool
        Write-Verbose "Set application pool for ${ReqSiteName} to ${CertSrvPool}"
    }
    if (-not (Get-WebBinding -Name $ReqSiteName -Protocol http -HostHeader $ReqHost -ErrorAction SilentlyContinue)) {
        New-WebBinding -Name $ReqSiteName -Protocol http -Port 80 -HostHeader $ReqHost
    }
    Start-Website $ReqSiteName

    # Ensure /certsrv exists under Default Web Site (create if missing)
    $oldCertSrv = Get-WebApplication -Site "Default Web Site" -Name "certsrv" -ErrorAction SilentlyContinue
    if (-not $oldCertSrv) {
        $certSrvPhysical = "C:\Windows\System32\CertSrv"
        if (Test-Path $certSrvPhysical) {
            New-WebApplication -Site "Default Web Site" -Name "certsrv" -PhysicalPath $certSrvPhysical -ApplicationPool $CertSrvPool
            Write-Host "Created /certsrv under Default Web Site from ${certSrvPhysical}" -ForegroundColor Green
            $oldCertSrv = Get-WebApplication -Site "Default Web Site" -Name "certsrv"
        } else {
            Write-Warning "CertSrv physical path not found: ${certSrvPhysical}. Ensure AD CS Web Enrollment role installed and files present."
        }
    } else {
        Write-Verbose "/certsrv already exists under Default Web Site"
    }

    # Move /certsrv to ReqSite or ensure it uses CertSrvPool
    $oldCertSrv = Get-WebApplication -Site "Default Web Site" -Name "certsrv" -ErrorAction SilentlyContinue
    if ($oldCertSrv) {
        $certSrvPath = $oldCertSrv.physicalPath
        try { Remove-WebApplication -Site "Default Web Site" -Name "certsrv" -ErrorAction Stop } catch { Write-Verbose "Remove-WebApplication failed or not present: $($_.Exception.Message)" }
        $newCertSrv = Get-WebApplication -Site $ReqSiteName -Name "certsrv" -ErrorAction SilentlyContinue
        if (-not $newCertSrv) {
            New-WebApplication -Site $ReqSiteName -Name "certsrv" -PhysicalPath $certSrvPath -ApplicationPool $CertSrvPool
            Write-Host "[INFO] Moved /certsrv from Default Web Site to ${ReqSiteName}" -ForegroundColor Green
        } else {
            Set-ItemProperty "IIS:\Sites\${ReqSiteName}\certsrv" -Name applicationPool -Value $CertSrvPool
            Write-Host "[INFO] /certsrv already under ${ReqSiteName}; app pool set to ${CertSrvPool}" -ForegroundColor Cyan
        }
    } else {
        $newCertSrv = Get-WebApplication -Site $ReqSiteName -Name "certsrv" -ErrorAction SilentlyContinue
        if ($newCertSrv) {
            Set-ItemProperty "IIS:\Sites\${ReqSiteName}\certsrv" -Name applicationPool -Value $CertSrvPool
            Write-Host "[INFO] /certsrv exists under ${ReqSiteName}; app pool set to ${CertSrvPool}" -ForegroundColor Cyan
        } else {
            Write-Warning "/certsrv not found under Default Web Site or ${ReqSiteName} and creation failed earlier."
        }
    }

    # Bind HTTPS if certificate exists for req.lab.local
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=${ReqHost}" } | Select-Object -First 1
    if ($cert) {
        $CertThumbprint = $cert.Thumbprint
        if (-not (Get-WebBinding -Name $ReqSiteName -Protocol https -HostHeader $ReqHost -ErrorAction SilentlyContinue)) {
            New-WebBinding -Name $ReqSiteName -Protocol https -Port 443 -HostHeader $ReqHost
            Write-Host "Created HTTPS binding for ${ReqHost} on ${ReqSiteName}" -ForegroundColor Green
        }
        & netsh http delete sslcert hostnameport="${ReqHost}`:443" 2>$null | Out-Null
        & netsh http add sslcert hostnameport="${ReqHost}`:443" certhash=$CertThumbprint appid='{00112233-4455-6677-8899-AABBCCDDEEFF}' certstorename=MY
        Write-Host "SSL cert bound to ${ReqHost} (thumbprint: ${CertThumbprint})" -ForegroundColor Green
    } else {
        Write-Warning "Certificate 'CN=${ReqHost}' not found in LocalMachine\My. Enroll the web server certificate for ${ReqHost} and re-run this script to bind HTTPS."
    }

    # Authentication: disable Anonymous on ReqSite and enforce WindowsAuth on /certsrv
    try {
        Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "IIS:\Sites\${ReqSiteName}" -Name enabled -Value $false -ErrorAction Stop
        Write-Host "Disabled Anonymous Authentication on site ${ReqSiteName}" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to disable anonymous on ${ReqSiteName}: $($_.Exception.Message)"
    }

    $certsrvApp = Get-WebApplication -Site $ReqSiteName -Name "certsrv" -ErrorAction SilentlyContinue
    if ($certsrvApp) {
        $appPSPath = "IIS:\Sites\${ReqSiteName}\certsrv"
        try {
            Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath $appPSPath -Name enabled -Value $true -ErrorAction Stop
            Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath $appPSPath -Name enabled -Value $false -ErrorAction Stop
            Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication/providers -PSPath $appPSPath -Name "." -Value @("Negotiate","NTLM") -ErrorAction SilentlyContinue
            Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath $appPSPath -Name useKernelMode -Value $false -ErrorAction SilentlyContinue
            Write-Host "Configured authentication on ${ReqSiteName}/certsrv (WindowsAuth enabled, Anonymous disabled)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to configure authentication for /certsrv: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "/certsrv application not found under ${ReqSiteName} to configure authentication."
    }

    # Classic ASP parent paths + detailed errors for /certsrv
    Set-WebConfiguration -Filter /system.webServer/asp -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow -ErrorAction SilentlyContinue
    if ($certsrvApp) {
        Set-WebConfigurationProperty -PSPath $appPSPath -Filter /system.webServer/asp -Name enableParentPaths -Value $true -ErrorAction SilentlyContinue
        Set-WebConfigurationProperty -PSPath $appPSPath -Filter /system.webServer/asp -Name scriptErrorSentToBrowser -Value $true -ErrorAction SilentlyContinue
        Set-WebConfigurationProperty -PSPath $appPSPath -Filter /system.webServer/httpErrors -Name errorMode -Value Detailed -ErrorAction SilentlyContinue
        Write-Verbose "Enabled Classic ASP parent paths and detailed errors for /certsrv"
    }

    # Grant LAB\PKIWebSvc access to CertSrv files
    $certSrvPath = "C:\Windows\System32\CertSrv"
    $certSrvEnUS = "C:\Windows\System32\CertSrv\en-US"
    if (Test-Path $certSrvPath) {
        icacls $certSrvPath /grant "${serviceAccount}:(OI)(CI)RX" /T /C /Q > $null 2>&1
        Write-Verbose "Granted RX on ${certSrvPath} to ${serviceAccount}"
    }
    if (Test-Path $certSrvEnUS) {
        try { takeown /F $certSrvEnUS /R /A /D Y > $null 2>&1 } catch { }
        icacls $certSrvEnUS /grant "${serviceAccount}:(OI)(CI)RX" /T /C /Q > $null 2>&1
        Write-Verbose "Granted RX on ${certSrvEnUS} to ${serviceAccount}"
    }

    # Set Connect As credentials on the /certsrv root virtual directory
    if ($certsrvApp) {
        $vdirFilter = "system.applicationHost/sites/site[@name='${ReqSiteName}']/application[@path='/certsrv']/virtualDirectory[@path='/']"
        try {
            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $vdirFilter -Name userName -Value $serviceAccount -ErrorAction Stop
            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $vdirFilter -Name password -Value $passwordPlain -ErrorAction Stop
            Write-Host "[INFO] /certsrv virtual directory root set to 'Connect as: ${serviceAccount}'" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to set Connect As on /certsrv virtual directory: $($_.Exception.Message)"
        }
    }

    # Ensure /certsrv app pool identity uses LAB\PKIWebSvc
    if ($certsrvApp) {
        $appPoolName = (Get-WebApplication -Site $ReqSiteName -Name "certsrv").ApplicationPool
        if ($appPoolName) {
            try {
                Set-ItemProperty "IIS:\AppPools\${appPoolName}" -Name processModel.identityType -Value 3
                Set-ItemProperty "IIS:\AppPools\${appPoolName}" -Name processModel.userName -Value $serviceAccount
                Set-ItemProperty "IIS:\AppPools\${appPoolName}" -Name processModel.password -Value $passwordPlain
                Restart-WebAppPool $appPoolName
                Write-Host "Set app pool '${appPoolName}' identity to ${serviceAccount} and restarted it." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to set app pool identity for ${appPoolName}: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Could not find app pool name for /certsrv."
        }
    }

    # Restart relevant pools and IIS to ensure changes take effect
    try { Restart-WebAppPool $CertSrvPool -ErrorAction SilentlyContinue } catch { }
    Write-Host "`n[INFO] ReqSite (/certsrv) configuration complete. If HTTPS binding did not occur because cert was missing, issue cert and re-run the script." -ForegroundColor Green

} catch {
    Write-Error "Error configuring ReqSite: $($_.Exception.Message)"
    throw
} finally {
    # clear plaintext password variable
    $passwordPlain = $null
    Stop-Transcript | Out-Null
}
```