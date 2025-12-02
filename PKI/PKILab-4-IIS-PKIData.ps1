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