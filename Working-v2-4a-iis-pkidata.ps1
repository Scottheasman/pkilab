<#
Working-4-2a-pkidata-plain.ps1
Configure PKI HTTP (/pkidata) on Default Web Site (CDP/AIA).
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
$logFile = Join-Path $logDir "PKIData-Setup-${env:COMPUTERNAME}-${timestamp}.log"
Start-Transcript -Path $logFile -Force
Write-Verbose "Transcript started: ${logFile}"

# CONFIG
$DomainNetBios   = "LAB"
$DfsRoot         = "\\lab.local\share"
$PkiFolderName   = "PKIData"
$DfsPkiPath      = Join-Path $DfsRoot $PkiFolderName
$PkiHttpHost     = "pki.lab.local"
$PKIHttpPool     = "PKIHttpPool"
$PkiWebSvcAccount = "PKIWebSvc"
$serviceAccount  = "${DomainNetBios}\${PkiWebSvcAccount}"

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

    # 2) Ensure Default Web Site running and bound to pki.lab.local
    Start-Website "Default Web Site"
    if (-not (Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue)) {
        New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
        Write-Host "Added HTTP binding for ${PkiHttpHost}" -ForegroundColor Green
    } else {
        Write-Verbose "HTTP binding for ${PkiHttpHost} already exists"
    }

    # 3) Create /pkidata virtual directory / application pointing to DFS
    if (-not (Test-Path $DfsPkiPath)) {
        Write-Warning "DFS path ${DfsPkiPath} not reachable. Check network/permissions for ${serviceAccount}."
    }
    $vdir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
    if (-not $vdir) {
        New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
        Write-Host "Created virtual directory Default Web Site/pkidata -> ${DfsPkiPath}" -ForegroundColor Green
    } else {
        Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
        Write-Verbose "Updated pkidata virtual directory physical path"
    }

    if (-not (Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue)) {
        New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
        Write-Host "Created application Default Web Site/pkidata using ${PKIHttpPool}" -ForegroundColor Green
    } else {
        Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
        Write-Verbose "Ensured application Default Web Site/pkidata uses ${PKIHttpPool}"
    }

    # 4) Ensure Default Web Site uses PKIHttpPool
    Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value $PKIHttpPool
    Restart-WebAppPool $PKIHttpPool

    # 5) Configure authentication and directory browsing for /pkidata (anonymous enabled)
    Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow -ErrorAction SilentlyContinue
    Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow -ErrorAction SilentlyContinue

    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\pkidata" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value $true
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\pkidata" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name userName -Value ""
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\pkidata" -Filter /system.webServer/security/authentication/windowsAuthentication -Name enabled -Value $false

    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\pkidata" -Filter /system.webServer/directoryBrowse -Name enabled -Value $true
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true

    # 6) Ensure mime types for crl/crt
    function Ensure-MimeType { param([string]$Extension,[string]$MimeType)
        $existing = Get-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent/mimeMap' -name '.' |
                    Where-Object { $_.fileExtension -eq $Extension }
        if (-not $existing) {
            Add-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent' -name '.' -value @{ fileExtension = $Extension; mimeType = $MimeType }
            Write-Verbose "Added mime type ${Extension} -> ${MimeType}"
        } else {
            Write-Verbose "Mime type for ${Extension} already exists"
        }
    }
    Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
    Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'

    Write-Host "`n[INFO] PKI HTTP (/pkidata) configuration complete." -ForegroundColor Green

} catch {
    Write-Error "Error configuring PKI HTTP: $($_.Exception.Message)"
    throw
} finally {
    # Clear plaintext password variable from memory (best-effort)
    $passwordPlain = $null
    Stop-Transcript | Out-Null
}