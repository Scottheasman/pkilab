# Deploy-PKI-HttpOnly.ps1
# Run elevated on WEB01 / WEB02

# ----- CONFIG -----
$DomainNetBios = "LAB"
$PkiWebSvcAccount = "PKIWebSvc"
$PkiHttpHost = "pki.lab.local"
$DfsPkiPath = "\\lab.local\share\PKIData"
$PKIHttpPool = "PKIHttpPool"

# ----- ensure elevated -----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script elevated (Run as Administrator)." ; exit 1
}

# ----- Install / import WebAdministration if missing -----
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Host "Installing IIS features..." -ForegroundColor Yellow
    Install-WindowsFeature Web-Server, Web-Static-Content, Web-Default-Doc, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Scripting-Tools -IncludeManagementTools -ErrorAction Stop
}
Import-Module WebAdministration -ErrorAction Stop

# ----- Prompt for service account password -----
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
$serviceAccount = "${DomainNetBios}\${PkiWebSvcAccount}"

# ----- Create app pool and set identity -----
if (-not (Test-Path "IIS:\AppPools\$PKIHttpPool")) { New-WebAppPool -Name $PKIHttpPool }
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.userName -Value $serviceAccount
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.password -Value $passwordPlain
Restart-WebAppPool $PKIHttpPool

# ----- Ensure Default Web Site bound to pki.lab.local:80 -----
Start-Website "Default Web Site"
if (-not (Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue)) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
    Write-Host "Added HTTP binding for $PkiHttpHost" -ForegroundColor Green
} else { Write-Host "HTTP binding for $PkiHttpHost already exists." }

# ----- Create /pkidata vdir and app pointing to DFS -----
if (-not (Test-Path $DfsPkiPath)) { Write-Warning "DFS path $DfsPkiPath not reachable. Check network/permissions for $serviceAccount." }
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}
if (-not (Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue)) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
}

# Ensure Default Web Site runs in the PKIHttpPool
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value $PKIHttpPool
Restart-WebAppPool $PKIHttpPool

# ----- Configure auth, directory browsing, request filtering -----
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value $true -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name userName -Value "" -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -Name enabled -Value $false -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\Sites\Default Web Site"

# ----- Ensure MIME types for CRL/CRT -----
function Ensure-MimeType { param([string]$Extension,[string]$MimeType)
    $existing = Get-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent/mimeMap' -name '.' | Where-Object { $_.fileExtension -eq $Extension }
    if (-not $existing) {
        Add-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent' -name '.' -value @{ fileExtension = $Extension; mimeType = $MimeType }
    }
}
Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'

# ----- Clear plaintext password and finish -----
$passwordPlain = $null
Write-Host "`nPKI HTTP /pkidata configuration complete." -ForegroundColor Green

# Quick validation
Write-Host "`n-- Quick validation --"
Get-WebBinding -Name "Default Web Site"
Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata"
Get-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel | Select-Object processModel.userName, processModel.identityType
try { Invoke-WebRequest "http://$PkiHttpHost/pkidata" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop | Select-Object StatusCode } catch { Write-Warn "Local HTTP test failed: $($_.Exception.Message)" }
