# ==============================
# PKI HTTP CONFIG FOR WEB01
# ==============================

# ---------- COMMON VARIABLES ----------
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"

$PkiHttpHost      = "pki.lab.local"   # HTTP CDP host
$PkiWebSvcAccount = "PKIWebSvc"

$DfsPkiPath       = "$DfsRoot\$PkiFolderName"   # \\lab.local\share\PKIData


# ---------- 1. INSTALL IIS BASE FEATURES ----------
Install-WindowsFeature Web-Server, Web-Static-Content, Web-Default-Doc, Web-ISAPI-Ext, Web-ISAPI-Filter `
    -IncludeManagementTools

Import-Module WebAdministration


# ---------- 2. CREATE PKIHttpPool AND SET IDENTITY ----------
# Create app pool if it doesn't exist
if (-not (Test-Path "IIS:\AppPools\PKIHttpPool")) {
    New-WebAppPool -Name "PKIHttpPool"
}

# Prompt for LAB\PKIWebSvc password
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR          = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Run PKIHttpPool as LAB\PKIWebSvc
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.password  -Value $passwordPlain

$passwordPlain = $null

Restart-WebAppPool PKIHttpPool


# ---------- 3. ENSURE DEFAULT WEB SITE IS RUNNING AND BOUND TO pki.lab.local ----------
Start-Website "Default Web Site"

# Add host header for pki.lab.local:80 if missing
$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}


# ---------- 4. CREATE /pkidata APPLICATION POINTING TO DFS ----------
# Create or correct the virtual directory
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}

# Convert pkidata to an application and bind to PKIHttpPool
$pkidataApp = Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $pkidataApp) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
}


# ---------- 5. RUN DEFAULT WEB SITE ITSELF IN PKIHttpPool ----------
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value "PKIHttpPool"
Restart-WebAppPool PKIHttpPool


# ---------- 6. CONFIGURE AUTH AND DIRECTORY BROWSING FOR /pkidata ----------
# Allow overrides at the server level
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow

# Anonymous on pkidata, using app pool identity (blank username)
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name userName -Value "" `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Disable Windows auth on pkidata
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name enabled -Value false `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Enable directory browsing on pkidata
Set-WebConfigurationProperty `
  -Filter /system.webServer/directoryBrowse `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Allow double escaping on Default Web Site (for CRL filenames, etc.)
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/requestFiltering `
  -Name allowDoubleEscaping -Value true `
  -PSPath "IIS:\Sites\Default Web Site"


# ---------- 7. ENSURE MIME TYPES FOR CRL/CRT ----------
function Ensure-MimeType {
    param([string]$Extension,[string]$MimeType)
    $existing = Get-WebConfigurationProperty -pspath 'IIS:' `
        -filter 'system.webServer/staticContent/mimeMap' -name '.' |
        Where-Object { $_.fileExtension -eq $Extension }
    if (-not $existing) {
        Add-WebConfigurationProperty -pspath 'IIS:' `
            -filter 'system.webServer/staticContent' -name '.' `
            -value @{ fileExtension = $Extension; mimeType = $MimeType }
    }
}

Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'


# ---------- 8. QUICK VALIDATION ----------
Write-Host "`n=== Application Pool for pkidata on WEB01 ==="
(Get-WebApplication -Site "Default Web Site" -Name "pkidata").applicationPool

Write-Host "`n=== App Pool Identity for PKIHttpPool on WEB01 ==="
Get-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel

Write-Host "`n=== Testing HTTP from this server (WEB01) ==="
Invoke-WebRequest "http://pki.lab.local/pkidata" -UseBasicParsing | Select-Object StatusCode


# ==============================
# PKI HTTP CONFIG FOR WEB02
# ==============================

# ---------- COMMON VARIABLES ----------
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"

$PkiHttpHost      = "pki.lab.local"   # HTTP CDP host
$PkiWebSvcAccount = "PKIWebSvc"

$DfsPkiPath       = "$DfsRoot\$PkiFolderName"   # \\lab.local\share\PKIData


# ---------- 1. INSTALL IIS BASE FEATURES ----------
Install-WindowsFeature Web-Server, Web-Static-Content, Web-Default-Doc, Web-ISAPI-Ext, Web-ISAPI-Filter `
    -IncludeManagementTools

Import-Module WebAdministration


# ---------- 2. CREATE PKIHttpPool AND SET IDENTITY ----------
# Create app pool if it doesn't exist
if (-not (Test-Path "IIS:\AppPools\PKIHttpPool")) {
    New-WebAppPool -Name "PKIHttpPool"
}

# Prompt for LAB\PKIWebSvc password (same password you used on WEB01)
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR          = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Run PKIHttpPool as LAB\PKIWebSvc
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.password  -Value $passwordPlain

$passwordPlain = $null

Restart-WebAppPool PKIHttpPool


# ---------- 3. ENSURE DEFAULT WEB SITE IS RUNNING AND BOUND TO pki.lab.local ----------
Start-Website "Default Web Site"

# Add host header for pki.lab.local:80 if missing
$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}


# ---------- 4. CREATE /pkidata APPLICATION POINTING TO DFS ----------
# Create or correct the virtual directory
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}

# Convert pkidata to an application and bind to PKIHttpPool
$pkidataApp = Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $pkidataApp) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
}


# ---------- 5. RUN DEFAULT WEB SITE ITSELF IN PKIHttpPool ----------
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value "PKIHttpPool"
Restart-WebAppPool PKIHttpPool


# ---------- 6. CONFIGURE AUTH AND DIRECTORY BROWSING FOR /pkidata ----------
# Allow overrides at the server level
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow

# Anonymous on pkidata, using app pool identity (blank username)
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name userName -Value "" `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Disable Windows auth on pkidata
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name enabled -Value false `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Enable directory browsing on pkidata
Set-WebConfigurationProperty `
  -Filter /system.webServer/directoryBrowse `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Allow double escaping on Default Web Site (for CRL filenames, etc.)
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/requestFiltering `
  -Name allowDoubleEscaping -Value true `
  -PSPath "IIS:\Sites\Default Web Site"


# ---------- 7. ENSURE MIME TYPES FOR CRL/CRT ----------
function Ensure-MimeType {
    param([string]$Extension,[string]$MimeType)
    $existing = Get-WebConfigurationProperty -pspath 'IIS:' `
        -filter 'system.webServer/staticContent/mimeMap' -name '.' |
        Where-Object { $_.fileExtension -eq $Extension }
    if (-not $existing) {
        Add-WebConfigurationProperty -pspath 'IIS:' `
            -filter 'system.webServer/staticContent' -name '.' `
            -value @{ fileExtension = $Extension; mimeType = $MimeType }
    }
}

Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'


# ---------- 8. QUICK VALIDATION ----------
Write-Host "`n=== Application Pool for pkidata on WEB02 ==="
(Get-WebApplication -Site "Default Web Site" -Name "pkidata").applicationPool

Write-Host "`n=== App Pool Identity for PKIHttpPool on WEB02 ==="
Get-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel

Write-Host "`n=== Testing HTTP from this server (WEB02) ==="
Invoke-WebRequest "http://pki.lab.local/pkidata" -UseBasicParsing | Select-Object StatusCode