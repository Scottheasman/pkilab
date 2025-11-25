# ====================================================================
# PKI HTTP + WEB ENROLLMENT CONFIG FOR WEB01
# ====================================================================

# ---- COMMON VARIABLES ----
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"

$PkiHttpHost      = "pki.lab.local"   # HTTP CDP/AIA host
$ReqHost          = "req.lab.local"   # HTTPS Web Enrollment host
$PkiWebSvcAccount = "PKIWebSvc"

$DfsPkiPath       = "$DfsRoot\$PkiFolderName"   # \\lab.local\share\PKIData
$ReqSiteName      = "ReqSite"
$CertSrvPool      = "CertSrvPool"
$ReqRoot          = "C:\InetPub\ReqSiteRoot"

# CA config string for WEB01 → SubCA1
$CAConfig         = "SubCA1.lab.local\Lab Issuing CA 1"


# ---- 1. INSTALL IIS + AD CS WEB ENROLLMENT FEATURES ----
Install-WindowsFeature Web-Server, Web-Static-Content, Web-Default-Doc, `
    Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Asp, Web-Windows-Auth, `
    ADCS-Web-Enrollment -IncludeManagementTools

Import-Module WebAdministration
Import-Module ADCSDeployment


# ---- 2. PROMPT FOR LAB\PKIWebSvc PASSWORD (ONCE) ----
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR           = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)


# ====================================================================
# PART A: PKI HTTP (CDP/AIA) ON DEFAULT WEB SITE
# ====================================================================

# ---- 3. CREATE PKIHttpPool AND SET IDENTITY ----
if (-not (Test-Path "IIS:\AppPools\PKIHttpPool")) {
    New-WebAppPool -Name "PKIHttpPool"
}

Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.password  -Value $passwordPlain

Restart-WebAppPool PKIHttpPool


# ---- 4. ENSURE DEFAULT WEB SITE IS RUNNING AND BOUND TO pki.lab.local ----
Start-Website "Default Web Site"

$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}


# ---- 5. CREATE /pkidata APPLICATION POINTING TO DFS ----
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}

$pkidataApp = Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $pkidataApp) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
}


# ---- 6. RUN DEFAULT WEB SITE ITSELF IN PKIHttpPool ----
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value "PKIHttpPool"
Restart-WebAppPool PKIHttpPool


# ---- 7. CONFIGURE AUTH AND DIRECTORY BROWSING FOR /pkidata ----
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name userName -Value "" `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name enabled -Value false `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/directoryBrowse `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/requestFiltering `
  -Name allowDoubleEscaping -Value true `
  -PSPath "IIS:\Sites\Default Web Site"


# ---- 8. ENSURE MIME TYPES FOR CRL/CRT ----
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


# ====================================================================
# PART B: WEB ENROLLMENT (/certsrv) ON DEDICATED REQSITE
# ====================================================================

# ---- 9. INSTALL / RECONFIGURE AD CS WEB ENROLLMENT TO CORRECT CA ----
Uninstall-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue

Install-AdcsWebEnrollment -CAConfig $CAConfig -Force

Write-Host "`n[INFO] Web Enrollment installed and pointed to: $CAConfig"


# ---- 10. CREATE CertSrvPool (RUNS AS LAB\PKIWebSvc) ----
if (-not (Test-Path "IIS:\AppPools\$CertSrvPool")) {
    New-WebAppPool -Name $CertSrvPool
}

Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.password  -Value $passwordPlain
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name managedPipelineMode -Value Classic

Restart-WebAppPool $CertSrvPool


# ---- 11. CREATE REQSITE (HTTP + HTTPS FOR req.lab.local) ----
if (-not (Test-Path $ReqRoot)) {
    New-Item -Path $ReqRoot -ItemType Directory | Out-Null
}

$reqSite = Get-Website -Name $ReqSiteName -ErrorAction SilentlyContinue
if (-not $reqSite) {
    New-Website -Name $ReqSiteName `
        -Port 80 `
        -HostHeader $ReqHost `
        -PhysicalPath $ReqRoot `
        -ApplicationPool $CertSrvPool
} else {
    Set-ItemProperty "IIS:\Sites\$ReqSiteName" -Name applicationPool -Value $CertSrvPool
}

$httpBinding = Get-WebBinding -Name $ReqSiteName -Protocol http -HostHeader $ReqHost -ErrorAction SilentlyContinue
if (-not $httpBinding) {
    New-WebBinding -Name $ReqSiteName -Protocol http -Port 80 -HostHeader $ReqHost
}

Start-Website $ReqSiteName


# ---- 12. MOVE /certsrv FROM DEFAULT WEB SITE TO REQSITE ----
$oldCertSrv = Get-WebApplication -Site "Default Web Site" -Name "certsrv" -ErrorAction SilentlyContinue

if ($oldCertSrv) {
    $certSrvPath = $oldCertSrv.physicalPath
    Remove-WebApplication -Site "Default Web Site" -Name "certsrv"
    New-WebApplication -Site $ReqSiteName -Name "certsrv" `
        -PhysicalPath $certSrvPath `
        -ApplicationPool $CertSrvPool
    Write-Host "[INFO] Moved /certsrv from Default Web Site to $ReqSiteName"
} else {
    $newCertSrv = Get-WebApplication -Site $ReqSiteName -Name "certsrv" -ErrorAction SilentlyContinue
    if ($newCertSrv) {
        Set-ItemProperty "IIS:\Sites\$ReqSiteName\certsrv" -Name applicationPool -Value $CertSrvPool
        Write-Host "[INFO] /certsrv already under $ReqSiteName; app pool set to $CertSrvPool"
    } else {
        Write-Warning "/certsrv not found under Default Web Site or $ReqSiteName."
    }
}


# ---- 13. BIND HTTPS (req.lab.local CERT) TO REQSITE ----
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq "CN=$ReqHost" } |
    Select-Object -First 1

if (-not $cert) {
    Write-Warning "Certificate 'CN=$ReqHost' not found in LocalMachine\My. You must enroll a Web Server cert for $ReqHost before HTTPS will work."
} else {
    $CertThumbprint = $cert.Thumbprint

    $httpsBinding = Get-WebBinding -Name $ReqSiteName -Protocol https -HostHeader $ReqHost -ErrorAction SilentlyContinue
    if (-not $httpsBinding) {
        New-WebBinding -Name $ReqSiteName -Protocol https -Port 443 -HostHeader $ReqHost
    }

    & netsh http delete sslcert hostnameport="$ReqHost`:443" 2>$null | Out-Null

    & netsh http add sslcert hostnameport="$ReqHost`:443" `
        certhash=$CertThumbprint `
        appid='{00112233-4455-6677-8899-AABBCCDDEEFF}' `
        certstorename=MY

    Write-Host "[INFO] HTTPS binding for $ReqHost configured with cert thumbprint: $CertThumbprint"
}


# ---- 14. CONFIGURE AUTHENTICATION ON /certsrv (WINDOWS AUTH ONLY) ----
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Name enabled `
  -Value true

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Name enabled `
  -Value false


# ---- 15. ENABLE CLASSIC ASP PARENT PATHS + DETAILED ERRORS FOR /certsrv ----
Set-WebConfiguration -Filter /system.webServer/asp `
  -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Metadata overrideMode -Value Allow

Set-WebConfigurationProperty `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Filter /system.webServer/asp `
  -Name enableParentPaths `
  -Value $true

Set-WebConfigurationProperty `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Filter /system.webServer/asp `
  -Name scriptErrorSentToBrowser `
  -Value $true

Set-WebConfigurationProperty `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Filter /system.webServer/httpErrors `
  -Name errorMode `
  -Value Detailed


# ---- 16. GRANT LAB\PKIWebSvc ACCESS TO C:\Windows\System32\CertSrv ----
$certSrvPath     = "C:\Windows\System32\CertSrv"
$certSrvEnUS     = "C:\Windows\System32\CertSrv\en-US"
$serviceAccount  = "${DomainNetBios}\${PkiWebSvcAccount}"

icacls $certSrvPath /grant "${serviceAccount}:(OI)(CI)RX" /T | Out-Null
takeown /F $certSrvEnUS /R /D Y | Out-Null
icacls $certSrvEnUS /grant "${serviceAccount}:(OI)(CI)RX" /T | Out-Null

Write-Host "[INFO] Granted $serviceAccount RX on $certSrvPath and $certSrvEnUS"


# ---- 17. CONFIGURE /certsrv VIRTUAL DIRECTORY TO USE LAB\PKIWebSvc (CONNECT AS) ----
# This ensures file access to C:\Windows\System32\CertSrv\en-US uses the service account
$certSrvVDir = Get-WebVirtualDirectory -Site $ReqSiteName -Application "certsrv" -Name "" -ErrorAction SilentlyContinue
if ($certSrvVDir) {
    Set-ItemProperty "IIS:\Sites\$ReqSiteName\certsrv" -Name virtualDirectory.userName -Value $serviceAccount
    Set-ItemProperty "IIS:\Sites\$ReqSiteName\certsrv" -Name virtualDirectory.password -Value $passwordPlain
    Write-Host "[INFO] /certsrv virtual directory set to 'Connect as: $serviceAccount'"
}

Restart-WebAppPool $CertSrvPool


# ---- 18. CLEAR PASSWORD FROM MEMORY ----
$passwordPlain = $null


# ---- 19. QUICK VALIDATION ----
Write-Host "`n=== WEB01 CONFIGURATION SUMMARY ==="
Write-Host "PKI HTTP:        http://pki.lab.local/pkidata"
Write-Host "Web Enrollment:  https://req.lab.local/certsrv"
Write-Host "CA Config:       $CAConfig"
Write-Host ""

Write-Host "=== Application Pool for /pkidata ==="
(Get-WebApplication -Site "Default Web Site" -Name "pkidata").applicationPool

Write-Host "`n=== Application Pool for /certsrv ==="
(Get-WebApplication -Site $ReqSiteName -Name "certsrv").applicationPool

Write-Host "`n=== Testing PKI HTTP from WEB01 ==="
Invoke-WebRequest "http://pki.lab.local/pkidata" -UseBasicParsing | Select-Object StatusCode

Write-Host "`n=== Testing Web Enrollment HTTPS from WEB01 (expect 401 without creds) ==="
Invoke-WebRequest "https://req.lab.local/certsrv" -UseBasicParsing -ErrorAction SilentlyContinue | Select-Object StatusCode

Write-Host "`n[DONE] WEB01 configuration complete. Test from a domain client with:"
Write-Host "  Invoke-WebRequest 'https://req.lab.local/certsrv' -UseDefaultCredentials"




# ====================================================================
# PKI HTTP + WEB ENROLLMENT CONFIG FOR WEB02
# ====================================================================

# ---- COMMON VARIABLES ----
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"

$PkiHttpHost      = "pki.lab.local"   # HTTP CDP/AIA host
$ReqHost          = "req.lab.local"   # HTTPS Web Enrollment host
$PkiWebSvcAccount = "PKIWebSvc"

$DfsPkiPath       = "$DfsRoot\$PkiFolderName"   # \\lab.local\share\PKIData
$ReqSiteName      = "ReqSite"
$CertSrvPool      = "CertSrvPool"
$ReqRoot          = "C:\InetPub\ReqSiteRoot"

# CA config string for WEB02 → SubCA2
$CAConfig         = "SubCA2.lab.local\Lab Issuing CA 2"


# ---- 1. INSTALL IIS + AD CS WEB ENROLLMENT FEATURES ----
Install-WindowsFeature Web-Server, Web-Static-Content, Web-Default-Doc, `
    Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Asp, Web-Windows-Auth, `
    ADCS-Web-Enrollment -IncludeManagementTools

Import-Module WebAdministration
Import-Module ADCSDeployment


# ---- 2. PROMPT FOR LAB\PKIWebSvc PASSWORD (ONCE) ----
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR           = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)


# ====================================================================
# PART A: PKI HTTP (CDP/AIA) ON DEFAULT WEB SITE
# ====================================================================

# ---- 3. CREATE PKIHttpPool AND SET IDENTITY ----
if (-not (Test-Path "IIS:\AppPools\PKIHttpPool")) {
    New-WebAppPool -Name "PKIHttpPool"
}

Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\PKIHttpPool" -Name processModel.password  -Value $passwordPlain

Restart-WebAppPool PKIHttpPool


# ---- 4. ENSURE DEFAULT WEB SITE IS RUNNING AND BOUND TO pki.lab.local ----
Start-Website "Default Web Site"

$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}


# ---- 5. CREATE /pkidata APPLICATION POINTING TO DFS ----
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}

$pkidataApp = Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $pkidataApp) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool "PKIHttpPool"
}


# ---- 6. RUN DEFAULT WEB SITE ITSELF IN PKIHttpPool ----
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value "PKIHttpPool"
Restart-WebAppPool PKIHttpPool


# ---- 7. CONFIGURE AUTH AND DIRECTORY BROWSING FOR /pkidata ----
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name userName -Value "" `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name enabled -Value false `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/directoryBrowse `
  -Name enabled -Value true `
  -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/requestFiltering `
  -Name allowDoubleEscaping -Value true `
  -PSPath "IIS:\Sites\Default Web Site"


# ---- 8. ENSURE MIME TYPES FOR CRL/CRT ----
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


# ====================================================================
# PART B: WEB ENROLLMENT (/certsrv) ON DEDICATED REQSITE
# ====================================================================

# ---- 9. INSTALL / RECONFIGURE AD CS WEB ENROLLMENT TO CORRECT CA ----
Uninstall-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue

Install-AdcsWebEnrollment -CAConfig $CAConfig -Force

Write-Host "`n[INFO] Web Enrollment installed and pointed to: $CAConfig"


# ---- 10. CREATE CertSrvPool (RUNS AS LAB\PKIWebSvc) ----
if (-not (Test-Path "IIS:\AppPools\$CertSrvPool")) {
    New-WebAppPool -Name $CertSrvPool
}

Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.password  -Value $passwordPlain
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name managedPipelineMode -Value Classic

Restart-WebAppPool $CertSrvPool


# ---- 11. CREATE REQSITE (HTTP + HTTPS FOR req.lab.local) ----
if (-not (Test-Path $ReqRoot)) {
    New-Item -Path $ReqRoot -ItemType Directory | Out-Null
}

$reqSite = Get-Website -Name $ReqSiteName -ErrorAction SilentlyContinue
if (-not $reqSite) {
    New-Website -Name $ReqSiteName `
        -Port 80 `
        -HostHeader $ReqHost `
        -PhysicalPath $ReqRoot `
        -ApplicationPool $CertSrvPool
} else {
    Set-ItemProperty "IIS:\Sites\$ReqSiteName" -Name applicationPool -Value $CertSrvPool
}

$httpBinding = Get-WebBinding -Name $ReqSiteName -Protocol http -HostHeader $ReqHost -ErrorAction SilentlyContinue
if (-not $httpBinding) {
    New-WebBinding -Name $ReqSiteName -Protocol http -Port 80 -HostHeader $ReqHost
}

Start-Website $ReqSiteName


# ---- 12. MOVE /certsrv FROM DEFAULT WEB SITE TO REQSITE ----
$oldCertSrv = Get-WebApplication -Site "Default Web Site" -Name "certsrv" -ErrorAction SilentlyContinue

if ($oldCertSrv) {
    $certSrvPath = $oldCertSrv.physicalPath
    Remove-WebApplication -Site "Default Web Site" -Name "certsrv"
    New-WebApplication -Site $ReqSiteName -Name "certsrv" `
        -PhysicalPath $certSrvPath `
        -ApplicationPool $CertSrvPool
    Write-Host "[INFO] Moved /certsrv from Default Web Site to $ReqSiteName"
} else {
    $newCertSrv = Get-WebApplication -Site $ReqSiteName -Name "certsrv" -ErrorAction SilentlyContinue
    if ($newCertSrv) {
        Set-ItemProperty "IIS:\Sites\$ReqSiteName\certsrv" -Name applicationPool -Value $CertSrvPool
        Write-Host "[INFO] /certsrv already under $ReqSiteName; app pool set to $CertSrvPool"
    } else {
        Write-Warning "/certsrv not found under Default Web Site or $ReqSiteName."
    }
}


# ---- 13. BIND HTTPS (req.lab.local CERT) TO REQSITE ----
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq "CN=$ReqHost" } |
    Select-Object -First 1

if (-not $cert) {
    Write-Warning "Certificate 'CN=$ReqHost' not found in LocalMachine\My. You must enroll a Web Server cert for $ReqHost before HTTPS will work."
} else {
    $CertThumbprint = $cert.Thumbprint

    $httpsBinding = Get-WebBinding -Name $ReqSiteName -Protocol https -HostHeader $ReqHost -ErrorAction SilentlyContinue
    if (-not $httpsBinding) {
        New-WebBinding -Name $ReqSiteName -Protocol https -Port 443 -HostHeader $ReqHost
    }

    & netsh http delete sslcert hostnameport="$ReqHost`:443" 2>$null | Out-Null

    & netsh http add sslcert hostnameport="$ReqHost`:443" `
        certhash=$CertThumbprint `
        appid='{00112233-4455-6677-8899-AABBCCDDEEFF}' `
        certstorename=MY

    Write-Host "[INFO] HTTPS binding for $ReqHost configured with cert thumbprint: $CertThumbprint"
}


# ---- 14. CONFIGURE AUTHENTICATION ON /certsrv (WINDOWS AUTH ONLY) ----
Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Name enabled `
  -Value true

Set-WebConfigurationProperty `
  -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Name enabled `
  -Value false


# ---- 15. ENABLE CLASSIC ASP PARENT PATHS + DETAILED ERRORS FOR /certsrv ----
Set-WebConfiguration -Filter /system.webServer/asp `
  -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Metadata overrideMode -Value Allow

Set-WebConfigurationProperty `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Filter /system.webServer/asp `
  -Name enableParentPaths `
  -Value $true

Set-WebConfigurationProperty `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Filter /system.webServer/asp `
  -Name scriptErrorSentToBrowser `
  -Value $true

Set-WebConfigurationProperty `
  -PSPath "IIS:\Sites\$ReqSiteName\certsrv" `
  -Filter /system.webServer/httpErrors `
  -Name errorMode `
  -Value Detailed


# ---- 16. GRANT LAB\PKIWebSvc ACCESS TO C:\Windows\System32\CertSrv ----
$certSrvPath     = "C:\Windows\System32\CertSrv"
$certSrvEnUS     = "C:\Windows\System32\CertSrv\en-US"
$serviceAccount  = "${DomainNetBios}\${PkiWebSvcAccount}"

icacls $certSrvPath /grant "${serviceAccount}:(OI)(CI)RX" /T | Out-Null
takeown /F $certSrvEnUS /R /D Y | Out-Null
icacls $certSrvEnUS /grant "${serviceAccount}:(OI)(CI)RX" /T | Out-Null

Write-Host "[INFO] Granted $serviceAccount RX on $certSrvPath and $certSrvEnUS"


# ---- 17. CONFIGURE /certsrv VIRTUAL DIRECTORY TO USE LAB\PKIWebSvc (CONNECT AS) ----
# This ensures file access to C:\Windows\System32\CertSrv\en-US uses the service account
$certSrvVDir = Get-WebVirtualDirectory -Site $ReqSiteName -Application "certsrv" -Name "" -ErrorAction SilentlyContinue
if ($certSrvVDir) {
    Set-ItemProperty "IIS:\Sites\$ReqSiteName\certsrv" -Name virtualDirectory.userName -Value $serviceAccount
    Set-ItemProperty "IIS:\Sites\$ReqSiteName\certsrv" -Name virtualDirectory.password -Value $passwordPlain
    Write-Host "[INFO] /certsrv virtual directory set to 'Connect as: $serviceAccount'"
}

Restart-WebAppPool $CertSrvPool


# ---- 18. CLEAR PASSWORD FROM MEMORY ----
$passwordPlain = $null


# ---- 19. QUICK VALIDATION ----
Write-Host "`n=== WEB02 CONFIGURATION SUMMARY ==="
Write-Host "PKI HTTP:        http://pki.lab.local/pkidata"
Write-Host "Web Enrollment:  https://req.lab.local/certsrv"
Write-Host "CA Config:       $CAConfig"
Write-Host ""

Write-Host "=== Application Pool for /pkidata ==="
(Get-WebApplication -Site "Default Web Site" -Name "pkidata").applicationPool

Write-Host "`n=== Application Pool for /certsrv ==="
(Get-WebApplication -Site $ReqSiteName -Name "certsrv").applicationPool

Write-Host "`n=== Testing PKI HTTP from WEB02 ==="
Invoke-WebRequest "http://pki.lab.local/pkidata" -UseBasicParsing | Select-Object StatusCode

Write-Host "`n=== Testing Web Enrollment HTTPS from WEB02 (expect 401 without creds) ==="
Invoke-WebRequest "https://req.lab.local/certsrv" -UseBasicParsing -ErrorAction SilentlyContinue | Select-Object StatusCode

Write-Host "`n[DONE] WEB02 configuration complete. Test from a domain client with:"
Write-Host "  Invoke-WebRequest 'https://req.lab.local/certsrv' -UseDefaultCredentials"