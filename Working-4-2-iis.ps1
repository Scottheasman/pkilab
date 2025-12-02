# Working-4-2-iis.ps1
# PKI HTTP + WEB ENROLLMENT CONFIG FOR WEB01 and WEB02
# Run elevated on each web server (adjust $CAConfig per server below)

# ---- COMMON VARIABLES ----
$DomainFqdn    = "lab.local"
$DomainNetBios = "LAB"
$DfsRoot       = "\\lab.local\share"
$PkiFolderName = "PKIData"

$PkiHttpHost   = "pki.lab.local"   # HTTP CDP/AIA host
$ReqHost       = "req.lab.local"   # HTTPS Web Enrollment host
$PkiWebSvcAccount = "PKIWebSvc"

$DfsPkiPath    = "$DfsRoot\$PkiFolderName"   # \\lab.local\share\PKIData
$ReqSiteName    = "ReqSite"
$CertSrvPool    = "CertSrvPool"
$PKIHttpPool    = "PKIHttpPool"
$ReqRoot        = "C:\InetPub\ReqSiteRoot"

# ---- CAConfig: set the appropriate CA for this server before running ----
# For WEB01:
# $CAConfig = "SubCA1.lab.local\Lab Issuing CA 1"
# For WEB02:
# $CAConfig = "SubCA2.lab.local\Lab Issuing CA 2"
if (-not $CAConfig) {
    Write-Warning "CAConfig not set. Edit the script or set $CAConfig before running."
}

# ---- Import modules ----
Import-Module WebAdministration -ErrorAction Stop
Import-Module ADCSDeployment -ErrorAction SilentlyContinue

# ---- Prompt for PKIWebSvc password ----
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR    = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# PART A: PKI HTTP (CDP/AIA) ON DEFAULT WEB SITE

# 1) Create PKIHttpPool and set identity
if (-not (Test-Path "IIS:\AppPools\$PKIHttpPool")) {
    New-WebAppPool -Name $PKIHttpPool
}
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.password  -Value $passwordPlain
Restart-WebAppPool $PKIHttpPool

# 2) Ensure Default Web Site is running and bound to pki.lab.local
Start-Website "Default Web Site"
$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}

# 3) Create /pkidata application pointing to DFS
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}
$pkidataApp = Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $pkidataApp) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
}

# 4) Run Default Web Site in PKIHttpPool
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value $PKIHttpPool
Restart-WebAppPool $PKIHttpPool

# 5) Configure authentication and directory browsing for /pkidata
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication `
  -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow

Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name enabled -Value $true -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication `
  -Name userName -Value "" -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name enabled -Value $false -PSPath "IIS:\Sites\Default Web Site\pkidata"

Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\Sites\Default Web Site"

# 6) Ensure mime types for crl/crt
function Ensure-MimeType { param([string]$Extension,[string]$MimeType)
    $existing = Get-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent/mimeMap' -name '.' |
        Where-Object { $_.fileExtension -eq $Extension }
    if (-not $existing) {
        Add-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent' -name '.' `
            -value @{ fileExtension = $Extension; mimeType = $MimeType }
    }
}
Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'

# PART B: WEB ENROLLMENT (/certsrv) ON DEDICATED REQSITE

# 7) Install / reconfigure AD CS Web Enrollment to correct CA
Uninstall-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue
if ($CAConfig) {
    Install-AdcsWebEnrollment -CAConfig $CAConfig -Force
    Write-Host "`n[INFO] Web Enrollment installed and pointed to: $CAConfig"
} else {
    Write-Warning "CAConfig not set - Install-AdcsWebEnrollment skipped. Set CAConfig and re-run the script."
}

# 8) Create CertSrvPool (runs as LAB\PKIWebSvc)
if (-not (Test-Path "IIS:\AppPools\$CertSrvPool")) {
    New-WebAppPool -Name $CertSrvPool
}
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel.password  -Value $passwordPlain
Set-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name managedPipelineMode -Value Classic
Restart-WebAppPool $CertSrvPool

# 9) Create ReqSite (HTTP + HTTPS for req.lab.local)
if (-not (Test-Path $ReqRoot)) {
    New-Item -Path $ReqRoot -ItemType Directory | Out-Null
}
$reqSite = Get-Website -Name $ReqSiteName -ErrorAction SilentlyContinue
if (-not $reqSite) {
    New-Website -Name $ReqSiteName -Port 80 -HostHeader $ReqHost -PhysicalPath $ReqRoot -ApplicationPool $CertSrvPool
} else {
    Set-ItemProperty "IIS:\Sites\$ReqSiteName" -Name applicationPool -Value $CertSrvPool
}
$httpBinding = Get-WebBinding -Name $ReqSiteName -Protocol http -HostHeader $ReqHost -ErrorAction SilentlyContinue
if (-not $httpBinding) {
    New-WebBinding -Name $ReqSiteName -Protocol http -Port 80 -HostHeader $ReqHost
}
Start-Website $ReqSiteName

# 10) Move /certsrv from Default Web Site to ReqSite
$oldCertSrv = Get-WebApplication -Site "Default Web Site" -Name "certsrv" -ErrorAction SilentlyContinue
if ($oldCertSrv) {
    $certSrvPath = $oldCertSrv.physicalPath
    Remove-WebApplication -Site "Default Web Site" -Name "certsrv"
    New-WebApplication -Site $ReqSiteName -Name "certsrv" -PhysicalPath $certSrvPath -ApplicationPool $CertSrvPool
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

# 11) Bind HTTPS (req.lab.local cert) to ReqSite
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$ReqHost" } | Select-Object -First 1
if (-not $cert) {
    Write-Warning "Certificate 'CN=$ReqHost' not found in LocalMachine\My. Enroll a web server cert for $ReqHost first."
} else {
    $CertThumbprint = $cert.Thumbprint
    $httpsBinding = Get-WebBinding -Name $ReqSiteName -Protocol https -HostHeader $ReqHost -ErrorAction SilentlyContinue
    if (-not $httpsBinding) {
        New-WebBinding -Name $ReqSiteName -Protocol https -Port 443 -HostHeader $ReqHost
    }
    & netsh http delete sslcert hostnameport="$ReqHost`:443" 2>$null | Out-Null
    & netsh http add sslcert hostnameport="$ReqHost`:443" certhash=$CertThumbprint appid='{00112233-4455-6677-8899-AABBCCDDEEFF}' certstorename=MY
    Write-Host "[INFO] HTTPS binding for $ReqHost configured with cert thumbprint: $CertThumbprint"
}

# 12) Configure authentication on /certsrv (Windows Auth only)
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath "IIS:\Sites\$ReqSiteName\certsrv" -Name enabled -Value $true
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "IIS:\Sites\$ReqSiteName\certsrv" -Name enabled -Value $false

# 13) Enable Classic ASP parent paths + detailed errors for /certsrv
Set-WebConfiguration -Filter /system.webServer/asp -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$ReqSiteName\certsrv" -Filter /system.webServer/asp -Name enableParentPaths -Value $true
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$ReqSiteName\certsrv" -Filter /system.webServer/asp -Name scriptErrorSentToBrowser -Value $true
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$ReqSiteName\certsrv" -Filter /system.webServer/httpErrors -Name errorMode -Value Detailed

# 14) Grant LAB\PKIWebSvc access to C:\Windows\System32\CertSrv
$certSrvPath    = "C:\Windows\System32\CertSrv"
$certSrvEnUS    = "C:\Windows\System32\CertSrv\en-US"
$serviceAccount  = "${DomainNetBios}\${PkiWebSvcAccount}"
icacls $certSrvPath /grant "${serviceAccount}:(OI)(CI)RX" /T | Out-Null
takeown /F $certSrvEnUS /R /D Y | Out-Null
icacls $certSrvEnUS /grant "${serviceAccount}:(OI)(CI)RX" /T | Out-Null
Write-Host "[INFO] Granted $serviceAccount RX on $certSrvPath and $certSrvEnUS"

# 15) Configure /certsrv virtual directory to use LAB\PKIWebSvc (Connect As)
$certSrvVDir = Get-WebVirtualDirectory -Site $ReqSiteName -Application "certsrv" -Name "" -ErrorAction SilentlyContinue
if ($certSrvVDir) {
    # Use the WebConfigurationProperty method (more reliable on some systems)
    $vdirFilter = "system.applicationHost/sites/site[@name='$ReqSiteName']/application[@path='/certsrv']/virtualDirectory"
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $vdirFilter -Name userName -Value $serviceAccount
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter $vdirFilter -Name password -Value $passwordPlain
    Write-Host "[INFO] /certsrv virtual directory set to 'Connect as: $serviceAccount'"
} else {
    Write-Warning "/certsrv virtual directory not found under $ReqSiteName"
}

Restart-WebAppPool $CertSrvPool

# 16) Clear password from memory
$passwordPlain = $null

# --- Quick SPN & Delegation check (informational) ---
Write-Host "`n=== SPN & Delegation Quick Check ===" -ForegroundColor Cyan
$httpSpn = "HTTP/$ReqHost"
Write-Host "Checking SPN: $httpSpn"
$spnQuery = & setspn -Q $httpSpn 2>&1
Write-Host $spnQuery
if ($spnQuery -notmatch $DomainNetBios -and $spnQuery -match "No matching") {
    Write-Host "`nSPN $httpSpn not found. On DC1 run: setspn -S $httpSpn ${DomainNetBios}\${PkiWebSvcAccount}" -ForegroundColor Yellow
} elseif ($spnQuery -match "cannot find") {
    Write-Host "`nsetspn couldn't query owner from this host. Run the AD delegation script on DC1: Working-AD-SetDelegation.ps1" -ForegroundColor Yellow
} else {
    Write-Host "`nSPN query returned registration(s). Verify it lists ${DomainNetBios}\${PkiWebSvcAccount} if you expect Kerberos to be accepted by the service account." -ForegroundColor Green
}
Write-Host "`nIf constrained delegation not yet applied, run Working-AD-SetDelegation.ps1 on DC1 (recommended) or Working-AD-SetRBCD.ps1 for RBCD." -ForegroundColor Cyan

# 17) Quick validation output
Write-Host "`n=== CONFIGURATION SUMMARY ==="
Write-Host "PKI HTTP:       http://$PkiHttpHost/pkidata"
Write-Host "Web Enrollment: https://$ReqHost/certsrv"
Write-Host "Site:           $ReqSiteName"
Write-Host "Application Pools:"
Get-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel | Select-Object @{n='Pool';e={$PKIHttpPool}}, processModel.userName, processModel.identityType
Get-ItemProperty "IIS:\AppPools\$CertSrvPool" -Name processModel | Select-Object @{n='Pool';e={$CertSrvPool}}, processModel.userName, processModel.identityType

Write-Host "`nLocal tests (server may not show Kerberos ticket):"
try { Invoke-WebRequest "http://$PkiHttpHost/pkidata" -UseBasicParsing -ErrorAction Stop | Select-Object StatusCode } catch { Write-Host "PKI HTTP local test failed: $($_.Exception.Message)" }
try { Invoke-WebRequest "https://$ReqHost/certsrv" -UseBasicParsing -ErrorAction SilentlyContinue | Select-Object StatusCode } catch { Write-Host "Web Enrollment local test skipped or failed." }

Write-Host "`n[DONE] Server configuration complete. Now run the AD delegation script on DC1 if not already applied."