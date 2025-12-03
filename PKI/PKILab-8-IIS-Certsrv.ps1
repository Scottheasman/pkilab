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