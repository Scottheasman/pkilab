<#
.SYNOPSIS
  Configure IIS for Kerberos delegation usage for /certsrv.
  - Set application pool identity to ApplicationPoolIdentity
  - Disable anonymous and enable Windows Authentication (Negotiate) on /certsrv

.NOTES
  - Run on each IIS server with Administrator privileges.
  - Edit $IISSiteName and $IISAppPoolName to match your site/app pool.
#>

Import-Module WebAdministration -ErrorAction Stop

# === CONFIGURATION - EDIT ME ===
$IISSiteName    = "ReqSite"       # name of the IIS site that contains certsrv
$IISAppPoolName = "CertSrvPool"   # app pool used by /certsrv
$CertSrvAppName = "certsrv"       # application name under the site
# ================================

# Validate app pool exists
if (-not (Test-Path "IIS:\AppPools$IISAppPoolName")) {
    Write-Error "App pool '$IISAppPoolName' not found. Create it or set correct name."; exit 1
}

# Set app pool to ApplicationPoolIdentity (value 4)
Write-Host "Setting app pool '$IISAppPoolName' to ApplicationPoolIdentity..." -ForegroundColor Cyan
Set-ItemProperty "IIS:\AppPools$IISAppPoolName" -Name processModel.identityType -Value 4

# Ensure the site/app exist
$appPath = "IIS:\Sites$IISSiteName$CertSrvAppName"
if (-not (Test-Path $appPath)) {
    Write-Warning "Application path $appPath not found. Ensure your site and /$CertSrvAppName exist before continuing."
} else {
    # Disable anonymous
    Write-Host "Disabling Anonymous Authentication for $appPath" -ForegroundColor Cyan
    Set-WebConfigurationProperty -PSPath $appPath -Filter system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value $false

    # Enable Windows Authentication
    Write-Host "Enabling Windows Authentication for $appPath (Negotiate provider)" -ForegroundColor Cyan
    Set-WebConfigurationProperty -PSPath $appPath -Filter system.webServer/security/authentication/windowsAuthentication -Name enabled -Value $true

    # Set providers to Negotiate only (so Kerberos preferred)
    # Note: If you rely on NTLM for fallback, add "NTLM" accordingly
    Set-WebConfigurationProperty -PSPath $appPath -Filter system.webServer/security/authentication/windowsAuthentication/providers -Name . -Value @("Negotiate")

    Write-Host "IIS authentication configuration applied to $appPath" -ForegroundColor Green
}

Write-Host "IIS KCD configuration complete. Restart IIS if necessary." -ForegroundColor Yellow
