<#
    Working-OCSP-FullDeploy.ps1
    Fully-automated OCSP deploy helper (install role, enroll OCSP signing cert, start service)
    Usage: Run elevated on each OCSP server (OCSP1, OCSP2).
    Edit CONFIG below for your environment before running.

    WARNING: This script will submit a certificate request to the specified CA and accept the issued cert into the LocalMachine\My store.
#>

# -----------------------
# CONFIG - EDIT BEFORE RUN
# -----------------------
# CAConfig must be the CAConfig string for the issuing CA that will issue the OCSP signing cert:
# e.g. "SubCA1.lab.local\Lab Issuing CA 1"
$CAConfig = "SubCA1.lab.local\Lab Issuing CA 1"

# The certificate template name you published on the issuing CA for OCSP signing
$OCSPTemplateName = "OCSP-Responder-Signing"

# Subject CN for this OCSP server's OCSP signing cert (should match what you want on the cert)
# e.g. "CN=ocsp1.lab.local" (only the CN value below, not full Subject string)
$OCSPCertCN = "ocsp1.lab.local"

# URL(s) where the OCSP responder's revocation configuration will fetch the CRL.
# Usually this points to your PKI HTTP CDP, e.g. "http://pki.lab.local/pkidata/<name>.crl"
# Use as many CRL URLs as necessary for the issuing CA.
$CRLUrls = @("http://pki.lab.local/pkidata/SubCA1_lab_local.crl")

# Optional: path to export the issuing CA certificate (this helps automated Revocation Config creation)
$ExportedCACertPath = "$env:TEMP\IssuingCA.cer"

# Path used for temporary certreq files
$WorkPath = "$env:TEMP\OCSPdeploy"
# -----------------------

function Assert-Elevated {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run elevated (Run as Administrator). Exiting."
        exit 1
    }
}

function Ensure-WorkPath {
    if (-not (Test-Path $WorkPath)) {
        New-Item -Path $WorkPath -ItemType Directory | Out-Null
    }
}

function Write-Info { param($m) Write-Host $m -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host $m -ForegroundColor Green }
function Write-Warn { param($m) Write-Host $m -ForegroundColor Yellow }
function Write-Err { param($m) Write-Host $m -ForegroundColor Red }

Assert-Elevated
Ensure-WorkPath

# 1) Install Online Responder role
Write-Info "1) Installing Online Responder role (if not already installed)..."
$role = Get-WindowsFeature -Name Online-Responder
if ($role -and $role.Installed) {
    Write-Info "Online Responder role already installed."
} else {
    Install-WindowsFeature Online-Responder -IncludeManagementTools -ErrorAction Stop
    Write-Success "Online Responder role installed."
}

# 2) Ensure Online Responder service set to Automatic
Write-Info "2) Configuring Online Responder service..."
try {
    Set-Service -Name ocsp -StartupType Automatic -ErrorAction Stop
    Write-Success "OCSP service startup set to Automatic."
} catch {
    Write-Warn "Could not set service properties for 'ocsp' (may not exist). Continuing..."
}

# 3) Build certreq INF
$infPath = Join-Path $WorkPath "OCSP-request.inf"
$reqPath = Join-Path $WorkPath "OCSP-request.req"
$respPath = Join-Path $WorkPath "OCSP-request.cer"

Write-Info "3) Creating certreq INF at $infPath ..."
$inf = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=$OCSPCertCN"
KeySpec = 1
KeyLength = 4096
Exportable = FALSE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
HashAlgorithm = SHA256

[EnhancedKeyUsage]
OID=1.3.6.1.5.5.7.3.9 ; OCSPSigning
"@

Set-Content -Path $infPath -Value $inf -Encoding ASCII

# 4) Create request and submit to CA
Write-Info "4) Creating request and submitting to CA ($CAConfig) using template $OCSPTemplateName ..."
if (Test-Path $reqPath) { Remove-Item $reqPath -Force -ErrorAction SilentlyContinue }
if (Test-Path $respPath) { Remove-Item $respPath -Force -ErrorAction SilentlyContinue }

# Create request
& certreq -new $infPath $reqPath
if ($LASTEXITCODE -ne 0) {
    Write-Err "certreq -new failed. Inspect $infPath and retry. Exiting."
    exit 1
}

# Submit request; include template attribute
# Note: certreq -submit will pop up UI if multiple CA choices exist; certreq returns 0 if succeeds.
Write-Info "Submitting request to CA. This may prompt to pick the CA if multiple are available on this host."
$submitArgs = @("-submit", "-attrib", "CertificateTemplate:$OCSPTemplateName", "-config", $CAConfig, $reqPath, $respPath)
& certreq @submitArgs
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $respPath)) {
    Write-Err "certreq -submit did not return a certificate. Please check CA availability, template permissions (Enroll for this server), and $CAConfig. Exiting."
    exit 1
}

# Accept the certificate into LocalMachine\My
Write-Info "Accepting certificate into LocalMachine\My ..."
& certreq -accept $respPath
if ($LASTEXITCODE -ne 0) {
    Write-Err "certreq -accept failed. Check permissions and try to import the cert manually. Exiting."
    exit 1
}

# 5) Validate certificate presence + EKU
Write-Info "5) Verifying the OCSP signing certificate exists and has OCSPSigning EKU ..."
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.Subject -match "CN=$OCSPCertCN" -and
        ($_.EnhancedKeyUsageList | Where-Object { $_.Oid.Value -eq "1.3.6.1.5.5.7.3.9" -or $_.FriendlyName -match "OCSP" })
    } | Select-Object -First 1

if (-not $cert) {
    Write-Err "OCSP signing certificate not found in LocalMachine\My with EKU OCSPSigning. Check template, enrollment rights, and CA. Exiting."
    exit 1
} else {
    Write-Success "Found OCSP signing cert: $($cert.Subject) (thumbprint: $($cert.Thumbprint))"
}

# 6) Start/Restart Online Responder service to ensure it picks up cert store
Write-Info "6) Restarting Online Responder service..."
try {
    Restart-Service -Name ocsp -Force -ErrorAction Stop
    Start-Sleep -Seconds 3
    Get-Service -Name ocsp | Select-Object Status
    Write-Success "Online Responder service restarted."
} catch {
    Write-Warn "Could not restart 'ocsp' service: $($_.Exception.Message). Verify service name and run manually if required."
}

# 7) Export issuing CA certificate to file for revocation config creation or manual import
Write-Info "7) Exporting issuing CA certificate for Revocation Configuration (to $ExportedCACertPath)..."
try {
    # Attempt to fetch the issuing CA cert from the configured CA (by querying AD or using certutil)
    # We'll use certutil to retrieve CA cert via -config and -cacert option
    & certutil -config $CAConfig -cacert $ExportedCACertPath > $null 2>&1
    if (-not (Test-Path $ExportedCACertPath)) {
        # fallback: try to find in LocalMachine\CA (if CA was previously added)
        $fallback = Get-ChildItem -Path Cert:\LocalMachine\CA -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fallback) {
            Export-Certificate -Cert $fallback -FilePath $ExportedCACertPath -Force | Out-Null
        } else {
            Write-Warn "Could not auto-export CA certificate. You may need to export the issuing CA cert manually and place it at $ExportedCACertPath"
        }
    } else {
        Write-Success "Exported issuing CA cert to $ExportedCACertPath"
    }
} catch {
    Write-Warn "Export attempt failed; ensure the host can contact the CA. You may export the CA cert manually to $ExportedCACertPath."
}

# 8) Attempt to auto-create Revocation Configuration if Online Responder cmdlets are available
Write-Info "8) Attempting to create Revocation Configuration automatically using Online Responder PowerShell cmdlets (if available)..."
$addCmd = Get-Command -Name Add-OnlineResponderRevocationConfiguration -ErrorAction SilentlyContinue
$exportCmd = Get-Command -Name Export-OnlineResponderRevocationConfiguration -ErrorAction SilentlyContinue
$importCmd = Get-Command -Name Import-OnlineResponderRevocationConfiguration -ErrorAction SilentlyContinue

if ($addCmd) {
    Write-Info "Found Add-OnlineResponderRevocationConfiguration cmdlet. Creating revocation configuration..."
    # Build parameters - these cmdlet parameters may vary by Windows version. We'll attempt common parameters and catch errors.
    $rcName = "RevConfig-$($env:COMPUTERNAME)-$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"
    try {
        Add-OnlineResponderRevocationConfiguration -RevocationConfigurationName $rcName `
            -CACertificateFilePath $ExportedCACertPath `
            -OCSPSigningCertThumbprint $cert.Thumbprint `
            -CRLDistributionPoint $CRLUrls[0] -Force -ErrorAction Stop
        Write-Success "Created Revocation Configuration: $rcName (verify in Online Responder Management)."
    } catch {
        Write-Warn "Automatic creation via Add-OnlineResponderRevocationConfiguration failed: $($_.Exception.Message)"
        Write-Warn "You can create the revocation config manually via the Online Responder MMC (see the runbook instructions)."
    }
} else {
    Write-Warn "Online Responder PowerShell cmdlets not present on this host. Skipping automated Revocation Configuration creation."
    Write-Host ""
    Write-Host "Manual/alternative options:"
    Write-Host "  - Open 'Online Responder Management' MMC on this server, right-click Revocation Configuration -> Add Revocation Configuration..."
    Write-Host "    * For CA Certificate, browse to the exported CA cert: $ExportedCACertPath"
    Write-Host "    * For OCSP Signing Certificate, choose the cert with Thumbprint: $($cert.Thumbprint)"
    Write-Host "    * Use CRL Distribution Point(s):"
    $CRLUrls | ForEach-Object { Write-Host "        $_" }
    Write-Host ""
    Write-Host "If you want to automate this step you can run this script on a machine that has the Online Responder Management PowerShell cmdlets installed (or install them on this box) and re-run the automated step."
}

# 9) Export the OCSP signing cert thumbprint and a small checklist file
$checkPath = Join-Path $WorkPath "OCSP-Deploy-Checklist.txt"
$check = @()
$check += "OCSP Deploy checklist - $([datetime]::UtcNow)"
$check += "Machine: $env:COMPUTERNAME"
$check += "OCSP signing cert subject: $($cert.Subject)"
$check += "OCSP signing cert thumbprint: $($cert.Thumbprint)"
$check += "Exported issuing CA cert path: $ExportedCACertPath"
$check += "CRL URLs intended for revocation config:"
$CRLUrls | ForEach-Object { $check += "  $_" }
$check += ""
$check += "If automated Revocation Configuration creation failed, open Online Responder Management and:"
$check += "  1) Add Revocation Configuration -> Name (e.g. Lab-SubCA1-RevConfig)"
$check += "  2) Browse and select the Issuing CA certificate file: $ExportedCACertPath"
$check += "  3) Select the OCSP signing cert (thumbprint shown above)"
$check += "  4) Add CRL distribution points (use CRL URLs above)"
$check += "  5) Activate the revocation configuration and test"
$check | Out-File -FilePath $checkPath -Encoding ASCII

Write-Success "Checklist and details saved to: $checkPath"

Write-Host ""
Write-Success "OCSP deployment tasks completed (role install, cert enrollment, and service start)."
Write-Host ""
Write-Host "Next steps (if automatic revocation config not created):"
Write-Host "  - Import the exported issuing CA certificate ($ExportedCACertPath) into the Revocation Configuration wizard"
Write-Host "  - Select the OCSP signing certificate (thumbprint above) in the wizard"
Write-Host "  - Provide CRL URLs and activate the configuration"
Write-Host ""
Write-Host "After configuring on OCSP1, EXPORT the Revocation Configuration (right-click -> Export Revocation Configuration) and IMPORT it on OCSP2 for identical configs."
Write-Host ""
Write-Host "Testing hints:"
Write-Host "  - On a client, use certutil -URL <certfile> to test OCSP responses"
Write-Host "  - Check Event Viewer -> Applications and Services Logs -> Online Responder for operational messages"
Write-Host ""
Write-Host "If you want, run this script on OCSP2 and then import the revocation configuration exported from OCSP1, or run the script on OCSP2 and then run the manual import steps above."

# End of script