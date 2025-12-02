# Duplicate the OCSP template (do this on the issuing CA)
# 
# Open Certification Authority console on the issuing CA (SubCA1 / SubCA2).
# Right‑click "Certificate Templates" → "Manage" (this opens the Certificate Templates MMC).
# Find the built‑in template named "OCSP Response Signing" (or "OCSPSigning" depending on OS).
# Right‑click it → Duplicate Template.
# On the Compatibility tab, set compatibility to at least Windows Server 2012 R2 (or match your environment).
# On the General tab, give a unique name, e.g.: "OCSP-Responder-Signing".
# On the Request Handling tab:
# Ensure "Allow private key to be exported" is set only if you explicitly need it (normally keep it off).
# Private Key Protection: disable UI prompts for unattended service use.
# On the Extensions tab:
# Verify Enhanced Key Usage includes "OCSP Signing" (1.3.6.1.5.5.7.3.9).
# On the Security tab:
# Add the computer accounts for your OCSP servers (e.g., OCSP1,OCSP2) and grant them Enroll and Read.
# If you will run the Online Responder service as a managed service account (gMSA), add that account (e.g., LAB\OCSPSvc$) with Enroll & Read.
# Click OK to create the new template.
# On the CA console, right‑click Certificate Templates → New → Certificate Template to Issue → select "OCSP-Responder-Signing" (or whatever you named it) → OK.
# Notes:
# 
# If you plan to use a gMSA for Online Responder service, give the gMSA Enroll/Read in the template security.
# If you will use the machine account, add the computer account (e.g., OCSP1,OCSP2).
# B. ENROLL OCSP SIGNING CERTIFICATE (recommended - use Certificates MMC for Computer Account)
# Method 1 — GUI (recommended for clarity)
# 
# Log on to each OCSP server (OCSP1 / OCSP2) as local admin.
# Start → mmc → File → Add/Remove Snap-in → Certificates → Add → Choose "Computer account" → Local computer → OK.
# Certificates (Local Computer) → Personal → Right‑click → All Tasks → Request New Certificate.
# Proceed to Enrollment → Select your AD CS Enrollment Policy and choose the template "OCSP-Responder-Signing".
# Complete enrollment. Confirm the certificate appears under Personal with EKU including OCSPSigning.
###
# Method 2 — certreq (scripted)
# 
# Use this when template is published and CA is reachable. Create an INF (example below) and use certreq to submit.
# Create a file named OCSP-request.inf:

[NewRequest]
Subject = "CN=ocsp1.lab.local"
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

# Submit the request (example — change CA config string to your CA):
# From OCSP1 machine (elevated):
certreq -new .\OCSP-request.inf .\OCSP1.req
certreq -submit -attrib "CertificateTemplate:OCSP-Responder-Signing" -config "SubCA1.lab.local\Lab Issuing CA 1" .\OCSP1.req .\OCSP1.cer
certreq -accept .\OCSP1.cer

# Notes:
# 
# If your template is set for Machine/Computer enrollment, you can request from the Computer account (Certificates MMC method will do that automatically).
# For gMSA enrollment, you might need to run enrollment under the gMSA context or enroll via the CA with an admin temporarily granting enrollment rights; GUI is simpler.


###
# C. Install Online Responder role and basic service setup (copy/paste into Working-OCSP-Install.ps1)
# Save as Working-OCSP-Install.ps1 and run elevated on each OCSP server (OCSP1, OCSP2):
# Working-OCSP-Install.ps1
# Run elevated on each OCSP server (OCSP1, OCSP2)

# CONFIG - adjust as needed
$OCSPHost = "ocsp.lab.local"       # OCSP service namespace you will use
$OCSPCertSubjectCN = "ocsp1.lab.local"  # CN used on the OCSP signing cert for this server
$ServiceName = "Online Responder"

# 1) Install Online Responder role
Install-WindowsFeature RSAT-Online-Responder, Online-Responder -IncludeManagementTools

# 2) Ensure the Online Responder service is set to Automatic and start it
Set-Service -Name ocsp -StartupType Automatic
Start-Service -Name ocsp

# 3) Validate OCSP signing certificate exists in LocalMachine\My
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    ($_).Subject -match "CN=$OCSPCertSubjectCN" -and
    ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -match "OCSP" -or $_.Oid.Value -eq "1.3.6.1.5.5.7.3.9" })
} | Select-Object -First 1

if (-not $cert) {
    Write-Warning "OCSP signing certificate CN=$OCSPCertSubjectCN not found in LocalMachine\My. Enroll the OCSP certificate using the 'OCSP-Responder-Signing' template and re-run this script."
    exit 1
} else {
    Write-Host "Found OCSP signing certificate: $($cert.Thumbprint)"
}

# 4) (Optional) Restart Online Responder to pick up certs
Restart-Service -Name ocsp -Force
Write-Host "Online Responder installed and started. Next: configure Revocation Configuration in Online Responder MMC (see runbook)."
