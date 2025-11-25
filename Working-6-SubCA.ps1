# 6. SUBCA1 – Lab Issuing CA 1 (do ALL of this first)
# 6.1 SubCA1 – Variables and Folder
# Run on SubCA1 as a domain admin:
# 
# powershell
# Copy
# Common PKI settings
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null
# 6.2 SubCA1 – CAPolicy.inf
# powershell
# Copy
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096  
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

# Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
# 6.3 SubCA1 – Install AD CS Role & Generate Request
# powershell
# Copy
# Install AD CS Certification Authority role
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configure as Enterprise Subordinate CA and output a request file
$vCaIssProperties = @{
  CACommonName              = $SubCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\Windows\System32\CertLog'
  LogDirectory              = 'C:\Windows\System32\CertLog'
  OutputCertRequestFile     = "$LocalPkiFolder\subca1_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force

# Open folder for manual copy
explorer.exe $LocalPkiFolder
# Manual step (SubCA1 → Root CA):

# Copy C:\PKIData\subca1_request.req from SubCA1 to the Root CA at
# C:\PKIData\subca1_request.req.
# 6.4 SubCA1 – Issue Subordinate Cert on Root CA
# Run on the Root CA:
# 
# powershell
# Copy
# Submit the request. If only one Root CA, you’ll get a prompt – choose your root.
certreq -submit C:\PKIData\subca1_request.req C:\PKIData\subca1_issued.cer
# If it goes pending:

# powershell
# Copy
# First SUbca request will be ID 2
certutil -resubmit 2
certreq -retrieve 2 C:\PKIData\subca1_issued.cer
# Manual step (Root CA → SubCA1):

# Copy C:\PKIData\subca1_issued.cer from Root CA back to SubCA1 at
C:\PKIData\subca1_issued.cer.
# 6.5 SubCA1 – Install Issued Cert and Start CA
# Run on SubCA1:
# 
# powershell
# Copy
# Install the issued SubCA certificate
certutil -installcert C:\PKIData\subca1_issued.cer

# Start CA service
Start-Service certsvc

# Basic health check
Get-Service certsvc
certutil -ping
# 6.6 SubCA1 – Configure Validity, CDP, and AIA
# Run on SubCA1:
# 
# powershell
# Copy
Import-Module ADCSAdministration

# ---- Validity & CRL settings ----

# 1-year issued certs
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod "Years"

# Weekly base CRL
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Weeks"

# Daily delta CRL
certutil -setreg CA\CRLDeltaPeriodUnits 1
certutil -setreg CA\CRLDeltaPeriod "Days"

# 3-day CRL overlap
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod "Days"

# Audit everything
certutil -setreg CA\AuditFilter 127

# ---- CDP (CRL Distribution Points) ----

$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# 1. Local CRL+delta location
Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

# 2. DFS share CRL+delta (for IIS)
Add-CACRLDistributionPoint `
    -Uri "$DfsPkiPath\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

# 3. HTTP CDP (embedded in certs)
Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8%9.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force

# ---- AIA (Authority Information Access) ----

# Clear existing HTTP/LDAP/file/UNC AIA entries
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

# Local + DFS publication of SubCA1 certificate
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt`n2:$DfsPkiPath\%3%4.crt"

# HTTP AIA (embedded)
Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Restart-Service certsvc
Start-Sleep -Seconds 2

# Publish initial CRL
certutil -CRL
# 6.7 SubCA1 – Publish Cert to AD and Copy to DFS
# Run on SubCA1:
# 
# powershell
# Copy
$SubCAName     = "Lab Issuing CA 1"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
$DfsPkiPath    = "\\lab.local\share\PKIData"
$PkiHttpBase   = "http://pki.lab.local/pkidata"

# 1. Rename the SubCA certificate to a clean name (if needed)
$cer = Get-ChildItem $CertEnrollDir -Filter "*.crt" | Select-Object -First 1
if ($cer -and $cer.Name -ne "$SubCAName.crt") {
    Rename-Item $cer.FullName "$CertEnrollDir\$SubCAName.crt" -Force
}

# 2. Publish into AD (NTAuth and SubCA containers)
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" NTAuthCA
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" SubCA

# 3. Copy SubCA1 cert to DFS for HTTP AIA
Copy-Item "$CertEnrollDir\$SubCAName.crt" "$DfsPkiPath\$SubCAName.crt" -Force

Write-Host "SubCA1 certificate published to AD and copied to DFS" -ForegroundColor Green

# 4. Quick HTTP verification
Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crt" -UseBasicParsing
Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crl" -UseBasicParsing
# 7. SUBCA2 – Lab Issuing CA 2 (repeat pattern)
# Now repeat the same procedure on SubCA2, changing only the CA name and the request file names.
# 
# 7.1 SubCA2 – Variables and Folder
# Run on SubCA2:
# 
# powershell
# Copy
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

$SubCAName = "Lab Issuing CA 2"

New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null
# 7.2 SubCA2 – CAPolicy.inf
# powershell
# Copy
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
# 7.3 SubCA2 – Install AD CS Role & Generate Request
# powershell
# Copy
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = $SubCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\Windows\System32\CertLog'
  LogDirectory              = 'C:\Windows\System32\CertLog'
  OutputCertRequestFile     = "$LocalPkiFolder\subca2_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force

explorer.exe $LocalPkiFolder
# Manual step (SubCA2 → Root CA):

# Copy C:\PKIData\subca2_request.req from SubCA2 to the Root CA at
C:\PKIData\subca2_request.req.
# 7.4 SubCA2 – Issue Subordinate Cert on Root CA
# Run on the Root CA:
# 
# powershell
# Copy
certreq -submit C:\PKIData\subca2_request.req C:\PKIData\subca2_issued.cer
# If pending:
# 
# powershell
# Copy
# if this is the second subca request the ID will be 3
certutil -resubmit 3
certreq -retrieve 3 C:\PKIData\subca2_issued.cer
# Manual step (Root CA → SubCA2):

# Copy C:\PKIData\subca2_issued.cer back to SubCA2 at C:\PKIData\subca2_issued.cer.
# 7.5 SubCA2 – Install Issued Cert and Start CA
# Run on SubCA2:
# 
# powershell
# Copy
certutil -installcert C:\PKIData\subca2_issued.cer
Start-Service certsvc
Get-Service certsvc
certutil -ping
# 7.6 SubCA2 – Configure Validity, CDP, and AIA
# Run on SubCA2 (same pattern as SubCA1):
# 
# powershell
# Copy
Import-Module ADCSAdministration

# ---- Validity & CRL ----
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod "Years"

certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Weeks"

certutil -setreg CA\CRLDeltaPeriodUnits 1
certutil -setreg CA\CRLDeltaPeriod "Days"

certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod "Days"

certutil -setreg CA\AuditFilter 127

# ---- CDP ----
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACRLDistributionPoint `
    -Uri "$DfsPkiPath\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8%9.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force

# ---- AIA ----
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt`n2:$DfsPkiPath\%3%4.crt"

Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -CRL
# 7.7 SubCA2 – Publish Cert to AD and Copy to DFS
# Run on SubCA2:
# 
# powershell
# Copy
$SubCAName     = "Lab Issuing CA 2"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
$DfsPkiPath    = "\\lab.local\share\PKIData"
$PkiHttpBase   = "http://pki.lab.local/pkidata"

$cer = Get-ChildItem $CertEnrollDir -Filter "*.crt" | Select-Object -First 1
if ($cer -and $cer.Name -ne "$SubCAName.crt") {
    Rename-Item $cer.FullName "$CertEnrollDir\$SubCAName.crt" -Force
}

certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" NTAuthCA
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" SubCA

Copy-Item "$CertEnrollDir\$SubCAName.crt" "$DfsPkiPath\$SubCAName.crt" -Force

Write-Host "SubCA2 certificate published to AD and copied to DFS" -ForegroundColor Green

Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crt" -UseBasicParsing
Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crl" -UseBasicParsing
# If you want, the next step after this is to define certificate templates + auto‑enrollment in the same “SubCA1 then SubCA2” style.
# 
