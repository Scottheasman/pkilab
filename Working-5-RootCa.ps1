# 5. Offline Root CA Setup – Final Version (Updated)
# Root CA host: $RootCA (e.g. CARoot1.lab.local)
# Root CA common name: $RootCAName (e.g. Lab Root CA)

# Run everything in this section on the Root CA (elevated PowerShell).

# 5.1 Define Variables (Root CA)
# powershell
# Copy
# Adjust these if you use different names
$DomainFqdn    = "lab.local"
$PkiHttpHost   = "pki.lab.local"
$RootCAName    = "Lab Root CA"

# Derived
$PkiHttpBase   = "http://$PkiHttpHost/pkidata"
$DfsPkiPath    = "\\lab.local\share\PKIData"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
# 5.2 Create CAPolicy.inf
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
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

# Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
# 5.3 Install AD CS Role and Configure Root CA
# powershell
# Copy
# Install AD CS Certification Authority role
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configure Root CA
$vCaRootProperties = @{
  CACommonName              = $RootCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'StandaloneRootCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  ValidityPeriod            = 'Years'
  ValidityPeriodUnits       = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force
# 5.4 Configure Validity and CRL Settings
# powershell
# Copy
# Issued cert validity (for subCAs etc.)
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod "Years"

# Base CRL
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Years"

# No delta CRL for offline root
certutil -setreg CA\CRLDeltaPeriodUnits 0

# CRL overlap
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod "Days"

# Audit everything
certutil -setreg CA\AuditFilter 127

Restart-Service certsvc
# 5.5 Configure CDP and AIA
# powershell
# Copy
Import-Module ADCSAdministration

# -------- CDP (CRL Distribution Points) --------

# Clear existing CDP entries
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# 1. Local CRL location where CA writes the CRL
Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

# 2. HTTP CDP that will be embedded in issued certs
Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force

# -------- AIA (Authority Information Access) --------

# Remove existing AIA entries (HTTP/LDAP/file/UNC)
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

# 1. Local publication path for the CA certificate (where CA saves its own cert)
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt"

# 2. HTTP AIA that clients will use to download the issuer (root) cert
Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Restart-Service certsvc
# 5.6 Publish Initial CRL and Prepare for Manual Copy
# powershell
# Copy
# Publish a fresh CRL
certutil -CRL
Start-Sleep -Seconds 2

# Rename the root CA certificate to a clean name
# (CRL is already named correctly by the CA)
Rename-Item "$CertEnrollDir\caroot1_$RootCAName.crt" "$CertEnrollDir\$RootCAName.crt" -Force

# Open the folder for manual copy
explorer.exe $CertEnrollDir
# Manual step (offline-root-friendly):

# In C:\Windows\System32\CertSrv\CertEnroll, you should now see:
# Lab Root CA.crt
# Lab Root CA.crl
# Copy these two files (USB / clipboard / etc.) to a domain-joined machine.
# Place them in the DFS/IIS location:
# \\lab.local\share\PKIData\
# Once copied, IIS + DFS make them available at:
# 
# http://pki.lab.local/pkidata/Lab Root CA.crt
# http://pki.lab.local/pkidata/Lab Root CA.crl
# 5.7 Verify CDP/AIA Configuration (Root CA)
# Run on the Root CA before taking it offline:
# 
# powershell
# Copy
# Check CA cert publication path
certutil -getreg CA\CACertPublicationURLs

# Check CDP configuration
Import-Module ADCSAdministration
Get-CACrlDistributionPoint | Format-Table Uri, PublishToServer, AddToCertificateCDP, AddToFreshestCrl -AutoSize

# Check AIA configuration
Get-CAAuthorityInformationAccess | Format-Table Uri, AddToCertificateAia, AddToCertificateOcsp -AutoSize
# You should see:
# 
# CDP:
# C:\Windows\System32\CertSrv\CertEnroll\<CAName><CRLNameSuffix>.crl with PublishToServer = True
# http://pki.lab.local/pkidata/<CAName><CRLNameSuffix>.crl with AddToCertificateCDP = True, AddToFreshestCrl = True
# AIA:
# http://pki.lab.local/pkidata/<CAName><CertificateName>.crt with AddToCertificateAia = True
# 5.8 Verify HTTP Access (From Any Domain Client)
# After manually copying the files to \\lab.local\share\PKIData\, verify from any domain-joined machine:
# 
# powershell
# Copy
$PkiHttpBase = "http://pki.lab.local/pkidata"
$RootCAName  = "Lab Root CA"

# Test HTTP access to Root CA cert
Invoke-WebRequest -Uri "$PkiHttpBase/$RootCAName.crt" -UseBasicParsing

# Test HTTP access to Root CRL
Invoke-WebRequest -Uri "$PkiHttpBase/$RootCAName.crl" -UseBasicParsing
# Both should return StatusCode 200.
# 
# You can also simply browse to:
# 
# http://pki.lab.local/pkidata/
# and confirm the two files are visible.
# 
# 5.9 (Optional) Take Root CA Offline
# Once the above is verified:
# 
# Shut down or disconnect the Root CA from the network.
# Store the Root CA securely (powered off or isolated).
# Clients and subordinate CAs will rely on the published HTTP locations, not direct access to the Root CA.

# 5.10 Publish Root CA Certificate and CRL to Active Directory
# After you've copied the Root CA cert and CRL to \\lab.local\share\PKIData\ and verified HTTP access, publish them to AD so domain clients and subordinate CAs can trust the root.

# Run on any domain-joined machine with access to the DFS share (e.g., a DC, SubCA1, or WEB01):

# powershell
# Copy
$DfsPkiPath = "\\lab.local\share\PKIData"
$RootCAName = "Lab Root CA"

# Publish Root CA certificate to AD (Trusted Root and NTAuth stores)
certutil -dspublish -f "$DfsPkiPath\$RootCAName.crt" RootCA

# Publish Root CRL to AD
certutil -addstore -f root "$DfsPkiPath\$RootCAName.crt"
# This ensures:

# Domain clients automatically trust certificates issued by your PKI.
# Subordinate CAs can validate their chain to the root.

# Open the cert store on the server you ran dspublish from and you will see the root cert in
# "trusted Root Certification Authorities"\Certificates
# "Intermediate Certification Authorities"\Certificates

# On other servers run Gpupdate /Force to pick up the new published cert

