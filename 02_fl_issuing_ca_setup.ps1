
# PKI Lab - Issuing CA Setup Script (fliss1 - Florida)
# Run on the Florida Issuing CA server

# 1. Create CAPolicy.inf
$capolicy = @"
[Version]
Signature="$Windows NT$"

[InternalPolicy]
URL=http://pki.pkilab.win.us/pkidata/cps.html

[Certsrv_Server]
LoadDefaultTemplates=0
"@
Set-Content -Path C:\Windows\CAPolicy.inf -Value $capolicy -Encoding ASCII

# 2. Install ADCS Role as Enterprise Subordinate CA
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# 3. Install Issuing CA
$issuingCAProps = @{
    CACommonName = 'PKILab Issuing CA - FL'
    CADistinguishedNameSuffix = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
    CAType = 'EnterpriseSubordinateCA'
    CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
    HashAlgorithmName = 'SHA256'
    KeyLength = 4096
    DatabaseDirectory = 'C:\pkidata'
    OutputCertRequestFile = 'C:\pkidata\pkilab_issuing_fl.req'
}
Install-AdcsCertificationAuthority @issuingCAProps -Force -OverwriteExistingKey

# 4. Manual Step: Submit the request file pkilab_issuing_fl.req to the Root CA for signing
Write-Host "Submit the request file C:\pkidata\pkilab_issuing_fl.req to the Root CA for signing."
Write-Host "After receiving the issued certificate, place it in C:\pkidata and run the next step."

# 5. Install the issued certificate and start the CA service
# Replace <issued_cert_path> with the actual path to the issued certificate
# Example: C:\pkidata\pkilab_issuing_fl.cer
#
# Install the certificate:
# certutil -installcert <issued_cert_path>
# Start the CA service:
# Start-Service certsvc

# 6. Configure CRL and AIA publishing
$crlList = Get-CACrlDistributionPoint
foreach ($crl in $crlList) { Remove-CACrlDistributionPoint $crl.Uri -Force }

Add-CACRLDistributionPoint -Uri '\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\pkilab.win.us\share\PKIData\%3%4.crt"

Get-CAAuthorityInformationAccess | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

# 7. Add OCSP URL via GUI
Write-Host "Add the OCSP URL 'ocsp:http://ocsp.pkilab.win.us/ocsp' via the CA Properties > Extensions tab > Authority Information Access (AIA) > Add..."

# 8. Publish Issuing CA certificate to AD
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*PKILab Issuing CA - FL*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA

# 9. Restart CA service and publish CRL
Restart-Service certsvc
certutil -crl

# 10. Verification
Write-Host "Verify the CA is running and CRLs are published correctly."
certutil -getreg CA\CRLPublicationURLs
certutil -getreg CA\CACertPublicationURLs
Get-CAAuthorityInformationAccess
