
# PKI Lab - Offline Root CA Setup Script (pkirootca)
# Run on the offline Root CA server

# 1. Create CAPolicy.inf
$capolicy = @"
[Version]
Signature="$Windows NT$"

[InternalPolicy]
URL=http://pki.pkilab.win.us/pkidata/cps.html

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@
Set-Content -Path C:\Windows\CAPolicy.inf -Value $capolicy -Encoding ASCII

# 2. Install ADCS Role as Standalone Root CA
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# 3. Install Root CA
$rootCAProps = @{
    CACommonName = 'PKILab Root CA'
    CADistinguishedNameSuffix = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
    CAType = 'StandaloneRootCA'
    CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
    HashAlgorithmName = 'SHA256'
    KeyLength = 4096
    ValidityPeriod = 'Years'
    ValidityPeriodUnits = 20
}
Install-AdcsCertificationAuthority @rootCAProps -Force -OverwriteExistingKey

# 4. Configure CRL and AIA publishing
$crlList = Get-CACrlDistributionPoint
foreach ($crl in $crlList) { Remove-CACrlDistributionPoint $crl.Uri -Force }

Add-CACRLDistributionPoint -Uri '\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\pkilab.win.us\share\PKIData\%3%4.crt"

Get-CAAuthorityInformationAccess | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

Restart-Service certsvc
certutil -crl

# 5. Export Root CA cert and CRL for manual transfer
$certPath = "C:\Windows\System32\CertSrv\CertEnroll\PKILab Root CA.crt"
$crlPath = "C:\Windows\System32\CertSrv\CertEnroll\PKILab Root CA.crl"

Write-Host "Root CA certificate located at: $certPath"
Write-Host "Root CA CRL located at: $crlPath"

# Manual Step: Copy these files to removable media and transfer to domain-joined machine for DFS publishing and AD publishing

# 6. Generate Issuing CA certificate requests
# For Florida Issuing CA
$flReqPath = "C:\pkidata\pkilab_issuing_fl.req"
# For New York Issuing CA
$nyReqPath = "C:\pkidata\pkilab_issuing_ny.req"

Write-Host "Generate certificate requests for Issuing CAs and save to $flReqPath and $nyReqPath"

# Note: The actual request generation is done on the Issuing CA servers, but the Root CA will sign these requests manually.
