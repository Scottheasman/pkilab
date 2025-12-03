## 6 - Install SubCA1 (Lab Issuing CA 1)

### RUN THIS ENTIRE SCRIPT ON SUBCA1 SERVER (elevated PowerShell)
### This script configures SubCA1 and generates the certificate request.
### Manual steps are required afterward to process the request on Root CA.

### 1 - Common PKI Settings
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$OcspHttpBase   = "http://ocsp.lab.local/ocsp"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

Write-Host "Creating local PKI folder..." -ForegroundColor Cyan
New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null

### 2 - Create CAPolicy.inf
Write-Host "Creating CAPolicy.inf..." -ForegroundColor Cyan
$caPolicyContent = @"
[Version]
Signature=`$Windows NT`$

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
Write-Host "CAPolicy.inf created successfully." -ForegroundColor Green

### 3 - Install AD CS Role & Generate Request
Write-Host "Installing ADCS-Cert-Authority feature..." -ForegroundColor Cyan
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

Write-Host "Configuring Enterprise Subordinate CA and generating request..." -ForegroundColor Cyan
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
Write-Host "SubCA1 role installed and request generated." -ForegroundColor Green

### 4 - Manual Steps for Offline Root CA Processing
Write-Host "`n`n=====================================================================================================" -ForegroundColor Red
Write-Host "                             *** MANUAL STEPS REQUIRED ***" -ForegroundColor Red
Write-Host "=====================================================================================================" -ForegroundColor Red
Write-Host "SubCA1 certificate request has been generated. The following manual steps are CRITICAL:" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "1. MANUALLY COPY REQUEST FILE FROM SUBCA1:" -ForegroundColor Cyan
Write-Host "   Location: C:\PKIData\subca1_request.req" -ForegroundColor Gray
Write-Host "   Action: Copy this file to a removable media (e.g., USB drive)." -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "2. PROCESS REQUEST ON OFFLINE ROOT CA:" -ForegroundColor Cyan
Write-Host "   Action: Take the media to the Offline Root CA server." -ForegroundColor Gray
Write-Host "   Location on Root CA: C:\PKIData\" -ForegroundColor Gray
Write-Host "   Action: Place the subca1_request.req file in the above folder." -ForegroundColor Gray
Write-Host "   Commands to run on Root CA:" -ForegroundColor Gray
Write-Host "   ---------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "   certreq -submit C:\PKIData\subca1_request.req C:\PKIData\subca1_issued.cer" -ForegroundColor Gray
Write-Host "   # If it goes pending:" -ForegroundColor Gray
Write-Host "   certutil -resubmit <REQUEST_ID>" -ForegroundColor Gray
Write-Host "   certreq -retrieve <REQUEST_ID> C:\PKIData\subca1_issued.cer" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "3. MANUALLY COPY ISSUED CERTIFICATE BACK TO SUBCA1:" -ForegroundColor Cyan
Write-Host "   Action: Copy C:\PKIData\subca1_issued.cer from Root CA to SubCA1 at:" -ForegroundColor Gray
Write-Host "   Location: C:\PKIData\subca1_issued.cer" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "4. COMPLETE SUBCA1 CONFIGURATION:" -ForegroundColor Cyan
Write-Host "   Action: After copying the issued certificate back, run PART 2 of this script on SubCA1." -ForegroundColor Gray
Write-Host "   File: Working-v2-6-SubCa1-Install-Part2.ps1" -ForegroundColor Gray
Write-Host "=====================================================================================================" -ForegroundColor Red
Write-Host "DO NOT PROCEED WITH PART 2 UNTIL THE ISSUED CERTIFICATE IS COPIED BACK!" -ForegroundColor Red
Write-Host "=====================================================================================================" -ForegroundColor Red

# Open folder for easy access to request file
explorer.exe $LocalPkiFolder