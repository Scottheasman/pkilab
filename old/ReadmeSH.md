## 1\. Environment

* AD Domain (FQDN): [lab.win.us]

* NetBIOS domain name: [LAB]

* AD DCs:

  * txdc1 10.30.1.201 (Texas)

  * txdc1 10.40.1.201 (Las Vegas)

* Root CA (offline): rootca 10.30.1.131

* Issuing CAs:

  * txsubca1 10.30.1.211 (Texas) — CA name: PKI Lab Issuing CA - TX

  * lvsubca1 10.40.1.211 (Las Vegas) — CA name: PKI Lab Issuing CA - LV

* Web servers (IIS for AIA/CDP HTTP):

  * txweb1 10.30.1.241 (Texas)

  * lvweb1 10.40.1.241 (Las Vegas)

* OCSP responders:

  * txocsp 10.30.1.221 (Texas)

  * lvocsp1 10.40.1.221 (Las Vegas)

* HTTP namespace (single, HA via DNS):  
    [http://pki.pkilab.win.us/]

* OCSP namespace (single, HA via DNS):  
    [http://ocsp.pkilab.win.us/ocsp]

* DFS path for pkidata:  
    [\\\lab.local\share\pkidata]

### ADCS variables in file paths:

  * %3 = CA Common Name
  
  * %4 = Certificate name suffix (renewal number)
  
  * %8 = CRL name suffix (CRL number + renewal)

Examples:

* %3%8.crl -> "PKI Lab Issuing CA - TX.crl" (with CRL numbering)

* %3%4.crt -> "PKI Lab Issuing CA - LV.crt" (with renewal suffix)

---

## 2\. DNS (no load balancer; DNS-based failover)

Purpose: Provide stable HTTP and OCSP namespaces with fast failover.

On a DNS server hosting [lab.win.us], create:

* A records:

  * [txweb1.pkilab.win.us] -> 10.30.1.241

  * [lvweb1.pkilab.win.us] -> 10.40.1.241

  * [txocsp.pkilab.win.us] -> 10.30.1.221

  * [flocsp1.pkilab.win.us]-> 10.40.1.221

  * [pki.lab.win.us] -> 10.30.1.241

  * [pki.lab.win.us] -> 10.40.1.241

  * [ocsp.lab.win.us] -> 10.30.1.221

  * [ocsp.lab.win.us] -> 10.40.1.221

* Set TTL to 60–120 seconds for [pki.pkilab.win.us]

* Set TTL to 60–120 seconds for [ocsp.pkilab.win.us]

A single HTTP namespace for CDP/AIA/OCSP: Keeps URLs embedded in certificates stable for the PKI lifetime.

## 3\. DFS
# Create the folder if it doesn't exist
```powershell
$folderPath = "C:\PKIData"
if (-Not (Test-Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
}
```

# Create the SMB share if it doesn't exist
```powershell
$shareName = "PKIData"
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

# Set Share Permissions
```powershell
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\txsubca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\lvsubca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\txweb1$" -AccessRight Read -Force
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\lvweb1$" -AccessRight Read -Force
```

# Set NTFS Permissions recursively with single quotes to handle $ in account names
```powershell
icacls $folderPath /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
icacls $folderPath /grant 'lab.local\txsubca1$:(OI)(CI)M' /T
icacls $folderPath /grant 'lab.local\lvsubca1$:(OI)(CI)M' /T
icacls $folderPath /grant 'lab.local\txweb1$:(OI)(CI)RX' /T
icacls $folderPath /grant 'lab.local\lvweb1$:(OI)(CI)RX' /T

Write-Host "Share and NTFS permissions set successfully on $env:COMPUTERNAME"
```

## 4\. IIS Installation and Configuration

On **txweb1** and **lvweb1** (run PowerShell as Administrator):

```powershell
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

---

### 4.1\. PKIWebSvc Account and Permissions Setup

Create and configure the `PKIWebSvc` service account to allow IIS to access the DFS share.

On a domain-joined admin machine, run:

```powershell
# Create PKIWebSvc account in Users container (adjust OU as needed)
$pwd = Read-Host -Prompt 'Enter password for PKIWebSvc' -AsSecureString
New-ADUser -Name 'PKIWebSvc' -SamAccountName 'PKIWebSvc' -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $false -Path 'CN=Users,DC=lab,DC=local' -PassThru

New-ADGroup -Name "PKI Web Servers" -GroupScope Global -GroupCategory Security -Path "OU=Groups,OU=Enterprise,DC=lab,DC=local"

# Add PKIWebSvc to PKI Web Servers group (create group if not existing)
Add-ADGroupMember -Identity 'PKI Web Servers' -Members 'PKIWebSvc'

# Grant NTFS and Share permissions on DFS targets (run on each file server hosting DFS targets)
Grant-SmbShareAccess -Name 'PKIData' -AccountName 'LAB\PKIWebSvc' -AccessRight Change -Force
icacls 'C:\PKIData' /grant "LAB\PKIWebSvc:(OI)(CI)M" /T
```

---

### 4.2\. Configure IIS Application Pool

On each IIS web server (txweb1, lvweb1), configure the IIS Application Pool to run as `PKIWebSvc`:

```powershell
Import-Module WebAdministration
Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel -Value @{userName='LAB\PKIWebSvc';password='<password>'}
Restart-WebAppPool DefaultAppPool
```

Replace `<password>` with the actual password set for `PKIWebSvc`.

---

### 4.3\. Create IIS Virtual Directory to DFS Path

```powershell
$vDirProperties = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\lab.local\share\PKIData' }
New-WebVirtualDirectory @vDirProperties
```

---

### 4.4\. Enable Directory Browsing and Allow Double-Escaping

```powershell
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value true -PSPath "IIS:\Sites\$($vDirProperties.Site)\$($vDirProperties.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value true -PSPath "IIS:\Sites\$($vDirProperties.Site)"
```

---

## 4.5\. Add MIME Types for CRL/CRT and Set Basic Caching Headers

```powershell
# Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
# Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
# Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}

# Optional: set cache-control for pkidata
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$($vDirProperties.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}
```

---

# 5. Offline Root CA 	6 pkirootca (Kept Offline)

**Purpose:** Establish the trust anchor. Configure AIA/CDP so clients know where to fetch the root CA cert and CRL. Manually transfer files to DFS and publish to AD.

### 5.1 Create CAPolicy.inf

```powershell
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'RenewalKeyLength=4096'
Add-Content C:\Windows\CAPolicy.inf 'RenewalValidityPeriod=Years'
Add-Content C:\Windows\CAPolicy.inf 'RenewalValidityPeriodUnits=20'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'
Add-Content C:\Windows\CAPolicy.inf 'AlternateSignatureAlgorithm=0'
```

### 5.2 Install AD CS Role and Root CA

```powershell
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaRootProperties = @{
  CACommonName    = 'Lab Root CA'
  CADistinguishedNameSuffix   = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType    = 'StandaloneRootCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  ValidityPeriod    = 'Years'
  ValidityPeriodUnits    = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force -OverwriteExistingKey
```

### 5.3 Configure Validity and CRL Settings

```powershell
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod Years
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod Days
certutil -setreg CA\AuditFilter 127
```

### 5.4 Configure CDP and AIA

```powershell
# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# Add CDP publish locations (UNC and local)
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# Add HTTP CDP embedded in issued certs
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# Clear existing AIA entries
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force

# Set AIA publish locations (local and UNC)
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt'


# Add HTTP AIA embedded in issued certs
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.local/pkidata/%3%4.crt' -Force
```

### 5.5 Publish Initial CRL and Restart Service

```powershell
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -CRL


Rename-Item "C:\windows\system32\Certsrv\Certenroll\labrootca_Lab Root CA.crt" "Lab Root CA.crt" 
explorer.exe "C:\windows\system32\Certsrv\Certenroll" 
```

copy 
Lab Root CA.crt
Lab Root CA.crl
to
\\lab.local\share\pkidata

From the Web Server run:
```powershell
certutil -dspublish -f "\\lab.local\share\PkiData\Lab Root CA.crt" rootca
certutil -dspublish -f "\\lab.local\share\pkiData\Lab Root CA.crl" "PKILab Root CA"

# Verify enterprise root store
certutil -viewstore -enterprise Root
```

# 6\. Issuing CAs txsubca1 (Texas) and lvsubca1 (Vegas)

**Purpose:** Two enterprise issuing CAs for HA. Each publishes CRLs locally; issued certs embed a single HTTP CDP/AIA URL pointing to [pki.lab.win.us].

---

## 6.1 Install Issuing CA on txsubca1

```powershell
# CAPolicy.inf (prevents default templates auto-load)
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'

# Role and request
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName    = 'Lab Issuing CA - TX'
  CADistinguishedNameSuffix = 'O=PKI,L=Dallas,S=Texas,C=US'
  CAType    = 'EnterpriseSubordinateCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  DatabaseDirectory    = 'C:\pkidata'
  OutputCertRequestFile    = 'C:\pkidata\lab issuing tx.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

---

## 6.2 Enroll/Issue SubCA Cert from the Root CA

- Copy `C:\pkidata\lab issuing tx.req` to c:\pkidata on labrootca (power on temporarily).

- On labrootca, submit, approve, and download the issuing CA certificate:

```powershell
# Submit the request
certreq -submit C:\pkidata\pkilab issuing tx.req C:\pkidata\lab issuing tx.cer

# Approve the request (requires CA admin privileges)
certutil -getrequests
certutil -approve <RequestID> ( probabl y '2')

# Download the issued certificate
certutil -retrieve <RequestID> C:\pkidata\lab issuing tx.cer
```

- On txsubca1, open Certification Authority console, right-click the stopped CA, choose **Install new key/certificate**, and select the issued `.cer`.

- Start the Certification Authority service.

---

## 6.3 Configure Validity, CDP, AIA, and OCSP on txsubca1

```powershell
# Validity and CRL schedule
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 52
certutil -setreg CA\CRLPeriod Weeks
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod Days
certutil -setreg CA\AuditFilter 127

# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# CDP publish locations (UNC and local)
Add-CACRLDistributionPoint -Uri '\\lab.local\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# CDP embedded in issued certs (HTTP only)
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA publish locations (UNC and local)
certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\\lab.local\share\PKIData\%3%4.crt"

# AIA embedded in issued certs (HTTP only)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.lab.local/pkidata/%3%4.crt' -Force

# OCSP URL (embedded) 	6 use Certification Authority GUI (no registry edits)
# certsrv.msc -> [CA] -> Properties -> Extensions tab
#   - Select: Authority Information Access (AIA)
#   - Click Add... -> Location: ocsp:http://ocsp.pkilab.win.us/ocsp
#   - Check: Include in the AIA extension of issued certificates
#   - Ensure the HTTP AIA entry is also checked
# Apply, then restart service and publish a CRL.
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

---

## 6.4 Publish Issuing CA - TX to AD

From txweb or any domain-joined admin machine:

```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*Lab Issuing CA - tx*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

---

## 6.5 Ensure Required Files for PKIView Are Copied to DFS pkidata Folder

- `C:\Windows\System32\CertSrv\CertEnroll\Lab Issuing CA - TX.crl`
- `C:\Windows\System32\CertSrv\CertEnroll\Lab Issuing CA - TX+.crl`
- `C:\pkidata\lab issuing tx.req.crt`

---

## 6.6 Repeat Steps lvsubca1

## 6.7 Install Issuing CA on lvsubca1

```powershell
# CAPolicy.inf (prevents default templates auto-load)
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'

# Role and request
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName    = 'Lab Issuing CA - LV'
  CADistinguishedNameSuffix = 'O=PKI,L=Vegas,S=Nevada,C=US'
  CAType    = 'EnterpriseSubordinateCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  DatabaseDirectory    = 'C:\pkidata'
  OutputCertRequestFile    = 'C:\pkidata\lab issuing lv.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

---

## 6.8 Enroll/Issue SubCA Cert from the Root CA

- Copy `C:\pkidata\lab issuing lv.req` to c:\pkidata on labrootca (power on temporarily).

- On labrootca, submit, approve, and download the issuing CA certificate:

```powershell
# Submit the request
certreq -submit C:\pkidata\pkilab issuing lv.req C:\pkidata\lab issuing lv.cer

# Approve the request (requires CA admin privileges)
certutil -getrequests
certutil -approve <RequestID> ( probabl y '3')

# Download the issued certificate
certutil -retrieve <RequestID> C:\pkidata\lab issuing lv.cer
```

- On txsubca1, open Certification Authority console, right-click the stopped CA, choose **Install new key/certificate**, and select the issued `.cer`.

- Start the Certification Authority service.

---

## 6.9 Configure Validity, CDP, AIA, and OCSP on lvsubca1

```powershell
# Validity and CRL schedule
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 52
certutil -setreg CA\CRLPeriod Weeks
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod Days
certutil -setreg CA\AuditFilter 127

# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# CDP publish locations (UNC and local)
Add-CACRLDistributionPoint -Uri '\\lab.local\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# CDP embedded in issued certs (HTTP only)
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA publish locations (UNC and local)
certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\\lab.local\share\PKIData\%3%4.crt"

# AIA embedded in issued certs (HTTP only)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.lab.local/pkidata/%3%4.crt' -Force

# OCSP URL (embedded) use Certification Authority GUI 
# certsrv.msc -> [CA] -> Properties -> Extensions tab
#   - Select: Authority Information Access (AIA)
#   - Click Add... -> Location: ocsp:http://ocsp.pkilab.win.us/ocsp
#   - Check: Include in the AIA extension of issued certificates
#   - Ensure the HTTP AIA entry is also checked
# Apply, then restart service and publish a CRL.
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

---

## 6.10 Publish Issuing CA - LV to AD

From txweb or any domain-joined admin machine:

```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*Lab Issuing CA - lv*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

---

## 6.11 Ensure Required Files for PKIView Are Copied to DFS pkidata Folder

- `C:\Windows\System32\CertSrv\CertEnroll\Lab Issuing CA - LV.crl`
- `C:\Windows\System32\CertSrv\CertEnroll\Lab Issuing CA - LV+.crl`
- `C:\pkidata\lab issuing tx.req.crt`

---