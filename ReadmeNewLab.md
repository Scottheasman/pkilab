### 🧱 PKI Infrastructure Deployment Guide – LAB Version

Modern, domain-integrated Public Key Infrastructure (PKI) for **lab.local** — featuring an **Offline Root CA**, two **Enterprise Issuing CAs (Site1 & Site2)**, redundant **HTTP/OCSP namespaces**, and full PowerShell-based automation, adapted to your lab hostnames.

---

## 1. Overview & Environment (LAB Version)

| Component               | Function                  | Hostname             | IP           | Location |
|-------------------------|---------------------------|----------------------|-------------|----------|
| Domain Controller       | AD DS                     | **dc1.lab.local**    | 10.10.1.101 | Site 1   |
| Domain Controller       | AD DS                     | **dc2.lab.local**    | 10.20.1.101 | Site 2   |
| File Server             | PKIData storage / DFS     | **file1.lab.local**  | 10.10.1.111 | Site 1   |
| File Server             | PKIData storage / DFS     | **file2.lab.local**  | 10.20.1.111 | Site 2   |
| Root CA                 | Offline standalone        | **caroot1.lab.local**| 10.10.1.151 | Vault    |
| Issuing CA (Site 1)     | Enterprise subordinate CA | **subca1.lab.local** | 10.10.1.121 | Site 1   |
| Issuing CA (Site 2)     | Enterprise subordinate CA | **subca2.lab.local** | 10.20.1.121 | Site 2   |
| Web Server (Site 1)     | IIS AIA/CDP HTTP          | **web01.lab.local**  | 10.10.1.131 | Site 1   |
| Web Server (Site 2)     | IIS AIA/CDP HTTP          | **web02.lab.local**  | 10.20.1.131 | Site 2   |
| OCSP Responder (Site 1) | Revocation (OCSP)         | **ocsp1.lab.local**  | 10.10.1.141 | Site 1   |
| OCSP Responder (Site 2) | Revocation (OCSP)         | **ocsp2.lab.local**  | 10.20.1.141 | Site 2   |

**Primary Namespaces**

- HTTP (AIA/CDP): `http://pki.lab.local/pkidata/`  
- OCSP: `http://ocsp.lab.local/ocsp`

**DFS Share (for PKI Data):** `\\lab.local\\share\\PKIData`  
**NetBIOS name:** `LAB`

---

## 3. DFS and File Permissions (LAB Version)

We host `C:\\PKIData` on **file1** and **file2** and expose it via DFS as `\\lab.local\\share\\PKIData`.

### 3.1 Create Folder and Share (File1 and File2)

On **file1**:

```powershell
$folderPath = "C:\\PKIData"
if (-Not (Test-Path $folderPath)) { New-Item -Path $folderPath -ItemType Directory }

$shareName = "PKIData"
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

Repeat the **same** on **file2**.

### 3.2 Grant Machine Permissions for PKI Roles

These machine accounts will publish/read PKI data:

- SubCAs: `subca1`, `subca2`
- Web: `web01`, `web02`
- OCSP: `ocsp1`, `ocsp2`

On **file1**:

```powershell
# Share Access
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\subca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\subca2$" -AccessRight Change -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\web01$"  -AccessRight Read   -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\web02$"  -AccessRight Read   -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\ocsp1$"  -AccessRight Read   -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\ocsp2$"  -AccessRight Read   -Force

# NTFS Permissions
icacls "C:\\PKIData" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
icacls "C:\\PKIData" /grant 'LAB\subca1$:(OI)(CI)M' /T
icacls "C:\\PKIData" /grant 'LAB\subca2$:(OI)(CI)M' /T
icacls "C:\\PKIData" /grant 'LAB\web01$:(OI)(CI)RX' /T
icacls "C:\\PKIData" /grant 'LAB\web02$:(OI)(CI)RX' /T
icacls "C:\\PKIData" /grant 'LAB\ocsp1$:(OI)(CI)RX' /T
icacls "C:\\PKIData" /grant 'LAB\ocsp2$:(OI)(CI)RX' /T
```

Repeat **exactly** the same on **file2**.

---

## 4. Web Server (IIS) Configuration (LAB Version)

Web servers: **web01.lab.local**, **web02.lab.local**  
PKI data via DFS: `\\lab.local\\share\\PKIData`  
Service account: `LAB\\PKIWebSvc`

### 4.1 Install IIS (web01 and web02)

On **web01** and **web02**:

```powershell
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

### 4.2 Create Service Account and Permissions

#### 4.2.1 Create service account & group (DC1 or DC2)

```powershell
$pwd = Read-Host -Prompt 'Enter password for PKIWebSvc' -AsSecureString

New-ADUser -Name 'PKIWebSvc' `
           -SamAccountName 'PKIWebSvc' `
           -AccountPassword $pwd `
           -Enabled $true `
           -PasswordNeverExpires $false

New-ADGroup -Name 'PKI Web Servers' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'PKI Web Servers' -Members 'PKIWebSvc'
```

#### 4.2.2 Grant PKIWebSvc access to PKIData (File1 and File2)

On **file1**:

```powershell
Grant-SmbShareAccess -Name 'PKIData' -AccountName 'LAB\PKIWebSvc' -AccessRight Change -Force
icacls 'C:\\PKIData' /grant 'LAB\PKIWebSvc:(OI)(CI)M' /T
```

Repeat on **file2**.

### 4.3 Configure IIS Application Pool Identity (web01 & web02)

Set **DefaultAppPool** to run as `LAB\\PKIWebSvc`.

On **web01**:

```powershell
Import-Module WebAdministration

Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.userName -Value "LAB\PKIWebSvc"
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.password -Value "<PKIWebSvc_password_here>"

Restart-WebAppPool DefaultAppPool
```

Repeat on **web02**.

### 4.4 Create Virtual Directory for PKI Data (web01 & web02)

On **web01**:

```powershell
Import-Module WebAdministration

Remove-WebVirtualDirectory -Site 'Default Web Site' -Name 'pkidata' -ErrorAction SilentlyContinue

$vDirProperties = @{
    Site         = 'Default Web Site'
    Name         = 'pkidata'
    PhysicalPath = '\\lab.local\\share\\PKIData'
}
New-WebVirtualDirectory @vDirProperties
```

Repeat on **web02**.

### 4.5 Enable Directory Browsing and MIME Types (web01 & web02)

On **web01**:

```powershell
Import-Module WebAdministration

# Enable directory browsing on /pkidata
Set-WebConfigurationProperty `
    -Filter /system.webServer/directoryBrowse `
    -Name enabled `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Allow double escaping
Set-WebConfigurationProperty `
    -Filter /system.webServer/security/requestFiltering `
    -Name allowDoubleEscaping `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site"

# MIME type for CRL
Add-WebConfigurationProperty -pspath 'IIS:' `
    -filter "system.webServer/staticContent" `
    -name "." `
    -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}

# MIME type for CRT
Add-WebConfigurationProperty -pspath 'IIS:' `
    -filter "system.webServer/staticContent" `
    -name "." `
    -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
```

Repeat on **web02**.

---

## 5. Offline Root CA Setup (LAB Version)

Root CA host: **caroot1.lab.local**  
CA Common Name: **Lab Root CA**

### 5.1 Create CAPolicy.inf (caroot1)

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

### 5.2 Install AD CS Role and Root CA (caroot1)

```powershell
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaRootProperties = @{
  CACommonName              = 'Lab Root CA'
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'StandaloneRootCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  ValidityPeriod            = 'Years'
  ValidityPeriodUnits       = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force -OverwriteExistingKey
```

### 5.3 Configure Validity and CRL Settings (caroot1)

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

### 5.4 Configure CDP and AIA (caroot1)

```powershell
# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# Local CRL publish
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# HTTP CDP embedded in issued certs
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# Clear existing AIA entries
Get-CAAuthorityInformationAccess |
    Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } |
    Remove-CAAuthorityInformationAccess -Force

# Local AIA
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt'

# HTTP AIA embedded in issued certs
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.local/pkidata/%3%4.crt' -Force
```

### 5.5 Publish Initial CRL and Copy to PKIData

```powershell
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -CRL

Rename-Item "C:\Windows\System32\CertSrv\CertEnroll\CARoot1_Lab Root CA.crt" "Lab Root CA.crt"
explorer.exe "C:\Windows\System32\CertSrv\CertEnroll"
```

Copy these from **caroot1** to `\\lab.local\share\PKIData`:

- `Lab Root CA.crt`
- `Lab Root CA.crl`

Then publish to AD:

```powershell
certutil -dspublish -f "\\lab.local\share\PKIData\Lab Root CA.crt" RootCA
certutil -dspublish -f "\\lab.local\share\PKIData\Lab Root CA.crl" "Lab Root CA"
```

---

## 6. Issuing CAs – subca1 & subca2 (LAB Version)

Issuing CAs:

- `subca1.lab.local` → **Lab Issuing CA - Site1**
- `subca2.lab.local` → **Lab Issuing CA - Site2**

### 6.0.1 Install Issuing CA on subca1

On **subca1**:

```powershell
# CAPolicy.inf
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C\Windows\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = 'Lab Issuing CA - Site1'
  CADistinguishedNameSuffix = 'O=PKI,L=Site1,S=State1,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\PKIData'
  OutputCertRequestFile     = 'C:\PKIData\lab_issuing_site1.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

### 6.0.2 Approve and Install SubCA1 Certificate (caroot1)

On **caroot1**:

```powershell
certreq -submit C:\PKIData\lab_issuing_site1.req C:\PKIData\lab_issuing_site1.cer
certutil -getrequests
certutil -approve <RequestID>
certutil -retrieve <RequestID> C:\PKIData\lab_issuing_site1.cer
```

Copy `lab_issuing_site1.cer` back to **subca1**, install via CA MMC (Install CA Certificate), then:

```powershell
Start-Service certsvc
```

### 6.0.3 Install Issuing CA on subca2

On **subca2**:

```powershell
# CAPolicy.inf
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = 'Lab Issuing CA - Site2'
  CADistinguishedNameSuffix = 'O=PKI,L=Site2,S=State2,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\PKIData'
  OutputCertRequestFile     = 'C:\PKIData\lab_issuing_site2.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

### 6.0.4 Approve and Install SubCA2 Certificate (caroot1)

On **caroot1**:

```powershell
certreq -submit C:\PKIData\lab_issuing_site2.req C:\PKIData\lab_issuing_site2.cer
certutil -getrequests
certutil -approve <RequestID>
certutil -retrieve <RequestID> C:\PKIData\lab_issuing_site2.cer
```

Copy `lab_issuing_site2.cer` to **subca2**, install via CA MMC, then:

```powershell
Start-Service certsvc
```

### 6.1 Core Issuing CA Configuration (Run on BOTH subca1 and subca2)

```powershell
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 52
certutil -setreg CA\CRLPeriod Weeks
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod Days

Get-CACrlDistributionPoint | ForEach-Object { Remove-CACrlDistributionPoint $_.Uri -Force }
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -match '^(ldap|file)' } | Remove-CAAuthorityInformationAccess -Force

Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri '\\lab.local\\share\\PKIData\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -Force

certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt\n2:\\lab.local\\share\\PKIData\%3%4.crt"
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.local/pkidata/%3%4.crt' -Force
Add-CAAuthorityInformationAccess -AddToCertificateOcsp 'http://ocsp.lab.local/ocsp' -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

Example for **subca1**:

```powershell
Rename-Item "C:\Windows\System32\CertSrv\CertEnroll\subca1.lab.local_Lab Issuing CA - Site1.crt" "Lab Issuing CA - Site1.crt"

$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*Lab Issuing CA - Site1*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

Repeat similarly on **subca2** for `Lab Issuing CA - Site2`.