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

Rename-Item "C:\Windows\System32\CertSrv\CertEnroll\caroot1.lab.local_Lab Root CA.crt" "Lab Root CA.crt"
explorer.exe "C:\Windows\System32\CertSrv\CertEnroll"
```

Copy these from **caroot1** to `\\lab.local\\share\\PKIData`:

- `Lab Root CA.crt`
- `Lab Root CA.crl`

Then publish to AD:

```powershell
certutil -dspublish -f "\\lab.local\\share\\PKIData\\Lab Root CA.crt" RootCA
certutil -dspublish -f "\\lab.local\\share\\PKIData\\Lab Root CA.crl" "Lab Root CA"
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
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
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

---

## 6.2 Certificate Templates Configuration (LAB Version)

Templates control what certificates can be issued, who can request them, and how they're used. The following templates must be created or duplicated from built‑ins.

### Overview

| Template                          | Based On                        | Purpose                                  | Autoenrollment | Publish to AD |
|-----------------------------------|---------------------------------|------------------------------------------|----------------|---------------|
| **PKI-WebServer**                 | Web Server                      | IIS and HTTPS endpoints                  | Yes            | Yes           |
| **PKI-OCSP**                      | OCSP Response Signing           | OCSP role signing certs                  | No             | No            |
| **PKI-DCAuth**                    | Domain Controller Authentication| DC authentication, smart card logon      | Yes            | Yes           |
| **PKI-LDAPS**                     | Computer                        | Secure LDAP over TLS                     | Yes            | Yes           |

### Steps (on subca1 or subca2)

Open the Certificate Templates console:

```powershell
certtmpl.msc
```

#### 6.2.1 Duplicate Template → Web Server (PKI-WebServer)

1. Right-click **Web Server** → **Duplicate Template**.
2. **General** tab:
   - Template display name: `PKI-WebServer`
   - Template name: `PKI-WebServer`
   - Validity period: `2 years`
   - Renewal period: `6 weeks`
3. **Request Handling** tab:
   - Purpose: `Signature and encryption`
   - Check: `Allow private key to be exported`
4. **Subject Name** tab:
   - Select: `Build from this Active Directory information`
   - Subject name format: `Common name`
   - Include: `DNS name`
5. **Security** tab:
   - Add `Domain Computers` with **Read** and **Enroll** permissions.
   - Add `PKI Web Servers` group with **Read**, **Enroll**, and **Autoenroll** permissions.
   - Add `Authenticated Users` with **Read** permission.
6. **Extensions** tab → **Application Policies**:
   - Ensure **Server Authentication** (1.3.6.1.5.5.7.3.1) is present.
7. Click **OK**.

#### 6.2.2 Duplicate Template → OCSP Response Signing (PKI-OCSP)

1. Right-click **OCSP Response Signing** → **Duplicate Template**.
2. **General** tab:
   - Template display name: `PKI-OCSP`
   - Template name: `PKI-OCSP`
   - Validity period: `1 year`
   - Renewal period: `6 weeks`
3. **Request Handling** tab:
   - Purpose: `Signature`
4. **Subject Name** tab:
   - Select: `Build from this Active Directory information`
   - Subject name format: `Common name`
5. **Security** tab:
   - Add `OCSP Servers` group (create if needed) with **Read** and **Enroll** permissions.
   - Add `Authenticated Users` with **Read** permission.
6. **Extensions** tab → **Application Policies**:
   - Ensure **OCSP Signing** (1.3.6.1.5.5.7.3.9) is the **only** policy.
7. **Issuance Requirements** tab:
   - Uncheck `CA certificate manager approval`.
8. Click **OK**.

#### 6.2.3 Duplicate Template → Domain Controller Authentication (PKI-DCAuth)

1. Right-click **Domain Controller Authentication** → **Duplicate Template**.
2. **General** tab:
   - Template display name: `PKI-DCAuth`
   - Template name: `PKI-DCAuth`
   - Validity period: `2 years`
   - Renewal period: `6 weeks`
3. **Subject Name** tab:
   - Select: `Build from this Active Directory information`
   - Subject name format: `Common name`
   - Include: `DNS name`
4. **Security** tab:
   - Add `Domain Controllers` with **Read**, **Enroll**, and **Autoenroll** permissions.
   - Add `Authenticated Users` with **Read** permission.
5. **Extensions** tab → **Application Policies**:
   - Ensure **Client Authentication** and **Server Authentication** are present.
6. Click **OK**.

#### 6.2.4 Duplicate Template → Computer (PKI-LDAPS)

1. Right-click **Computer** → **Duplicate Template**.
2. **General** tab:
   - Template display name: `PKI-LDAPS`
   - Template name: `PKI-LDAPS`
   - Validity period: `2 years`
   - Renewal period: `6 weeks`
3. **Subject Name** tab:
   - Select: `Build from this Active Directory information`
   - Subject name format: `Common name`
   - Include: `DNS name`
4. **Security** tab:
   - Add `Domain Controllers` with **Read**, **Enroll**, and **Autoenroll** permissions.
   - Add `Domain Computers` with **Read**, **Enroll**, and **Autoenroll** permissions.
   - Add `Authenticated Users` with **Read** permission.
5. **Extensions** tab → **Application Policies**:
   - Add **Server Authentication** (1.3.6.1.5.5.7.3.1).
   - Optionally add **Client Authentication** (1.3.6.1.5.5.7.3.2).
6. Click **OK**.

### 6.2.5 Publish Templates to Issuing CAs

On **subca1** (and repeat on **subca2**):

```powershell
certutil -SetCATemplates +PKI-WebServer +PKI-OCSP +PKI-DCAuth +PKI-LDAPS
```

Or via GUI:

1. Open **Certification Authority** MMC.
2. Right-click **Certificate Templates** → **New** → **Certificate Template to Issue**.
3. Select:
   - `PKI-WebServer`
   - `PKI-OCSP`
   - `PKI-DCAuth`
   - `PKI-LDAPS`
4. Click **OK**.

### 6.2.6 Create OCSP Servers Group (if not already created)

On **dc1** or **dc2**:

```powershell
New-ADGroup -Name 'OCSP Servers' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'OCSP Servers' -Members 'ocsp1$','ocsp2$'
```

---

## 6.3 Certificate Services & OCSP Role Installation (LAB Version)

### 6.3.1 Install Web Enrollment on Web Servers (web01 & web02)

On **web01**:

```powershell
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsWebEnrollment -Confirm:$false
```

Repeat on **web02**.

### 6.3.2 Install OCSP Responder Role (ocsp1 & ocsp2)

On **ocsp1**:

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
Install-AdcsOnlineResponder -Confirm:$false
```

Repeat on **ocsp2**.

### 6.3.3 Request OCSP Signing Certificates

#### On ocsp1 (for subca1)

Create a request INF file `C:\ocsp_request.inf`:

```ini
[NewRequest]
Subject = "CN=OCSP Signing Certificate - ocsp1"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0x80

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.9
```

Generate and submit the request:

```powershell
certreq -new C:\ocsp_request.inf C:\ocsp1.req

# Submit to subca1
certreq -submit -config "subca1.lab.local\Lab Issuing CA - Site1" -attrib "CertificateTemplate:PKI-OCSP" C:\ocsp1.req C:\ocsp1.cer

# Install certificate
certreq -accept C:\ocsp1.cer
```

#### On ocsp2 (for subca2)

Create `C:\ocsp_request.inf`:

```ini
[NewRequest]
Subject = "CN=OCSP Signing Certificate - ocsp2"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0x80

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.9
```

Generate and submit:

```powershell
certreq -new C:\ocsp_request.inf C:\ocsp2.req

# Submit to subca2
certreq -submit -config "subca2.lab.local\Lab Issuing CA - Site2" -attrib "CertificateTemplate:PKI-OCSP" C:\ocsp2.req C:\ocsp2.cer

# Install certificate
certreq -accept C:\ocsp2.cer
```

### 6.3.4 Configure OCSP Revocation Configuration

#### On ocsp1 (pointing to subca1)

1. Open **Online Responder Management** console (`ocsp.msc`).
2. Right-click **Revocation Configuration** → **Add Revocation Configuration**.
3. **Name**: `subca1-revocation`
4. **Select a CA certificate location**: Browse and select the **Lab Issuing CA - Site1** certificate from `\\lab.local\share\PKIData\Lab Issuing CA - Site1.crt`.
5. **Provider**: Select `Local Certificate`.
6. **Signing Certificate**: Select the OCSP signing certificate you just enrolled (CN=OCSP Signing Certificate - ocsp1).
7. Click **Finish**.

#### On ocsp2 (pointing to subca2)

1. Open **Online Responder Management** console (`ocsp.msc`).
2. Right-click **Revocation Configuration** → **Add Revocation Configuration**.
3. **Name**: `subca2-revocation`
4. **Select a CA certificate location**: Browse and select the **Lab Issuing CA - Site2** certificate from `\\lab.local\share\PKIData\Lab Issuing CA - Site2.crt`.
5. **Provider**: Select `Local Certificate`.
6. **Signing Certificate**: Select the OCSP signing certificate you just enrolled (CN=OCSP Signing Certificate - ocsp2).
7. Click **Finish**.

---

## 6.4 Testing Template Deployment (LAB Version)

### Test Web Server Certificate Enrollment

From **web01**:

```powershell
# Force group policy update to get new templates
certutil -pulse

# Request a web server certificate
$cert = Get-Certificate -Template "PKI-WebServer" -CertStoreLocation Cert:\LocalMachine\My -DnsName "web01.lab.local"
$cert
```

From **web02**:

```powershell
certutil -pulse
$cert = Get-Certificate -Template "PKI-WebServer" -CertStoreLocation Cert:\LocalMachine\My -DnsName "web02.lab.local"
$cert
```

### Test OCSP Signing Certificate

Verify the OCSP signing certificates are installed:

On **ocsp1**:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "OCSP" }
```

On **ocsp2**:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "OCSP" }
```

### Test OCSP Responder

From any domain-joined machine:

```powershell
# Test ocsp1
certutil -url "http://ocsp1.lab.local/ocsp"

# Test ocsp2
certutil -url "http://ocsp2.lab.local/ocsp"
```

You should see "Verified" status for the OCSP responder.

---

## 7. Validation & Compliance Checklist (LAB Version)

### CRL Distribution Points

| Setting                      | Local | UNC | HTTP |
|------------------------------|-------|-----|------|
| Publish CRLs                 | ✅    | ✅  | ❌   |
| Delta CRLs                   | ✅    | ✅  | ❌   |
| Include in CDP extension     | ❌    | ❌  | ✅   |

### Authority Information Access

| URL              | AIA Extension | OCSP Extension | Purpose                    |
|------------------|---------------|----------------|----------------------------|
| Local File Path  | ❌            | ❌             | Internal use only          |
| HTTP AIA         | ✅            | ❌             | Client cert chain building |
| OCSP URL         | ❌            | ✅             | Real-time revocation       |

✅ **No** `ldap://` or `file://` URLs in issued certificates.  
✅ Certificates embed **only** HTTP and OCSP URLs.

---

## 8. Deep PKI Configuration Validation Script (LAB Version)

Run this on **subca1** and **subca2** to validate CDP/AIA/OCSP configuration:

```powershell
Write-Host "=== PKI Configuration Validation ===" -ForegroundColor Cyan

$expectedCDP_HTTP = 'http://pki.lab.local/pkidata/'
$expectedAIA_HTTP = 'http://pki.lab.local/pkidata/'
$expectedOCSP = 'http://ocsp.lab.local/ocsp'

$caName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active
Write-Host "`nCA Name: $caName" -ForegroundColor Yellow

Write-Host "`n--- CRL Distribution Points ---" -ForegroundColor Yellow
$crlOutput = certutil -getreg CA\CRLPublicationURLs
$crlOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$') {
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToCertCDP = ($flags -band 0x02) -ne 0

    if ($url -match $expectedCDP_HTTP -and $addToCertCDP) {
      Write-Host "CDP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ldap://|file://' -and $addToCertCDP) {
      Write-Host "Legacy CDP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n--- Authority Information Access ---" -ForegroundColor Yellow
$aiaOutput = certutil -getreg CA\CACertPublicationURLs
$aiaOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$') {
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToAIA = ($flags -band 0x02) -ne 0
    $addToOCSP = ($flags -band 0x20) -ne 0

    if ($url -match $expectedAIA_HTTP -and $addToAIA) {
      Write-Host "AIA OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match $expectedOCSP -and $addToOCSP) {
      Write-Host "OCSP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ocsp' -and $addToOCSP -and $url -notmatch $expectedOCSP) {
      Write-Host "OCSP Wrong Domain ⚠️ $url (should be $expectedOCSP)" -ForegroundColor Yellow
    } elseif ($url -match 'ldap://|file://' -and ($addToAIA -or $addToOCSP)) {
      Write-Host "Legacy AIA/OCSP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan
```

**Expected Output (All Green):**

- CDP OK ✅ http://pki.lab.local/pkidata/%3%8.crl
- AIA OK ✅ http://pki.lab.local/pkidata/%3%4.crt
- OCSP OK ✅ http://ocsp.lab.local/ocsp

---

## 9. Final Notes (LAB Version)

- Always run the validation script after modifying CA URLs.
- Maintain **only HTTP (AIA/CDP)** and **OCSP HTTP** entries — no LDAP/file.
- Replicate CRL/AIA files across both IIS web servers via DFS.
- Back up the Root CA `.crt` and `.crl` securely offline.
- Document each CRL renewal and Root CA publishing event.
- Both issuing CAs (**subca1** and **subca2**) should be configured identically except for their common names and locations.
- OCSP responders (**ocsp1** and **ocsp2**) should point to their respective regional issuing CAs for optimal performance.

✅ **Result:** Fully modern, Microsoft‑compliant, two‑tier PKI with redundant issuing CAs and OCSP responders ready for production operations.

---

## 🧩 Appendix A – Revoking an Issuing CA Certificate (LAB Version)

**Purpose:**  
To invalidate a subordinate CA certificate (e.g. `Lab Issuing CA - Site1`) when that CA is retired, compromised, or replaced by a renewal.

### A.1 Preconditions

- Root CA (**caroot1**) is **offline**, but accessible for revocation and CRL publication.  
- The certificate to revoke (e.g. *Lab Issuing CA - Site1.crt*) is **present on caroot1** under `C:\PKIData`.

### A.2 Identify the Subordinate Certificate on the Root CA

Run the following on **caroot1**:

```powershell
certutil -view -restrict "Certificate Template=SubCA"
```

If you're unsure, list all issued CA certificates:

```powershell
certutil -view -restrict "Issued Common Name=Lab Issuing CA - Site1"
```

Verify the **Serial Number** matches the one from the target SubCA certificate.

### A.3 Revoke the Issuing CA Certificate

Use **certutil** to revoke by serial number (or RequestID):

```powershell
certutil -revoke <SerialNumber> "Key Compromise"
```

Common revocation reasons:

- `KeyCompromise`
- `CACompromise`
- `CeaseOfOperation`
- `Superseded`

Example:

```powershell
certutil -revoke 4b2a "CeaseOfOperation"
```

### A.4 Publish an Updated CRL

After revoking the certificate, issue a fresh CRL:

```powershell
certutil -crl
```

Copy the Root CA's new `.crl` file to your PKI share:

```powershell
Copy-Item "C:\Windows\System32\CertSrv\CertEnroll\Lab Root CA.crl" "\\lab.local\share\PKIData\"
```

Then publish it to AD:

```powershell
certutil -dspublish -f "\\lab.local\share\PKIData\Lab Root CA.crl" "Lab Root CA"
```

### A.5 Verify CRL Contains the Revoked SubCA

Check that the revoked CA's serial number appears in the CRL:

```powershell
certutil -dump "Lab Root CA.crl" | findstr /i "<SerialNumber>"
```

A successful entry appears under the CRL's "Revoked Certificates" list.

### A.6 Notify Administrators & Dependents

- Disable **CertSvc** on the revoked issuing CA:

  ```powershell
  Stop-Service certsvc
  Set-Service certsvc -StartupType Disabled
  ```

- Remove DNS A records for `subca1` or `subca2` if decommissioned.
- Update AIA/CDP hosting (remove old public `.crt`).
- Document the revocation reason and time.

### A.7 Optional – Replace the Revoked Issuing CA

If replacing the CA (e.g., due to renewal or compromise):

1. Deploy a new subordinate CA following **Section 6.0**.
2. Update all dependent services (OCSP responders, IIS, templates).
3. Validate using the **Deep PKI Validation Script** in Section 8.

---

**End of PKI Infrastructure Deployment Guide – LAB Version**