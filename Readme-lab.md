# 🧱 PKI Infrastructure Deployment Guide 11sh

Modern, domain-integrated Public Key Infrastructure (PKI) for **lab.local** — featuring an **Offline Root CA**, two **Enterprise Issuing CAs (TX & LV)**, redundant **HTTP/OCSP namespaces**, and full PowerShell-based automation.

---

## 📖 Table of Contents

1. [Overview & Environment](#1-overview--environment)  
2. [Network & DNS Configuration](#2-network--dns-configuration)  
3. [DFS and File Permissions](#3-dfs-and-file-permissions)  
4. [Web Server (IIS) Configuration](#4-web-server-iis-configuration)  
5. [Offline Root CA Setup](#5-offline-root-ca-setup)  
6. [Issuing CAs (TX & LV)](#6-issuing-cas-tx--lv)  
7. [Validation & Compliance Checklist](#7-validation--compliance-checklist)  
8. [Deep PKI Configuration Validation Script](#8-deep-pki-configuration-validation-script)  
9. [Final Notes](#9-final-notes)  
10. [Appendix A – Revoking an Issuing CA Certificate](#appendix-a--revoking-an-issuing-ca-certificate)

---

## 1. Overview & Environment

| Component | Function | Hostname | IP | Location |
|----|----|----|----|----|
| Domain Controllers | AD DS | **txdc1.lab.local** / **lvdc1.lab.local** | 10.30.1.201 / 10.40.1.201 | Texas / Las Vegas |
| Root CA | Offline standalone | **rootca.lab.local** | 10.30.1.131 | Offline vault |
| Issuing CAs | Enterprise subordinate | **txsubca1.lab.local**, **lvsubca1.lab.local** | 10.30.1.211 / 10.40.1.211 | TX / LV |
| Web Servers | IIS AIA/CDP HTTP | **txweb1.lab.local**, **lvweb1.lab.local** | 10.30.1.241 / 10.40.1.241 | TX / LV |
| OCSP Responders | Revocation (OCSP) | **txocsp.lab.local**, **lvocsp.lab.local** | 10.30.1.221 / 10.40.1.221 | TX / LV |

**Primary Namespaces**  
- HTTP (AIA/CDP): `http://pki.lab.local/pkidata/`  
- OCSP: `http://ocsp.lab.local/ocsp`  

**DFS Share (for PKI Data Replication):** `\\lab.local\\share\\pkidata`

**NetBIOS name:** `LAB`

### ADCS Path Variables

| Variable | Description |
|----|----|
| `%3` | CA Common Name |
| `%4` | Certificate renewal suffix |
| `%8` | CRL name suffix |

Example:  
- `%3%8.crl` → `Lab Issuing CA - TX.crl`  
- `%3%4.crt` → `Lab Issuing CA - TX.crt`

---

## 2. Network & DNS Configuration

Using **DNS-based HA failover** (no load balancer required):

| Record | Target | IP | Purpose |
|----|----|----|----|
| `txweb1.lab.local` | 10.30.1.241 | IIS Host TX |
| `lvweb1.lab.local` | 10.40.1.241 | IIS Host LV |
| `txocsp.lab.local` | 10.30.1.221 | OCSP TX |
| `lvocsp.lab.local` | 10.40.1.221 | OCSP LV |
| `pki.lab.local` | 10.30.1.241 / 10.40.1.241 | HTTP AIA/CDP namespace |
| `ocsp.lab.local` | 10.30.1.221 / 10.40.1.221 | OCSP namespace |

**TTL Recommendation:** 60–120 seconds  
Ensures fast DNS failover between regions.

---

## 3. DFS and File Permissions

### Create Folder and Share

```powershell
$folderPath = "C:\PKIData"
if (-Not (Test-Path $folderPath)) { New-Item -Path $folderPath -ItemType Directory }

$shareName = "PKIData"
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

### Grant Permissions

```powershell
# Share Access
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\subca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\subca2$" -AccessRight Change -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\web01$"  -AccessRight Read   -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\web02$"  -AccessRight Read   -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\ocsp1$"  -AccessRight Read   -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\ocsp2$"  -AccessRight Read   -Force

# NTFS Permissions
icacls "C:\PKIData" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
icacls "C:\PKIData" /grant 'LAB\subca1$:(OI)(CI)M' /T
icacls "C:\PKIData" /grant 'LAB\subca2$:(OI)(CI)M' /T
icacls "C:\PKIData" /grant 'LAB\web01$:(OI)(CI)RX' /T
icacls "C:\PKIData" /grant 'LAB\web02$:(OI)(CI)RX' /T
icacls "C:\PKIData" /grant 'LAB\ocsp1$:(OI)(CI)RX' /T
icacls "C:\PKIData" /grant 'LAB\ocsp2$:(OI)(CI)RX' /T

Get-SmbShareAccess -Name PKIData | Format-Table AccountName, AccessRight -AutoSize
```

---

## 4. Web Server (IIS) Configuration
Web servers: web01.lab.local and web02.lab.local
PKI content path: \\lab.local\share\PKIData (DFS)
### 4.1 Install IIS
Run on web01 and repeat on web02:

```powershell
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

### 4.2 Create Service Account and Permissions
### 4.2.1 Create service account and group (run on DC1 or DC2)

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

Optional verification:
```powershell
Get-ADUser PKIWebSvc
Get-ADGroup 'PKI Web Servers'
Get-ADGroupMember 'PKI Web Servers'
```

### 4.2.2 Grant PKIWebSvc access to PKIData (run on File1 and File2)

On file1:
```powershell
Grant-SmbShareAccess -Name 'PKIData' -AccountName 'LAB\PKIWebSvc' -AccessRight Change -Force
icacls 'C:\PKIData' /grant 'LAB\PKIWebSvc:(OI)(CI)M' /T
```
Repeat the same commands on file2.
```powershell
Grant-SmbShareAccess -Name 'PKIData' -AccountName 'LAB\PKIWebSvc' -AccessRight Change -Force
icacls 'C:\PKIData' /grant 'LAB\PKIWebSvc:(OI)(CI)M' /T
```
Optional verification:
```powershell
Get-SmbShareAccess -Name PKIData | Where-Object AccountName -match 'PKIWebSvc'
icacls C:\PKIData | findstr /i PKIWebSvc
```



### 4.3 Configure IIS Application Pool Identity (web01 and web02)
Set the DefaultAppPool to run as LAB\PKIWebSvc.

Run on web01:
```powershell
Import-Module WebAdministration

# Set identity type to SpecificUser (3)
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.identityType -Value 3

# Set service account and password
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.userName -Value "LAB\PKIWebSvc"
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.password -Value "<PKIWebSvc_password_here>"

# Restart the app pool
Restart-WebAppPool DefaultAppPool

# Verify
Get-Item "IIS:\AppPools\DefaultAppPool" | Select-Object -ExpandProperty processModel
```
Expected key values:

identityType : SpecificUser
userName     : LAB\PKIWebSvc
Repeat the same block on web02.

Run on web02:
```powershell
Import-Module WebAdministration

# Set identity type to SpecificUser (3)
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.identityType -Value 3

# Set service account and password
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.userName -Value "LAB\PKIWebSvc"
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.password -Value "<PKIWebSvc_password_here>"

# Restart the app pool
Restart-WebAppPool DefaultAppPool

# Verify
Get-Item "IIS:\AppPools\DefaultAppPool" | Select-Object -ExpandProperty processModel
```
### 4.4 Create Virtual Directory for PKI Data (web01 and web02)
Assumes a DFS namespace \\lab.local\share\PKIData.

Run on web01:
```powershell
Import-Module WebAdministration

# Remove if it already exists (no error if missing)
Remove-WebVirtualDirectory -Site 'Default Web Site' -Name 'pkidata' -ErrorAction SilentlyContinue

# Create virtual directory pointing to DFS path
$vDirProperties = @{
    Site         = 'Default Web Site'
    Name         = 'pkidata'
    PhysicalPath = '\\lab.local\share\PKIData'
}
New-WebVirtualDirectory @vDirProperties

# Verify
Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'pkidata' | Select-Object physicalPath
```
Repeat on web02.
```powershell
Import-Module WebAdministration

# Remove if it already exists (no error if missing)
Remove-WebVirtualDirectory -Site 'Default Web Site' -Name 'pkidata' -ErrorAction SilentlyContinue

# Create virtual directory pointing to DFS path
$vDirProperties = @{
    Site         = 'Default Web Site'
    Name         = 'pkidata'
    PhysicalPath = '\\lab.local\share\PKIData'
}
New-WebVirtualDirectory @vDirProperties

# Verify
Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'pkidata' | Select-Object physicalPath
```

### 4.5 Enable Directory Browsing and MIME Types (web01 and web02)
Run on web01:

```powershell
Import-Module WebAdministration

# Enable directory browsing on /pkidata
Set-WebConfigurationProperty `
    -Filter /system.webServer/directoryBrowse `
    -Name enabled `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Allow double escaping (needed for some CRL/AIA paths)
Set-WebConfigurationProperty `
    -Filter /system.webServer/security/requestFiltering `
    -Name allowDoubleEscaping `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site"

# Add MIME types for CRL and CRT
Add-WebConfigurationProperty -pspath 'IIS:' `
    -filter "system.webServer/staticContent" `
    -name "." `
    -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}

Add-WebConfigurationProperty -pspath 'IIS:' `
    -filter "system.webServer/staticContent" `
    -name "." `
    -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
```
Repeat on web02.
```powershell
Import-Module WebAdministration

# Enable directory browsing on /pkidata
Set-WebConfigurationProperty `
    -Filter /system.webServer/directoryBrowse `
    -Name enabled `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Allow double escaping (needed for some CRL/AIA paths)
Set-WebConfigurationProperty `
    -Filter /system.webServer/security/requestFiltering `
    -Name allowDoubleEscaping `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site"

# Add MIME types for CRL and CRT
Add-WebConfigurationProperty -pspath 'IIS:' `
    -filter "system.webServer/staticContent" `
    -name "." `
    -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}

Add-WebConfigurationProperty -pspath 'IIS:' `
    -filter "system.webServer/staticContent" `
    -name "." `
    -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
```

## 4.6 Basic Test
On web01:

Browse to http://web01.lab.local/pkidata/
On web02:

Browse to http://web02.lab.local/pkidata/
---

## 5. Offline Root CA Setup

### Purpose
Acts as the **trust anchor** for the environment.

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

Copy:
```
Lab Root CA.crt
Lab Root CA.crl
```

to `\\lab.local\\share\\pkidata` and publish:

```powershell
certutil -dspublish -f "\\lab.local\\share\\pkidata\\Lab Root CA.crt" RootCA
certutil -dspublish -f "\\lab.local\\share\\pkidata\\Lab Root CA.crl" "Lab Root CA"
```

---

## 6. Issuing CAs (TX & LV)

### Purpose
Provide enterprise-grade certificate issuance with modern CDP/AIA/OCSP design and high availability.

---

### 6.0 Install Issuing CAs txsubca1 (Texas) and lvsubca1 (Vegas)

**Purpose:** Install two enterprise issuing CAs. Each publishes CRLs locally and embeds a single HTTP CDP/AIA URL pointing to `http://pki.lab.local/pkidata/`.

#### 6.0.1 Install Issuing CA on txsubca1

```powershell
# CAPolicy.inf (prevents default templates auto-load)
Set-Content  C:\\Windows\\CAPolicy.inf '[Version]'
Add-Content C:\\Windows\\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\\Windows\\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\\Windows\\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\\Windows\\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\\Windows\\CAPolicy.inf 'LoadDefaultTemplates=0'

# Role and Request
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName = 'Lab Issuing CA - TX'
  CADistinguishedNameSuffix = 'O=PKI,L=Dallas,S=Texas,C=US'
  CAType = 'EnterpriseSubordinateCA'
  CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName = 'SHA256'
  KeyLength = 4096
  DatabaseDirectory = 'C:\\pkidata'
  OutputCertRequestFile = 'C:\\pkidata\\lab_issuing_tx.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

#### 6.0.2 Approve and Install TX SubCA Certificate

Perform the following on the Root CA:

```powershell
certreq -submit C:\\pkidata\\lab_issuing_tx.req C:\\pkidata\\lab_issuing_tx.cer
certutil -getrequests
certutil -approve <RequestID>
certutil -retrieve <RequestID> C:\\pkidata\\lab_issuing_tx.cer
```

Copy the `.cer` back to `txsubca1` and install via **Certification Authority → All Tasks → Install CA Certificate**.

Start the CA service:

```powershell
Start-Service certsvc
```

---

#### 6.0.3 Install Issuing CA on lvsubca1

```powershell
# CAPolicy.inf
Set-Content  C:\\Windows\\CAPolicy.inf '[Version]'
Add-Content C:\\Windows\\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\\Windows\\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\\Windows\\CAPolicy.inf 'URL=http://pki.lab.local/pkidata/cps.html'
Add-Content C:\\Windows\\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\\Windows\\CAPolicy.inf 'LoadDefaultTemplates=0'

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName = 'Lab Issuing CA - LV'
  CADistinguishedNameSuffix = 'O=PKI,L=Las Vegas,S=Nevada,C=US'
  CAType = 'EnterpriseSubordinateCA'
  CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName = 'SHA256'
  KeyLength = 4096
  DatabaseDirectory = 'C:\\pkidata'
  OutputCertRequestFile = 'C:\\pkidata\\lab_issuing_lv.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

#### 6.0.4 Approve and Install LV SubCA Certificate

Repeat the same process on the Root CA for the LV request file:

```powershell
certreq -submit C:\\pkidata\\lab_issuing_lv.req C:\\pkidata\\lab_issuing_lv.cer
certutil -getrequests
certutil -approve <RequestID>
certutil -retrieve <RequestID> C:\\pkidata\\lab_issuing_lv.cer
```

Copy and install the certificate back on `lvsubca1`, then start the CA service.

---

### 6.1 Core Configuration (Both TX and LV)

Run the following on **both txsubca1 and lvsubca1**:

```powershell
certutil -setreg CA\\ValidityPeriodUnits 1
certutil -setreg CA\\ValidityPeriod Years
certutil -setreg CA\\CRLPeriodUnits 52
certutil -setreg CA\\CRLPeriod Weeks
certutil -setreg CA\\CRLOverlapPeriodUnits 3
certutil -setreg CA\\CRLOverlapPeriod Days

# Remove legacy entries
Get-CACrlDistributionPoint | ForEach-Object { Remove-CACrlDistributionPoint $_.Uri -Force }
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -match '^(ldap|file)' } | Remove-CAAuthorityInformationAccess -Force

# Add CRL Paths
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri '\\lab.local\share\PKIData\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -Force

# Add AIA + OCSP
certutil -setreg CA\\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt\n2:\\lab.local\share\PKIData\%3%4.crt"
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.local/pkidata/%3%4.crt' -Force
Add-CAAuthorityInformationAccess -AddToCertificateOcsp 'http://ocsp.lab.local/ocsp' -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl

Rename-Item "C:\Windows\System32\CertSrv\CertEnroll\txsubca1.lab.local_Lab Issuing CA - TX.crt" "Lab Issuing CA - TX.crt"
explorer C:\windows\System32\CertSrv\CertEnroll
```
## Publish Issuing CA - FL to AD
```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*Lab Issuing CA - tx*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```
---

### 6.2 Certificate Templates Configuration

### Overview
Templates control what certificates can be issued, who can request them, and how they're used. The following templates must be created or duplicated from built‑ins:

| Template | Based On | Purpose | Autoenrollment | Publish to AD |
|----|----|----|----|----|
| **Web Server (PKI‑Web)** | Web Server | IIS and HTTPS endpoints | Yes | Yes |
| **OCSP Responder (PKI‑OCSP)** | OCSP Response Signing | OCSP role signing certs | No | No |
| **Domain Controller Authentication (PKI‑DCAuth)** | Domain Controller Authentication | DC authentication, smart card logon | Yes | Yes |
| **LDAPS (PKI‑LDAPS)** | Computer | Secure LDAP over TLS | Yes | Yes |

### Steps (on an Issuing CA)

```powershell
certtmpl.msc
```

1. **Duplicate Template → Web Server**
   - General tab: *PKI‑WebServer*
   - Security tab: add `Domain Computers`, `PKI Web Servers`, and `OCSP Servers` with **Enroll** and **Autoenroll** permissions.
   - Subject Name: "Build from Active Directory Information".
   - Extensions → Application Policies: ensure **Server Authentication**.

2. **Duplicate Template → OCSP Response Signing**
   - General: *PKI‑OCSP*
   - Security: assign `OCSP Servers` **Enroll** rights.
   - Extensions: Application Policies → **OCSP Signing** only.
   - Uncheck "Publish certificate in Active Directory".

3. **Duplicate Template → Domain Controller Authentication**
   - Name: *PKI‑DCAuth*
   - Retain default "Domain Controllers" security with Auto‑Enrollment.
   - Validity = 2 years, Renewal = 6 weeks.

4. **Duplicate Template → LDAPS / Secure LDAP**
   - Name: *PKI‑LDAPS*
   - Based on *Computer* template.
   - Application Policies → **Server Authentication** + optionally **Client Authentication**.
   - Security: add `Domain Controllers`, `Domain Computers` with Enroll/Autoenroll.

5. **Publish templates:**
   ```powershell
   certutil -setcatemplates +PKI-WebServer,+PKI-OCSP,+PKI-DCAuth,+PKI-LDAPS
   ```

---

### 6.3 Certificate Services & OCSP Role Installation

#### On Each **Web Server** (`txweb1`, `lvweb1`)

```powershell
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsWebEnrollment -Confirm:$false
```

> 💡 If you need the web servers to also act as issuing CAs (not recommended for production), use:
> ```powershell
> Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools
> Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName "WebServer CA" -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5
> ```

#### On Each **OCSP Server** (`txocsp`, `lvocsp`)

**For txocsp (pointing to TX Issuing CA):**

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
Install-AdcsOnlineResponder -Confirm:$false
```

Configure the OCSP responder to use the TX issuing CA:

```powershell
# Open OCSP console and add revocation configuration pointing to:
# CA: txsubca1.lab.local\Lab Issuing CA - TX
```

**For lvocsp (pointing to LV Issuing CA):**

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
Install-AdcsOnlineResponder -Confirm:$false
```

Configure the OCSP responder to use the LV issuing CA:

```powershell
# Open OCSP console and add revocation configuration pointing to:
# CA: lvsubca1.lab.local\Lab Issuing CA - LV
```

#### Grant Enrollment Rights

Ensure each OCSP server has permission to enroll the *PKI‑OCSP* template:

```powershell
# Create OCSP Servers group if not exists
New-ADGroup -Name 'OCSP Servers' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'OCSP Servers' -Members 'txocsp$', 'lvocsp$'

# On the issuing CA, ensure template is published
certutil -setcatemplates +PKI-OCSP
```

#### Request OCSP Signing Certificates

On each OCSP server, request an OCSP signing certificate:

```powershell
# Create request
certreq -new -f ocsp_request.inf ocsp.req

# Submit to CA (replace with your CA name)
certreq -submit -config "txsubca1.lab.local\Lab Issuing CA - TX" -attrib "CertificateTemplate:PKI-OCSP" ocsp.req ocsp.cer

# Install certificate
certreq -accept ocsp.cer
```

Sample `ocsp_request.inf`:

```ini
[NewRequest]
Subject = "CN=OCSP Signing Certificate"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0x80

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.9
```

---

### 6.4 Testing Template Deployment

- From a web server:  
  ```powershell
  certutil -pulse
  certreq -submit -attrib "CertificateTemplate:PKI-WebServer" web.req
  ```
- From an OCSP server:  
  ```powershell
  certreq -submit -attrib "CertificateTemplate:PKI-OCSP" ocsp.req
  ```

Confirm issued certificates appear under `Issued Certificates` in CA console.

---

## 7. Validation & Compliance Checklist

### CRL Distribution Points

| Setting | Local | UNC | HTTP |
|----|----|----|----|
| Publish CRLs | ✅ | ✅ | ❌ |
| Delta CRLs | ✅ | ✅ | ❌ |
| Include in CDP extension | ❌ | ❌ | ✅ |

### Authority Information Access

| URL | AIA Extension | OCSP Extension | Purpose |
|----|----|----|----|
| Local File Path | ❌ | ❌ | Internal use only |
| HTTP AIA | ✅ | ❌ | Client cert chain building |
| OCSP URL | ❌ | ✅ | Real-time revocation |

✅ **No** `ldap://` or `file://` URLs.  
✅ Certificates embed **only** HTTP and OCSP URLs.

---

## 8. Deep PKI Configuration Validation Script

```powershell
Write-Host "=== PKI Configuration Validation ===" -ForegroundColor Cyan

$expectedCDP_HTTP = 'http://pki.lab.local/pkidata/'
$expectedAIA_HTTP = 'http://pki.lab.local/pkidata/'
$expectedOCSP = 'http://ocsp.lab.local/ocsp'

$caName = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration').Active
Write-Host "`nCA Name: $caName" -ForegroundColor Yellow

Write-Host "`n--- CRL Distribution Points ---" -ForegroundColor Yellow
$crlOutput = certutil -getreg CA\\CRLPublicationURLs
$crlOutput | Where-Object { $_ -match '^\\s+\\d+:\\s+\\d+:' } | ForEach-Object {
  if ($_ -match '^\\s+\\d+:\\s+(\\d+):(.+)$') {
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
$aiaOutput = certutil -getreg CA\\CACertPublicationURLs
$aiaOutput | Where-Object { $_ -match '^\\s+\\d+:\\s+\\d+:' } | ForEach-Object {
  if ($_ -match '^\\s+\\d+:\\s+(\\d+):(.+)$') {
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

Expected Output (All Green):
- CDP OK ✅ http://pki.lab.local/pkidata/%3%8.crl
- AIA OK ✅ http://pki.lab.local/pkidata/%3%4.crt
- OCSP OK ✅ http://ocsp.lab.local/ocsp

---

## 9. Final Notes

- Always run the validation script after modifying CA URLs.
- Maintain **only HTTP (AIA/CDP)** and **OCSP HTTP** entries — no LDAP/file.
- Replicate CRL/AIA files across both IIS web servers via DFS.
- Back up the Root CA `.crt` and `.crl` securely offline.
- Document each CRL renewal and Root CA publishing event.
- Both issuing CAs (TX and LV) should be configured identically except for their common names and locations.
- OCSP responders should point to their respective regional issuing CAs for optimal performance.

✅ **Result:** Fully modern, Microsoft‑compliant, two‑tier PKI with redundant issuing CAs and OCSP responders ready for production operations.

---

## 🧩 Appendix A – Revoking an Issuing CA Certificate

**Purpose:**  
To invalidate a subordinate CA certificate (e.g. `Lab Issuing CA - TX`) when that CA is retired, compromised, or replaced by a renewal.

---

### A.1 Preconditions

- Root CA is **offline**, but accessible for revocation and CRL publication.  
- The certificate to revoke (e.g. *Lab Issuing CA - TX.cert*) is **present on the Root CA** under `C:\PKIData`.

---

### A.2 Identify the Subordinate Certificate on the Root CA

Run the following on the **Offline Root CA**:

```powershell
certutil -view -restrict "Certificate Template=SubCA"
```

If you're unsure, list all issued CA certificates:

```powershell
certutil -view -restrict "Issued Common Name=Lab Issuing CA - TX"
```

Verify the **Serial Number** matches the one from the target SubCA certificate.

---

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

---

### A.4 Publish an Updated CRL

After revoking the certificate, issue a fresh CRL:

```powershell
certutil -crl
```

Copy the Root CA's new `.crl` file to your PKI share:
```powershell
copy "C:\Windows\System32\CertSrv\CertEnroll\Lab Root CA.crl" "\\lab.local\share\pkidata\"
```

Then publish it to AD and web servers:
```powershell
certutil -dspublish -f "\\lab.local\share\pkidata\Lab Root CA.crl" "Lab Root CA"
```

---

### A.5 Verify CRL Contains the Revoked SubCA

Check that the revoked CA's serial number appears in the CRL:

```powershell
certutil -dump "Lab Root CA.crl" | findstr /i "<SerialNumber>"
```

A successful entry appears under the CRL's "Revoked Certificates" list.

---

### A.6 Notify Administrators & Dependents

- Disable **CertSvc** on the revoked issuing CA:
  ```powershell
  Stop-Service certsvc
  Set-Service certsvc -StartupType Disabled
  ```
- Remove DNS A records for `txsubca1` or `lvsubca1` if decommissioned.
- Update AIA/CDP hosting (remove old public `.crt`).
- Document the revocation reason and time.

---

### A.7 Optional – Replace the Revoked Issuing CA

If replacing the CA (e.g., due to renewal or compromise):
1. Deploy a new subordinate CA following **Section 6.0**.
2. Update all dependent services (OCSP responders, IIS, templates).
3. Validate using the **Deep PKI Validation Script** in Section 8.

---

**End of PKI Infrastructure Deployment Guide**