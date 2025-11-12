# 🧱 PKI Infrastructure Deployment Guide

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

---

## 1. Overview & Environment

| Component | Function | Hostname | IP | Location |
|------------|-----------|-----------|----|-----------|
| Domain Controllers | AD DS | **txdc1.lab.local** / **lvdc1.lab.local** | 10.30.1.201 / 10.40.1.201 | Texas / Las Vegas |
| Root CA | Offline standalone | **rootca.lab.local** | 10.30.1.131 | Offline vault |
| Issuing CAs | Enterprise subordinate | **txsubca1.lab.local**, **lvsubca1.lab.local** | 10.30.1.211 / 10.40.1.211 | TX / LV |
| Web Servers | IIS AIA/CDP HTTP | **txweb1.lab.local**, **lvweb1.lab.local** | 10.30.1.241 / 10.40.1.241 | TX / LV |
| OCSP Responders | Revocation (OCSP) | **txocsp.lab.local**, **lvocsp.lab.local** | 10.30.1.221 / 10.40.1.221 | TX / LV |

**Primary Namespaces**  
- HTTP (AIA/CDP): `http://pki.lab.local/pkidata/`  
- OCSP: `http://ocsp.lab.local/ocsp`  

**DFS Share (for PKI Data Replication):** `\\lab.local\share\pkidata`

**NetBIOS name:** `LAB`

### ADCS Path Variables

| Variable | Description |
|-----------|-------------|
| `%3` | CA Common Name |
| `%4` | Certificate renewal suffix |
| `%8` | CRL name suffix |

Example:  
- `%3%8.crl` → `PKI Lab Issuing CA - TX.crl`  
- `%3%4.crt` → `PKI Lab Issuing CA - TX.crt`

---

## 2. Network & DNS Configuration

Using **DNS-based HA failover** (no load balancer required):

| Record | Target | IP | Purpose |
|---------|---------|----|----------|
| `txweb1.lab.local` | 10.30.1.241 | IIS Host TX |
| `lvweb1.lab.local` | 10.40.1.241 | IIS Host LV |
| `txocsp.lab.local` | 10.30.1.221 | OCSP TX |
| `lvocsp.lab.local` | 10.40.1.221 | OCSP LV |
| `pki.lab.local` | 10.30.1.241 / 10.40.1.241 | HTTP AIA/CDP namespace |
| `ocsp.lab.local` | 10.30.1.221 / 10.40.1.221 | OCSP namespace |

**TTL Recommendation:** 60–120 seconds.  
Ensures fast DNS failover between regions.

---

## 3. DFS and File Permissions

### Create Folder and Share

```powershell
$folderPath = "C:\\PKIData"
if (-Not (Test-Path $folderPath)) { New-Item -Path $folderPath -ItemType Directory }

$shareName = "PKIData"
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

### Grant Permissions

```powershell
# Share Access
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\\txsubca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\\lvsubca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\\txweb1$" -AccessRight Read -Force
Grant-SmbShareAccess -Name PKIData -AccountName "LAB\\lvweb1$" -AccessRight Read -Force

# NTFS Permissions
icacls "C:\\PKIData" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
icacls "C:\\PKIData" /grant 'LAB\\txsubca1$:(OI)(CI)M' /T
icacls "C:\\PKIData" /grant 'LAB\\lvsubca1$:(OI)(CI)M' /T
icacls "C:\\PKIData" /grant 'LAB\\txweb1$:(OI)(CI)RX' /T
icacls "C:\\PKIData" /grant 'LAB\\lvweb1$:(OI)(CI)RX' /T
```

---

## 4. Web Server (IIS) Configuration

### 4.1 Install IIS

```powershell
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

### 4.2 Create Service Account and Permissions

```powershell
$pwd = Read-Host -Prompt 'Enter password for PKIWebSvc' -AsSecureString
New-ADUser -Name 'PKIWebSvc' -SamAccountName 'PKIWebSvc' -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $false

New-ADGroup -Name 'PKI Web Servers' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'PKI Web Servers' -Members 'PKIWebSvc'

Grant-SmbShareAccess -Name 'PKIData' -AccountName 'LAB\\PKIWebSvc' -AccessRight Change -Force
icacls 'C:\\PKIData' /grant 'LAB\\PKIWebSvc:(OI)(CI)M' /T
```

### 4.3 Configure IIS Application Pool

```powershell
Import-Module WebAdministration
Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel -Value @{userName='LAB\\PKIWebSvc';password='<password>'}
Restart-WebAppPool DefaultAppPool
```

### 4.4 Create Virtual Directory for DFS Path

```powershell
$vDirProperties = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\lab.local\\share\\PKIData' }
New-WebVirtualDirectory @vDirProperties
```

### 4.5 Enable Directory Browsing and MIME Types

```powershell
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value true -PSPath "IIS:\\Sites\\Default Web Site\\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value true -PSPath "IIS:\\Sites\\Default Web Site"
```

Optional MIME types:

```powershell
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
```

---

## 5. Offline Root CA Setup

### Purpose
Acts as the **trust anchor** for the environment.

### 5.1 Create CAPolicy.inf

```powershell
@'
[Version]
Signature="$Windows NT$"
[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
'@ | Out-File C:\\Windows\\CAPolicy.inf -Encoding ascii
```

### 5.2 Install Root CA

```powershell
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName 'Lab Root CA' -ValidityPeriod Years -ValidityPeriodUnits 20 -HashAlgorithmName SHA256 -KeyLength 4096
```

### 5.3 Configure CRL/AIA Registry

```powershell
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod Years
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod Days
```

### 5.4 Configure CDP and AIA

Remove defaults:

```powershell
Get-CACrlDistributionPoint | ForEach-Object { Remove-CACrlDistributionPoint $_.Uri -Force }
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -match '^(ldap|file)://' } | Remove-CAAuthorityInformationAccess -Force
```

Add entries:

```powershell
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -Force
certutil -setreg CA\CACertPublicationURLs '1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.local/pkidata/%3%4.crt' -Force
```

### 5.5 Publish CRL

```powershell
Restart-Service certsvc
certutil -crl
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
Provide enterprise-grade certificate issuance with modern CDP/AIA/OCSP design.

### 6.1 Core Configuration

```powershell
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 52
certutil -setreg CA\CRLPeriod Weeks
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod Days

# Remove legacy entries
Get-CACrlDistributionPoint | ForEach-Object { Remove-CACrlDistributionPoint $_.Uri -Force }
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -match '^(ldap|file)' } | Remove-CAAuthorityInformationAccess -Force

# Add CRL Paths
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri '\\lab.local\\share\\PKIData\\%3%8.crl' -PublishToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.lab.local/pkidata/%3%8.crl' -AddToCertificateCDP -Force

# Add AIA + OCSP
certutil -setreg CA\\CACertPublicationURLs "1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt\n2:\\lab.local\\share\\PKIData\\%3%4.crt"
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.lab.local/pkidata/%3%4.crt' -Force
Add-CAAuthorityInformationAccess -AddToCertificateOcsp 'http://ocsp.lab.local/ocsp' -Force

Restart-Service certsvc
certutil -crl
```

---

## 7. Validation & Compliance Checklist

### CRL Distribution Points

| Setting | Local | UNC | HTTP |
|----------|--------|------|------|
| Publish CRLs | ✅ | ✅ | ❌ |
| Delta CRLs | ✅ | ✅ | ❌ |
| Include in CDP extension | ❌ | ❌ | ✅ |

### Authority Information Access

| URL | AIA Extension | OCSP Extension | Purpose |
|------|----------------|----------------|----------|
| Local File Path | ❌ | ❌ | Internal use only |
| HTTP AIA | ✅ | ❌ | Client cert chain building |
| OCSP URL | ❌ | ✅ | Real-time revocation |

✅ **No** `ldap://` or `file://` URLs.  
✅ Certificates embed **only** HTTP and OCSP URLs.

---

## 8. Deep PKI Configuration Validation Script

Use this PowerShell validation script to confirm registry accuracy for CDP/AIA/OCSP settings.

```powershell
# --- Deep PKI Configuration Validation ---
Write-Host "=== PKI Validation Check ===" -ForegroundColor Cyan
$expectedCDP_HTTP = 'http://pki.lab.local/pkidata/'
$expectedAIA_HTTP = 'http://pki.lab.local/pkidata/'
$expectedOCSP = 'http://ocsp.lab.local/ocsp'

function Decode-Flags($value) {
  $f = @{}
  $f['CertCDP'] = ($value -band 0x04) -ne 0
  $f['CertAIA'] = ($value -band 0x10) -ne 0
  $f['CertOCSP'] = ($value -band 0x20) -ne 0
  return $f
}

$keys = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\*'
$urls = $keys | Get-Member -MemberType NoteProperty | ForEach-Object { $keys.$($_.Name) }

foreach ($entry in $urls) {
  $url, $val = $entry -split '\s+'
  $decoded = Decode-Flags([int]$val)
  if ($url -match $expectedCDP_HTTP -and $decoded['CertCDP']) { Write-Host "CDP OK ✅ $url" -ForegroundColor Green }
  elseif ($url -match $expectedAIA_HTTP -and $decoded['CertAIA']) { Write-Host "AIA OK ✅ $url" -ForegroundColor Green }
  elseif ($url -match $expectedOCSP -and $decoded['CertOCSP']) { Write-Host "OCSP OK ✅ $url" -ForegroundColor Green }
  elseif ($url -match 'ldap|file') { Write-Host "Legacy URL ❌ $url" -ForegroundColor Red }
}

Write-Host "=== Validation Complete ===" -ForegroundColor Cyan
```

---

## 9. Final Notes

- Always run the validation script after modifying CA URLs.
- Maintain **only HTTP (AIA/CDP)** and **OCSP HTTP** entries — no LDAP/file.
- Replicate CRL/AIA files across both IIS web servers via DFS.
- Back up the Root CA `.crt` and `.crl` securely offline.
- Document each CRL renewal and Root CA publishing event.

✅ **Result:** Fully modern, Microsoft‑compliant, two‑tier PKI ready for production operations.