# 🧱 PKI Infrastructure Deployment Guide – Parameterized Version

Modern, domain-integrated Public Key Infrastructure (PKI) featuring an **Offline Root CA**, two **Enterprise Issuing CAs**, redundant **HTTP/OCSP namespaces**, and full PowerShell-based automation.

This guide is **parameterized** for easy migration from lab to production environments.

---

## 🔧 Configuration Variables

**Set these variables at the beginning of your deployment. All commands below will reference these values.**

### Lab Environment (Current)

```powershell
# Domain and Namespace
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"

# HTTP Namespaces
$PkiHttpHost      = "pki.lab.local"
$OcspHttpHost     = "ocsp.lab.local"

# Server Hostnames
$DC1              = "dc1.lab.local"
$DC2              = "dc2.lab.local"
$FileServer1      = "file1.lab.local"
$FileServer2      = "file2.lab.local"
$RootCA           = "caroot1.lab.local"
$SubCA1           = "subca1.lab.local"
$SubCA2           = "subca2.lab.local"
$WebServer1       = "web01.lab.local"
$WebServer2       = "web02.lab.local"
$OcspServer1      = "ocsp1.lab.local"
$OcspServer2      = "ocsp2.lab.local"

# CA Names
$RootCAName       = "Lab Root CA"
$SubCA1Name       = "Lab Issuing CA - Site1"
$SubCA2Name       = "Lab Issuing CA - Site2"

# Service Account
$PkiWebSvcAccount = "PKIWebSvc"

# Derived Paths (DO NOT EDIT - auto-calculated)
$DfsPkiPath       = "$DfsRoot\$PkiFolderName"
$PkiHttpBase      = "http://$PkiHttpHost/pkidata"
$OcspHttpBase     = "http://$OcspHttpHost/ocsp"
$LocalPkiFolder   = "C:\$PkiFolderName"
$ShareName        = $PkiFolderName
```

### Production Environment (Example - Update as needed)

```powershell
# Domain and Namespace
$DomainFqdn       = "name1.name2.name3"
$DomainNetBios    = "PROD"
$DfsRoot          = "\\name1.name2.name3\share"
$PkiFolderName    = "PKIData"

# HTTP Namespaces
$PkiHttpHost      = "pki.name1.name2.name3"
$OcspHttpHost     = "ocsp.name1.name2.name3"

# Server Hostnames
$DC1              = "dc1.name1.name2.name3"
$DC2              = "dc2.name1.name2.name3"
$FileServer1      = "file1.name1.name2.name3"
$FileServer2      = "file2.name1.name2.name3"
$RootCA           = "caroot1.name1.name2.name3"
$SubCA1           = "subca1.name1.name2.name3"
$SubCA2           = "subca2.name1.name2.name3"
$WebServer1       = "web01.name1.name2.name3"
$WebServer2       = "web02.name1.name2.name3"
$OcspServer1      = "ocsp1.name1.name2.name3"
$OcspServer2      = "ocsp2.name1.name2.name3"

# CA Names
$RootCAName       = "Corp Root CA"
$SubCA1Name       = "Corp Issuing CA - Region1"
$SubCA2Name       = "Corp Issuing CA - Region2"

# Service Account
$PkiWebSvcAccount = "PKIWebSvc"

# Derived Paths (DO NOT EDIT - auto-calculated)
$DfsPkiPath       = "$DfsRoot\$PkiFolderName"
$PkiHttpBase      = "http://$PkiHttpHost/pkidata"
$OcspHttpBase     = "http://$OcspHttpHost/ocsp"
$LocalPkiFolder   = "C:\$PkiFolderName"
$ShareName        = $PkiFolderName
```

---

## 1. Overview & Environment

| Component | Function | Hostname (Variable) | Location |
|-----------|----------|---------------------|----------|
| Domain Controller | AD DS | `$DC1` / `$DC2` | Site 1 / Site 2 |
| File Server | PKIData storage / DFS | `$FileServer1` / `$FileServer2` | Site 1 / Site 2 |
| Root CA | Offline standalone | `$RootCA` | Vault |
| Issuing CA (Site 1) | Enterprise subordinate CA | `$SubCA1` | Site 1 |
| Issuing CA (Site 2) | Enterprise subordinate CA | `$SubCA2` | Site 2 |
| Web Server (Site 1) | IIS AIA/CDP HTTP | `$WebServer1` | Site 1 |
| Web Server (Site 2) | IIS AIA/CDP HTTP | `$WebServer2` | Site 2 |
| OCSP Responder (Site 1) | Revocation (OCSP) | `$OcspServer1` | Site 1 |
| OCSP Responder (Site 2) | Revocation (OCSP) | `$OcspServer2` | Site 2 |

**Primary Namespaces**

- HTTP (AIA/CDP): `$PkiHttpBase/` (e.g., `http://pki.lab.local/pkidata/`)
- OCSP: `$OcspHttpBase` (e.g., `http://ocsp.lab.local/ocsp`)

**DFS Share (for PKI Data):** `$DfsPkiPath` (e.g., `\\lab.local\share\PKIData`)

**NetBIOS name:** `$DomainNetBios` (e.g., `LAB`)

---

## 2. Network & DNS Configuration

Using **DNS-based HA failover** (no load balancer required):

| Record | Target | Purpose |
|--------|--------|---------|
| `$WebServer1` | IP of Web Server 1 | IIS Host Site 1 |
| `$WebServer2` | IP of Web Server 2 | IIS Host Site 2 |
| `$OcspServer1` | IP of OCSP Server 1 | OCSP Site 1 |
| `$OcspServer2` | IP of OCSP Server 2 | OCSP Site 2 |
| `$PkiHttpHost` | IP of Web Server 1 & 2 | HTTP AIA/CDP namespace |
| `$OcspHttpHost` | IP of OCSP Server 1 & 2 | OCSP namespace |

**TTL Recommendation:** 60–120 seconds for fast DNS failover between regions.

---

## 3. DFS and File Permissions

We host `$LocalPkiFolder` (e.g., `C:\PKIData`) on both file servers and expose it via DFS as `$DfsPkiPath` (e.g., `\\lab.local\share\PKIData`).

### 3.1 Create Folder and Share (Both File Servers)

Run on **both** `$FileServer1` and `$FileServer2`:

```powershell
# Create local folder
$folderPath = $LocalPkiFolder
if (-Not (Test-Path $folderPath)) { 
    New-Item -Path $folderPath -ItemType Directory 
}

# Create SMB share
$shareName = $ShareName
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

### 3.2 Grant Machine Permissions for PKI Roles

These machine accounts will publish/read PKI data:

- SubCAs: `$SubCA1`, `$SubCA2`
- Web: `$WebServer1`, `$WebServer2`
- OCSP: `$OcspServer1`, `$OcspServer2`

Run on **both** `$FileServer1` and `$FileServer2`:

```powershell
# Extract short hostnames for machine accounts
$SubCA1Short = ($SubCA1 -split '\.')[0]
$SubCA2Short = ($SubCA2 -split '\.')[0]
$Web1Short = ($WebServer1 -split '\.')[0]
$Web2Short = ($WebServer2 -split '\.')[0]
$Ocsp1Short = ($OcspServer1 -split '\.')[0]
$Ocsp2Short = ($OcspServer2 -split '\.')[0]

# Share Access
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$SubCA1Short`$" -AccessRight Change -Force
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$SubCA2Short`$" -AccessRight Change -Force
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$Web1Short`$" -AccessRight Read -Force
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$Web2Short`$" -AccessRight Read -Force
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$Ocsp1Short`$" -AccessRight Read -Force
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$Ocsp2Short`$" -AccessRight Read -Force

# NTFS Permissions
icacls $LocalPkiFolder /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
icacls $LocalPkiFolder /grant "$DomainNetBios\$SubCA1Short`$:(OI)(CI)M" /T
icacls $LocalPkiFolder /grant "$DomainNetBios\$SubCA2Short`$:(OI)(CI)M" /T
icacls $LocalPkiFolder /grant "$DomainNetBios\$Web1Short`$:(OI)(CI)RX" /T
icacls $LocalPkiFolder /grant "$DomainNetBios\$Web2Short`$:(OI)(CI)RX" /T
icacls $LocalPkiFolder /grant "$DomainNetBios\$Ocsp1Short`$:(OI)(CI)RX" /T
icacls $LocalPkiFolder /grant "$DomainNetBios\$Ocsp2Short`$:(OI)(CI)RX" /T
```

### 3.3 Create DFS Namespace and Folder (Domain Controller)

Run on `$DC1` or `$DC2`:

```powershell
# Install DFS if not already installed
Install-WindowsFeature FS-DFS-Namespace, FS-DFS-Replication, RSAT-DFS-Mgmt-Con -IncludeManagementTools

# Create DFS namespace root if it doesn't exist
$DfsRootPath = $DfsRoot
$DfsRootName = ($DfsRoot -split '\\')[-1]  # e.g., "share"
$DfsNamespace = "$DomainFqdn\$DfsRootName"

if (-Not (Get-DfsnRoot -Path $DfsRootPath -ErrorAction SilentlyContinue)) {
    New-DfsnRoot -Path $DfsRootPath -TargetPath "\\$DC1\$DfsRootName" -Type DomainV2
}

# Create DFS folder for PKIData
$DfsPkiFullPath = "$DfsRootPath\$PkiFolderName"
if (-Not (Get-DfsnFolder -Path $DfsPkiFullPath -ErrorAction SilentlyContinue)) {
    New-DfsnFolder -Path $DfsPkiFullPath -TargetPath "\\$($FileServer1 -split '\.')[0]\$ShareName"
}

# Add second file server as DFS target
$FileServer1Short = ($FileServer1 -split '\.')[0]
$FileServer2Short = ($FileServer2 -split '\.')[0]
Add-DfsnFolderTarget -Path $DfsPkiFullPath -TargetPath "\\$FileServer2Short\$ShareName"

# Verify DFS configuration
Get-DfsnFolder -Path $DfsPkiFullPath | Get-DfsnFolderTarget
```

---

## 4. Web Server (IIS) Configuration

Web servers: `$WebServer1`, `$WebServer2`  
PKI data via DFS: `$DfsPkiPath`  
Service account: `$DomainNetBios\$PkiWebSvcAccount`

### 4.1 Install IIS (Both Web Servers)

Run on **both** `$WebServer1` and `$WebServer2`:

```powershell
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

### 4.2 Create Service Account and Permissions

#### 4.2.1 Create service account & group (Domain Controller)

Run on `$DC1` or `$DC2`:

```powershell
$pwd = Read-Host -Prompt "Enter password for $PkiWebSvcAccount" -AsSecureString

New-ADUser -Name $PkiWebSvcAccount `
    -SamAccountName $PkiWebSvcAccount `
    -AccountPassword $pwd `
    -Enabled $true `
    -PasswordNeverExpires $false

New-ADGroup -Name 'PKI Web Servers' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'PKI Web Servers' -Members $PkiWebSvcAccount
```

#### 4.2.2 Grant PKIWebSvc access to PKIData (Both File Servers)

Run on **both** `$FileServer1` and `$FileServer2`:

```powershell
Grant-SmbShareAccess -Name $ShareName -AccountName "$DomainNetBios\$PkiWebSvcAccount" -AccessRight Change -Force
icacls $LocalPkiFolder /grant "$DomainNetBios\$PkiWebSvcAccount:(OI)(CI)M" /T
```

### 4.3 Configure IIS Application Pool Identity (Both Web Servers)

Set **DefaultAppPool** to run as # --- VARIABLES ---
$DomainNetBios    = "LAB"
$PkiWebSvcAccount = "PKIWebSvc"

# --- INSTALL IIS ---
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools

Import-Module WebAdministration

# --- GET PASSWORD SECURELY ---
$passwordPlain = Read-Host -Prompt "Enter password for $DomainNetBios\$PkiWebSvcAccount"
# NOTE: WebAdministration wants the clear text password string

# --- SET APP POOL IDENTITY TO DOMAIN USER ---
# identityType 3 = SpecificUser
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.identityType -Value 3

# Use the fully qualified domain\user from variables
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.userName -Value "$DomainNetBios\$PkiWebSvcAccount"

# Set the clear-text password string (what IIS actually wants here)
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.password -Value $passwordPlain

# Restart app pool
Restart-WebAppPool DefaultAppPool
```

### 4.4 Create IIS Binding for PKI HTTP Host (Both Web Servers)

Run on **both** `$WebServer1` and `$WebServer2`:

```powershell
Import-Module WebAdministration

# Add binding for pki.domain.com
$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-Not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}
```

### 4.5 Create Virtual Directory for PKI Data (Both Web Servers)

Run on **both** `$WebServer1` and `$WebServer2`:

```powershell
Import-Module WebAdministration

Remove-WebVirtualDirectory -Site 'Default Web Site' -Name 'pkidata' -ErrorAction SilentlyContinue

$vDirProperties = @{
    Site         = 'Default Web Site'
    Name         = 'pkidata'
    PhysicalPath = $DfsPkiPath
}
New-WebVirtualDirectory @vDirProperties
```

### 4.6 Enable Directory Browsing and MIME Types (Both Web Servers)

Run on **both** `$WebServer1` and `$WebServer2`:

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

---

## 5. Offline Root CA Setup

Root CA host: `$RootCA`  
CA Common Name: `$RootCAName`

### 5.1 Create CAPolicy.inf (Root CA)

Run on `$RootCA`:

```powershell
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"
[InternalPolicy]
URL=$PkiHttpBase/cps.html
[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent
```

### 5.2 Install AD CS Role and Root CA (Root CA)

Run on `$RootCA`:

```powershell
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

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
Install-AdcsCertificationAuthority @vCaRootProperties -Force -OverwriteExistingKey
```

### 5.3 Configure Validity and CRL Settings (Root CA)

Run on `$RootCA`:

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

### 5.4 Configure CDP and AIA (Root CA)

Run on `$RootCA`:

```powershell
# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# Local CRL publish
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# HTTP CDP embedded in issued certs
Add-CACRLDistributionPoint -Uri "$PkiHttpBase/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force

# Clear existing AIA entries
Get-CAAuthorityInformationAccess |
    Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } |
    Remove-CAAuthorityInformationAccess -Force

# Local AIA
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt'

# HTTP AIA embedded in issued certs
Add-CAAuthorityInformationAccess -AddToCertificateAia "$PkiHttpBase/%3%4.crt" -Force
```

### 5.5 Publish Initial CRL and Copy to PKIData (Root CA)

Run on `$RootCA`:

```powershell
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -CRL

# Get the actual filename
$rootCertFile = Get-ChildItem "C:\Windows\System32\CertSrv\CertEnroll" -Filter "*$RootCAName.crt" | Select-Object -First 1
$rootCrlFile = Get-ChildItem "C:\Windows\System32\CertSrv\CertEnroll" -Filter "*$RootCAName.crl" | Select-Object -First 1

# Rename to clean names
Rename-Item $rootCertFile.FullName "$RootCAName.crt" -Force
Rename-Item $rootCrlFile.FullName "$RootCAName.crl" -Force

# Open folder for manual copy
explorer.exe "C:\Windows\System32\CertSrv\CertEnroll"
```

**Manual step:** Copy these files from `$RootCA` to `$DfsPkiPath`:

- `$RootCAName.crt`
- `$RootCAName.crl`

Then publish to AD (run on `$RootCA` or a domain-joined machine with access to DFS):

```powershell
certutil -dspublish -f "$DfsPkiPath\$RootCAName.crt" RootCA
certutil -dspublish -f "$DfsPkiPath\$RootCAName.crl" "$RootCAName"
```

---

## 6. Issuing CAs – SubCA1 & SubCA2

Issuing CAs:

- `$SubCA1` → `$SubCA1Name`
- `$SubCA2` → `$SubCA2Name`

### 6.0.1 Install Issuing CA on SubCA1

Run on `$SubCA1`:

```powershell
# CAPolicy.inf
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"
[InternalPolicy]
URL=$PkiHttpBase/cps.html
[Certsrv_Server]
LoadDefaultTemplates=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = $SubCA1Name
  CADistinguishedNameSuffix = 'O=PKI,L=Site1,S=State1,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = $LocalPkiFolder
  OutputCertRequestFile     = "$LocalPkiFolder\subca1_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey

explorer $LocalPkiFolder
```

**Manual step:** Copy `subca1_request.req` to `$RootCA` at `C:\PKIData\`.

### 6.0.2 Approve and Install SubCA1 Certificate (Root CA)

Run on `$RootCA`:

```powershell
certreq -submit C:\PKIData\subca1_request.req C:\PKIData\subca1_issued.cer
certutil -resubmit <RequestID>
certreq -retrieve <RequestID> C:\PKIData\subca1_issued.cer
```

**Manual step:** Copy `subca1_issued.cer` back to `$SubCA1`, install via CA MMC (Install CA Certificate), then:

Run on `$SubCA1`:

```powershell
Start-Service certsvc
```

### 6.0.3 Install Issuing CA on SubCA2

Run on `$SubCA2`:

```powershell
# CAPolicy.inf
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"
[InternalPolicy]
URL=$PkiHttpBase/cps.html
[Certsrv_Server]
LoadDefaultTemplates=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = $SubCA2Name
  CADistinguishedNameSuffix = 'O=PKI,L=Site2,S=State2,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = $LocalPkiFolder
  OutputCertRequestFile     = "$LocalPkiFolder\subca2_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey

explorer $LocalPkiFolder
```

**Manual step:** Copy `subca2_request.req` to `$RootCA` at `C:\PKIData\`.

### 6.0.4 Approve and Install SubCA2 Certificate (Root CA)

Run on `$RootCA`:

```powershell
certreq -submit C:\PKIData\subca2_request.req C:\PKIData\subca2_issued.cer
certutil -getrequests
certutil -approve <RequestID>
certutil -retrieve <RequestID> C:\PKIData\subca2_issued.cer
```

**Manual step:** Copy `subca2_issued.cer` to `$SubCA2`, install via CA MMC, then:

Run on `$SubCA2`:

```powershell
Start-Service certsvc
```

### 6.1 Core Issuing CA Configuration (Run on BOTH SubCA1 and SubCA2)

Run on **both** `$SubCA1` and `$SubCA2`:

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
Add-CACRLDistributionPoint -Uri "$DfsPkiPath\%3%8.crl" -PublishToServer -Force
Add-CACRLDistributionPoint -Uri "$PkiHttpBase/%3%8.crl" -AddToCertificateCDP -Force

certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt\n2:$DfsPkiPath\%3%4.crt"
Add-CAAuthorityInformationAccess -AddToCertificateAia "$PkiHttpBase/%3%4.crt" -Force
Add-CAAuthorityInformationAccess -AddToCertificateOcsp "$OcspHttpBase" -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

### 6.1.1 Publish SubCA1 Certificate to AD

Run on `$SubCA1`:

```powershell
$SubCA1Short = ($SubCA1 -split '\.')[0]
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter "*$SubCA1Name*.crt" | Select-Object -First 1

if ($cer) {
    Rename-Item $cer.FullName "$SubCA1Name.crt" -Force
    $cer = Get-Item "C:\Windows\System32\CertSrv\CertEnroll\$SubCA1Name.crt"
    certutil -dspublish -f "$($cer.FullName)" NTAuthCA
    certutil -dspublish -f "$($cer.FullName)" SubCA
}
```

### 6.1.2 Publish SubCA2 Certificate to AD

Run on `$SubCA2`:

```powershell
$SubCA2Short = ($SubCA2 -split '\.')[0]
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter "*$SubCA2Name*.crt" | Select-Object -First 1

if ($cer) {
    Rename-Item $cer.FullName "$SubCA2Name.crt" -Force
    $cer = Get-Item "C:\Windows\System32\CertSrv\CertEnroll\$SubCA2Name.crt"
    certutil -dspublish -f "$($cer.FullName)" NTAuthCA
    certutil -dspublish -f "$($cer.FullName)" SubCA
}
```

---

## 6.2 Certificate Templates Configuration

Templates control what certificates can be issued, who can request them, and how they're used.

### Overview

| Template | Based On | Purpose | Autoenrollment | Publish to AD |
|----------|----------|---------|----------------|---------------|
| **PKI-WebServer** | Web Server | IIS and HTTPS endpoints | Yes | Yes |
| **PKI-OCSP** | OCSP Response Signing | OCSP role signing certs | No | No |
| **PKI-DCAuth** | Domain Controller Authentication | DC authentication, smart card logon | Yes | Yes |
| **PKI-LDAPS** | Computer | Secure LDAP over TLS | Yes | Yes |

### Steps (on SubCA1 or SubCA2)

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

Run on **both** `$SubCA1` and `$SubCA2`:

```powershell
certutil -SetCATemplates +PKI-WebServer +PKI-OCSP +PKI-DCAuth +PKI-LDAPS
```

### 6.2.6 Create OCSP Servers Group

Run on `$DC1` or `$DC2`:

```powershell
$Ocsp1Short = ($OcspServer1 -split '\.')[0]
$Ocsp2Short = ($OcspServer2 -split '\.')[0]

New-ADGroup -Name 'OCSP Servers' -GroupScope Global -GroupCategory Security -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity 'OCSP Servers' -Members "$Ocsp1Short`$","$Ocsp2Short`$"
```

---

## 6.3 Certificate Services & OCSP Role Installation

### 6.3.1 Install Web Enrollment on Web Servers

Run on **both** `$WebServer1` and `$WebServer2`:

```powershell
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsWebEnrollment -Confirm:$false
```

### 6.3.2 Install OCSP Responder Role

Run on **both** `$OcspServer1` and `$OcspServer2`:

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
Install-AdcsOnlineResponder -Confirm:$false
```

### 6.3.3 Request OCSP Signing Certificates

#### On OcspServer1 (for SubCA1)

Run on `$OcspServer1`:

```powershell
$Ocsp1Short = ($OcspServer1 -split '\.')[0]
$SubCA1Short = ($SubCA1 -split '\.')[0]

$ocspRequestContent = @"
[NewRequest]
Subject = "CN=OCSP Signing Certificate - $Ocsp1Short"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0x80

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.9
"@

Set-Content -Path C:\ocsp_request.inf -Value $ocspRequestContent

certreq -new C:\ocsp_request.inf C:\ocsp1.req

# Submit to SubCA1
certreq -submit -config "$SubCA1\$SubCA1Name" -attrib "CertificateTemplate:PKI-OCSP" C:\ocsp1.req C:\ocsp1.cer

# Install certificate
certreq -accept C:\ocsp1.cer
```

#### On OcspServer2 (for SubCA2)

Run on `$OcspServer2`:

```powershell
$Ocsp2Short = ($OcspServer2 -split '\.')[0]
$SubCA2Short = ($SubCA2 -split '\.')[0]

$ocspRequestContent = @"
[NewRequest]
Subject = "CN=OCSP Signing Certificate - $Ocsp2Short"
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0x80

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.9
"@

Set-Content -Path C:\ocsp_request.inf -Value $ocspRequestContent

certreq -new C:\ocsp_request.inf C:\ocsp2.req

# Submit to SubCA2
certreq -submit -config "$SubCA2\$SubCA2Name" -attrib "CertificateTemplate:PKI-OCSP" C:\ocsp2.req C:\ocsp2.cer

# Install certificate
certreq -accept C:\ocsp2.cer
```

### 6.3.4 Configure OCSP Revocation Configuration

#### On OcspServer1 (pointing to SubCA1)

1. Open **Online Responder Management** console (`ocsp.msc`).
2. Right-click **Revocation Configuration** → **Add Revocation Configuration**.
3. **Name**: `subca1-revocation`
4. **Select a CA certificate location**: Browse and select the `$SubCA1Name` certificate from `$DfsPkiPath\$SubCA1Name.crt`.
5. **Provider**: Select `Local Certificate`.
6. **Signing Certificate**: Select the OCSP signing certificate you just enrolled.
7. Click **Finish**.

#### On OcspServer2 (pointing to SubCA2)

1. Open **Online Responder Management** console (`ocsp.msc`).
2. Right-click **Revocation Configuration** → **Add Revocation Configuration**.
3. **Name**: `subca2-revocation`
4. **Select a CA certificate location**: Browse and select the `$SubCA2Name` certificate from `$DfsPkiPath\$SubCA2Name.crt`.
5. **Provider**: Select `Local Certificate`.
6. **Signing Certificate**: Select the OCSP signing certificate you just enrolled.
7. Click **Finish**.

---

## 6.4 Testing Template Deployment

### Test Web Server Certificate Enrollment

Run on `$WebServer1`:

```powershell
$Web1Short = ($WebServer1 -split '\.')[0]

# Force group policy update to get new templates
certutil -pulse

# Request a web server certificate
$cert = Get-Certificate -Template "PKI-WebServer" -CertStoreLocation Cert:\LocalMachine\My -DnsName $WebServer1
$cert
```

Run on `$WebServer2`:

```powershell
$Web2Short = ($WebServer2 -split '\.')[0]

certutil -pulse
$cert = Get-Certificate -Template "PKI-WebServer" -CertStoreLocation Cert:\LocalMachine\My -DnsName $WebServer2
$cert
```

### Test OCSP Signing Certificate

Run on `$OcspServer1`:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "OCSP" }
```

Run on `$OcspServer2`:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "OCSP" }
```

### Test OCSP Responder

From any domain-joined machine:

```powershell
# Test OcspServer1
certutil -url "$OcspHttpBase"

# Test OcspServer2
certutil -url "http://$OcspServer2/ocsp"
```

You should see "Verified" status for the OCSP responder.

---

## 7. Validation & Compliance Checklist

### CRL Distribution Points

| Setting | Local | UNC | HTTP |
|---------|-------|-----|------|
| Publish CRLs | ✅ | ✅ | ❌ |
| Delta CRLs | ✅ | ✅ | ❌ |
| Include in CDP extension | ❌ | ❌ | ✅ |

### Authority Information Access

| URL | AIA Extension | OCSP Extension | Purpose |
|-----|---------------|----------------|---------|
| Local File Path | ❌ | ❌ | Internal use only |
| HTTP AIA | ✅ | ❌ | Client cert chain building |
| OCSP URL | ❌ | ✅ | Real-time revocation |

✅ **No** `ldap://` or `file://` URLs in issued certificates.  
✅ Certificates embed **only** HTTP and OCSP URLs.

---

## 8. Deep PKI Configuration Validation Script

Run this on **both** `$SubCA1` and `$SubCA2` to validate CDP/AIA/OCSP configuration:

```powershell
Write-Host "=== PKI Configuration Validation ===" -ForegroundColor Cyan

$expectedCDP_HTTP = $PkiHttpBase
$expectedAIA_HTTP = $PkiHttpBase
$expectedOCSP = $OcspHttpBase

$caName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active
Write-Host "`nCA Name: $caName" -ForegroundColor Yellow

Write-Host "`n--- CRL Distribution Points ---" -ForegroundColor Yellow
$crlOutput = certutil -getreg CA\CRLPublicationURLs
$crlOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$') {
    $flags = [int]$matches[1]
    $url = $matches[2].Trim()
    $addToCertCDP = ($flags -band 0x02) -ne 0

    if ($url -match [regex]::Escape($expectedCDP_HTTP) -and $addToCertCDP) {
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

    if ($url -match [regex]::Escape($expectedAIA_HTTP) -and $addToAIA) {
      Write-Host "AIA OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match [regex]::Escape($expectedOCSP) -and $addToOCSP) {
      Write-Host "OCSP OK ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ocsp' -and $addToOCSP -and $url -notmatch [regex]::Escape($expectedOCSP)) {
      Write-Host "OCSP Wrong Domain ⚠️ $url (should be $expectedOCSP)" -ForegroundColor Yellow
    } elseif ($url -match 'ldap://|file://' -and ($addToAIA -or $addToOCSP)) {
      Write-Host "Legacy AIA/OCSP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan
```

**Expected Output (All Green):**

- CDP OK ✅ `$PkiHttpBase/%3%8.crl`
- AIA OK ✅ `$PkiHttpBase/%3%4.crt`
- OCSP OK ✅ `$OcspHttpBase`

---

## 9. Final Notes

- Always run the validation script after modifying CA URLs.
- Maintain **only HTTP (AIA/CDP)** and **OCSP HTTP** entries — no LDAP/file.
- Replicate CRL/AIA files across both IIS web servers via DFS.
- Back up the Root CA `.crt` and `.crl` securely offline.
- Document each CRL renewal and Root CA publishing event.
- Both issuing CAs should be configured identically except for their common names and locations.
- OCSP responders should point to their respective regional issuing CAs for optimal performance.

### Migration from Lab to Production

To migrate this PKI design from lab to production:

1. **Update the configuration variables** at the top of this guide (Section 0).
2. **Do NOT attempt to rename** the existing lab environment—rebuild from scratch using the new variables.
3. **Reuse all PowerShell commands** as-is—they will automatically use the new values.
4. **Test thoroughly** in the new environment before issuing production certificates.

✅ **Result:** Fully modern, Microsoft-compliant, two-tier PKI with redundant issuing CAs and OCSP responders ready for production operations.

---

## 🧩 Appendix A – Revoking an Issuing CA Certificate

**Purpose:**  
To invalidate a subordinate CA certificate when that CA is retired, compromised, or replaced by a renewal.

### A.1 Preconditions

- Root CA is **offline**, but accessible for revocation and CRL publication.  
- The certificate to revoke is **present on the Root CA** under `C:\PKIData`.

### A.2 Identify the Subordinate Certificate on the Root CA

Run on `$RootCA`:

```powershell
certutil -view -restrict "Certificate Template=SubCA"
```

If you're unsure, list all issued CA certificates:

```powershell
certutil -view -restrict "Issued Common Name=$SubCA1Name"
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
Copy-Item "C:\Windows\System32\CertSrv\CertEnroll\$RootCAName.crl" "$DfsPkiPath\"
```

Then publish it to AD:

```powershell
certutil -dspublish -f "$DfsPkiPath\$RootCAName.crl" "$RootCAName"
```

### A.5 Verify CRL Contains the Revoked SubCA

Check that the revoked CA's serial number appears in the CRL:

```powershell
certutil -dump "$RootCAName.crl" | findstr /i "<SerialNumber>"
```

A successful entry appears under the CRL's "Revoked Certificates" list.

### A.6 Notify Administrators & Dependents

- Disable **CertSvc** on the revoked issuing CA:

  ```powershell
  Stop-Service certsvc
  Set-Service certsvc -StartupType Disabled
  ```

- Remove DNS A records if decommissioned.
- Update AIA/CDP hosting (remove old public `.crt`).
- Document the revocation reason and time.

### A.7 Optional – Replace the Revoked Issuing CA

If replacing the CA (e.g., due to renewal or compromise):

1. Deploy a new subordinate CA following **Section 6.0**.
2. Update all dependent services (OCSP responders, IIS, templates).
3. Validate using the **Deep PKI Validation Script** in Section 8.

---

**End of PKI Infrastructure Deployment Guide – Parameterized Version**