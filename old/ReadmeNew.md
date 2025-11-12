# PKI Lab: Offline Root CA + Two Enterprise Issuing CAs + HTTP AIA/CDP + Single OCSP + HA (DNS + DFS)

This manual provides step-by-step deployment instructions to build a two-tier Microsoft PKI for the [pkilab.win.us](http://pkilab.win.us) domain using your finalized hostnames and IPs. Every command is included in order with clear roles. No prior knowledge is assumed.

---

## Environment

- **AD Domain (FQDN):** [pkilab.win.us](http://pkilab.win.us)
- **NetBIOS domain name:** PKILAB
- **AD DCs:**
  - fldc1 10.10.1.201 (Florida)
  - nydc1 10.20.1.201 (New York)
- **Root CA (offline):** pkirootca 10.10.1.131
- **Issuing CAs:**
  - fliss1 10.10.1.211 (Florida) — CA name: PKILab Issuing CA - FL
  - nyiss1 10.20.1.211 (New York) — CA name: PKILab Issuing CA - NY
- **Web servers (IIS for AIA/CDP HTTP):**
  - flweb1 10.10.1.241 (Florida)
  - nyweb1 10.20.1.241 (New York)
- **OCSP responders:**
  - flocsp 10.10.1.221 (Florida)
  - nyocsp1 10.20.1.221 (New York)
- **HTTP namespace (single, HA via DNS):** [http://pki.pkilab.win.us/](http://pki.pkilab.win.us/)
- **OCSP namespace (single, HA via DNS):** [http://ocsp.pkilab.win.us/ocsp](http://ocsp.pkilab.win.us/ocsp)
- **DFS path for pkidata:** `\\pkilab.win.us\share\PKIData`

---

## ADCS Variables in File Paths

- `%3` = CA Common Name
- `%4` = Certificate name suffix (renewal number)
- `%8` = CRL name suffix (CRL number + renewal)

**Examples:**
- `%3%8.crl` -> PKILab Issuing CA - FL.crl13 (with CRL numbering)
- `%3%4.crt` -> PKILab Issuing CA - FL.crt13 (with renewal suffix)

---

# 1. DNS (No Load Balancer; DNS-Based Failover)

**Purpose:** Provide stable HTTP and OCSP namespaces with fast failover.

On a DNS server hosting `pkilab.win.us`, create the following **A records**:

| Hostname               | IP Address     |
|------------------------|----------------|
| flweb1.pkilab.win.us   | 10.10.1.241    |
| nyweb1.pkilab.win.us   | 10.20.1.241    |
| flocsp.pkilab.win.us   | 10.10.1.221    |
| nyocsp1.pkilab.win.us  | 10.20.1.221    |
| pki.pkilab.win.us      | 10.10.1.241    |
| pki.pkilab.win.us      | 10.20.1.241    |
| ocsp.pkilab.win.us     | 10.10.1.221    |
| ocsp.pkilab.win.us     | 10.20.1.221    |

- Set TTL to 60-0120 seconds for `pki.pkilab.win.us` and `ocsp.pkilab.win.us` to enable quick failover.

**Note:**
A single HTTP namespace for CDP/AIA/OCSP keeps URLs embedded in certificates stable for the PKI lifetime.

---

# 2. DFS Namespace Setup

# Create the folder if it doesn't exist
$folderPath = "C:\PKIData"
if (-Not (Test-Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
}

# Create the SMB share if it doesn't exist
$shareName = "PKIData"
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}

# Set Share Permissions
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\txsubca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\lvsubca1$" -AccessRight Change -Force
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\txweb1$" -AccessRight Read -Force
Grant-SmbShareAccess -Name $shareName -AccountName "lab.local\lvweb1$" -AccessRight Read -Force

# Set NTFS Permissions recursively with single quotes to handle $ in account names
icacls $folderPath /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T
icacls $folderPath /grant 'lab.local\txsubca1$:(OI)(CI)M' /grant 'lab.local\lvsubca1$:(OI)(CI)M' /T
icacls $folderPath /grant 'lab.local\txweb1$:(OI)(CI)RX' /grant 'lab.local\lvweb1$:(OI)(CI)RX' /T

Write-Host "Share and NTFS permissions set successfully on $env:COMPUTERNAME"

---

# 3. Offline Root CA 	6 pkirootca (Kept Offline)

**Purpose:** Establish the trust anchor. Configure AIA/CDP so clients know where to fetch the root CA cert and CRL. Manually transfer files to DFS and publish to AD.

### 3.1 Create CAPolicy.inf

```powershell
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.pkilab.win.us/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'RenewalKeyLength=4096'
Add-Content C:\Windows\CAPolicy.inf 'RenewalValidityPeriod=Years'
Add-Content C:\Windows\CAPolicy.inf 'RenewalValidityPeriodUnits=20'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'
Add-Content C:\Windows\CAPolicy.inf 'AlternateSignatureAlgorithm=0'
```

### 3.2 Install AD CS Role and Root CA

```powershell
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaRootProperties = @{
  CACommonName    = 'PKILab Root CA'
  CADistinguishedNameSuffix   = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
  CAType    = 'StandaloneRootCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  ValidityPeriod    = 'Years'
  ValidityPeriodUnits    = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force -OverwriteExistingKey
```

### 3.3 Configure Validity and CRL Settings

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

### 3.4 Configure CDP and AIA

```powershell
# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# Add CDP publish locations (UNC and local)
Add-CACRLDistributionPoint -Uri '\\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# Add HTTP CDP embedded in issued certs
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# Clear existing AIA entries
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force

# Set AIA publish locations (local and UNC)
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\\pkilab.win.us\share\PKIData\%3%4.crt'

# Add HTTP AIA embedded in issued certs
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force
```

### 3.5 Publish Initial CRL and Restart Service

```powershell
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

### 3.6 Manual Transfer (Root is Offline)

1. Copy from pkirootca (CertEnroll folder) to removable media:
   - `PKILab Root CA.crt`
   - `PKILab Root CA.crl`

2. Place into DFS path using any domain-joined machine:
   `\\pkilab.win.us\share\PKIData`

3. From a domain-joined admin machine, publish to AD:

```powershell
certutil -dspublish -f "\\pkilab.win.us\share\PKIData\PKILab Root CA.crt" rootca
certutil -dspublish -f "\\pkilab.win.us\share\PKIData\PKILab Root CA.crl" "PKILab Root CA"

# Verify enterprise root store
certutil -viewstore -enterprise Root
```

**Power off pkirootca when not in use.**

---

# 4. Issuing CAs 	6 fliss1 (FL) and nyiss1 (NY)

**Purpose:** Two enterprise issuing CAs for HA. Each publishes CRLs locally; issued certs embed a single HTTP CDP/AIA URL pointing to [pki.pkilab.win.us](http://pki.pkilab.win.us).

---

## 4.1 Install Issuing CA on fliss1

```powershell
# CAPolicy.inf (prevents default templates auto-load)
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.pkilab.win.us/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'

# Role and request
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName    = 'PKILab Issuing CA - FL'
  CADistinguishedNameSuffix = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
  CAType    = 'EnterpriseSubordinateCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  DatabaseDirectory    = 'C:\pkidata'
  OutputCertRequestFile    = 'C:\pkidata\pkilab_issuing_fl.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

---

## 4.2 Enroll/Issue SubCA Cert from the Root CA

- Copy `C:\pkidata\pkilab_issuing_fl.req` to pkirootca (power on temporarily).

- On pkirootca, submit, approve, and download the issuing CA certificate:

```powershell
# Submit the request
certreq -submit C:\pkidata\pkilab_issuing_fl.req C:\pkidata\pkilab_issuing_fl.cer

# Approve the request (requires CA admin privileges)
certutil -getrequests
certutil -approve <RequestID>

# Download the issued certificate
certutil -retrieve <RequestID> C:\pkidata\pkilab_issuing_fl.cer
```

- On fliss1, open Certification Authority console, right-click the stopped CA, choose **Install new key/certificate**, and select the issued `.cer`.

- Start the Certification Authority service.

---

## 4.3 Configure Validity, CDP, AIA, and OCSP on fliss1

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
Add-CACRLDistributionPoint -Uri '\\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# CDP embedded in issued certs (HTTP only)
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA publish locations (UNC and local)
certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\\pkilab.win.us\share\PKIData\%3%4.crt"

# AIA embedded in issued certs (HTTP only)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

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

## 4.4 Publish Issuing CA - FL to AD

From fliss1 or any domain-joined admin machine:

```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*PKILab Issuing CA - FL*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

---

## 4.5 Ensure Required Files for PKIView Are Copied to DFS pkidata Folder

- `C:\Windows\System32\CertSrv\CertEnroll\PKILab Issuing CA - FL.crl`
- `C:\Windows\System32\CertSrv\CertEnroll\PKILab Issuing CA - FL+.crl`
- `C:\pkidata\pkilab_issuing_fl.req.crt`

---

## 4.6 Repeat Steps 4.1 to 4.5 for nyiss1 with NY Names

Use the same commands as above, replacing FL names with NY.

---

# 5. Certificate Templates Creation and Publishing on Issuing CAs

---

## 5.1 Create and Publish Certificate Templates

Perform template creation with `certtmpl.msc` (Certificate Templates MMC). Then publish templates on each Issuing CA (`certsrv.msc` > Certification Authority > Certificate Templates > New > Certificate Template to Issue).

### A) Web Server Certificate (for IIS/LDAPS/HTTPS)

- Base: Duplicate "Web Server" (Windows Server 2016+ compatibility).
- Template display name: PKILab Web Server
- Template name: PKILabWebServer
- Validity: 2 years; Renewal period: 6 weeks (adjust as desired).
- Subject Name: Supply in the request (allow SAN). For AD autoenroll, you may prefer "Build from AD information" if names are predictable.
- Cryptography: KSP; 2048 or 4096-bit RSA; allow private key export (optional).
- Extensions (EKU): Server Authentication only (remove others).
- Security: Grant Read/Enroll/Autoenroll to PKI Web Servers. Grant Read/Enroll to admins as needed.
- Publish on both Issuing CAs.

### B) OCSP Response Signing (for OCSP responders)

- Use built-in template "OCSP Response Signing" (do not duplicate unless needed).
- Security: Grant Read/Enroll/Autoenroll to PKI OCSP Servers.
- Ensure Autoenrollment GPO applies to OCSP servers.
- Publish on both Issuing CAs.

### C) Computer (Machine) Certificate (for domain members, LDAPS, Wi-Fi, etc.)

- Use built-in "Computer" template.
- Security: Domain Computers already have Enroll/Autoenroll by default (verify).
- Publish on both Issuing CAs as needed.

### D) Domain Controller Authentication (Smart Card/LDAPS readiness)

- Use built-in "Domain Controller Authentication" template.
- Security: Domain Controllers group should have Enroll/Autoenroll.
- Publish on both Issuing CAs.
- Validate on each DC:

```powershell
# On each DC
gpupdate /force
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'Server Authentication|Client Authentication' }
```

### E) User Certificate (for client auth/SMIME; required for some Horizon use-cases)

- Base: Duplicate "User".
- Template display name: PKILab User
- Template name: PKILabUser
- Validity: 1	2 years; Renewal: 6 weeks.
- Subject Name: Build from AD (UPN/email).
- Extensions (EKU): Client Authentication (and optionally Secure Email if SMIME required).
- Security: Grant Read/Enroll/Autoenroll to appropriate user groups (e.g., Domain Users or a scoped group).
- Publish on both Issuing CAs as needed.

### F) Horizon VDI (Omnissa) 	6 Choose ONE Path

#### Path 1: Horizon True SSO (Recommended)

- Requires an Enrollment Server and integration with AD CS.
- Templates:
  1. Enrollment Agent certificate for the Enrollment Server: Use built-in "Enrollment Agent" (or duplicate) and issue to the Enrollment Server service account/computer as per Omnissa guidance.
  2. True SSO User Logon certificate template (short-lived user logon certs):
     - Base: Duplicate "Smartcard Logon" or "User" and include EKUs: Smart Card Logon + Client Authentication.
     - Subject Name: Supply in request (UPN in SAN). Allow subject alternative name: UPN.
     - Validity: very short (e.g., 8 hours). Renewal: not applicable (non-renewed short-lived).
     - Security: Grant Enroll to the Enrollment Server (service/computer) and Horizon Connection Servers per vendor guidance (PKI Horizon Enrollment group).
     - Cryptography: KSP, RSA 2048+, no export needed.
- Publish both templates on both Issuing CAs.

#### Path 2: Classic Smart Card Logon (Physical/Smart Card Based)

- Template: Duplicate "Smartcard Logon".
- EKUs: Smart Card Logon + Client Authentication.
- Subject: Supply in request (UPN in SAN), enforce KDC mapping.
- Security: Enroll permissions to issuance process or users; typically not autoenrolled.

---

# 6. Web Servers Setup (flweb1 and nyweb1)

---

## 6.1 IIS Installation and Configuration

On **flweb1** and **nyweb1** (run PowerShell as Administrator):

```powershell
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

---

## 6.2 PKIWebSvc Account and Permissions Setup

Create and configure the `PKIWebSvc` service account to allow IIS to access the DFS share.

On a domain-joined admin machine, run:

```powershell
# Create PKIWebSvc account in Users container (adjust OU as needed)
$pwd = Read-Host -Prompt 'Enter password for PKIWebSvc' -AsSecureString
New-ADUser -Name 'PKIWebSvc' -SamAccountName 'PKIWebSvc' -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $false -Path 'CN=Users,DC=pkilab,DC=win,DC=us' -PassThru

# Add PKIWebSvc to PKI Web Servers group (create group if not existing)
Add-ADGroupMember -Identity 'PKI Web Servers' -Members 'PKIWebSvc'

# Grant NTFS and Share permissions on DFS targets (run on each file server hosting DFS targets)
Grant-SmbShareAccess -Name 'PKIData' -AccountName 'PKILAB\PKIWebSvc' -AccessRight Change -Force
icacls 'C:\PKIData' /grant "PKILAB\PKIWebSvc:(OI)(CI)M" /T
```

---

## 6.3 Configure IIS Application Pool

On each IIS web server (flweb1, nyweb1), configure the IIS Application Pool to run as `PKIWebSvc`:

```powershell
Import-Module WebAdministration
Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel -Value @{userName='PKILAB\PKIWebSvc';password='<password>'}
Restart-WebAppPool DefaultAppPool
```

Replace `<password>` with the actual password set for `PKIWebSvc`.

---

## 6.4 Create IIS Virtual Directory to DFS Path

```powershell
$vDirProperties = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\pkilab.win.us\share\PKIData' }
New-WebVirtualDirectory @vDirProperties
```

---

## 6.5 Enable Directory Browsing and Allow Double-Escaping

```powershell
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value true -PSPath "IIS:\Sites\$($vDirProperties.Site)\$($vDirProperties.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value true -PSPath "IIS:\Sites\$($vDirProperties.Site)"
```

---

## 6.6 Add MIME Types for CRL/CRT and Set Basic Caching Headers

```powershell
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}

# Optional: set cache-control for pkidata
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$($vDirProperties.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}
```

---

## 6.7 Install Web Enrollment Role on Web Servers

On each web server (flweb1 and nyweb1), install the Web Enrollment role:

```powershell
Install-WindowsFeature -Name Web-Enrollment -IncludeManagementTools
```

---

## 6.8 Create AD Security Group for Web Enrollment Access

```powershell
New-ADGroup -Name "PKI Web Enrollment Users" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=pkilab,DC=win,DC=us"
```

Add users who should have access to this group.

---

## 6.9 Configure SSL for Web Enrollment

Bind the SSL certificate to the Default Web Site in IIS to secure `/certsrv`:

1. Open IIS Manager.
2. Select Default Web Site.
3. Click "Bindings..." on the right.
4. Add or edit the HTTPS binding to use the SSL certificate issued to the web server.

---

## 6.10 Restrict Access to `/certsrv`

Configure IIS to restrict access to the `/certsrv` virtual directory to members of the "PKI Web Enrollment Users" group:

1. In IIS Manager, navigate to the `/certsrv` virtual directory.
2. Open "Authorization Rules".
3. Remove the default "Allow All Users" rule.
4. Add an "Allow" rule for the "PKI Web Enrollment Users" group.

---

## 6.11 Configure HTTP to HTTPS Redirection

To ensure secure access, configure HTTP to HTTPS redirection for the Default Web Site:

1. In IIS Manager, select Default Web Site.
2. Open "HTTP Redirect".
3. Enable redirect and specify the destination as `https://<webserver_fqdn>/`.
4. Check "Only redirect requests to content in this directory".

---

## 6.12 Request and Install Web Server Certificates

- Use the **PKILab Web Server** certificate template created earlier.
- Request certificates for `flweb1.pkilab.win.us` and `nyweb1.pkilab.win.us` from the Issuing CAs.
- Install the certificates on the respective web servers.
- Bind the certificates to IIS HTTPS bindings as shown in the validation section.

---

# 7. OCSP Responders 	6 flocsp and nyocsp1 (Single URL)

---

## 7.1 Install Online Responder Role

On each OCSP server:

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
```

---

## 7.2 Configure AIA on Issuing CAs

Ensure AIA includes the single OCSP URL:

- `ocsp:http://ocsp.pkilab.win.us/ocsp` (checked to include in AIA of issued certs)
- Restart each CA service after configuration.

---

## 7.3 Configure Online Responder Management

On flocsp and nyocsp1:

- Create a Revocation Configuration per Issuing CA (two configs per server: FL and NY CA).
- Provider: Microsoft CRL-based Revocation.
- Ensure OCSP servers can read Issuing CA CRLs (HTTP or AD CDP access).
- Enroll "OCSP Response Signing" certificates (autoenroll or manual).
- Confirm status = Online.

---

## 7.4 Validation from Any Domain-Joined Machine

```powershell
certutil -url <path-to-an-end-entity.cer>
# Select OCSP, click Retrieve; flip ocsp DNS to validate failover.
```

---

# 8. Important Notes for PKIView and CRL Publishing

---

- Ensure all files required for PKIView to work are present and correctly published:
  - Root CA and Issuing CA certificates and CRLs must be accessible via HTTP URLs.
  - Files must be copied to the DFS path: `\\pkilab.win.us\share\PKIData`.
- If the CRL or delta CRL is republished, the publish path must be the DFS UNC path (`\\pkilab.win.us\share\PKIData`) and NOT a local path.
- Manual copying of CRLs to the DFS path is not acceptable in production; the CA must publish directly to the DFS path.
- This ensures PKIView and clients always access the latest CRLs and certificates without manual intervention.

---

# 9. Validation

---

## 9.1 HTTP Checks (Should Return Files)

Test from any domain machine:

```powershell
$urls = @(
  'http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crl'
)
foreach ($u in $urls) { try { (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10).StatusCode | Out-Host } catch { $_.Exception.Message | Out-Host } }
```

Also test site-specific hosts to verify both IIS instances:

```powershell
Invoke-WebRequest 'http://flweb1.pkilab.win.us/pkidata/' -UseBasicParsing
Invoke-WebRequest 'http://nyweb1.pkilab.win.us/pkidata/' -UseBasicParsing
```

---

## 9.2 OCSP Retrieval and Validation

Pick any end-entity certificate (e.g., a Web Server or Computer cert) and run:

```powershell
certutil -url <path-to-end-entity.cer>
# In the dialog, select OCSP and click Retrieve. Result should be Successful.
```

Simulate failover: Update DNS CNAME for `ocsp.pkilab.win.us` to the secondary responder and repeat.

---

## 9.3 LDAPS (636) on Both DCs

Verify a DC has a Domain Controller Authentication cert and the chain is Issuing CA  Root:

```powershell
# On each DC
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*CN=*' } | Format-List Subject, NotAfter, EnhancedKeyUsageList
```

From a test host with OpenSSL installed:

```bash
openssl s_client -connect fldc1.pkilab.win.us:636 -showcerts -servername fldc1.pkilab.win.us </dev/null | sed -n '/----BEGIN CERTIFICATE----/,$p'
openssl s_client -connect nydc1.pkilab.win.us:636 -showcerts -servername nydc1.pkilab.win.us </dev/null | sed -n '/----BEGIN CERTIFICATE----/,$p'
```

Confirm the certificate CN/SAN matches the DC hostname and the chain builds to PKILab Root CA.

---

## 9.4 Web Server Certificate Binding (IIS)

On flweb1 (repeat on nyweb1) after enrolling a PKILab Web Server cert:

```powershell
# Find the cert by subject and bind to Default Web Site (443)
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*CN=flweb1.pkilab.win.us*' } | Select-Object -First 1
New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -IPAddress * -HostHeader 'flweb1.pkilab.win.us' -SslFlags 1
Push-Location IIS:\SslBindings
Get-Item '0.0.0.0!443' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
New-Item '0.0.0.0!443' -Thumbprint $cert.Thumbprint -SSLFlags 1
Pop-Location
```

Test HTTPS:

```powershell
Invoke-WebRequest 'https://flweb1.pkilab.win.us' -UseBasicParsing
Invoke-WebRequest 'https://nyweb1.pkilab.win.us' -UseBasicParsing
```

---

## 9.5 PKIView Summary

Launch `pkiview.msc` and confirm green checks for AIA/CDP/CRLs and for OCSP.

If any test fails, check firewall rules, DNS CNAMEs, IIS logs (`u_ex*.log`), and event logs on CAs and OCSP servers.

---

# 10. Security, Networking, and Operations Enhancements

---

## 10.1 Firewall and Service Ports (Review/Allow)

- Clients  Web: TCP 80 to flweb1/nyweb1 (`pki.pkilab.win.us` resolves via CNAME).
- Clients  OCSP: TCP 80 to flocsp/nyocsp1 (`ocsp.pkilab.win.us` CNAME).
- CAs  DCs/AD: RPC 135 + dynamic RPC 49152	65535, LDAP 389/636, GC 3268/3269, Kerberos 88, SMB 445, DNS 53.
- CAs/OCSP  HTTP CDP: TCP 80 to web servers.

---

## 10.2 Time Sync

Ensure all PKI servers use a reliable NTP source. Skew breaks Kerberos, CRL/OCSP validity.

---

## 10.3 CA Security Hardening and RBAC

- Create and use:
  - PKI Admins  manage CA configuration
  - PKI Auditors  read-only log review
  - Certificate Managers  approve/revoke certs
- Remove daily use of Domain Admins on CAs; use least privilege.
- Confirm CA auditing (AuditFilter 127) and Windows auditing for Object Access and Certification Services.

---

## 10.4 Key Archival and Recovery (Optional; Needed for S/MIME)

- Create small KRA group; issue "Key Recovery Agent" template to KRA members.
- Enable key archival on templates that require recovery (e.g., PKILabUser if S/MIME used).
- Secure KRAs and document recovery steps; test with a lab certificate.

---

## 10.5 Backup and Disaster Recovery

On each Issuing CA (periodic):

```powershell
# Backup CA database and logs
certutil -backupDB C:\CA_Backup\DB

# Backup CA key and cert (prompt for password)
certutil -backupKey C:\CA_Backup\Key

# Export CA config
reg export "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" C:\CA_Backup\ca_config.reg /y
Copy-Item C:\Windows\CAPolicy.inf C:\CA_Backup\ -ErrorAction SilentlyContinue
```

- Root CA: back up to offline, secured media with tamper evidence.
- Web pkidata: DFS provides redundancy; also back up backend targets.
- Document CA restore steps (install ADCS role, restore DB/Key, import config, start service).

---

## 10.6 Monitoring and Health

- PKIView: regular checks for AIA/CDP/CRLs and OCSP status.
- Event logs:
  - Microsoft-Windows-CertificationAuthority/Operational
  - Microsoft-Windows-OnlineResponder/Operational
- Synthetic health checks: HTTP 200 checks for pkidata files; OCSP test queries.

---

## 10.7 Template Scope and SAN Rules

- For PKILab Web Server: enforce DNS SANs; include any farm/alias names (e.g., `pki.pkilab.win.us`) as SANs where needed.
- Decide on private key export policy.

---

## 10.8 Directory Browsing Hardening (Optional)

- Consider disabling directory browsing in production; publish an `index.html` with explicit links if you still want a landing page.

---

## 10.9 OCSP Responder Signing Cert Lifecycle

- Ensure autoenrollment for OCSP Response Signing is active.
- Verify each responder renews before expiry and can read updated CRLs.

---

## 10.10 Renewal Runbooks

- Root CA CRL: generate annually (or as policy dictates), copy to `\\pkilab.win.us\share\PKIData`, and `certutil -dspublish` to AD.
- Issuing CA CRL: schedule weekly; verify HTTP availability after each publication.
- DNS flip procedures for pki/ocsp CNAMEs documented and tested.

---

# 11. Client Trust Distribution

- Domain-joined: trust is automatic via AD (you published Root and SubCA to NTAuth/SubCA).
- Non-domain devices (if any):
  - Export Root + Issuing CA certs from `\\pkilab.win.us\share\PKIData` and import to the devices trust stores.
  - For Linux/Unix services using OpenSSL, add to system trust bundle and restart daemons.

---

# Appendix 	6 Notes on DFS

- DFS Namespace: `\\pkilab.win.us\share` with a folder `PKIData`.
- Ensure DFS Namespace referrals are site-aware (DFSR/targets present in both sites with proper priorities).
- Set NTFS and share ACLs on DFS targets to include `PKILAB\fliss1$` and `PKILAB\nyiss1$` with Modify so CAs can publish/copy when needed.
- Clients will only ever see the HTTP URL; DFS is a backend implementation detail that the web servers read from.

---

# Appendix 	6 DFS Namespace Targets (Examples and ACLs)

**Example DFS Namespace and Targets**

- DFS Namespace: `\\pkilab.win.us\share`
- Folder in namespace: `PKIData`
- Target 1 (Florida): `\\flfilesrv\pki\PKIData`
- Target 2 (New York): `\\nyfilesrv\pki\PKIData`

**DFS Namespace Settings (Recommended)**

- Enable site-costed referrals.
- Set target priority: prefer local site (e.g., FL users prefer `\\flfilesrv`, NY users prefer `\\nyfilesrv`).
- Low TTL (300	600 seconds) for quick failover.
- Enable failback so clients return to preferred target after recovery.

**DFS Replication (DFSR) for PKIData**

- Create a replication group for the two targets.
- Topology: Full mesh (2-way) with reasonable bandwidth throttling as needed.
- Staging quota: 4	8 GB (or larger for big CRLs/archives); disable RDC (optional) as CRLs are small.
- File/Folder filters: Ensure `.crl`, `.crt`, `.cer` are NOT excluded.
- Antivirus exclusions: Exclude the PKIData folders from real-time scan to avoid lock delays during CRL writes.

**Share Permissions (On Each Backend Target Share)**

- Administrators: Full Control
- `PKILAB\fliss1$`: Change
- `PKILAB\nyiss1$`: Change
- Web access principals: Read
  - Option A (simplest): Authenticated Users: Read
  - Option B (tightest): `PKILAB\flweb1$`, `PKILAB\nyweb1$`: Read

**NTFS Permissions (On the PKIData Folder Root, Inherit to Children)**

- SYSTEM: Full Control
- Administrators: Full Control
- `PKILAB\fliss1$`: Modify, This folder, subfolders and files
- `PKILAB\nyiss1$`: Modify, This folder, subfolders and files
- Web servers (if using tight ACLs): `PKILAB\flweb1$`, `PKILAB\nyweb1$`: Read & execute, This folder, subfolders and files
- (Optional) Deny write for non-PKI admins to protect integrity of published files.

**Operational Notes**

- CAs publish CRLs/certs locally; copy to `\\pkilab.win.us\share\PKIData` (DFS namespace) or directly into backend target for their site; DFSR replicates across sites.
- IIS virtual directory on flweb1/nyweb1 points to the DFS namespace path (`\\pkilab.win.us\share\PKIData`) so both servers always serve the current content.

---

# End of README