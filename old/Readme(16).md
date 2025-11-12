# PKI Lab: Offline Root CA + Two Enterprise Issuing CAs + HTTP AIA/CDP + Single OCSP + HA (DNS + DFS) (16)

This manual provides step-by-step deployment instructions to build a two-tier Microsoft PKI for the [pkilab.win.us](http://pkilab.win.us) domain using your finalized hostnames and IPs. Every command is included in order with clear roles. No prior knowledge is assumed.

  ## Environment

* AD Domain (FQDN): [pkilab.win.us](http://pkilab.win.us)

* NetBIOS domain name: PKILAB

* AD DCs:

  * fldc1 10.10.1.201 (Florida)

  * nydc1 10.20.1.201 (New York)

* Root CA (offline): pkirootca 10.10.1.131

* Issuing CAs:

  * fliss1 10.10.1.211 (Florida) — CA name: PKILab Issuing CA - FL

  * nyiss1 10.20.1.211 (New York) — CA name: PKILab Issuing CA - NY

* Web servers (IIS for AIA/CDP HTTP):

  * flweb1 10.10.1.241 (Florida)

  * nyweb1 10.20.1.241 (New York)

* OCSP responders:

  * flocsp 10.10.1.221 (Florida)

  * nyocsp1 10.20.1.221 (New York)

* HTTP namespace (single, HA via DNS): [http://pki.pkilab.win.us/](http://pki.pkilab.win.us/)

* OCSP namespace (single, HA via DNS): [http://ocsp.pkilab.win.us/ocsp](http://ocsp.pkilab.win.us/ocsp)

* DFS path for pkidata: \\pkilab.win.us\\share\\PKIData

## ADCS variables in file paths

* %3 = CA Common Name

* %4 = Certificate name suffix (renewal number)

* %8 = CRL name suffix (CRL number + renewal)

Examples:

* %3%8.crl -> "PKILab Issuing CA - FL.crl" (with CRL numbering)

* %3%4.crt -> "PKILab Issuing CA - FL.crt" (with renewal suffix)

---

## 1\. DNS (no load balancer; DNS-based failover)

Purpose: Provide stable HTTP and OCSP namespaces with fast failover.

On a DNS server hosting [pkilab.win.us](http://pkilab.win.us), create:

* A records (host records):

  * [flweb1.pkilab.win.us](http://flweb1.pkilab.win.us) -> 10.10.1.241

  * [nyweb1.pkilab.win.us](http://nyweb1.pkilab.win.us) -> 10.20.1.241

  * [flocsp.pkilab.win.us](http://flocsp.pkilab.win.us) -> 10.10.1.221

  * [nyocsp1.pkilab.win.us](http://nyocsp1.pkilab.win.us) -> 10.20.1.221

* Remove the previous CNAME records for:

  * [pki.pkilab.win.us](http://pki.pkilab.win.us)

  * [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us)

* Instead, create DNS entries for [pki.pkilab.win.us](http://pki.pkilab.win.us) and [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us) as DNS round-robin or DNS failover pointing to the above A records for web servers and OCSP responders respectively.

* Set TTL to 60–120 seconds for [pki.pkilab.win.us](http://pki.pkilab.win.us) and [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us).

Failover runbook:

* Web down in FL: update DNS to point [pki.pkilab.win.us](http://pki.pkilab.win.us) to [nyweb1.pkilab.win.us](http://nyweb1.pkilab.win.us) IP.

* OCSP down in FL: update DNS to point [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us) to [nyocsp1.pkilab.win.us](http://nyocsp1.pkilab.win.us) IP.

Why single HTTP namespace for CDP/AIA/OCSP: Keeps URLs embedded in certificates stable for the PKI lifetime; only DNS changes during failover.

---

## 2\. Web Servers (flweb1 and nyweb1) — DFS-backed pkidata

Goal: Serve [http://pki.pkilab.win.us/pkidata/](http://pki.pkilab.win.us/pkidata/) with current CA certs and CRLs, using DFS namespace \\pkilab.win.us\\share\\PKIData as the single path in both sites.

Prerequisites:

* A DFS Namespace at \\pkilab.win.us\\share with a folder target PKIData that points to backend folders in FL and NY. Ensure multi-site targets are healthy and replicate.

* NTFS & share permissions on the DFS target folders must grant Modify to:

  * PKILAB\\fliss1$

  * PKILAB\\nyiss1$

  * Administrators Full Control

Perform on flweb1 (run PowerShell as Administrator), then repeat identical steps on nyweb1:

```powershell
# Install IIS
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools
```

# Create IIS Virtual Directory to DFS path

```powershell
$vDirProperties = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\pkilab.win.us\\share\\PKIData' }
New-WebVirtualDirectory @vDirProperties
```

# Enable directory browsing and allow double-escaping

```powershell
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value true -PSPath "IIS:\Sites\$($vDirProperties.Site)\$($vDirProperties.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value true -PSPath "IIS:\Sites\$($vDirProperties.Site)"
```

# Add MIME types for CRL/CRT and set basic caching headers

```powershell
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}
```

# Optional: set cache-control for pkidata

```powershell
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$($vDirProperties.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}
```

Verification:

* Browse [http://pki.pkilab.win.us/pkidata/](http://pki.pkilab.win.us/pkidata/) (should list directory).

* Also test server-specific URLs:

  * [http://flweb1.pkilab.win.us/pkidata/](http://flweb1.pkilab.win.us/pkidata/)

  * [http://nyweb1.pkilab.win.us/pkidata/](http://nyweb1.pkilab.win.us/pkidata/)

Optional hardening for production:

```powershell
# Disable directory browsing (if you choose to lock it down)
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath "IIS:\Sites\$($vDirProperties.Site)\$($vDirProperties.Name)"
```

---

## 3\. Offline Root CA — pkirootca (kept offline)

Purpose: Establish the trust anchor. Configure AIA/CDP so clients know where to fetch the root CA cert and CRL. Manually transfer files to DFS and publish to AD.

On pkirootca (standalone, NOT domain-joined):

```powershell
# CAPolicy.inf
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

# Install AD CS role
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Install the Root CA
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

# Validity and CRL
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod Years
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod Days
certutil -setreg CA\AuditFilter 127

# CDP: clear and set (local + HTTP + DFS UNC)
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACRLDistributionPoint -Uri '\\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA: clear LDAP/HTTP/FILE then set (local + HTTP + DFS UNC)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt
2:\\pkilab.win.us\share\PKIData\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

# Publish initial CRL
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl

# Optional rename and open folder
Rename-Item 'C:\Windows\System32\CertSrv\CertEnroll\pkirootca_PKILab Root CA.crt' 'PKILab Root CA.crt' -ErrorAction SilentlyContinue
explorer.exe 'C:\Windows\System32\CertSrv\CertEnroll'
```

Manual transfer (Root is offline):

1. Copy from pkirootca (CertEnroll) to removable media:

* PKILab Root CA.crt

* PKILab Root CA.crl

1. Place into DFS path using any domain-joined machine:

* \\pkilab.win.us\\share\\PKIData\\

1. From a domain-joined admin machine, publish to AD:

```powershell
certutil -dspublish -f "\\pkilab.win.us\share\PKIData\PKILab Root CA.crt" rootca
certutil -dspublish -f "\\pkilab.win.us\share\PKIData\PKILab Root CA.crl" "PKILab Root CA"

# Verify enterprise root store
certutil -viewstore -enterprise Root
```

Power off pkirootca when not in use.

---

## 4\. Issuing CAs — fliss1 (FL) and nyiss1 (NY)

Purpose: Two enterprise issuing CAs for HA. Each publishes CRLs locally; issued certs embed a single HTTP CDP/AIA URL pointing to [pki.pkilab.win.us](http://pki.pkilab.win.us).

CA Common Names:

* FL: PKILab Issuing CA - FL

* NY: PKILab Issuing CA - NY

### 4.1 Install Issuing CA on fliss1

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

### 4.2 Enroll/issue SubCA cert from the Root CA

* Copy `C:\pkidata\pkilab_issuing_fl.req` to pkirootca (power on temporarily).

* On pkirootca, submit, approve, and download the issuing CA certificate using the following commands:

```powershell
# Submit the request
certreq -submit C:\pkidata\pkilab_issuing_fl.req C:\pkidata\pkilab_issuing_fl.cer

# Approve the request (requires CA admin privileges)
certutil -getrequests
certutil -approve <RequestID>

# Download the issued certificate
certutil -retrieve <RequestID> C:\pkidata\pkilab_issuing_fl.cer
```

* On fliss1, open Certification Authority console, right-click the stopped CA, choose "Install new key/certificate" and select the issued `.cer`.

* Start the Certification Authority service.

### 4.3 Configure validity, CDP, AIA, and OCSP on fliss1

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

# CDP publish locations (UNC and optional local)
Add-CACRLDistributionPoint -Uri '\\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# CDP embedded in issued certs (HTTP only)
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA publish locations (UNC and optional local)
certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt\n2:\\pkilab.win.us\share\PKIData\%3%4.crt"

# AIA embedded in issued certs (HTTP only)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

# OCSP URL (embedded) — use Certification Authority GUI (no registry edits)
# certsrv.msc -> [CA] -> Properties -> Extensions tab
#   - Select: Authority Information Access (AIA)
#   - Click Add... -> Location: ocsp:http://ocsp.pkilab.win.us/ocsp
#   - Check: Include in the AIA extension of issued certificates
#   - Ensure the HTTP AIA entry is also checked
# Apply, then restart service and publish a CRL.
Restart-Service certsvc
certutil -crl
```

### 4.4 Publish Issuing CA - FL to AD (from fliss1 or any domain-joined admin machine)

```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*PKILab Issuing CA - FL*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

### 4.5 Ensure that all required files for PKIView are copied to the DFS pkidata folder

* C:\\Windows\\System32\\CertSrv\\CertEnroll\\PKILab Issuing CA - FL.crl

* C:\\Windows\\System32\\CertSrv\\CertEnroll\\PKILab Issuing CA - FL+.crl

* C:\\pkidata\\pkilab_issuing_fl.req.crt

### 4.6 Repeat steps 4.1 to 4.5 for nyiss1 with NY names

---

## 5\. OCSP Responders — flocsp and nyocsp1 (single URL)

Purpose: Real-time revocation with responders in both sites. Use single OCSP URL with DNS failover for HA.

Install role on each OCSP server:

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
```

On both Issuing CAs, ensure AIA includes the single OCSP URL:

* ocsp:[http://ocsp.pkilab.win.us/ocsp](http://ocsp.pkilab.win.us/ocsp) (checked to include in AIA of issued certs) and restart each CA service.

Configure Online Responder Management on flocsp and nyocsp1:

* Create a Revocation Configuration per Issuing CA (two configs per server: FL and NY CA).

* Provider: Microsoft CRL-based Revocation.

* Ensure OCSP servers can read Issuing CA CRLs (HTTP or AD CDP access).

* Enroll "OCSP Response Signing" certificates (autoenroll or manual).

* Confirm status = Online.

Validation from any domain-joined machine:

```powershell
certutil -url <path-to-an-end-entity.cer>
# Select OCSP, click Retrieve; flip ocsp DNS to validate failover.
```

---

## 6\. Enable required certificate templates on BOTH issuing CAs

Duplicate the existing OCSP Template "PKILab OCSP Response Signing" with these settings:

* Compatibility: Certificate Authority = 2016, Certificate recipient = Win10/Server 2016

* Request Handling: Purpose = Signature, Allow private key to be exported - unchecked

* Cryptography: Minimum Key size = 4096

* Security: Add both OCSP server computer objects with Read, Enroll, and AutoEnroll

---

## 7\. Important Notes for PKIView and CRL Publishing

* Ensure all files required for PKIView to work are present and correctly published:

  * Root CA and Issuing CA certificates and CRLs must be accessible via HTTP URLs.

  * Files must be copied to the DFS path: \\pkilab.win.us\\share\\PKIData.

* If the CRL or delta CRL is republished, the publish path must be the DFS UNC path (\\pkilab.win.us\\share\\PKIData) and NOT a local path.

* Manual copying of CRLs to the DFS path is not acceptable in production; the CA must publish directly to the DFS path.

* This ensures PKIView and clients always access the latest CRLs and certificates without manual intervention.

---

## 8\. Validation

HTTP checks (should return files):

* [http://pki.pkilab.win.us/pkidata/PKILab Root CA.crt](http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crt)

* [http://pki.pkilab.win.us/pkidata/PKILab Root CA.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crl)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL.crt](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crt)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crl)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY.crt](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crt)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crl)

PKIView should show OK for: Root CA and both Issuing CAs (CA Certificate, AIA, CDP).

Deep test:

```powershell
certutil -verify -urlfetch '<path-to-an-end-entity-cert.cer>'
```

---

## 9\. Additional Sections

The rest of the original README content remains unchanged, including:

* Certificate Templates, Autoenrollment, and Horizon VDI

* Security, Networking, and Operations Enhancements

* Client trust distribution

* Appendix — Notes on DFS

* Appendix — DFS Namespace Targets

* Initial Smoke Tests

* Appendix — CA Extensions: Set AIA/CDP/OCSP using supported commands and GUI

Refer to the original README for these details.

---

# End of updated README