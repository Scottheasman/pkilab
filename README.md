# PKI Lab: Offline Root CA + Two Enterprise Issuing CAs + HTTP AIA/CDP + Single OCSP + HA (DNS + DFS)

This manual provides step-by-step deployment instructions to build a two-tier Microsoft PKI for the pkilab.win.us domain using your finalized hostnames and IPs. Every command is included in order with clear roles. No prior knowledge is assumed.

Environment
- AD Domain (FQDN): pkilab.win.us
- NetBIOS domain name: PKILAB
- AD DCs:
  - fldc1 10.10.1.201 (Florida)
  - nydc1 10.20.1.201 (New York)
- Root CA (offline): pkirootca 10.10.1.131
- Issuing CAs:
  - fliss1 10.10.1.211 (Florida) — CA name: PKILab Issuing CA - FL
  - nyiss1 10.20.1.211 (New York) — CA name: PKILab Issuing CA - NY
- Web servers (IIS for AIA/CDP HTTP):
  - flweb1 10.10.1.241 (Florida)
  - nyweb1 10.20.1.241 (New York)
- OCSP responders:
  - flocsp 10.10.1.221 (Florida)
  - nyocsp1 10.20.1.221 (New York)
- HTTP namespace (single, HA via DNS): http://pki.pkilab.win.us/
- OCSP namespace (single, HA via DNS): http://ocsp.pkilab.win.us/ocsp
- DFS path for pkidata: \\pkilab.win.us\share\PKIData

ADCS variables in file paths
- %3 = CA Common Name
- %4 = Certificate name suffix (renewal number)
- %8 = CRL name suffix (CRL number + renewal)

Examples:
- %3%8.crl -> "PKILab Issuing CA - FL.crl" (with CRL numbering)
- %3%4.crt -> "PKILab Issuing CA - FL.crt" (with renewal suffix)

---

0) DNS (no load balancer; DNS-based failover)
Purpose: Provide stable HTTP and OCSP namespaces with fast failover.

On a DNS server hosting pkilab.win.us, create:
- A records:
  - flweb1.pkilab.win.us -> 10.10.1.241
  - nyweb1.pkilab.win.us -> 10.20.1.241
  - flocsp.pkilab.win.us -> 10.10.1.221
  - nyocsp1.pkilab.win.us -> 10.20.1.221
- CNAMES:
  - pki.pkilab.win.us -> flweb1.pkilab.win.us (steady state)
  - ocsp.pkilab.win.us -> flocsp.pkilab.win.us (steady state)
- Set TTL to 60–120 seconds for pki.pkilab.win.us and ocsp.pkilab.win.us.

Failover runbook:
- Web down in FL: flip CNAME pki.pkilab.win.us -> nyweb1.pkilab.win.us.
- OCSP down in FL: flip CNAME ocsp.pkilab.win.us -> nyocsp1.pkilab.win.us.

Why single HTTP namespace for CDP/AIA/OCSP: Keeps URLs embedded in certificates stable for the PKI lifetime; only DNS changes during failover.

---

1) Web Servers (flweb1 and nyweb1) — DFS-backed pkidata
Goal: Serve http://pki.pkilab.win.us/pkidata/ with current CA certs and CRLs, using DFS namespace \\pkilab.win.us\share\PKIData as the single path in both sites.

Prerequisites:
- A DFS Namespace at \\pkilab.win.us\share with a folder target PKIData that points to backend folders in FL and NY. Ensure multi-site targets are healthy and replicate.
- NTFS & share permissions on the DFS target folders must grant Modify to:
  - PKILAB\fliss1$
  - PKILAB\nyiss1$
  - Administrators Full Control

Perform on flweb1 (run PowerShell as Administrator), then repeat identical steps on nyweb1:
```powershell
# Install IIS
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools

# Create IIS Virtual Directory to DFS path
$vDirProperties = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\pkilab.win.us\share\PKIData' }
New-WebVirtualDirectory @vDirProperties

# Enable directory browsing and allow double-escaping
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProperties.Site)\$($vDirProperties.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\Sites\$($vDirProperties.Site)"

# Add MIME types for CRL/CRT and set basic caching headers
Add-WebConfigurationProperty -pspath 'IIS:\' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:\' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
Add-WebConfigurationProperty -pspath 'IIS:\' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}

# Optional: set cache-control for pkidata
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$($vDirProperties.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}
```

Verification:
- Browse http://pki.pkilab.win.us/pkidata/ (should list directory).
- Also test server-specific URLs:
  - http://flweb1.pkilab.win.us/pkidata/
  - http://nyweb1.pkilab.win.us/pkidata/

Optional hardening for production:
```powershell
# Disable directory browsing (if you choose to lock it down)
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath "IIS:\Sites\$($vDirProperties.Site)\$($vDirProperties.Name)"
```

---

2) Offline Root CA — pkirootca (kept offline)
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
  CACommonName                = 'PKILab Root CA'
  CADistinguishedNameSuffix   = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                      = 'StandaloneRootCA'
  CryptoProviderName          = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName           = 'SHA256'
  KeyLength                   = 4096
  ValidityPeriod              = 'Years'
  ValidityPeriodUnits         = 20
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

# CDP: clear and set (local + HTTP)
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA: clear LDAP/HTTP/FILE then set (local + HTTP)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt'
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
1) Copy from pkirootca (CertEnroll) to removable media:
   - PKILab Root CA.crt
   - PKILab Root CA.crl
2) Place into DFS path using any domain-joined machine:
   - \\pkilab.win.us\share\PKIData\
3) From a domain-joined admin machine, publish to AD:
```powershell
certutil -dspublish -f "\\pkilab.win.us\share\PKIData\PKILab Root CA.crt" rootca
certutil -dspublish -f "\\pkilab.win.us\share\PKIData\PKILab Root CA.crl" "PKILab Root CA"

# Verify enterprise root store
certutil -viewstore -enterprise Root
```

Power off pkirootca when not in use.

---

3) Issuing CAs — fliss1 (FL) and nyiss1 (NY)
Purpose: Two enterprise issuing CAs for HA. Each publishes CRLs locally; issued certs embed a single HTTP CDP/AIA URL pointing to pki.pkilab.win.us.

CA Common Names:
- FL: PKILab Issuing CA - FL
- NY: PKILab Issuing CA - NY

3.1 Install Issuing CA on fliss1
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
  CACommonName              = 'PKILab Issuing CA - FL'
  CADistinguishedNameSuffix = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\pkidata'
  OutputCertRequestFile     = 'C:\pkidata\pkilab_issuing_fl.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

Enroll/issue SubCA cert from the Root CA:
- Copy C:\pkidata\pkilab_issuing_fl.req to pkirootca (power on temporarily).
- On pkirootca, issue pkilab_issuing_fl.cer to the SubCA request.
- On fliss1, open Certification Authority console, right-click the stopped CA, choose "Install new key/certificate" and select the issued .cer.
- Start the Certification Authority service.

Configure validity, CDP, AIA, and OCSP on fliss1:
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

# 1) Local publish
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# 2) Single HTTP namespace for clients (embed in issued certs)
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA: local + HTTP (embed HTTP in issued certs)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

# OCSP URL (single, DNS HA) — Scripted addition to AIA (alternative to GUI)

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

Publish Issuing CA - FL to AD (from fliss1 or any domain-joined admin machine):
```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*PKILab Issuing CA - FL*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

3.2 Install Issuing CA on nyiss1 (repeat with NY names)
```powershell
# CAPolicy.inf
Set-Content  C:\Windows\CAPolicy.inf '[Version]'
Add-Content C:\Windows\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\Windows\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\Windows\CAPolicy.inf 'URL=http://pki.pkilab.win.us/pkidata/cps.html'
Add-Content C:\Windows\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\Windows\CAPolicy.inf 'LoadDefaultTemplates=0'

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = 'PKILab Issuing CA - NY'
  CADistinguishedNameSuffix = 'O=PKILab,L=New York,S=New York,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\pkidata'
  OutputCertRequestFile     = 'C:\pkidata\pkilab_issuing_ny.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

- Copy C:\pkidata\pkilab_issuing_ny.req to pkirootca, issue pkilab_issuing_ny.cer, complete installation on nyiss1, then start the service.

Configure CDP/AIA/OCSP on nyiss1 (same as FL):
```powershell
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod Years
certutil -setreg CA\CRLPeriodUnits 52
certutil -setreg CA\CRLPeriod Weeks
certutil -setreg CA\CRLDeltaPeriodUnits 0
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod Days
certutil -setreg CA\AuditFilter 127

$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACRLDistributionPoint -Uri 'C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\CACertPublicationURLs '1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force
# Scripted ocsp URL addition (alternative)

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

Publish Issuing CA - NY to AD:
```powershell
$cer = Get-ChildItem 'C:\Windows\System32\CertSrv\CertEnroll' -Filter '*PKILab Issuing CA - NY*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

Enable required certificate templates on BOTH issuing CAs (see Section 6).

---

4) OCSP Responders — flocsp and nyocsp1 (single URL)
Purpose: Real-time revocation with responders in both sites. Use single OCSP URL with DNS flip for HA.

Install role on each OCSP server:
```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
```

On both Issuing CAs, ensure AIA includes the single OCSP URL:
- ocsp:http://ocsp.pkilab.win.us/ocsp (checked to include in AIA of issued certs) and restart each CA service.

Configure Online Responder Management on flocsp and nyocsp1:
- Create a Revocation Configuration per Issuing CA (two configs per server: FL and NY CA).
- Provider: Microsoft CRL-based Revocation.
- Ensure OCSP servers can read Issuing CA CRLs (HTTP or AD CDP access).
- Enroll "OCSP Response Signing" certificates (autoenroll or manual).
- Confirm status = Online.

Validation from any domain-joined machine:
```powershell
certutil -url <path-to-an-end-entity.cer>
# Select OCSP, click Retrieve; flip ocsp CNAME to validate failover.
```

---

5) Validation
HTTP checks (should return files):
- http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crt
- http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crl
- http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crt
- http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crl
- http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crt
- http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crl

PKIView should show OK for: Root CA and both Issuing CAs (CA Certificate, AIA, CDP).

Deep test:
```powershell
certutil -verify -urlfetch '<path-to-an-end-entity-cert.cer>'
```

---

6) Certificate Templates, Autoenrollment, and Horizon VDI (Omnissa)
Goal: Define and publish the minimum certificate templates, enable autoenrollment, and support Horizon VDI user certificates.

6.1 Create AD groups for template security
Create these global security groups (in AD Users and Computers):
- PKI Web Servers — add web servers (flweb1$, nyweb1$) or any server that needs a Web Server cert.
- PKI OCSP Servers — add flocsp$, nyocsp1$.
- PKI Horizon Enrollment — service accounts/servers involved in Horizon True SSO (if used).
- PKI Certificate Managers — delegated approvers for pending requests (optional).

6.2 Enable Autoenrollment via GPO
On a domain GPO applied to the target scope (Computers and/or Users):
- Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client – Auto-Enrollment:
  - Configuration Model: Enabled
  - Renew expired certificates, update pending certificates, and remove revoked…: Checked
  - Update certificates that use certificate templates: Checked
- If issuing User certificates, also enable the same under User Configuration.

6.3 Minimum templates to publish
Perform template creation with certtmpl.msc (Certificate Templates MMC). Then publish templates on each Issuing CA (certsrv.msc > Certification Authority > Certificate Templates > New > Certificate Template to Issue).

A) Web Server certificate (for IIS/LDAPS/HTTPS)
- Base: Duplicate "Web Server" (Windows Server 2016+ compatibility).
- Template display name: PKILab Web Server
- Template name: PKILabWebServer
- Validity: 2 years; Renewal period: 6 weeks (adjust as desired).
- Subject Name: Supply in the request (allow SAN). For AD autoenroll, you may prefer "Build from AD information" if names are predictable.
- Cryptography: KSP; 2048 or 4096-bit RSA; allow private key export (optional).
- Extensions (EKU): Server Authentication only (remove others).
- Security: Grant Read/Enroll/Autoenroll to PKI Web Servers. Grant Read/Enroll to admins as needed.
- Publish on both Issuing CAs.

B) OCSP Response Signing (for OCSP responders)
- Use built-in template "OCSP Response Signing" (do not duplicate unless needed).
- Security: Grant Read/Enroll/Autoenroll to PKI OCSP Servers.
- Ensure Autoenrollment GPO applies to OCSP servers.
- Publish on both Issuing CAs.

C) Computer (Machine) certificate (for domain members, LDAPS, Wi-Fi, etc.)
- Use built-in "Computer" template.
- Security: Domain Computers already have Enroll/Autoenroll by default (verify).
- Publish on both Issuing CAs as needed.

D) Domain Controller Authentication (Smart Card/LDAPS readiness)
- Use built-in "Domain Controller Authentication" template.
- Security: Domain Controllers group should have Enroll/Autoenroll.
- Publish on both Issuing CAs.
- Validate on each DC:
```powershell
# On each DC
gpupdate /force
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'Server Authentication|Client Authentication' }
```

E) User certificate (for client auth/SMIME; required for some Horizon use-cases)
- Base: Duplicate "User".
- Template display name: PKILab User
- Template name: PKILabUser
- Validity: 1–2 years; Renewal: 6 weeks.
- Subject Name: Build from AD (UPN/email).
- Extensions (EKU): Client Authentication (and optionally Secure Email if SMIME required).
- Security: Grant Read/Enroll/Autoenroll to appropriate user groups (e.g., Domain Users or a scoped group).
- Publish on both Issuing CAs as needed.

F) Horizon VDI (Omnissa) — choose ONE path
- Path 1: Horizon True SSO (recommended)
  - Requires an Enrollment Server and integration with AD CS.
  - Templates:
    1) Enrollment Agent certificate for the Enrollment Server:
       - Use built-in "Enrollment Agent" (or duplicate) and issue to the Enrollment Server service account/computer as per Omnissa guidance.
    2) True SSO User Logon certificate template (short-lived user logon certs):
       - Base: Duplicate "Smartcard Logon" or "User" and include EKUs: Smart Card Logon + Client Authentication.
       - Subject Name: Supply in request (UPN in SAN). Allow subject alternative name: UPN.
       - Validity: very short (e.g., 8 hours). Renewal: not applicable (non-renewed short-lived).
       - Security: Grant Enroll to the Enrollment Server (service/computer) and Horizon Connection Servers per vendor guidance (PKI Horizon Enrollment group).
       - Cryptography: KSP, RSA 2048+, no export needed.
    - Publish both templates on both Issuing CAs.

- Path 2: Classic Smart Card Logon (physical/smart card based)
  - Template:
    - Duplicate "Smartcard Logon".
    - EKUs: Smart Card Logon + Client Authentication.
    - Subject: Supply in request (UPN in SAN), enforce KDC mapping.
    - Security: Enroll permissions to issuance process or users; typically not autoenrolled.

Horizon Integration Checklist (placeholder — fill with your specifics later)
- Enrollment Server has Enrollment Agent cert issued and trusted.
- True SSO User Logon template created and permissions assigned.
- Connection Servers trust chain includes Root + Issuing CAs.
- Test flow: VDI launch → short-lived user cert issued → logon succeeds; OCSP reachable at http://ocsp.pkilab.win.us/ocsp.

6.4 Publish the templates on each Issuing CA
On each Issuing CA (fliss1 and nyiss1):
- certsrv.msc > Certification Authority > [CA Name] > Certificate Templates > right-click > New > Certificate Template to Issue
- Select: PKILab Web Server, OCSP Response Signing, Computer, Domain Controller Authentication, PKILab User, and your Horizon True SSO templates (if used).

6.5 Verify autoenrollment and issuance
- On an OCSP server (e.g., flocsp), run `gpupdate /force`, then open certlm.msc > Personal > Certificates. You should see an "OCSP Response Signing" certificate.
- On a web server (e.g., flweb1), request a "PKILab Web Server" cert via MMC or autoenrollment; ensure SAN contains the host FQDN.
- On DCs, verify "Domain Controller Authentication" certificate is present; validate LDAPS with `openssl s_client -connect <dc>:636 -showcerts` from a test box.
- For Computer/User templates, verify autoenrollment delivers certs after GPO refresh.

---

7) Security, Networking, and Operations Enhancements

7.1 Firewall and service ports (review/allow)
- Clients → Web: TCP 80 to flweb1/nyweb1 (pki.pkilab.win.us resolves via CNAME).
- Clients → OCSP: TCP 80 to flocsp/nyocsp1 (ocsp.pkilab.win.us CNAME).
- CAs ↔ DCs/AD: RPC 135 + dynamic RPC 49152–65535, LDAP 389/636, GC 3268/3269, Kerberos 88, SMB 445, DNS 53.
- CAs/OCSP → HTTP CDP: TCP 80 to web servers.

7.2 Time sync
- Ensure all PKI servers use a reliable NTP source. Skew breaks Kerberos, CRL/OCSP validity.

7.3 CA security hardening and RBAC
- Create and use:
  - PKI Admins — manage CA configuration
  - PKI Auditors — read-only log review
  - Certificate Managers — approve/revoke certs
- Remove daily use of Domain Admins on CAs; use least privilege.
- Confirm CA auditing (AuditFilter 127) and Windows auditing for Object Access and Certification Services.

7.4 Key archival and Recovery (optional; needed for S/MIME)
- Create small KRA group; issue "Key Recovery Agent" template to KRA members.
- Enable key archival on templates that require recovery (e.g., PKILabUser if S/MIME used).
- Secure KRAs and document recovery steps; test with a lab certificate.

7.5 Backup and Disaster Recovery
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

7.6 Monitoring and health
- PKIView: regular checks for AIA/CDP/CRLs and OCSP status.
- Event logs:
  - Microsoft-Windows-CertificationAuthority/Operational
  - Microsoft-Windows-OnlineResponder/Operational
- Synthetic health checks: HTTP 200 checks for pkidata files; OCSP test queries.

7.7 Template scope and SAN rules
- For PKILab Web Server: enforce DNS SANs; include any farm/alias names (e.g., pki.pkilab.win.us) as SANs where needed.
- Decide on private key export policy.

7.8 Directory browsing hardening (optional)
- Consider disabling directory browsing in production; publish an index.html with explicit links if you still want a landing page.

7.9 OCSP responder signing cert lifecycle
- Ensure autoenrollment for OCSP Response Signing is active.
- Verify each responder renews before expiry and can read updated CRLs.

7.10 Renewal runbooks
- Root CA CRL: generate annually (or as policy dictates), copy to \\pkilab.win.us\share\PKIData, and `certutil -dspublish` to AD.
- Issuing CA CRL: schedule weekly; verify HTTP availability after each publication.
- DNS flip procedures for pki/ocsp CNAMEs documented and tested.

---

8) Client trust distribution
- Domain-joined: trust is automatic via AD (you published Root and SubCA to NTAuth/SubCA).
- Non-domain devices (if any):
  - Export Root + Issuing CA certs from \\pkilab.win.us\share\PKIData and import to the devices’ trust stores.
  - For Linux/Unix services using OpenSSL, add to system trust bundle and restart daemons.

---

Appendix — Notes on DFS
- DFS Namespace: \\pkilab.win.us\share with folder PKIData.
- Ensure DFS Namespace referrals are site-aware (DFSR/targets present in both sites with proper priorities).
- Set NTFS and share ACLs on DFS targets to include PKILAB\fliss1$ and PKILAB\nyiss1$ with Modify so CAs can publish/copy when needed.
- Clients will only ever see the HTTP URL; DFS is a backend implementation detail that the web servers read from.


---

Appendix — DFS Namespace Targets (examples and ACLs)
This appendix provides concrete examples for backend DFS targets and recommended permissions. Replace the example server names with your actual file servers if they differ.

Example DFS Namespace and targets
- DFS Namespace: \\pkilab.win.us\share
- Folder in namespace: PKIData
- Target 1 (Florida): \\flfilesrv\pki\PKIData
- Target 2 (New York): \\nyfilesrv\pki\PKIData

DFS Namespace settings (recommended)
- Enable site-costed referrals.
- Set target priority: prefer local site (e.g., FL users prefer \\flfilesrv, NY users prefer \\nyfilesrv).
- Low TTL (300–600 seconds) for quick failover.
- Enable failback so clients return to preferred target after recovery.

DFS Replication (DFSR) for PKIData
- Create a replication group for the two targets.
- Topology: Full mesh (2-way) with reasonable bandwidth throttling as needed.
- Staging quota: 4–8 GB (or larger for big CRLs/archives); disable RDC (optional) as CRLs are small.
- File/Folder filters: Ensure .crl, .crt, .cer are NOT excluded.
- Antivirus exclusions: Exclude the PKIData folders from real-time scan to avoid lock delays during CRL writes.

Share permissions (on each backend target share)
- Administrators: Full Control
- PKILAB\\fliss1$: Change
- PKILAB\\nyiss1$: Change
- Web access principals: Read
  - Option A (simplest): Authenticated Users: Read
  - Option B (tightest): PKILAB\\flweb1$, PKILAB\\nyweb1$: Read

NTFS permissions (on the PKIData folder root, inherit to children)
- SYSTEM: Full Control
- Administrators: Full Control
- PKILAB\\fliss1$: Modify, This folder, subfolders and files
- PKILAB\\nyiss1$: Modify, This folder, subfolders and files
- Web servers (if using tight ACLs): PKILAB\\flweb1$, PKILAB\\nyweb1$: Read & execute, This folder, subfolders and files
- (Optional) Deny write for non-PKI admins to protect integrity of published files.

Operational notes
- CAs publish CRLs/certs locally; copy to \\pkilab.win.us\share\PKIData (DFS namespace) or directly into backend target for their site; DFSR replicates across sites.
- IIS virtual directory on flweb1/nyweb1 points to the DFS namespace path (\\pkilab.win.us\share\PKIData) so both servers always serve the current content.

---

9) Initial Smoke Tests (LDAPS, OCSP, Web bindings)
Run these after completing the setup to validate core functionality.

9.1 Web AIA/CDP (HTTP) checks
- From any domain machine:
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
- Also test site-specific hosts to verify both IIS instances:
```powershell
Invoke-WebRequest 'http://flweb1.pkilab.win.us/pkidata/' -UseBasicParsing
Invoke-WebRequest 'http://nyweb1.pkilab.win.us/pkidata/' -UseBasicParsing
```

9.2 OCSP retrieval and validation
- Pick any end-entity certificate (e.g., a Web Server or Computer cert) and run:
```powershell
certutil -url <path-to-end-entity.cer>
# In the dialog, select OCSP and click Retrieve. Result should be Successful.
```
- Simulate failover: Update DNS CNAME for ocsp.pkilab.win.us to the secondary responder and repeat.

9.3 LDAPS (636) on both DCs
- Verify a DC has a Domain Controller Authentication cert and the chain is Issuing CA -> Root.
```powershell
# On each DC
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*CN=*' } | Format-List Subject, NotAfter, EnhancedKeyUsageList
```
- From a test host with OpenSSL installed:
```bash
openssl s_client -connect fldc1.pkilab.win.us:636 -showcerts -servername fldc1.pkilab.win.us </dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,$p'
openssl s_client -connect nydc1.pkilab.win.us:636 -showcerts -servername nydc1.pkilab.win.us </dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,$p'
```
- Confirm the certificate CN/SAN matches the DC hostname and the chain builds to PKILab Root CA.

9.4 Web server certificate binding (IIS)
- On flweb1 (repeat on nyweb1) after enrolling a PKILab Web Server cert:
```powershell
# Find the cert by subject and bind to Default Web Site (443)
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*CN=flweb1.pkilab.win.us*' } | Select-Object -First 1
New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -IPAddress * -HostHeader 'flweb1.pkilab.win.us' -SslFlags 1
Push-Location IIS:\SslBindings
Get-Item '0.0.0.0!443' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
New-Item '0.0.0.0!443' -Thumbprint $cert.Thumbprint -SSLFlags 1
Pop-Location
```
- Test HTTPS:
```powershell
Invoke-WebRequest 'https://flweb1.pkilab.win.us' -UseBasicParsing
Invoke-WebRequest 'https://nyweb1.pkilab.win.us' -UseBasicParsing
```

9.5 PKIView summary
- Launch `pkiview.msc` and confirm green checks for AIA/CDP/CRLs and for OCSP.

If any test fails, check firewall rules, DNS CNAMEs, IIS logs (u_ex*.log), and event logs on CAs and OCSP servers.


---

Appendix — CA Extensions: Set AIA/CDP/OCSP using supported commands and GUI (no raw registry edits)


#### Screenshot: AIA configuration and adding OCSP URL

![AIA and OCSP Configuration](https://cdn.abacus.ai/images/2275154c-c38a-417d-bc8b-cf6f5b7d560f.png)

Caption:
1. HTTP AIA included in issued certificates.
2. Local/UNC AIA locations are publish-only (not embedded).
3. OCSP URL added via AIA Add... dialog as ocsp:// http endpoint and included in issued certificates.



#### Screenshot: CDP configuration (publish to UNC/local; include HTTP only)

![CDP Configuration](https://cdn.abacus.ai/images/c8a4736f-6e6c-43cb-8826-a7585f140a45.png)

Caption:
1. HTTP CDP included in issued certificates (and in IDP of issued CRLs).
2. Local/UNC paths set to Publish-only so the CA writes CRLs to CertEnroll and \pkilab.win.us\share\PKIData.



#### Screenshot: Configure AIA/CDP/OCSP in CA Properties (Extensions tab)

![CA Extensions Configuration](https://cdn.abacus.ai/images/61be305d-f4d3-4cc4-a76f-23a8c7b1ab8e.png)

Caption:
1. AIA: Only the HTTP AIA entry is checked to be included in issued certificates.
2. AIA: UNC/local AIA entries are publish targets only (not included in certificates).
3. CDP: HTTP CDP entry is included in issued certs (and in IDP of issued CRLs).
4. CDP: UNC/local CDP entries are publish targets only (CRLs are written there; not embedded).
5. OCSP: Add via AIA “Add...” using `ocsp:http://ocsp.pkilab.win.us/ocsp`, included in issued certs.

This clarifies exactly how to configure CA policy paths so CAs publish to the DFS UNC while issued certificates contain only HTTP/OCSP URLs.

Key rules
- Publish targets (where the CA writes files): use UNC path \\pkilab.win.us\share\PKIData and optional local CertEnroll folder.
- Embedded URLs in certificates: use only HTTP for AIA/CDP and the single OCSP URL. Do NOT embed UNC paths.

Root CA (pkirootca)
```powershell
# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# CDP publish locations (UNC and optional local)
Add-CACRLDistributionPoint -Uri '\\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# CDP embedded in issued certs (HTTP only)
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA publish locations (UNC and optional local)
certutil -setreg CA\CACertPublicationURLs "1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt\n2:\\pkilab.win.us\\share\\PKIData\\%3%4.crt"

# AIA embedded in issued certs (HTTP only)
Get-CAAuthorityInformationAccess | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

Restart-Service certsvc
certutil -crl
```

Issuing CAs (fliss1, nyiss1)
```powershell
# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# CDP publish locations (UNC and optional local)
Add-CACRLDistributionPoint -Uri '\\pkilab.win.us\share\PKIData\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# CDP embedded in issued certs (HTTP only)
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA publish locations (UNC and optional local)
certutil -setreg CA\CACertPublicationURLs "1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt\n2:\\pkilab.win.us\\share\\PKIData\\%3%4.crt"

# AIA embedded in issued certs (HTTP only)
Get-CAAuthorityInformationAccess | Remove-CAAuthorityInformationAccess -Force
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

Verification
```powershell
certutil -getreg CA\CRLPublicationURLs
certutil -getreg CA\CACertPublicationURLs
Get-CAAuthorityInformationAccess

# Issue a test cert, confirm it contains only HTTP AIA/CDP and the OCSP URL
certutil -dump <path-to-test-cert.cer> | more
```

Why certutil -setreg appears: These are the supported commands ADCS provides to set the CA's publish locations (the CA stores them in its configuration). We avoid manual registry tweaks and use only built-in ADCS cmdlets and certutil.
