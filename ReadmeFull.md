# PKI Lab: Offline Root CA + Two Enterprise Issuing CAs + HTTP AIA/CDP + Single OCSP + HA (DNS + DFS)

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

* Certificate Enrollment Web UI: [https://pki.pkilab.win.us/certsrv](https://pki.pkilab.win.us/certsrv)

* DFS path for pkidata: \\\\pkilab.win.us\\share\\PKIData

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

* A records:

  * [flweb1.pkilab.win.us](http://flweb1.pkilab.win.us) -> 10.10.1.241

  * [nyweb1.pkilab.win.us](http://nyweb1.pkilab.win.us) -> 10.20.1.241

  * [flocsp.pkilab.win.us](http://flocsp.pkilab.win.us) -> 10.10.1.221

  * [nyocsp1.pkilab.win.us](http://nyocsp1.pkilab.win.us) -> 10.20.1.221

* CNAMES:

  * [pki.pkilab.win.us](http://pki.pkilab.win.us) -> [flweb1.pkilab.win.us](http://flweb1.pkilab.win.us) (steady state)

  * [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us) -> [flocsp.pkilab.win.us](http://flocsp.pkilab.win.us) (steady state)

* Set TTL to 60–120 seconds for [pki.pkilab.win.us](http://pki.pkilab.win.us) and [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us).

Failover runbook:

* Web down in FL: flip CNAME [pki.pkilab.win.us](http://pki.pkilab.win.us) -> [nyweb1.pkilab.win.us](http://nyweb1.pkilab.win.us).

* OCSP down in FL: flip CNAME [ocsp.pkilab.win.us](http://ocsp.pkilab.win.us) -> [nyocsp1.pkilab.win.us](http://nyocsp1.pkilab.win.us).

Why single HTTP namespace for CDP/AIA/OCSP: Keeps URLs embedded in certificates stable for the PKI lifetime; only DNS changes during failover.

---

## 2\. Web Servers (flweb1 and nyweb1) — DFS-backed pkidata

Goal: Serve [http://pki.pkilab.win.us/pkidata/](http://pki.pkilab.win.us/pkidata/) with current CA certs and CRLs, using DFS namespace \\\\pkilab.win.us\\share\\PKIData as the single path in both sites.

Prerequisites:

* A DFS Namespace at \\\\pkilab.win.us\\share with a folder target PKIData that points to backend folders in FL and NY. Ensure multi-site targets are healthy and replicate.

* NTFS & share permissions on the DFS target folders must grant Modify to:

  * PKILAB\\fliss1$

  * PKILAB\\nyiss1$

  * Administrators Full Control

Perform on flweb1 (run PowerShell as Administrator), then repeat identical steps on nyweb1:

```powershell
# Install IIS
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools

# Create IIS Virtual Directory to DFS path
$vDirProperties = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\\\pkilab.win.us\\\\share\\\\PKIData' }
New-WebVirtualDirectory @vDirProperties

# Enable directory browsing and allow double-escaping
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\\\\Sites\\\\$($vDirProperties.Site)\\\\$($vDirProperties.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\\\\Sites\\\\$($vDirProperties.Site)"

# Add MIME types for CRL/CRT and set basic caching headers
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}

# Optional: set cache-control for pkidata
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\\\\Sites\\\\$($vDirProperties.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}
```

Verification:

* Browse [http://pki.pkilab.win.us/pkidata/](http://pki.pkilab.win.us/pkidata/) (should list directory).

* Also test server-specific URLs:

  * [http://flweb1.pkilab.win.us/pkidata/](http://flweb1.pkilab.win.us/pkidata/)

  * [http://nyweb1.pkilab.win.us/pkidata/](http://nyweb1.pkilab.win.us/pkidata/)

Optional hardening for production:

```powershell
# Disable directory browsing (if you choose to lock it down)
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath "IIS:\\\\Sites\\\\$($vDirProperties.Site)\\\\$($vDirProperties.Name)"
```

---

## 2.5 PKIWebSvc Account and Permissions Setup

Before configuring the Web Servers to serve the DFS-backed PKIData share, create and configure the PKIWebSvc service account and set appropriate permissions.

On a domain-joined admin machine, run:

```powershell
# Create PKIWebSvc account in Users container (adjust OU as needed)
$pwd = Read-Host -Prompt 'Enter password for PKIWebSvc' -AsSecureString
New-ADUser -Name 'PKIWebSvc' -SamAccountName 'PKIWebSvc' -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $false -Path 'CN=Users,DC=pkilab,DC=win,DC=us' -PassThru

# Add PKIWebSvc to PKI Web Servers group (create group if not existing)
Add-ADGroupMember -Identity 'PKI Web Servers' -Members 'PKIWebSvc'

# Grant NTFS and Share permissions on DFS targets (run on each file server hosting DFS targets)
Grant-SmbShareAccess -Name 'PKIData' -AccountName 'PKILAB\\\\PKIWebSvc' -AccessRight Change -Force
icacls 'D:\\PKIData' /grant "PKILAB\\\\PKIWebSvc:(OI)(CI)M" /T
```

On each IIS web server (flweb1, nyweb1), configure the IIS Application Pool to run as PKIWebSvc:

```powershell
Import-Module WebAdministration
Set-ItemProperty IIS:\\AppPools\\DefaultAppPool -Name processModel -Value @{userName='PKILAB\\\\PKIWebSvc';password='<password>'}
Restart-WebAppPool DefaultAppPool
```

Replace `<password>` with the actual password set for PKIWebSvc.

This ensures IIS can access the DFS share with the correct permissions.

---

## 2.6 Certificate Enrollment Web Services (/certsrv) — SSL and Access Control

Purpose: Provide a secure web-based interface for certificate enrollment at [https://pki.pkilab.win.us/certsrv](https://pki.pkilab.win.us/certsrv), accessible only to authorized users.

Prerequisites:

* Both web servers (flweb1 and nyweb1) must have valid Web Server certificates issued from the PKI (see Section 7.3A).

* Create an AD security group: **PKI Web Enrollment Users** and add authorized users/groups.

* Ensure both issuing CAs (fliss1 and nyiss1) are online and accessible from the web servers.

### 2.6.1 Create AD Security Group for /certsrv Access

On a domain controller or admin workstation:

```powershell
# Create the PKI Web Enrollment Users group
New-ADGroup -Name 'PKI Web Enrollment Users' -GroupScope Global -GroupCategory Security -Path 'CN=Users,DC=pkilab,DC=win,DC=us' -Description 'Users authorized to access the Certificate Enrollment Web UI'

# Add authorized users (example)
Add-ADGroupMember -Identity 'PKI Web Enrollment Users' -Members 'jdoe','admin1'
```

### 2.6.2 Install Certificate Services Web Enrollment Role

Perform on **both flweb1 and nyweb1**:

```powershell
# Install the Web Enrollment role
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools

# Configure the Web Enrollment service
Install-AdcsWebEnrollment -Force
```

### 2.6.3 Configure SSL Binding for /certsrv

On **both flweb1 and nyweb1**, bind the Web Server certificate to HTTPS (443):

```powershell
# Find the Web Server certificate (adjust Subject filter as needed)
$cert = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { 
    $_.Subject -like '*CN=flweb1.pkilab.win.us*' -or 
    $_.Subject -like '*CN=pki.pkilab.win.us*' -or
    $_.DnsNameList.Unicode -contains 'pki.pkilab.win.us'
} | Select-Object -First 1

if ($cert) {
    # Create HTTPS binding if it doesn't exist
    $binding = Get-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -ErrorAction SilentlyContinue
    if (-not $binding) {
        New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -IPAddress '*'
    }

    # Bind the certificate
    Push-Location IIS:\\SslBindings
    Get-Item '0.0.0.0!443' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    New-Item '0.0.0.0!443' -Thumbprint $cert.Thumbprint
    Pop-Location

    Write-Host "SSL binding configured with certificate: $($cert.Subject)" -ForegroundColor Green
} else {
    Write-Warning "No suitable Web Server certificate found. Enroll a certificate first (see Section 7.3A)."
}
```

**Note:** Repeat on nyweb1, adjusting the Subject filter to match `*CN=nyweb1.pkilab.win.us*`.

### 2.6.4 Restrict /certsrv Access to Authorized Users

Configure IIS to require Windows Authentication and restrict access to the **PKI Web Enrollment Users** group.

On **both flweb1 and nyweb1**:

```powershell
Import-Module WebAdministration

# Enable Windows Authentication for /certsrv
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name enabled -Value $true -PSPath 'IIS:\\Sites\\Default Web Site\\CertSrv'

# Disable Anonymous Authentication for /certsrv
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -Name enabled -Value $false -PSPath 'IIS:\\Sites\\Default Web Site\\CertSrv'

# Remove default authorization rules
Clear-WebConfiguration -Filter '/system.webServer/security/authorization' -PSPath 'IIS:\\Sites\\Default Web Site\\CertSrv'

# Add authorization rule: Allow only PKI Web Enrollment Users
Add-WebConfigurationProperty -Filter '/system.webServer/security/authorization' -Name '.' -Value @{accessType='Allow'; roles='PKILAB\\PKI Web Enrollment Users'} -PSPath 'IIS:\\Sites\\Default Web Site\\CertSrv'

Write-Host "/certsrv access restricted to PKI Web Enrollment Users group" -ForegroundColor Green
```

### 2.6.5 Force HTTPS Redirect for /certsrv (Optional but Recommended)

Ensure all HTTP requests to /certsrv are redirected to HTTPS:

```powershell
# Install URL Rewrite module if not already installed (download from IIS.net if needed)
# Then configure redirect rule:

$ruleName = 'Redirect certsrv to HTTPS'
$filterPath = 'IIS:\\Sites\\Default Web Site\\CertSrv'

# Check if rule exists
$existingRule = Get-WebConfigurationProperty -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']" -Name '.' -PSPath $filterPath -ErrorAction SilentlyContinue

if (-not $existingRule) {
    Add-WebConfigurationProperty -Filter 'system.webServer/rewrite/rules' -Name '.' -Value @{name=$ruleName; stopProcessing='True'} -PSPath $filterPath
    Set-WebConfigurationProperty -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/match" -Name url -Value '(.*)' -PSPath $filterPath
    Set-WebConfigurationProperty -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/conditions" -Name '.' -Value @{input='{HTTPS}'; pattern='off'} -PSPath $filterPath
    Set-WebConfigurationProperty -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/action" -Name type -Value 'Redirect' -PSPath $filterPath
    Set-WebConfigurationProperty -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/action" -Name url -Value 'https://{HTTP_HOST}{REQUEST_URI}' -PSPath $filterPath
    Set-WebConfigurationProperty -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/action" -Name redirectType -Value 'Permanent' -PSPath $filterPath

    Write-Host "HTTPS redirect configured for /certsrv" -ForegroundColor Green
} else {
    Write-Host "HTTPS redirect rule already exists for /certsrv" -ForegroundColor Yellow
}
```

**Note:** If URL Rewrite module is not installed, download and install it from [IIS.net](https://www.iis.net/downloads/microsoft/url-rewrite) before running this script.

### 2.6.6 Create Certificate Template for Web Enrollment SSL

A dedicated Web Server template is required for the /certsrv SSL binding. This is covered in **Section 7.3A (PKILab Web Server template)**.

Ensure the template includes:

* **Subject Alternative Name (SAN):** `pki.pkilab.win.us`, `flweb1.pkilab.win.us`, `nyweb1.pkilab.win.us`

* **Enhanced Key Usage:** Server Authentication

* **Security:** Grant Read/Enroll/Autoenroll to **PKI Web Servers** group (add flweb1$ and nyweb1$ computer accounts)

### 2.6.7 Verification

From an authorized user's workstation (member of **PKI Web Enrollment Users**):

```powershell
# Test HTTPS access to /certsrv
Start-Process 'https://pki.pkilab.win.us/certsrv'

# Should prompt for Windows credentials and display the Certificate Services enrollment page
```

From an unauthorized user's workstation:

* Access should be denied (HTTP 401 or 403).

Test failover:

* Update DNS CNAME for [pki.pkilab.win.us](http://pki.pkilab.win.us) to point to [nyweb1.pkilab.win.us](http://nyweb1.pkilab.win.us) and verify /certsrv remains accessible.

Troubleshooting:

* **Certificate errors:** Ensure the Web Server certificate includes the correct SANs and is trusted by clients.

* **Access denied:** Verify the user is a member of **PKI Web Enrollment Users** and Windows Authentication is enabled.

* **IIS logs:** Check `C:\\inetpub\\logs\\LogFiles\\W3SVC1\\` for detailed error messages.

---

## 3\. Offline Root CA — pkirootca (kept offline)

Purpose: Establish the trust anchor. Configure AIA/CDP so clients know where to fetch the root CA cert and CRL. Manually transfer files to DFS and publish to AD.

On pkirootca (standalone, NOT domain-joined):

```powershell
# CAPolicy.inf
Set-Content  C:\\Windows\\CAPolicy.inf '[Version]'
Add-Content C:\\Windows\\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\\Windows\\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\\Windows\\CAPolicy.inf 'URL=http://pki.pkilab.win.us/pkidata/cps.html'
Add-Content C:\\Windows\\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\\Windows\\CAPolicy.inf 'RenewalKeyLength=4096'
Add-Content C:\\Windows\\CAPolicy.inf 'RenewalValidityPeriod=Years'
Add-Content C:\\Windows\\CAPolicy.inf 'RenewalValidityPeriodUnits=20'
Add-Content C:\\Windows\\CAPolicy.inf 'LoadDefaultTemplates=0'
Add-Content C:\\Windows\\CAPolicy.inf 'AlternateSignatureAlgorithm=0'

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
certutil -setreg CA\\ValidityPeriodUnits 10
certutil -setreg CA\\ValidityPeriod Years
certutil -setreg CA\\CRLPeriodUnits 1
certutil -setreg CA\\CRLPeriod Years
certutil -setreg CA\\CRLDeltaPeriodUnits 0
certutil -setreg CA\\CRLOverlapPeriodUnits 7
certutil -setreg CA\\CRLOverlapPeriod Days
certutil -setreg CA\\AuditFilter 127

# CDP: clear and set (local + HTTP)
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA: clear LDAP/HTTP/FILE then set (local + HTTP)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\\CACertPublicationURLs '1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

# Publish initial CRL
Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl

# Optional rename and open folder
Rename-Item 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\pkirootca_PKILab Root CA.crt' 'PKILab Root CA.crt' -ErrorAction SilentlyContinue
explorer.exe 'C:\\Windows\\System32\\CertSrv\\CertEnroll'
```

Manual transfer (Root is offline):

1. Copy from pkirootca (CertEnroll) to removable media:

  * PKILab Root CA.crt

  * PKILab Root CA.crl

2. Place into DFS path using any domain-joined machine:

  * \\\\pkilab.win.us\\share\\PKIData\\

3. From a domain-joined admin machine, publish to AD:

```powershell
certutil -dspublish -f "\\\\pkilab.win.us\\share\\PKIData\\PKILab Root CA.crt" rootca
certutil -dspublish -f "\\\\pkilab.win.us\\share\\PKIData\\PKILab Root CA.crl" "PKILab Root CA"

# Verify enterprise root store
certutil -viewstore -enterprise Root
```

Power off pkirootca when not in use.

---

## 3.5 Issuing Subordinate CA Certificates from the Root CA

Purpose: Issue subordinate CA certificates for fliss1 and nyiss1 from the offline Root CA using command-line tools.

Prerequisites:

* Root CA (pkirootca) is powered on and the certsvc service is running.

* Subordinate CA request files have been copied to pkirootca:

  * `C:\\pkidata\\pkilab_issuing_fl.req` (from fliss1)

  * `C:\\pkidata\\pkilab_issuing_ny.req` (from nyiss1)

### 3.5.1 Submit, Approve, and Download Subordinate CA Certificates

On pkirootca, run the following commands for each issuing CA:

**For Florida Issuing CA (fliss1):**

```powershell
# Submit the certificate request
certutil -submit "C:\\pkidata\\pkilab_issuing_fl.req"

# Note the Request ID returned (e.g., 2). Use it in the next commands.

# Approve the request (replace <RequestID> with the actual ID, e.g., 2)
certutil -resubmit <RequestID>

# Download the issued certificate (replace <RequestID>)
certutil -retrieve <RequestID> "C:\\pkidata\\pkilab_issuing_fl.crt"
```

**For New York Issuing CA (nyiss1):**

```powershell
# Submit the certificate request
certutil -submit "C:\\pkidata\\pkilab_issuing_ny.req"

# Note the Request ID returned (e.g., 3). Use it in the next commands.

# Approve the request (replace <RequestID> with the actual ID, e.g., 3)
certutil -resubmit <RequestID>

# Download the issued certificate (replace <RequestID>)
certutil -retrieve <RequestID> "C:\\pkidata\\pkilab_issuing_ny.crt"
```

### 3.5.2 Transfer Issued Certificates to Issuing CAs

Copy the issued certificates to removable media or network share:

* `C:\\pkidata\\pkilab_issuing_fl.crt` → transfer to fliss1

* `C:\\pkidata\\pkilab_issuing_ny.crt` → transfer to nyiss1

### 3.5.3 Install Issued Certificates on Issuing CAs

On **fliss1**:

```powershell
# Install the issued certificate
certutil -installcert "C:\\pkidata\\pkilab_issuing_fl.crt"

# Start the Certification Authority service
Start-Service certsvc
```

On **nyiss1**:

```powershell
# Install the issued certificate
certutil -installcert "C:\\pkidata\\pkilab_issuing_ny.crt"

# Start the Certification Authority service
Start-Service certsvc
```

Alternatively, use the Certification Authority MMC:

1. Open `certsrv.msc` on the issuing CA.

2. Right-click the CA name → **All Tasks** → **Install CA Certificate**.

3. Browse to the issued `.crt` file and complete the wizard.

4. Start the Certification Authority service.

### 3.5.4 Verification

On each issuing CA, verify the CA certificate is installed:

```powershell
certutil -cainfo cert
```

Ensure the certificate chain builds to the Root CA and the CA service is running.

---

## 4\. Issuing CAs — fliss1 (FL) and nyiss1 (NY)

Purpose: Two enterprise issuing CAs for HA. Each publishes CRLs locally; issued certs embed a single HTTP CDP/AIA URL pointing to [pki.pkilab.win.us](http://pki.pkilab.win.us).

CA Common Names:

* FL: PKILab Issuing CA - FL

* NY: PKILab Issuing CA - NY

### 4.1 Install Issuing CA on fliss1

```powershell
# CAPolicy.inf (prevents default templates auto-load)
Set-Content  C:\\Windows\\CAPolicy.inf '[Version]'
Add-Content C:\\Windows\\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\\Windows\\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\\Windows\\CAPolicy.inf 'URL=http://pki.pkilab.win.us/pkidata/cps.html'
Add-Content C:\\Windows\\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\\Windows\\CAPolicy.inf 'LoadDefaultTemplates=0'

# Role and request
Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName    = 'PKILab Issuing CA - FL'
  CADistinguishedNameSuffix = 'O=PKILab,L=Fort Lauderdale,S=Florida,C=US'
  CAType    = 'EnterpriseSubordinateCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  DatabaseDirectory    = 'C:\\pkidata'
  OutputCertRequestFile    = 'C:\\pkidata\\pkilab_issuing_fl.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

Enroll/issue SubCA cert from the Root CA:

* Copy C:\\pkidata\\pkilab_issuing_fl.req to pkirootca (power on temporarily).

* On pkirootca, issue pkilab_issuing_fl.crt to the SubCA request (see Section 3.5).

* On fliss1, install the issued certificate and start the Certification Authority service.

Configure validity, CDP, AIA, and OCSP on fliss1:

```powershell
# Validity and CRL schedule
certutil -setreg CA\\ValidityPeriodUnits 1
certutil -setreg CA\\ValidityPeriod Years
certutil -setreg CA\\CRLPeriodUnits 52
certutil -setreg CA\\CRLPeriod Weeks
certutil -setreg CA\\CRLDeltaPeriodUnits 0
certutil -setreg CA\\CRLOverlapPeriodUnits 3
certutil -setreg CA\\CRLOverlapPeriod Days
certutil -setreg CA\\AuditFilter 127

# Clear existing CDPs
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# 1) Local publish
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force

# 2) Single HTTP namespace for clients (embed in issued certs)
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

# AIA: local + HTTP (embed HTTP in issued certs)
Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\\CACertPublicationURLs '1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

# OCSP URL (single, DNS HA) — Scripted addition to AIA (alternative to GUI)

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

Publish Issuing CA - FL to AD (from fliss1 or any domain-joined admin machine):

```powershell
$cer = Get-ChildItem 'C:\\Windows\\System32\\CertSrv\\CertEnroll' -Filter '*PKILab Issuing CA - FL*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

Ensure that files are copied to the DFS pkidata folder:

* C:\\Windows\\System32\\CertSrv\\CertEnroll\\PKILab Issuing CA - FL.crl

* C:\\Windows\\System32\\CertSrv\\CertEnroll\\PKILab Issuing CA - FL+.crl

* C:\\pkidata\\pkilab_issuing_fl.crt

### 4.2 Install Issuing CA on nyiss1 (repeat with NY names)

```powershell
# CAPolicy.inf
Set-Content  C:\\Windows\\CAPolicy.inf '[Version]'
Add-Content C:\\Windows\\CAPolicy.inf 'Signature="$Windows NT$"'
Add-Content C:\\Windows\\CAPolicy.inf '[InternalPolicy]'
Add-Content C:\\Windows\\CAPolicy.inf 'URL=http://pki.pkilab.win.us/pkidata/cps.html'
Add-Content C:\\Windows\\CAPolicy.inf '[Certsrv_Server]'
Add-Content C:\\Windows\\CAPolicy.inf 'LoadDefaultTemplates=0'

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName    = 'PKILab Issuing CA - NY'
  CADistinguishedNameSuffix = 'O=PKILab,L=New York,S=New York,C=US'
  CAType    = 'EnterpriseSubordinateCA'
  CryptoProviderName    = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName    = 'SHA256'
  KeyLength    = 4096
  DatabaseDirectory    = 'C:\\pkidata'
  OutputCertRequestFile    = 'C:\\pkidata\\pkilab_issuing_ny.req'
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force -OverwriteExistingKey
```

* Copy C:\\pkidata\\pkilab_issuing_ny.req to pkirootca, issue pkilab_issuing_ny.crt (see Section 3.5), complete installation on nyiss1, then start the service.

Configure CDP/AIA/OCSP on nyiss1 (same as FL):

```powershell
certutil -setreg CA\\ValidityPeriodUnits 1
certutil -setreg CA\\ValidityPeriod Years
certutil -setreg CA\\CRLPeriodUnits 52
certutil -setreg CA\\CRLPeriod Weeks
certutil -setreg CA\\CRLDeltaPeriodUnits 0
certutil -setreg CA\\CRLOverlapPeriodUnits 3
certutil -setreg CA\\CRLOverlapPeriod Days
certutil -setreg CA\\AuditFilter 127

$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }
Add-CACRLDistributionPoint -Uri 'C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%8.crl' -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri 'http://pki.pkilab.win.us/pkidata/%3%8.crl' -AddToCertificateCDP -AddToFreshestCrl -Force

Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
certutil -setreg CA\\CACertPublicationURLs '1:C:\\Windows\\System32\\CertSrv\\CertEnroll\\%3%4.crt'
Add-CAAuthorityInformationAccess -AddToCertificateAia 'http://pki.pkilab.win.us/pkidata/%3%4.crt' -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -crl
```

Publish Issuing CA - NY to AD:

```powershell
$cer = Get-ChildItem 'C:\\Windows\\System32\\CertSrv\\CertEnroll' -Filter '*PKILab Issuing CA - NY*.crt' | Select-Object -First 1
certutil -dspublish -f "$($cer.FullName)" NTAuthCA
certutil -dspublish -f "$($cer.FullName)" SubCA
```

Ensure that files are copied to the DFS pkidata folder:

* C:\\Windows\\System32\\CertSrv\\CertEnroll\\PKILab Issuing CA - NY.crl

* C:\\Windows\\System32\\CertSrv\\CertEnroll\\PKILab Issuing CA - NY+.crl

* C:\\pkidata\\pkilab_issuing_ny.crt

### Enable required certificate templates on BOTH issuing CAs (see Section 7).

Duplicate the existing OCSP Template "PKILab OCSP Response Signing":

* Compatibility: Certificate Authority = 2016, Certificate recipient = Win10/Server 2016

* Request Handling: Purpose = Signature, Allow private key to be exported - "leave unchecked"

* Cryptography: Minimum Key size = 4096

* Security: Add both OCSP server computer objects with Read, Enroll and AutoEnroll

---

## 5\. OCSP Responders — flocsp and nyocsp1 (single URL)

Purpose: Real-time revocation with responders in both sites. Use single OCSP URL with DNS flip for HA.

Install role on each OCSP server:

```powershell
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
```

On both Issuing CAs, ensure AIA includes the single OCSP URL:

* ocsp:[http://ocsp.pkilab.win.us/ocsp](http://ocsp.pkilab.win.us/ocsp) (checked to include in AIA of issued certs) and restart each CA service.

Configure Online Responder Management on flocsp and nyocsp1:

**For FLOCSP1:**

* Base CRLs: [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crl)

* Delta CRLs: [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL+.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL+.crl)

**For NYOCSP1:**

* Base CRLs: [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crl)

* Delta CRLs: [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY+.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY+.crl)

* Create a Revocation Configuration per Issuing CA (two configs per server: FL and NY CA).

* Provider: Microsoft CRL-based Revocation.

* Ensure OCSP servers can read Issuing CA CRLs (HTTP or AD CDP access).

* Enroll "OCSP Response Signing" certificates (autoenroll or manual).

* Confirm status = Online.

Validation from any domain-joined machine:

```powershell
certutil -url <path-to-an-end-entity.cer>
# Select OCSP, click Retrieve; flip ocsp CNAME to validate failover.
```

---

## 6\. Validation

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

## 7\. Certificate Templates, Autoenrollment, and Horizon VDI (Omnissa)

Goal: Define and publish the minimum certificate templates, enable autoenrollment, and support Horizon VDI user certificates.

### 7.1 Create AD groups for template security

Create these global security groups (in AD Users and Computers):

* PKI Web Servers — add web servers (flweb1$, nyweb1$) or any server that needs a Web Server cert.

* PKI OCSP Servers — add flocsp$$.

* PKI Horizon Enrollment — service accounts/servers involved in Horizon True SSO (if used).

* PKI Certificate Managers — delegated approvers for pending requests (optional).

* **PKI Web Enrollment Users** — users authorized to access [https://pki.pkilab.win.us/certsrv](https://pki.pkilab.win.us/certsrv) (created in Section 2.6.1).

### 7.2 Enable Autoenrollment via GPO

On a domain GPO applied to the target scope (Computers and/or Users):

* Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client – Auto-Enrollment:

  * Configuration Model: Enabled

  * Renew expired certificates, update pending certificates, and remove revoked…: Checked

  * Update certificates that use certificate templates: Checked

* If issuing User certificates, also enable the same under User Configuration.

### 7.3 Minimum templates to publish

Perform template creation with certtmpl.msc (Certificate Templates MMC). Then publish templates on each Issuing CA (certsrv.msc > Certification Authority > Certificate Templates > New > Certificate Template to Issue).

#### A) Web Server certificate (for IIS/LDAPS/HTTPS)

* Base: Duplicate "Web Server" (Windows Server 2016+ compatibility).

* Template display name: PKILab Web Server

* Template name: PKILabWebServer

* Validity: 2 years; Renewal period: 6 weeks (adjust as desired).

* Subject Name: Supply in the request (allow SAN). For AD autoenroll, you may prefer "Build from AD information" if names are predictable.

* Cryptography: KSP; 2048 or 4096-bit RSA; allow private key export (optional).

* Extensions (EKU): Server Authentication only (remove others).

* Security: Grant Read/Enroll/Autoenroll to PKI Web Servers. Grant Read/Enroll to admins as needed.

* **Important for /certsrv SSL:** Ensure the certificate includes SANs for `pki.pkilab.win.us`, `flweb1.pkilab.win.us`, and `nyweb1.pkilab.win.us`.

* Publish on both Issuing CAs.

#### B) OCSP Response Signing (for OCSP responders)

* Use built-in template "OCSP Response Signing" (do not duplicate unless needed).

* Security: Grant Read/Enroll/Autoenroll to PKI OCSP Servers.

* Ensure Autoenrollment GPO applies to OCSP servers.

* Publish on both Issuing CAs.

#### C) Computer (Machine) certificate (for domain members, LDAPS, Wi-Fi, etc.)

* Use built-in "Computer" template.

* Security: Domain Computers already have Enroll/Autoenroll by default (verify).

* Publish on both Issuing CAs as needed.

#### D) Domain Controller Authentication (Smart Card/LDAPS readiness)

* Use built-in "Domain Controller Authentication" template.

* Security: Domain Controllers group should have Enroll/Autoenroll.

* Publish on both Issuing CAs.

* Validate on each DC:

```powershell
# On each DC
gpupdate /force
Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'Server Authentication|Client Authentication' }
```

#### E) User certificate (for client auth/SMIME; required for some Horizon use-cases)

* Base: Duplicate "User".

* Template display name: PKILab User

* Template name: PKILabUser

* Validity: 1–2 years; Renewal: 6 weeks.

* Subject Name: Build from AD (UPN/email).

* Extensions (EKU): Client Authentication (and optionally Secure Email if SMIME required).

* Security: Grant Read/Enroll/Autoenroll to appropriate user groups (e.g., Domain Users or a scoped group).

* Publish on both Issuing CAs as needed.

#### F) Horizon VDI (Omnissa) — choose ONE path

**Path 1: Horizon True SSO (recommended)**

Requires an Enrollment Server and integration with AD CS.

Templates:

1. Enrollment Agent certificate for the Enrollment Server:

  * Use built-in "Enrollment Agent" (or duplicate) and issue to the Enrollment Server service account/computer as per Omnissa guidance.

2. True SSO User Logon certificate template (short-lived user logon certs):

  * Base: Duplicate "Smartcard Logon" or "User" and include EKUs: Smart Card Logon + Client Authentication.

  * Subject Name: Supply in request (UPN in SAN). Allow subject alternative name: UPN.

  * Validity: very short (e.g., 8 hours). Renewal: not applicable (non-renewed short-lived).

  * Security: Grant Enroll to the Enrollment Server (service/computer) and Horizon Connection Servers per vendor guidance (PKI Horizon Enrollment group).

  * Cryptography: KSP, RSA 2048+, no export needed.

  * Publish both templates on both Issuing CAs.

**Path 2: Classic Smart Card Logon (physical/smart card based)**

Template:

* Duplicate "Smartcard Logon".

* EKUs: Smart Card Logon + Client Authentication.

* Subject: Supply in request (UPN in SAN), enforce KDC mapping.

* Security: Enroll permissions to issuance process or users; typically not autoenrolled.

**Horizon Integration Checklist (placeholder — fill with your specifics later)**

* Enrollment Server has Enrollment Agent cert issued and trusted.

* True SSO User Logon template created and permissions assigned.

* Connection Servers trust chain includes Root + Issuing CAs.

* Test flow: VDI launch → short-lived user cert issued → logon succeeds; OCSP reachable at [http://ocsp.pkilab.win.us/ocsp](http://ocsp.pkilab.win.us/ocsp).

### 7.4 Publish the templates on each Issuing CA

On each Issuing CA (fliss1 and nyiss1):

* certsrv.msc > Certification Authority > \[CA Name\] > Certificate Templates > right-click > New > Certificate Template to Issue

* Select: PKILab Web Server, OCSP Response Signing, Computer, Domain Controller Authentication, PKILab User, and your Horizon True SSO templates (if used).

### 7.5 Verify autoenrollment and issuance

* On an OCSP server (e.g., flocsp), run `gpupdate /force`, then open certlm.msc > Personal > Certificates. You should see an "OCSP Response Signing" certificate.

* On a web server (e.g., flweb1), request a "PKILab Web Server" cert via MMC or autoenrollment; ensure SAN contains the host FQDN and `pki.pkilab.win.us`.

* On DCs, verify "Domain Controller Authentication" certificate is present; validate LDAPS with `openssl s_client -connect <dc>:636 -showcerts` from a test box.

* For Computer/User templates, verify autoenrollment delivers certs after GPO refresh.

---

## 8\. Security, Networking, and Operations Enhancements

### 8.1 Firewall and service ports (review/allow)

* Clients → Web: TCP 80 and TCP 443 to flweb1/nyweb1 ([pki.pkilab.win.us](http://pki.pkilab.win.us) resolves via CNAME).

* Clients → OCSP: TCP 80 to flocsp/nyocsp1 ([ocsp.pkilab.win.us](http://ocsp.pkilab.win.us) CNAME).

* CAs ↔ DCs/AD: RPC 135 + dynamic RPC 49152–65535, LDAP 389/636, GC 3268/3269, Kerberos 88, SMB 445, DNS 53.

* CAs/OCSP → HTTP CDP: TCP 80 to web servers.

### 8.2 Time sync

* Ensure all PKI servers use a reliable NTP source. Skew breaks Kerberos, CRL/OCSP validity.

### 8.3 CA security hardening and RBAC

* Create and use:

  * PKI Admins — manage CA configuration

  * PKI Auditors — read-only log review

  * Certificate Managers — approve/revoke certs

* Remove daily use of Domain Admins on CAs; use least privilege.

* Confirm CA auditing (AuditFilter 127) and Windows auditing for Object Access and Certification Services.

### 8.4 Key archival and Recovery (optional; needed for S/MIME)

* Create small KRA group; issue "Key Recovery Agent" template to KRA members.

* Enable key archival on templates that require recovery (e.g., PKILabUser if S/MIME used).

* Secure KRAs and document recovery steps; test with a lab certificate.

### 8.5 Backup and Disaster Recovery

On each Issuing CA (periodic):

```powershell
# Backup CA database and logs
certutil -backupDB C:\\CA_Backup\\DB

# Backup CA key and cert (prompt for password)
certutil -backupKey C:\\CA_Backup\\Key

# Export CA config
reg export "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration" C:\\CA_Backup\\ca_config.reg /y
Copy-Item C:\\Windows\\CAPolicy.inf C:\\CA_Backup\\ -ErrorAction SilentlyContinue
```

* Root CA: back up to offline, secured media with tamper evidence.

* Web pkidata: DFS provides redundancy; also back up backend targets.

* Document CA restore steps (install ADCS role, restore DB/Key, import config, start service).

### 8.6 Monitoring and health

* PKIView: regular checks for AIA/CDP/CRLs and OCSP status.

* Event logs:

  * Microsoft-Windows-CertificationAuthority/Operational

  * Microsoft-Windows-OnlineResponder/Operational

* Synthetic health checks: HTTP 200 checks for pkidata files; OCSP test queries.

### 8.7 Template scope and SAN rules

* For PKILab Web Server: enforce DNS SANs; include any farm/alias names (e.g., [pki.pkilab.win.us](http://pki.pkilab.win.us)) as SANs where needed.

* Decide on private key export policy.

### 8.8 Directory browsing hardening (optional)

* Consider disabling directory browsing in production; publish an index.html with explicit links if you still want a landing page.

### 8.9 OCSP responder signing cert lifecycle

* Ensure autoenrollment for OCSP Response Signing is active.

* Verify each responder renews before expiry and can read updated CRLs.

### 8.10 Renewal runbooks

* Root CA CRL: generate annually (or as policy dictates), copy to \\\\pkilab.win.us\\share\\PKIData, and `certutil -dspublish` to AD.

* Issuing CA CRL: schedule weekly; verify HTTP availability after each publication.

* DNS flip procedures for pki/ocsp CNAMEs documented and tested.

### 8.11 CRL Republishing Path (Important for Production)

**Critical Note:** If the CRL or delta CRL is republished manually (e.g., after a revocation or scheduled update), the publish path **must** be the DFS path `\\\\pkilab.win.us\\share\\PKIData` rather than a local path.

Publishing to the local `C:\\Windows\\System32\\CertSrv\\CertEnroll` folder will require manual copying to the DFS share in production, which introduces delay and potential for error.

To republish CRLs to the DFS path:

```powershell
# On each Issuing CA (fliss1 or nyiss1)
certutil -crl "\\\\pkilab.win.us\\share\\PKIData\\%3%8.crl"
```

Alternatively, ensure the CDP publish locations include the DFS UNC path (see Section 4 and Appendix for configuration).

---

## 9\. Client trust distribution

* Domain-joined: trust is automatic via AD (you published Root and SubCA to NTAuth/SubCA).

* Non-domain devices (if any):

  * Export Root + Issuing CA certs from \\\\pkilab.win.us\\share\\PKIData and import to the devices' trust stores.

  * For Linux/Unix services using OpenSSL, add to system trust bundle and restart daemons.

---

## 10\. PKIView Required Files

PKIView (pkiview.msc) is a critical tool for validating the health of your PKI infrastructure. For PKIView to function properly and display accurate status information, the following files must be accessible:

### Required Files for Root CA Validation:

* **Root CA Certificate:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Root CA.crt

* **Root CA CRL:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Root CA.crl

### Required Files for Florida Issuing CA Validation:

* **Issuing CA Certificate:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Issuing CA - FL.crt

* **Issuing CA CRL:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Issuing CA - FL.crl

* **Issuing CA Delta CRL:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Issuing CA - FL+.crl

### Required Files for New York Issuing CA Validation:

* **Issuing CA Certificate:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Issuing CA - NY.crt

* **Issuing CA CRL:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Issuing CA - NY.crl

* **Issuing CA Delta CRL:** \\\\pkilab.win.us\\share\\PKIData\\PKILab Issuing CA - NY+.crl

### HTTP Accessibility Requirements:

All files must be accessible via HTTP at the following URLs:

* [http://pki.pkilab.win.us/pkidata/PKILab Root CA.crt](http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crt)

* [http://pki.pkilab.win.us/pkidata/PKILab Root CA.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crl)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL.crt](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crt)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crl)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - FL+.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL+.crl)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY.crt](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crt)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crl)

* [http://pki.pkilab.win.us/pkidata/PKILab Issuing CA - NY+.crl](http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY+.crl)

### Active Directory Publication Requirements:

The following certificates must also be published to Active Directory:

* Root CA certificate published to the Enterprise Root store

* Both Issuing CA certificates published to NTAuthCA and SubCA containers

### Verification Commands:

```powershell
# Verify Root CA in AD
certutil -viewstore -enterprise Root

# Verify Issuing CAs in AD
certutil -viewstore -enterprise NTAuth
certutil -viewstore -enterprise CA

# Test HTTP accessibility
$urls = @(
  'http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL+.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20NY+.crl'
)
foreach ($u in $urls) { 
    try { 
        $response = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10
        Write-Host "$u - OK ($($response.StatusCode))" -ForegroundColor Green
    } catch { 
        Write-Host "$u - FAILED: $($_.Exception.Message)" -ForegroundColor Red
    } 
}
```

**Note:** If PKIView shows errors, verify that all files listed above are present in the DFS share and accessible via HTTP. Missing or inaccessible files will cause PKIView validation failures.

---

## Appendix A — Notes on DFS

* DFS Namespace: \\\\pkilab.win.us\\share with folder PKIData.

* Ensure DFS Namespace referrals are site-aware (DFSR/targets present in both sites with proper priorities).

* Set NTFS and share ACLs on DFS targets to include PKILAB\\fliss1$ and PKILAB\\nyiss1$ with Modify so CAs can publish/copy when needed.

* Clients will only ever see the HTTP URL; DFS is a backend implementation detail that the web servers read from.

---

## Appendix B — DFS Namespace Targets (examples and ACLs)

This appendix provides concrete examples for backend DFS targets and recommended permissions. Replace the example server names with your actual file servers if they differ.

### Example DFS Namespace and targets

* DFS Namespace: \\\\pkilab.win.us\\share

* Folder in namespace: PKIData

* Target 1 (Florida): \\\\flfilesrv\\pki\\PKIData

* Target 2 (New York): \\\\nyfilesrv\\pki\\PKIData

### DFS Namespace settings (recommended)

* Enable site-costed referrals.

* Set target priority: prefer local site (e.g., FL users prefer \\\\flfilesrv, NY users prefer \\\\nyfilesrv).

* Low TTL (300–600 seconds) for quick failover.

* Enable failback so clients return to preferred target after recovery.

### DFS Replication (DFSR) for PKIData

* Create a replication group for the two targets.

* Topology: Full mesh (2-way) with reasonable bandwidth throttling as needed.

* Staging quota: 4–8 GB (or larger for big CRLs/archives); disable RDC (optional) as CRLs are small.

* File/Folder filters: Ensure .crl, .crt, .cer are NOT excluded.

* Antivirus exclusions: Exclude the PKIData folders from real-time scan to avoid lock delays during CRL writes.

### Share permissions (on each backend target share)

* Administrators: Full Control

* PKILAB\\fliss1$: Change

* PKILAB\\nyiss1$: Change

* Web access principals: Read

  * Option A (simplest): Authenticated Users: Read

  * Option B (tightest): PKILAB\\flweb1$, PKILAB\\nyweb1$: Read

### NTFS permissions (on the PKIData folder root, inherit to children)

* SYSTEM: Full Control

* Administrators: Full Control

* PKILAB\\fliss1$: Modify, This folder, subfolders and files

* PKILAB\\nyiss1$: Modify, This folder, subfolders and files

* Web servers (if using tight ACLs): PKILAB\\flweb1$, PKILAB\\nyweb1$: Read & execute, This folder, subfolders and files

* (Optional) Deny write for non-PKI admins to protect integrity of published files.

### Operational notes

* CAs publish CRLs/certs locally; copy to \\\\pkilab.win.us\\share\\PKIData (DFS namespace) or directly into backend target for their site; DFSR replicates across sites.

* IIS virtual directory on flweb1/nyweb1 points to the DFS namespace path (\\\\pkilab.win.us\\share\\PKIData) so both servers always serve the current content.

---

## Appendix C — Initial Smoke Tests (LDAPS, OCSP, Web bindings)

Run these after completing the setup to validate core functionality.

### Web AIA/CDP (HTTP) checks

From any domain machine:

```powershell
$urls = @(
  'http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crt',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Root%20CA.crl',
  'http://pki.pkilab.win.us/pkidata/PKILab%20Issuing%20CA%20-%20FL.crt',
  'http://pk
```