0. Common Assumptions / Variables
Root CA: Lab Root CA (offline).
Issuing CAs (already configured):
Lab Issuing CA 1 (SubCA1)
Lab Issuing CA 2 (SubCA2)
DFS Share: \\lab.local\share\PKIData
HTTP path: http://pki.lab.local/pkidata
Web servers: WEB1, WEB2
OCSP servers: OCSP1, OCSP2
OCSP URL to embed: http://ocsp.lab.local/ocsp
1. Web Server Template for CertSrv
Do this once on one issuing CA (SubCA1).

1.1 Create WebServer-CertSrv Template
On SubCA1:

Open Certificate Templates console:
text
Copy
certtmpl.msc
Right‑click Web Server → Duplicate Template.
Configure:
General:
Template display name: WebServer-CertSrv
Template name: WebServer-CertSrv
Validity: e.g. 2 years
Renewal period: e.g. 6 weeks
Request Handling:
Purpose: Signature and encryption
Allow private key to be exported: Unchecked.
Subject Name:
Supply in the request.
Extensions → Application Policies:
Ensure Server Authentication is present.
Security:
Add either:
a group (recommended): LAB\PKI-WebServers, or
specific servers: WEB1$, WEB2$
Allow: Enroll (Autoenroll optional).
Click OK to save.
1.2 Issue the Template from SubCA1
On SubCA1, open Certification Authority (certsrv.msc):

Right‑click Certificate Templates → New → Certificate Template to Issue.
Select WebServer-CertSrv → OK.
(Optionally repeat that on SubCA2 if you want both CAs to issue from this template.)

2. HTTPS CertSrv on WEB1
2.1 Request HTTPS Certificate (CN = pki.lab.local, SAN = pki.lab.local + WEB1)
On WEB1 (as domain admin):

powershell
Copy
$PkiHttpHost           = "pki.lab.local"
$WebServerTemplateName = "WebServer-CertSrv"

New-Item -Path "C:\PKIData" -ItemType Directory -Force | Out-Null

$infPath  = "C:\PKIData\web1_https.inf"
$reqPath  = "C:\PKIData\web1_https.req"
$certPath = "C:\PKIData\web1_https.cer"

@"
[Version]
Signature=`"$Windows NT$`

[NewRequest]
Subject = "CN=$PkiHttpHost"
Exportable = FALSE
KeyLength = 4096
KeySpec = 1
KeyUsage = 0xa0
MachineKeySet = TRUE
SMIME = FALSE
RequestType = PKCS10
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$PkiHttpHost&"
_continue_ = "dns=WEB1.lab.local&"

[RequestAttributes]
CertificateTemplate = $WebServerTemplateName
"@ | Set-Content -Path $infPath -Encoding ASCII

certreq -new  $infPath $reqPath
certreq -submit -attrib "CertificateTemplate:$WebServerTemplateName" $reqPath $certPath
certreq -accept $certPath
When prompted, select Lab Issuing CA 1.

You should see output showing:

Subject: CN=pki.lab.local (DNS Name=pki.lab.local, DNS Name=WEB1.lab.local)
NotAfter around 1 year (due to CA limits).
2.2 Bind Certificate with netsh (ipport)
Still on WEB1:

powershell
Copy
$PkiHttpHost = "pki.lab.local"

# Get the new cert
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -like "*CN=$PkiHttpHost*"
} | Sort-Object NotAfter -Descending | Select-Object -First 1

$thumb = $cert.Thumbprint -replace ' ', ''
$thumb

# Bind to 0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=$thumb appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" certstorename=MY
You should see:

text
Copy
SSL Certificate successfully added
2.3 Ensure HTTPS Binding in IIS
powershell
Copy
Import-Module WebAdministration

# Check existing HTTPS binding
Get-WebBinding -Name "Default Web Site" -Protocol https

# If nothing returns, create it:
# New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -HostHeader "pki.lab.local"
If you already see:

text
Copy
https    *:443:pki.lab.local
you’re set. If not, run the New-WebBinding line once.

3. HTTPS CertSrv on WEB2
Repeat a similar process on WEB2.

3.1 Request HTTPS Certificate (CN = pki.lab.local, SAN = pki.lab.local + WEB2)
On WEB2:

powershell
Copy
$PkiHttpHost           = "pki.lab.local"
$WebServerTemplateName = "WebServer-CertSrv"

New-Item -Path "C:\PKIData" -ItemType Directory -Force | Out-Null

$infPath  = "C:\PKIData\web2_https.inf"
$reqPath  = "C:\PKIData\web2_https.req"
$certPath = "C:\PKIData\web2_https.cer"

@"
[Version]
Signature=`"$Windows NT$`

[NewRequest]
Subject = "CN=$PkiHttpHost"
Exportable = FALSE
KeyLength = 4096
KeySpec = 1
KeyUsage = 0xa0
MachineKeySet = TRUE
SMIME = FALSE
RequestType = PKCS10
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$PkiHttpHost&"
_continue_ = "dns=WEB2.lab.local&"

[RequestAttributes]
CertificateTemplate = $WebServerTemplateName
"@ | Set-Content -Path $infPath -Encoding ASCII

certreq -new  $infPath $reqPath
certreq -submit -attrib "CertificateTemplate:$WebServerTemplateName" $reqPath $certPath
certreq -accept $certPath
3.2 Bind Certificate with netsh (ipport)
powershell
Copy
$PkiHttpHost = "pki.lab.local"

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -like "*CN=$PkiHttpHost*"
} | Sort-Object NotAfter -Descending | Select-Object -First 1

$thumb = $cert.Thumbprint -replace ' ', ''
$thumb

netsh http add sslcert ipport=0.0.0.0:443 certhash=$thumb appid="{00112233-4455-6677-8899-AABBCCDDEEFF}" certstorename=MY
3.3 Ensure HTTPS Binding in IIS
powershell
Copy
Import-Module WebAdministration

Get-WebBinding -Name "Default Web Site" -Protocol https

# If empty, run:
# New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -HostHeader "pki.lab.local"
4. OCSP Response Signing Template
Do this once on SubCA1.

4.1 Create OCSP-ResponseSigning Template
On SubCA1:

Run certtmpl.msc.
Right‑click OCSP Response Signing → Duplicate Template.
Configure:
General:
Template display name: OCSP-ResponseSigning
Template name: OCSP-ResponseSigning
Validity: 2 days
Renewal period: 1 day
Request Handling:
Purpose: Signature
Allow private key to be exported: Unchecked
Subject Name:
Supply in the request
Security:
Add: OCSP1$, OCSP2$ (or group LAB\PKI-OCSP-Servers)
Allow: Enroll (Autoenroll optional)
Save.
4.2 Issue the Template
On SubCA1 (certsrv.msc):

Right‑click Certificate Templates → New → Certificate Template to Issue.
Select OCSP-ResponseSigning → OK.
(Optionally repeat on SubCA2’s CA console if you want both CAs to issue OCSP signing certs.)

5. Install and Configure OCSP Role
5.1 OCSP1
On OCSP1:

powershell
Copy
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
Then configure via GUI:

Open Online Responder Management: ocsp.msc.
Right‑click Revocation Configuration → Add Revocation Configuration.
Wizard steps for Lab Issuing CA 1:
Name: Lab Issuing CA 1 OCSP
Provider: select Lab Issuing CA 1.
Revocation provider: Use CRLs from SubCA1 (wizard auto‑configures from CA).
Signing certificate:
Choose Automatically select a signing certificate.
Template: OCSP-ResponseSigning.
Optionally add another revocation config for Lab Issuing CA 2 on OCSP1:

Name: Lab Issuing CA 2 OCSP
CA: Lab Issuing CA 2
Same signing template.
5.2 OCSP2
On OCSP2:

powershell
Copy
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools
Repeat the same GUI configuration in ocsp.msc:

Revocation configurations for:
Lab Issuing CA 1 OCSP
Lab Issuing CA 2 OCSP
Using OCSP-ResponseSigning.
6. Add OCSP URL to SubCAs (OCSP Extension)
We want newly issued certs from SubCA1 and SubCA2 to contain:

HTTP AIA: http://pki.lab.local/pkidata/...
OCSP: http://ocsp.lab.local/ocsp
On SubCA1 and then SubCA2:

powershell
Copy
$OcspHttpBase = "http://ocsp.lab.local/ocsp"
Import-Module ADCSAdministration

# Remove any existing OCSP entries
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ocsp*' } |
  Remove-CAAuthorityInformationAccess -Force

# Add OCSP URL to OCSP extension
Add-CAAuthorityInformationAccess `
    -Uri $OcspHttpBase `
    -AddToCertificateOcsp `
    -Force

Restart-Service certsvc
(New certs from these CAs now include OCSP URL.)

7. Validation & Compliance
7.1 Manual Checks
On each SubCA (1 and 2):

CRL Distribution Points:
Local & UNC publish CRLs + delta, not in CDP extension.
HTTP URL present in CDP extension only.
AIA:
HTTP AIA present.
No ldap:// or file:// in embedded URLs.
OCSP:
OCSP URL in OCSP extension: http://ocsp.lab.local/ocsp.
7.2 Deep Validation Script (Run on SubCA1 & SubCA2)
Before running, set:

powershell
Copy
$PkiHttpBase  = "http://pki.lab.local/pkidata"
$OcspHttpBase = "http://ocsp.lab.local/ocsp"
Then:

powershell
Copy
Write-Host "=== PKI Configuration Validation ===" -ForegroundColor Cyan

$expectedCDP_HTTP = $PkiHttpBase
$expectedAIA_HTTP = $PkiHttpBase
$expectedOCSP     = $OcspHttpBase

$caConfigKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$caName = (Get-ItemProperty $caConfigKey).Active
Write-Host "`nCA Name: $caName" -ForegroundColor Yellow

Write-Host "`n--- CRL Distribution Points (CRLPublicationURLs) ---" -ForegroundColor Yellow
$crlOutput = certutil -getreg CA\CRLPublicationURLs
$crlOutput | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$') {
    $flags = [int]$matches[1]
    $url   = $matches[2].Trim()
    $addToCertCDP = ($flags -band 0x02) -ne 0

    if ($url -match [regex]::Escape($expectedCDP_HTTP) -and $addToCertCDP) {
      Write-Host "CDP OK   ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ldap://|file://' -and $addToCertCDP) {
      Write-Host "Legacy CDP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n--- AIA & OCSP (CACertPublicationURLs / AIA) ---" -ForegroundColor Yellow

$aiaReg = certutil -getreg CA\CACertPublicationURLs
$aiaReg | Where-Object { $_ -match '^\s+\d+:\s+\d+:' } | ForEach-Object {
  if ($_ -match '^\s+\d+:\s+(\d+):(.+)$') {
    $flags = [int]$matches[1]
    $url   = $matches[2].Trim()
    $addToAIA  = ($flags -band 0x02) -ne 0
    $addToOCSP = ($flags -band 0x20) -ne 0

    if ($url -match [regex]::Escape($expectedAIA_HTTP) -and $addToAIA) {
      Write-Host "AIA OK   ✅ $url" -ForegroundColor Green
    } elseif ($url -match [regex]::Escape($expectedOCSP) -and $addToOCSP) {
      Write-Host "OCSP OK  ✅ $url" -ForegroundColor Green
    } elseif ($url -match 'ocsp' -and $addToOCSP -and $url -notmatch [regex]::Escape($expectedOCSP)) {
      Write-Host "OCSP Wrong Domain ⚠️ $url (should be $expectedOCSP)" -ForegroundColor Yellow
    } elseif ($url -match 'ldap://|file://' -and ($addToAIA -or $addToOCSP)) {
      Write-Host "Legacy AIA/OCSP embedded ❌ $url" -ForegroundColor Red
    }
  }
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan
Expected: all green CDP OK, AIA OK, OCSP OK, and no red legacy URLs.

You can now re‑run this entire set in your lab from a clean snapshot, and it should get you to:

HTTPS CertSrv on WEB1/WEB2 with pki.lab.local.
OCSP online responders for both SubCAs.
Clean HTTP‑only CDP/AIA/OCSP configuration validated on both issuing CAs