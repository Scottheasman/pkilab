# EnrollCertOnly.ps1

# ----- CONFIG -----
$hostname = $env:COMPUTERNAME
$domain = "lab.local"
$fqdn = "$hostname.$domain"
$reqHost = "req.lab.local"
$pkiHost = "pki.lab.local"
$templateName = "Lab-WebServerCertsrv"

# ----- Create INF for 4096-bit cert request with SANs -----
$infContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$reqHost"
Exportable = TRUE
KeyLength = 4096
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = True
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$reqHost&dns=$fqdn"

[RequestAttributes]
CertificateTemplate = $templateName
"@

$infPath = "$env:TEMP\WebServerCert.inf"
$infContent | Out-File -FilePath $infPath -Encoding ASCII

# ----- Submit request -----
$requestPath = "$env:TEMP\WebServerCert.req"
$responsePath = "$env:TEMP\WebServerCert.cer"
Write-Host "Submitting certificate request for $fqdn..." -ForegroundColor Yellow
certreq -new $infPath $requestPath
certreq -submit -config "subca1.lab.local\Lab Issuing CA 1" $requestPath $responsePath

# ----- Accept cert -----
Write-Host "Accepting certificate for $fqdn..." -ForegroundColor Yellow
certreq -accept $responsePath

# ----- Clean up -----
Remove-Item $infPath, $requestPath, $responsePath -Force

Write-Host "✅ Certificate enrolled for $fqdn with SANs: $reqHost, $fqdn" -ForegroundColor Green