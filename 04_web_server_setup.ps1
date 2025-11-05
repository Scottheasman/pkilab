
# PKI Lab - Web Server Setup Script (flweb1 or nyweb1)
# Run on each web server

# 1. Install IIS and management tools
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools

# 2. Create IIS virtual directory pointing to DFS UNC path
$vDirProps = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\pkilab.win.us\share\PKIData' }
New-WebVirtualDirectory @vDirProps

# 3. Enable directory browsing and allow double escaping
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProps.Site)\$($vDirProps.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\Sites\$($vDirProps.Site)"

# 4. Add MIME types for CRL and CRT
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}

# 5. Optional: Set cache-control header for pkidata
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$($vDirProps.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}

# 6. Verification
Write-Host "Verify IIS virtual directory and MIME types are configured."
Invoke-WebRequest 'http://pki.pkilab.win.us/pkidata/' -UseBasicParsing
