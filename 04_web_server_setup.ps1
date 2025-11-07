# PKI Lab - Web Server Setup Script (flweb1 or nyweb1)
# Run on each web server (run as Administrator)

# 1. Install IIS and management tools
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools

# 2. Create IIS virtual directory pointing to DFS UNC path (correct UNC with double backslashes)
$vDirProps = @{ Site = 'Default Web Site'; Name = 'pkidata'; PhysicalPath = '\\pkilab.win.us\share\PKIData' }
# Create the virtual directory if it does not exist, otherwise update the physical path
if (-not (Test-Path "IIS:\Sites\$($vDirProps.Site)\$($vDirProps.Name)")) {
    New-WebVirtualDirectory @vDirProps
} else {
    Set-ItemProperty "IIS:\Sites\$($vDirProps.Site)\$($vDirProps.Name)" -Name physicalPath -Value $vDirProps.PhysicalPath
}

# 3. Enable directory browsing (optional) and allow double escaping
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProps.Site)\$($vDirProps.Name)"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\Sites\$($vDirProps.Site)"

# 4. Add MIME types for CRL and CRT
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crl'; mimeType='application/pkix-crl'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.crt'; mimeType='application/x-x509-ca-cert'}
Add-WebConfigurationProperty -pspath 'IIS:' -filter "system.webServer/staticContent" -name "." -value @{fileExtension='.cer'; mimeType='application/x-x509-ca-cert'}

# 5. Optional: Set cache-control header for pkidata
Set-WebConfiguration -Filter /system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$($vDirProps.Site)" -Value @{name='Cache-Control';value='public, max-age=604800'}

# 6. Optionally configure the App Pool to run as the domain service account PKILAB\PKIWebSvc
#    Recommended: either set the virtual directory "Connect As..." to PKILAB\PKIWebSvc (GUI) or set the AppPool identity to that account.
#    The script below offers an interactive option to change DefaultAppPool to the service account (you will be prompted for the password).
$choose = Read-Host "Change DefaultAppPool identity to PKILAB\PKIWebSvc? (y/N)"
if ($choose -match '^(?i)y') {
    $cred = Get-Credential 'PKILAB\PKIWebSvc'
    $pw = $cred.GetNetworkCredential().Password
    # Use appcmd to set the app pool identity (appcmd requires cleartext password in the command)
    & "$env:windir\system32\inetsrv\appcmd.exe" set apppool /apppool.name:"DefaultAppPool" /processModel.identityType:SpecificUser /processModel.userName:"PKILAB\PKIWebSvc" /processModel.password:"$pw"
    Restart-WebAppPool -Name 'DefaultAppPool'
    Write-Host "DefaultAppPool identity set to PKILAB\PKIWebSvc and recycled."
} else {
    Write-Host "Skipping AppPool identity change. To use Connect As for only the virtual directory, set it manually in IIS Manager -> Sites -> Default Web Site -> pkidata -> Basic Settings -> Connect As..."
}

# 7. Verification - test the HTTP endpoint
Write-Host "Testing http://pki.pkilab.win.us/pkidata/ ..."
try {
    $r = Invoke-WebRequest 'http://pki.pkilab.win.us/pkidata/' -UseBasicParsing -TimeoutSec 10
    Write-Host "HTTP request succeeded, StatusCode: $($r.StatusCode)"
} catch {
    Write-Warning "HTTP request failed: $($_.Exception.Message)"
    Write-Host "If this fails, verify: (1) the virtual directory points to \\pkilab.win.us\share\PKIData, (2) PKILAB\PKIWebSvc or the web machine accounts have Read on the share and NTFS, and (3) the DefaultAppPool identity or Connect As is configured correctly."
}