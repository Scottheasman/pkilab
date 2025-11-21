# 1. Common Variables
# Domain and Namespace
$DomainFqdn       = "lab.local"
$DomainNetBios    = "LAB"
$DfsRoot          = "\\lab.local\share"
$PkiFolderName    = "PKIData"

# HTTP Hostnames
$PkiHttpHost      = "pki.lab.local"
$OcspHttpHost     = "ocsp.lab.local"

# Service Account for IIS
$PkiWebSvcAccount = "PKIWebSvc"

# Derived Paths
$DfsPkiPath       = "$DfsRoot\$PkiFolderName"   # \\lab.local\share\PKIData
$PkiHttpBase      = "http://$PkiHttpHost/pkidata"
$OcspHttpBase     = "http://$OcspHttpHost/ocsp"

###

#2. Configure IIS and App Pool Identity (Both Web Servers)
# Install IIS and scripting tools
Install-WindowsFeature Web-Server, Web-Scripting-Tools -IncludeManagementTools

Import-Module WebAdministration

# Prompt securely for the PKI web service account password
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString

# Convert SecureString → plain text (required by IIS for app pool password)
$BSTR          = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Configure DefaultAppPool to run as LAB\PKIWebSvc
# identityType 3 = SpecificUser
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.userName  -Value "${DomainNetBios}\${PkiWebSvcAccount}"
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.password  -Value $passwordPlain

# Clear plain-text password variable
$passwordPlain = $null

# Restart the app pool
Restart-WebAppPool DefaultAppPool

# 3. Create HTTP Binding for pki.lab.local (Both Web Servers)
Import-Module WebAdministration

$binding = Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
}

# 4. Create Virtual Directory /pkidata to DFS (Both Web Servers)
Import-Module WebAdministration

# Create (or re-use) the pkidata virtual directory under Default Web Site
$DfsPkiPath = "\\lab.local\share\PKIData"

$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory `
        -Site "Default Web Site" `
        -Name "pkidata" `
        -PhysicalPath $DfsPkiPath
} else {
    # Ensure path is correct if it already exists
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}

# 5. Enable Directory Browsing, Request Filtering, MIME Types (Both Web Servers)
Import-Module WebAdministration

# Enable directory browsing on /pkidata
Set-WebConfigurationProperty `
    -Filter /system.webServer/directoryBrowse `
    -Name enabled `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site\pkidata"

# Allow double escaping on the site
Set-WebConfigurationProperty `
    -Filter /system.webServer/security/requestFiltering `
    -Name allowDoubleEscaping `
    -Value true `
    -PSPath "IIS:\Sites\Default Web Site"

# Helper to ensure MIME type exists (idempotent)
function Ensure-MimeType {
    param(
        [string]$Extension,
        [string]$MimeType
    )

    $existing = Get-WebConfigurationProperty -pspath 'IIS:' `
        -filter 'system.webServer/staticContent/mimeMap' `
        -name '.' |
        Where-Object { $_.fileExtension -eq $Extension }

    if (-not $existing) {
        Add-WebConfigurationProperty -pspath 'IIS:' `
            -filter 'system.webServer/staticContent' `
            -name '.' `
            -value @{ fileExtension = $Extension; mimeType = $MimeType }
    }
}

# Ensure MIME types for CRL and CRT
Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'

# 6. Quick Validation
# Confirm IIS vDir
Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata"

# Confirm DFS path is reachable
Test-Path '\\lab.local\share\PKIData'
Get-ChildItem '\\lab.local\share\PKIData'
