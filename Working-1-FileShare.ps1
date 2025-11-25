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

####

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

#####

### 3.2 Grant Machine Permissions for PKI Roles

# These machine accounts will publish/read PKI data:
# 
# - SubCAs: `$SubCA1`, `$SubCA2`
# - Web: `$WebServer1`, `$WebServer2`
# - OCSP: `$OcspServer1`, `$OcspServer2`
# 
# Run on **both** `$FileServer1` and `$FileServer2`:

# ```powershell
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
#```