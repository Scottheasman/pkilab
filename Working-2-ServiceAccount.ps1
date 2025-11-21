
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

### 4.2 Create Service Account and Permissions

#### 4.2.1 Create service account & group (Domain Controller)

Run on `$DC1` or `$DC2`:

```powershell
$pwd = Read-Host -Prompt "Enter password for $PkiWebSvcAccount" -AsSecureString

New-ADUser -Name $PkiWebSvcAccount `
    -SamAccountName $PkiWebSvcAccount `
    -AccountPassword $pwd `
    -Enabled $true `
    -PasswordNeverExpires $false

New-ADGroup -Name 'PKI Web Servers' -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity 'PKI Web Servers' -Members $PkiWebSvcAccount