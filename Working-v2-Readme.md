# PKI Lab Deployment Instructions  

## 1 - Domain Controllers - Service Account SPN and Delegation

### DC.lab.local

### 1 - Common Variables
```powershell
$DomainNetBios = "LAB"
$SvcSam = "PKIWebSvc"
$GroupName = "PKI Web Servers"
```

### 2 - Create a service account
```powershell
# Prompt for password
$pwd = Read-Host -Prompt "Enter password for $DomainNetBios\$SvcSam" -AsSecureString

# Create service account
New-ADUser -Name $SvcSam `
    -SamAccountName $SvcSam `
    -AccountPassword $pwd `
    -Enabled $true `
    -PasswordNeverExpires $true

# Create group and add membership
if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security
}
Add-ADGroupMember -Identity $GroupName -Members $SvcSam
```
### 3 - Create SPN 

```powershell
setspn -S HTTP/pki.lab.local LAB\PKIWebSvc
setspn -S HTTP/req.lab.local LAB\PKIWebSvc

# verify SPN
setspn -L LAB\PKIWebSvc
setspn -Q HTTP/pki.lab.local

```
### 4 - Configure Resource-Based Constrained Delegation (RBCD) so CA computers trust PKIWebSvc

```powershell
Import-Module ActiveDirectory -ErrorAction Stop

# CONFIGURATION
$ServiceAccount = "PKIWebSvc"
$TargetComputers = @("subca1", "subca2")  # EDIT YOUR CA SERVER NAMES HERE

Write-Host "🚀 Configuring RBCD: $ServiceAccount → $($TargetComputers -join ', ')" -ForegroundColor Cyan

# RBCD GUID: Validated-MS-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
$RBCD_GUID = [guid]"cc05a6da-1a38-433b-b09c-9f4d07f55eaa"

foreach ($computer in $TargetComputers) {
    Write-Host "`n📋 Processing $computer..." -ForegroundColor Green
    
    try {
        # Get target computer object
        $target = Get-ADComputer $computer -ErrorAction Stop
        
        # Create RBCD ACE
        $trustee = [System.Security.Principal.NTAccount]$ServiceAccount
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $trustee,
            [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight",
            [System.Security.AccessControl.AccessControlType]::Allow,
            $RBCD_GUID
        )
        
        # Apply ACE to nTSecurityDescriptor
        $acl = Get-Acl "AD:\$($target.DistinguishedName)"
        $acl.AddAccessRule($ace)
        Set-Acl "AD:\$($target.DistinguishedName)" $acl
        
        Write-Host "  ✅ RBCD GRANTED: $ServiceAccount → $computer" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ FAILED $computer`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n🎉 RBCD CONFIGURATION COMPLETE!" -ForegroundColor Green
Write-Host "⏳ Replication: Instant on DC" -ForegroundColor Yellow
```

### 5 Validation of Delegation   
#### =============================================================================
#### Run on DC after configuration
#### =============================================================================

```powershell
Import-Module ActiveDirectory -ErrorAction Stop

# CONFIGURATION
$ServiceAccount = "PKIWebSvc"
$TargetComputers = @("subca1", "subca2")  # SAME AS CONFIG SCRIPT

$RBCD_GUID = [guid]"cc05a6da-1a38-433b-b09c-9f4d07f55eaa"

Write-Host "🔍 RBCD VALIDATION REPORT" -ForegroundColor Cyan
Write-Host "Service Account: $ServiceAccount`n" -ForegroundColor White

$AllGood = $true

foreach ($computer in $TargetComputers) {
    try {
        $target = Get-ADComputer $computer -ErrorAction Stop
        $acl = Get-Acl "AD:\$($target.DistinguishedName)"
        $rbcdAce = $acl.Access | Where-Object { 
            $_.ObjectType -eq $RBCD_GUID -and 
            $_.IdentityReference -like "*$ServiceAccount*"
        }
        
        Write-Host "$computer :" -NoNewline -ForegroundColor Cyan
        
        if ($rbcdAce) {
            Write-Host " ✅ VALID RBCD ACE" -ForegroundColor Green
            Write-Host "  👤 User: $($rbcdAce.IdentityReference)" -ForegroundColor White
            Write-Host "  ⚡ Right: $($rbcdAce.ActiveDirectoryRights)" -ForegroundColor White
            Write-Host "  🔑 GUID: $($rbcdAce.ObjectType)" -ForegroundColor Gray
        } else {
            Write-Host " ❌ RBCD ACE MISSING!" -ForegroundColor Red
            $AllGood = $false
        }
    }
    catch {
        Write-Host "$computer : ❌ ERROR - $($_.Exception.Message)" -ForegroundColor Red
        $AllGood = $false
    }
    Write-Host ""
}

# FINAL STATUS
Write-Host "📊 VALIDATION SUMMARY:" -ForegroundColor Yellow
if ($AllGood) {
    Write-Host "  🎉 ALL RBCD ACES VALIDATED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "  ✅ PKIWebSvc can delegate to all target CAs" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  SOME RBCD ACES MISSING - Re-run configuration script" -ForegroundColor Red
}

Write-Host "`n✅ EXPECTED STATE:"
Write-Host "   • PKIWebSvc Delegation tab: 'Do not trust'" -ForegroundColor Gray
Write-Host "   • CA Servers Delegation tab: 'Do not trust'" -ForegroundColor Gray
Write-Host "   • RBCD ACE: In CA nTSecurityDescriptor only" -ForegroundColor Gray
```




## 2 - File Share   

### File1.lab.local   
Run the following commands on file1.lab.local   

### 1 - Common Variables

```powershell
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
```

### 2 - Create Folder  
 
```powershell
$folderPath = $LocalPkiFolder
if (-Not (Test-Path $folderPath)) { 
    New-Item -Path $folderPath -ItemType Directory 
}
```
### 3 - Create SMB share   
```powershell
$shareName = $ShareName
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

### 4 - Grant computer accounts Permissions 

```powershell
# These machine accounts will publish/read PKI data:
# 
# - SubCAs: `$SubCA1`, `$SubCA2`
# - Web: `$WebServer1`, `$WebServer2`
# - OCSP: `$OcspServer1`, `$OcspServer2`
# 
# Extract short hostnames for machine accounts
$SubCA1Short = ($SubCA1 -split '\.')[0]
$SubCA2Short = ($SubCA2 -split '\.')[0]
$Web1Short = ($WebServer1 -split '\.')[0]
$Web2Short = ($WebServer2 -split '\.')[0]
$Ocsp1Short = ($OcspServer1 -split '\.')[0]
$Ocsp2Short = ($OcspServer2 -split '\.')[0]
```

### 5 - Share Access
```powershell
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
# Serive account must already exist.
icacls $LocalPkiFolder /grant "${DomainNetBios}\${PkiWebSvcAccount}:(OI)(CI)RX" /T
Grant-SmbShareAccess -Name $ShareName `
  -AccountName "${DomainNetBios}\${PkiWebSvcAccount}" `
  -AccessRight Read -Force
```

## Switch to File2.lab.local   

### File2.lab.local   
Run the following commands on file2.lab.local   

### 1 - Common Variables

```powershell
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
```

### 2 - Create Folder  
 
```powershell
$folderPath = $LocalPkiFolder
if (-Not (Test-Path $folderPath)) { 
    New-Item -Path $folderPath -ItemType Directory 
}
```
### 3 - Create SMB share   
```powershell
$shareName = $ShareName
if (-Not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Administrators","SYSTEM"
}
```

### 4 - Grant computer accounts Permissions 

```powershell
# These machine accounts will publish/read PKI data:
# 
# - SubCAs: `$SubCA1`, `$SubCA2`
# - Web: `$WebServer1`, `$WebServer2`
# - OCSP: `$OcspServer1`, `$OcspServer2`
# 
# Extract short hostnames for machine accounts
$SubCA1Short = ($SubCA1 -split '\.')[0]
$SubCA2Short = ($SubCA2 -split '\.')[0]
$Web1Short = ($WebServer1 -split '\.')[0]
$Web2Short = ($WebServer2 -split '\.')[0]
$Ocsp1Short = ($OcspServer1 -split '\.')[0]
$Ocsp2Short = ($OcspServer2 -split '\.')[0]
```

### 5 - Share Access
```powershell
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
# Serive account must already exist.
icacls $LocalPkiFolder /grant "${DomainNetBios}\${PkiWebSvcAccount}:(OI)(CI)RX" /T
Grant-SmbShareAccess -Name $ShareName `
  -AccountName "${DomainNetBios}\${PkiWebSvcAccount}" `
  -AccessRight Read -Force
  ```

## 3 - Install IIS for pki.lab.local/pkidata
### Deploy-PKI-HttpOnly.ps1
### Run elevated on WEB01 / WEB02

```powershell
# ----- CONFIG -----
$DomainNetBios = "LAB"
$PkiWebSvcAccount = "PKIWebSvc"
$PkiHttpHost = "pki.lab.local"
$DfsPkiPath = "\\lab.local\share\PKIData"
$PKIHttpPool = "PKIHttpPool"

# ----- ensure elevated -----
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script elevated (Run as Administrator)." ; exit 1
}

# ----- Install / import WebAdministration if missing -----
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Host "Installing IIS features..." -ForegroundColor Yellow
    Install-WindowsFeature Web-Server, Web-Static-Content, Web-Default-Doc, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Scripting-Tools -IncludeManagementTools -ErrorAction Stop
}
Import-Module WebAdministration -ErrorAction Stop

# ----- Prompt for service account password -----
$passwordSecure = Read-Host -Prompt "Enter password for ${DomainNetBios}\${PkiWebSvcAccount}" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordSecure)
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
$serviceAccount = "${DomainNetBios}\${PkiWebSvcAccount}"

# ----- Create app pool and set identity -----
if (-not (Test-Path "IIS:\AppPools\$PKIHttpPool")) { New-WebAppPool -Name $PKIHttpPool }
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.userName -Value $serviceAccount
Set-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel.password -Value $passwordPlain
Restart-WebAppPool $PKIHttpPool

# ----- Ensure Default Web Site bound to pki.lab.local:80 -----
Start-Website "Default Web Site"
if (-not (Get-WebBinding -Name "Default Web Site" -Protocol http -HostHeader $PkiHttpHost -ErrorAction SilentlyContinue)) {
    New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -HostHeader $PkiHttpHost
    Write-Host "Added HTTP binding for $PkiHttpHost" -ForegroundColor Green
} else { Write-Host "HTTP binding for $PkiHttpHost already exists." }

# ----- Create /pkidata vdir and app pointing to DFS -----
if (-not (Test-Path $DfsPkiPath)) { Write-Warning "DFS path $DfsPkiPath not reachable. Check network/permissions for $serviceAccount." }
$existingVDir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue
if (-not $existingVDir) {
    New-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
} else {
    Set-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath
}
if (-not (Get-WebApplication -Site "Default Web Site" -Name "pkidata" -ErrorAction SilentlyContinue)) {
    New-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
} else {
    Set-WebApplication -Site "Default Web Site" -Name "pkidata" -PhysicalPath $DfsPkiPath -ApplicationPool $PKIHttpPool
}

# Ensure Default Web Site runs in the PKIHttpPool
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name applicationPool -Value $PKIHttpPool
Restart-WebAppPool $PKIHttpPool

# ----- Configure auth, directory browsing, request filtering -----
Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfiguration -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath "MACHINE/WEBROOT/APPHOST" -Metadata overrideMode -Value Allow
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value $true -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name userName -Value "" -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -Name enabled -Value $false -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $true -PSPath "IIS:\Sites\Default Web Site\pkidata"
Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $true -PSPath "IIS:\Sites\Default Web Site"

# ----- Ensure MIME types for CRL/CRT -----
function Ensure-MimeType { param([string]$Extension,[string]$MimeType)
    $existing = Get-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent/mimeMap' -name '.' | Where-Object { $_.fileExtension -eq $Extension }
    if (-not $existing) {
        Add-WebConfigurationProperty -pspath 'IIS:' -filter 'system.webServer/staticContent' -name '.' -value @{ fileExtension = $Extension; mimeType = $MimeType }
    }
}
Ensure-MimeType -Extension '.crl' -MimeType 'application/pkix-crl'
Ensure-MimeType -Extension '.crt' -MimeType 'application/x-x509-ca-cert'

# ----- Clear plaintext password and finish -----
$passwordPlain = $null
Write-Host "`nPKI HTTP /pkidata configuration complete." -ForegroundColor Green

# Quick validation
Write-Host "`n-- Quick validation --"
Get-WebBinding -Name "Default Web Site"
Get-WebVirtualDirectory -Site "Default Web Site" -Name "pkidata"
Get-ItemProperty "IIS:\AppPools\$PKIHttpPool" -Name processModel | Select-Object processModel.userName, processModel.identityType
try { Invoke-WebRequest "http://$PkiHttpHost/pkidata" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop | Select-Object StatusCode } catch { Write-Warn "Local HTTP test failed: $($_.Exception.Message)" }
```

## 4 - Install the Offline Root CA

### 1 - Common Variables
```powershell
$DomainFqdn    = "lab.local"
$PkiHttpHost   = "pki.lab.local"
$RootCAName    = "Lab Root CA"

# Derived
$PkiHttpBase   = "http://$PkiHttpHost/pkidata"
$DfsPkiPath    = "\\lab.local\share\PKIData"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
```
### 2 - Create CAPolicy.inf
```powershell
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=20
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
```
### 3 Install AD CS Role and Configure Root CA
```powershell
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configure Root CA
$vCaRootProperties = @{
  CACommonName              = $RootCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'StandaloneRootCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  ValidityPeriod            = 'Years'
  ValidityPeriodUnits       = 20
}
Install-AdcsCertificationAuthority @vCaRootProperties -Force
```

### 4 Configure Validity and CRL Settings
```powershell
# Issued cert validity (for subCAs etc.)
certutil -setreg CA\ValidityPeriodUnits 10
certutil -setreg CA\ValidityPeriod "Years"

# Base CRL
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Years"

# No delta CRL for offline root
certutil -setreg CA\CRLDeltaPeriodUnits 0

# CRL overlap
certutil -setreg CA\CRLOverlapPeriodUnits 7
certutil -setreg CA\CRLOverlapPeriod "Days"

# Audit everything
certutil -setreg CA\AuditFilter 127

Restart-Service certsvc
# 5.5 Configure CDP and AIA
# powershell
# Copy
Import-Module ADCSAdministration
```

### 5 - Configure CDP and AIA locations

#### 5.1 -------- CDP (CRL Distribution Points) --------
```powershell
# 1 Clear existing CDP entries
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# 2 Local CRL location where CA writes the CRL
Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

# 3 HTTP CDP that will be embedded in issued certs
Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force
```

#### 5.2 -------- AIA (Authority Information Access) --------

```powershell
# 1 Remove existing AIA entries (HTTP/LDAP/file/UNC)
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

# 2 Local publication path for the CA certificate (where CA saves its own cert)
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt"

# 3. HTTP AIA that clients will use to download the issuer (root) cert
Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Restart-Service certsvc
# 4 Publish a fresh CRL
certutil -CRL
Start-Sleep -Seconds 2

# 5 Rename the root CA certificate to a clean name
# (CRL is already named correctly by the CA)
Rename-Item "$CertEnrollDir\caroot1_$RootCAName.crt" "$CertEnrollDir\$RootCAName.crt" -Force

# 6 Open the folder for manual copy
explorer.exe $CertEnrollDir

# Manual step (offline-root-friendly):

# In C:\Windows\System32\CertSrv\CertEnroll, you should now see:
# Lab Root CA.crt
# Lab Root CA.crl
# Copy these two files (USB / clipboard / etc.) to a domain-joined machine.
```
### 6 Check CA cert publication path
```powershell
certutil -getreg CA\CACertPublicationURLs
```
### 7 Check CDP configuration
```powershell
Import-Module ADCSAdministration
Get-CACrlDistributionPoint | Format-Table Uri, PublishToServer, AddToCertificateCDP, AddToFreshestCrl -AutoSize
```

### 8 Check AIA configuration
Get-CAAuthorityInformationAccess | Format-Table Uri, AddToCertificateAia, AddToCertificateOcsp -AutoSize
```
```text
You should see:
 
CDP:
C:\Windows\System32\CertSrv\CertEnroll\<CAName><CRLNameSuffix>.crl with PublishToServer = True
http://pki.lab.local/pkidata/<CAName><CRLNameSuffix>.crl with AddToCertificateCDP = True, AddToFreshestCrl = True
AIA:
http://pki.lab.local/pkidata/<CAName><CertificateName>.crt with AddToCertificateAia = True
```

### 9 - Place Root CA files in DFS/IIS location:
```text
Past the two files to:  \\lab.local\share\PKIData\
Validate by going to the following urls on a domain joined client.
http://pki.lab.local/pkidata/Lab Root CA.crt
http://pki.lab.local/pkidata/Lab Root CA.crl

Verify HTTP Access
From Any Domain Client:
\\lab.local\share\PKIData\

Verify from any domain-joined machine:
```

```powershell
$PkiHttpBase = "http://pki.lab.local/pkidata"
$RootCAName  = "Lab Root CA"

# Test HTTP access to Root CA cert
Invoke-WebRequest -Uri "$PkiHttpBase/$RootCAName.crt" -UseBasicParsing

# Test HTTP access to Root CRL
Invoke-WebRequest -Uri "$PkiHttpBase/$RootCAName.crl" -UseBasicParsing
# Both should return StatusCode 200.
# 
# You can also simply browse to:
# 
http://pki.lab.local/pkidata/
# and confirm the two files are visible.
```

### 10 Publish Root CA Certificate and CRL to Active Directory

```text   
After you've copied the Root CA cert and CRL to \\lab.local\share\PKIData\ and verified HTTP access, publish them to AD so domain clients and subordinate CAs can trust the root.
Run on any domain-joined machine with access to the DFS share (e.g., a DC, SubCA1, or WEB01):
```   
```powershell
$DfsPkiPath = "\\lab.local\share\PKIData"
$RootCAName = "Lab Root CA"

# Publish Root CA certificate to AD (Trusted Root and NTAuth stores)
certutil -dspublish -f "$DfsPkiPath\$RootCAName.crt" RootCA

# Publish Root CRL to AD
certutil -addstore -f root "$DfsPkiPath\$RootCAName.crt"
```
```text
This ensures:

Domain clients automatically trust certificates issued by your PKI.
Subordinate CAs can validate their chain to the root.

Open the cert store on the server you ran dspublish from and you will see the root cert in
"trusted Root Certification Authorities"\Certificates
"Intermediate Certification Authorities"\Certificates

On other servers run Gpupdate /Force to pick up the new published cert
```

## 5 - Install Sub CAs
### Install Subca1.lab.local
# 6. SUBCA1 – Lab Issuing CA 1 (do ALL of this first)
# 6.1 SubCA1 – Variables and Folder
# Run on SubCA1 as a domain admin:
# 
# powershell
# Copy
# Common PKI settings
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

# This CA's name
$SubCAName = "Lab Issuing CA 1"

New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null
# 6.2 SubCA1 – CAPolicy.inf
# powershell
# Copy
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096  
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

# Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
# 6.3 SubCA1 – Install AD CS Role & Generate Request
# powershell
# Copy
# Install AD CS Certification Authority role
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configure as Enterprise Subordinate CA and output a request file
$vCaIssProperties = @{
  CACommonName              = $SubCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\Windows\System32\CertLog'
  LogDirectory              = 'C:\Windows\System32\CertLog'
  OutputCertRequestFile     = "$LocalPkiFolder\subca1_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force

# Open folder for manual copy
explorer.exe $LocalPkiFolder
# Manual step (SubCA1 → Root CA):

# Copy C:\PKIData\subca1_request.req from SubCA1 to the Root CA at
# C:\PKIData\subca1_request.req.
# 6.4 SubCA1 – Issue Subordinate Cert on Root CA
# Run on the Root CA:
# 
# powershell
# Copy
# Submit the request. If only one Root CA, you’ll get a prompt – choose your root.
certreq -submit C:\PKIData\subca1_request.req C:\PKIData\subca1_issued.cer
# If it goes pending:

# powershell
# Copy
# First SUbca request will be ID 2
certutil -resubmit 2
certreq -retrieve 2 C:\PKIData\subca1_issued.cer
# Manual step (Root CA → SubCA1):

# Copy C:\PKIData\subca1_issued.cer from Root CA back to SubCA1 at
C:\PKIData\subca1_issued.cer.
# 6.5 SubCA1 – Install Issued Cert and Start CA
# Run on SubCA1:
# 
# powershell
# Copy
# Install the issued SubCA certificate
certutil -installcert C:\PKIData\subca1_issued.cer

# Start CA service
Start-Service certsvc

# Basic health check
Get-Service certsvc
certutil -ping
# 6.6 SubCA1 – Configure Validity, CDP, and AIA
# Run on SubCA1:
# 
# powershell
# Copy
Import-Module ADCSAdministration

# ---- Validity & CRL settings ----

# 1-year issued certs
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod "Years"

# Weekly base CRL
certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Weeks"

# Daily delta CRL
certutil -setreg CA\CRLDeltaPeriodUnits 1
certutil -setreg CA\CRLDeltaPeriod "Days"

# 3-day CRL overlap
certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod "Days"

# Audit everything
certutil -setreg CA\AuditFilter 127

# ---- CDP (CRL Distribution Points) ----

$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

# 1. Local CRL+delta location
Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

# 2. DFS share CRL+delta (for IIS)
Add-CACRLDistributionPoint `
    -Uri "$DfsPkiPath\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

# 3. HTTP CDP (embedded in certs)
Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8%9.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force

# ---- AIA (Authority Information Access) ----

# Clear existing HTTP/LDAP/file/UNC AIA entries
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

# Local + DFS publication of SubCA1 certificate
certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt`n2:$DfsPkiPath\%3%4.crt"

# HTTP AIA (embedded)
Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Restart-Service certsvc
Start-Sleep -Seconds 2

# Publish initial CRL
certutil -CRL
# 6.7 SubCA1 – Publish Cert to AD and Copy to DFS
# Run on SubCA1:
# 
# powershell
# Copy
$SubCAName     = "Lab Issuing CA 1"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
$DfsPkiPath    = "\\lab.local\share\PKIData"
$PkiHttpBase   = "http://pki.lab.local/pkidata"

# 1. Rename the SubCA certificate to a clean name (if needed)
$cer = Get-ChildItem $CertEnrollDir -Filter "*.crt" | Select-Object -First 1
if ($cer -and $cer.Name -ne "$SubCAName.crt") {
    Rename-Item $cer.FullName "$CertEnrollDir\$SubCAName.crt" -Force
}

# 2. Publish into AD (NTAuth and SubCA containers)
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" NTAuthCA
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" SubCA

# 3. Copy SubCA1 cert to DFS for HTTP AIA
Copy-Item "$CertEnrollDir\$SubCAName.crt" "$DfsPkiPath\$SubCAName.crt" -Force

Write-Host "SubCA1 certificate published to AD and copied to DFS" -ForegroundColor Green

# 4. Quick HTTP verification
Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crt" -UseBasicParsing
Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crl" -UseBasicParsing
# 7. SUBCA2 – Lab Issuing CA 2 (repeat pattern)
# Now repeat the same procedure on SubCA2, changing only the CA name and the request file names.
# 
# 7.1 SubCA2 – Variables and Folder
# Run on SubCA2:
# 
# powershell
# Copy
$PkiHttpHost    = "pki.lab.local"
$PkiHttpBase    = "http://$PkiHttpHost/pkidata"
$DfsPkiPath     = "\\lab.local\share\PKIData"
$CertEnrollDir  = "C:\Windows\System32\CertSrv\CertEnroll"
$LocalPkiFolder = "C:\PKIData"

$SubCAName = "Lab Issuing CA 2"

New-Item -Path $LocalPkiFolder -ItemType Directory -Force | Out-Null
# 7.2 SubCA2 – CAPolicy.inf
# powershell
# Copy
$caPolicyContent = @"
[Version]
Signature="`$Windows NT`$"

[PolicyStatementExtension]
Policies=InternalPolicy

[InternalPolicy]
OID=1.2.3.4.1455.67.89.5
Notice="Legal Policy Statement"
URL=$PkiHttpBase/cps.html

[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Set-Content -Path C:\Windows\CAPolicy.inf -Value $caPolicyContent -Force
# 7.3 SubCA2 – Install AD CS Role & Generate Request
# powershell
# Copy
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

$vCaIssProperties = @{
  CACommonName              = $SubCAName
  CADistinguishedNameSuffix = 'O=Lab,L=Fort Lauderdale,S=Florida,C=US'
  CAType                    = 'EnterpriseSubordinateCA'
  CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
  HashAlgorithmName         = 'SHA256'
  KeyLength                 = 4096
  DatabaseDirectory         = 'C:\Windows\System32\CertLog'
  LogDirectory              = 'C:\Windows\System32\CertLog'
  OutputCertRequestFile     = "$LocalPkiFolder\subca2_request.req"
}
Install-AdcsCertificationAuthority @vCaIssProperties -Force

explorer.exe $LocalPkiFolder
# Manual step (SubCA2 → Root CA):

# Copy C:\PKIData\subca2_request.req from SubCA2 to the Root CA at
C:\PKIData\subca2_request.req.
# 7.4 SubCA2 – Issue Subordinate Cert on Root CA
# Run on the Root CA:
# 
# powershell
# Copy
certreq -submit C:\PKIData\subca2_request.req C:\PKIData\subca2_issued.cer
# If pending:
# 
# powershell
# Copy
# if this is the second subca request the ID will be 3
certutil -resubmit 3
certreq -retrieve 3 C:\PKIData\subca2_issued.cer
# Manual step (Root CA → SubCA2):

# Copy C:\PKIData\subca2_issued.cer back to SubCA2 at C:\PKIData\subca2_issued.cer.
# 7.5 SubCA2 – Install Issued Cert and Start CA
# Run on SubCA2:
# 
# powershell
# Copy
certutil -installcert C:\PKIData\subca2_issued.cer
Start-Service certsvc
Get-Service certsvc
certutil -ping
# 7.6 SubCA2 – Configure Validity, CDP, and AIA
# Run on SubCA2 (same pattern as SubCA1):
# 
# powershell
# Copy
Import-Module ADCSAdministration

# ---- Validity & CRL ----
certutil -setreg CA\ValidityPeriodUnits 1
certutil -setreg CA\ValidityPeriod "Years"

certutil -setreg CA\CRLPeriodUnits 1
certutil -setreg CA\CRLPeriod "Weeks"

certutil -setreg CA\CRLDeltaPeriodUnits 1
certutil -setreg CA\CRLDeltaPeriod "Days"

certutil -setreg CA\CRLOverlapPeriodUnits 3
certutil -setreg CA\CRLOverlapPeriod "Days"

certutil -setreg CA\AuditFilter 127

# ---- CDP ----
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.Uri -Force }

Add-CACRLDistributionPoint `
    -Uri "$CertEnrollDir\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACRLDistributionPoint `
    -Uri "$DfsPkiPath\%3%8%9.crl" `
    -PublishToServer `
    -PublishDeltaToServer `
    -Force

Add-CACRLDistributionPoint `
    -Uri "$PkiHttpBase/%3%8%9.crl" `
    -AddToCertificateCDP `
    -AddToFreshestCrl `
    -Force

# ---- AIA ----
Get-CAAuthorityInformationAccess |
  Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' -or $_.Uri -like '\\*' } |
  Remove-CAAuthorityInformationAccess -Force

certutil -setreg CA\CACertPublicationURLs "1:$CertEnrollDir\%3%4.crt`n2:$DfsPkiPath\%3%4.crt"

Add-CAAuthorityInformationAccess `
    -Uri "$PkiHttpBase/%3%4.crt" `
    -AddToCertificateAia `
    -Force

Restart-Service certsvc
Start-Sleep -Seconds 2
certutil -CRL
# 7.7 SubCA2 – Publish Cert to AD and Copy to DFS
# Run on SubCA2:
# 
# powershell
# Copy
$SubCAName     = "Lab Issuing CA 2"
$CertEnrollDir = "C:\Windows\System32\CertSrv\CertEnroll"
$DfsPkiPath    = "\\lab.local\share\PKIData"
$PkiHttpBase   = "http://pki.lab.local/pkidata"

$cer = Get-ChildItem $CertEnrollDir -Filter "*.crt" | Select-Object -First 1
if ($cer -and $cer.Name -ne "$SubCAName.crt") {
    Rename-Item $cer.FullName "$CertEnrollDir\$SubCAName.crt" -Force
}

certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" NTAuthCA
certutil -dspublish -f "$CertEnrollDir\$SubCAName.crt" SubCA

Copy-Item "$CertEnrollDir\$SubCAName.crt" "$DfsPkiPath\$SubCAName.crt" -Force

Write-Host "SubCA2 certificate published to AD and copied to DFS" -ForegroundColor Green

Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crt" -UseBasicParsing
Invoke-WebRequest -Uri "$PkiHttpBase/$SubCAName.crl" -UseBasicParsing
# If you want, the next step after this is to define certificate templates + auto‑enrollment in the same “SubCA1 then SubCA2” style.
# 


### Install Subca2.lab.local
