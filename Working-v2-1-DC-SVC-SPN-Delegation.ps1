# Run elevated on a DC or RSAT host with AD module
Import-Module ActiveDirectory

# Variables (adjust if needed)
$DomainNetBios = "LAB"
$SvcSam = "PKIWebSvc"
$GroupName = "PKI Web Servers"

# Prompt for password
$pwd = Read-Host -Prompt "Enter password for $DomainNetBios\$SvcSam" -AsSecureString

# Create user (adjust properties if you want password never expires = $true)
New-ADUser -Name $SvcSam `
    -SamAccountName $SvcSam `
    -AccountPassword $pwd `
    -Enabled $true `
    -PasswordNeverExpires $false

# Create group and add membership
if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security
}
Add-ADGroupMember -Identity $GroupName -Members $SvcSam

# SPN
setspn -X
setspn -S HTTP/pki.lab.local LAB\PKIWebSvc
setspn -S HTTP/req.lab.local LAB\PKIWebSvc

# Optional: add short-name SPNs if clients will use short names:
setspn -S HTTP/pki LAB\PKIWebSvc
setspn -S HTTP/req LAB\PKIWebSvc

# 4 - Configure Resource-Based Constrained Delegation (RBCD) so CA computers trust PKIWebSvc

# =============================================================================
# RBCD-SET.ps1 - Configure RBCD for PKIWebSvc → CA Servers
# Run on DC as Enterprise Admin
# =============================================================================

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


# 5 Validation of Delegation
# =============================================================================
# RBCD-VALIDATE.ps1 - Verify RBCD Configuration
# Run on DC after configuration
# =============================================================================

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