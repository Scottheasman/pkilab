# Working-AD-SetDelegation.ps1
# Configure constrained (Kerberos-only) delegation for PKIWebSvc
# Run elevated on DC1 or an RSAT host

Import-Module ActiveDirectory -ErrorAction Stop

# --- CONFIGURE THESE VALUES as needed ---
$SvcSam = "PKIWebSvc"                   # sAMAccountName of your service user
$CAHostsFqdn = @("subca1.lab.local","subca2.lab.local")  # CA host FQDNs
# ----------------------------------------

# Build list of SPNs to allow delegation to (HOST/<fqdn> is usually sufficient)
$spnsToAdd = $CAHostsFqdn | ForEach-Object { "HOST/$_" }

Write-Host "Setting msDS-AllowedToDelegateTo on $SvcSam to allow:" -ForegroundColor Cyan
$spnsToAdd | ForEach-Object { Write-Host "  $_" }

# Read current attribute safely
$user = Get-ADUser -Identity $SvcSam -Properties msDS-AllowedToDelegateTo -ErrorAction Stop
$current = @()
if ($user.'msDS-AllowedToDelegateTo') { $current = $user.'msDS-AllowedToDelegateTo' }

# Merge uniquely and apply (preserve existing)
$new = ($current + $spnsToAdd) | Select-Object -Unique
$ht = @{}
$ht['msDS-AllowedToDelegateTo'] = $new

Write-Host "Applying delegation configuration..."
Set-ADUser -Identity $SvcSam -Replace $ht -ErrorAction Stop

# Confirm
Write-Host "`nResulting msDS-AllowedToDelegateTo for $SvcSam:" -ForegroundColor Green
(Get-ADUser -Identity $SvcSam -Properties msDS-AllowedToDelegateTo).'msDS-AllowedToDelegateTo' | ForEach-Object { Write-Host "  $_" }

Write-Host "`nDone. Allow AD replication if multiple DCs. Restart CertSrvPool/PKIHttpPool on both web servers and test from a client." -ForegroundColor Yellow