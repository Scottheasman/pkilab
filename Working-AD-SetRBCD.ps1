# Working-AD-SetRBCD.ps1
# Configure Resource-Based Constrained Delegation (RBCD) so CA computers trust PKIWebSvc
# Run elevated on DC1 or an RSAT host

Import-Module ActiveDirectory -ErrorAction Stop

# --- CONFIGURE ---
$SvcSam = "PKIWebSvc"
$CAComputerNames = @("subca1","subca2")   # AD computer 'Name' values (short hostnames)
# --- END CONFIG ---

# Resolve the service user SID
$svc = Get-ADUser -Identity $SvcSam -ErrorAction Stop
$svcSid = $svc.SID.Value

Write-Host "Adding PKIWebSvc SID $svcSid to msDS-AllowedToActOnBehalfOfOtherIdentity on CA computers..." -ForegroundColor Cyan

foreach ($c in $CAComputerNames) {
    Write-Host "Processing $c ..."
    # Append SID to the CA computer object's attribute
    Set-ADComputer -Identity $c -Add @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $svcSid} -ErrorAction Stop
    Write-Host "  Added to $c"
}

# Verify
foreach ($c in $CAComputerNames) {
    $vals = (Get-ADComputer -Identity $c -Properties msDS-AllowedToActOnBehalfOfOtherIdentity).'msDS-AllowedToActOnBehalfOfOtherIdentity'
    Write-Host "`n$c msDS-AllowedToActOnBehalfOfOtherIdentity:"
    if ($vals) { $vals | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  <none>" }
}

Write-Host "`nDone. Allow AD replication where applicable. Restart web app pools and test." -ForegroundColor Yellow
