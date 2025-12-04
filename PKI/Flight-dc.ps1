<#
.SYNOPSIS
  Configure Kerberos Constrained Delegation (KCD) on Domain Controller for IIS web servers.

.NOTES
  - Run on a Domain Controller with the ActiveDirectory module.
  - Edit $IISWebServers, $CAServers, and $DomainDns to match your environment.
#>

Import-Module ActiveDirectory -ErrorAction Stop

# === CONFIGURATION - EDIT ME ===
$DomainDns   = "lab.local"
$IISWebServers = @("WEB01","WEB02")    # computer names (no $)
$CAServers     = @("subca1","subca2")  # CA computer names (no $)
$CAServiceSPNs = @("HOST","RPCSS")     # service SPN types to delegate to (common values)
# ================================

function Register-SPNs {
    param($server)
    $computerAccount = "$server`$"
    $spn1 = "HTTP/$server.$DomainDns"
    $spn2 = "HTTP/$server"
    Write-Host "Registering SPNs for $computerAccount: $spn1, $spn2" -ForegroundColor Cyan

    & setspn -S $spn1 $computerAccount 2>&1 | ForEach-Object { Write-Host $_ }
    & setspn -S $spn2 $computerAccount 2>&1 | ForEach-Object { Write-Host $_ }
}

function Configure-Delegation {
    param($server)
    # Build list of SPNs for CA services
    $delegateSPNs = @()
    foreach ($ca in $CAServers) {
        foreach ($sp in $CAServiceSPNs) {
            $delegateSPNs += "$sp/$ca.$DomainDns"
            $delegateSPNs += "$sp/$ca"
        }
    }

    Write-Host "Configuring msDS-AllowedToDelegateTo for $server -> $($delegateSPNs -join ', ')" -ForegroundColor Green
    # Replace attribute with desired SPNs
    Set-ADComputer -Identity $server -Replace @{msDS-AllowedToDelegateTo = $delegateSPNs} -ErrorAction Stop

    # Ensure delegation flags - this sets computer to be trusted to auth for delegation (protocol transition)
    Set-ADComputer -Identity $server -TrustedForDelegation $false -TrustedToAuthForDelegation $true -ErrorAction Stop
}

foreach ($srv in $IISWebServers) {
    try {
        Register-SPNs -server $srv
        Configure-Delegation -server $srv
        Write-Host "OK: $srv configured" -ForegroundColor Green
    } catch {
        Write-Warning "Failed for $srv: $_"
    }
}

Write-Host "DC KCD configuration complete. Allow AD replication time if necessary." -ForegroundColor Yellow
