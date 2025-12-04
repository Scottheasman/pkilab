<#
.SYNOPSIS
  Validate KCD settings:
   - Role=DC: validate msDS-AllowedToDelegateTo and delegation flags
   - Role=IIS: validate app pool identity and authentication settings
   - Role=IIS-Live: check the current identity/authentication type (run inside app pool or an impersonated session)

USAGE:
  .\PKILab-KCD-Validation.ps1 -Role DC
  .\PKILab-KCD-Validation.ps1 -Role IIS
  .\PKILab-KCD-Validation.ps1 -Role IIS-Live
#>

param(
    [ValidateSet("DC","IIS","IIS-Live")]
    [string]$Role
)

function Validate-DC {
    Import-Module ActiveDirectory -ErrorAction Stop
    $IISWebServers = @("WEB01","WEB02")
    foreach ($s in $IISWebServers) {
        try {
            $comp = Get-ADComputer -Identity $s -Properties msDS-AllowedToDelegateTo,TrustedForDelegation,TrustedToAuthForDelegation
            Write-Host "Computer: $s" -ForegroundColor Cyan
            Write-Host "  TrustedForDelegation: $($comp.TrustedForDelegation)"
            Write-Host "  TrustedToAuthForDelegation: $($comp.TrustedToAuthForDelegation)"
            if ($comp.'msDS-AllowedToDelegateTo') {
                Write-Host "  msDS-AllowedToDelegateTo:"
                $comp.'msDS-AllowedToDelegateTo' | ForEach-Object { Write-Host "    $_" }
            } else {
                Write-Warning "  msDS-AllowedToDelegateTo is empty!"
            }
        } catch {
            Write-Warning "  Failed to retrieve $s: $_"
        }
        Write-Host ""
    }
}

function Validate-IIS {
    Import-Module WebAdministration -ErrorAction Stop
    $IISAppPoolName = "CertSrvPool"
    $IISSiteName = "ReqSite"
    $certsrvPath = "IIS:\Sites$IISSiteName\certsrv"

    Write-Host "Validating app pool: $IISAppPoolName" -ForegroundColor Cyan
    try {
        $ap = Get-Item "IIS:\AppPools$IISAppPoolName"
        Write-Host "  identityType: $($ap.processModel.identityType) (4 = ApplicationPoolIdentity)"
        Write-Host "  userName: $($ap.processModel.userName)"
    } catch {
        Write-Warning "  Could not read app pool $IISAppPoolName: $_"
    }

    Write-Host "`nValidating /certsrv auth settings" -ForegroundColor Cyan
    try {
        $anon = Get-WebConfigurationProperty -PSPath $certsrvPath -Filter system.webServer/security/authentication/anonymousAuthentication -Name enabled
        $win  = Get-WebConfigurationProperty -PSPath $certsrvPath -Filter system.webServer/security/authentication/windowsAuthentication -Name enabled
        $providers = Get-WebConfigurationProperty -PSPath $certsrvPath -Filter system.webServer/security/authentication/windowsAuthentication/providers -Name .

        Write-Host "  Anonymous enabled: $anon"
        Write-Host "  Windows enabled: $win"
        Write-Host "  Providers: $($providers -join ', ')"
    } catch {
        Write-Warning "  Could not read authentication settings: $_"
    }
}

function Check-LiveKerb {
    # This function reports the current WindowsIdentity. It should be executed in the context that the web app uses
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        Write-Host "Current identity: $($id.Name)"
        Write-Host "IsAuthenticated: $($id.IsAuthenticated)"
        Write-Host "AuthenticationType: $($id.AuthenticationType)"
        if ($id.AuthenticationType -eq "Kerberos") {
            Write-Host "Kerberos ticket present - delegated identity is Kerberos" -ForegroundColor Green
        } else {
            Write-Warning "Kerberos not present. AuthenticationType: $($id.AuthenticationType)"
        }
    } catch {
        Write-Warning "Error checking identity: $_"
    }
}

if ($Role -eq "DC") { Validate-DC }
elseif ($Role -eq "IIS") { Validate-IIS }
elseif ($Role -eq "IIS-Live") { Check-LiveKerb }
else { Write-Host "Specify -Role DC, IIS or IIS-Live" }
