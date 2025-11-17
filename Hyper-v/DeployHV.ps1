# DeployHV.ps1
# Main script to create the entire PKI lab environment

#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

<#
.SYNOPSIS
    Creates a complete PKI lab environment in Hyper-V
.DESCRIPTION
    Automates the creation of Domain Controllers, File Servers, CAs, Web Servers, and OCSP responders
    Configures: RDP enabled, Firewall off, IEESC off, Timezone = Eastern, Domain join (except Root CA)
#>

[CmdletBinding()]
param(
    [string]$VMPath = "F:\Hyper-v\Labs\PKILab-Base",
    [string]$ISOPath = "C:\vms\SERVER_EVAL_x64FRE_en-us-2022.iso",
    [string]$SwitchName1 = "IS-10.10.1.0",
    [string]$SwitchName2 = "IS-10.20.1.0",
    [UInt64]$VMMemory = 4GB,
    [int]$VMProcessors = 2,
    [UInt64]$VHDSize = 30GB,
    
    # Credentials
    [string]$LocalAdminPassword = "P@ssw0rd123!",
    [string]$DomainAdminPassword = "P@ssw0rd123!"
)

# Lab configuration
$LabConfig = @{
    DomainName = "lab.local"
    DomainNetBIOS = "LAB"
    SafeModePassword = "P@ssw0rd123!"
    LocalAdminPassword = $LocalAdminPassword
    DomainAdminPassword = $DomainAdminPassword
    
    VMs = @(
        # Domain Controllers
        @{
            Name = "DC1"
            FQDN = "dc1.lab.local"
            IP = "10.10.1.101"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.10.1.1"
            DNS = @("127.0.0.1", "10.20.1.101")
            Switch = $SwitchName1
            Role = "DomainController"
            Memory = 4GB
            Processors = 2
            JoinDomain = $false  # DC1 creates the domain
        },
        @{
            Name = "DC2"
            FQDN = "dc2.lab.local"
            IP = "10.20.1.101"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.20.1.1"
            DNS = @("10.10.1.101", "10.20.1.101")
            Switch = $SwitchName2
            Role = "DomainController"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        
        # File Servers
        @{
            Name = "File1"
            FQDN = "file1.lab.local"
            IP = "10.10.1.111"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.10.1.1"
            DNS = @("10.10.1.101", "10.20.1.101")
            Switch = $SwitchName1
            Role = "FileServer"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        @{
            Name = "File2"
            FQDN = "file2.lab.local"
            IP = "10.20.1.111"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.20.1.1"
            DNS = @("10.20.1.101", "10.10.1.101")
            Switch = $SwitchName2
            Role = "FileServer"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        
        # Enterprise Sub CAs
        @{
            Name = "SubCA1"
            FQDN = "subca1.lab.local"
            IP = "10.10.1.121"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.10.1.1"
            DNS = @("10.10.1.101", "10.20.1.101")
            Switch = $SwitchName1
            Role = "EnterpriseSubCA"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        @{
            Name = "SubCA2"
            FQDN = "subca2.lab.local"
            IP = "10.20.1.121"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.20.1.1"
            DNS = @("10.20.1.101", "10.10.1.101")
            Switch = $SwitchName2
            Role = "EnterpriseSubCA"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        
        # Web Servers
        @{
            Name = "Web01"
            FQDN = "web01.lab.local"
            IP = "10.10.1.131"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.10.1.1"
            DNS = @("10.10.1.101", "10.20.1.101")
            Switch = $SwitchName1
            Role = "WebServer"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        @{
            Name = "Web02"
            FQDN = "web02.lab.local"
            IP = "10.20.1.131"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.20.1.1"
            DNS = @("10.20.1.101", "10.10.1.101")
            Switch = $SwitchName2
            Role = "WebServer"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        
        # OCSP Responders
        @{
            Name = "OCSP1"
            FQDN = "ocsp1.lab.local"
            IP = "10.10.1.141"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.10.1.1"
            DNS = @("10.10.1.101", "10.20.1.101")
            Switch = $SwitchName1
            Role = "OCSP"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        @{
            Name = "OCSP2"
            FQDN = "ocsp2.lab.local"
            IP = "10.20.1.141"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.20.1.1"
            DNS = @("10.20.1.101", "10.10.1.101")
            Switch = $SwitchName2
            Role = "OCSP"
            Memory = 4GB
            Processors = 2
            JoinDomain = $true
        },
        
        # Root CA (standalone - NOT joined to domain)
        @{
            Name = "CARoot1"
            FQDN = "caroot1.lab.local"
            IP = "10.10.1.151"
            Mask = "255.255.255.0"
            PrefixLength = 24
            Gateway = "10.10.1.1"
            DNS = @("10.10.1.101", "10.20.1.101")
            Switch = $SwitchName1
            Role = "RootCA"
            Memory = 4GB
            Processors = 2
            JoinDomain = $false  # Root CA stays standalone
        }
    )
}

# Function to create virtual switches
function New-LabSwitch {
    param(
        [string]$SwitchName,
        [string]$SwitchType = "Internal"
    )
    
    Write-Host "Checking virtual switch: $SwitchName" -ForegroundColor Cyan
    
    $existingSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if ($existingSwitch) {
        Write-Host "  Switch already exists" -ForegroundColor Yellow
        return
    }
    
    Write-Host "  Creating switch..." -ForegroundColor Gray
    New-VMSwitch -Name $SwitchName -SwitchType $SwitchType -Notes "PKI Lab Network"
    Write-Host "  Switch created successfully" -ForegroundColor Green
}

# Function to create a VM
function New-LabVM {
    param(
        [hashtable]$VMConfig,
        [string]$VMPath,
        [string]$ISOPath,
        [UInt64]$VHDSize
    )
    
    $VMName = $VMConfig.Name
    Write-Host "`nCreating VM: $VMName" -ForegroundColor Cyan
    
    # Check if VM already exists
    $existingVM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($existingVM) {
        Write-Host "  VM already exists. Skipping..." -ForegroundColor Yellow
        return
    }
    
    # Create VM directory
    $VMDir = Join-Path $VMPath $VMName
    if (-not (Test-Path $VMDir)) {
        New-Item -Path $VMDir -ItemType Directory -Force | Out-Null
    }
    
    # Create VHD path
    $VHDPath = Join-Path $VMDir "$VMName.vhdx"
    
    # Create the VM
    Write-Host "  Creating VM with $($VMConfig.Memory / 1GB)GB RAM and $($VMConfig.Processors) processors" -ForegroundColor Gray
    New-VM -Name $VMName `
           -MemoryStartupBytes $VMConfig.Memory `
           -Path $VMPath `
           -NewVHDPath $VHDPath `
           -NewVHDSizeBytes $VHDSize `
           -Generation 2 `
           -Switch $VMConfig.Switch
    
    # Configure VM
    Set-VM -Name $VMName -ProcessorCount $VMConfig.Processors -AutomaticCheckpointsEnabled $false
    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false
    
    # Add DVD drive and mount ISO
    Add-VMDvdDrive -VMName $VMName -Path $ISOPath
    
    # Set boot order (DVD first for installation)
    $dvd = Get-VMDvdDrive -VMName $VMName
    $disk = Get-VMHardDiskDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -BootOrder $dvd, $disk
    
    # Disable Secure Boot for compatibility
    Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
    
    Write-Host "  VM created successfully" -ForegroundColor Green
}

# Function to generate post-installation configuration script
function New-PostInstallScript {
    param(
        [hashtable]$LabConfig,
        [string]$OutputPath
    )
    
    Write-Host "`nGenerating post-installation configuration script..." -ForegroundColor Cyan
    
    $ScriptPath = Join-Path $OutputPath "Post-Install-Configure.ps1"
    
    $postInstallScript = @"
# Post-Install-Configure.ps1
# Run this script on the Hyper-V HOST after all VMs have Windows installed
# This will configure: IP, DNS, Timezone, RDP, Firewall OFF, IEESC OFF, and Domain Join

#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

param(
    [switch]`$SkipDomainJoin
)

`$DomainName = "$($LabConfig.DomainName)"
`$DomainNetBIOS = "$($LabConfig.DomainNetBIOS)"
`$LocalAdminPassword = "$($LabConfig.LocalAdminPassword)"
`$DomainAdminPassword = "$($LabConfig.DomainAdminPassword)"

# Build credentials
`$localCred = New-Object System.Management.Automation.PSCredential(
    "Administrator",
    (ConvertTo-SecureString `$LocalAdminPassword -AsPlainText -Force)
)

`$domainCred = New-Object System.Management.Automation.PSCredential(
    "`$DomainNetBIOS\Administrator",
    (ConvertTo-SecureString `$DomainAdminPassword -AsPlainText -Force)
)

# VM configurations
`$VMs = @(
"@

    # Add each VM configuration
    foreach ($VM in $LabConfig.VMs) {
        $postInstallScript += @"

    @{
        Name = "$($VM.Name)"
        IP = "$($VM.IP)"
        PrefixLength = $($VM.PrefixLength)
        Gateway = "$($VM.Gateway)"
        DNS = @("$($VM.DNS[0])", "$($VM.DNS[1])")
        JoinDomain = `$$($VM.JoinDomain.ToString().ToLower())
    },
"@
    }

    $postInstallScript += @"

)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Post-Installation Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach (`$vm in `$VMs) {
    `$vmName = `$vm.Name
    Write-Host "`nConfiguring `$vmName..." -ForegroundColor Yellow
    
    # Check if VM exists and is running
    `$vmObj = Get-VM -Name `$vmName -ErrorAction SilentlyContinue
    if (-not `$vmObj) {
        Write-Warning "  VM `$vmName not found. Skipping..."
        continue
    }
    
    if (`$vmObj.State -ne 'Running') {
        Write-Host "  Starting VM..." -ForegroundColor Gray
        Start-VM -Name `$vmName
        Start-Sleep -Seconds 45
    }
    
    # Wait for VM to be ready for PowerShell Direct
    Write-Host "  Waiting for VM to be ready..." -ForegroundColor Gray
    `$timeout = 120
    `$elapsed = 0
    while (`$elapsed -lt `$timeout) {
        try {
            Invoke-Command -VMName `$vmName -Credential `$localCred -ScriptBlock { `$true } -ErrorAction Stop | Out-Null
            break
        } catch {
            Start-Sleep -Seconds 5
            `$elapsed += 5
        }
    }
    
    if (`$elapsed -ge `$timeout) {
        Write-Warning "  Timeout waiting for `$vmName. Skipping..."
        continue
    }
    
    # Configure the VM
    Write-Host "  Applying configuration..." -ForegroundColor Gray
    
    Invoke-Command -VMName `$vmName -Credential `$localCred -ScriptBlock {
        param(`$ip, `$prefix, `$gw, `$dnsServers, `$vmName)
        
        # 1. Configure network
        `$adapter = Get-NetAdapter | Where-Object { `$_.Status -eq "Up" } | Select-Object -First 1
        if (`$adapter) {
            # Remove existing IP configuration
            Remove-NetIPAddress -InterfaceIndex `$adapter.ifIndex -Confirm:`$false -ErrorAction SilentlyContinue
            Remove-NetRoute -InterfaceIndex `$adapter.ifIndex -Confirm:`$false -ErrorAction SilentlyContinue
            
            # Set new IP configuration
            New-NetIPAddress -InterfaceIndex `$adapter.ifIndex -IPAddress `$ip -PrefixLength `$prefix -DefaultGateway `$gw -ErrorAction SilentlyContinue
            Set-DnsClientServerAddress -InterfaceIndex `$adapter.ifIndex -ServerAddresses `$dnsServers
        }
        
        # 2. Set timezone to Eastern Standard Time (New York)
        Set-TimeZone -Id "Eastern Standard Time"
        
        # 3. Enable RDP
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1
        
        # 4. Disable all Windows Firewall profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        
        # 5. Disable IE Enhanced Security Configuration (IEESC) for Admins and Users
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
        
        # 6. Rename computer if needed
        `$currentName = (Get-WmiObject Win32_ComputerSystem).Name
        if (`$currentName -ne `$vmName) {
            Rename-Computer -NewName `$vmName -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "    Configuration applied successfully" -ForegroundColor Green
        
    } -ArgumentList `$vm.IP, `$vm.PrefixLength, `$vm.Gateway, `$vm.DNS, `$vmName
    
    # Domain join (if applicable and not skipped)
    if (`$vm.JoinDomain -and -not `$SkipDomainJoin) {
        Write-Host "  Joining to domain `$DomainName..." -ForegroundColor Gray
        
        Invoke-Command -VMName `$vmName -Credential `$localCred -ScriptBlock {
            param(`$domain, `$domainCred)
            
            try {
                Add-Computer -DomainName `$domain -Credential `$domainCred -Force -ErrorAction Stop
                Write-Host "    Domain join successful. Rebooting..." -ForegroundColor Green
                Restart-Computer -Force
            } catch {
                Write-Warning "    Domain join failed: `$(`$_.Exception.Message)"
                Write-Host "    You may need to join manually after DC1 is promoted" -ForegroundColor Yellow
            }
        } -ArgumentList `$DomainName, `$using:domainCred
        
        Start-Sleep -Seconds 5
    }
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Promote DC1 to Domain Controller (creates lab.local domain)" -ForegroundColor White
Write-Host "2. If domain join failed, re-run this script after DC1 is ready" -ForegroundColor White
Write-Host "3. Promote DC2 as additional Domain Controller" -ForegroundColor White
Write-Host "4. Run your PKI configuration scripts" -ForegroundColor White
"@

    $postInstallScript | Out-File -FilePath $ScriptPath -Encoding utf8
    Write-Host "  Post-install script created: $ScriptPath" -ForegroundColor Green
}

# Function to generate DC1 promotion script
function New-DC1PromotionScript {
    param(
        [hashtable]$LabConfig,
        [string]$OutputPath
    )
    
    $ScriptPath = Join-Path $OutputPath "Promote-DC1.ps1"
    
    $dcScript = @"
# Promote-DC1.ps1
# Run this script INSIDE DC1 to promote it to the first Domain Controller

#Requires -RunAsAdministrator

`$DomainName = "$($LabConfig.DomainName)"
`$DomainNetBIOS = "$($LabConfig.DomainNetBIOS)"
`$SafeModePassword = ConvertTo-SecureString "$($LabConfig.SafeModePassword)" -AsPlainText -Force

Write-Host "Promoting DC1 to Domain Controller..." -ForegroundColor Cyan
Write-Host "Domain: `$DomainName" -ForegroundColor Yellow
Write-Host "NetBIOS: `$DomainNetBIOS" -ForegroundColor Yellow

# Install AD DS role
Write-Host "`nInstalling AD DS role..." -ForegroundColor Gray
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC and create forest
Write-Host "`nPromoting to Domain Controller and creating forest..." -ForegroundColor Gray
Install-ADDSForest ``
    -DomainName `$DomainName ``
    -DomainNetbiosName `$DomainNetBIOS ``
    -ForestMode "WinThreshold" ``
    -DomainMode "WinThreshold" ``
    -InstallDns ``
    -SafeModeAdministratorPassword `$SafeModePassword ``
    -Force

Write-Host "`nDC1 promotion complete. System will reboot." -ForegroundColor Green
"@

    $dcScript | Out-File -FilePath $ScriptPath -Encoding utf8
    Write-Host "  DC1 promotion script created: $ScriptPath" -ForegroundColor Green
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PKI Lab Environment Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Verify prerequisites
Write-Host "`nVerifying prerequisites..." -ForegroundColor Cyan

if (-not (Test-Path $ISOPath)) {
    Write-Host "ERROR: ISO file not found at $ISOPath" -ForegroundColor Red
    Write-Host "Please download Windows Server 2022 ISO and update the path" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $VMPath)) {
    Write-Host "Creating VM storage path: $VMPath" -ForegroundColor Yellow
    New-Item -Path $VMPath -ItemType Directory -Force | Out-Null
}

# Check virtual switches
Write-Host "`nChecking virtual switches..." -ForegroundColor Cyan
New-LabSwitch -SwitchName $SwitchName1
New-LabSwitch -SwitchName $SwitchName2

# Create VMs
Write-Host "`nCreating virtual machines..." -ForegroundColor Cyan
foreach ($VM in $LabConfig.VMs) {
    New-LabVM -VMConfig $VM -VMPath $VMPath -ISOPath $ISOPath -VHDSize $VHDSize
}

# Generate helper scripts
New-PostInstallScript -LabConfig $LabConfig -OutputPath $VMPath
New-DC1PromotionScript -LabConfig $LabConfig -OutputPath $VMPath

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Lab VMs Created Successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Start all VMs and install Windows Server 2022 from ISO" -ForegroundColor White
Write-Host "   - Use Administrator password: $LocalAdminPassword" -ForegroundColor Gray
Write-Host "`n2. After all VMs have Windows installed, run on HOST:" -ForegroundColor White
Write-Host "   $VMPath\Post-Install-Configure.ps1" -ForegroundColor Yellow
Write-Host "   (This configures IP, DNS, RDP, Firewall, IEESC, Timezone)" -ForegroundColor Gray
Write-Host "`n3. Log into DC1 and run:" -ForegroundColor White
Write-Host "   $VMPath\Promote-DC1.ps1" -ForegroundColor Yellow
Write-Host "   (This creates the lab.local domain)" -ForegroundColor Gray
Write-Host "`n4. After DC1 reboots, re-run Post-Install-Configure.ps1 to join other servers" -ForegroundColor White
Write-Host "`n5. Run your PKI configuration scripts" -ForegroundColor White
Write-Host "`nAll scripts saved to: $VMPath" -ForegroundColor Cyan