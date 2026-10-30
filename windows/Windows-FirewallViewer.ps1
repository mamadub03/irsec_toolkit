# IRSeC W07 - Windows Firewall Viewer
# READ ONLY - Windows PowerShell 5.1
# Usage:
# .\Windows-FirewallViewer.ps1
# .\Windows-FirewallViewer.ps1 -Port 23
# .\Windows-FirewallViewer.ps1 -Port 5985 -Direction Inbound
# .\Windows-FirewallViewer.ps1 -ShowAll

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1,65535)]
    [int]$Port = 0,

    [ValidateSet('Inbound','Outbound','Both')]
    [string]$Direction = 'Both',

    [switch]$ShowAll
)

$ErrorActionPreference = 'Stop'

function Test-PortMatch {
    param([string]$Specification,[int]$Wanted)

    if ($Wanted -eq 0) { return $true }

    foreach ($Part in ($Specification -split ',')) {
        $Part = $Part.Trim()

        if ($Part -eq 'Any') { return $true }
        if ($Part -match '^\d+$' -and
            [int]$Part -eq $Wanted) { return $true }

        if ($Part -match '^(\d+)-(\d+)$') {
            if ($Wanted -ge [int]$Matches[1] -and
                $Wanted -le [int]$Matches[2]) {
                return $true
            }
        }
    }

    return $false
}

Write-Host "`n=== WINDOWS FIREWALL STATUS ===" `
    -ForegroundColor Cyan

Get-NetFirewallProfile |
    Select-Object Name,Enabled,DefaultInboundAction,
        DefaultOutboundAction,AllowInboundRules,
        AllowLocalFirewallRules |
    Format-Table -AutoSize

Write-Host "`n=== NETWORK PROFILES ===" -ForegroundColor Cyan

Get-NetConnectionProfile |
    Select-Object InterfaceAlias,NetworkCategory,
        IPv4Connectivity |
    Format-Table -AutoSize

Write-Host "`n=== FIREWALL RULES ===" -ForegroundColor Cyan

$Rules = @(
    Get-NetFirewallRule -PolicyStore ActiveStore |
    Where-Object {
        ($ShowAll -or $_.Enabled -eq 'True') -and
        ($Direction -eq 'Both' -or
         [string]$_.Direction -eq $Direction)
    }
)

$Rows = foreach ($Rule in $Rules) {

    try {
        $PF = $Rule | Get-NetFirewallPortFilter
        $AF = $Rule | Get-NetFirewallAddressFilter
        $App = $Rule | Get-NetFirewallApplicationFilter
        $Svc = $Rule | Get-NetFirewallServiceFilter

        $LocalPort = [string]$PF.LocalPort
        $RemotePort = [string]$PF.RemotePort
        $Protocol = [string]$PF.Protocol

        if ($Port -gt 0) {
            # Inbound traffic generally targets LocalPort.
            # Outbound traffic generally targets RemotePort.
            $RelevantPort = if ($Rule.Direction -eq 'Inbound') {
                $LocalPort
            } else {
                $RemotePort
            }

            if (-not (Test-PortMatch $RelevantPort $Port)) {
                continue
            }

            if ($Protocol -notin @('TCP','UDP','6','17','Any')) {
                continue
            }
        }

        [pscustomobject]@{
            Rule = $Rule.DisplayName
            Action = [string]$Rule.Action
            Direction = [string]$Rule.Direction
            Enabled = [string]$Rule.Enabled
            Profile = [string]$Rule.Profile
            Protocol = $Protocol
            LocalPort = $LocalPort
            RemotePort = $RemotePort
            RemoteIP = [string]($AF.RemoteAddress -join ',')
            LocalIP = [string]($AF.LocalAddress -join ',')
            Program = [string]$App.Program
            Service = [string]$Svc.Service
            Name = $Rule.Name
        }
    }
    catch {
        Write-Warning "Could not inspect rule $($Rule.Name)"
    }
}

$Rows = @($Rows | Sort-Object Action,Direction,Rule)

if ($Rows.Count) {

    $Rows |
        Select-Object Rule,Action,Direction,Profile,
            Protocol,LocalPort,RemotePort,RemoteIP |
        Format-Table -Wrap -AutoSize

    Write-Host "`n=== RULE DETAILS ===" -ForegroundColor Cyan

    $Rows |
        Format-List Rule,Action,Direction,Enabled,Profile,
            Protocol,LocalPort,RemotePort,LocalIP,RemoteIP,
            Program,Service,Name
}
else {
    Write-Host 'No matching rules found.'
}

if ($Port -gt 0) {
    Write-Host "`n=== LOCAL TCP LISTENER ===" `
        -ForegroundColor Cyan

    $Listeners = @(
        Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction SilentlyContinue
    )

    if ($Listeners.Count) {
        $Listeners |
            Select-Object LocalAddress,LocalPort,OwningProcess |
            Format-Table -AutoSize
    }
    else {
        Write-Warning "No TCP listener found on port $Port."
    }

    Write-Host "`n=== POSSIBLE TROUBLESHOOTING ==="
    Write-Host '1. Check the active firewall profile.'
    Write-Host '2. Review enabled Block rules.'
    Write-Host '3. Compare source IP and rule scope.'
    Write-Host '4. Check whether the process listens on the LAN IP.'
    Write-Host '5. If local access works, inspect pfSense and test remotely.'
}

Write-Host "`nRead-only inspection complete."
Write-Warning 'A matching rule does not prove traffic is permitted or denied.'
Write-Warning 'Rule priority, scope, profile, GPO, and IPsec can affect the result.'