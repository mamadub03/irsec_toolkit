# ============================================================
# IRSeC W07 - Windows Firewall Viewer
# Windows PowerShell 5.1
# READ ONLY - Does not modify firewall rules or logging.
#
# Usage:
# .\Windows-FirewallViewer.ps1
# .\Windows-FirewallViewer.ps1 -Port 23
# .\Windows-FirewallViewer.ps1 -Port 5985
# .\Windows-FirewallViewer.ps1 -Port 23 -ShowBroadAllow
# .\Windows-FirewallViewer.ps1 -Port 23 -ShowDrops
# .\Windows-FirewallViewer.ps1 -ShowAll
# ============================================================

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(0,65535)]
    [int]$Port = 0,

    [ValidateSet('Inbound','Outbound','Both')]
    [string]$Direction = 'Inbound',

    [switch]$ShowAll,
    [switch]$ShowBroadAllow,
    [switch]$ShowDrops
)

$ErrorActionPreference = 'Stop'

function Test-PortMatch {
    param(
        [string]$Specification,
        [int]$Wanted
    )

    if ($Wanted -eq 0) { return $true }

    foreach ($Part in ($Specification -split ',')) {
        $Part = $Part.Trim()

        if ($Part -eq 'Any') { return $true }

        if ($Part -match '^\d+$') {
            if ([int]$Part -eq $Wanted) {
                return $true
            }
        }

        if ($Part -match '^(\d+)-(\d+)$') {
            if ($Wanted -ge [int]$Matches[1] -and
                $Wanted -le [int]$Matches[2]) {
                return $true
            }
        }
    }

    return $false
}

function Test-ExplicitPort {
    param(
        [string]$Specification,
        [int]$Wanted
    )

    if ($Wanted -eq 0) { return $false }
    if ($Specification -eq 'Any') { return $false }

    return (Test-PortMatch $Specification $Wanted)
}

function Show-RuleGroup {
    param(
        [string]$Title,
        [array]$Items
    )

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan

    if (@($Items).Count -eq 0) {
        Write-Host 'No matching rules.'
        return
    }

    $Items |
        Select-Object Rule,Action,Direction,Profile,
            Protocol,LocalPort,RemotePort,RemoteIP,
            Program,Service |
        Format-Table -AutoSize -Wrap

    Write-Host "Rules found: $(@($Items).Count)"
}

function Show-RuleDetails {
    param([array]$Items)

    if (@($Items).Count -eq 0) { return }

    Write-Host "`n=== MATCHED RULE DETAILS ===" -ForegroundColor Cyan

    $Items |
        Format-List Rule,Name,Enabled,Action,Direction,
            Profile,Protocol,LocalPort,RemotePort,
            LocalIP,RemoteIP,Program,Service,Category
}

function Show-DroppedPackets {
    param([int]$RequestedPort)

    Write-Host "`n=== RECENT LOGGED FIREWALL DROPS ===" `
        -ForegroundColor Cyan

    $Profiles = @(Get-NetFirewallProfile)

    foreach ($Profile in $Profiles) {
        Write-Host (
            "$($Profile.Name): " +
            "DropLogging=$($Profile.LogBlocked); " +
            "Log=$($Profile.LogFileName)"
        )
    }

    $Paths = @(
        foreach ($Profile in $Profiles) {
            if ($Profile.LogFileName) {
                [Environment]::ExpandEnvironmentVariables(
                    [string]$Profile.LogFileName
                )
            }
        }
    )

    $Paths += "$env:windir\System32\LogFiles\Firewall\pfirewall.log"

    $Paths = @($Paths | Sort-Object -Unique)
    $Drops = @()

    foreach ($Path in $Paths) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            continue
        }

        try {
            $Lines = @(
                Get-Content -LiteralPath $Path `
                    -Tail 2000 -ErrorAction Stop
            )

            # Windows Firewall logs declare their field order.
            $Fields = @()

            foreach ($Line in $Lines) {
                if ($Line -match '^#Fields:\s*(.*)$') {
                    $Fields = @(
                        $Matches[1].Trim() -split '\s+'
                    )
                    continue
                }

                if ($Line -match '^#' -or
                    [string]::IsNullOrWhiteSpace($Line)) {
                    continue
                }

                if ($Fields.Count -eq 0) { continue }

                $Values = @($Line.Trim() -split '\s+')

                if ($Values.Count -lt $Fields.Count) {
                    continue
                }

                $Record = @{}

                for ($i = 0; $i -lt $Fields.Count; $i++) {
                    $Record[$Fields[$i]] = $Values[$i]
                }

                if ($Record['action'] -ne 'DROP') {
                    continue
                }

                if ($RequestedPort -gt 0) {
                    if ($Record['dst-port'] -ne "$RequestedPort" -and
                        $Record['src-port'] -ne "$RequestedPort") {
                        continue
                    }
                }

                $Drops += [pscustomobject]@{
                    Date = $Record['date']
                    Time = $Record['time']
                    Protocol = $Record['protocol']
                    SourceIP = $Record['src-ip']
                    SourcePort = $Record['src-port']
                    DestinationIP = $Record['dst-ip']
                    DestinationPort = $Record['dst-port']
                    Action = $Record['action']
                }
            }
        }
        catch {
            Write-Warning "Could not read ${Path}: $($_.Exception.Message)"
        }
    }

    if ($Drops.Count -gt 0) {
        $Drops |
            Select-Object -Last 30 |
            Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host 'No matching DROP records found in readable logs.'
        Write-Host 'Logging may be disabled or traffic may not have been logged.'
    }

    Write-Host 'No firewall logging settings were changed.'
}

# ============================================================
# FIREWALL PROFILES
# ============================================================

Write-Host "`n========================================" `
    -ForegroundColor Cyan
Write-Host "       IRSeC WINDOWS FIREWALL VIEWER"
Write-Host "========================================"
Write-Host "Host: $env:COMPUTERNAME"
Write-Host "Port: $(if ($Port) { $Port } else { 'ALL' })"
Write-Host "Direction: $Direction"
Write-Host "Mode: READ ONLY"

Write-Host "`n=== FIREWALL PROFILES ===" -ForegroundColor Cyan

$Profiles = @(Get-NetFirewallProfile)

$Profiles |
    Select-Object Name,Enabled,DefaultInboundAction,
        DefaultOutboundAction,AllowInboundRules,
        AllowLocalFirewallRules |
    Format-Table -AutoSize

Write-Host "`n=== ACTIVE NETWORK PROFILES ===" `
    -ForegroundColor Cyan

Get-NetConnectionProfile |
    Select-Object InterfaceAlias,NetworkCategory,
        IPv4Connectivity |
    Format-Table -AutoSize

# ============================================================
# COLLECT FIREWALL RULES
# ============================================================

Write-Host "`nCollecting firewall rules..."

$Rules = @(
    Get-NetFirewallRule -PolicyStore ActiveStore |
    Where-Object {
        ($ShowAll -or [string]$_.Enabled -eq 'True') -and
        ($Direction -eq 'Both' -or
         [string]$_.Direction -eq $Direction)
    }
)

$Rows = @(
    foreach ($Rule in $Rules) {
        try {
            $PF = $Rule | Get-NetFirewallPortFilter
            $AF = $Rule | Get-NetFirewallAddressFilter
            $App = $Rule | Get-NetFirewallApplicationFilter
            $Svc = $Rule | Get-NetFirewallServiceFilter

            $LocalPort = [string]($PF.LocalPort -join ',')
            $RemotePort = [string]($PF.RemotePort -join ',')
            $Protocol = [string]$PF.Protocol

            if ([string]::IsNullOrWhiteSpace($LocalPort)) {
                $LocalPort = 'Any'
            }

            if ([string]::IsNullOrWhiteSpace($RemotePort)) {
                $RemotePort = 'Any'
            }

            if ($Port -gt 0) {
                # Inbound checks destination/local port.
                # Outbound checks destination/remote port.
                $RelevantPort = if (
                    [string]$Rule.Direction -eq 'Inbound'
                ) {
                    $LocalPort
                }
                else {
                    $RemotePort
                }

                if (-not (Test-PortMatch $RelevantPort $Port)) {
                    continue
                }

                # TCP investigation; rules for another
                # protocol are not included.
                if ($Protocol -notin @('TCP','6','Any')) {
                    continue
                }
            }
            else {
                $RelevantPort = 'Any'
            }

            $Category = 'GENERAL'

            if ($Port -gt 0) {
                if (Test-ExplicitPort $RelevantPort $Port) {
                    $Category = 'EXPLICIT_PORT'
                }
                elseif ([string]$Rule.Action -eq 'Block') {
                    $Category = 'BROAD_BLOCK'
                }
                else {
                    $Category = 'BROAD_ALLOW'
                }
            }

            [pscustomobject]@{
                Rule = $Rule.DisplayName
                Name = $Rule.Name
                Enabled = [string]$Rule.Enabled
                Action = [string]$Rule.Action
                Direction = [string]$Rule.Direction
                Profile = [string]$Rule.Profile
                Protocol = $Protocol
                LocalPort = $LocalPort
                RemotePort = $RemotePort
                LocalIP = [string]($AF.LocalAddress -join ',')
                RemoteIP = [string]($AF.RemoteAddress -join ',')
                Program = [string]$App.Program
                Service = [string]$Svc.Service
                Category = $Category
            }
        }
        catch {
            Write-Warning "Could not inspect $($Rule.Name)"
        }
    }
)

# ============================================================
# DISPLAY RULES
# ============================================================

if ($Port -eq 0) {
    Show-RuleGroup 'ALL MATCHING FIREWALL RULES' $Rows
}
else {
    $Explicit = @(
        $Rows | Where-Object Category -eq 'EXPLICIT_PORT'
    )

    $BroadBlocks = @(
        $Rows | Where-Object Category -eq 'BROAD_BLOCK'
    )

    $BroadAllows = @(
        $Rows | Where-Object Category -eq 'BROAD_ALLOW'
    )

    Show-RuleGroup "EXPLICIT TCP $Port RULES" $Explicit

    Show-RuleGroup "BROAD BLOCK RULES THAT MAY AFFECT TCP $Port" `
        $BroadBlocks

    if ($ShowBroadAllow) {
        Show-RuleGroup 'BROAD ALLOW RULES' $BroadAllows
    }
    else {
        Write-Host "`nBroad allow rules hidden: $($BroadAllows.Count)"
        Write-Host 'Use -ShowBroadAllow to display them.'
    }

    $VisibleRows = @($Explicit) + @($BroadBlocks)

    if ($ShowBroadAllow) {
        $VisibleRows += @($BroadAllows)
    }

    Show-RuleDetails $VisibleRows

    # ========================================================
    # LOCAL TCP LISTENER AND PROCESS
    # ========================================================

    Write-Host "`n=== LOCAL TCP $Port LISTENER ===" `
        -ForegroundColor Cyan

    $Listeners = @(
        Get-NetTCPConnection -State Listen `
            -LocalPort $Port -ErrorAction SilentlyContinue
    )

    if ($Listeners.Count -gt 0) {
        $ListenerRows = foreach ($Listener in $Listeners) {
            $ProcessName = 'Unknown'

            try {
                $P = Get-Process -Id $Listener.OwningProcess `
                    -ErrorAction Stop
                $ProcessName = $P.ProcessName
            }
            catch {}

            [pscustomobject]@{
                LocalAddress = $Listener.LocalAddress
                LocalPort = $Listener.LocalPort
                PID = $Listener.OwningProcess
                Process = $ProcessName
            }
        }

        $ListenerRows | Format-Table -AutoSize
    }
    else {
        Write-Warning "No local TCP $Port listener detected."
    }

    Write-Host "`n=== TROUBLESHOOTING SUGGESTIONS ===" `
        -ForegroundColor Yellow

    Write-Host '1. Check which firewall profile is active.'
    Write-Host '2. Review explicit port rules first.'
    Write-Host '3. Inspect broad blocks and their RemoteIP scope.'
    Write-Host '4. Check Program and Service restrictions.'
    Write-Host '5. Verify the listener binds to the expected LAN IP.'
    Write-Host '6. If local checks pass, test remotely and inspect pfSense.'
}

# ============================================================
# OPTIONAL DROP LOGS
# ============================================================

if ($ShowDrops) {
    Show-DroppedPackets $Port
}

Write-Host "`n=== COMPLETED ===" -ForegroundColor Green
Write-Host 'No firewall settings were modified.'
Write-Warning 'Matching rules are candidates, not proof of a block.'
Write-Warning 'Profile, scope, application, rule precedence, GPO and IPsec matter.'
