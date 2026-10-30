# IRSeC W10 - Windows Deep Diagnostics (read-only)
# Windows PowerShell 5.1. Run elevated for firewall/event-log visibility.
# Usage: .\Windows-DeepDiagnostics.ps1 [-Role safetycar] [-RecentMinutes 30]
[CmdletBinding()]
param(
    [ValidateSet('Auto','pitwall','teamradio','safetycar','transporters','stewards')]
    [string]$Role='Auto',
    [ValidateRange(1,240)][int]$RecentMinutes=30
)
$ErrorActionPreference='Stop'
if ($Role -eq 'Auto') { $Role=$env:COMPUTERNAME.ToLowerInvariant() }
if ($Role -notin @('pitwall','teamradio','safetycar','transporters','stewards')) {
    throw 'Unknown hostname. Supply -Role with a competition host name.'
}
$script:Results=New-Object System.Collections.ArrayList
function Add-Result($Area,$Status,$Finding,$Next='') {
    [void]$script:Results.Add([pscustomobject]@{
        Area=$Area; Status=$Status; Finding=$Finding; Suggestion=$Next
    })
}
function Show-Section($Name) { Write-Host "`n=== $Name ===" -ForegroundColor Cyan }
function Check-Service($Name) {
    $s=Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $s) { Add-Result $Name 'WARN' 'Service not found' "Verify that $Name is the expected service name" }
    elseif ($s.Status -eq 'Running') { Add-Result $Name 'PASS' 'Running' }
    else { Add-Result $Name 'FAIL' "State: $($s.Status)" "Review Get-Service $Name and System event logs" }
}
function Check-Listener([int]$Port,[string]$Name) {
    try { $s=@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop) }
    catch { $s=@() }
    if (-not $s.Count) { Add-Result $Name 'FAIL' "No TCP $Port listener" 'Check daemon, service configuration and binding' ; return }
    $addresses=@($s | Select-Object -ExpandProperty LocalAddress -Unique)
    $loop=@($addresses | Where-Object { $_ -notin @('127.0.0.1','::1') }).Count -eq 0
    $label=if ($loop) {'WARN'} else {'PASS'}
    $note=if ($loop) {'Only loopback: remote clients cannot reach this binding'} else {''}
    Add-Result $Name $label "TCP $Port bound to: $($addresses -join ', ')" $note
}
function Test-LocalTCP([int]$Port,[string]$Name,[switch]$ReadBanner) {
    $c=New-Object System.Net.Sockets.TcpClient
    try {
        $ar=$c.BeginConnect('127.0.0.1',$Port,$null,$null)
        if (-not $ar.AsyncWaitHandle.WaitOne(1200)) {
            Add-Result $Name 'FAIL' 'Local TCP timeout' 'Review listener and local filtering'; return
        }
        $c.EndConnect($ar)
        if (-not $ReadBanner) { Add-Result $Name 'PASS' 'Local TCP connection accepted'; return }
        $stream=$c.GetStream(); $stream.ReadTimeout=1400
        $bytes=New-Object byte[] 256
        try {
            $count=$stream.Read($bytes,0,$bytes.Length)
            $raw=[System.Text.Encoding]::ASCII.GetString($bytes,0,$count)
            $print=($raw -replace '[^\x20-\x7E]',' ').Trim()
            if ($print.Length -gt 110) { $print=$print.Substring(0,110) }
            if ($raw -match '(?i)(login:|username:|password:|welcome)') {
                Add-Result $Name 'PASS' "Login-like prompt received: $print"
            } else {
                Add-Result $Name 'WARN' "TCP connected; no recognizable prompt in first response: $print" 'Telnet negotiation or delayed prompts may require an interactive test'
            }
        } catch {
            Add-Result $Name 'WARN' 'TCP connected but no prompt received within 1.4 seconds' 'Check Telnet child process, inetd config, and test interactively'
        }
    } catch { Add-Result $Name 'FAIL' "Local TCP connect failed: $($_.Exception.Message)" 'Review service and port listener' }
    finally { $c.Close() }
}
function Show-FirewallRules([string]$Name,[int]$Port=0,[switch]$Icmp) {
    Show-Section "FIREWALL: $Name"
    try {
        $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -ErrorAction Stop)
        $rows=@(foreach ($r in $rules) {
            try {
                $f=$r | Get-NetFirewallPortFilter -ErrorAction Stop
                $af=$r | Get-NetFirewallAddressFilter -ErrorAction Stop
                $proto=[string]$f.Protocol
                $matched=$false
                if ($Icmp) { $matched=$proto -in @('ICMPv4','1') }
                else {
                    if ($proto -in @('TCP','6','Any')) {
                        $spec=[string]($f.LocalPort -join ',')
                        if ($spec -eq 'Any') { $matched=$true }
                        else { foreach ($p in ($spec -split ',')) {
                            if ($p -eq [string]$Port) { $matched=$true }
                            elseif ($p -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { $matched=$true }
                        }}
                    }
                }
                if ($matched) {
                    [pscustomobject]@{Action=$r.Action;Profile=$r.Profile;Rule=$r.DisplayName;
                        Protocol=$proto;LocalPort=($f.LocalPort -join ',');ICMPType=($f.IcmpType -join ',');
                        RemoteIP=($af.RemoteAddress -join ',')}
                }
            } catch {}
        })
        if ($rows.Count) { $rows | Sort-Object Action,Rule | Format-Table -Wrap -AutoSize | Out-Host }
        else { Write-Host 'No enabled matching inbound rules found.' }
        $profiles=@(Get-NetFirewallProfile)
        $profiles | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize | Out-Host