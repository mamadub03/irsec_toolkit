# IRSeC 2026 - W05 Windows Service Health
# READ ONLY - Windows PowerShell 5.1
# Run in elevated PowerShell for complete visibility.

[CmdletBinding()]
param(
    [ValidateSet(
        'Auto','pitwall','teamradio','safetycar',
        'transporters','stewards'
    )]
    [string]$Role = 'Auto'
)

$ErrorActionPreference = 'Continue'
$Results = @()

if ($Role -eq 'Auto') {
    $Role = $env:COMPUTERNAME.ToLowerInvariant()
}

$KnownRoles = @(
    'pitwall','teamradio','safetycar',
    'transporters','stewards'
)

if ($Role -notin $KnownRoles) {
    throw "Unknown host. Supply -Role with a valid hostname."
}

function Add-Check {
    param(
        [string]$Component,
        [string]$Status,
        [string]$Details,
        [string]$Suggestion = ''
    )

    $script:Results += [pscustomobject]@{
        Component = $Component
        Status = $Status
        Details = $Details
        Suggestion = $Suggestion
    }
}

function Check-Service {
    param(
        [string]$Name,
        [string]$Label = $Name
    )

    $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if (-not $Svc) {
        Add-Check $Label 'FAIL' 'Service not found' `
            "Check whether $Name is installed and configured."
        return
    }

    if ($Svc.Status -eq 'Running') {
        Add-Check $Label 'PASS' 'Running'
    }
    else {
        Add-Check $Label 'FAIL' "Status: $($Svc.Status)" `
            "Inspect: Get-Service $Name; Get-WinEvent -LogName System -MaxEvents 30"
    }
}

function Check-Port {
    param(
        [int]$Port,
        [string]$Label,
        [switch]$Optional
    )

    try {
        $Listeners = @(
            Get-NetTCPConnection -LocalPort $Port `
                -State Listen -ErrorAction Stop
        )

        if ($Listeners.Count -gt 0) {
            $Addresses = (
                $Listeners |
                ForEach-Object { $_.LocalAddress } |
                Sort-Object -Unique
            ) -join ', '

            Add-Check $Label 'PASS' "TCP $Port listening ($Addresses)"
        }
        else {
            if ($Optional) {
                Add-Check $Label 'INFO' "TCP $Port not listening"
            }
            else {
                Add-Check $Label 'FAIL' "TCP $Port not listening" `
                    "Inspect listener configuration and port conflicts using Get-NetTCPConnection."
            }
        }
    }
    catch {
        Add-Check $Label 'WARN' "Unable to inspect TCP $Port" `
            'Run elevated and inspect netstat -ano.'
    }
}

function Check-TCPResponse {
    param([int]$Port,[string]$Label)

    try {
        $Client = New-Object Net.Sockets.TcpClient

        $Async = $Client.BeginConnect(
            '127.0.0.1',$Port,$null,$null
        )

        $Connected = $Async.AsyncWaitHandle.WaitOne(1500,$false)

        if ($Connected) {
            try {
                $Client.EndConnect($Async)
                Add-Check $Label 'PASS' "Local TCP $Port accepted"
            }
            catch {
                Add-Check $Label 'FAIL' "Local TCP $Port rejected"
            }
        }
        else {
            Add-Check $Label 'FAIL' "Local TCP $Port timed out"
        }
    }
    catch {
        Add-Check $Label 'FAIL' "Local TCP $Port failed"
    }
    finally {
        if ($Client) { $Client.Close() }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "       IRSeC WINDOWS SERVICE HEALTH"
Write-Host "========================================"
Write-Host "Host: $env:COMPUTERNAME"
Write-Host "Profile: $Role"
Write-Host "Time: $(Get-Date)"
Write-Host "Mode: READ ONLY"

# ------------------------------------------------------------
# General network information
# ------------------------------------------------------------

$Adapters = @(
    Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' }
)

if ($Adapters.Count -gt 0) {
    Add-Check 'Network adapter' 'PASS' `
        "$($Adapters.Count) active adapter(s)"
}
else {
    Add-Check 'Network adapter' 'FAIL' 'No active adapter found' `
        'Inspect Get-NetAdapter and physical/virtual interface settings.'
}

$Addresses = @(
    Get-NetIPAddress -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -ne '127.0.0.1' -and
        $_.AddressState -eq 'Preferred'
    }
)

if ($Addresses.Count -gt 0) {
    Add-Check 'IPv4 address' 'PASS' `
        (($Addresses.IPAddress) -join ', ')
}
else {
    Add-Check 'IPv4 address' 'FAIL' 'No preferred non-loopback IPv4' `
        'Inspect Get-NetIPConfiguration.'
}

try {
    $Profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

    foreach ($Profile in $Profiles) {
        $State = if ($Profile.Enabled) { 'PASS' } else { 'WARN' }
        Add-Check "Firewall $($Profile.Name)" $State `
            "Enabled: $($Profile.Enabled); DefaultInbound: $($Profile.DefaultInboundAction)"
    }
}
catch {
    Add-Check 'Windows Firewall' 'WARN' 'Could not inspect profiles'
}

# ------------------------------------------------------------
# Host-specific scored service checks
# ------------------------------------------------------------

switch ($Role) {

    'pitwall' {
        Check-Service 'NTDS' 'Active Directory'
        Check-Service 'DNS' 'DNS Server'
        Check-Service 'Netlogon' 'Netlogon'

        Check-Port 53 'DNS TCP listener'
        Check-Port 88 'Kerberos TCP listener'
        Check-Port 389 'LDAP TCP listener'

        try {
            $Domain = (Get-CimInstance Win32_ComputerSystem).Domain

            $DNS = Resolve-DnsName -Name $Domain `
                -Server 127.0.0.1 -Type SOA `
                -ErrorAction Stop

            if ($DNS) {
                Add-Check 'DNS query' 'PASS' "Resolved $Domain SOA"
            }
        }
        catch {
            Add-Check 'DNS query' 'FAIL' 'Local DNS query failed' `
                'Inspect DNS zones, DNS service, and the local resolver.'
        }

        Add-Check 'AD authentication' 'INFO' `
            'Full domain login verification requires a separate credential test.' `
            'Verify authorized domain authentication and Hermes scoring.'
    }

    'teamradio' {
        Check-Service 'WinRM'
        Check-Port 5985 'WinRM HTTP listener'

        try {
            Test-WSMan -ComputerName localhost `
                -ErrorAction Stop | Out-Null

            Add-Check 'WSMan response' 'PASS' 'Local WSMan responded'
        }
        catch {
            Add-Check 'WSMan response' 'FAIL' 'Local WSMan failed' `
                'Inspect winrm enumerate winrm/config/listener and authentication settings.'
        }
    }

    'safetycar' {
        $TelnetServices = @(
            Get-Service inetd,tlntsvr `
                -ErrorAction SilentlyContinue
        )

        if ($TelnetServices.Count -eq 0) {
            Add-Check 'Telnet daemon' 'WARN' `
                'No inetd or tlntsvr service found' `
                'Identify the installed Telnet server and its actual service name.'
        }
        else {
            foreach ($Svc in $TelnetServices) {
                Check-Service $Svc.Name
            }
        }

        Check-Port 23 'Telnet listener'
        Check-TCPResponse 23 'Telnet TCP response'

        $ICMPRules = @(
            Get-NetFirewallRule -Enabled True `
                -Direction Inbound -Action Allow `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $Filter = $_ | Get-NetFirewallPortFilter `
                    -ErrorAction SilentlyContinue
                $Filter.Protocol -in @('ICMPv4',1)
            }
        )

        Add-Check 'Inbound ICMP allow rules' 'INFO' `
            "Matching enabled allow rules: $($ICMPRules.Count)" `
            'Inspect firewall rule profiles, scope, and priority; verify ping remotely.'
    }

    'transporters' {
        Check-Service 'LanmanServer' 'SMB Server'
        Check-Port 445 'SMB listener'
        Check-TCPResponse 445 'SMB TCP response'

        try {
            $Shares = @(Get-SmbShare -ErrorAction Stop)

            $Names = ($Shares.Name -join ', ')
            Add-Check 'SMB shares' 'INFO' `
                "$($Shares.Count) shares: $Names"
        }
        catch {
            Add-Check 'SMB shares' 'WARN' 'Unable to enumerate shares'
        }
    }

    'stewards' {
        Check-Service 'W3SVC' 'IIS Web Server'
        Check-Service 'WAS' 'Windows Process Activation'

        if (Get-Module -ListAvailable WebAdministration) {
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $Sites = @(Get-Website -ErrorAction Stop)

                foreach ($Site in $Sites) {
                    $Status = if ($Site.State -eq 'Started') {
                        'PASS'
                    } else {
                        'FAIL'
                    }

                    Add-Check "IIS site: $($Site.Name)" $Status `
                        "State: $($Site.State); Bindings: $($Site.Bindings.Collection.bindingInformation -join ', ')" `
                        'Inspect site bindings, app pool, and applicationHost.config.'
                }
            }
            catch {
                Add-Check 'IIS sites' 'WARN' `
                    "Could not enumerate websites: $($_.Exception.Message)"
            }
        }
        else {
            Add-Check 'IIS module' 'WARN' `
                'WebAdministration module unavailable'
        }

        $HTTP = @(
            Get-NetTCPConnection -State Listen `
                -LocalPort 80,443 -ErrorAction SilentlyContinue
        )

        if ($HTTP.Count -gt 0) {
            Add-Check 'HTTP/HTTPS listeners' 'PASS' `
                "Listening ports: $(($HTTP.LocalPort | Sort-Object -Unique) -join ', ')"
        }
        else {
            Add-Check 'HTTP/HTTPS listeners' 'WARN' `
                'Neither default web port is listening' `
                'Inspect actual IIS bindings; the site may use another port.'
        }
    }
}

# ------------------------------------------------------------
# Final report
# ------------------------------------------------------------

Write-Host "`n=== HEALTH SUMMARY ===" -ForegroundColor Cyan
$Results |
    Format-Table Component,Status,Details -Wrap -AutoSize

$Problems = @(
    $Results |
    Where-Object { $_.Status -in @('FAIL','WARN') }
)

Write-Host "`n=== SUGGESTED INVESTIGATIONS ===" -ForegroundColor Yellow

if ($Problems.Count -eq 0) {
    Write-Host 'No obvious failures detected by these checks.'
}
else {
    foreach ($Problem in $Problems) {
        Write-Host "[$($Problem.Status)] $($Problem.Component)"
        Write-Host "  $($Problem.Details)"

        if ($Problem.Suggestion) {
            Write-Host "  Suggestion: $($Problem.Suggestion)"
        }
    }
}

Write-Host "`nPASS: $( @($Results | Where-Object Status -eq 'PASS').Count )"
Write-Host "WARN: $( @($Results | Where-Object Status -eq 'WARN').Count )"
Write-Host "FAIL: $( @($Results | Where-Object Status -eq 'FAIL').Count )"
Write-Host 'Read-only checks complete. No changes made.'