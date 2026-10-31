# ============================================================
# IRSeC 2026 - W05 Windows Service Health
# Windows PowerShell 5.1
#
# READ ONLY - Does not modify system configuration
#
# Supported profiles:
#   pitwall      - AD / DNS
#   teamradio    - WinRM
#   safetycar    - Telnet / ICMP
#   transporters - SMB
#   stewards     - IIS
#
# Usage:
#   .\Windows-ServiceHealth.ps1
#   .\Windows-ServiceHealth.ps1 -Role safetycar
# ============================================================

[CmdletBinding()]
param(
    [ValidateSet(
        'Auto',
        'pitwall',
        'teamradio',
        'safetycar',
        'transporters',
        'stewards'
    )]
    [string]$Role = 'Auto'
)

$ErrorActionPreference = 'Continue'
$Results = @()

if ($Role -eq 'Auto') {
    $Role = $env:COMPUTERNAME.ToLowerInvariant()
}

$KnownRoles = @(
    'pitwall',
    'teamradio',
    'safetycar',
    'transporters',
    'stewards'
)

if ($Role -notin $KnownRoles) {
    throw "Unknown host. Supply -Role with a valid hostname."
}

# ============================================================
# REPORTING
# ============================================================

function Add-Check {
    param(
        [string]$Component,
        [string]$Status,
        [string]$Details,
        [string]$Suggestion = ''
    )

    $script:Results += [PSCustomObject]@{
        Component  = $Component
        Status     = $Status
        Details    = $Details
        Suggestion = $Suggestion
    }
}

# ============================================================
# WINDOWS SERVICE STATUS
# ============================================================

function Check-Service {
    param(
        [string]$Name,
        [string]$Label = $Name
    )

    $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if (-not $Svc) {
        Add-Check $Label 'FAIL' 'Service not found' `
            "Check whether $Name is installed."
        return
    }

    if ($Svc.Status -eq 'Running') {
        Add-Check $Label 'PASS' 'Running'
    }
    else {
        Add-Check $Label 'FAIL' "Status: $($Svc.Status)" `
            "Inspect: Get-Service $Name; sc.exe qc $Name"
    }
}

# ============================================================
# TCP LISTENER CHECK
# ============================================================

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

            Add-Check $Label 'PASS' `
                "TCP $Port listening ($Addresses)"
        }
        else {
            if ($Optional) {
                Add-Check $Label 'INFO' `
                    "TCP $Port not listening"
            }
            else {
                Add-Check $Label 'FAIL' `
                    "TCP $Port not listening" `
                    'Inspect service status, listener configuration, and port conflicts.'
            }
        }
    }
    catch {
        # A missing port can also cause Get-NetTCPConnection
        # to return an error depending on Windows version.
        $Fallback = @(
            Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LocalPort -eq $Port -and
                $_.State -eq 'Listen'
            }
        )

        if ($Fallback.Count -gt 0) {
            Add-Check $Label 'PASS' `
                "TCP $Port listening"
        }
        elseif ($Optional) {
            Add-Check $Label 'INFO' `
                "TCP $Port not listening"
        }
        else {
            Add-Check $Label 'FAIL' `
                "No TCP $Port listener detected" `
                'Inspect the service and listener configuration.'
        }
    }
}

# ============================================================
# LOCAL TCP CONNECTIVITY
# ============================================================

function Check-TCPResponse {
    param(
        [int]$Port,
        [string]$Label
    )

    $Client = $null
    $WaitHandle = $null

    try {
        $Client = New-Object Net.Sockets.TcpClient

        $Async = $Client.BeginConnect(
            '127.0.0.1',
            $Port,
            $null,
            $null
        )

        $WaitHandle = $Async.AsyncWaitHandle

        $Connected = $WaitHandle.WaitOne(1500, $false)

        if ($Connected) {
            try {
                $Client.EndConnect($Async)

                Add-Check $Label 'PASS' `
                    "Local TCP $Port accepted"
            }
            catch {
                Add-Check $Label 'FAIL' `
                    "Local TCP $Port rejected"
            }
        }
        else {
            Add-Check $Label 'FAIL' `
                "Local TCP $Port timed out"
        }
    }
    catch {
        Add-Check $Label 'FAIL' `
            "Local TCP $Port connection failed"
    }
    finally {
        if ($WaitHandle) {
            $WaitHandle.Close()
        }

        if ($Client) {
            $Client.Close()
        }
    }
}

# ============================================================
# NEW - DETECT THE REAL TELNET PROCESS
# ============================================================

function Check-TelnetProcess {

    Write-Host "`n=== TELNET PROCESS INVESTIGATION ===" `
        -ForegroundColor Cyan

    # Check common Telnet Windows service names.
    $KnownServices = @(
        Get-Service -Name 'inetd','tlntsvr' `
            -ErrorAction SilentlyContinue
    )

    if ($KnownServices.Count -gt 0) {
        foreach ($Svc in $KnownServices) {
            Check-Service $Svc.Name "Telnet service: $($Svc.Name)"
        }
    }
    else {
        Add-Check 'Telnet service registration' 'INFO' `
            'Neither inetd nor tlntsvr is registered' `
            'The listener may be started manually or registered under another name.'
    }

    # Identify which process actually owns TCP 23.
    $Listeners = @(
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LocalPort -eq 23 -and
            $_.State -eq 'Listen'
        }
    )

    if ($Listeners.Count -eq 0) {
        Add-Check 'Telnet owning process' 'FAIL' `
            'No TCP 23 listener found' `
            'Inspect inetd/telnetd startup and configuration.'

        return
    }

    $ProcessIDs = @(
        $Listeners |
        Select-Object -ExpandProperty OwningProcess -Unique
    )

    $ServiceInventory = @(
        Get-CimInstance Win32_Service `
            -ErrorAction SilentlyContinue
    )

    foreach ($ProcessId in $ProcessIDs) {

        $ProcessObject = Get-CimInstance Win32_Process `
            -Filter "ProcessId=$ProcessId" `
            -ErrorAction SilentlyContinue

        if (-not $ProcessObject) {
            Add-Check 'Telnet owning process' 'WARN' `
                "PID $ProcessId was not found in process inventory" `
                'Recheck the listener; its owning process may have exited.'

            continue
        }

        $ProcessName = [string]$ProcessObject.Name
        $Executable = [string]$ProcessObject.ExecutablePath
        $CommandLine = [string]$ProcessObject.CommandLine

        $MatchingServices = @(
            $ServiceInventory |
            Where-Object {
                $_.ProcessId -eq $ProcessId
            }
        )

        Write-Host "PID: $ProcessId"
        Write-Host "Process: $ProcessName"
        Write-Host "Executable: $Executable"
        Write-Host "Command Line: $CommandLine"

        if ($MatchingServices.Count -gt 0) {

            foreach ($Svc in $MatchingServices) {
                Write-Host "Windows Service: $($Svc.Name)"
                Write-Host "Service State: $($Svc.State)"
            }

            Add-Check 'Telnet process owner' 'PASS' `
                "PID $ProcessId ($ProcessName); Service: $(($MatchingServices.Name) -join ', ')"
        }
        else {
            Write-Host 'Windows Service: None associated with PID'

            Add-Check 'Telnet process owner' 'INFO' `
                "PID $ProcessId ($ProcessName); no Windows service associated" `
                'Process may be running independently. Verify this is the expected Telnet server.'
        }

        if ($Executable) {
            Add-Check 'Telnet executable' 'INFO' $Executable
        }
        else {
            Add-Check 'Telnet executable' 'WARN' `
                "Executable path unavailable for PID $ProcessId" `
                'Inspect process permissions and executable ownership.'
        }

        Write-Host ""
    }
}

# ============================================================
# HEADER
# ============================================================

Write-Host "`n========================================" `
    -ForegroundColor Cyan
Write-Host "       IRSeC WINDOWS SERVICE HEALTH"
Write-Host "========================================"
Write-Host "Host: $env:COMPUTERNAME"
Write-Host "Profile: $Role"
Write-Host "Time: $(Get-Date)"
Write-Host "Mode: READ ONLY"

# ============================================================
# GENERAL NETWORK CHECKS
# ============================================================

$Adapters = @(
    Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' }
)

if ($Adapters.Count -gt 0) {
    Add-Check 'Network adapter' 'PASS' `
        "$($Adapters.Count) active adapter(s)"
}
else {
    Add-Check 'Network adapter' 'FAIL' `
        'No active adapter found' `
        'Inspect Get-NetAdapter and network interface settings.'
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
    Add-Check 'IPv4 address' 'FAIL' `
        'No preferred non-loopback IPv4 address' `
        'Inspect Get-NetIPConfiguration.'
}

# ============================================================
# FIREWALL PROFILES
# ============================================================

try {
    $Profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

    foreach ($Profile in $Profiles) {

        $State = if ($Profile.Enabled) {
            'PASS'
        }
        else {
            'WARN'
        }

        Add-Check "Firewall $($Profile.Name)" $State `
            "Enabled: $($Profile.Enabled); DefaultInbound: $($Profile.DefaultInboundAction)"
    }
}
catch {
    Add-Check 'Windows Firewall' 'WARN' `
        'Could not inspect firewall profiles'
}

# ============================================================
# HOST-SPECIFIC SERVICE CHECKS
# ============================================================

switch ($Role) {

    # --------------------------------------------------------
    # PITWALL - ACTIVE DIRECTORY / DNS
    # --------------------------------------------------------

    'pitwall' {

        Check-Service 'NTDS' 'Active Directory'
        Check-Service 'DNS' 'DNS Server'
        Check-Service 'Netlogon' 'Netlogon'

        Check-Port 53 'DNS TCP listener'
        Check-Port 88 'Kerberos TCP listener'
        Check-Port 389 'LDAP TCP listener'

        try {
            $Domain = (
                Get-CimInstance Win32_ComputerSystem
            ).Domain

            $DNS = Resolve-DnsName -Name $Domain `
                -Server 127.0.0.1 `
                -Type SOA `
                -ErrorAction Stop

            if ($DNS) {
                Add-Check 'DNS query' 'PASS' `
                    "Resolved $Domain SOA"
            }
        }
        catch {
            Add-Check 'DNS query' 'FAIL' `
                'Local DNS query failed' `
                'Inspect DNS zones, service, and resolver settings.'
        }

        Add-Check 'AD authentication' 'INFO' `
            'Domain login verification requires a separate credential test.'
    }

    # --------------------------------------------------------
    # TEAMRADIO - WINRM
    # --------------------------------------------------------

    'teamradio' {

        Check-Service 'WinRM'
        Check-Port 5985 'WinRM HTTP listener'

        try {
            Test-WSMan -ComputerName localhost `
                -ErrorAction Stop | Out-Null

            Add-Check 'WSMan response' 'PASS' `
                'Local WSMan responded'
        }
        catch {
            Add-Check 'WSMan response' 'FAIL' `
                'Local WSMan failed' `
                'Inspect WinRM listeners, authentication, and firewall rules.'
        }
    }

    # --------------------------------------------------------
    # SAFETYCAR - TELNET / ICMP
    # --------------------------------------------------------

    'safetycar' {

        # NEW: Identify the actual process hosting Telnet.
        Check-TelnetProcess

        # Standard TCP checks remain unchanged.
        Check-Port 23 'Telnet listener'
        Check-TCPResponse 23 'Telnet TCP response'

        # Report ICMP firewall allowances.
        $ICMPRules = @(
            Get-NetFirewallRule -Enabled True `
                -Direction Inbound `
                -Action Allow `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $Filter = $_ |
                    Get-NetFirewallPortFilter `
                        -ErrorAction SilentlyContinue

                $Filter.Protocol -in @('ICMPv4',1)
            }
        )

        Add-Check 'Inbound ICMP allow rules' 'INFO' `
            "Matching enabled allow rules: $($ICMPRules.Count)" `
            'Check firewall scope, profile, and remote ping reachability.'

        Add-Check 'Telnet login prompt' 'INFO' `
            'TCP acceptance does not prove a login prompt is presented.' `
            'Run W10 Deep Diagnostics to inspect Telnet protocol behavior.'
    }

    # --------------------------------------------------------
    # TRANSPORTERS - SMB
    # --------------------------------------------------------

    'transporters' {

        Check-Service 'LanmanServer' 'SMB Server'
        Check-Port 445 'SMB listener'
        Check-TCPResponse 445 'SMB TCP response'

        try {
            $Shares = @(Get-SmbShare -ErrorAction Stop)

            $Names = $Shares.Name -join ', '

            Add-Check 'SMB shares' 'INFO' `
                "$($Shares.Count) shares: $Names"
        }
        catch {
            Add-Check 'SMB shares' 'WARN' `
                'Unable to enumerate SMB shares'
        }
    }

    # --------------------------------------------------------
    # STEWARDS - IIS
    # --------------------------------------------------------

    'stewards' {

        Check-Service 'W3SVC' 'IIS Web Server'
        Check-Service 'WAS' 'Windows Process Activation'

        if (Get-Module -ListAvailable WebAdministration) {
            try {
                Import-Module WebAdministration `
                    -ErrorAction Stop

                $Sites = @(Get-Website -ErrorAction Stop)

                foreach ($Site in $Sites) {

                    $Status = if ($Site.State -eq 'Started') {
                        'PASS'
                    }
                    else {
                        'FAIL'
                    }

                    $BindingText = (
                        $Site.Bindings.Collection.bindingInformation -join ', '
                    )

                    Add-Check "IIS site: $($Site.Name)" `
                        $Status `
                        "State: $($Site.State); Bindings: $BindingText" `
                        'Inspect app pool, site bindings, and applicationHost.config.'
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
                -LocalPort 80,443 `
                -ErrorAction SilentlyContinue
        )

        if ($HTTP.Count -gt 0) {
            Add-Check 'HTTP/HTTPS listeners' 'PASS' `
                "Listening ports: $(($HTTP.LocalPort | Sort-Object -Unique) -join ', ')"
        }
        else {
            Add-Check 'HTTP/HTTPS listeners' 'WARN' `
                'Neither default HTTP port is listening' `
                'Inspect actual IIS bindings; a site may use another port.'
        }
    }
}

# ============================================================
# FINAL HEALTH REPORT
# ============================================================

Write-Host "`n=== HEALTH SUMMARY ===" -ForegroundColor Cyan

$Results |
    Format-Table Component,Status,Details -Wrap -AutoSize

$Problems = @(
    $Results |
    Where-Object {
        $_.Status -in @('FAIL','WARN')
    }
)

Write-Host "`n=== SUGGESTED INVESTIGATIONS ===" `
    -ForegroundColor Yellow

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

Write-Host ""
Write-Host "PASS: $(@($Results | Where-Object Status -eq 'PASS').Count)"
Write-Host "WARN: $(@($Results | Where-Object Status -eq 'WARN').Count)"
Write-Host "FAIL: $(@($Results | Where-Object Status -eq 'FAIL').Count)"
Write-Host "INFO: $(@($Results | Where-Object Status -eq 'INFO').Count)"

Write-Host 'Read-only checks complete. No changes made.'
