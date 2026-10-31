# ============================================================
# IRSeC W10 - Windows Deep Diagnostics
# Windows PowerShell 5.1 - READ ONLY
#
# Profiles:
#   pitwall      AD/DNS
#   teamradio    WinRM
#   safetycar    Telnet/ICMP
#   transporters SMB
#   stewards     IIS
#
# Usage:
# .\Windows-DeepDiagnostics.ps1 -Role safetycar
# .\Windows-DeepDiagnostics.ps1 -Role pitwall
# ============================================================

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet(
        'Auto','pitwall','teamradio','safetycar',
        'transporters','stewards'
    )]
    [string]$Role = 'Auto',

    [ValidateRange(1,240)]
    [int]$RecentMinutes = 30
)

$ErrorActionPreference = 'Stop'
$script:Results = @()

if ($Role -eq 'Auto') {
    $Role = $env:COMPUTERNAME.ToLowerInvariant()
}

if ($Role -notin @(
    'pitwall','teamradio','safetycar',
    'transporters','stewards'
)) {
    throw "Unknown role: $Role"
}

# ============================================================
# REPORTING
# ============================================================

function Add-Result {
    param(
        [string]$Area,
        [string]$Status,
        [string]$Finding,
        [string]$Suggestion = ''
    )

    $script:Results += [pscustomobject]@{
        Area       = $Area
        Status     = $Status
        Finding    = $Finding
        Suggestion = $Suggestion
    }
}

function Show-Section {
    param([string]$Name)

    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
}

# ============================================================
# SERVICE AND PROCESS INVESTIGATION
# ============================================================

function Check-Service {
    param([string]$Name)

    $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if (-not $Svc) {
        Add-Result $Name 'WARN' 'Service not found'
    }
    elseif ($Svc.Status -eq 'Running') {
        Add-Result $Name 'PASS' 'Running'
    }
    else {
        Add-Result $Name 'FAIL' "Status: $($Svc.Status)" `
            "Inspect Get-Service $Name and System event logs."
    }
}

function Check-Listener {
    param(
        [int]$Port,
        [string]$Name
    )

    $Listeners = @(
        Get-NetTCPConnection -State Listen `
            -LocalPort $Port -ErrorAction SilentlyContinue
    )

    if ($Listeners.Count -eq 0) {
        Add-Result $Name 'FAIL' "No TCP $Port listener" `
            'Inspect service startup, binding, and configuration.'
        return
    }

    $Addresses = @(
        $Listeners |
            Select-Object -ExpandProperty LocalAddress -Unique
    )

    $ExternalBindings = @(
        $Addresses |
            Where-Object { $_ -notin @('127.0.0.1','::1') }
    )

    $Status = if ($ExternalBindings.Count) { 'PASS' } else { 'WARN' }

    Add-Result $Name $Status `
        "TCP $Port bound to: $($Addresses -join ', ')" `
        'Loopback-only binding cannot accept connections on the LAN IP.'

    foreach ($Listener in $Listeners) {
        $ProcessID = [int]$Listener.OwningProcess

        $Proc = Get-CimInstance Win32_Process `
            -Filter "ProcessId=$ProcessID" `
            -ErrorAction SilentlyContinue

        if (-not $Proc) {
            Add-Result "$Name owner" 'WARN' `
                "PID $ProcessID could not be inspected"
            continue
        }

        $Services = @(
            Get-CimInstance Win32_Service `
                -Filter "ProcessId=$ProcessID" `
                -ErrorAction SilentlyContinue
        )

        Show-Section "$Name PROCESS OWNER"

        Write-Host "PID: $ProcessID"
        Write-Host "Process: $($Proc.Name)"
        Write-Host "Executable: $($Proc.ExecutablePath)"
        Write-Host "Command: $($Proc.CommandLine)"

        if ($Services.Count) {
            Write-Host "Windows services: $(($Services.Name) -join ', ')"

            foreach ($Svc in $Services) {
                Write-Host "  $($Svc.Name): $($Svc.State)"
            }
        }
        else {
            Write-Host 'Windows service: No matching registration'
        }

        Add-Result "$Name owner" 'INFO' `
            "PID $ProcessID; process=$($Proc.Name); services=$(($Services.Name) -join ',')"
    }
}

# ============================================================
# LOCAL TCP AND OPTIONAL BANNER CHECK
# ============================================================

function Test-LocalTCP {
    param(
        [int]$Port,
        [string]$Name,
        [switch]$ReadBanner
    )

    $Client = New-Object System.Net.Sockets.TcpClient
    $WaitHandle = $null

    try {
        $Async = $Client.BeginConnect(
            '127.0.0.1',$Port,$null,$null
        )

        $WaitHandle = $Async.AsyncWaitHandle

        if (-not $WaitHandle.WaitOne(1500,$false)) {
            Add-Result $Name 'FAIL' 'Local TCP connection timed out'
            return
        }

        $Client.EndConnect($Async)

        if (-not $ReadBanner) {
            Add-Result $Name 'PASS' "TCP $Port accepted locally"
            return
        }

        $Stream = $Client.GetStream()
        $Stream.ReadTimeout = 2500

        $Buffer = New-Object byte[] 512

        try {
            $Count = $Stream.Read($Buffer,0,$Buffer.Length)

            if ($Count -le 0) {
                Add-Result $Name 'WARN' `
                    'TCP accepted but connection closed without a prompt'
                return
            }

            $Raw = [Text.Encoding]::ASCII.GetString(
                $Buffer,0,$Count
            )

            $Display = (
                $Raw -replace '[^\x20-\x7E]',' '
            ).Trim()

            if ($Display.Length -gt 150) {
                $Display = $Display.Substring(0,150)
            }

            if ($Raw -match '(?i)login:|username:|password:|welcome') {
                Add-Result $Name 'PASS' `
                    "Login-like prompt received: $Display"
            }
            else {
                Add-Result $Name 'WARN' `
                    "TCP responded but no recognizable prompt: $Display" `
                    'Telnet negotiation may require an interactive client.'
            }
        }
        catch {
            Add-Result $Name 'WARN' `
                'TCP connected but no initial prompt arrived within 2.5 seconds' `
                'Inspect the Telnet daemon and test with a Telnet client.'
        }
    }
    catch {
        Add-Result $Name 'FAIL' `
            "TCP connection failed: $($_.Exception.Message)"
    }
    finally {
        if ($WaitHandle) {
            $WaitHandle.Close()
        }

        $Client.Close()
    }
}

# ============================================================
# FIREWALL DIAGNOSTICS
# ============================================================

function Test-RulePort {
    param(
        [string]$Specification,
        [int]$Port
    )

    if ($Specification -eq 'Any') {
        return $true
    }

    foreach ($Part in ($Specification -split ',')) {
        $Part = $Part.Trim()

        if ($Part -eq [string]$Port) {
            return $true
        }

        if ($Part -match '^(\d+)-(\d+)$') {
            if ($Port -ge [int]$Matches[1] -and
                $Port -le [int]$Matches[2]) {
                return $true
            }
        }
    }

    return $false
}

function Show-FirewallRules {
    param(
        [string]$Name,
        [int]$Port = 0,
        [switch]$Icmp
    )

    Show-Section "FIREWALL: $Name"

    try {
        $Profiles = @(Get-NetFirewallProfile -ErrorAction Stop)

        $Profiles |
            Select-Object Name,Enabled,DefaultInboundAction |
            Format-Table -AutoSize |
            Out-Host

        $Rules = @(
            Get-NetFirewallRule -PolicyStore ActiveStore `
                -Direction Inbound -Enabled True `
                -ErrorAction Stop
        )

        $Matches = @(
            foreach ($Rule in $Rules) {
                try {
                    $Filter = $Rule |
                        Get-NetFirewallPortFilter -ErrorAction Stop

                    $Address = $Rule |
                        Get-NetFirewallAddressFilter -ErrorAction Stop

                    $Protocol = [string]$Filter.Protocol
                    $LocalPort = [string]($Filter.LocalPort -join ',')

                    $Include = $false

                    if ($Icmp) {
                        $Include = $Protocol -in @('ICMPv4','1')
                    }
                    elseif ($Port -gt 0) {
                        if ($Protocol -in @('TCP','6','Any')) {
                            $Include = Test-RulePort `
                                -Specification $LocalPort `
                                -Port $Port
                        }
                    }

                    if ($Include) {
                        $Category = if ($LocalPort -eq 'Any') {
                            'BROAD'
                        }
                        else {
                            'PORT-SPECIFIC'
                        }

                        [pscustomobject]@{
                            Rule     = $Rule.DisplayName
                            Action   = [string]$Rule.Action
                            Profile  = [string]$Rule.Profile
                            Protocol = $Protocol
                            Port     = $LocalPort
                            ICMPType = [string]($Filter.IcmpType -join ',')
                            RemoteIP = [string]($Address.RemoteAddress -join ',')
                            Category = $Category
                        }
                    }
                }
                catch {
                    Write-Warning "Could not inspect rule $($Rule.Name)"
                }
            }
        )

        $Important = @(
            $Matches | Where-Object {
                $_.Category -eq 'PORT-SPECIFIC' -or
                $_.Action -eq 'Block' -or
                $Icmp
            }
        )

        if ($Important.Count) {
            $Important |
                Sort-Object Action,Category,Rule |
                Format-Table -AutoSize -Wrap |
                Out-Host
        }
        else {
            Write-Host 'No explicit or blocking matching rules found.'
        }

        $Hidden = $Matches.Count - $Important.Count

        if ($Hidden -gt 0) {
            Write-Host "$Hidden broad allow rule(s) omitted for readability."
        }

        Add-Result $Name 'INFO' `
            "$($Matches.Count) matching enabled inbound firewall rules" `
            'Inspect rule scope, active profiles, and blocks. This is not a definitive packet decision.'
    }
    catch {
        Add-Result $Name 'WARN' `
            "Firewall inspection failed: $($_.Exception.Message)"
    }
}

# ============================================================
# RECENT SYSTEM ERRORS
# ============================================================

function Show-Events {
    param([string[]]$Patterns)

    Show-Section 'RECENT RELATED SYSTEM ERRORS'

    try {
        $Events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Level     = 2,3
                StartTime = (Get-Date).AddMinutes(-$RecentMinutes)
            } -MaxEvents 150 -ErrorAction Stop
        )

        $Filtered = @(
            $Events | Where-Object {
                $Text = "$($_.ProviderName) $($_.Message)"
                $Found = $false

                foreach ($Pattern in $Patterns) {
                    if ($Text -match $Pattern) {
                        $Found = $true
                        break
                    }
                }

                $Found
            } | Select-Object -First 12
        )

        if ($Filtered.Count) {
            $Filtered |
                Select-Object TimeCreated,ProviderName,Id,
                    @{Name='Message';Expression={
                        $Msg = [string]$_.Message -replace '\s+',' '
                        if ($Msg.Length -gt 160) {
                            $Msg.Substring(0,160)
                        }
                        else {
                            $Msg
                        }
                    }} |
                Format-Table -AutoSize -Wrap |
                Out-Host
        }
        else {
            Write-Host 'No matching recent System warnings/errors.'
        }
    }
    catch {
        Write-Host 'No readable matching System events.'
    }
}

# ============================================================
# HOST INFORMATION
# ============================================================

Show-Section 'IRSeC WINDOWS DEEP DIAGNOSTICS'

Write-Host "Host: $env:COMPUTERNAME"
Write-Host "Profile: $Role"
Write-Host "Time: $(Get-Date)"
Write-Host 'Mode: READ ONLY'

Show-Section 'NETWORK CONFIGURATION'

try {
    Get-NetIPConfiguration |
        Select-Object InterfaceAlias,
            @{N='IPv4';E={$_.IPv4Address.IPAddress -join ','}},
            @{N='Gateway';E={$_.IPv4DefaultGateway.NextHop -join ','}} |
        Format-Table -AutoSize |
        Out-Host
}
catch {
    Add-Result 'Network' 'WARN' 'Network configuration unavailable'
}

# ============================================================
# SERVICE-SPECIFIC CHECKS
# ============================================================

switch ($Role) {

    'safetycar' {
        Show-Section 'ICMP DIAGNOSTICS'

        Show-FirewallRules 'Inbound ICMPv4' -Icmp

        Add-Result 'Remote ICMP' 'INFO' `
            'Remote ping not tested from this machine' `
            'Verify ping from another authorized competition host.'

        Show-Section 'TELNET DIAGNOSTICS'

        Check-Listener 23 'Telnet listener'

        Test-LocalTCP 23 'Telnet prompt' -ReadBanner

        foreach ($Path in @(
            'C:\cygwin64\etc\inetd.conf',
            'C:\cygwin\etc\inetd.conf'
        )) {
            if (Test-Path -LiteralPath $Path) {
                Write-Host "Cygwin configuration: $Path"
            }
        }

        Show-FirewallRules 'Telnet TCP 23' -Port 23

        Show-Events @('telnet','inetd','kts','service control')
    }

    'teamradio' {
        Show-Section 'WINRM DIAGNOSTICS'

        Check-Service 'WinRM'
        Check-Listener 5985 'WinRM listener'

        try {
            Test-WSMan localhost -ErrorAction Stop | Out-Null
            Add-Result 'WSMan' 'PASS' 'Local WSMan responded'
        }
        catch {
            Add-Result 'WSMan' 'FAIL' `
                "Local WSMan failed: $($_.Exception.Message)"
        }

        Write-Host "`n=== WINRM LISTENER CONFIGURATION ==="

        & winrm.exe enumerate winrm/config/listener 2>&1 |
            Out-Host

        Show-FirewallRules 'WinRM TCP 5985' -Port 5985
        Show-Events @('winrm','ws-management')
    }

    'pitwall' {
        Show-Section 'AD / DNS DIAGNOSTICS'

        foreach ($Name in @('NTDS','DNS','Netlogon')) {
            Check-Service $Name
        }

        foreach ($Port in @(53,88,389)) {
            Check-Listener $Port "AD/DNS TCP $Port"
        }

        try {
            $Domain = (Get-CimInstance Win32_ComputerSystem).Domain

            Resolve-DnsName -Name $Domain -Type SOA `
                -Server 127.0.0.1 -ErrorAction Stop |
                Out-Null

            Add-Result 'DNS SOA' 'PASS' "$Domain resolved locally"

            $SRV = "_ldap._tcp.dc._msdcs.$Domain"

            $Records = @(
                Resolve-DnsName -Name $SRV -Type SRV `
                    -Server 127.0.0.1 -ErrorAction Stop
            )

            Add-Result 'DC locator' 'PASS' `
                "$($Records.Count) DNS response record(s)"
        }
        catch {
            Add-Result 'AD/DNS discovery' 'FAIL' `
                "$($_.Exception.Message)"
        }

        Show-Events @('ntds','dns','netlogon','kerberos','kdc')
    }

    'transporters' {
        Show-Section 'SMB DIAGNOSTICS'

        Check-Service 'LanmanServer'
        Check-Listener 445 'SMB listener'

        try {
            $Config = Get-SmbServerConfiguration

            Add-Result 'SMB settings' 'INFO' `
                "SMB1=$($Config.EnableSMB1Protocol); SMB2=$($Config.EnableSMB2Protocol); Signing=$($Config.RequireSecuritySignature)"

            Get-SmbShare |
                Select-Object Name,Path,Description |
                Format-Table -AutoSize |
                Out-Host
        }
        catch {
            Add-Result 'SMB inventory' 'WARN' `
                "$($_.Exception.Message)"
        }

        Show-FirewallRules 'SMB TCP 445' -Port 445
        Show-Events @('smb','lanmanserver','srv2')
    }

    'stewards' {
        Show-Section 'IIS DIAGNOSTICS'

        Check-Service 'W3SVC'
        Check-Service 'WAS'

        try {
            Import-Module WebAdministration -ErrorAction Stop

            foreach ($Pool in @(Get-ChildItem IIS:\AppPools)) {
                $State = (Get-WebAppPoolState -Name $Pool.Name).Value

                $Status = if ($State -eq 'Started') {
                    'PASS'
                }
                else {
                    'FAIL'
                }

                Add-Result "AppPool $($Pool.Name)" $Status `
                    "State: $State"
            }

            foreach ($Site in @(Get-Website)) {
                $Status = if ($Site.State -eq 'Started') {
                    'PASS'
                }
                else {
                    'FAIL'
                }

                Add-Result "Site $($Site.Name)" $Status `
                    "State: $($Site.State)"

                foreach ($Binding in @($Site.Bindings.Collection)) {
                    $Info = [string]$Binding.bindingInformation
                    Write-Host "Binding: $($Site.Name) $($Binding.protocol) $Info"

                    if ($Info -match '^.*:(\d+):') {
                        $Port = [int]$Matches[1]

                        Check-Listener $Port "IIS TCP $Port"
                        Show-FirewallRules "IIS TCP $Port" -Port $Port
                    }
                }
            }
        }
        catch {
            Add-Result 'IIS inspection' 'WARN' `
                "$($_.Exception.Message)"
        }

        Show-Events @('w3svc','was','iis','application pool')
    }
}

# ============================================================
# FINAL REPORT
# ============================================================

Show-Section 'DIAGNOSTIC SUMMARY'

$Results |
    Format-Table Area,Status,Finding -AutoSize -Wrap |
    Out-Host

Show-Section 'INVESTIGATION SUGGESTIONS'

$Problems = @(
    $Results | Where-Object {
        $_.Status -in @('FAIL','WARN')
    }
)

if ($Problems.Count -eq 0) {
    Write-Host 'No obvious local faults detected.'
}
else {
    foreach ($Problem in $Problems) {
        Write-Host "[$($Problem.Status)] $($Problem.Area)"
        Write-Host "  $($Problem.Finding)"

        if ($Problem.Suggestion) {
            Write-Host "  Suggestion: $($Problem.Suggestion)"
        }
    }
}

Write-Host "`nREAD-ONLY diagnostics complete."
Write-Host 'Local success does not prove remote Hermes/pfSense reachability.'
