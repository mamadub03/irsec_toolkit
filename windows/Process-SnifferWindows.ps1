# IRSeC W06 - Windows Session & Process Investigator
# Windows PowerShell 5.1
# Run elevated for full visibility.
# No automatic IP blocking or service termination.

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1,10080)]
    [int]$Minutes = 60,

    [ValidateRange(1,100)]
    [int]$FailureThreshold = 5
)

$ErrorActionPreference = 'Stop'

$ProtectedNames = @(
    'System','Idle','smss.exe','csrss.exe',
    'wininit.exe','winlogon.exe','services.exe',
    'lsass.exe','svchost.exe','lsm.exe',
    'dns.exe','dfsr.exe','w3wp.exe',
    'inetinfo.exe','sshd.exe','inetd.exe',
    'tlntsvr.exe','datadog-agent.exe'
)

$ProtectedUsers = @(
    'whiteteam','dd-agent','ddagentuser'
)

function Get-ProcessOwner {
    param($ProcessObject)

    try {
        $Result = Invoke-CimMethod -InputObject $ProcessObject `
            -MethodName GetOwner -ErrorAction Stop

        if ($Result.ReturnValue -eq 0) {
            return "$($Result.Domain)\$($Result.User)"
        }
    }
    catch {}

    return 'Unavailable'
}

function Get-ServicePIDs {
    @(
        Get-CimInstance Win32_Service |
        Where-Object { $_.ProcessId -gt 0 } |
        Select-Object -ExpandProperty ProcessId -Unique
    )
}

function Get-ProcessDetails {
    param([int]$ProcessId)

    $ProcessObject = Get-CimInstance Win32_Process `
        -Filter "ProcessId=$ProcessId"

    if (-not $ProcessObject) {
        throw "PID $ProcessId was not found."
    }

    $Parent = Get-CimInstance Win32_Process `
        -Filter "ProcessId=$($ProcessObject.ParentProcessId)" `
        -ErrorAction SilentlyContinue

    $Owner = Get-ProcessOwner $ProcessObject

    $Services = @(
        Get-CimInstance Win32_Service |
        Where-Object { $_.ProcessId -eq $ProcessId }
    )

    $Connections = @(
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.OwningProcess -eq $ProcessId }
    )

    $Path = [string]$ProcessObject.ExecutablePath
    $Hash = 'Unavailable'

    if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
        try {
            $Hash = (Get-FileHash -LiteralPath $Path `
                -Algorithm SHA256).Hash
        }
        catch {}
    }

    [pscustomobject]@{
        PID = $ProcessId
        Name = $ProcessObject.Name
        Owner = $Owner
        ParentPID = $ProcessObject.ParentProcessId
        ParentName = if ($Parent) { $Parent.Name } else { 'Unknown' }
        CommandLine = $ProcessObject.CommandLine
        Executable = $Path
        SHA256 = $Hash
        Services = @($Services.Name) -join ', '
        Connections = $Connections
        Created = $ProcessObject.CreationDate
    }
}

function Test-ProtectedProcess {
    param($Details)

    if ($Details.PID -in @(0,4,$PID)) {
        return 'System or current PowerShell process'
    }

    if ($Details.Name -in $ProtectedNames) {
        return 'Protected operating-system or service process'
    }

    if ($Details.Services) {
        return "Windows service process: $($Details.Services)"
    }

    $Username = ($Details.Owner -split '\\')[-1]

    if ($Username -in $ProtectedUsers) {
        return 'Protected competition identity'
    }

    if ($Details.Executable) {
        $Path = $Details.Executable

        if ($Path -like "$env:windir\*" -or
            $Path -like "$env:ProgramFiles\*" -or
            $Path -like "${env:ProgramFiles(x86)}\*" -or
            $Path -match '(?i)datadog') {
            return 'Executable is in a protected application/system location'
        }
    }

    return $null
}

function Show-Connections {
    Write-Host "`n=== LIVE TCP CONNECTIONS ===" -ForegroundColor Cyan

    $Connections = @(
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $_.State -in @('Established','Listen') -and
            $_.OwningProcess -gt 0
        }
    )

    if (-not $Connections.Count) {
        Write-Host 'No matching connections found.'
        return
    }

    $Processes = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $Processes[[int]$_.ProcessId] = $_
    }

    $Rows = foreach ($Conn in $Connections) {
        $P = $Processes[[int]$Conn.OwningProcess]

        $Indicators = @()

        if ($P) {
            $Path = [string]$P.ExecutablePath
            if ($Path -match '(?i)\\(Temp|AppData\\Local\\Temp|Users\\Public)\\') {
                $Indicators += 'Unusual path'
            }
        }

        [pscustomobject]@{
            PID = $Conn.OwningProcess
            Process = if ($P) { $P.Name } else { '?' }
            State = $Conn.State
            Local = "$($Conn.LocalAddress):$($Conn.LocalPort)"
            Remote = "$($Conn.RemoteAddress):$($Conn.RemotePort)"
            Indicators = $Indicators -join ', '
        }
    }

    $Rows |
        Sort-Object Process,PID |
        Format-Table -AutoSize -Wrap

    Write-Host "`nUse menu option 2 to inspect a PID."
}

function Show-Sessions {
    Write-Host "`n=== WINDOWS INTERACTIVE SESSIONS ===" `
        -ForegroundColor Cyan

    & "$env:SystemRoot\System32\quser.exe" 2>&1 |
        Out-Host

    Write-Host 'Note: WinRM and some other remote access methods'
    Write-Host 'may not create a visible interactive session.'
}

function Show-Authentication {
    Write-Host "`n=== AUTHENTICATION IP SUMMARY ===" `
        -ForegroundColor Cyan

    try {
        $Events = @(
            Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4624,4625
                StartTime = (Get-Date).AddMinutes(-$Minutes)
            } -ErrorAction Stop
        )
    }
    catch {
        Write-Warning "Authentication events unavailable: $($_.Exception.Message)"
        return
    }

    $Records = @(
        foreach ($Event in $Events) {
            try {
                [xml]$Xml = $Event.ToXml()
                $Fields = @{}

                foreach ($Field in $Xml.Event.EventData.Data) {
                    $Fields[[string]$Field.Name] = [string]$Field.'#text'
                }

                $IP = [string]$Fields['IpAddress']
                $Type = [string]$Fields['LogonType']

                if ($IP -in @('','-','127.0.0.1','::1') -or
                    $Type -notin @('3','10')) {
                    continue
                }

                [pscustomobject]@{
                    Time = $Event.TimeCreated
                    IP = $IP
                    User = $Fields['TargetUserName']
                    Success = ($Event.Id -eq 4624)
                }
            }
            catch {}
        }
    )

    $Summary = foreach ($Group in ($Records | Group-Object IP)) {
        $Failed = @($Group.Group | Where-Object { -not $_.Success })
        $Success = @($Group.Group | Where-Object { $_.Success })

        $Flags = @()

        if ($Failed.Count -ge $FailureThreshold) {
            $Flags += 'Repeated login failures'
        }

        foreach ($S in $Success) {
            if (@($Failed | Where-Object {
                $_.Time -lt $S.Time -and $_.User -eq $S.User
            }).Count -gt 0) {
                $Flags += 'Success after failure'
                break
            }
        }

        [pscustomobject]@{
            IP = $Group.Name
            Failed = $Failed.Count
            Success = $Success.Count
            Users = ($Group.Group.User | Sort-Object -Unique) -join ','
            Indicators = ($Flags | Select-Object -Unique) -join '; '
        }
    }

    if ($Summary) {
        $Summary |
            Sort-Object Failed -Descending |
            Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host 'No matching remote authentication events.'
    }

    Write-Host "`nThese IPs require investigation, not automatic blocking."
}

function Inspect-PID {
    param([int]$ProcessId)

    $D = Get-ProcessDetails $ProcessId
    $Reason = Test-ProtectedProcess $D

    Write-Host "`n=== PROCESS DETAILS ===" -ForegroundColor Cyan
    $D |
        Select-Object PID,Name,Owner,ParentPID,ParentName,
            Created,Executable,SHA256,Services,CommandLine |
        Format-List

    Write-Host "`n=== PROCESS CONNECTIONS ===" -ForegroundColor Cyan
    $D.Connections |
        Select-Object State,LocalAddress,LocalPort,
            RemoteAddress,RemotePort |
        Format-Table -AutoSize

    if ($Reason) {
        Write-Host "`nPROTECTED: $Reason" -ForegroundColor Yellow
    }
    else {
        Write-Host "`nNo built-in protection rule matched." `
            -ForegroundColor Yellow
        Write-Host 'This does NOT establish that the process is malicious.'
    }
}

function Kill-PID {
    param([int]$ProcessId)

    $D = Get-ProcessDetails $ProcessId
    $Reason = Test-ProtectedProcess $D

    if ($Reason) {
        throw "Termination refused: $Reason"
    }

    Inspect-PID $ProcessId

    Write-Warning 'Terminating the wrong process may disrupt a scored service.'
    $Expected = "KILL $ProcessId"

    if ((Read-Host "Type $Expected") -cne $Expected) {
        Write-Host 'Cancelled.'
        return
    }

    # Recheck identity to reduce PID-reuse risk.
    $Fresh = Get-ProcessDetails $ProcessId

    if ($Fresh.Created -ne $D.Created -or
        $Fresh.Executable -ne $D.Executable -or
        (Test-ProtectedProcess $Fresh)) {
        throw 'Process identity or protection status changed.'
    }

    Stop-Process -Id $ProcessId -Force -ErrorAction Stop

    Write-Host "[SUCCESS] Termination requested for PID $ProcessId" `
        -ForegroundColor Green
    Write-Host "Executable location: $($D.Executable)"
    Write-Host 'No executable was deleted and no IP was blocked.'
}

while ($true) {
    Write-Host "`n========== IRSeC WINDOWS INVESTIGATOR ==========" `
        -ForegroundColor Cyan

    Write-Host '[1] Live connections and processes'
    Write-Host '[2] Inspect a PID'
    Write-Host '[3] Sessions and authentication IPs'
    Write-Host '[4] Kill a selected process'
    Write-Host '[5] Refresh all'
    Write-Host '[Q] Exit'

    $Choice = (Read-Host 'Choose').Trim().ToUpperInvariant()

    try {
        switch ($Choice) {
            '1' { Show-Connections }
            '2' {
                $InputPID = [int](Read-Host 'PID to inspect')
                Inspect-PID $InputPID
            }
            '3' {
                Show-Sessions
                Show-Authentication
            }
            '4' {
                $InputPID = [int](Read-Host 'PID to terminate')
                Kill-PID $InputPID
            }
            '5' {
                Show-Sessions
                Show-Connections
                Show-Authentication
            }
            'Q' { return }
            default { Write-Warning 'Invalid option.' }
        }
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}