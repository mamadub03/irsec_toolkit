# IRSeC W02 - Windows Local Password Rotator
# Windows PowerShell 5.1, run elevated.

#Requires -Version 5.1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$Admins = @(
    'scrutineer','techdirector','crewchief','firecrew'
)
$Regular = @(
    'jackcrew','garagecrew','celebrity',
    'pitlaner','reserve','gunners'
)
$Allowed = @($Admins) + @($Regular)

$Protected = @(
    'whiteteam','Administrator','Guest','DefaultAccount',
    'WDAGUtilityAccount','dd-agent','ddagentuser'
)
$ProtectedRIDs = @(500,501,503,504)

function Read-Password {
    param([string]$Name)
    while ($true) {
        $a = Read-Host "New password for $Name" -AsSecureString
        $b = Read-Host "Confirm password for $Name" -AsSecureString

        try {
            $x = [pscredential]::new('temp',$a).
                GetNetworkCredential().Password
            $y = [pscredential]::new('temp',$b).
                GetNetworkCredential().Password
            $ok = ($x.Length -gt 0 -and $x -ceq $y)
        }
        finally {
            $x = $null
            $y = $null
            $b.Dispose()
        }

        if ($ok) { return $a }
        $a.Dispose()
        Write-Warning 'Passwords do not match or are empty.'
    }
}

$Computer = Get-CimInstance Win32_ComputerSystem
if ($Computer.DomainRole -in @(4,5)) {
    throw 'Domain controller detected. Local rotation is prohibited.'
}

Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

# Build exact local service-account references.
$Dependencies = @(
    Get-CimInstance Win32_Service |
    Where-Object { $_.StartName } |
    ForEach-Object { [string]$_.StartName }
)

try {
    $Dependencies += @(
        Get-ScheduledTask |
        Where-Object { $_.Principal.UserId } |
        ForEach-Object { [string]$_.Principal.UserId }
    )
}
catch {
    # Fail closed: we cannot establish task dependencies.
    throw "Unable to inspect scheduled tasks: $($_.Exception.Message)"
}

function Test-Eligible {
    param($User)

    if ($null -eq $User) { return $false }
    if ($User.Name -notin $Allowed) { return $false }
    if ($User.Name -in $Protected) { return $false }
    if (-not $User.Enabled) { return $false }

    $rid = [int](($User.SID.Value -split '-')[-1])
    if ($rid -in $ProtectedRIDs) { return $false }

    $localForms = @(
        "$env:COMPUTERNAME\$($User.Name)",
        ".\$($User.Name)",
        $User.SID.Value
    )

    foreach ($dependency in $Dependencies) {
        if ($dependency -in $localForms) { return $false }

        # An unqualified identity is ambiguous: protect it.
        if ($dependency -ieq $User.Name) { return $false }
    }

    return $true
}

$Available = @(
    Get-LocalUser | Where-Object { Test-Eligible $_ }
)

Write-Host "`n=== IRSeC WINDOWS LOCAL ROTATOR ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME"
$Available | Select-Object Name,Enabled | Format-Table -AutoSize

if ($Available.Count -eq 0) {
    throw 'No eligible local accounts found.'
}

Write-Host '[1] Rotate ONE'
Write-Host '[2] Rotate SELECTED'
Write-Host '[3] Rotate ALL eligible'
Write-Host '[4] Rotate regular accounts'
Write-Host '[5] Exit'

$choice = Read-Host 'Choose'

switch ($choice) {
    '1' {
        $Names = @((Read-Host 'Username').Trim())
    }
    '2' {
        $Names = @(
            (Read-Host 'Comma-separated usernames') -split ',' |
            ForEach-Object { $_.Trim() }
        )
    }
    '3' {
        $Names = @($Available | ForEach-Object Name)
    }
    '4' {
        $Names = @(
            $Available |
            Where-Object { $_.Name -in $Regular } |
            ForEach-Object Name
        )
    }
    '5' { return }
    default { throw 'Invalid menu option.' }
}

if ($Names.Count -eq 0 -or
    @($Names | Where-Object { -not $_ }).Count -gt 0 -or
    @($Names | Sort-Object -Unique).Count -ne $Names.Count) {
    throw 'Invalid or duplicate selections.'
}

$Targets = @(
    foreach ($Name in $Names) {
        $match = @($Available | Where-Object { $_.Name -ieq $Name })
        if ($match.Count -ne 1) {
            throw "Not an eligible local account: $Name"
        }
        $match[0]
    }
)

# Move the current account to the end, not out of the list.
$CurrentSID = [Security.Principal.WindowsIdentity]::GetCurrent().
    User.Value

$Targets = @(
    $Targets | Where-Object { $_.SID.Value -ne $CurrentSID }
) + @(
    $Targets | Where-Object { $_.SID.Value -eq $CurrentSID }
)

Write-Host "`n=== ROTATION PREVIEW ==="
$Targets | Select-Object Name | Format-Table -AutoSize

$expected = "ROTATE $($Targets.Count)"
if ((Read-Host "Type $expected") -cne $expected) { return }

if (@($Targets | Where-Object { $_.Name -in $Admins }).Count -gt 0) {
    if ((Read-Host 'Admins included. Type ADMINS') -cne 'ADMINS') {
        return
    }
}

if (@($Targets | Where-Object {
    $_.SID.Value -eq $CurrentSID
}).Count -gt 0) {
    Write-Warning 'Your current login password will rotate LAST.'
    if ((Read-Host 'Type CURRENT') -cne 'CURRENT') { return }
}

Write-Host '[1] Unique passwords (recommended)'
Write-Host '[2] Shared password'
$mode = Read-Host 'Choose'
if ($mode -notin @('1','2')) { return }

if ($mode -eq '2' -and $Targets.Count -gt 1) {
    Write-Warning 'Shared passwords increase compromise risk.'
    if ((Read-Host 'Type SHARED') -cne 'SHARED') { return }
}

$Assignments = @()
$Shared = $null
$Results = @()

try {
    if ($mode -eq '2') {
        $Shared = Read-Password 'ALL SELECTED'
    }

    foreach ($User in $Targets) {
        $pwd = if ($mode -eq '2') {
            $Shared
        } else {
            Read-Password $User.Name
        }

        $Assignments += [pscustomobject]@{
            User = $User
            Password = $pwd
        }
    }

    foreach ($item in $Assignments) {
        try {
            $fresh = Get-LocalUser -SID $item.User.SID
            if (-not (Test-Eligible $fresh)) {
                throw 'Account no longer eligible.'
            }

            Set-LocalUser -SID $fresh.SID `
                -Password $item.Password -ErrorAction Stop

            Write-Host "[SUCCESS] $($fresh.Name)" -ForegroundColor Green
            $Results += [pscustomobject]@{
                Account = $fresh.Name
                Status = 'SUCCESS'
            }
        }
        catch {
            Write-Warning "Stopping at $($item.User.Name): $($_.Exception.Message)"
            $Results += [pscustomobject]@{
                Account = $item.User.Name
                Status = 'FAILED OR UNCERTAIN'
            }
            break
        }
    }
}
finally {
    if ($null -ne $Shared) {
        $Shared.Dispose()
    } else {
        foreach ($item in $Assignments) {
            if ($null -ne $item.Password) {
                $item.Password.Dispose()
            }
        }
    }
}

Write-Host "`n=== RESULTS ==="
$Results | Format-Table -AutoSize
Write-Host 'Verify authentication with the new credentials.'