# IRSeC W09 - Windows Persistence Scanner
# READ ONLY - Windows PowerShell 5.1
# Run elevated for full visibility.

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$All
)

$ErrorActionPreference = 'Continue'
$Findings = @()

function Get-Indicators {
    param([string]$Text)

    $Flags = @()

    if ($Text -match '(?i)\\Users\\Public\\|\\AppData\\|\\Temp\\') {
        $Flags += 'USER_WRITABLE_PATH'
    }

    if ($Text -match '(?i)powershell(?:\.exe)?\b.*(?:-enc|-encodedcommand|downloadstring|invoke-expression|iex\b)') {
        $Flags += 'ENCODED_OR_DOWNLOAD_COMMAND'
    }

    if ($Text -match '(?i)\\(?:ProgramData|Windows\\Tasks)\\.*\.(?:exe|ps1|vbs|bat|cmd)') {
        $Flags += 'REVIEW_EXECUTABLE_PATH'
    }

    if ($Text -match '(?i)(?:\\|/)(?:curl|wget)\b.*(?:https?://)') {
        $Flags += 'NETWORK_DOWNLOAD_COMMAND'
    }

    return @($Flags)
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Command,
        [string]$Location,
        [string]$User = '',
        [string]$State = ''
    )

    $Flags = @(Get-Indicators $Command)

    if (-not $All -and $Flags.Count -eq 0) {
        return
    }

    $script:Findings += [pscustomobject]@{
        Category = $Category
        Name = $Name
        User = $User
        State = $State
        Command = $Command
        Location = $Location
        Indicators = $Flags -join ', '
    }
}

Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan

try {
    foreach ($Task in @(Get-ScheduledTask)) {
        $Command = @(
            foreach ($Action in $Task.Actions) {
                "$($Action.Execute) $($Action.Arguments)"
            }
        ) -join '; '

        Add-Finding `
            -Category 'ScheduledTask' `
            -Name $Task.TaskName `
            -Command $Command `
            -Location $Task.TaskPath `
            -User $Task.Principal.UserId `
            -State ([string]$Task.State)
    }
}
catch {
    Write-Warning "Could not enumerate scheduled tasks."
}

Write-Host "Scheduled task scan finished."

Write-Host "`n=== WINDOWS SERVICES ===" -ForegroundColor Cyan

try {
    foreach ($Svc in @(Get-CimInstance Win32_Service)) {
        Add-Finding `
            -Category 'Service' `
            -Name $Svc.Name `
            -Command ([string]$Svc.PathName) `
            -Location 'Windows Service Control Manager' `
            -User $Svc.StartName `
            -State $Svc.State
    }
}
catch {
    Write-Warning "Could not enumerate services."
}

Write-Host "Service scan finished."

Write-Host "`n=== REGISTRY AUTORUNS ===" -ForegroundColor Cyan

$RunPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($Path in $RunPaths) {
    if (-not (Test-Path $Path)) { continue }

    try {
        $Item = Get-ItemProperty -Path $Path

        foreach ($Property in $Item.PSObject.Properties) {
            if ($Property.Name -match '^PS') { continue }

            Add-Finding `
                -Category 'RegistryAutorun' `
                -Name $Property.Name `
                -Command ([string]$Property.Value) `
                -Location $Path
        }
    }
    catch {
        Write-Warning "Could not read $Path"
    }
}

# Also inspect loaded user registry hives.
$UserRunPaths = @(
    'Software\Microsoft\Windows\CurrentVersion\Run',
    'Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($Hive in @(Get-ChildItem Registry::HKEY_USERS)) {
    $SID = $Hive.PSChildName

    if ($SID -notmatch '^S-1-5-21-.*-\d+$') {
        continue
    }

    foreach ($Suffix in $UserRunPaths) {
        $Path = "Registry::HKEY_USERS\$SID\$Suffix"

        if (-not (Test-Path $Path)) { continue }

        try {
            $Item = Get-ItemProperty -LiteralPath $Path

            foreach ($Property in $Item.PSObject.Properties) {
                if ($Property.Name -match '^PS') { continue }

                Add-Finding `
                    -Category 'UserRegistryAutorun' `
                    -Name $Property.Name `
                    -Command ([string]$Property.Value) `
                    -Location $Path `
                    -User $SID
            }
        }
        catch {}
    }
}

Write-Host "`n=== STARTUP FOLDERS ===" -ForegroundColor Cyan

$StartupPaths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

$Profiles = @(
    Get-CimInstance Win32_UserProfile |
    Where-Object { $_.LocalPath -and -not $_.Special }
)

foreach ($Profile in $Profiles) {
    $StartupPaths += Join-Path $Profile.LocalPath `
        'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
}

foreach ($Folder in $StartupPaths) {
    if (-not (Test-Path $Folder)) { continue }

    foreach ($Item in @(Get-ChildItem -LiteralPath $Folder `
                -Force -ErrorAction SilentlyContinue)) {

        $Target = $Item.FullName

        if ($Item.Extension -ieq '.lnk') {
            try {
                $Shell = New-Object -ComObject WScript.Shell
                $Shortcut = $Shell.CreateShortcut($Item.FullName)
                $Target = "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
            }
            catch {}
        }

        Add-Finding `
            -Category 'StartupFolder' `
            -Name $Item.Name `
            -Command $Target `
            -Location $Item.FullName
    }
}

Write-Host "`n=== PERSISTENCE RESULTS ===" -ForegroundColor Cyan

if ($Findings.Count -eq 0) {
    Write-Host 'No matching entries found.'
    Write-Host 'Use -All to inspect all collected entries.'
}
else {
    $Findings |
        Select-Object Category,Name,User,State,Indicators |
        Format-Table -AutoSize -Wrap

    Write-Host "`n=== DETAILS AND LOCATIONS ==="

    $Findings |
        Format-List Category,Name,User,State,
            Command,Location,Indicators
}

Write-Host "`nNo tasks, registry values, services, or files were modified."