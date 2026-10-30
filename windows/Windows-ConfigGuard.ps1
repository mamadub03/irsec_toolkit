# ============================================================
# IRSeC 2026 - WINDOWS SERVICE CONFIGURATION GUARD
# File: Windows-ConfigGuard.ps1
#
# Supported services:
#   - Telnet (safetycar)
#   - IIS    (stewards)
#
# Actions:
#   Backup  - Save configuration files and hashes
#   Compare - Detect additions, deletions, modifications
#   Restore - Selectively restore a backed-up file
#
# Run in elevated Windows PowerShell 5.1.
# ============================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Telnet", "IIS")]
    [string]$Service,

    [Parameter(Mandatory)]
    [ValidateSet("Backup", "Compare", "Restore")]
    [string]$Action
)

$ErrorActionPreference = "Stop"

$BackupRoot = "C:\ProgramData\IRSeC-Blue\Backups"
$BackupDir = Join-Path $BackupRoot $Service
$FilesDir = Join-Path $BackupDir "Files"
$ManifestPath = Join-Path $BackupDir "manifest.json"

# ============================================================
# 1. DISCOVER SERVICE CONFIGURATION FILES
# ============================================================

function Get-ConfigFiles {

    $Files = @()

    if ($Service -eq "Telnet") {

        # Common Cygwin Telnet/inetd locations.
        $Candidates = @(
            "C:\cygwin64\etc\inetd.conf",
            "C:\cygwin\etc\inetd.conf",
            "C:\cygwin64\etc\services",
            "C:\cygwin\etc\services"
        )

        foreach ($Path in $Candidates) {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                $Files += $Path
            }
        }
    }

    if ($Service -eq "IIS") {

        Import-Module WebAdministration -ErrorAction Stop

        # Main IIS server configuration.
        $MainConfig = Join-Path $env:windir `
            "System32\inetsrv\config\applicationHost.config"

        if (Test-Path -LiteralPath $MainConfig) {
            $Files += $MainConfig
        }

        # Discover web.config files under registered IIS site roots.
        $Sites = @(Get-Website)

        foreach ($Site in $Sites) {

            $PhysicalPath = [Environment]::ExpandEnvironmentVariables(
                [string]$Site.PhysicalPath
            )

            if (-not (Test-Path -LiteralPath $PhysicalPath `
                    -PathType Container)) {
                continue
            }

            $WebConfigs = @(
                Get-ChildItem -LiteralPath $PhysicalPath `
                    -Filter "web.config" `
                    -File -Recurse `
                    -ErrorAction Stop
            )

            foreach ($Config in $WebConfigs) {
                $Files += $Config.FullName
            }
        }
    }

    @($Files | Sort-Object -Unique)
}

# ============================================================
# 2. FILE HASH / SAFETY HELPERS
# ============================================================

function Get-ConfigHash {
    param([string]$Path)

    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Assert-RegularFile {
    param([string]$Path)

    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

    if ($Item.PSIsContainer -or
        ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe configuration file type: $Path"
    }
}

function Show-FileDiff {
    param(
        [string]$Original,
        [string]$Current
    )

    $OldLines = @(Get-Content -LiteralPath $Original)
    $NewLines = @(Get-Content -LiteralPath $Current)

    $Differences = @(
        Compare-Object `
            -ReferenceObject $OldLines `
            -DifferenceObject $NewLines
    )

    if ($Differences.Count -eq 0) {
        Write-Host "No line-level differences displayed."
        return
    }

    foreach ($Difference in $Differences) {

        if ($Difference.SideIndicator -eq "<=") {
            Write-Host "- $($Difference.InputObject)" `
                -ForegroundColor Red
        }
        elseif ($Difference.SideIndicator -eq "=>") {
            Write-Host "+ $($Difference.InputObject)" `
                -ForegroundColor Green
        }
    }
}

# ============================================================
# 3. BACKUP
# ============================================================

if ($Action -eq "Backup") {

    if (Test-Path -LiteralPath $BackupDir) {
        throw "Backup already exists: $BackupDir"
    }

    $ConfigFiles = @(Get-ConfigFiles)

    if ($ConfigFiles.Count -eq 0) {
        throw "No configuration files found for $Service."
    }

    New-Item -Path $FilesDir -ItemType Directory -Force |
        Out-Null

    # Restrict backup-directory access.
    & icacls.exe $BackupDir /inheritance:r `
        /grant:r "*S-1-5-18:(OI)(CI)F" `
                 "*S-1-5-32-544:(OI)(CI)F" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict backup directory permissions."
    }

    $Records = @()

    for ($i = 0; $i -lt $ConfigFiles.Count; $i++) {

        $Path = $ConfigFiles[$i]
        Assert-RegularFile $Path

        $SavedName = "$i.bak"
        $SavedPath = Join-Path $FilesDir $SavedName

        Copy-Item -LiteralPath $Path `
            -Destination $SavedPath `
            -ErrorAction Stop

        $OriginalHash = Get-ConfigHash $Path
        $SavedHash = Get-ConfigHash $SavedPath

        if ($OriginalHash -ne $SavedHash) {
            throw "Backup hash verification failed: $Path"
        }

        $Records += [PSCustomObject]@{
            Path = $Path
            SavedName = $SavedName
            SHA256 = $OriginalHash
        }

        Write-Host "[BACKED UP] $Path" -ForegroundColor Green
    }

    $Manifest = [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        Service = $Service
        Created = (Get-Date).ToString("o")
        Files = @($Records)
    }

    $Manifest |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $ManifestPath

    Write-Host ""
    Write-Host "=== BACKUP COMPLETE ===" -ForegroundColor Cyan
    Write-Host "Service: $Service"
    Write-Host "Files: $($Records.Count)"
    Write-Host "Location: $BackupDir"

    Write-Warning "Verify the configuration is legitimate before trusting this backup."
    return
}

# ============================================================
# 4. LOAD EXISTING BACKUP
# ============================================================

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "No backup found. Run Backup first."
}

$Manifest = Get-Content -LiteralPath $ManifestPath -Raw |
    ConvertFrom-Json

if ($Manifest.Computer -ne $env:COMPUTERNAME -or
    $Manifest.Service -ne $Service) {
    throw "Backup does not match this host and service."
}

$Records = @($Manifest.Files)

# ============================================================
# 5. COMPARE
# ============================================================

if ($Action -eq "Compare") {

    Write-Host ""
    Write-Host "=== CONFIGURATION COMPARISON ===" `
        -ForegroundColor Cyan

    $Changes = 0

    foreach ($Record in $Records) {

        $Path = $Record.Path
        $SavedPath = Join-Path $FilesDir $Record.SavedName

        if (-not (Test-Path -LiteralPath $Path)) {

            Write-Host "[MISSING] $Path" -ForegroundColor Red
            $Changes++
            continue
        }

        Assert-RegularFile $Path

        $CurrentHash = Get-ConfigHash $Path

        if ($CurrentHash -ne $Record.SHA256) {

            Write-Host ""
            Write-Host "[MODIFIED] $Path" -ForegroundColor Yellow

            if (Test-Path -LiteralPath $SavedPath) {

                if ((Get-ConfigHash $SavedPath) -eq $Record.SHA256) {
                    Show-FileDiff `
                        -Original $SavedPath `
                        -Current $Path
                }
                else {
                    Write-Warning "Backup integrity check failed."
                }
            }

            $Changes++
        }
    }

    # Detect newly created configuration files.
    $KnownPaths = @($Records | ForEach-Object { $_.Path })

    foreach ($Path in @(Get-ConfigFiles)) {

        if ($Path -notin $KnownPaths) {
            Write-Host "[ADDED] $Path" -ForegroundColor Yellow
            $Changes++
        }
    }

    Write-Host ""
    Write-Host "=== COMPARISON SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Changes detected: $Changes"

    if ($Changes -eq 0) {
        Write-Host "[+] Configuration matches backup." `
            -ForegroundColor Green
    }

    Write-Host "No configuration was modified."
    return
}

# ============================================================
# 6. RESTORE
# ============================================================

if ($Action -eq "Restore") {

    $Changed = @()

    foreach ($Record in $Records) {

        $Path = $Record.Path

        if (-not (Test-Path -LiteralPath $Path)) {
            $Changed += $Record
            continue
        }

        Assert-RegularFile $Path

        if ((Get-ConfigHash $Path) -ne $Record.SHA256) {
            $Changed += $Record
        }
    }

    if ($Changed.Count -eq 0) {
        Write-Host "[+] No backed-up files need restoration."
        return
    }

    Write-Host ""
    Write-Host "=== CONFIGURATION RESTORE ===" `
        -ForegroundColor Cyan

    for ($i = 0; $i -lt $Changed.Count; $i++) {
        Write-Host "$($i + 1). $($Changed[$i].Path)"
    }

    $Selection = Read-Host "Enter the number of the file to restore"
    $Index = 0

    if (-not [int]::TryParse($Selection, [ref]$Index) -or
        $Index -lt 1 -or
        $Index -gt $Changed.Count) {
        throw "Invalid selection."
    }

    $Record = $Changed[$Index - 1]
    $Target = $Record.Path
    $Source = Join-Path $FilesDir $Record.SavedName

    Assert-RegularFile $Source

    if ((Get-ConfigHash $Source) -ne $Record.SHA256) {
        throw "Backup hash verification failed. Restore cancelled."
    }

    $Parent = Split-Path -Parent $Target

    if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
        throw "Target directory missing. Manual recovery required."
    }

    Write-Host ""
    Write-Host "Target: $Target" -ForegroundColor Yellow
    Write-Host "The current configuration will be saved for rollback."

    $Confirmation = Read-Host "Type RESTORE to confirm"

    if ($Confirmation -cne "RESTORE") {
        Write-Host "Cancelled."
        return
    }

    $RollbackDir = Join-Path $BackupDir "Rollback"

    if (-not (Test-Path -LiteralPath $RollbackDir)) {
        New-Item -Path $RollbackDir -ItemType Directory |
            Out-Null
    }

    if (Test-Path -LiteralPath $Target) {

        $RollbackName = "$(Get-Date -Format yyyyMMddHHmmss)-$($Record.SavedName)"

        Copy-Item -LiteralPath $Target `
            -Destination (Join-Path $RollbackDir $RollbackName) `
            -ErrorAction Stop
    }

    # Restore the configuration contents.
    Copy-Item -LiteralPath $Source `
        -Destination $Target -Force -ErrorAction Stop

    if ((Get-ConfigHash $Target) -ne $Record.SHA256) {
        throw "Restored file failed verification."
    }

    Write-Host ""
    Write-Host "[SUCCESS] Configuration restored." `
        -ForegroundColor Green

    Write-Host "Service: $Service"
    Write-Host "File: $Target"
    Write-Host ""
    Write-Host "The service was not restarted automatically."

    if ($Service -eq "Telnet") {
        Write-Host "Verify the Telnet listener and login prompt."
    }
    elseif ($Service -eq "IIS") {
        Write-Host "Verify IIS site bindings and HTTP functionality."
    }
}