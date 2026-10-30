# ============================================================
# IRSeC 2026 - DOMAIN PASSWORD ROTATOR
# File: Rotate-DomainPasswords.ps1
#
# Target: pitwall (Windows Server 2025 AD/DNS)
# ONLY RAN ON AD BOX
#
# Features:
# - Rotate ONE, SELECTED, ALL, or NON-ADMIN accounts
# - Include current logged-in account (rotated LAST)
# - Unique or shared passwords
# - Double password confirmation
# - Protect critical and unapproved accounts
# - Validate account identities before changing passwords
# - Stop batch on failure
# ============================================================

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

$ErrorActionPreference = "Stop"

# ============================================================
# 1. APPROVED DOMAIN ACCOUNTS
# ============================================================

$AdminAccounts = @(
    "principal",
    "sportingdir",
    "chiefeng",
    "strategist"
)

$RegularAccounts = @(
    "pitcrew",
    "mechanic",
    "analyst",
    "driver",
    "tireman",
    "fuelman"
)

$AllowedAccounts = @($AdminAccounts) + @($RegularAccounts)

# Explicitly protected accounts.
$ProtectedAccounts = @(
    "whiteteam",
    "krbtgt",
    "Administrator",
    "Guest",
    "dd-agent",
    "ddagentuser"
)

# ============================================================
# 2. PASSWORD CONFIRMATION FUNCTION
# ============================================================

function Get-ConfirmedPassword {
    param(
        [Parameter(Mandatory)]
        [string]$Username
    )

    while ($true) {

        Write-Host ""
        Write-Host "Setting password for: $Username" `
            -ForegroundColor Cyan

        $First = Read-Host "Enter new password" -AsSecureString
        $Second = Read-Host "Confirm new password" -AsSecureString

        try {
            $P1 = [PSCredential]::new(
                "temp", $First
            ).GetNetworkCredential().Password

            $P2 = [PSCredential]::new(
                "temp", $Second
            ).GetNetworkCredential().Password

            $Match = (
                $P1.Length -gt 0 -and
                $P1 -ceq $P2
            )
        }
        finally {
            $P1 = $null
            $P2 = $null
            $Second.Dispose()
        }

        if ($Match) {
            Write-Host "[+] Password confirmed." `
                -ForegroundColor Green

            return $First
        }

        $First.Dispose()

        Write-Warning "Passwords do not match or are empty."
    }
}

# ============================================================
# 3. VERIFY DOMAIN CONTROLLER
# ============================================================

try {

    Import-Module ActiveDirectory -ErrorAction Stop

    $Computer = Get-CimInstance Win32_ComputerSystem

    if ($Computer.DomainRole -notin @(4, 5)) {
        throw "This machine is not a domain controller."
    }

    $ADDomain = Get-ADDomain -ErrorAction Stop

    $Domain = $ADDomain.DNSRoot
    $DC = $env:COMPUTERNAME

    Write-Host ""
    Write-Host "[+] Connected to domain: $Domain" `
        -ForegroundColor Green

    Write-Host "[+] Domain Controller: $DC"

}
catch {

    Write-Host "[ERROR] AD initialization failed." `
        -ForegroundColor Red

    Write-Host $_.Exception.Message
    return
}

# ============================================================
# 4. DETECT LOCAL SERVICE ACCOUNT DEPENDENCIES
# ============================================================

$ServiceAccounts = @(
    Get-CimInstance Win32_Service |
    ForEach-Object {

        $Name = [string]$_.StartName

        if ($Name) {
            ($Name -split '\\')[-1].TrimEnd('$')
        }

    } |
    Where-Object { $_ } |
    Sort-Object -Unique
)

# ============================================================
# 5. ACCOUNT SELECTION MENU
# ============================================================

Write-Host ""
Write-Host "========================================"
Write-Host "      IRSeC DOMAIN PASSWORD ROTATOR"
Write-Host "========================================"
Write-Host ""
Write-Host "Approved Administrators:"
Write-Host ($AdminAccounts -join ", ")
Write-Host ""
Write-Host "Approved Regular Users:"
Write-Host ($RegularAccounts -join ", ")
Write-Host ""
Write-Host "[1] Rotate ONE account"
Write-Host "[2] Rotate SELECTED accounts"
Write-Host "[3] Rotate ALL approved accounts"
Write-Host "[4] Rotate ALL regular accounts"
Write-Host "[5] Exit"
Write-Host ""

$Choice = Read-Host "Choose an option"

$Targets = @()

switch ($Choice) {

    "1" {

        $Name = (Read-Host "Enter username").Trim()

        $Targets = @($Name)
    }

    "2" {

        $InputNames = Read-Host "Enter usernames separated by commas"

        $Targets = @(
            $InputNames -split "," |
            ForEach-Object { $_.Trim() }
        )
    }

    "3" {

        $Targets = @($AllowedAccounts)
    }

    "4" {

        $Targets = @($RegularAccounts)
    }

    "5" {

        Write-Host "Exiting."
        return
    }

    default {

        Write-Host "[ERROR] Invalid option."
        return
    }
}

# ============================================================
# 6. VALIDATE ACCOUNT SELECTION
# ============================================================

if ($Targets.Count -eq 0) {
    throw "No accounts selected."
}

if (@($Targets | Where-Object { -not $_ }).Count -gt 0) {
    throw "Empty usernames are not allowed."
}

if (
    @($Targets | Sort-Object -Unique).Count -ne
    $Targets.Count
) {
    throw "Duplicate usernames selected."
}

foreach ($Name in $Targets) {

    if ($Name -notin $AllowedAccounts) {
        throw "Unapproved account: $Name"
    }

    if ($Name -in $ProtectedAccounts) {
        throw "Protected account: $Name"
    }
}

# ============================================================
# 7. VALIDATE ACTIVE DIRECTORY USERS
# ============================================================

$Validated = @()

foreach ($Name in $Targets) {

    try {

        $User = Get-ADUser `
            -Identity $Name `
            -Server $DC `
            -Properties Enabled, ServicePrincipalName `
            -ErrorAction Stop

        if ($User.SamAccountName -ine $Name) {
            throw "Account identity mismatch."
        }

        if (-not $User.Enabled) {
            throw "Account is disabled."
        }

        $SPNs = @(
            $User.ServicePrincipalName |
            Where-Object { $_ }
        )

        if ($SPNs.Count -gt 0) {
            throw "Account has service principal names."
        }

        if ($Name -in $ServiceAccounts) {
            throw "Account is used by a Windows service."
        }

        $Role = if ($Name -in $AdminAccounts) {
            "Admin"
        }
        else {
            "Regular"
        }

        $Validated += [PSCustomObject]@{
            Username = $User.SamAccountName
            DN       = $User.DistinguishedName
            SID      = $User.SID.Value
            Role     = $Role
        }

    }
    catch {

        Write-Host "[ERROR] Validation failed: $Name" `
            -ForegroundColor Red

        Write-Host $_.Exception.Message
        return
    }
}

# ============================================================
# 8. MOVE CURRENT LOGIN ACCOUNT TO THE END
# ============================================================

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

$CurrentSID = $CurrentIdentity.User.Value
$CurrentUsername = ($CurrentIdentity.Name -split '\\')[-1]

$CurrentSelected = @(
    $Validated |
    Where-Object { $_.SID -eq $CurrentSID }
)

if ($CurrentSelected.Count -gt 0) {

    $OtherAccounts = @(
        $Validated |
        Where-Object { $_.SID -ne $CurrentSID }
    )

    $Validated = @($OtherAccounts) + @($CurrentSelected)
}

# ============================================================
# 9. ROTATION PREVIEW
# ============================================================

Write-Host ""
Write-Host "========================================"
Write-Host "           ROTATION PREVIEW"
Write-Host "========================================"

$Validated |
Select-Object Username, Role |
Format-Table -AutoSize

Write-Host "Domain: $Domain"
Write-Host "Selected Accounts: $($Validated.Count)"
Write-Host ""

$Expected = "ROTATE $($Validated.Count)"

$Confirmation = Read-Host "Type '$Expected' to continue"

if ($Confirmation -cne $Expected) {

    Write-Host "Cancelled."
    return
}

# ============================================================
# 10. ADMINISTRATOR CONFIRMATION
# ============================================================

$SelectedAdmins = @(
    $Validated |
    Where-Object { $_.Role -eq "Admin" }
)

if ($SelectedAdmins.Count -gt 0) {

    Write-Warning "Administrative accounts are selected!"

    $AdminConfirmation = Read-Host "Type ADMINS to continue"

    if ($AdminConfirmation -cne "ADMINS") {

        Write-Host "Cancelled."
        return
    }
}

# ============================================================
# 11. CURRENT ACCOUNT CONFIRMATION
# ============================================================

if ($CurrentSelected.Count -gt 0) {

    Write-Warning "The account running this script is selected."
    Write-Host "Current account: $CurrentUsername"
    Write-Host "It WILL be rotated LAST."
    Write-Host "Future authentication requires the new password."

    $CurrentConfirmation = Read-Host "Type CURRENT to continue"

    if ($CurrentConfirmation -cne "CURRENT") {

        Write-Host "Cancelled."
        return
    }
}

# ============================================================
# 12. PASSWORD MODE
# ============================================================

Write-Host ""
Write-Host "========================================"
Write-Host "            PASSWORD MODE"
Write-Host "========================================"
Write-Host ""
Write-Host "[1] UNIQUE password for each account"
Write-Host "[2] SHARED password for all selected accounts"
Write-Host "[3] Cancel"

$Mode = Read-Host "Choose mode"

if ($Mode -notin @("1", "2")) {

    Write-Host "Cancelled."
    return
}

if ($Mode -eq "2" -and $Validated.Count -gt 1) {

    Write-Warning "All selected users will share the same password."

    $SharedConfirmation = Read-Host "Type SHARED to continue"

    if ($SharedConfirmation -cne "SHARED") {

        Write-Host "Cancelled."
        return
    }
}

# ============================================================
# 13. COLLECT PASSWORDS BEFORE MAKING CHANGES
# ============================================================

$Assignments = @()
$SharedPassword = $null
$Results = @()

try {

    if ($Mode -eq "2") {

        $SharedPassword = Get-ConfirmedPassword `
            -Username "ALL SELECTED ACCOUNTS"
    }

    foreach ($Account in $Validated) {

        if ($Mode -eq "2") {

            $Password = $SharedPassword
        }
        else {

            $Password = Get-ConfirmedPassword `
                -Username $Account.Username
        }

        $Assignments += [PSCustomObject]@{
            Account  = $Account
            Password = $Password
        }
    }

    # ========================================================
    # 14. EXECUTE PASSWORD ROTATION
    # ========================================================

    Write-Host ""
    Write-Host "========================================"
    Write-Host "          ROTATING PASSWORDS"
    Write-Host "========================================"

    foreach ($Item in $Assignments) {

        $Account = $Item.Account

        try {

            # Revalidate the account before resetting.
            $Fresh = Get-ADUser `
                -Identity $Account.DN `
                -Server $DC `
                -Properties Enabled, ServicePrincipalName `
                -ErrorAction Stop

            $FreshSPNs = @(
                $Fresh.ServicePrincipalName |
                Where-Object { $_ }
            )

            if (
                $Fresh.SID.Value -ne $Account.SID -or
                $Fresh.SamAccountName -notin $AllowedAccounts -or
                $Fresh.SamAccountName -in $ProtectedAccounts -or
                $Fresh.SamAccountName -in $ServiceAccounts -or
                -not $Fresh.Enabled -or
                $FreshSPNs.Count -gt 0
            ) {
                throw "Account failed final safety validation."
            }

            Set-ADAccountPassword `
                -Identity $Fresh.DistinguishedName `
                -Server $DC `
                -Reset `
                -NewPassword $Item.Password `
                -Confirm:$false `
                -ErrorAction Stop

            Write-Host "[SUCCESS] $($Account.Username)" `
                -ForegroundColor Green

            $Results += [PSCustomObject]@{
                Username = $Account.Username
                Status   = "SUCCESS"
            }

        }
        catch {

            Write-Host "[ERROR] $($Account.Username)" `
                -ForegroundColor Red

            Write-Host $_.Exception.Message

            $Results += [PSCustomObject]@{
                Username = $Account.Username
                Status   = "FAILED OR UNCERTAIN"
            }

            Write-Warning "Stopping remaining password rotations."
            break
        }
    }
}
finally {

    # ========================================================
    # 15. CLEAN UP PASSWORD OBJECTS
    # ========================================================

    if ($null -ne $SharedPassword) {

        $SharedPassword.Dispose()
    }
    else {

        foreach ($Item in $Assignments) {

            if ($null -ne $Item.Password) {
                $Item.Password.Dispose()
            }
        }
    }

    $Assignments = @()
}

# ============================================================
# 16. FINAL RESULTS
# ============================================================

Write-Host ""
Write-Host "========================================"
Write-Host "           ROTATION SUMMARY"
Write-Host "========================================"

$Results | Format-Table -AutoSize

$SuccessCount = @(
    $Results |
    Where-Object { $_.Status -eq "SUCCESS" }
).Count

Write-Host "Successful: $SuccessCount"
Write-Host "Processed: $($Results.Count)"
Write-Host "Selected: $($Validated.Count)"

if ($Results.Count -lt $Validated.Count) {
    Write-Warning "Some selected accounts were not attempted."
}

Write-Host ""
Write-Host "Verify domain authentication using the new passwords."
Write-Host "Rotation completed."