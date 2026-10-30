# IRSeC 2026 - Windows Account Checker
# Read-only: does not modify accounts.

param(
    [ValidateSet("Domain","Local")]
    [string]$Scope = "Local"
)

$DomainApproved = @(
    "principal","sportingdir","chiefeng","strategist",
    "pitcrew","mechanic","analyst","driver",
    "tireman","fuelman"
)

$LocalApproved = @(
    "scrutineer","techdirector","crewchief","firecrew",
    "jackcrew","garagecrew","celebrity",
    "pitlaner","reserve","gunners"
)

$Protected = @(
    "whiteteam","krbtgt","Administrator","Guest",
    "DefaultAccount","WDAGUtilityAccount",
    "dd-agent","ddagentuser"
)

# Built-in Windows account RIDs.
$ProtectedRIDs = @(500,501,502,503,504)

$ErrorActionPreference = "Stop"

if ($Scope -eq "Domain") {

    Import-Module ActiveDirectory

    $Approved = $DomainApproved

    $Users = Get-ADUser -Filter * -Properties Enabled,SID |
        Select-Object SamAccountName,Enabled,SID

}
else {

    Import-Module Microsoft.PowerShell.LocalAccounts

    $Approved = $LocalApproved

    $Users = Get-LocalUser |
        Select-Object @{
            Name="SamAccountName"
            Expression={$_.Name}
        },Enabled,SID
}

$Results = foreach ($User in $Users) {

    $Name = $User.SamAccountName
    $RID = [int](($User.SID.Value -split "-")[-1])

    $Status = if (
        $Name -in $Protected -or
        $RID -in $ProtectedRIDs
    ) {
        "PROTECTED"
    }
    elseif ($Name -in $Approved) {
        "APPROVED"
    }
    else {
        "INVESTIGATE"
    }

    [PSCustomObject]@{
        Account = $Name
        Enabled = $User.Enabled
        Status = $Status
    }
}

Write-Host "`n=== ACCOUNT CHECK ===" -ForegroundColor Cyan

$Results |
    Sort-Object Status,Account |
    Format-Table -AutoSize

$Suspicious = @(
    $Results | Where-Object Status -eq "INVESTIGATE"
)

Write-Host "`n=== UNRECOGNIZED ACCOUNTS ===" -ForegroundColor Yellow

if ($Suspicious.Count -gt 0) {
    $Suspicious | Format-Table -AutoSize
}
else {
    Write-Host "No unrecognized accounts found."
}

Write-Host "`nNo accounts were modified."