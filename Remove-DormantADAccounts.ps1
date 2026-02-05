<#
.SYNOPSIS
    Processes a list of AD accounts, validates dormancy, and disables/moves confirmed dormant accounts.

.DESCRIPTION
    This script reads a list of account names from a text file, checks each account's
    lastLogonTimestamp to determine dormancy status, and optionally disables and moves
    dormant accounts to a designated OU.

.PARAMETER InputFile
    Path to a text file containing account names (one per line).

.PARAMETER DormantDays
    Number of days of inactivity to consider an account dormant.

.PARAMETER TargetOU
    Distinguished Name of the OU to move disabled accounts to.

.PARAMETER ReportPath
    Path for CSV report output. Defaults to ./DormantAccountReport_<timestamp>.csv

.PARAMETER WhatIf
    Preview actions without making changes.

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -WhatIf

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$DormantDays,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOU,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath
)

#Requires -Modules ActiveDirectory

function Get-AccountDormancyStatus {
    <#
    .SYNOPSIS
        Retrieves dormancy status for an AD account.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [int]$ThresholdDays
    )

    $result = [PSCustomObject]@{
        SamAccountName = $SamAccountName
        DisplayName    = $null
        LastLogonDate  = $null
        DaysInactive   = $null
        Status         = $null
        OriginalOU     = $null
        Enabled        = $null
    }

    try {
        $account = Get-ADUser -Identity $SamAccountName -Properties lastLogonTimestamp, DisplayName, Enabled, DistinguishedName -ErrorAction Stop

        $result.DisplayName = $account.DisplayName
        $result.Enabled = $account.Enabled

        # Extract OU from DistinguishedName (remove the CN=username, part)
        $dnParts = $account.DistinguishedName -split ',', 2
        if ($dnParts.Count -gt 1) {
            $result.OriginalOU = $dnParts[1]
        } else {
            $result.OriginalOU = $account.DistinguishedName
        }

        if ($account.lastLogonTimestamp) {
            $lastLogon = [DateTime]::FromFileTime($account.lastLogonTimestamp)
            $result.LastLogonDate = $lastLogon
            $result.DaysInactive = (Get-Date).Subtract($lastLogon).Days

            if ($result.DaysInactive -gt $ThresholdDays) {
                $result.Status = "DORMANT"
            } else {
                $result.Status = "ACTIVE"
            }
        } else {
            # Account has never logged in
            $result.Status = "NEVER_LOGGED_IN"
            $result.DaysInactive = $null
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $result.Status = "NOT_FOUND"
    }
    catch {
        Write-Warning "Error retrieving account '$SamAccountName': $_"
        $result.Status = "ERROR"
    }

    return $result
}

# Set default report path if not provided
if (-not $ReportPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path -Path (Get-Location) -ChildPath "DormantAccountReport_$timestamp.csv"
}

# Validate input file exists
if (-not (Test-Path -Path $InputFile -PathType Leaf)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}

# Validate target OU exists
try {
    $null = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop
} catch {
    Write-Error "Target OU not found or inaccessible: $TargetOU"
    exit 1
}

# Read account list
$accounts = Get-Content -Path $InputFile | Where-Object { $_.Trim() -ne '' }

if ($accounts.Count -eq 0) {
    Write-Warning "No accounts found in input file."
    exit 0
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD Dormant Account Cleanup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Input File:    $InputFile"
Write-Host "Dormant Days:  $DormantDays"
Write-Host "Target OU:     $TargetOU"
Write-Host "Report Path:   $ReportPath"
Write-Host "Mode:          $(if ($WhatIfPreference) { 'WhatIf (Preview)' } else { 'Execute' })"
Write-Host "Accounts:      $($accounts.Count)"
Write-Host "========================================`n"

$results = @()
$counters = @{
    Active       = 0
    Dormant      = 0
    NeverLoggedIn = 0
    NotFound     = 0
    Errors       = 0
}

foreach ($accountName in $accounts) {
    $accountName = $accountName.Trim()

    # Get dormancy status
    $status = Get-AccountDormancyStatus -SamAccountName $accountName -ThresholdDays $DormantDays

    $resultEntry = [PSCustomObject]@{
        SamAccountName = $status.SamAccountName
        DisplayName    = $status.DisplayName
        LastLogonDate  = if ($status.LastLogonDate) { $status.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
        DaysInactive   = $status.DaysInactive
        Status         = $status.Status
        Action         = $null
        OriginalOU     = $status.OriginalOU
        NewOU          = $null
        Timestamp      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }

    switch ($status.Status) {
        "ACTIVE" {
            $counters.Active++
            $resultEntry.Action = "SKIPPED"
            Write-Host "[ACTIVE]    $accountName - Last login: $($status.DaysInactive) days ago" -ForegroundColor Green
        }
        "DORMANT" {
            $counters.Dormant++
            if ($WhatIfPreference) {
                $resultEntry.Action = "WHATIF"
                $resultEntry.NewOU = $TargetOU
                Write-Host "[WHATIF]    $accountName - Would disable and move (inactive $($status.DaysInactive) days)" -ForegroundColor Yellow
            } else {
                try {
                    # Disable the account
                    Disable-ADAccount -Identity $accountName -ErrorAction Stop

                    # Move to target OU
                    $userDN = (Get-ADUser -Identity $accountName).DistinguishedName
                    Move-ADObject -Identity $userDN -TargetPath $TargetOU -ErrorAction Stop

                    $resultEntry.Action = "DISABLED_AND_MOVED"
                    $resultEntry.NewOU = $TargetOU
                    Write-Host "[DORMANT]   $accountName - Disabled and moved (inactive $($status.DaysInactive) days)" -ForegroundColor Red
                } catch {
                    $resultEntry.Action = "ERROR: $_"
                    $counters.Errors++
                    Write-Host "[ERROR]     $accountName - Failed to process: $_" -ForegroundColor Magenta
                }
            }
        }
        "NEVER_LOGGED_IN" {
            $counters.NeverLoggedIn++
            if ($WhatIfPreference) {
                $resultEntry.Action = "WHATIF"
                $resultEntry.NewOU = $TargetOU
                Write-Host "[WHATIF]    $accountName - Would disable and move (never logged in)" -ForegroundColor Yellow
            } else {
                try {
                    # Disable the account
                    Disable-ADAccount -Identity $accountName -ErrorAction Stop

                    # Move to target OU
                    $userDN = (Get-ADUser -Identity $accountName).DistinguishedName
                    Move-ADObject -Identity $userDN -TargetPath $TargetOU -ErrorAction Stop

                    $resultEntry.Action = "DISABLED_AND_MOVED"
                    $resultEntry.NewOU = $TargetOU
                    Write-Host "[DORMANT]   $accountName - Disabled and moved (never logged in)" -ForegroundColor Red
                } catch {
                    $resultEntry.Action = "ERROR: $_"
                    $counters.Errors++
                    Write-Host "[ERROR]     $accountName - Failed to process: $_" -ForegroundColor Magenta
                }
            }
        }
        "NOT_FOUND" {
            $counters.NotFound++
            $resultEntry.Action = "SKIPPED"
            Write-Host "[NOT FOUND] $accountName - Account does not exist in AD" -ForegroundColor Gray
        }
        default {
            $counters.Errors++
            $resultEntry.Action = "SKIPPED"
            Write-Host "[ERROR]     $accountName - $($status.Status)" -ForegroundColor Magenta
        }
    }

    $results += $resultEntry
}

# Export report
$results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

# Summary
Write-Host "`n========================================"  -ForegroundColor Cyan
Write-Host "              Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Active accounts (skipped):   $($counters.Active)" -ForegroundColor Green
Write-Host "Dormant accounts:            $($counters.Dormant)" -ForegroundColor Red
Write-Host "Never logged in:             $($counters.NeverLoggedIn)" -ForegroundColor Red
Write-Host "Not found:                   $($counters.NotFound)" -ForegroundColor Gray
Write-Host "Errors:                      $($counters.Errors)" -ForegroundColor Magenta
Write-Host "----------------------------------------"
Write-Host "Total processed:             $($accounts.Count)"
Write-Host "Report saved to:             $ReportPath"
Write-Host "========================================`n"
