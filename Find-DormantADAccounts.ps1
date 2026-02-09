<#
.SYNOPSIS
    Queries Active Directory for dormant user accounts within a specified OU.

.DESCRIPTION
    This script discovers dormant accounts directly from AD based on lastLogonTimestamp
    and can generate an input file for Disable-DormantADAccounts.ps1. Outputs results
    to console and optionally exports to CSV report and/or target file.

.PARAMETER SearchBase
    Distinguished Name of the OU to search for dormant accounts.

.PARAMETER DormantDays
    Number of days of inactivity to consider an account dormant.

.PARAMETER OutputFile
    Path to generate a target file containing only SamAccountNames (one per line).
    This file can be used as input for Disable-DormantADAccounts.ps1.

.PARAMETER ReportPath
    Path for full CSV report output. Defaults to ./DormantAccountDiscovery_<timestamp>.csv

.PARAMETER IncludeNeverLoggedIn
    Include accounts that have never logged in (null lastLogonTimestamp).

.PARAMETER Help
    Display help information.

.EXAMPLE
    .\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90

.EXAMPLE
    .\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -OutputFile "targets.txt"

.EXAMPLE
    .\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -IncludeNeverLoggedIn
#>

[CmdletBinding(DefaultParameterSetName = 'Help')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$DormantDays,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNeverLoggedIn,

    [Parameter(ParameterSetName = 'Help')]
    [Alias('h', '?')]
    [switch]$Help
)

#Requires -Modules ActiveDirectory

# Show help if no arguments provided or -Help specified
if ($PSCmdlet.ParameterSetName -eq 'Help' -or $Help) {
    $helpText = @"
Find-DormantADAccounts.ps1

SYNOPSIS
    Queries Active Directory for dormant user accounts within a specified OU.

DESCRIPTION
    This script discovers dormant accounts directly from AD based on lastLogonTimestamp
    and can generate an input file for Disable-DormantADAccounts.ps1. Outputs results
    to console and optionally exports to CSV report and/or target file.

PARAMETERS
    -SearchBase <string>         Distinguished Name of OU to search
    -DormantDays <int>           Days of inactivity to consider dormant
    -OutputFile <string>         Path to generate target file (SamAccountNames only)
    -ReportPath <string>         Path for full CSV report (optional)
    -IncludeNeverLoggedIn        Include accounts that never logged in
    -Help, -h, -?                Display this help message

EXAMPLES
    # Find dormant accounts in OU
    .\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90

    # Generate target file for Disable-DormantADAccounts
    .\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -OutputFile "targets.txt"

    # Include never-logged-in accounts
    .\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -IncludeNeverLoggedIn

OUTPUT COLUMNS
    SamAccountName   - Account login name
    DisplayName      - User display name
    Created          - Account creation date (whenCreated)
    PasswordLastSet  - Last password change date
    Description      - Account description
    LastLogonDate    - Last logon timestamp
    DaysInactive     - Days since last logon
"@
    Write-Host $helpText
    exit 0
}

# ============================================================================
# Functions
# ============================================================================

function Test-DomainControllerHealth {
    <#
    .SYNOPSIS
        Verifies connectivity to Active Directory before processing.
    #>
    try {
        $null = Get-ADDomainController -Discover -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ============================================================================
# Main Script
# ============================================================================

# Set default report path if not provided
if (-not $ReportPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path -Path (Get-Location) -ChildPath "DormantAccountDiscovery_$timestamp.csv"
}

# DC health check
Write-Host "Checking domain controller connectivity..." -ForegroundColor Cyan
if (-not (Test-DomainControllerHealth)) {
    Write-Error "Cannot connect to Active Directory. Please verify network connectivity and domain controller availability."
    exit 1
}
Write-Host "Domain controller connection verified." -ForegroundColor Green

# Validate SearchBase OU exists
try {
    $null = Get-ADOrganizationalUnit -Identity $SearchBase -ErrorAction Stop
} catch {
    Write-Error "SearchBase OU not found or inaccessible: $SearchBase"
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD Dormant Account Discovery" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Search Base:         $SearchBase"
Write-Host "Dormant Days:        $DormantDays"
Write-Host "Include Never Login: $(if ($IncludeNeverLoggedIn) { 'Yes' } else { 'No' })"
Write-Host "Report Path:         $ReportPath"
if ($OutputFile) {
    Write-Host "Output File:         $OutputFile"
}
Write-Host "========================================`n"

# Query AD for enabled accounts
Write-Host "Querying Active Directory..." -ForegroundColor Cyan
try {
    $allAccounts = Get-ADUser -SearchBase $SearchBase -Filter { Enabled -eq $true } `
        -Properties whenCreated, PasswordLastSet, Description, lastLogonTimestamp -ErrorAction Stop
} catch {
    Write-Error "Failed to query Active Directory: $_"
    exit 1
}

if ($allAccounts.Count -eq 0) {
    Write-Warning "No enabled accounts found in SearchBase."
    exit 0
}

Write-Host "Found $($allAccounts.Count) enabled accounts. Analyzing..." -ForegroundColor Cyan

# Calculate dormancy threshold date
$thresholdDate = (Get-Date).AddDays(-$DormantDays)

# Process accounts and filter for dormant
$results = @()
$dormantCount = 0
$neverLoggedInCount = 0

foreach ($account in $allAccounts) {
    $lastLogonDate = $null
    $daysInactive = $null
    $isDormant = $false

    if ($account.lastLogonTimestamp) {
        $lastLogonDate = [DateTime]::FromFileTime($account.lastLogonTimestamp)
        $daysInactive = (Get-Date).Subtract($lastLogonDate).Days

        if ($daysInactive -gt $DormantDays) {
            $isDormant = $true
            $dormantCount++
        }
    } else {
        # Account has never logged in - only flag if created before threshold
        $createdDate = $account.whenCreated
        if ($createdDate -and $createdDate -lt $thresholdDate) {
            $neverLoggedInCount++
            if ($IncludeNeverLoggedIn) {
                $isDormant = $true
            }
        }
        # Skip accounts created within dormancy period - too new to evaluate
    }

    if ($isDormant) {
        $results += [PSCustomObject]@{
            SamAccountName  = $account.SamAccountName
            DisplayName     = $account.DisplayName
            Created         = if ($account.whenCreated) { $account.whenCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
            PasswordLastSet = if ($account.PasswordLastSet) { $account.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
            Description     = $account.Description
            LastLogonDate   = if ($lastLogonDate) { $lastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            DaysInactive    = if ($null -ne $daysInactive) { $daysInactive } else { "N/A" }
        }
    }
}

# Display results
Write-Host "`n----------------------------------------" -ForegroundColor Cyan
Write-Host "         Dormant Accounts Found" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan

if ($results.Count -eq 0) {
    Write-Host "No dormant accounts found matching criteria." -ForegroundColor Green
} else {
    # Display table to console
    $results | Format-Table -Property SamAccountName, DisplayName, @{Name='Description'; Expression={if ($_.Description -and $_.Description.Length -gt 50) { $_.Description.Substring(0,47) + '...' } else { $_.Description }}}, LastLogonDate, DaysInactive -AutoSize

    # Color-coded summary
    foreach ($result in $results) {
        if ($result.LastLogonDate -eq "Never") {
            Write-Host "[NEVER]   $($result.SamAccountName) - $($result.DisplayName)" -ForegroundColor Yellow
        } else {
            Write-Host "[DORMANT] $($result.SamAccountName) - Inactive $($result.DaysInactive) days" -ForegroundColor Red
        }
    }
}

# Export full report
$results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host "`nFull report saved to: $ReportPath" -ForegroundColor Green

# Generate target file if specified
if ($OutputFile) {
    $results | Select-Object -ExpandProperty SamAccountName | Set-Content -Path $OutputFile -Encoding UTF8
    Write-Host "Target file saved to: $OutputFile" -ForegroundColor Green
    Write-Host "Use with: .\Disable-DormantADAccounts.ps1 -InputFile `"$OutputFile`" -DormantDays $DormantDays -TargetOU `"<OU>`"" -ForegroundColor Cyan
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "              Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total enabled accounts:      $($allAccounts.Count)"
Write-Host "Dormant (>$DormantDays days):         $dormantCount" -ForegroundColor Red
Write-Host "Never logged in:             $neverLoggedInCount" -ForegroundColor Yellow
if ($IncludeNeverLoggedIn) {
    Write-Host "Total identified:            $($results.Count)" -ForegroundColor Red
} else {
    Write-Host "Total identified:            $($results.Count)" -ForegroundColor Red
    if ($neverLoggedInCount -gt 0) {
        Write-Host "(Use -IncludeNeverLoggedIn to include never-logged-in accounts)" -ForegroundColor Gray
    }
}
Write-Host "========================================`n"
