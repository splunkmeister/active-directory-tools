<#
.SYNOPSIS
    Processes a list of AD accounts, validates dormancy, and disables/moves confirmed dormant accounts.

.DESCRIPTION
    This script reads a list of account names from a text file, checks each account's
    lastLogonTimestamp to determine dormancy status, and optionally disables and moves
    dormant accounts to a designated OU. Also supports rollback from a previous run's report.

.PARAMETER InputFile
    Path to a text file containing account names (one per line).

.PARAMETER DormantDays
    Number of days of inactivity to consider an account dormant.

.PARAMETER TargetOU
    Distinguished Name of the OU to move disabled accounts to.

.PARAMETER ReportPath
    Path for CSV report output. Defaults to ./DormantAccountReport_<timestamp>.csv

.PARAMETER Rollback
    Switch to enable rollback mode. Requires RollbackFile parameter.

.PARAMETER RollbackFile
    Path to a previous run's CSV report to use for rollback operations.

.PARAMETER MaxAccounts
    Maximum number of accounts to process before requiring -Force or switching to WhatIf mode.
    Defaults to 50.

.PARAMETER MaxConsecutiveFailures
    Stop processing if this many consecutive failures occur. Defaults to 5.

.PARAMETER Force
    Override the MaxAccounts safety limit and allow execution mode for large batches.

.PARAMETER Help
    Display help information.

.PARAMETER WhatIf
    Preview actions without making changes.

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=adkfoo,DC=com" -WhatIf

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=adkfoo,DC=com"

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -Rollback -RollbackFile "DormantAccountReport_20240115_120000.csv" -WhatIf

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -Rollback -RollbackFile "DormantAccountReport_20240115_120000.csv"

.EXAMPLE
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=adkfoo,DC=com" -MaxAccounts 100 -Force
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Help')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$DormantDays,

    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOU,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
    [switch]$Rollback,

    [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
    [ValidateNotNullOrEmpty()]
    [string]$RollbackFile,

    # Circuit breaker: max accounts before forcing dry run
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxAccounts = 50,

    # Circuit breaker: stop after N consecutive failures
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxConsecutiveFailures = 5,

    # Override for MaxAccounts safety limit
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    # Show help information
    [Parameter(ParameterSetName = 'Help')]
    [Alias('h', '?')]
    [switch]$Help
)

#Requires -Modules ActiveDirectory

# Show help if no arguments provided or -Help specified
if ($PSCmdlet.ParameterSetName -eq 'Help' -or $Help) {
    $helpText = @"
Remove-DormantADAccounts.ps1

SYNOPSIS
    Processes a list of AD accounts, validates dormancy, and disables/moves confirmed dormant accounts.

DESCRIPTION
    This script reads a list of account names from a text file, checks each account's
    lastLogonTimestamp to determine dormancy status, and optionally disables and moves
    dormant accounts to a designated OU. Also supports rollback from a previous run's report.

PARAMETERS
    -InputFile <string>        Path to text file with account names (one per line)
    -DormantDays <int>         Days of inactivity to consider an account dormant
    -TargetOU <string>         Distinguished Name of OU to move disabled accounts to
    -ReportPath <string>       Path for CSV report output (optional)
    -Rollback                  Enable rollback mode
    -RollbackFile <string>     Path to previous run's CSV report for rollback
    -MaxAccounts <int>         Max accounts before requiring -Force (default: 50)
    -MaxConsecutiveFailures    Stop after N consecutive failures (default: 5)
    -Force                     Override MaxAccounts safety limit
    -WhatIf                    Preview actions without making changes
    -Help, -h, -?              Display this help message

EXAMPLES
    # Preview dormant account cleanup
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -WhatIf

    # Execute cleanup
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com"

    # Rollback previous run
    .\Remove-DormantADAccounts.ps1 -Rollback -RollbackFile "DormantAccountReport_20240115_120000.csv"

    # Large batch with force
    .\Remove-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -MaxAccounts 100 -Force

CIRCUIT BREAKERS
    - DC Health Check: Verifies AD connectivity before processing
    - MaxAccounts Limit: Forces WhatIf mode for large batches unless -Force specified
    - Consecutive Failures: Stops after repeated errors to catch systemic issues
"@
    Write-Host $helpText
    exit 0
}

# ============================================================================
# Circuit Breaker Functions
# ============================================================================

function Test-DomainControllerHealth {
    <#
    .SYNOPSIS
        Verifies connectivity to Active Directory before processing.
    .DESCRIPTION
        Attempts a simple AD query to confirm the domain controller is reachable.
        Returns $true if healthy, $false otherwise.
    #>
    try {
        # Simple query to verify AD connectivity
        $null = Get-ADDomainController -Discover -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ============================================================================
# Core Functions
# ============================================================================

function Restore-ADAccount {
    <#
    .SYNOPSIS
        Restores a previously disabled AD account by re-enabling and moving back to original OU.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [string]$OriginalOU,

        [Parameter(Mandatory = $false)]
        [switch]$WhatIfMode
    )

    $result = [PSCustomObject]@{
        SamAccountName = $SamAccountName
        OriginalOU     = $OriginalOU
        RestoredFrom   = $null
        Action         = $null
        Timestamp      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }

    try {
        # Verify account exists
        $account = Get-ADUser -Identity $SamAccountName -Properties DistinguishedName -ErrorAction Stop

        # Extract current OU
        $dnParts = $account.DistinguishedName -split ',', 2
        if ($dnParts.Count -gt 1) {
            $result.RestoredFrom = $dnParts[1]
        } else {
            $result.RestoredFrom = $account.DistinguishedName
        }

        if ($WhatIfMode) {
            $result.Action = "WHATIF"
            return $result
        }

        # Re-enable the account
        Enable-ADAccount -Identity $SamAccountName -ErrorAction Stop

        # Move back to original OU
        Move-ADObject -Identity $account.DistinguishedName -TargetPath $OriginalOU -ErrorAction Stop

        $result.Action = "RESTORED"
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $result.Action = "NOT_FOUND"
    }
    catch {
        $result.Action = "ERROR: $_"
    }

    return $result
}

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

# Handle Rollback mode
if ($Rollback) {
    # Set default report path for rollback if not provided
    if (-not $ReportPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $ReportPath = Join-Path -Path (Get-Location) -ChildPath "RollbackReport_$timestamp.csv"
    }

    # Validate rollback file exists
    if (-not (Test-Path -Path $RollbackFile -PathType Leaf)) {
        Write-Error "Rollback file not found: $RollbackFile"
        exit 1
    }

    # Circuit breaker: DC health check
    Write-Host "Checking domain controller connectivity..." -ForegroundColor Cyan
    if (-not (Test-DomainControllerHealth)) {
        Write-Error "Cannot connect to Active Directory. Please verify network connectivity and domain controller availability."
        exit 1
    }
    Write-Host "Domain controller connection verified." -ForegroundColor Green

    # Import and filter for eligible accounts
    $rollbackData = Import-Csv -Path $RollbackFile
    $eligibleAccounts = $rollbackData | Where-Object { $_.Action -eq "DISABLED_AND_MOVED" }

    if ($eligibleAccounts.Count -eq 0) {
        Write-Warning "No eligible accounts found in rollback file (looking for Action = 'DISABLED_AND_MOVED')."
        exit 0
    }

    # Circuit breaker: Force dry run if over limit (unless -Force specified)
    $forcedWhatIf = $false
    if ($eligibleAccounts.Count -gt $MaxAccounts -and -not $Force -and -not $WhatIfPreference) {
        Write-Warning "Account count ($($eligibleAccounts.Count)) exceeds MaxAccounts limit ($MaxAccounts). Forcing WhatIf mode."
        Write-Warning "Use -Force to override this safety limit."
        $forcedWhatIf = $true
    }

    # Determine effective WhatIf mode
    $effectiveWhatIf = $WhatIfPreference -or $forcedWhatIf

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  AD Account Rollback Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Rollback File: $RollbackFile"
    Write-Host "Report Path:   $ReportPath"
    Write-Host "Mode:          $(if ($effectiveWhatIf) { 'WhatIf (Preview)' } else { 'Execute' })"
    if ($forcedWhatIf) {
        Write-Host "               (Forced due to MaxAccounts limit)" -ForegroundColor Yellow
    }
    Write-Host "Accounts:      $($eligibleAccounts.Count)"
    Write-Host "Max Failures:  $MaxConsecutiveFailures consecutive"
    Write-Host "========================================`n"

    $results = @()
    $counters = @{
        Restored   = 0
        NotFound   = 0
        Errors     = 0
        WhatIf     = 0
    }
    $consecutiveFailures = 0
    $abortedEarly = $false

    foreach ($account in $eligibleAccounts) {
        $restoreResult = Restore-ADAccount -SamAccountName $account.SamAccountName -OriginalOU $account.OriginalOU -WhatIfMode:$effectiveWhatIf

        switch -Wildcard ($restoreResult.Action) {
            "RESTORED" {
                $counters.Restored++
                $consecutiveFailures = 0  # Reset on success
                Write-Host "[RESTORED]  $($account.SamAccountName) - Enabled and moved to $($account.OriginalOU)" -ForegroundColor Green
            }
            "WHATIF" {
                $counters.WhatIf++
                $consecutiveFailures = 0  # Reset on success
                Write-Host "[WHATIF]    $($account.SamAccountName) - Would enable and move to $($account.OriginalOU)" -ForegroundColor Yellow
            }
            "NOT_FOUND" {
                $counters.NotFound++
                # NOT_FOUND doesn't count as a failure - account was likely deleted intentionally
                Write-Host "[NOT FOUND] $($account.SamAccountName) - Account no longer exists in AD" -ForegroundColor Gray
            }
            "ERROR*" {
                $counters.Errors++
                $consecutiveFailures++
                Write-Host "[ERROR]     $($account.SamAccountName) - $($restoreResult.Action)" -ForegroundColor Magenta

                # Circuit breaker: Check consecutive failures
                if ($consecutiveFailures -ge $MaxConsecutiveFailures) {
                    Write-Error "Circuit breaker triggered: $MaxConsecutiveFailures consecutive failures. Aborting."
                    $abortedEarly = $true
                    $results += $restoreResult
                    break
                }
            }
        }

        $results += $restoreResult
    }

    # Export rollback report
    $results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "         Rollback Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    if ($abortedEarly) {
        Write-Host "STATUS: ABORTED (consecutive failure limit)" -ForegroundColor Red
    }
    if ($effectiveWhatIf) {
        Write-Host "Would restore:               $($counters.WhatIf)" -ForegroundColor Yellow
    } else {
        Write-Host "Restored:                    $($counters.Restored)" -ForegroundColor Green
    }
    Write-Host "Not found:                   $($counters.NotFound)" -ForegroundColor Gray
    Write-Host "Errors:                      $($counters.Errors)" -ForegroundColor Magenta
    Write-Host "----------------------------------------"
    Write-Host "Total processed:             $($results.Count) of $($eligibleAccounts.Count)"
    Write-Host "Report saved to:             $ReportPath"
    Write-Host "========================================`n"

    if ($abortedEarly) { exit 1 }
    exit 0
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

# Circuit breaker: DC health check
Write-Host "Checking domain controller connectivity..." -ForegroundColor Cyan
if (-not (Test-DomainControllerHealth)) {
    Write-Error "Cannot connect to Active Directory. Please verify network connectivity and domain controller availability."
    exit 1
}
Write-Host "Domain controller connection verified." -ForegroundColor Green

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

# Circuit breaker: Force dry run if over limit (unless -Force specified)
$forcedWhatIf = $false
if ($accounts.Count -gt $MaxAccounts -and -not $Force -and -not $WhatIfPreference) {
    Write-Warning "Account count ($($accounts.Count)) exceeds MaxAccounts limit ($MaxAccounts). Forcing WhatIf mode."
    Write-Warning "Use -Force to override this safety limit."
    $forcedWhatIf = $true
}

# Determine effective WhatIf mode
$effectiveWhatIf = $WhatIfPreference -or $forcedWhatIf

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD Dormant Account Cleanup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Input File:    $InputFile"
Write-Host "Dormant Days:  $DormantDays"
Write-Host "Target OU:     $TargetOU"
Write-Host "Report Path:   $ReportPath"
Write-Host "Mode:          $(if ($effectiveWhatIf) { 'WhatIf (Preview)' } else { 'Execute' })"
if ($forcedWhatIf) {
    Write-Host "               (Forced due to MaxAccounts limit)" -ForegroundColor Yellow
}
Write-Host "Accounts:      $($accounts.Count)"
Write-Host "Max Failures:  $MaxConsecutiveFailures consecutive"
Write-Host "========================================`n"

$results = @()
$counters = @{
    Active        = 0
    Dormant       = 0
    NeverLoggedIn = 0
    NotFound      = 0
    Errors        = 0
}
$consecutiveFailures = 0
$abortedEarly = $false

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
            $consecutiveFailures = 0  # Reset on success
            $resultEntry.Action = "SKIPPED"
            Write-Host "[ACTIVE]    $accountName - Last login: $($status.DaysInactive) days ago" -ForegroundColor Green
        }
        "DORMANT" {
            $counters.Dormant++
            if ($effectiveWhatIf) {
                $consecutiveFailures = 0  # Reset on success
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

                    $consecutiveFailures = 0  # Reset on success
                    $resultEntry.Action = "DISABLED_AND_MOVED"
                    $resultEntry.NewOU = $TargetOU
                    Write-Host "[DORMANT]   $accountName - Disabled and moved (inactive $($status.DaysInactive) days)" -ForegroundColor Red
                } catch {
                    $resultEntry.Action = "ERROR: $_"
                    $counters.Errors++
                    $consecutiveFailures++
                    Write-Host "[ERROR]     $accountName - Failed to process: $_" -ForegroundColor Magenta
                }
            }
        }
        "NEVER_LOGGED_IN" {
            $counters.NeverLoggedIn++
            if ($effectiveWhatIf) {
                $consecutiveFailures = 0  # Reset on success
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

                    $consecutiveFailures = 0  # Reset on success
                    $resultEntry.Action = "DISABLED_AND_MOVED"
                    $resultEntry.NewOU = $TargetOU
                    Write-Host "[DORMANT]   $accountName - Disabled and moved (never logged in)" -ForegroundColor Red
                } catch {
                    $resultEntry.Action = "ERROR: $_"
                    $counters.Errors++
                    $consecutiveFailures++
                    Write-Host "[ERROR]     $accountName - Failed to process: $_" -ForegroundColor Magenta
                }
            }
        }
        "NOT_FOUND" {
            $counters.NotFound++
            # NOT_FOUND doesn't count as a failure - account may have been removed
            $resultEntry.Action = "SKIPPED"
            Write-Host "[NOT FOUND] $accountName - Account does not exist in AD" -ForegroundColor Gray
        }
        default {
            $counters.Errors++
            $consecutiveFailures++
            $resultEntry.Action = "SKIPPED"
            Write-Host "[ERROR]     $accountName - $($status.Status)" -ForegroundColor Magenta
        }
    }

    $results += $resultEntry

    # Circuit breaker: Check consecutive failures
    if ($consecutiveFailures -ge $MaxConsecutiveFailures) {
        Write-Error "Circuit breaker triggered: $MaxConsecutiveFailures consecutive failures. Aborting."
        $abortedEarly = $true
        break
    }
}

# Export report
$results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "              Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
if ($abortedEarly) {
    Write-Host "STATUS: ABORTED (consecutive failure limit)" -ForegroundColor Red
}
Write-Host "Active accounts (skipped):   $($counters.Active)" -ForegroundColor Green
Write-Host "Dormant accounts:            $($counters.Dormant)" -ForegroundColor Red
Write-Host "Never logged in:             $($counters.NeverLoggedIn)" -ForegroundColor Red
Write-Host "Not found:                   $($counters.NotFound)" -ForegroundColor Gray
Write-Host "Errors:                      $($counters.Errors)" -ForegroundColor Magenta
Write-Host "----------------------------------------"
Write-Host "Total processed:             $($results.Count) of $($accounts.Count)"
Write-Host "Report saved to:             $ReportPath"
Write-Host "========================================`n"

if ($abortedEarly) { exit 1 }
