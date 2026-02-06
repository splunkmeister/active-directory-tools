# Active Directory Tools

PowerShell scripts for Active Directory dormant account management.

## Scripts

| Script | Purpose |
|--------|---------|
| `Find-DormantADAccounts.ps1` | Query AD to discover dormant accounts |
| `Disable-DormantADAccounts.ps1` | Disable and move dormant accounts to a target OU |

## Requirements

- PowerShell 5.1+
- Active Directory PowerShell module
- Appropriate AD permissions

## Find-DormantADAccounts.ps1

Queries AD for dormant user accounts based on `lastLogonTimestamp`. Generates reports and can create input files for the Disable script.

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-SearchBase` | Yes | - | OU distinguished name to search |
| `-DormantDays` | Yes | - | Days of inactivity threshold |
| `-OutputFile` | No | - | Path to generate target file (SamAccountNames only) |
| `-ReportPath` | No | Auto | Path for full CSV report |
| `-IncludeNeverLoggedIn` | No | $false | Include accounts that never logged in |

### Usage

```powershell
# Find dormant accounts
.\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90

# Generate target file for Disable script
.\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -OutputFile "targets.txt"

# Include never-logged-in accounts
.\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -IncludeNeverLoggedIn
```

## Disable-DormantADAccounts.ps1

Processes a list of accounts, validates dormancy, and disables/moves confirmed dormant accounts. Includes rollback capability.

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-InputFile` | Yes* | - | Path to text file with account names |
| `-DormantDays` | Yes* | - | Days of inactivity threshold |
| `-TargetOU` | Yes* | - | DN of OU to move disabled accounts to |
| `-ReportPath` | No | Auto | Path for CSV report |
| `-Rollback` | Yes** | - | Enable rollback mode |
| `-RollbackFile` | Yes** | - | Previous run's CSV report for rollback |
| `-MaxAccounts` | No | 50 | Max accounts before requiring `-Force` |
| `-MaxConsecutiveFailures` | No | 5 | Stop after N consecutive failures |
| `-Force` | No | - | Override MaxAccounts limit |
| `-TestPermissions` | No | - | Test AD permissions and exit |
| `-WhatIf` | No | - | Preview without changes |

\* Required for default mode | \** Required for rollback mode

### Usage

```powershell
# Preview (dry run)
.\Disable-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -WhatIf

# Execute
.\Disable-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com"

# Rollback
.\Disable-DormantADAccounts.ps1 -Rollback -RollbackFile "DormantAccountReport_20240115_120000.csv"

# Large batch
.\Disable-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -Force

# Test permissions before processing
.\Disable-DormantADAccounts.ps1 -InputFile "accounts.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -TestPermissions
```

## Workflow Example

```powershell
# 1. Discover dormant accounts and generate target file
.\Find-DormantADAccounts.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -DormantDays 90 -OutputFile "targets.txt"

# 2. Review the discovery report (DormantAccountDiscovery_*.csv)

# 3. Preview what will be disabled
.\Disable-DormantADAccounts.ps1 -InputFile "targets.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -WhatIf

# 4. Execute the cleanup
.\Disable-DormantADAccounts.ps1 -InputFile "targets.txt" -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com"

# 5. Keep DormantAccountReport_*.csv for rollback if needed
```

## Circuit Breakers

The Disable script includes safety mechanisms:

- **DC Health Check**: Verifies AD connectivity before processing
- **MaxAccounts Limit**: Forces WhatIf mode for large batches (override with `-Force`)
- **Consecutive Failures**: Stops after N consecutive errors (default: 5)

## Testing

```powershell
Invoke-Pester -Path ./Tests/
```

## Input File Format

Simple text file with one account name per line:
```
jsmith
mjohnson
agarcia
```
