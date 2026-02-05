# Active Directory Tools

A collection of PowerShell scripts for Active Directory management.

## Remove-DormantADAccounts

PowerShell script to identify, disable, and move dormant Active Directory accounts with built-in safety controls and rollback capability.

### Features

- Identify dormant accounts based on `lastLogonTimestamp`
- Disable and move accounts to a designated OU
- Rollback capability to restore previously disabled accounts
- Circuit breakers to prevent accidental mass changes
- Detailed CSV reporting
- WhatIf support for dry runs

### Requirements

- PowerShell 5.1 or later
- Active Directory PowerShell module
- Appropriate AD permissions (disable accounts, move objects)

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-InputFile` | Yes* | - | Path to text file with account names (one per line) |
| `-DormantDays` | Yes* | - | Days of inactivity to consider an account dormant |
| `-TargetOU` | Yes* | - | Distinguished Name of OU to move disabled accounts to |
| `-ReportPath` | No | Auto-generated | Path for CSV report output |
| `-Rollback` | Yes** | - | Enable rollback mode |
| `-RollbackFile` | Yes** | - | Path to previous run's CSV report for rollback |
| `-MaxAccounts` | No | 50 | Max accounts before requiring `-Force` |
| `-MaxConsecutiveFailures` | No | 5 | Stop after N consecutive failures |
| `-Force` | No | - | Override MaxAccounts safety limit |
| `-WhatIf` | No | - | Preview actions without making changes |

\* Required for default mode
\** Required for rollback mode

### Usage

#### Basic Usage

Preview what would happen (dry run):
```powershell
.\Remove-DormantADAccounts.ps1 `
    -InputFile "accounts.txt" `
    -DormantDays 90 `
    -TargetOU "OU=Disabled Users,DC=contoso,DC=com" `
    -WhatIf
```

Execute the cleanup:
```powershell
.\Remove-DormantADAccounts.ps1 `
    -InputFile "accounts.txt" `
    -DormantDays 90 `
    -TargetOU "OU=Disabled Users,DC=contoso,DC=com"
```

#### Large Batch Processing

For batches exceeding the default limit (50 accounts), use `-Force`:
```powershell
.\Remove-DormantADAccounts.ps1 `
    -InputFile "large_batch.txt" `
    -DormantDays 90 `
    -TargetOU "OU=Disabled Users,DC=contoso,DC=com" `
    -MaxAccounts 200 `
    -Force
```

#### Rollback

Restore accounts from a previous run:
```powershell
# Preview rollback
.\Remove-DormantADAccounts.ps1 `
    -Rollback `
    -RollbackFile "DormantAccountReport_20240115_120000.csv" `
    -WhatIf

# Execute rollback
.\Remove-DormantADAccounts.ps1 `
    -Rollback `
    -RollbackFile "DormantAccountReport_20240115_120000.csv"
```

### Circuit Breakers

The script includes safety mechanisms to prevent unintended mass changes:

#### 1. Domain Controller Health Check
Verifies AD connectivity before processing. Exits with error if unreachable.

#### 2. MaxAccounts Limit
If account count exceeds the limit (default: 50), the script automatically switches to WhatIf mode. Override with `-Force` to proceed with execution.

#### 3. Consecutive Failure Limit
Processing stops after N consecutive failures (default: 5). This catches systemic issues like permission problems or DC connectivity loss. The counter resets on any successful operation.

### Reports

#### Dormant Account Report
Generated during normal operation with columns:
- `SamAccountName`, `DisplayName`, `LastLogonDate`, `DaysInactive`
- `Status` (ACTIVE, DORMANT, NEVER_LOGGED_IN, NOT_FOUND)
- `Action` (SKIPPED, WHATIF, DISABLED_AND_MOVED, ERROR)
- `OriginalOU`, `NewOU`, `Timestamp`

#### Rollback Report
Generated during rollback with columns:
- `SamAccountName`, `OriginalOU`, `RestoredFrom`
- `Action` (RESTORED, WHATIF, NOT_FOUND, ERROR)
- `Timestamp`

### Input File Format

Simple text file with one account name per line:
```
jsmith
mjohnson
agarcia
```

### Testing

Run Pester tests:
```powershell
Invoke-Pester -Path ./Tests/
```

### Example Workflow

1. **Generate account list** from your identity management system or AD query

2. **Preview changes** with WhatIf:
   ```powershell
   .\Remove-DormantADAccounts.ps1 -InputFile accounts.txt -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com" -WhatIf
   ```

3. **Review the report** to verify accounts targeted

4. **Execute the cleanup**:
   ```powershell
   .\Remove-DormantADAccounts.ps1 -InputFile accounts.txt -DormantDays 90 -TargetOU "OU=Disabled,DC=contoso,DC=com"
   ```

5. **Keep the report** - it's required for rollback if needed

6. **Rollback if necessary**:
   ```powershell
   .\Remove-DormantADAccounts.ps1 -Rollback -RollbackFile "DormantAccountReport_20240115_120000.csv"
   ```
