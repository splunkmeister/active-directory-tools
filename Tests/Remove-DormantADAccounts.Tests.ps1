#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Remove-DormantADAccounts.ps1
.DESCRIPTION
    Unit tests with mocked Active Directory cmdlets.
    Run with: Invoke-Pester -Path ./Tests/
#>

BeforeAll {
    # Get the script path
    $ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "..\Remove-DormantADAccounts.ps1"

    # Create a temp directory for test files
    $script:TestDir = Join-Path -Path $env:TEMP -ChildPath "ADDormantTests_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Default test parameters
    $script:TestInputFile = Join-Path -Path $script:TestDir -ChildPath "test_accounts.txt"
    $script:TestReportPath = Join-Path -Path $script:TestDir -ChildPath "test_report.csv"
    $script:TestTargetOU = "OU=Disabled,DC=contoso,DC=com"
    $script:DormantDays = 90
}

AfterAll {
    # Cleanup temp directory
    if (Test-Path $script:TestDir) {
        Remove-Item -Path $script:TestDir -Recurse -Force
    }
}

Describe "Help Flag" {
    It "Should display help when run with -Help" {
        $result = & $ScriptPath -Help 2>&1
        $result | Should -Match "SYNOPSIS"
    }

    It "Should display help when run with -h alias" {
        $result = & $ScriptPath -h 2>&1
        $result | Should -Match "SYNOPSIS"
    }

    It "Should display help when run without arguments" {
        $result = & $ScriptPath 2>&1
        $result | Should -Match "SYNOPSIS"
    }

    It "Should exit with code 0 when showing help" {
        & $ScriptPath -Help | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
}

Describe "Get-AccountDormancyStatus Function" {
    BeforeAll {
        # Dot-source just the function for isolated testing
        # Extract and define the function
        $functionDef = @'
function Get-AccountDormancyStatus {
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
            $result.Status = "NEVER_LOGGED_IN"
            $result.DaysInactive = $null
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $result.Status = "NOT_FOUND"
    }
    catch {
        $result.Status = "ERROR"
    }

    return $result
}
'@
        Invoke-Expression $functionDef
    }

    Context "When account is active (logged in within threshold)" {
        BeforeAll {
            Mock Get-ADUser {
                $daysAgo = 30
                [PSCustomObject]@{
                    SamAccountName     = "activeuser"
                    DisplayName        = "Active User"
                    Enabled            = $true
                    DistinguishedName  = "CN=activeuser,OU=Users,DC=contoso,DC=com"
                    lastLogonTimestamp = (Get-Date).AddDays(-$daysAgo).ToFileTime()
                }
            }
        }

        It "Should return ACTIVE status" {
            $result = Get-AccountDormancyStatus -SamAccountName "activeuser" -ThresholdDays 90
            $result.Status | Should -Be "ACTIVE"
        }

        It "Should calculate correct days inactive" {
            $result = Get-AccountDormancyStatus -SamAccountName "activeuser" -ThresholdDays 90
            $result.DaysInactive | Should -BeGreaterOrEqual 29
            $result.DaysInactive | Should -BeLessOrEqual 31
        }

        It "Should populate DisplayName" {
            $result = Get-AccountDormancyStatus -SamAccountName "activeuser" -ThresholdDays 90
            $result.DisplayName | Should -Be "Active User"
        }

        It "Should extract OriginalOU correctly" {
            $result = Get-AccountDormancyStatus -SamAccountName "activeuser" -ThresholdDays 90
            $result.OriginalOU | Should -Be "OU=Users,DC=contoso,DC=com"
        }
    }

    Context "When account is dormant (exceeded threshold)" {
        BeforeAll {
            Mock Get-ADUser {
                $daysAgo = 120
                [PSCustomObject]@{
                    SamAccountName     = "dormantuser"
                    DisplayName        = "Dormant User"
                    Enabled            = $true
                    DistinguishedName  = "CN=dormantuser,OU=Users,DC=contoso,DC=com"
                    lastLogonTimestamp = (Get-Date).AddDays(-$daysAgo).ToFileTime()
                }
            }
        }

        It "Should return DORMANT status" {
            $result = Get-AccountDormancyStatus -SamAccountName "dormantuser" -ThresholdDays 90
            $result.Status | Should -Be "DORMANT"
        }

        It "Should show days inactive greater than threshold" {
            $result = Get-AccountDormancyStatus -SamAccountName "dormantuser" -ThresholdDays 90
            $result.DaysInactive | Should -BeGreaterThan 90
        }
    }

    Context "When account has never logged in" {
        BeforeAll {
            Mock Get-ADUser {
                [PSCustomObject]@{
                    SamAccountName     = "newuser"
                    DisplayName        = "New User"
                    Enabled            = $true
                    DistinguishedName  = "CN=newuser,OU=Users,DC=contoso,DC=com"
                    lastLogonTimestamp = $null
                }
            }
        }

        It "Should return NEVER_LOGGED_IN status" {
            $result = Get-AccountDormancyStatus -SamAccountName "newuser" -ThresholdDays 90
            $result.Status | Should -Be "NEVER_LOGGED_IN"
        }

        It "Should have null DaysInactive" {
            $result = Get-AccountDormancyStatus -SamAccountName "newuser" -ThresholdDays 90
            $result.DaysInactive | Should -BeNullOrEmpty
        }
    }

    Context "When account does not exist" {
        BeforeAll {
            Mock Get-ADUser {
                $ex = New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                throw $ex
            }
        }

        It "Should return NOT_FOUND status" {
            $result = Get-AccountDormancyStatus -SamAccountName "nonexistent" -ThresholdDays 90
            $result.Status | Should -Be "NOT_FOUND"
        }
    }

    Context "When AD query fails with error" {
        BeforeAll {
            Mock Get-ADUser {
                throw "Connection to AD failed"
            }
        }

        It "Should return ERROR status" {
            $result = Get-AccountDormancyStatus -SamAccountName "erroruser" -ThresholdDays 90
            $result.Status | Should -Be "ERROR"
        }
    }

    Context "Edge case: Account exactly at threshold" {
        BeforeAll {
            Mock Get-ADUser {
                [PSCustomObject]@{
                    SamAccountName     = "edgeuser"
                    DisplayName        = "Edge User"
                    Enabled            = $true
                    DistinguishedName  = "CN=edgeuser,OU=Users,DC=contoso,DC=com"
                    lastLogonTimestamp = (Get-Date).AddDays(-90).ToFileTime()
                }
            }
        }

        It "Should return ACTIVE when exactly at threshold (not greater than)" {
            $result = Get-AccountDormancyStatus -SamAccountName "edgeuser" -ThresholdDays 90
            $result.Status | Should -Be "ACTIVE"
        }
    }
}

Describe "Script Input Validation" {
    Context "When input file does not exist" {
        It "Should exit with error" {
            $result = & $ScriptPath `
                -InputFile "C:\nonexistent\fake.txt" `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:TestReportPath `
                -ErrorAction SilentlyContinue 2>&1

            $result | Should -Match "Input file not found"
        }
    }

    Context "When input file is empty" {
        BeforeAll {
            # Create empty input file
            Set-Content -Path $script:TestInputFile -Value ""

            # Mock OU validation to pass
            Mock Get-ADOrganizationalUnit { return $true }
        }

        It "Should exit gracefully with warning" {
            $result = & $ScriptPath `
                -InputFile $script:TestInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:TestReportPath `
                -WarningAction SilentlyContinue 2>&1

            # Script should complete without error
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "When DormantDays is invalid" {
        It "Should reject zero value" {
            { & $ScriptPath `
                -InputFile $script:TestInputFile `
                -DormantDays 0 `
                -TargetOU $script:TestTargetOU `
                -ErrorAction Stop } | Should -Throw
        }

        It "Should reject negative value" {
            { & $ScriptPath `
                -InputFile $script:TestInputFile `
                -DormantDays -1 `
                -TargetOU $script:TestTargetOU `
                -ErrorAction Stop } | Should -Throw
        }
    }
}

Describe "Script Execution with WhatIf" {
    BeforeAll {
        # Create input file with test accounts
        @("dormantuser", "activeuser", "newuser") | Set-Content -Path $script:TestInputFile

        # Mock all AD cmdlets
        Mock Get-ADOrganizationalUnit { return $true }

        Mock Get-ADUser {
            param($Identity)
            switch ($Identity) {
                "dormantuser" {
                    [PSCustomObject]@{
                        SamAccountName     = "dormantuser"
                        DisplayName        = "Dormant User"
                        Enabled            = $true
                        DistinguishedName  = "CN=dormantuser,OU=Users,DC=contoso,DC=com"
                        lastLogonTimestamp = (Get-Date).AddDays(-120).ToFileTime()
                    }
                }
                "activeuser" {
                    [PSCustomObject]@{
                        SamAccountName     = "activeuser"
                        DisplayName        = "Active User"
                        Enabled            = $true
                        DistinguishedName  = "CN=activeuser,OU=Users,DC=contoso,DC=com"
                        lastLogonTimestamp = (Get-Date).AddDays(-30).ToFileTime()
                    }
                }
                "newuser" {
                    [PSCustomObject]@{
                        SamAccountName     = "newuser"
                        DisplayName        = "New User"
                        Enabled            = $true
                        DistinguishedName  = "CN=newuser,OU=Users,DC=contoso,DC=com"
                        lastLogonTimestamp = $null
                    }
                }
            }
        }

        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    Context "WhatIf mode" {
        It "Should not call Disable-ADAccount" {
            & $ScriptPath `
                -InputFile $script:TestInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:TestReportPath `
                -WhatIf

            Should -Invoke Disable-ADAccount -Times 0
        }

        It "Should not call Move-ADObject" {
            & $ScriptPath `
                -InputFile $script:TestInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:TestReportPath `
                -WhatIf

            Should -Invoke Move-ADObject -Times 0
        }

        It "Should generate report with WHATIF actions" {
            & $ScriptPath `
                -InputFile $script:TestInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:TestReportPath `
                -WhatIf

            $report = Import-Csv -Path $script:TestReportPath
            $whatifActions = $report | Where-Object { $_.Action -eq "WHATIF" }
            $whatifActions.Count | Should -BeGreaterOrEqual 1
        }
    }
}

Describe "Report Generation" {
    BeforeAll {
        @("testuser") | Set-Content -Path $script:TestInputFile

        Mock Get-ADOrganizationalUnit { return $true }
        Mock Get-ADUser {
            [PSCustomObject]@{
                SamAccountName     = "testuser"
                DisplayName        = "Test User"
                Enabled            = $true
                DistinguishedName  = "CN=testuser,OU=Users,DC=contoso,DC=com"
                lastLogonTimestamp = (Get-Date).AddDays(-30).ToFileTime()
            }
        }
    }

    It "Should create CSV report" {
        & $ScriptPath `
            -InputFile $script:TestInputFile `
            -DormantDays 90 `
            -TargetOU $script:TestTargetOU `
            -ReportPath $script:TestReportPath `
            -WhatIf

        Test-Path $script:TestReportPath | Should -BeTrue
    }

    It "Should include required columns" {
        & $ScriptPath `
            -InputFile $script:TestInputFile `
            -DormantDays 90 `
            -TargetOU $script:TestTargetOU `
            -ReportPath $script:TestReportPath `
            -WhatIf

        $report = Import-Csv -Path $script:TestReportPath
        $report[0].PSObject.Properties.Name | Should -Contain "SamAccountName"
        $report[0].PSObject.Properties.Name | Should -Contain "Status"
        $report[0].PSObject.Properties.Name | Should -Contain "Action"
        $report[0].PSObject.Properties.Name | Should -Contain "DaysInactive"
    }

    It "Should use default report path when not specified" {
        # This test verifies the default naming convention
        $defaultPattern = "DormantAccountReport_\d{8}_\d{6}\.csv"
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        $scriptContent | Should -Match 'DormantAccountReport_\$timestamp\.csv'
    }
}

Describe "Restore-ADAccount Function" {
    BeforeAll {
        # Extract and define the function for isolated testing
        $functionDef = @'
function Restore-ADAccount {
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
        $account = Get-ADUser -Identity $SamAccountName -Properties DistinguishedName -ErrorAction Stop

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

        Enable-ADAccount -Identity $SamAccountName -ErrorAction Stop
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
'@
        Invoke-Expression $functionDef
    }

    Context "When account exists and can be restored" {
        BeforeAll {
            Mock Get-ADUser {
                [PSCustomObject]@{
                    SamAccountName    = "disableduser"
                    DistinguishedName = "CN=disableduser,OU=Disabled,DC=contoso,DC=com"
                }
            }
            Mock Enable-ADAccount { }
            Mock Move-ADObject { }
        }

        It "Should return RESTORED action" {
            $result = Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com"
            $result.Action | Should -Be "RESTORED"
        }

        It "Should populate RestoredFrom with current OU" {
            $result = Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com"
            $result.RestoredFrom | Should -Be "OU=Disabled,DC=contoso,DC=com"
        }

        It "Should call Enable-ADAccount" {
            Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com"
            Should -Invoke Enable-ADAccount -Times 1
        }

        It "Should call Move-ADObject" {
            Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com"
            Should -Invoke Move-ADObject -Times 1
        }
    }

    Context "When WhatIfMode is enabled" {
        BeforeAll {
            Mock Get-ADUser {
                [PSCustomObject]@{
                    SamAccountName    = "disableduser"
                    DistinguishedName = "CN=disableduser,OU=Disabled,DC=contoso,DC=com"
                }
            }
            Mock Enable-ADAccount { }
            Mock Move-ADObject { }
        }

        It "Should return WHATIF action" {
            $result = Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com" -WhatIfMode
            $result.Action | Should -Be "WHATIF"
        }

        It "Should not call Enable-ADAccount" {
            Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com" -WhatIfMode
            Should -Invoke Enable-ADAccount -Times 0
        }

        It "Should not call Move-ADObject" {
            Restore-ADAccount -SamAccountName "disableduser" -OriginalOU "OU=Users,DC=contoso,DC=com" -WhatIfMode
            Should -Invoke Move-ADObject -Times 0
        }
    }

    Context "When account does not exist" {
        BeforeAll {
            Mock Get-ADUser {
                $ex = New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                throw $ex
            }
        }

        It "Should return NOT_FOUND action" {
            $result = Restore-ADAccount -SamAccountName "deleteduser" -OriginalOU "OU=Users,DC=contoso,DC=com"
            $result.Action | Should -Be "NOT_FOUND"
        }
    }

    Context "When AD operation fails" {
        BeforeAll {
            Mock Get-ADUser {
                [PSCustomObject]@{
                    SamAccountName    = "erroruser"
                    DistinguishedName = "CN=erroruser,OU=Disabled,DC=contoso,DC=com"
                }
            }
            Mock Enable-ADAccount {
                throw "Access denied"
            }
        }

        It "Should return ERROR action with message" {
            $result = Restore-ADAccount -SamAccountName "erroruser" -OriginalOU "OU=Users,DC=contoso,DC=com"
            $result.Action | Should -Match "^ERROR:"
        }
    }
}

Describe "Rollback Mode" {
    BeforeAll {
        $script:TestRollbackFile = Join-Path -Path $script:TestDir -ChildPath "rollback_source.csv"
        $script:TestRollbackReportPath = Join-Path -Path $script:TestDir -ChildPath "rollback_report.csv"
    }

    Context "When rollback file does not exist" {
        It "Should exit with error" {
            $result = & $ScriptPath `
                -Rollback `
                -RollbackFile "C:\nonexistent\fake.csv" `
                -ErrorAction SilentlyContinue 2>&1

            $result | Should -Match "Rollback file not found"
        }
    }

    Context "When rollback file has no eligible accounts" {
        BeforeAll {
            # Create rollback file with only SKIPPED accounts
            @(
                [PSCustomObject]@{
                    SamAccountName = "activeuser"
                    Action         = "SKIPPED"
                    OriginalOU     = "OU=Users,DC=contoso,DC=com"
                }
            ) | Export-Csv -Path $script:TestRollbackFile -NoTypeInformation
        }

        It "Should exit gracefully with warning" {
            $result = & $ScriptPath `
                -Rollback `
                -RollbackFile $script:TestRollbackFile `
                -ReportPath $script:TestRollbackReportPath `
                -WarningAction SilentlyContinue 2>&1

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "Rollback with valid CSV" {
        BeforeAll {
            # Create rollback file with DISABLED_AND_MOVED accounts
            @(
                [PSCustomObject]@{
                    SamAccountName = "dormantuser1"
                    Action         = "DISABLED_AND_MOVED"
                    OriginalOU     = "OU=Users,DC=contoso,DC=com"
                    NewOU          = "OU=Disabled,DC=contoso,DC=com"
                },
                [PSCustomObject]@{
                    SamAccountName = "dormantuser2"
                    Action         = "DISABLED_AND_MOVED"
                    OriginalOU     = "OU=Sales,DC=contoso,DC=com"
                    NewOU          = "OU=Disabled,DC=contoso,DC=com"
                },
                [PSCustomObject]@{
                    SamAccountName = "activeuser"
                    Action         = "SKIPPED"
                    OriginalOU     = "OU=Users,DC=contoso,DC=com"
                }
            ) | Export-Csv -Path $script:TestRollbackFile -NoTypeInformation

            Mock Get-ADUser {
                param($Identity)
                [PSCustomObject]@{
                    SamAccountName    = $Identity
                    DistinguishedName = "CN=$Identity,OU=Disabled,DC=contoso,DC=com"
                }
            }
            Mock Enable-ADAccount { }
            Mock Move-ADObject { }
        }

        It "Should only process DISABLED_AND_MOVED accounts" {
            & $ScriptPath `
                -Rollback `
                -RollbackFile $script:TestRollbackFile `
                -ReportPath $script:TestRollbackReportPath `
                -WhatIf

            $report = Import-Csv -Path $script:TestRollbackReportPath
            $report.Count | Should -Be 2
        }

        It "Should not call Enable-ADAccount in WhatIf mode" {
            & $ScriptPath `
                -Rollback `
                -RollbackFile $script:TestRollbackFile `
                -ReportPath $script:TestRollbackReportPath `
                -WhatIf

            Should -Invoke Enable-ADAccount -Times 0
        }

        It "Should not call Move-ADObject in WhatIf mode" {
            & $ScriptPath `
                -Rollback `
                -RollbackFile $script:TestRollbackFile `
                -ReportPath $script:TestRollbackReportPath `
                -WhatIf

            Should -Invoke Move-ADObject -Times 0
        }

        It "Should generate rollback report with WHATIF actions" {
            & $ScriptPath `
                -Rollback `
                -RollbackFile $script:TestRollbackFile `
                -ReportPath $script:TestRollbackReportPath `
                -WhatIf

            $report = Import-Csv -Path $script:TestRollbackReportPath
            $whatifActions = $report | Where-Object { $_.Action -eq "WHATIF" }
            $whatifActions.Count | Should -Be 2
        }
    }

    Context "Rollback when account no longer exists" {
        BeforeAll {
            @(
                [PSCustomObject]@{
                    SamAccountName = "deleteduser"
                    Action         = "DISABLED_AND_MOVED"
                    OriginalOU     = "OU=Users,DC=contoso,DC=com"
                }
            ) | Export-Csv -Path $script:TestRollbackFile -NoTypeInformation

            Mock Get-ADUser {
                $ex = New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
                throw $ex
            }
        }

        It "Should report NOT_FOUND in rollback report" {
            & $ScriptPath `
                -Rollback `
                -RollbackFile $script:TestRollbackFile `
                -ReportPath $script:TestRollbackReportPath

            $report = Import-Csv -Path $script:TestRollbackReportPath
            $report[0].Action | Should -Be "NOT_FOUND"
        }
    }
}

Describe "Rollback Report Generation" {
    BeforeAll {
        $script:TestRollbackFile = Join-Path -Path $script:TestDir -ChildPath "rollback_report_test.csv"
        $script:TestRollbackReportPath = Join-Path -Path $script:TestDir -ChildPath "rollback_output.csv"

        @(
            [PSCustomObject]@{
                SamAccountName = "testuser"
                Action         = "DISABLED_AND_MOVED"
                OriginalOU     = "OU=Users,DC=contoso,DC=com"
            }
        ) | Export-Csv -Path $script:TestRollbackFile -NoTypeInformation

        Mock Get-ADUser {
            [PSCustomObject]@{
                SamAccountName    = "testuser"
                DistinguishedName = "CN=testuser,OU=Disabled,DC=contoso,DC=com"
            }
        }
        Mock Enable-ADAccount { }
        Mock Move-ADObject { }
    }

    It "Should create rollback report CSV" {
        & $ScriptPath `
            -Rollback `
            -RollbackFile $script:TestRollbackFile `
            -ReportPath $script:TestRollbackReportPath `
            -WhatIf

        Test-Path $script:TestRollbackReportPath | Should -BeTrue
    }

    It "Should include required columns in rollback report" {
        & $ScriptPath `
            -Rollback `
            -RollbackFile $script:TestRollbackFile `
            -ReportPath $script:TestRollbackReportPath `
            -WhatIf

        $report = Import-Csv -Path $script:TestRollbackReportPath
        $report[0].PSObject.Properties.Name | Should -Contain "SamAccountName"
        $report[0].PSObject.Properties.Name | Should -Contain "OriginalOU"
        $report[0].PSObject.Properties.Name | Should -Contain "RestoredFrom"
        $report[0].PSObject.Properties.Name | Should -Contain "Action"
        $report[0].PSObject.Properties.Name | Should -Contain "Timestamp"
    }

    It "Should use default rollback report path when not specified" {
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        $scriptContent | Should -Match 'RollbackReport_\$timestamp\.csv'
    }
}

Describe "Circuit Breakers" {
    BeforeAll {
        $script:CircuitBreakerInputFile = Join-Path -Path $script:TestDir -ChildPath "circuit_breaker_accounts.txt"
        $script:CircuitBreakerReportPath = Join-Path -Path $script:TestDir -ChildPath "circuit_breaker_report.csv"
    }

    Describe "Test-DomainControllerHealth Function" {
        BeforeAll {
            # Define the function for isolated testing
            $functionDef = @'
function Test-DomainControllerHealth {
    try {
        $null = Get-ADDomainController -Discover -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}
'@
            Invoke-Expression $functionDef
        }

        Context "When DC is reachable" {
            BeforeAll {
                Mock Get-ADDomainController { return @{ Name = "DC01" } }
            }

            It "Should return true" {
                Test-DomainControllerHealth | Should -BeTrue
            }
        }

        Context "When DC is not reachable" {
            BeforeAll {
                Mock Get-ADDomainController { throw "Cannot contact domain controller" }
            }

            It "Should return false" {
                Test-DomainControllerHealth | Should -BeFalse
            }
        }
    }

    Describe "MaxAccounts Limit" {
        BeforeAll {
            # Create input file with 5 accounts (will exceed limit of 3)
            @("user1", "user2", "user3", "user4", "user5") | Set-Content -Path $script:CircuitBreakerInputFile

            Mock Get-ADDomainController { return @{ Name = "DC01" } }
            Mock Get-ADOrganizationalUnit { return $true }
            Mock Get-ADUser {
                param($Identity)
                [PSCustomObject]@{
                    SamAccountName     = $Identity
                    DisplayName        = "Test User"
                    Enabled            = $true
                    DistinguishedName  = "CN=$Identity,OU=Users,DC=contoso,DC=com"
                    lastLogonTimestamp = (Get-Date).AddDays(-120).ToFileTime()
                }
            }
            Mock Disable-ADAccount { }
            Mock Move-ADObject { }
        }

        It "Should force WhatIf mode when exceeding MaxAccounts without -Force" {
            & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 3

            # Should not call Disable-ADAccount because WhatIf was forced
            Should -Invoke Disable-ADAccount -Times 0
        }

        It "Should generate WHATIF actions when exceeding limit" {
            & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 3

            $report = Import-Csv -Path $script:CircuitBreakerReportPath
            $whatifActions = $report | Where-Object { $_.Action -eq "WHATIF" }
            $whatifActions.Count | Should -BeGreaterThan 0
        }

        It "Should allow execution when -Force is specified" {
            & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 3 `
                -Force

            # Should call Disable-ADAccount because -Force overrides the limit
            Should -Invoke Disable-ADAccount -Times 5
        }

        It "Should process normally when under MaxAccounts limit" {
            @("user1", "user2") | Set-Content -Path $script:CircuitBreakerInputFile

            & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 5

            Should -Invoke Disable-ADAccount -Times 2
        }
    }

    Describe "Consecutive Failure Circuit Breaker" {
        BeforeAll {
            # Create input file with 10 accounts
            @("user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "user10") |
                Set-Content -Path $script:CircuitBreakerInputFile

            Mock Get-ADDomainController { return @{ Name = "DC01" } }
            Mock Get-ADOrganizationalUnit { return $true }
            Mock Get-ADUser {
                param($Identity)
                [PSCustomObject]@{
                    SamAccountName     = $Identity
                    DisplayName        = "Test User"
                    Enabled            = $true
                    DistinguishedName  = "CN=$Identity,OU=Users,DC=contoso,DC=com"
                    lastLogonTimestamp = (Get-Date).AddDays(-120).ToFileTime()
                }
            }
            # Always fail on disable
            Mock Disable-ADAccount { throw "Access denied" }
            Mock Move-ADObject { }
        }

        It "Should abort after MaxConsecutiveFailures" {
            $result = & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 100 `
                -MaxConsecutiveFailures 3 `
                -Force 2>&1

            # Script should have aborted early
            $result | Should -Match "Circuit breaker triggered"
        }

        It "Should process fewer accounts than total when circuit breaker triggers" {
            & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 100 `
                -MaxConsecutiveFailures 3 `
                -Force 2>&1

            $report = Import-Csv -Path $script:CircuitBreakerReportPath
            # Should have stopped after 3 consecutive failures
            $report.Count | Should -BeLessOrEqual 3
        }

        It "Should reset failure count on success" {
            # Mock that alternates between success and failure
            $script:callCount = 0
            Mock Disable-ADAccount {
                $script:callCount++
                if ($script:callCount % 2 -eq 0) {
                    throw "Access denied"
                }
            }

            & $ScriptPath `
                -InputFile $script:CircuitBreakerInputFile `
                -DormantDays 90 `
                -TargetOU $script:TestTargetOU `
                -ReportPath $script:CircuitBreakerReportPath `
                -MaxAccounts 100 `
                -MaxConsecutiveFailures 3 `
                -Force

            $report = Import-Csv -Path $script:CircuitBreakerReportPath
            # Should process all accounts since failures are not consecutive
            $report.Count | Should -Be 10
        }
    }

    Describe "DC Health Check Integration" {
        BeforeAll {
            @("user1") | Set-Content -Path $script:CircuitBreakerInputFile
        }

        Context "When DC is unreachable" {
            BeforeAll {
                Mock Get-ADDomainController { throw "Cannot contact domain" }
            }

            It "Should exit with error before processing" {
                $result = & $ScriptPath `
                    -InputFile $script:CircuitBreakerInputFile `
                    -DormantDays 90 `
                    -TargetOU $script:TestTargetOU `
                    -ReportPath $script:CircuitBreakerReportPath `
                    -ErrorAction SilentlyContinue 2>&1

                $result | Should -Match "Cannot connect to Active Directory"
            }
        }
    }
}
