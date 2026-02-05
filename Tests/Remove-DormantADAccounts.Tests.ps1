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
