#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Find-DormantADAccounts.ps1
.DESCRIPTION
    Unit tests with mocked Active Directory cmdlets.
    Run with: Invoke-Pester -Path ./Tests/
#>

BeforeAll {
    # Get the script path
    $ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "..\Find-DormantADAccounts.ps1"

    # Create a temp directory for test files
    $script:TestDir = Join-Path -Path $env:TEMP -ChildPath "ADFindDormantTests_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Default test parameters
    $script:TestReportPath = Join-Path -Path $script:TestDir -ChildPath "test_report.csv"
    $script:TestOutputFile = Join-Path -Path $script:TestDir -ChildPath "test_output.txt"
    $script:TestSearchBase = "OU=Users,DC=contoso,DC=com"
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
        $result = & $ScriptPath -Help 2>&1 | Out-String
        $result | Should -Match "SYNOPSIS"
        $result | Should -Match "PARAMETERS"
        $result | Should -Match "EXAMPLES"
    }

    It "Should display help when run with -h alias" {
        $result = & $ScriptPath -h 2>&1 | Out-String
        $result | Should -Match "SYNOPSIS"
    }

    It "Should display help when run without arguments" {
        $result = & $ScriptPath 2>&1 | Out-String
        $result | Should -Match "SYNOPSIS"
    }

    It "Should exit with code 0 when showing help" {
        & $ScriptPath -Help 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It "Should display output columns information" {
        $result = & $ScriptPath -Help 2>&1 | Out-String
        $result | Should -Match "OUTPUT COLUMNS"
        $result | Should -Match "SamAccountName"
        $result | Should -Match "DaysInactive"
    }
}

Describe "SearchBase Validation" {
    BeforeAll {
        Mock Get-ADDomainController { return @{ Name = "DC01" } }
    }

    Context "When SearchBase OU does not exist" {
        BeforeAll {
            Mock Get-ADOrganizationalUnit { throw "OU not found" }
        }

        It "Should exit with error" {
            $result = & $ScriptPath `
                -SearchBase "OU=NonExistent,DC=contoso,DC=com" `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath `
                -ErrorAction SilentlyContinue 2>&1

            $result | Should -Match "SearchBase OU not found"
        }
    }

    Context "When SearchBase OU exists" {
        BeforeAll {
            Mock Get-ADOrganizationalUnit { return $true }
            Mock Get-ADUser { return @() }
        }

        It "Should proceed without error" {
            $result = & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath `
                -WarningAction SilentlyContinue 2>&1

            $LASTEXITCODE | Should -Be 0
        }
    }
}

Describe "DormantDays Validation" {
    It "Should reject zero value" {
        { & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 0 `
            -ErrorAction Stop } | Should -Throw
    }

    It "Should reject negative value" {
        { & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays -1 `
            -ErrorAction Stop } | Should -Throw
    }
}

Describe "Dormancy Detection" {
    BeforeAll {
        Mock Get-ADDomainController { return @{ Name = "DC01" } }
        Mock Get-ADOrganizationalUnit { return $true }
    }

    Context "When accounts have various dormancy states" {
        BeforeAll {
            Mock Get-ADUser {
                @(
                    # Dormant account (120 days inactive)
                    [PSCustomObject]@{
                        SamAccountName     = "dormantuser"
                        DisplayName        = "Dormant User"
                        whenCreated        = (Get-Date).AddYears(-2)
                        PasswordLastSet    = (Get-Date).AddDays(-150)
                        Description        = "Test dormant user"
                        lastLogonTimestamp = (Get-Date).AddDays(-120).ToFileTime()
                    },
                    # Active account (30 days inactive)
                    [PSCustomObject]@{
                        SamAccountName     = "activeuser"
                        DisplayName        = "Active User"
                        whenCreated        = (Get-Date).AddYears(-1)
                        PasswordLastSet    = (Get-Date).AddDays(-30)
                        Description        = "Test active user"
                        lastLogonTimestamp = (Get-Date).AddDays(-30).ToFileTime()
                    },
                    # Never logged in account
                    [PSCustomObject]@{
                        SamAccountName     = "neverloggedin"
                        DisplayName        = "Never Logged In"
                        whenCreated        = (Get-Date).AddDays(-60)
                        PasswordLastSet    = (Get-Date).AddDays(-60)
                        Description        = "Test never logged in"
                        lastLogonTimestamp = $null
                    }
                )
            }
        }

        It "Should identify dormant accounts correctly" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath

            $report = Import-Csv -Path $script:TestReportPath
            $dormantUsers = $report | Where-Object { $_.SamAccountName -eq "dormantuser" }
            $dormantUsers.Count | Should -Be 1
        }

        It "Should not include active accounts" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath

            $report = Import-Csv -Path $script:TestReportPath
            $activeUsers = $report | Where-Object { $_.SamAccountName -eq "activeuser" }
            $activeUsers.Count | Should -Be 0
        }

        It "Should not include never-logged-in by default" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath

            $report = Import-Csv -Path $script:TestReportPath
            $neverLoggedIn = $report | Where-Object { $_.SamAccountName -eq "neverloggedin" }
            $neverLoggedIn.Count | Should -Be 0
        }

        It "Should include never-logged-in when flag is set" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath `
                -IncludeNeverLoggedIn

            $report = Import-Csv -Path $script:TestReportPath
            $neverLoggedIn = $report | Where-Object { $_.SamAccountName -eq "neverloggedin" }
            $neverLoggedIn.Count | Should -Be 1
        }
    }

    Context "Edge case: Account exactly at threshold" {
        BeforeAll {
            Mock Get-ADUser {
                @(
                    [PSCustomObject]@{
                        SamAccountName     = "edgeuser"
                        DisplayName        = "Edge User"
                        whenCreated        = (Get-Date).AddYears(-1)
                        PasswordLastSet    = (Get-Date).AddDays(-90)
                        Description        = "Test edge case"
                        lastLogonTimestamp = (Get-Date).AddDays(-90).ToFileTime()
                    }
                )
            }
        }

        It "Should not include account at exactly threshold (uses greater than)" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath

            $report = Import-Csv -Path $script:TestReportPath
            $report.Count | Should -Be 0
        }
    }
}

Describe "Report Generation" {
    BeforeAll {
        Mock Get-ADDomainController { return @{ Name = "DC01" } }
        Mock Get-ADOrganizationalUnit { return $true }
        Mock Get-ADUser {
            @(
                [PSCustomObject]@{
                    SamAccountName     = "testuser"
                    DisplayName        = "Test User"
                    whenCreated        = (Get-Date).AddYears(-1)
                    PasswordLastSet    = (Get-Date).AddDays(-100)
                    Description        = "Test description"
                    lastLogonTimestamp = (Get-Date).AddDays(-100).ToFileTime()
                }
            )
        }
    }

    It "Should create CSV report" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath

        Test-Path $script:TestReportPath | Should -BeTrue
    }

    It "Should include required columns" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath

        $report = Import-Csv -Path $script:TestReportPath
        $report[0].PSObject.Properties.Name | Should -Contain "SamAccountName"
        $report[0].PSObject.Properties.Name | Should -Contain "DisplayName"
        $report[0].PSObject.Properties.Name | Should -Contain "Created"
        $report[0].PSObject.Properties.Name | Should -Contain "PasswordLastSet"
        $report[0].PSObject.Properties.Name | Should -Contain "Description"
        $report[0].PSObject.Properties.Name | Should -Contain "LastLogonDate"
        $report[0].PSObject.Properties.Name | Should -Contain "DaysInactive"
    }

    It "Should use default report path when not specified" {
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        $scriptContent | Should -Match 'DormantAccountDiscovery_\$timestamp\.csv'
    }
}

Describe "OutputFile Generation" {
    BeforeAll {
        Mock Get-ADDomainController { return @{ Name = "DC01" } }
        Mock Get-ADOrganizationalUnit { return $true }
        Mock Get-ADUser {
            @(
                [PSCustomObject]@{
                    SamAccountName     = "dormant1"
                    DisplayName        = "Dormant One"
                    whenCreated        = (Get-Date).AddYears(-1)
                    PasswordLastSet    = (Get-Date).AddDays(-100)
                    Description        = "First dormant"
                    lastLogonTimestamp = (Get-Date).AddDays(-100).ToFileTime()
                },
                [PSCustomObject]@{
                    SamAccountName     = "dormant2"
                    DisplayName        = "Dormant Two"
                    whenCreated        = (Get-Date).AddYears(-2)
                    PasswordLastSet    = (Get-Date).AddDays(-200)
                    Description        = "Second dormant"
                    lastLogonTimestamp = (Get-Date).AddDays(-150).ToFileTime()
                }
            )
        }
    }

    It "Should create output file when specified" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -OutputFile $script:TestOutputFile

        Test-Path $script:TestOutputFile | Should -BeTrue
    }

    It "Should contain only SamAccountNames" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -OutputFile $script:TestOutputFile

        $content = Get-Content -Path $script:TestOutputFile
        $content | Should -Contain "dormant1"
        $content | Should -Contain "dormant2"
        $content.Count | Should -Be 2
    }

    It "Should have one account per line" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -OutputFile $script:TestOutputFile

        $content = Get-Content -Path $script:TestOutputFile
        $content[0] | Should -Not -Match ","
        $content[1] | Should -Not -Match ","
    }

    It "Should be compatible with Disable-DormantADAccounts input format" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -OutputFile $script:TestOutputFile

        # Verify file can be read as simple account list
        $accounts = Get-Content -Path $script:TestOutputFile | Where-Object { $_.Trim() -ne '' }
        $accounts.Count | Should -Be 2
        $accounts | ForEach-Object { $_ | Should -Match "^[a-zA-Z0-9_-]+$" }
    }
}

Describe "DC Health Check" {
    Context "When DC is unreachable" {
        BeforeAll {
            Mock Get-ADDomainController { throw "Cannot contact domain" }
        }

        It "Should exit with error before processing" {
            $result = & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath `
                -ErrorAction SilentlyContinue 2>&1

            $result | Should -Match "Cannot connect to Active Directory"
        }
    }

    Context "When DC is reachable" {
        BeforeAll {
            Mock Get-ADDomainController { return @{ Name = "DC01" } }
            Mock Get-ADOrganizationalUnit { return $true }
            Mock Get-ADUser { return @() }
        }

        It "Should proceed with query" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath `
                -WarningAction SilentlyContinue 2>&1

            $LASTEXITCODE | Should -Be 0
        }
    }
}

Describe "Empty Results Handling" {
    BeforeAll {
        Mock Get-ADDomainController { return @{ Name = "DC01" } }
        Mock Get-ADOrganizationalUnit { return $true }
    }

    Context "When no enabled accounts in OU" {
        BeforeAll {
            Mock Get-ADUser { return @() }
        }

        It "Should exit gracefully with warning" {
            $result = & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath `
                -WarningAction SilentlyContinue 2>&1

            $LASTEXITCODE | Should -Be 0
        }
    }

    Context "When no dormant accounts found" {
        BeforeAll {
            Mock Get-ADUser {
                @(
                    [PSCustomObject]@{
                        SamAccountName     = "activeuser"
                        DisplayName        = "Active User"
                        whenCreated        = (Get-Date).AddYears(-1)
                        PasswordLastSet    = (Get-Date).AddDays(-10)
                        Description        = "Active user"
                        lastLogonTimestamp = (Get-Date).AddDays(-10).ToFileTime()
                    }
                )
            }
        }

        It "Should create empty report" {
            & $ScriptPath `
                -SearchBase $script:TestSearchBase `
                -DormantDays 90 `
                -ReportPath $script:TestReportPath

            $report = Import-Csv -Path $script:TestReportPath
            $report.Count | Should -Be 0
        }
    }
}

Describe "IncludeNeverLoggedIn Flag" {
    BeforeAll {
        Mock Get-ADDomainController { return @{ Name = "DC01" } }
        Mock Get-ADOrganizationalUnit { return $true }
        Mock Get-ADUser {
            @(
                [PSCustomObject]@{
                    SamAccountName     = "neverloggedin1"
                    DisplayName        = "Never Logged In 1"
                    whenCreated        = (Get-Date).AddDays(-30)
                    PasswordLastSet    = (Get-Date).AddDays(-30)
                    Description        = "New account 1"
                    lastLogonTimestamp = $null
                },
                [PSCustomObject]@{
                    SamAccountName     = "neverloggedin2"
                    DisplayName        = "Never Logged In 2"
                    whenCreated        = (Get-Date).AddDays(-60)
                    PasswordLastSet    = (Get-Date).AddDays(-60)
                    Description        = "New account 2"
                    lastLogonTimestamp = $null
                }
            )
        }
    }

    It "Should exclude never-logged-in accounts by default" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath

        $report = Import-Csv -Path $script:TestReportPath
        $report.Count | Should -Be 0
    }

    It "Should include never-logged-in accounts when flag is set" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -IncludeNeverLoggedIn

        $report = Import-Csv -Path $script:TestReportPath
        $report.Count | Should -Be 2
    }

    It "Should mark LastLogonDate as 'Never' for never-logged-in accounts" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -IncludeNeverLoggedIn

        $report = Import-Csv -Path $script:TestReportPath
        $report | ForEach-Object { $_.LastLogonDate | Should -Be "Never" }
    }

    It "Should mark DaysInactive as 'N/A' for never-logged-in accounts" {
        & $ScriptPath `
            -SearchBase $script:TestSearchBase `
            -DormantDays 90 `
            -ReportPath $script:TestReportPath `
            -IncludeNeverLoggedIn

        $report = Import-Csv -Path $script:TestReportPath
        $report | ForEach-Object { $_.DaysInactive | Should -Be "N/A" }
    }
}
