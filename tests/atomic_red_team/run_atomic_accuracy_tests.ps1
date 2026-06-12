param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$AtomicsPath = "C:\AtomicRedTeam\atomics",
    [string]$InvokeAtomicModulePath = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1",
    [string]$SelectedTestsPath = "",
    [ValidateSet("all", "tuning", "holdout")]
    [string]$Set = "tuning",
    [int]$TimeoutSeconds = 30,
    [int]$SettleSeconds = 5,
    [string]$ReportPath = "",
    [switch]$IncludeAdmin,
    [switch]$AdminOnly,
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"

if (-not $SelectedTestsPath) {
    $SelectedTestsPath = Join-Path $ScriptDir "expanded_atomic_accuracy_tests.json"
}
if (-not $ReportPath) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path $ScriptDir "atomic_accuracy_report_$stamp.json"
}

function Get-VerdictRank {
    param([string]$Verdict)

    if ([string]::IsNullOrWhiteSpace($Verdict)) {
        $Verdict = "ALLOW"
    }

    switch ($Verdict.ToUpperInvariant()) {
        "ALLOW" { return 0 }
        "ALERT" { return 1 }
        "TERMINATE" { return 2 }
        default { return -1 }
    }
}

function Test-AgentHealth {
    try {
        $health = Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
        return [pscustomobject]@{
            ok = [bool]($health.status -eq "running")
            detail = $health
            error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            ok = $false
            detail = $null
            error = $_.Exception.Message
        }
    }
}

function Read-EventLogSnapshot {
    if (-not (Test-Path $EventLogPath)) {
        return @()
    }

    $events = New-Object System.Collections.Generic.List[object]
    $stream = [System.IO.FileStream]::new($EventLogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = [System.IO.StreamReader]::new($stream)
        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }
                try {
                    $events.Add(($line | ConvertFrom-Json))
                }
                catch {
                    continue
                }
            }
        }
        finally {
            $reader.Close()
        }
    }
    finally {
        $stream.Close()
    }

    return @($events.ToArray())
}

function Get-NewEvents {
    param([int]$BeforeCount)

    $all = @(Read-EventLogSnapshot)
    if ($all.Count -le $BeforeCount) {
        return @()
    }
    return @($all | Select-Object -Skip $BeforeCount)
}

function Get-MaxVerdict {
    param([object[]]$Events)

    $max = "ALLOW"
    foreach ($event in $Events) {
        $verdict = ([string]$event.final_verdict).ToUpperInvariant()
        if ($verdict -eq "TERMINATE") {
            return "TERMINATE"
        }
        if ($verdict -eq "ALERT") {
            $max = "ALERT"
        }
    }
    return $max
}

function Invoke-CapturedAtomicCommand {
    param([scriptblock]$Script)

    $out = New-Object System.Collections.Generic.List[string]
    $oldOut = [Console]::Out
    $writer = New-Object System.IO.StringWriter
    [Console]::SetOut($writer)
    try {
        & $Script *>&1 | ForEach-Object { $out.Add([string]$_) }
    }
    finally {
        [Console]::SetOut($oldOut)
        $captured = $writer.ToString()
        if ($captured) {
            $out.Add($captured)
        }
        $writer.Dispose()
    }
    return ($out -join "`n")
}

function Test-AnyExpectedSource {
    param(
        [object[]]$ObservedSources,
        [object[]]$ExpectedSources
    )

    if (-not $ExpectedSources -or $ExpectedSources.Count -eq 0) {
        return $true
    }

    foreach ($source in $ObservedSources) {
        if ($ExpectedSources -contains $source) {
            return $true
        }
    }
    return $false
}

if (-not (Test-Path $SelectedTestsPath)) {
    throw "Selected tests file not found: $SelectedTestsPath"
}
if (-not (Test-Path $InvokeAtomicModulePath)) {
    throw "Invoke-Atomic module not found: $InvokeAtomicModulePath"
}

Import-Module powershell-yaml
Import-Module $InvokeAtomicModulePath

$health = Test-AgentHealth
if (-not $health.ok) {
    throw "PythonAgent is not reachable at $AgentUrl. Detail: $($health.error)"
}

$allTests = @(Get-Content $SelectedTestsPath -Raw | ConvertFrom-Json)
if ($Set -eq "all") {
    $tests = @($allTests)
}
else {
    $tests = @($allTests | Where-Object { ([string]$_.set) -eq $Set })
}

if ($AdminOnly) {
    $tests = @($tests | Where-Object { [bool]$_.run_as_admin })
}
elseif (-not $IncludeAdmin) {
    $tests = @($tests | Where-Object { -not [bool]$_.run_as_admin })
}

$startedAt = Get-Date
$results = New-Object System.Collections.Generic.List[object]

foreach ($test in $tests) {
    $technique = [string]$test.technique
    $testNumber = [string]$test.test_number
    $name = [string]$test.name
    $testId = if ($test.id) { [string]$test.id } else { "$technique-$testNumber" }

    $beforeEvents = @(Read-EventLogSnapshot)
    $beforeCount = $beforeEvents.Count
    $prereqOutput = ""
    $executionOutput = ""
    $cleanupOutput = ""
    $cleanupError = $null
    $errorText = $null
    $status = "UNKNOWN"

    try {
        $prereqOutput = Invoke-CapturedAtomicCommand {
            Invoke-AtomicTest $technique -TestNumbers $testNumber -PathToAtomicsFolder $AtomicsPath -CheckPrereqs
        }

        if ($prereqOutput -match "Prerequisites met") {
            $status = "EXECUTED"
            $executionOutput = Invoke-CapturedAtomicCommand {
                Invoke-AtomicTest $technique -TestNumbers $testNumber -PathToAtomicsFolder $AtomicsPath -TimeoutSeconds $TimeoutSeconds -NoExecutionLog
            }
            Start-Sleep -Seconds $SettleSeconds
        }
        else {
            $status = "SKIPPED_PREREQ"
        }
    }
    catch {
        $status = "ERROR"
        $errorText = $_.Exception.Message
    }

    $newEvents = @(Get-NewEvents -BeforeCount $beforeCount)
    $sources = @($newEvents | ForEach-Object { $_.source } | Where-Object { $_ } | Select-Object -Unique)
    $finalVerdicts = @($newEvents | ForEach-Object { $_.final_verdict } | Where-Object { $_ } | Select-Object -Unique)
    $ruleVerdicts = @($newEvents | ForEach-Object { $_.rule_verdict } | Where-Object { $_ } | Select-Object -Unique)
    $mlVerdicts = @($newEvents | ForEach-Object { $_.ml_verdict } | Where-Object { $_ } | Select-Object -Unique)
    $mlEnabledSeen = [bool](@($newEvents | Where-Object { $_.ml_enabled }).Count -gt 0)
    $observedMaxVerdict = Get-MaxVerdict -Events $newEvents

    $expectedTelemetry = if ($null -ne $test.expected_telemetry) { [bool]$test.expected_telemetry } else { $true }
    $telemetryPass = if ($status -eq "EXECUTED") {
        if ($expectedTelemetry) { $newEvents.Count -gt 0 } else { $newEvents.Count -eq 0 }
    }
    else {
        $false
    }

    $expectedSourcesAny = @($test.expected_sources_any)
    $sourcePass = if ($status -eq "EXECUTED" -and $telemetryPass) {
        Test-AnyExpectedSource -ObservedSources $sources -ExpectedSources $expectedSourcesAny
    }
    else {
        $false
    }

    $minVerdict = if ($test.expected_min_verdict) { [string]$test.expected_min_verdict } else { "ALLOW" }
    $maxVerdict = if ($test.expected_max_verdict) { [string]$test.expected_max_verdict } else { "TERMINATE" }
    $actualRank = Get-VerdictRank $observedMaxVerdict
    $minRank = Get-VerdictRank $minVerdict
    $maxRank = Get-VerdictRank $maxVerdict
    $verdictPass = if ($status -eq "EXECUTED" -and $telemetryPass) {
        ($actualRank -ge $minRank) -and ($actualRank -le $maxRank)
    }
    else {
        $false
    }

    $accuracyPass = ($status -eq "EXECUTED") -and $telemetryPass -and $sourcePass -and $verdictPass

    if (-not $SkipCleanup -and ($status -eq "EXECUTED" -or $status -eq "ERROR")) {
        try {
            $cleanupOutput = Invoke-CapturedAtomicCommand {
                Invoke-AtomicTest $technique -TestNumbers $testNumber -PathToAtomicsFolder $AtomicsPath -Cleanup
            }
        }
        catch {
            $cleanupError = $_.Exception.Message
        }
        Start-Sleep -Seconds $SettleSeconds
    }

    $results.Add([pscustomobject]@{
        id = $testId
        set = [string]$test.set
        category = [string]$test.category
        technique = $technique
        test_number = $testNumber
        name = $name
        status = $status
        accuracy_pass = $accuracyPass
        telemetry_pass = $telemetryPass
        source_pass = $sourcePass
        verdict_pass = $verdictPass
        error = $errorText
        observed_event_count = $newEvents.Count
        observed_sources = $sources
        expected_sources_any = $expectedSourcesAny
        observed_rule_verdicts = $ruleVerdicts
        observed_ml_verdicts = $mlVerdicts
        observed_final_verdicts = $finalVerdicts
        observed_max_verdict = $observedMaxVerdict
        expected_min_verdict = $minVerdict
        expected_max_verdict = $maxVerdict
        ml_enabled_seen = $mlEnabledSeen
        run_as_admin = [bool]$test.run_as_admin
        rationale = [string]$test.rationale
        prereq_output_tail = ($prereqOutput -split "`n" | Select-Object -Last 8) -join "`n"
        execution_output_tail = ($executionOutput -split "`n" | Select-Object -Last 12) -join "`n"
        cleanup_error = $cleanupError
        cleanup_output_tail = ($cleanupOutput -split "`n" | Select-Object -Last 8) -join "`n"
    }) | Out-Null
}

$resultArray = @($results.ToArray())
$executed = @($resultArray | Where-Object { $_.status -eq "EXECUTED" }).Count
$skipped = @($resultArray | Where-Object { $_.status -eq "SKIPPED_PREREQ" }).Count
$errors = @($resultArray | Where-Object { $_.status -eq "ERROR" }).Count
$accuracyPassed = @($resultArray | Where-Object { $_.accuracy_pass }).Count
$accuracyFailed = @($resultArray | Where-Object { $_.status -eq "EXECUTED" -and -not $_.accuracy_pass }).Count
$accuracyRate = if ($executed -gt 0) { [math]::Round(($accuracyPassed / $executed) * 100, 2) } else { 0 }

$report = [pscustomobject]@{
    run_id = "ATOMIC_ACCURACY_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    started_at = $startedAt.ToString("o")
    finished_at = (Get-Date).ToString("o")
    agent_url = $AgentUrl
    agent_health_ok = [bool]$health.ok
    agent_ml_enabled = [bool]($health.detail -and $health.detail.ml_enabled)
    atomics_path = $AtomicsPath
    selected_tests_path = $SelectedTestsPath
    selected_set = $Set
    include_admin = [bool]$IncludeAdmin
    admin_only = [bool]$AdminOnly
    cleanup_enabled = -not [bool]$SkipCleanup
    event_log_path = $EventLogPath
    total_selected = $tests.Count
    executed = $executed
    skipped_prereq = $skipped
    errors = $errors
    accuracy_passed = $accuracyPassed
    accuracy_failed = $accuracyFailed
    accuracy_rate_percent = $accuracyRate
    results = $resultArray
}

$report | ConvertTo-Json -Depth 12 | Set-Content -Path $ReportPath -Encoding UTF8

$csvPath = [System.IO.Path]::ChangeExtension($ReportPath, ".csv")
$resultArray | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Atomic accuracy report:"
Write-Host "  Set: $Set"
Write-Host "  Selected: $($tests.Count)"
Write-Host "  Executed: $executed"
Write-Host "  Skipped prereq: $skipped"
Write-Host "  Errors: $errors"
Write-Host "  Accuracy passed: $accuracyPassed"
Write-Host "  Accuracy failed: $accuracyFailed"
Write-Host "  Accuracy rate: $accuracyRate%"
Write-Host "  Report: $ReportPath"
Write-Host "  CSV: $csvPath"

$failed = @($resultArray | Where-Object { $_.status -eq "EXECUTED" -and -not $_.accuracy_pass })
if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed accuracy cases:"
    $failed |
        Select-Object id,category,technique,test_number,observed_event_count,observed_max_verdict,expected_min_verdict,expected_max_verdict,telemetry_pass,source_pass,verdict_pass |
        Format-Table -AutoSize
}

if ($errors -gt 0 -or $accuracyFailed -gt 0) {
    exit 1
}
