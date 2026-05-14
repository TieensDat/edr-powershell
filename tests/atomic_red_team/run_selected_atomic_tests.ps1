param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$AtomicsPath = "C:\AtomicRedTeam\atomics",
    [string]$InvokeAtomicModulePath = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1",
    [string]$SelectedTestsPath = "",
    [int]$TimeoutSeconds = 30,
    [int]$SettleSeconds = 5,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"

if (-not $SelectedTestsPath) {
    $SelectedTestsPath = Join-Path $ScriptDir "selected_atomic_tests.json"
}
if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "selected_atomic_report.json"
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

Import-Module powershell-yaml
Import-Module $InvokeAtomicModulePath

$health = Test-AgentHealth
$tests = @(Get-Content $SelectedTestsPath -Raw | ConvertFrom-Json)
$startedAt = Get-Date
$results = New-Object System.Collections.Generic.List[object]

foreach ($test in $tests) {
    $technique = [string]$test.technique
    $testNumber = [string]$test.test_number
    $name = [string]$test.name
    $testId = "$technique-$testNumber"

    $beforeEvents = @(Read-EventLogSnapshot)
    $beforeCount = $beforeEvents.Count
    $prereqOutput = ""
    $executionOutput = ""
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

    $passed = $false
    if ($status -eq "EXECUTED") {
        $passed = ($newEvents.Count -gt 0)
    }
    elseif ($status -eq "SKIPPED_PREREQ") {
        $passed = $true
    }

    $results.Add([pscustomobject]@{
        id = $testId
        technique = $technique
        test_number = $testNumber
        name = $name
        status = $status
        passed = $passed
        error = $errorText
        observed_event_count = $newEvents.Count
        observed_sources = $sources
        observed_rule_verdicts = $ruleVerdicts
        observed_ml_verdicts = $mlVerdicts
        observed_final_verdicts = $finalVerdicts
        observed_max_verdict = Get-MaxVerdict -Events $newEvents
        ml_enabled_seen = $mlEnabledSeen
        prereq_output_tail = ($prereqOutput -split "`n" | Select-Object -Last 8) -join "`n"
        execution_output_tail = ($executionOutput -split "`n" | Select-Object -Last 12) -join "`n"
    })
}

$executed = @($results | Where-Object { $_.status -eq "EXECUTED" }).Count
$skipped = @($results | Where-Object { $_.status -eq "SKIPPED_PREREQ" }).Count
$errors = @($results | Where-Object { $_.status -eq "ERROR" }).Count
$executedWithTelemetry = @($results | Where-Object { $_.status -eq "EXECUTED" -and $_.observed_event_count -gt 0 }).Count
$successRate = if ($executed -gt 0) { [math]::Round(($executedWithTelemetry / $executed) * 100, 2) } else { 0 }

$report = [pscustomobject]@{
    run_id = "SELECTED_ATOMIC_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    started_at = $startedAt.ToString("o")
    finished_at = (Get-Date).ToString("o")
    agent_url = $AgentUrl
    agent_health_ok = [bool]$health.ok
    agent_ml_enabled = [bool]($health.detail -and $health.detail.ml_enabled)
    atomics_path = $AtomicsPath
    selected_tests_path = $SelectedTestsPath
    event_log_path = $EventLogPath
    total_selected = $tests.Count
    executed = $executed
    skipped_prereq = $skipped
    errors = $errors
    executed_with_telemetry = $executedWithTelemetry
    telemetry_success_rate_percent = $successRate
    results = $results
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "Selected Atomic Red Team report:"
Write-Host "  Selected: $($tests.Count)"
Write-Host "  Executed: $executed"
Write-Host "  Skipped prereq: $skipped"
Write-Host "  Errors: $errors"
Write-Host "  Executed with telemetry: $executedWithTelemetry"
Write-Host "  Telemetry success rate: $successRate%"
Write-Host "  Report: $ReportPath"

if ($errors -gt 0 -or ($executed -gt 0 -and $executedWithTelemetry -lt $executed)) {
    exit 1
}
