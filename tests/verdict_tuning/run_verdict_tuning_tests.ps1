param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$CasesPath = "",
    [string]$ReportPath = "",
    [int]$TimeoutSeconds = 5
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $CasesPath) {
    $CasesPath = Join-Path $ScriptDir "verdict_tuning_cases.json"
}
if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "verdict_tuning_report.json"
}

function Invoke-AgentTelemetry {
    param([object]$Payload)

    $json = $Payload | ConvertTo-Json -Depth 12
    return Invoke-RestMethod -Uri "$AgentUrl/telemetry" -Method POST -Body $json -ContentType "application/json" -TimeoutSec $TimeoutSeconds
}

function Test-AgentHealth {
    try {
        $health = Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec $TimeoutSeconds
        return [bool]($health.status -eq "running")
    }
    catch {
        return $false
    }
}

if (-not (Test-Path $CasesPath)) {
    throw "Cases file not found: $CasesPath"
}

if (-not (Test-AgentHealth)) {
    throw "PythonAgent is not reachable at $AgentUrl. Start PythonAgent before running verdict tuning tests."
}

$loadedCases = Get-Content -Raw -LiteralPath $CasesPath | ConvertFrom-Json
if ($loadedCases -is [System.Array]) {
    $cases = $loadedCases
}
else {
    $cases = @($loadedCases)
}
$runId = "VTUNE_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$startedAt = Get-Date
$results = New-Object System.Collections.Generic.List[object]

foreach ($case in $cases) {
    $marker = "$runId`_$($case.id)"
    $script = ([string]$case.script).Replace("{{MARKER}}", $marker)

    $payload = [ordered]@{
        source = [string]$case.source
        pid = 0
        ppid = 0
        process = [string]$case.process
        parent_process = "verdict_tuning_runner"
        script = $script
        local_verdict = "ALLOW"
        marker = $marker
        tuning_case_id = [string]$case.id
        tuning_category = [string]$case.category
    }

    $actualVerdict = "ERROR"
    $status = "error"
    $errorText = ""
    $response = $null

    try {
        $response = Invoke-AgentTelemetry -Payload $payload
        $actualVerdict = [string]$response.verdict
        $status = [string]$response.status
    }
    catch {
        $errorText = $_.Exception.Message
    }

    $expected = [string]$case.expected_final_verdict
    $passed = ($actualVerdict -eq $expected)

    $results.Add([pscustomobject]@{
        id = [string]$case.id
        category = [string]$case.category
        name = [string]$case.name
        source = [string]$case.source
        expected_final_verdict = $expected
        actual_final_verdict = $actualVerdict
        passed = $passed
        response_status = $status
        rule_verdict = if ($response) { [string]$response.rule_verdict } else { "" }
        ml_enabled = if ($response) { [bool]$response.ml_enabled } else { $false }
        ml_verdict = if ($response) { [string]$response.ml_verdict } else { "" }
        ml_confidence = if ($response) { [double]$response.ml_confidence } else { 0.0 }
        risk_level = if ($response) { [string]$response.risk_level } else { "" }
        risk_score = if ($response) { [double]$response.risk_score } else { 0.0 }
        raw_risk_score = if ($response) { [double]$response.raw_risk_score } else { 0.0 }
        benign_score = if ($response) { [double]$response.benign_score } else { 0.0 }
        marker = $marker
        error = $errorText
        severity_policy = [string]$case.severity_policy
        tuning_note = [string]$case.tuning_note
    }) | Out-Null

    Start-Sleep -Milliseconds 300
}

$finishedAt = Get-Date
$resultArray = @($results.ToArray())
$failed = @($resultArray | Where-Object { -not $_.passed })

$summary = [ordered]@{
    run_id = $runId
    started_at = $startedAt.ToString("o")
    finished_at = $finishedAt.ToString("o")
    agent_url = $AgentUrl
    cases_path = (Resolve-Path $CasesPath).Path
    total = $resultArray.Count
    passed = @($resultArray | Where-Object { $_.passed }).Count
    failed = $failed.Count
    pass_rate_percent = if ($resultArray.Count -gt 0) { [Math]::Round(((@($resultArray | Where-Object { $_.passed }).Count / $resultArray.Count) * 100), 2) } else { 0 }
    results = $resultArray
}

$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

$csvPath = [System.IO.Path]::ChangeExtension($ReportPath, ".csv")
$resultArray | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "[VERDICT TUNING] Run ID: $runId"
Write-Host "[VERDICT TUNING] Total: $($summary.total)"
Write-Host "[VERDICT TUNING] Passed: $($summary.passed)"
Write-Host "[VERDICT TUNING] Failed: $($summary.failed)"
Write-Host "[VERDICT TUNING] Pass rate: $($summary.pass_rate_percent)%"
Write-Host "[VERDICT TUNING] Report: $ReportPath"
Write-Host "[VERDICT TUNING] CSV: $csvPath"

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "[VERDICT TUNING] Failed cases:"
    $failed | Select-Object id,category,expected_final_verdict,actual_final_verdict,rule_verdict,ml_verdict,risk_level,tuning_note | Format-Table -AutoSize
}
