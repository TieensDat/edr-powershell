param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [int]$TimeoutSeconds = 12,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "ml_model_report.json"
}

function Get-AgentHealth {
    try {
        return Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
    }
    catch {
        return $null
    }
}

function Get-MatchingEvent {
    param([string]$Marker)

    if (-not (Test-Path $EventLogPath)) {
        return $null
    }

    $matches = New-Object System.Collections.Generic.List[object]
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
                    $event = $line | ConvertFrom-Json
                }
                catch {
                    continue
                }

                $script = [string]$event.script
                if ($script.Contains($Marker)) {
                    $matches.Add($event)
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

    return @($matches.ToArray()) | Select-Object -Last 1
}

function Wait-ForMatchingEvent {
    param(
        [string]$Marker,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $event = Get-MatchingEvent -Marker $Marker
        if ($event) {
            return $event
        }
    } while ((Get-Date) -lt $deadline)

    return $null
}

$runId = "MLRUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$marker = "${runId}_ML001"
$startedAt = Get-Date
$health = Get-AgentHealth

$script = @"
# $marker
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA
IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1/$marker.ps1")
[Convert]::FromBase64String("TVqQAAMAAAAEAAAA")
Set-MpPreference -DisableRealtimeMonitoring `$true
"@

$payload = @{
    source = "ml_model_test"
    pid = $PID
    ppid = 0
    process = "powershell.exe"
    parent_process = "manual_ml_test"
    sha256 = ""
    local_verdict = "ALLOW"
    script = $script
} | ConvertTo-Json -Compress

$response = $null
$postError = $null
try {
    $response = Invoke-RestMethod -Uri "$AgentUrl/telemetry" -Method POST -Body $payload -ContentType "application/json" -TimeoutSec 5
}
catch {
    $postError = $_.Exception.Message
}

$event = Wait-ForMatchingEvent -Marker $marker -TimeoutSeconds $TimeoutSeconds

$mlEnabled = [bool]($health -and $health.ml_enabled)
$mlVerdict = if ($response) { [string]$response.ml_verdict } else { "" }
$mlConfidence = if ($response) { [double]$response.ml_confidence } else { 0.0 }
$finalVerdict = if ($response) { [string]$response.verdict } else { "" }

$passed = (
    $mlEnabled -and
    $null -eq $postError -and
    $response -ne $null -and
    $mlVerdict -and
    $mlVerdict -ne "UNKNOWN" -and
    $mlConfidence -ge 0.0 -and
    $finalVerdict -in @("ALERT", "TERMINATE") -and
    $event -ne $null -and
    [bool]$event.ml_enabled
)

$report = [pscustomobject]@{
    run_id = $runId
    started_at = $startedAt.ToString("o")
    finished_at = (Get-Date).ToString("o")
    agent_url = $AgentUrl
    test_id = "ML001"
    marker = $marker
    agent_ml_enabled = $mlEnabled
    post_error = $postError
    response = $response
    event_found = [bool]$event
    event_ml_enabled = if ($event) { [bool]$event.ml_enabled } else { $false }
    event_ml_verdict = if ($event) { [string]$event.ml_verdict } else { "" }
    event_ml_confidence = if ($event) { [double]$event.ml_confidence } else { 0.0 }
    event_rule_verdict = if ($event) { [string]$event.rule_verdict } else { "" }
    event_final_verdict = if ($event) { [string]$event.final_verdict } else { "" }
    event_risk_level = if ($event) { [string]$event.data_analysis.risk_level } else { "" }
    passed = $passed
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "ML model classification test:"
Write-Host "  ML enabled: $mlEnabled"
Write-Host "  ML verdict: $mlVerdict"
Write-Host "  ML confidence: $mlConfidence"
Write-Host "  Final verdict: $finalVerdict"
Write-Host "  Event found: $([bool]$event)"
Write-Host "  Passed: $passed"
Write-Host "  Report: $ReportPath"

if (-not $passed) {
    exit 1
}
