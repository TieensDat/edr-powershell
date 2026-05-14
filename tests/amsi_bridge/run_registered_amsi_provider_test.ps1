param(
    [string]$AgentConsolePath = "bin\AgentConsole.exe",
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$ReportPath = "",
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$PythonAgentDir = Join-Path $RepoRoot "PythonAgent"
$EventLogPath = Join-Path $PythonAgentDir "logs\edr_events.jsonl"
$CppLogPath = Join-Path $RepoRoot "edr_cpp_agent.log"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "registered_amsi_provider_report.json"
}

function Resolve-AgentConsolePath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path) -and (Test-Path $Path)) {
        return (Resolve-Path $Path).Path
    }

    $repoRelative = Join-Path $RepoRoot $Path
    if (Test-Path $repoRelative) {
        return (Resolve-Path $repoRelative).Path
    }

    return ""
}

function Get-AgentHealth {
    try {
        return Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
    }
    catch {
        return $null
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
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try { $events.Add(($line | ConvertFrom-Json)) } catch { continue }
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

function Wait-ForMarkerEvent {
    param(
        [string]$Marker,
        [int]$BeforeCount,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $events = @(Read-EventLogSnapshot)
        if ($events.Count -le $BeforeCount) { continue }

        $matches = @($events | Select-Object -Skip $BeforeCount | Where-Object {
            ([string]$_.source) -eq "amsi_cpp_bridge" -and ([string]$_.script).Contains($Marker)
        })

        if ($matches.Count -gt 0) {
            return $matches[-1]
        }
    } while ((Get-Date) -lt $deadline)

    return $null
}

function Test-CppLogContains {
    param([string]$Text)

    if (-not (Test-Path $CppLogPath)) {
        return $false
    }

    return [bool](Select-String -Path $CppLogPath -Pattern ([regex]::Escape($Text)) -Quiet)
}

$startedAt = Get-Date
$runId = "AMSI_REAL_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$marker = "${runId}_REGISTERED_PROVIDER"
$resolvedAgentConsole = Resolve-AgentConsolePath -Path $AgentConsolePath

$pythonProcess = $null
$cppProcess = $null
$targetProcess = $null
$pythonStartedByTest = $false
$previousResponseEnv = $env:EDR_ENABLE_RESPONSE

try {
    if (-not $resolvedAgentConsole) {
        throw "AgentConsole.exe not found at '$AgentConsolePath'."
    }

    $health = Get-AgentHealth
    if (-not $health) {
        $env:EDR_ENABLE_RESPONSE = "1"
        $pythonProcess = Start-Process `
            -FilePath "python" `
            -ArgumentList @("-u", "PythonAgent.py") `
            -WorkingDirectory $PythonAgentDir `
            -WindowStyle Hidden `
            -PassThru
        $pythonStartedByTest = $true

        for ($i = 0; $i -lt $TimeoutSeconds; $i++) {
            Start-Sleep -Seconds 1
            $health = Get-AgentHealth
            if ($health -and $health.status -eq "running") { break }
        }
    }

    if (-not $health -or $health.status -ne "running") {
        throw "PythonAgent is not healthy."
    }

    if (Test-Path $CppLogPath) {
        Remove-Item -Path $CppLogPath -Force -ErrorAction SilentlyContinue
    }

    $beforeCount = @(Read-EventLogSnapshot).Count
    $cppProcess = Start-Process -FilePath $resolvedAgentConsole -WorkingDirectory $RepoRoot -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2

    $payload = @"
# $marker
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
`$kernel = 'kernel32'
`$alloc = 'VirtualAlloc'
`$thread = 'CreateThread'
`$protect = '0x40'
[Convert]::FromBase64String("TVqQAAMAAAAEAAAA")
Start-Sleep -Seconds 60
"@

    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
    $targetProcess = Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-EncodedCommand", $encodedPayload) `
        -WindowStyle Hidden `
        -PassThru

    $event = Wait-ForMarkerEvent -Marker $marker -BeforeCount $beforeCount -TimeoutSeconds $TimeoutSeconds

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $targetAlive = [bool](Get-Process -Id $targetProcess.Id -ErrorAction SilentlyContinue)
        if (-not $targetAlive) { break }
    } while ((Get-Date) -lt $deadline)

    $targetAlive = [bool](Get-Process -Id $targetProcess.Id -ErrorAction SilentlyContinue)
    $cppSawAmsi = Test-CppLogContains -Text "[AMSI] PID=$($targetProcess.Id)"
    $cppTerminatedProcess = Test-CppLogContains -Text "[ACTION] Terminated suspicious process. PID=$($targetProcess.Id)"
    $cppForwardedPython = Test-CppLogContains -Text "[FORWARD] Sent telemetry to Python Agent."

    $passed = (
        $event -ne $null -and
        [string]$event.source -eq "amsi_cpp_bridge" -and
        [string]$event.final_verdict -in @("ALERT", "TERMINATE") -and
        $cppSawAmsi -and
        $cppForwardedPython -and
        $cppTerminatedProcess -and
        -not $targetAlive
    )

    $report = [ordered]@{
        run_id = $runId
        started_at = $startedAt.ToString("o")
        finished_at = (Get-Date).ToString("o")
        agent_url = $AgentUrl
        agent_console_path = $resolvedAgentConsole
        marker = $marker
        status = "EXECUTED"
        passed = $passed
        reason = if ($passed) { "Registered AMSI Provider produced telemetry through AgentConsole; PythonAgent logged amsi_cpp_bridge event; C++ Agent terminated target process." } else { "One or more registered AMSI checks failed." }
        python_started_by_test = $pythonStartedByTest
        python_health_ok = [bool]($health -and $health.status -eq "running")
        python_response_enabled = [bool]($health -and $health.response_enabled)
        event_found = [bool]$event
        event_source = if ($event) { [string]$event.source } else { "" }
        event_rule_verdict = if ($event) { [string]$event.rule_verdict } else { "" }
        event_ml_verdict = if ($event) { [string]$event.ml_verdict } else { "" }
        event_final_verdict = if ($event) { [string]$event.final_verdict } else { "" }
        event_response_action = if ($event) { [string]$event.response_action } else { "" }
        cpp_saw_amsi_pid = $cppSawAmsi
        cpp_forwarded_python = $cppForwardedPython
        cpp_terminated_process = $cppTerminatedProcess
        target_pid = $targetProcess.Id
        target_alive_after = $targetAlive
        cpp_log_path = $CppLogPath
        event_log_path = $EventLogPath
    }

    [pscustomobject]$report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding UTF8

    Write-Host "Registered AMSI Provider E2E test:"
    Write-Host "  Status: $($report.status)"
    Write-Host "  Passed: $($report.passed)"
    Write-Host "  Event found: $($report.event_found)"
    Write-Host "  Event source: $($report.event_source)"
    Write-Host "  Event final verdict: $($report.event_final_verdict)"
    Write-Host "  C++ saw AMSI PID: $($report.cpp_saw_amsi_pid)"
    Write-Host "  C++ forwarded Python: $($report.cpp_forwarded_python)"
    Write-Host "  C++ terminated target: $($report.cpp_terminated_process)"
    Write-Host "  Report: $ReportPath"

    if (-not $passed) {
        exit 1
    }
}
finally {
    if ($targetProcess -and (Get-Process -Id $targetProcess.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $targetProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($cppProcess -and (Get-Process -Id $cppProcess.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $cppProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($pythonProcess -and (Get-Process -Id $pythonProcess.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $pythonProcess.Id -Force -ErrorAction SilentlyContinue
    }
    $env:EDR_ENABLE_RESPONSE = $previousResponseEnv
}
