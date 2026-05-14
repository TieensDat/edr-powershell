param(
    [string]$AgentConsolePath = "",
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$ReportPath = "",
    [int]$TimeoutSeconds = 20
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$PythonAgentDir = Join-Path $RepoRoot "PythonAgent"
$EventLogPath = Join-Path $PythonAgentDir "logs\edr_events.jsonl"
$CppLogPath = Join-Path $RepoRoot "edr_cpp_agent.log"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "amsi_bridge_e2e_report.json"
}

function Find-AgentConsole {
    param([string]$ExplicitPath)

    if ($ExplicitPath -and (Test-Path $ExplicitPath)) {
        return (Resolve-Path $ExplicitPath).Path
    }

    $candidates = @(
        "AgentConsole\x64\Release\AgentConsole.exe",
        "AgentConsole\x64\Debug\AgentConsole.exe",
        "x64\Release\AgentConsole.exe",
        "x64\Debug\AgentConsole.exe",
        "AgentConsole.exe",
        "CppAgent.exe"
    )

    foreach ($candidate in $candidates) {
        $path = Join-Path $RepoRoot $candidate
        if (Test-Path $path) {
            return (Resolve-Path $path).Path
        }
    }

    $found = Get-ChildItem -Path $RepoRoot -Recurse -Filter AgentConsole.exe -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) {
        return $found.FullName
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

function Get-Utf8Sha256 {
    param([string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    }
    finally {
        $sha.Dispose()
    }
}

function Copy-FixedAscii {
    param(
        [byte[]]$Buffer,
        [int]$Offset,
        [int]$Length,
        [string]$Value
    )

    if ($null -eq $Value) {
        $Value = ""
    }
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $copyLength = [Math]::Min($bytes.Length, $Length - 1)
    if ($copyLength -gt 0) {
        [Array]::Copy($bytes, 0, $Buffer, $Offset, $copyLength)
    }
}

function New-ScanMessageBytes {
    param(
        [uint32]$ScanPid,
        [uint32]$ParentPid,
        [string]$Process,
        [string]$ParentProcess,
        [string]$Sha256,
        [string]$Script
    )

    $size = 4 + 4 + 260 + 260 + 65 + 4096
    $buffer = New-Object byte[] $size

    [BitConverter]::GetBytes($ScanPid).CopyTo($buffer, 0)
    [BitConverter]::GetBytes($ParentPid).CopyTo($buffer, 4)
    Copy-FixedAscii -Buffer $buffer -Offset 8 -Length 260 -Value $Process
    Copy-FixedAscii -Buffer $buffer -Offset 268 -Length 260 -Value $ParentProcess
    Copy-FixedAscii -Buffer $buffer -Offset 528 -Length 65 -Value $Sha256
    Copy-FixedAscii -Buffer $buffer -Offset 593 -Length 4096 -Value $Script

    return $buffer
}

function Send-ScanMessageToPipe {
    param([byte[]]$MessageBytes)

    $client = [System.IO.Pipes.NamedPipeClientStream]::new(
        ".",
        "EdrAmsiPipe",
        [System.IO.Pipes.PipeDirection]::Out
    )

    try {
        $client.Connect($TimeoutSeconds * 1000)
        $client.Write($MessageBytes, 0, $MessageBytes.Length)
        $client.Flush()
    }
    finally {
        $client.Dispose()
    }
}

function Test-CppLogContains {
    param([string]$Text)

    if (-not (Test-Path $CppLogPath)) {
        return $false
    }

    return [bool](Select-String -Path $CppLogPath -Pattern ([regex]::Escape($Text)) -Quiet)
}

$startedAt = Get-Date
$runId = "AMSI_E2E_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$marker = "${runId}_REMOTE_TERMINATE"
$resolvedAgentConsole = Find-AgentConsole -ExplicitPath $AgentConsolePath

$reportBase = [ordered]@{
    run_id = $runId
    started_at = $startedAt.ToString("o")
    finished_at = ""
    agent_url = $AgentUrl
    agent_console_path = $resolvedAgentConsole
    marker = $marker
    status = ""
    passed = $false
    reason = ""
}

if (-not $resolvedAgentConsole) {
    $reportBase.status = "SKIPPED"
    $reportBase.reason = "AgentConsole.exe not found. Build AgentConsole first, then rerun this script with -AgentConsolePath."
    $reportBase.finished_at = (Get-Date).ToString("o")
    [pscustomobject]$reportBase | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Host "AMSI bridge E2E test skipped: AgentConsole.exe not found."
    Write-Host "Report: $ReportPath"
    exit 2
}

$pythonProcess = $null
$cppProcess = $null
$targetProcess = $null
$pipeWriteError = $null
$pythonStartedByTest = $false
$previousResponseEnv = $env:EDR_ENABLE_RESPONSE

try {
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

    $beforeCount = @(Read-EventLogSnapshot).Count

    if (Test-Path $CppLogPath) {
        Remove-Item -Path $CppLogPath -Force -ErrorAction SilentlyContinue
    }

    $cppProcess = Start-Process -FilePath $resolvedAgentConsole -WorkingDirectory $RepoRoot -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2

    $sleepCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Start-Sleep -Seconds 60"))
    $targetProcess = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-EncodedCommand", $sleepCommand) `
        -WindowStyle Hidden `
        -PassThru

    $script = @"
# $marker
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
`$kernel = 'kernel32'
`$alloc = 'VirtualAlloc'
`$thread = 'CreateThread'
`$protect = '0x40'
[Convert]::FromBase64String("TVqQAAMAAAAEAAAA")
"@

    $hash = Get-Utf8Sha256 -Text $script
    $messageBytes = New-ScanMessageBytes `
        -ScanPid ([uint32]$targetProcess.Id) `
        -ParentPid 0 `
        -Process "powershell.exe" `
        -ParentProcess "amsi_bridge_e2e_test" `
        -Sha256 $hash `
        -Script $script

    try {
        Send-ScanMessageToPipe -MessageBytes $messageBytes
    }
    catch {
        $pipeWriteError = $_.Exception.Message
    }

    $event = Wait-ForMarkerEvent -Marker $marker -BeforeCount $beforeCount -TimeoutSeconds $TimeoutSeconds

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $targetAlive = [bool](Get-Process -Id $targetProcess.Id -ErrorAction SilentlyContinue)
        if (-not $targetAlive) { break }
    } while ((Get-Date) -lt $deadline)

    $targetAlive = [bool](Get-Process -Id $targetProcess.Id -ErrorAction SilentlyContinue)
    $cppSawPythonTerminate = Test-CppLogContains -Text "[PYTHON_AGENT] verdict=TERMINATE"
    $cppTerminatedProcess = Test-CppLogContains -Text "[ACTION] Terminated suspicious process. PID=$($targetProcess.Id)"

    $passed = (
        $null -eq $pipeWriteError -and
        $event -ne $null -and
        [string]$event.source -eq "amsi_cpp_bridge" -and
        [string]$event.final_verdict -eq "TERMINATE" -and
        $cppSawPythonTerminate -and
        $cppTerminatedProcess -and
        -not $targetAlive
    )

    $report = [ordered]@{}
    foreach ($key in $reportBase.Keys) { $report[$key] = $reportBase[$key] }
    $report.finished_at = (Get-Date).ToString("o")
    $report.status = "EXECUTED"
    $report.passed = $passed
    $report.reason = if ($passed) { "C++ bridge received AMSI-style telemetry, Python returned TERMINATE, C++ Agent terminated target process." } else { "One or more E2E checks failed." }
    $report.python_started_by_test = $pythonStartedByTest
    $report.python_health_ok = [bool]($health -and $health.status -eq "running")
    $report.python_response_enabled = [bool]($health -and $health.response_enabled)
    $report.pipe_write_error = $pipeWriteError
    $report.event_found = [bool]$event
    $report.event_source = if ($event) { [string]$event.source } else { "" }
    $report.event_rule_verdict = if ($event) { [string]$event.rule_verdict } else { "" }
    $report.event_ml_verdict = if ($event) { [string]$event.ml_verdict } else { "" }
    $report.event_final_verdict = if ($event) { [string]$event.final_verdict } else { "" }
    $report.event_response_action = if ($event) { [string]$event.response_action } else { "" }
    $report.cpp_saw_python_terminate = $cppSawPythonTerminate
    $report.cpp_terminated_process = $cppTerminatedProcess
    $report.target_pid = $targetProcess.Id
    $report.target_alive_after = $targetAlive
    $report.cpp_log_path = $CppLogPath
    $report.event_log_path = $EventLogPath

    [pscustomobject]$report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding UTF8

    Write-Host "AMSI bridge E2E test:"
    Write-Host "  Status: $($report.status)"
    Write-Host "  Passed: $($report.passed)"
    Write-Host "  Event final verdict: $($report.event_final_verdict)"
    Write-Host "  C++ saw Python TERMINATE: $($report.cpp_saw_python_terminate)"
    Write-Host "  C++ terminated target: $($report.cpp_terminated_process)"
    Write-Host "  Target alive after: $($report.target_alive_after)"
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
