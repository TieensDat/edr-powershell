param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$TestRoot = (Join-Path $PSScriptRoot "runtime_process"),
    [int]$TimeoutSeconds = 12,
    [int]$SettleSeconds = 3,
    [string]$ReportPath = "",
    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"
$ExpectedPath = Join-Path $ScriptDir "expected_results.json"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "process_sensor_report.json"
}

function Read-ExpectedCases {
    if (-not (Test-Path $ExpectedPath)) {
        throw "Expected result file not found: $ExpectedPath"
    }
    return Get-Content $ExpectedPath -Raw | ConvertFrom-Json
}

function Test-AgentHealth {
    try {
        $health = Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
        return [pscustomobject]@{
            ok = [bool]($health.status -eq "running" -and $health.process_sensor)
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

function Get-MatchingProcessSensorEvents {
    param([string]$Marker)

    if (-not (Test-Path $EventLogPath)) {
        return @()
    }

    $encodedMarkerCommand = ConvertTo-EncodedPowerShellCommand "Write-Output '$Marker'; Start-Sleep -Seconds 2"
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

                if ($event.source -ne "process_sensor") {
                    continue
                }

                $script = [string]$event.script
                $process = [string]$event.process
                $path = [string]$event.executable_path
                if ($script.Contains($Marker) -or $script.Contains($encodedMarkerCommand) -or $process.Contains($Marker) -or $path.Contains($Marker)) {
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

    return @($matches.ToArray())
}

function Wait-ForEventIncrease {
    param(
        [string]$Marker,
        [int]$BeforeCount,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $events = @(Get-MatchingProcessSensorEvents -Marker $Marker)
        if ($events.Count -gt $BeforeCount) {
            return $events
        }
    } while ((Get-Date) -lt $deadline)

    return @(Get-MatchingProcessSensorEvents -Marker $Marker)
}

function ConvertTo-EncodedPowerShellCommand {
    param([string]$Command)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
    return [Convert]::ToBase64String($bytes)
}

function Start-TestProcess {
    param(
        [string]$FilePath,
        [object[]]$ArgumentList,
        [switch]$Wait,
        [switch]$Hidden
    )

    $params = @{
        FilePath = $FilePath
        ArgumentList = $ArgumentList
        PassThru = $true
    }

    if ($Wait) {
        $params["Wait"] = $true
    }
    if ($Hidden) {
        $params["WindowStyle"] = "Hidden"
    }

    return Start-Process @params
}

function Invoke-TestAction {
    param(
        [string]$Id,
        [string]$Marker,
        [string]$CaseDir
    )

    switch ($Id) {
        "PS001" { Start-TestProcess "powershell.exe" @("-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS002" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS003" { Start-TestProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS004" {
            $encoded = ConvertTo-EncodedPowerShellCommand "Write-Output '$Marker'; Start-Sleep -Seconds 2"
            Start-TestProcess "powershell.exe" @("-NoProfile", "-EncodedCommand", $encoded) -Hidden | Out-Null
        }
        "PS005" { Start-TestProcess "powershell.exe" @("-NoProfile", "-WindowStyle", "Hidden", "-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS006" {
            $long = "X" * 180
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$m='$Marker'; `$x='$long'; Write-Output `$m; Start-Sleep -Seconds 2") -Hidden | Out-Null
        }
        "PS007" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output `"quoted $Marker value`"; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS008" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "IEX `"Write-Output '$Marker'`"; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS009" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$u='http://127.0.0.1/$Marker'; Write-Output `$u; Invoke-WebRequest -UseBasicParsing `$u -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS010" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; `$x='Start-Process'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS011" {
            $scriptPath = Join-Path $CaseDir "$Marker.ps1"
            Set-Content -Path $scriptPath -Value "param([string]`$MarkerArg); Write-Output `$MarkerArg; Start-Sleep -Seconds 2" -Encoding UTF8
            Start-TestProcess "powershell.exe" @("-NoProfile", "-File", $scriptPath, "-MarkerArg", $Marker) -Hidden | Out-Null
        }
        "PS012" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$marker='$Marker'; Write-Output `$marker; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS013" { Start-TestProcess "powershell.exe" @("-NoPrOfIlE", "-ExEcUtIoNpOlIcY", "Bypass", "-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS014" { Start-TestProcess "powershell.exe" @("-NoProfile", "-NonInteractive", "-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS015" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; Get-Date | Out-Null; Start-Sleep -Seconds 2") -Hidden | Out-Null }
        "PS016" {
            $blob = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("process-sensor-$Marker"))
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; `$b='$blob'; Start-Sleep -Seconds 2") -Hidden | Out-Null
        }
        "PS017" { Start-TestProcess "cmd.exe" @("/c", "echo $Marker") -Hidden -Wait | Out-Null }
        "PS018" {
            $proc = Start-TestProcess "notepad.exe" @() -Hidden
            Start-Sleep -Seconds 1
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
        "PS019" { Start-TestProcess "timeout.exe" @("/T", "1", "/NOBREAK") -Hidden -Wait | Out-Null }
        "PS020" {
            $proc = Start-TestProcess "powershell.exe" @() -Hidden
            Start-Sleep -Seconds 2
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
        default {
            throw "Unknown test id: $Id"
        }
    }
}

$health = Test-AgentHealth
$expectedCases = @(Read-ExpectedCases)
$runId = "PSRUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$runRoot = Join-Path $TestRoot $runId

New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$startedAt = Get-Date

foreach ($case in $expectedCases) {
    $caseDir = Join-Path $runRoot $case.id
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

    $marker = "$runId`_$($case.id)"
    $beforeEvents = @(Get-MatchingProcessSensorEvents -Marker $marker)
    $beforeCount = $beforeEvents.Count
    $errorText = $null

    try {
        Invoke-TestAction -Id $case.id -Marker $marker -CaseDir $caseDir
    }
    catch {
        $errorText = $_.Exception.Message
    }

    if ($case.expected_event) {
        $events = @(Wait-ForEventIncrease -Marker $marker -BeforeCount $beforeCount -TimeoutSeconds $TimeoutSeconds)
    }
    else {
        Start-Sleep -Seconds $SettleSeconds
        $events = @(Get-MatchingProcessSensorEvents -Marker $marker)
    }

    $afterCount = $events.Count
    $newEvents = @($events | Select-Object -Skip $beforeCount)
    $newCount = $afterCount - $beforeCount
    if ($newCount -lt 0) {
        $newCount = 0
    }

    $processMatched = $true
    if ($case.expected_event -and $case.expected_process) {
        $expectedProcess = [string]$case.expected_process
        $processMatched = [bool](@($newEvents | Where-Object { ([string]$_.process).ToLowerInvariant() -eq $expectedProcess.ToLowerInvariant() }).Count -gt 0)
    }

    $metadataComplete = $true
    if ($case.expected_event) {
        $metadataComplete = [bool](@($newEvents | Where-Object {
            $_.pid -and $_.ppid -ne $null -and $_.process -and $_.script -and $_.sha256 -and $_.received_at_human
        }).Count -gt 0)
    }

    $passed = $false
    if ($null -eq $errorText) {
        if ($case.expected_event) {
            $passed = ($newCount -gt 0 -and $processMatched -and $metadataComplete)
        }
        else {
            $passed = ($newCount -eq 0)
        }
    }

    $results.Add([pscustomobject]@{
        id = $case.id
        name = $case.name
        marker = $marker
        expected_event = [bool]$case.expected_event
        expected_process = [string]$case.expected_process
        observed_new_events = $newCount
        observed_processes = @($newEvents | ForEach-Object { $_.process } | Where-Object { $_ } | Select-Object -Unique)
        metadata_complete = $metadataComplete
        passed = $passed
        error = $errorText
    })
}

$passedCount = @($results | Where-Object { $_.passed }).Count
$totalCount = $results.Count
$successRate = if ($totalCount -gt 0) { [math]::Round(($passedCount / $totalCount) * 100, 2) } else { 0 }

$report = [pscustomobject]@{
    run_id = $runId
    started_at = $startedAt.ToString("o")
    finished_at = (Get-Date).ToString("o")
    agent_url = $AgentUrl
    agent_health_ok = [bool]$health.ok
    agent_health_error = $health.error
    event_log_path = $EventLogPath
    test_root = $runRoot
    total = $totalCount
    passed = $passedCount
    failed = $totalCount - $passedCount
    success_rate_percent = $successRate
    results = $results
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8

if (-not $KeepArtifacts) {
    try {
        Remove-Item -Path $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Keep artifacts if cleanup fails.
    }
}

Write-Host "Process Sensor test report:"
Write-Host "  Total: $totalCount"
Write-Host "  Passed: $passedCount"
Write-Host "  Failed: $($totalCount - $passedCount)"
Write-Host "  Success rate: $successRate%"
Write-Host "  Report: $ReportPath"

if ($passedCount -ne $totalCount) {
    exit 1
}
