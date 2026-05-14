param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$TestRoot = (Join-Path $PSScriptRoot "runtime_event"),
    [int]$TimeoutSeconds = 15,
    [int]$SettleSeconds = 4,
    [string]$ReportPath = "",
    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"
$ExpectedPath = Join-Path $ScriptDir "expected_results.json"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "event_sensor_report.json"
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
            ok = [bool]($health.status -eq "running" -and $health.eventlog_4104_sensor)
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

function Get-MatchingEventSensorEvents {
    param([string]$Marker)

    if (-not (Test-Path $EventLogPath)) {
        return @()
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

                if ($event.source -ne "eventlog_4104_sensor") {
                    continue
                }

                $script = [string]$event.script
                $path = [string]$event.path
                if ($script.Contains($Marker) -or $path.Contains($Marker)) {
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
        $events = @(Get-MatchingEventSensorEvents -Marker $Marker)
        if ($events.Count -gt $BeforeCount) {
            return $events
        }
    } while ((Get-Date) -lt $deadline)

    return @(Get-MatchingEventSensorEvents -Marker $Marker)
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
        PassThru = $true
    }

    if ($ArgumentList -and $ArgumentList.Count -gt 0) {
        $params["ArgumentList"] = $ArgumentList
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
        "EV001" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Host '$Marker'") -Hidden -Wait | Out-Null }
        "EV002" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'") -Hidden -Wait | Out-Null }
        "EV003" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; Start-Sleep -Milliseconds 200") -Hidden -Wait | Out-Null }
        "EV004" { Start-TestProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Write-Output '$Marker'") -Hidden -Wait | Out-Null }
        "EV005" {
            $encoded = ConvertTo-EncodedPowerShellCommand "Write-Output '$Marker'"
            Start-TestProcess "powershell.exe" @("-NoProfile", "-EncodedCommand", $encoded) -Hidden -Wait | Out-Null
        }
        "EV006" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "IEX `"Write-Output '$Marker'`"") -Hidden -Wait | Out-Null }
        "EV007" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$u='http://127.0.0.1/$Marker'; Write-Output `$u; Invoke-WebRequest -UseBasicParsing `$u -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null") -Hidden -Wait | Out-Null }
        "EV008" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; Get-Date | Out-Null") -Hidden -Wait | Out-Null }
        "EV009" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$marker='$Marker'; Write-Output `$marker") -Hidden -Wait | Out-Null }
        "EV010" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "function Invoke-EvTest { '$Marker' }; Invoke-EvTest | Out-Null") -Hidden -Wait | Out-Null }
        "EV011" {
            $scriptPath = Join-Path $CaseDir "$Marker.ps1"
            Set-Content -Path $scriptPath -Value "Write-Output '$Marker'" -Encoding UTF8
            Start-TestProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath) -Hidden -Wait | Out-Null
        }
        "EV012" {
            $scriptPath = Join-Path $CaseDir "$Marker.ps1"
            Set-Content -Path $scriptPath -Value @("`$m='$Marker'", "Write-Output `$m", "Get-Date | Out-Null") -Encoding UTF8
            Start-TestProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath) -Hidden -Wait | Out-Null
        }
        "EV013" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "'$Marker' | ForEach-Object { Write-Output `$_ }") -Hidden -Wait | Out-Null }
        "EV014" {
            $blob = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("event-sensor-$Marker"))
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; `$b='$blob'") -Hidden -Wait | Out-Null
        }
        "EV015" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$x='Start-Process'; Write-Output '$Marker'") -Hidden -Wait | Out-Null }
        "EV016" { Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output `"quoted $Marker value`"") -Hidden -Wait | Out-Null }
        "EV017" {
            $command = @"
`$text = @'
$Marker
'@
Write-Output `$text
"@
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", $command) -Hidden -Wait | Out-Null
        }
        "EV018" { Start-TestProcess "powershell.exe" @("-NoProfile", "-NonInteractive", "-Command", "Write-Output '$Marker'") -Hidden -Wait | Out-Null }
        "EV019" { Start-TestProcess "cmd.exe" @("/c", "echo $Marker") -Hidden -Wait | Out-Null }
        "EV020" {
            $proc = Start-TestProcess "notepad.exe" @() -Hidden
            Start-Sleep -Seconds 1
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
if ($expectedCases.Count -eq 1 -and $expectedCases[0] -is [array]) {
    $expectedCases = @($expectedCases[0])
}
$runId = "EVRUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$runRoot = Join-Path $TestRoot $runId

New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$startedAt = Get-Date

foreach ($case in $expectedCases) {
    $caseId = [string]$case.id
    $caseDir = Join-Path $runRoot $caseId
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

    $marker = "$runId`_$caseId"
    $beforeEvents = @(Get-MatchingEventSensorEvents -Marker $marker)
    $beforeCount = $beforeEvents.Count
    $errorText = $null

    try {
        Invoke-TestAction -Id $caseId -Marker $marker -CaseDir $caseDir
    }
    catch {
        $errorText = $_.Exception.Message
    }

    if ($case.expected_event) {
        $events = @(Wait-ForEventIncrease -Marker $marker -BeforeCount $beforeCount -TimeoutSeconds $TimeoutSeconds)
    }
    else {
        Start-Sleep -Seconds $SettleSeconds
        $events = @(Get-MatchingEventSensorEvents -Marker $marker)
    }

    $afterCount = $events.Count
    $newEvents = @($events | Select-Object -Skip $beforeCount)
    $newCount = $afterCount - $beforeCount
    if ($newCount -lt 0) {
        $newCount = 0
    }

    $metadataComplete = $true
    if ($case.expected_event) {
        $metadataComplete = [bool](@($newEvents | Where-Object {
            $_.record_id -and $_.event_id -eq 4104 -and $_.script -and $_.sha256 -and $_.received_at_human
        }).Count -gt 0)
    }

    $passed = $false
    if ($null -eq $errorText) {
        if ($case.expected_event) {
            $passed = ($newCount -gt 0 -and $metadataComplete)
        }
        else {
            $passed = ($newCount -eq 0)
        }
    }

    $results.Add([pscustomobject]@{
        id = $caseId
        name = $case.name
        marker = $marker
        expected_event = [bool]$case.expected_event
        observed_new_events = $newCount
        observed_record_ids = @($newEvents | ForEach-Object { $_.record_id } | Where-Object { $_ } | Select-Object -Unique)
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

Write-Host "Event 4104 Sensor test report:"
Write-Host "  Total: $totalCount"
Write-Host "  Passed: $passedCount"
Write-Host "  Failed: $($totalCount - $passedCount)"
Write-Host "  Success rate: $successRate%"
Write-Host "  Report: $ReportPath"

if ($passedCount -ne $totalCount) {
    exit 1
}
