param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$TestRoot = (Join-Path ([Environment]::GetFolderPath("MyDocuments")) "edr_file_sensor_tests"),
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
    $ReportPath = Join-Path $ScriptDir "file_sensor_report.json"
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
            ok = [bool]($health.status -eq "running" -and $health.file_sensor)
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

function Get-MatchingFileSensorEvents {
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

                if ($event.source -ne "file_sensor") {
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
        $events = @(Get-MatchingFileSensorEvents -Marker $Marker)
        if ($events.Count -gt $BeforeCount) {
            return $events
        }
    } while ((Get-Date) -lt $deadline)

    return @(Get-MatchingFileSensorEvents -Marker $Marker)
}

function Write-TextFile {
    param(
        [string]$Path,
        [string]$Content
    )
    Set-Content -Path $Path -Value $Content -Encoding UTF8
}

function Invoke-TestAction {
    param(
        [string]$Id,
        [string]$Marker,
        [string]$CaseDir
    )

    switch ($Id) {
        "FS001" { Write-TextFile (Join-Path $CaseDir "$Marker.ps1") "Write-Host '$Marker'; IEX 'Write-Host file-test'" }
        "FS002" { Write-TextFile (Join-Path $CaseDir "$Marker.psm1") "function Invoke-$($Id) { '$Marker' }" }
        "FS003" { Write-TextFile (Join-Path $CaseDir "$Marker.psd1") "@{ RootModule = '$Marker.psm1'; Description = '$Marker' }" }
        "FS004" { Write-TextFile (Join-Path $CaseDir "$Marker.js") "var marker = '$Marker';" }
        "FS005" { Write-TextFile (Join-Path $CaseDir "$Marker.vbs") "WScript.Echo ""$Marker""" }
        "FS006" { Write-TextFile (Join-Path $CaseDir "$Marker.bat") "echo $Marker" }
        "FS007" { Write-TextFile (Join-Path $CaseDir "$Marker.cmd") "echo $Marker" }

        "FS008" {
            $path = Join-Path $CaseDir "$Id-base.ps1"
            Write-TextFile $path "Write-Host 'baseline ps1'"
            Start-Sleep -Milliseconds 1500
            Write-TextFile $path "Write-Host '$Marker'; IEX 'Write-Host modified'"
        }
        "FS009" {
            $path = Join-Path $CaseDir "$Id-base.psm1"
            Write-TextFile $path "function Invoke-Baseline { 'baseline' }"
            Start-Sleep -Milliseconds 1500
            Add-Content -Path $path -Value "function Invoke-Changed { '$Marker' }" -Encoding UTF8
        }
        "FS010" {
            $path = Join-Path $CaseDir "$Id-base.psd1"
            Write-TextFile $path "@{ Description = 'baseline' }"
            Start-Sleep -Milliseconds 1500
            Write-TextFile $path "@{ Description = '$Marker' }"
        }
        "FS011" {
            $path = Join-Path $CaseDir "$Id-base.js"
            Write-TextFile $path "var baseline = true;"
            Start-Sleep -Milliseconds 1500
            Write-TextFile $path "var marker = '$Marker';"
        }

        "FS012" {
            $src = Join-Path $CaseDir "$Marker.tmp"
            $dst = Join-Path $CaseDir "$Marker.ps1"
            Write-TextFile $src "Write-Host '$Marker'"
            Move-Item -Path $src -Destination $dst
        }
        "FS013" {
            $src = Join-Path $CaseDir "$Marker.tmp"
            $dst = Join-Path $CaseDir "$Marker.psm1"
            Write-TextFile $src "function Invoke-Moved { '$Marker' }"
            Move-Item -Path $src -Destination $dst
        }
        "FS014" {
            $src = Join-Path $CaseDir "$Marker.tmp"
            $dst = Join-Path $CaseDir "$Marker.cmd"
            Write-TextFile $src "echo $Marker"
            Move-Item -Path $src -Destination $dst
        }
        "FS015" {
            $path = Join-Path $CaseDir "$Marker.ps1"
            $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes("Write-Host '$Marker'")
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush()
                Start-Sleep -Milliseconds 1200
            }
            finally {
                $stream.Close()
            }
        }

        "FS016" { Write-TextFile (Join-Path $CaseDir "$Marker.txt") "Write-Host '$Marker'" }
        "FS017" { Write-TextFile (Join-Path $CaseDir "$Marker.log") "Write-Host '$Marker'" }
        "FS018" { Write-TextFile (Join-Path $CaseDir "$Marker.csv") "script,$Marker" }
        "FS019" { New-Item -ItemType File -Path (Join-Path $CaseDir "$Marker.ps1") -Force | Out-Null }
        "FS020" {
            $path = Join-Path $CaseDir "$Marker.ps1"
            $chunk = "A" * 8192
            $writer = [System.IO.StreamWriter]::new($path, $false, [System.Text.Encoding]::UTF8)
            try {
                $writer.WriteLine("# $Marker")
                for ($i = 0; $i -lt 140; $i++) {
                    $writer.WriteLine($chunk)
                }
            }
            finally {
                $writer.Close()
            }
        }
        default {
            throw "Unknown test id: $Id"
        }
    }
}

$health = Test-AgentHealth
$expectedCases = @(Read-ExpectedCases)
$runId = "FSRUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$runRoot = Join-Path $TestRoot $runId

New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$startedAt = Get-Date

foreach ($case in $expectedCases) {
    $caseDir = Join-Path $runRoot $case.id
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

    $marker = "$runId`_$($case.id)"
    $beforeEvents = @(Get-MatchingFileSensorEvents -Marker $marker)
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
        $events = @(Get-MatchingFileSensorEvents -Marker $marker)
    }

    $afterCount = $events.Count
    $newEvents = @($events | Select-Object -Skip $beforeCount)
    $newCount = $afterCount - $beforeCount
    if ($newCount -lt 0) {
        $newCount = 0
    }

    $eventTypeMatched = $true
    if ($case.expected_event -and $case.expected_event_type) {
        $eventTypeMatched = [bool](@($newEvents | Where-Object { $_.file_event_type -eq $case.expected_event_type }).Count -gt 0)
    }

    $passed = $false
    if ($null -eq $errorText) {
        if ($case.expected_event) {
            $passed = ($newCount -gt 0 -and $eventTypeMatched)
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
        expected_event_type = [string]$case.expected_event_type
        observed_new_events = $newCount
        observed_event_types = @($newEvents | ForEach-Object { $_.file_event_type } | Where-Object { $_ } | Select-Object -Unique)
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

Write-Host "File Sensor test report:"
Write-Host "  Total: $totalCount"
Write-Host "  Passed: $passedCount"
Write-Host "  Failed: $($totalCount - $passedCount)"
Write-Host "  Success rate: $successRate%"
Write-Host "  Report: $ReportPath"

if ($passedCount -ne $totalCount) {
    exit 1
}
