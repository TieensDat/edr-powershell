param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$TestRoot = (Join-Path $PSScriptRoot "runtime_atomic"),
    [int]$TimeoutSeconds = 15,
    [string]$ReportPath = "",
    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"
$ExpectedPath = Join-Path $ScriptDir "expected_baseline.json"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "atomic_powershell_report.json"
}

function ConvertTo-EncodedPowerShellCommand {
    param([string]$Command)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
    return [Convert]::ToBase64String($bytes)
}

function Get-Severity {
    param([string]$Verdict)
    switch (($Verdict ?? "").ToUpperInvariant()) {
        "TERMINATE" { return 2 }
        "ALERT" { return 1 }
        default { return 0 }
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

function Get-MatchingEvents {
    param(
        [string]$Marker,
        [string[]]$ExtraNeedles = @()
    )

    if (-not (Test-Path $EventLogPath)) {
        return @()
    }

    $needles = @($Marker) + @($ExtraNeedles | Where-Object { $_ })
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

                $haystack = @(
                    [string]$event.script,
                    [string]$event.path,
                    [string]$event.process,
                    [string]$event.executable_path
                ) -join "`n"

                foreach ($needle in $needles) {
                    if ($haystack.Contains($needle)) {
                        $matches.Add($event)
                        break
                    }
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

function Wait-ForCaseEvents {
    param(
        [string]$Marker,
        [string[]]$ExtraNeedles,
        [int]$BeforeCount,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $events = @(Get-MatchingEvents -Marker $Marker -ExtraNeedles $ExtraNeedles)
        if ($events.Count -gt $BeforeCount) {
            return $events
        }
    } while ((Get-Date) -lt $deadline)

    return @(Get-MatchingEvents -Marker $Marker -ExtraNeedles $ExtraNeedles)
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
    if ($Wait) { $params["Wait"] = $true }
    if ($Hidden) { $params["WindowStyle"] = "Hidden" }
    return Start-Process @params
}

function Invoke-AtomicStyleCase {
    param(
        [string]$Id,
        [string]$Marker,
        [string]$CaseDir
    )

    $extraNeedles = @()

    switch ($Id) {
        "ART-PS-001" {
            $command = "Write-Output '$Marker'; Start-Sleep -Seconds 2"
            $encoded = ConvertTo-EncodedPowerShellCommand $command
            $extraNeedles += $encoded
            Start-TestProcess "powershell.exe" @("-NoProfile", "-EncodedCommand", $encoded) -Hidden -Wait | Out-Null
        }
        "ART-PS-002" {
            Start-TestProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Write-Output '$Marker'; Start-Sleep -Seconds 2") -Hidden -Wait | Out-Null
        }
        "ART-PS-003" {
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "IEX `"Write-Output '$Marker'`"") -Hidden -Wait | Out-Null
        }
        "ART-PS-004" {
            $literal = "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/$Marker.ps1')"
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "`$x=`"$literal`"; Write-Output `$x") -Hidden -Wait | Out-Null
        }
        "ART-PS-005" {
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker'; [Convert]::FromBase64String('TVqQAAMAAAAEAAAA') | Out-Null") -Hidden -Wait | Out-Null
        }
        "ART-PS-006" {
            $literal = "Set-MpPreference -DisableRealtimeMonitoring `$true # $Marker"
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output `"$literal`"") -Hidden -Wait | Out-Null
        }
        "ART-PS-007" {
            $literal = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static') # $Marker"
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output `"$literal`"") -Hidden -Wait | Out-Null
        }
        "ART-PS-008" {
            $literal = "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords' # $Marker"
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output `"$literal`"") -Hidden -Wait | Out-Null
        }
        "ART-PS-009" {
            $scriptPath = Join-Path $CaseDir "$Marker.ps1"
            Set-Content -Path $scriptPath -Value @(
                "# $Marker",
                "`$x = `"IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/$Marker.ps1')`"",
                "Write-Output `$x"
            ) -Encoding UTF8
            Start-Sleep -Seconds 2
            Start-TestProcess "powershell.exe" @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath) -Hidden -Wait | Out-Null
        }
        "ART-PS-010" {
            Start-TestProcess "powershell.exe" @("-NoProfile", "-Command", "Write-Output '$Marker benign control'; Get-Date | Out-Null") -Hidden -Wait | Out-Null
        }
        default {
            throw "Unknown atomic-style case: $Id"
        }
    }

    return $extraNeedles
}

$health = Test-AgentHealth
$expectedCases = @(Get-Content $ExpectedPath -Raw | ConvertFrom-Json)
$runId = "ATOMICRUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$runRoot = Join-Path $TestRoot $runId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$startedAt = Get-Date

foreach ($case in $expectedCases) {
    $caseDir = Join-Path $runRoot $case.id
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

    $marker = "$runId`_$($case.id)"
    $before = @(Get-MatchingEvents -Marker $marker)
    $beforeCount = $before.Count
    $errorText = $null
    $extraNeedles = @()

    try {
        $extraNeedles = @(Invoke-AtomicStyleCase -Id $case.id -Marker $marker -CaseDir $caseDir)
    }
    catch {
        $errorText = $_.Exception.Message
    }

    $events = @(Wait-ForCaseEvents -Marker $marker -ExtraNeedles $extraNeedles -BeforeCount $beforeCount -TimeoutSeconds $TimeoutSeconds)
    $newEvents = @($events | Select-Object -Skip $beforeCount)

    $sources = @($newEvents | ForEach-Object { $_.source } | Where-Object { $_ } | Select-Object -Unique)
    $finalVerdicts = @($newEvents | ForEach-Object { $_.final_verdict } | Where-Object { $_ } | Select-Object -Unique)
    $ruleVerdicts = @($newEvents | ForEach-Object { $_.rule_verdict } | Where-Object { $_ } | Select-Object -Unique)
    $mlVerdicts = @($newEvents | ForEach-Object { $_.ml_verdict } | Where-Object { $_ } | Select-Object -Unique)
    $mlEnabledSeen = [bool](@($newEvents | Where-Object { $_.ml_enabled }).Count -gt 0)

    $maxSeverity = 0
    foreach ($verdict in $finalVerdicts) {
        $severity = Get-Severity $verdict
        if ($severity -gt $maxSeverity) {
            $maxSeverity = $severity
        }
    }
    $expectedSeverity = Get-Severity ([string]$case.expected_min_verdict)
    $sourceMatched = [bool](@($sources | Where-Object { $_ -in @($case.expected_sources_any) }).Count -gt 0)
    $verdictMatched = $maxSeverity -ge $expectedSeverity
    if ($case.expected_max_verdict) {
        $expectedMaxSeverity = Get-Severity ([string]$case.expected_max_verdict)
        $verdictMatched = $verdictMatched -and ($maxSeverity -le $expectedMaxSeverity)
    }
    $mlMatched = (-not [bool]$case.expected_ml_enabled) -or $mlEnabledSeen
    $passed = ($null -eq $errorText -and $newEvents.Count -gt 0 -and $sourceMatched -and $verdictMatched -and $mlMatched)

    $results.Add([pscustomobject]@{
        id = $case.id
        technique = $case.technique
        name = $case.name
        marker = $marker
        expected_min_verdict = $case.expected_min_verdict
        expected_max_verdict = if ($case.expected_max_verdict) { [string]$case.expected_max_verdict } else { "" }
        expected_sources_any = @($case.expected_sources_any)
        observed_event_count = $newEvents.Count
        observed_sources = $sources
        observed_rule_verdicts = $ruleVerdicts
        observed_ml_verdicts = $mlVerdicts
        observed_final_verdicts = $finalVerdicts
        observed_max_severity = $maxSeverity
        ml_enabled_seen = $mlEnabledSeen
        passed = $passed
        error = $errorText
    })
}

$passedCount = @($results | Where-Object { $_.passed }).Count
$totalCount = $results.Count
$successRate = if ($totalCount -gt 0) { [math]::Round(($passedCount / $totalCount) * 100, 2) } else { 0 }

$report = [pscustomobject]@{
    run_id = $runId
    mode = "atomic-red-team-style-safe-powershell-simulation"
    note = "Uses safe local simulations aligned to common Atomic Red Team PowerShell techniques; no external Atomic Red Team module was installed on this host."
    started_at = $startedAt.ToString("o")
    finished_at = (Get-Date).ToString("o")
    agent_url = $AgentUrl
    agent_health_ok = [bool]$health.ok
    agent_ml_enabled = [bool]($health.detail -and $health.detail.ml_enabled)
    event_log_path = $EventLogPath
    test_root = $runRoot
    total = $totalCount
    passed = $passedCount
    failed = $totalCount - $passedCount
    success_rate_percent = $successRate
    expected_baseline_path = $ExpectedPath
    results = $results
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding UTF8

if (-not $KeepArtifacts) {
    Remove-Item -Path $runRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Atomic-style PowerShell scenario report:"
Write-Host "  Total: $totalCount"
Write-Host "  Passed: $passedCount"
Write-Host "  Failed: $($totalCount - $passedCount)"
Write-Host "  Success rate: $successRate%"
Write-Host "  Report: $ReportPath"

if ($passedCount -ne $totalCount) {
    exit 1
}
