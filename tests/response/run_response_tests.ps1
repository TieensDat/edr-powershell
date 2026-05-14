param(
    [string]$AgentUrl = "http://127.0.0.1:9001",
    [string]$ReportPath = "",
    [string]$TestRoot = "",
    [int]$TimeoutSeconds = 15
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$EventLogPath = Join-Path $RepoRoot "PythonAgent\logs\edr_events.jsonl"
$QuarantineIndexPath = Join-Path $RepoRoot "PythonAgent\logs\quarantine_index.jsonl"

if (-not $ReportPath) {
    $ReportPath = Join-Path $ScriptDir "response_report.json"
}
if (-not $TestRoot) {
    $TestRoot = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "edr_response_tests"
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

        $newEvents = @($events | Select-Object -Skip $BeforeCount)
        $matches = @($newEvents | Where-Object {
            ([string]$_.script).Contains($Marker) -or
            ([string]$_.path).Contains($Marker) -or
            ([string]$_.original_path).Contains($Marker) -or
            ([string]$_.quarantine_path).Contains($Marker)
        })

        if ($matches.Count -gt 0) {
            $successful = @($matches | Where-Object { [bool]$_.response_success })
            if ($successful.Count -gt 0) { return $successful[-1] }
            return $matches[-1]
        }
    } while ((Get-Date) -lt $deadline)

    return $null
}

function Invoke-AgentTelemetry {
    param([object]$Payload)

    $json = $Payload | ConvertTo-Json -Depth 8
    return Invoke-RestMethod -Uri "$AgentUrl/telemetry" -Method POST -Body $json -ContentType "application/json" -TimeoutSec 5
}

function New-EncodedPowerShellCommand {
    param([string]$Command)
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
}

function New-TerminateScript {
    param([string]$Marker)
    return "Write-Output '$Marker'; 'mimikatz sekurlsa logonpasswords' | Out-Null"
}

function New-AlertScript {
    param([string]$Marker)
    return "Write-Output '$Marker'; Invoke-WebRequest -UseBasicParsing http://127.0.0.1/$Marker -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null"
}

function New-AllowScript {
    param([string]$Marker)
    return "Write-Output '$Marker'"
}

function Test-QuarantineIndexForMarker {
    param([string]$Marker)

    if (-not (Test-Path $QuarantineIndexPath)) {
        return $false
    }

    $stream = [System.IO.FileStream]::new($QuarantineIndexPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = [System.IO.StreamReader]::new($stream)
        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if (-not [string]::IsNullOrWhiteSpace($line) -and $line.Contains($Marker)) {
                    return $true
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

    return $false
}

function Add-Result {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Marker,
        [object]$Event,
        [bool]$Passed,
        [hashtable]$Extra = @{}
    )

    $row = [ordered]@{
        id = $Id
        name = $Name
        marker = $Marker
        event_found = [bool]$Event
        final_verdict = if ($Event) { [string]$Event.final_verdict } else { "" }
        response_action = if ($Event) { [string]$Event.response_action } else { "" }
        response_success = if ($Event) { [bool]$Event.response_success } else { $false }
        response_reason = if ($Event) { [string]$Event.response_reason } else { "" }
        passed = $Passed
    }

    foreach ($key in $Extra.Keys) {
        $row[$key] = $Extra[$key]
    }

    $script:results.Add([pscustomobject]$row)
}

function Submit-And-Wait {
    param(
        [object]$Payload,
        [string]$Marker,
        [int]$BeforeCount
    )

    $postError = $null
    try {
        Invoke-AgentTelemetry -Payload $Payload | Out-Null
    }
    catch {
        $postError = $_.Exception.Message
    }

    $event = Wait-ForMarkerEvent -Marker $Marker -BeforeCount $BeforeCount -TimeoutSeconds $TimeoutSeconds
    return [pscustomobject]@{
        event = $event
        post_error = $postError
    }
}

function Start-SleepPowerShell {
    param([string]$Marker)
    $encoded = New-EncodedPowerShellCommand "Write-Output '$Marker'; Start-Sleep -Seconds 30"
    return Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded) -WindowStyle Hidden -PassThru
}

$health = Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
$runId = "RSRUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$runRoot = Join-Path $TestRoot $runId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$startedAt = Get-Date

# RS001: process_sensor + TERMINATE -> process is terminated.
$marker = "$runId`_RS001"
$beforeCount = @(Read-EventLogSnapshot).Count
$proc = Start-SleepPowerShell -Marker $marker
$payload = [pscustomobject]@{
    source = "process_sensor"; pid = $proc.Id; ppid = 0; process = "powershell.exe"; parent_process = "response_test"
    script = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand test # $marker [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
$alive = [bool](Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
if ($alive) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Add-Result "RS001" "process terminate on TERMINATE verdict" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "TERMINATE" -and $result.event.response_action -eq "TERMINATE_PROCESS" -and [bool]$result.event.response_success -and -not $alive) `
    @{ process_alive_after = $alive; post_error = $result.post_error }

# RS002: file_sensor + TERMINATE -> file is quarantined.
$marker = "$runId`_RS002"
$caseDir = Join-Path $runRoot "RS002"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
$filePath = Join-Path $caseDir "$marker.ps1"
$script = New-TerminateScript -Marker $marker
$beforeCount = @(Read-EventLogSnapshot).Count
Set-Content -Path $filePath -Value $script -Encoding ASCII
$payload = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    path = $filePath; file_event_type = "created"; script = $script; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
$fileExists = Test-Path $filePath
$quarantinePath = if ($result.event) { [string]$result.event.quarantine_path } else { "" }
$quarantineExists = if ($quarantinePath) { Test-Path $quarantinePath } else { $false }
$quarantineIndexFound = Test-QuarantineIndexForMarker -Marker $marker
$quarantineEvidence = $quarantineExists -or $quarantineIndexFound
$quarantineReasonOk = $result.event -and $result.event.response_reason -in @("final_verdict_TERMINATE", "already_quarantined")
Add-Result "RS002" "file quarantine on TERMINATE verdict" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "TERMINATE" -and $result.event.response_action -eq "QUARANTINE_FILE" -and [bool]$result.event.response_success -and $quarantineReasonOk -and -not $fileExists -and $quarantineEvidence) `
    @{ file_exists_after = $fileExists; quarantine_path = $quarantinePath; quarantine_exists = $quarantineExists; quarantine_index_found = $quarantineIndexFound; post_error = $result.post_error }

# RS003: process_sensor + ALERT -> no kill.
$marker = "$runId`_RS003"
$beforeCount = @(Read-EventLogSnapshot).Count
$proc = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
$payload = [pscustomobject]@{
    source = "process_sensor"; pid = $proc.Id; ppid = 0; process = "notepad.exe"; parent_process = "response_test"
    script = "$(New-AllowScript -Marker $marker)"
    local_verdict = "ALERT"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
$alive = [bool](Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
if ($alive) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Add-Result "RS003" "ALERT process should not be killed" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "ALERT" -and $result.event.response_action -eq "NONE" -and $alive) `
    @{ process_alive_after = $alive; post_error = $result.post_error }

# RS004: file_sensor + ALERT -> no quarantine.
$marker = "$runId`_RS004"
$caseDir = Join-Path $runRoot "RS004"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
$filePath = Join-Path $caseDir "$marker.ps1"
$script = New-AlertScript -Marker $marker
Set-Content -Path $filePath -Value $script -Encoding ASCII
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    path = $filePath; file_event_type = "created"; script = $script; local_verdict = "ALERT"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
$fileExists = Test-Path $filePath
Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
Add-Result "RS004" "ALERT file should not be quarantined" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "ALERT" -and $result.event.response_action -eq "NONE" -and $fileExists) `
    @{ file_exists_after = $fileExists; post_error = $result.post_error }

# RS005: file_sensor + ALLOW -> no quarantine.
$marker = "$runId`_RS005"
$caseDir = Join-Path $runRoot "RS005"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
$filePath = Join-Path $caseDir "$marker.ps1"
$script = New-AllowScript -Marker $marker
Set-Content -Path $filePath -Value $script -Encoding ASCII
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    path = $filePath; file_event_type = "created"; script = $script; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
$fileExists = Test-Path $filePath
Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
Add-Result "RS005" "ALLOW file should not be quarantined" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "ALLOW" -and $result.event.response_action -eq "NONE" -and $fileExists) `
    @{ file_exists_after = $fileExists; post_error = $result.post_error }

# RS006: eventlog_4104_sensor + TERMINATE -> LOG_ONLY.
$marker = "$runId`_RS006"
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "eventlog_4104_sensor"; pid = 0; ppid = 0; process = "powershell_eventlog"; parent_process = ""
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS006" "eventlog TERMINATE should be LOG_ONLY" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "TERMINATE" -and $result.event.response_action -eq "LOG_ONLY" -and [bool]$result.event.response_success) `
    @{ post_error = $result.post_error }

# RS007: amsi_cpp_bridge + TERMINATE -> delegated to C++ Agent.
$marker = "$runId`_RS007"
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "amsi_cpp_bridge"; pid = 0; ppid = 0; process = "powershell.exe"; parent_process = "response_test"
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "TERMINATE"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS007" "amsi TERMINATE should be delegated" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "TERMINATE" -and $result.event.response_action -eq "DELEGATED_TO_CPP_AGENT" -and [bool]$result.event.response_success) `
    @{ post_error = $result.post_error }

# RS008: protected commandline should not be killed.
$marker = "$runId`_RS008"
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "process_sensor"; pid = $PID; ppid = 0; process = "powershell.exe"; parent_process = "response_test"
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS008" "protected commandline should not be killed" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "TERMINATE" -and $result.event.response_action -eq "TERMINATE_PROCESS" -and -not [bool]$result.event.response_success -and $result.event.response_reason -eq "protected_commandline") `
    @{ post_error = $result.post_error }

# RS009: agent self PID should not be killed.
$marker = "$runId`_RS009"
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "process_sensor"; pid = [int]$health.agent_pid; ppid = 0; process = "python.exe"; parent_process = "response_test"
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS009" "agent self PID should not be killed" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.final_verdict -eq "TERMINATE" -and $result.event.response_action -eq "TERMINATE_PROCESS" -and -not [bool]$result.event.response_success -and $result.event.response_reason -eq "refuse_to_terminate_self") `
    @{ post_error = $result.post_error }

# RS010: missing PID.
$marker = "$runId`_RS010"
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "process_sensor"; pid = 0; ppid = 0; process = "powershell.exe"; parent_process = "response_test"
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS010" "missing PID should be logged" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.response_action -eq "TERMINATE_PROCESS" -and -not [bool]$result.event.response_success -and $result.event.response_reason -eq "missing_pid") `
    @{ post_error = $result.post_error }

# RS011: missing path.
$marker = "$runId`_RS011"
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS011" "missing file path should be logged" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.response_action -eq "QUARANTINE_FILE" -and -not [bool]$result.event.response_success -and $result.event.response_reason -eq "missing_path") `
    @{ post_error = $result.post_error }

# RS012: outside watch path should not be quarantined.
$marker = "$runId`_RS012"
$caseDir = Join-Path $RepoRoot "tests\response\runtime_outside_watch\$runId"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
$outsidePath = Join-Path $caseDir "$marker.ps1"
$script = New-TerminateScript -Marker $marker
Set-Content -Path $outsidePath -Value $script -Encoding ASCII
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    path = $outsidePath; file_event_type = "created"; script = $script; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
$outsideExists = Test-Path $outsidePath
Remove-Item -Path $outsidePath -Force -ErrorAction SilentlyContinue
Add-Result "RS012" "outside watch path should not be quarantined" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.response_action -eq "QUARANTINE_FILE" -and -not [bool]$result.event.response_success -and $result.event.response_reason -eq "path_outside_watch_scope" -and $outsideExists) `
    @{ file_exists_after = $outsideExists; post_error = $result.post_error }

# RS013: repeated event for already quarantined path should not be treated as crash/failure.
$markerA = "$runId`_RS013A"
$markerB = "$runId`_RS013B"
$caseDir = Join-Path $runRoot "RS013"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
$filePath = Join-Path $caseDir "$markerA.ps1"
$scriptA = New-TerminateScript -Marker $markerA
$scriptB = New-TerminateScript -Marker $markerB
Set-Content -Path $filePath -Value $scriptA -Encoding ASCII
$beforeCount = @(Read-EventLogSnapshot).Count
$payloadA = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    path = $filePath; file_event_type = "created"; script = $scriptA; local_verdict = "ALLOW"
}
Submit-And-Wait -Payload $payloadA -Marker $markerA -BeforeCount $beforeCount | Out-Null
$beforeCount = @(Read-EventLogSnapshot).Count
$payloadB = [pscustomobject]@{
    source = "file_sensor"; pid = 0; ppid = 0; process = "file_system"; parent_process = "response_test"
    path = $filePath; file_event_type = "modified"; script = $scriptB; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payloadB -Marker $markerB -BeforeCount $beforeCount
Add-Result "RS013" "already quarantined path should be idempotent" $markerB $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.response_action -eq "QUARANTINE_FILE" -and [bool]$result.event.response_success -and $result.event.response_reason -eq "already_quarantined") `
    @{ post_error = $result.post_error }

# RS014: process already exited.
$marker = "$runId`_RS014"
$shortProc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-Command", "Write-Output '$marker'") -WindowStyle Hidden -PassThru -Wait
$beforeCount = @(Read-EventLogSnapshot).Count
$payload = [pscustomobject]@{
    source = "process_sensor"; pid = $shortProc.Id; ppid = 0; process = "powershell.exe"; parent_process = "response_test"
    script = "$(New-TerminateScript -Marker $marker)"; local_verdict = "ALLOW"
}
$result = Submit-And-Wait -Payload $payload -Marker $marker -BeforeCount $beforeCount
Add-Result "RS014" "already exited process should be logged" $marker $result.event `
    ($null -eq $result.post_error -and $result.event -and $result.event.response_action -eq "TERMINATE_PROCESS" -and -not [bool]$result.event.response_success -and $result.event.response_reason -eq "process_not_running") `
    @{ post_error = $result.post_error }

# RS015: agent remains healthy after response actions.
$marker = "$runId`_RS015"
$postHealth = $null
$healthError = $null
try {
    $postHealth = Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
}
catch {
    $healthError = $_.Exception.Message
}
Add-Result "RS015" "agent health remains OK after response" $marker $null `
    ($null -eq $healthError -and $postHealth.status -eq "running" -and [bool]$postHealth.response_enabled) `
    @{ health_error = $healthError; health_status = if ($postHealth) { [string]$postHealth.status } else { "" } }

$passed = @($results | Where-Object { $_.passed }).Count
$report = [pscustomobject]@{
    run_id = $runId
    started_at = $startedAt.ToString("o")
    finished_at = (Get-Date).ToString("o")
    agent_url = $AgentUrl
    response_enabled = [bool]$health.response_enabled
    quarantine_path = [string]$health.quarantine_path
    total = $results.Count
    passed = $passed
    failed = $results.Count - $passed
    success_rate_percent = if ($results.Count -gt 0) { [math]::Round(($passed / $results.Count) * 100, 2) } else { 0 }
    results = $results
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "PythonAgent response test report:"
Write-Host "  Total: $($report.total)"
Write-Host "  Passed: $($report.passed)"
Write-Host "  Failed: $($report.failed)"
Write-Host "  Success rate: $($report.success_rate_percent)%"
Write-Host "  Report: $ReportPath"

if ($report.failed -gt 0) {
    exit 1
}
