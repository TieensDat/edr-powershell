param(
    [ValidateSet("Synthetic", "Atomic", "Both")]
    [string]$Mode = "Synthetic",
    [int]$DurationSeconds = 120,
    [int]$IntervalMilliseconds = 1000,
    [string]$WorkloadRoot = "",
    [string]$AtomicRunnerPath = "",
    [string]$SelectedTestsPath = "",
    [string]$AtomicReportPath = "",
    [switch]$CleanupAfterRun
)

$ErrorActionPreference = "Stop"

if ($DurationSeconds -lt 5) {
    throw "DurationSeconds must be at least 5."
}

if ($IntervalMilliseconds -lt 100) {
    throw "IntervalMilliseconds must be at least 100."
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")

if (-not $WorkloadRoot) {
    $WorkloadRoot = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "edr_attack_workload"
}

if (-not $AtomicRunnerPath) {
    $AtomicRunnerPath = Join-Path $RepoRoot "tests\atomic_red_team\run_selected_atomic_tests.ps1"
}

if (-not $SelectedTestsPath) {
    $SelectedTestsPath = Join-Path $RepoRoot "tests\atomic_red_team\selected_atomic_tests.json"
}

if (-not $AtomicReportPath) {
    $AtomicReportPath = Join-Path $WorkloadRoot "attack_atomic_report.json"
}

$runId = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $WorkloadRoot "attack_workload_$runId"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

function Invoke-SyntheticAttackStep {
    param(
        [int]$Step,
        [string]$RunDir
    )

    $safeText = "benign suspicious telemetry simulation $Step"
    $encodedCommandText = "Write-Output '$safeText encoded-command'; Get-Date | Out-Null"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($encodedCommandText))

    & powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand | Out-Null

    $decodedPayload = "Write-Output '$safeText decoded-payload'"
    $base64Payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($decodedPayload))
    $fromBase64Command = '$p = "{0}"; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | Out-Null' -f $base64Payload

    & powershell -NoProfile -ExecutionPolicy Bypass -Command $fromBase64Command | Out-Null

    $iexCommand = '$cmd = "Write-Output ''{0} invoke-expression''"; Invoke-Expression $cmd | Out-Null' -f $safeText

    & powershell -NoProfile -ExecutionPolicy Bypass -Command $iexCommand | Out-Null

    $hiddenCommand = "Write-Output '$safeText hidden-window' | Out-Null"
    Start-Process -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-WindowStyle", "Hidden", "-Command", $hiddenCommand) `
        -WindowStyle Hidden `
        -Wait

    $scriptPath = Join-Path $RunDir ("benign_suspicious_{0:D4}.ps1" -f $Step)
    $scriptContent = @(
        "# Benign suspicious telemetry sample. This script is non-destructive.",
        "`$payload = '$base64Payload'",
        "`$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$payload))",
        "`$cmd = `"Write-Output '$safeText file-sensor-iex'`"",
        "Invoke-Expression `$cmd | Out-Null",
        "Get-Date | Out-Null"
    )

    Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8
    & powershell -NoProfile -ExecutionPolicy Bypass -File $scriptPath | Out-Null
}

function Invoke-SyntheticAttackWorkload {
    $stopAt = (Get-Date).AddSeconds($DurationSeconds)
    $iteration = 0

    while ((Get-Date) -lt $stopAt) {
        $iteration++
        Invoke-SyntheticAttackStep -Step $iteration -RunDir $runDir
        Start-Sleep -Milliseconds $IntervalMilliseconds
    }

    Write-Host "[ATTACK WORKLOAD] Synthetic iterations: $iteration"
}

function Invoke-AtomicWorkload {
    if (-not (Test-Path $AtomicRunnerPath)) {
        Write-Warning "Atomic runner not found: $AtomicRunnerPath"
        Write-Warning "Skipping Atomic mode. Use Synthetic mode or copy tests/atomic_red_team into the runtime package."
        return
    }

    if (-not (Test-Path $SelectedTestsPath)) {
        Write-Warning "Selected Atomic tests file not found: $SelectedTestsPath"
        Write-Warning "Skipping Atomic mode."
        return
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $AtomicReportPath) -Force | Out-Null

    Write-Host "[ATTACK WORKLOAD] Running Atomic Red Team selected tests..."
    & powershell -NoProfile -ExecutionPolicy Bypass `
        -File $AtomicRunnerPath `
        -SelectedTestsPath $SelectedTestsPath `
        -ReportPath $AtomicReportPath `
        -TimeoutSeconds 45 `
        -SettleSeconds 3
}

Write-Host "[ATTACK WORKLOAD] Started."
Write-Host "[ATTACK WORKLOAD] Mode: $Mode"
Write-Host "[ATTACK WORKLOAD] Duration: $DurationSeconds seconds"
Write-Host "[ATTACK WORKLOAD] Directory: $runDir"

if ($Mode -eq "Both") {
    $syntheticArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $MyInvocation.MyCommand.Path,
        "-Mode", "Synthetic",
        "-DurationSeconds", $DurationSeconds,
        "-IntervalMilliseconds", $IntervalMilliseconds,
        "-WorkloadRoot", $WorkloadRoot
    )

    if ($CleanupAfterRun) {
        $syntheticArgs += "-CleanupAfterRun"
    }

    Write-Host "[ATTACK WORKLOAD] Starting Synthetic workload in parallel with Atomic Red Team..."
    $syntheticProcess = Start-Process -FilePath "powershell" -ArgumentList $syntheticArgs -WindowStyle Hidden -PassThru
    try {
        Invoke-AtomicWorkload
        if ($null -ne $syntheticProcess -and -not $syntheticProcess.HasExited) {
            Wait-Process -Id $syntheticProcess.Id -Timeout ($DurationSeconds + 30) -ErrorAction SilentlyContinue
        }
    }
    finally {
        if ($null -ne $syntheticProcess -and -not $syntheticProcess.HasExited) {
            Stop-Process -Id $syntheticProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
elseif ($Mode -eq "Atomic") {
    Invoke-AtomicWorkload
}
elseif ($Mode -eq "Synthetic") {
    Invoke-SyntheticAttackWorkload
}

if ($CleanupAfterRun) {
    Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[ATTACK WORKLOAD] Cleanup completed."
}

Write-Host "[ATTACK WORKLOAD] Completed."
Write-Host "[ATTACK WORKLOAD] Directory: $runDir"
