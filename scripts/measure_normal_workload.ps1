param(
    [string]$Label = "normal_workload_run",
    [int]$DurationSeconds = 120,
    [int]$SampleIntervalSeconds = 1,
    [int]$WorkloadIntervalMilliseconds = 750,
    [string]$WorkloadRoot = "",
    [string]$OutputCsvPath = "",
    [switch]$CleanupAfterRun
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MeasureScript = Join-Path $ScriptDir "measure_performance.ps1"
$WorkloadScript = Join-Path $ScriptDir "run_normal_workload.ps1"

if (-not (Test-Path $MeasureScript)) {
    throw "measure_performance.ps1 not found: $MeasureScript"
}

if (-not (Test-Path $WorkloadScript)) {
    throw "run_normal_workload.ps1 not found: $WorkloadScript"
}

$workloadArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $WorkloadScript,
    "-DurationSeconds", $DurationSeconds,
    "-IntervalMilliseconds", $WorkloadIntervalMilliseconds
)

if ($WorkloadRoot) {
    $workloadArgs += @("-WorkloadRoot", $WorkloadRoot)
}

if ($CleanupAfterRun) {
    $workloadArgs += "-CleanupAfterRun"
}

Write-Host "[NORMAL MEASURE] Starting normal workload in background..."
$workloadProcess = Start-Process -FilePath "powershell" -ArgumentList $workloadArgs -WindowStyle Hidden -PassThru

try {
    Start-Sleep -Seconds 2

    $measureArgs = @{
        Label = $Label
        DurationSeconds = $DurationSeconds
        SampleIntervalSeconds = $SampleIntervalSeconds
    }

    if ($OutputCsvPath) {
        $measureArgs.OutputCsvPath = $OutputCsvPath
    }

    & $MeasureScript @measureArgs
}
finally {
    if ($null -ne $workloadProcess -and -not $workloadProcess.HasExited) {
        Stop-Process -Id $workloadProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[NORMAL MEASURE] Completed."
