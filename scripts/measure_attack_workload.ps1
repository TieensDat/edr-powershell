param(
    [string]$Label = "attack_workload_run",
    [ValidateSet("Synthetic", "Atomic", "Both")]
    [string]$Mode = "Synthetic",
    [int]$DurationSeconds = 120,
    [int]$SampleIntervalSeconds = 1,
    [int]$WorkloadIntervalMilliseconds = 1000,
    [string]$WorkloadRoot = "",
    [string]$AtomicRunnerPath = "",
    [string]$SelectedTestsPath = "",
    [string]$AtomicReportPath = "",
    [string]$OutputCsvPath = "",
    [switch]$CleanupAfterRun
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MeasureScript = Join-Path $ScriptDir "measure_performance.ps1"
$WorkloadScript = Join-Path $ScriptDir "run_attack_workload.ps1"

if (-not (Test-Path $MeasureScript)) {
    throw "measure_performance.ps1 not found: $MeasureScript"
}

if (-not (Test-Path $WorkloadScript)) {
    throw "run_attack_workload.ps1 not found: $WorkloadScript"
}

function New-WorkloadArgs {
    param([string]$WorkloadMode)

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $WorkloadScript,
        "-Mode", $WorkloadMode,
        "-DurationSeconds", $DurationSeconds,
        "-IntervalMilliseconds", $WorkloadIntervalMilliseconds
    )

    if ($WorkloadRoot) {
        $args += @("-WorkloadRoot", $WorkloadRoot)
    }

    if ($AtomicRunnerPath) {
        $args += @("-AtomicRunnerPath", $AtomicRunnerPath)
    }

    if ($SelectedTestsPath) {
        $args += @("-SelectedTestsPath", $SelectedTestsPath)
    }

    if ($AtomicReportPath) {
        $args += @("-AtomicReportPath", $AtomicReportPath)
    }

    if ($CleanupAfterRun) {
        $args += "-CleanupAfterRun"
    }

    return $args
}

$workloadProcesses = @()

Write-Host "[ATTACK MEASURE] Starting attack workload in background..."
Write-Host "[ATTACK MEASURE] Mode: $Mode"

if ($Mode -eq "Both") {
    $syntheticArgs = New-WorkloadArgs -WorkloadMode "Synthetic"
    $atomicArgs = New-WorkloadArgs -WorkloadMode "Atomic"

    $workloadProcesses += Start-Process -FilePath "powershell" -ArgumentList $syntheticArgs -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    $workloadProcesses += Start-Process -FilePath "powershell" -ArgumentList $atomicArgs -WindowStyle Hidden -PassThru
}
else {
    $workloadProcesses += Start-Process -FilePath "powershell" -ArgumentList (New-WorkloadArgs -WorkloadMode $Mode) -WindowStyle Hidden -PassThru
}

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
    foreach ($proc in $workloadProcesses) {
        if ($null -ne $proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "[ATTACK MEASURE] Completed."
