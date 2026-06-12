param(
    [int]$DurationSeconds = 120,
    [int]$IntervalMilliseconds = 750,
    [string]$WorkloadRoot = "",
    [switch]$CleanupAfterRun
)

$ErrorActionPreference = "Stop"

if ($DurationSeconds -lt 5) {
    throw "DurationSeconds must be at least 5."
}

if ($IntervalMilliseconds -lt 100) {
    throw "IntervalMilliseconds must be at least 100."
}

if (-not $WorkloadRoot) {
    $WorkloadRoot = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "edr_normal_workload"
}

$runId = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $WorkloadRoot "normal_workload_$runId"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

Write-Host "[WORKLOAD] Normal workload started."
Write-Host "[WORKLOAD] Duration: $DurationSeconds seconds"
Write-Host "[WORKLOAD] Directory: $runDir"

$stopAt = (Get-Date).AddSeconds($DurationSeconds)
$iteration = 0
$createdFiles = 0

while ((Get-Date) -lt $stopAt) {
    $iteration++

    $psFile = Join-Path $runDir ("benign_script_{0:D4}.ps1" -f $iteration)
    $txtFile = Join-Path $runDir ("note_{0:D4}.txt" -f $iteration)

    $scriptLines = @(
        "Write-Output 'Normal administrative script sample $iteration'",
        "Get-Date | Out-Null",
        "Get-ChildItem -Path `$env:USERPROFILE -ErrorAction SilentlyContinue | Select-Object -First 3 | Out-Null"
    )

    Set-Content -Path $psFile -Value $scriptLines -Encoding UTF8
    Add-Content -Path $psFile -Value "# benign update $iteration"
    Set-Content -Path $txtFile -Value "Normal workload note $iteration at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Encoding UTF8
    Get-Content -Path $txtFile -ErrorAction SilentlyContinue | Out-Null
    $createdFiles += 2

    if (($iteration % 5) -eq 0) {
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Date | Out-Null; Get-Process | Select-Object -First 5 | Out-Null"
    }

    Start-Sleep -Milliseconds $IntervalMilliseconds
}

if ($CleanupAfterRun) {
    Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[WORKLOAD] Cleanup completed."
}

Write-Host "[WORKLOAD] Completed."
Write-Host "[WORKLOAD] Iterations: $iteration"
Write-Host "[WORKLOAD] Files created: $createdFiles"
Write-Host "[WORKLOAD] Directory: $runDir"
