param(
    [string]$FilesManifest = ".\datasets\the_stack\powershell_pilot\metadata\files_manifest.csv",
    [string]$OutputRoot = ".\datasets\the_stack\powershell_pilot\reports",
    [string]$AgentPath = ".\PythonAgent\PythonAgent.py",
    [int]$MaxBytes = 204800,
    [switch]$EnableML
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $FilesManifest)) {
    throw "Files manifest not found: $FilesManifest"
}

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}

$arguments = @(
    ".\tests\the_stack\evaluate_the_stack_static.py",
    "--files-manifest", $FilesManifest,
    "--agent-path", $AgentPath,
    "--output-dir", $OutputRoot,
    "--max-bytes", "$MaxBytes"
)

if ($EnableML) {
    $arguments += "--enable-ml"
}

Write-Host "[THE-STACK] Running static baseline..."
& python @arguments

$summaryPath = Join-Path $OutputRoot "evaluation_summary.json"
if (Test-Path -LiteralPath $summaryPath) {
    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "[THE-STACK] Summary"
    $summary | Format-List
}

$extensionSummary = Join-Path $OutputRoot "summary_by_extension.csv"
if (Test-Path -LiteralPath $extensionSummary) {
    Write-Host ""
    Write-Host "[THE-STACK] By extension"
    Import-Csv -LiteralPath $extensionSummary | Format-Table -AutoSize
}

$sizeSummary = Join-Path $OutputRoot "summary_by_size_bucket.csv"
if (Test-Path -LiteralPath $sizeSummary) {
    Write-Host ""
    Write-Host "[THE-STACK] By size bucket"
    Import-Csv -LiteralPath $sizeSummary | Format-Table -AutoSize
}
