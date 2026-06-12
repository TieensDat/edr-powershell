param(
    [string]$RepoRoot = ".\datasets\fleschutz\PowerShell",
    [string]$FilesManifest = ".\datasets\fleschutz\powershell_scripts\metadata\files_manifest.csv",
    [string]$OutputRoot = ".\datasets\fleschutz\powershell_scripts\reports_ml_supplemental_current",
    [string]$AgentPath = ".\PythonAgent\PythonAgent.py",
    [switch]$EnableML,
    [int]$MaxFiles = 0,
    [int]$MaxBytes = 1048576
)

$ErrorActionPreference = "Stop"

Write-Host "[FLESCHUTZ] Creating manifest..."
python .\tests\fleschutz\collect_fleschutz_manifest.py `
    --repo-root $RepoRoot `
    --output $FilesManifest

$argsList = @(
    ".\tests\fleschutz\evaluate_fleschutz_static.py",
    "--files-manifest", $FilesManifest,
    "--agent-path", $AgentPath,
    "--output-dir", $OutputRoot,
    "--max-files", "$MaxFiles",
    "--max-bytes", "$MaxBytes"
)

if ($EnableML) {
    $argsList += "--enable-ml"
}

Write-Host "[FLESCHUTZ] Running static holdout baseline..."
python @argsList

Write-Host "[FLESCHUTZ] Summary:"
Get-Content (Join-Path $OutputRoot "evaluation_summary.json")

Write-Host "[FLESCHUTZ] Category summary:"
Import-Csv (Join-Path $OutputRoot "category_verdict_summary.csv") | Format-Table -AutoSize
