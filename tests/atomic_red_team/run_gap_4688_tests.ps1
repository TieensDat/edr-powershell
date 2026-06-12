param(
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script in an elevated PowerShell session."
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

if (-not $ReportPath) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path $ScriptDir "atomic_gap_4688_report_$stamp.json"
}

$auditScript = Join-Path $RepoRoot "scripts\enable_process_creation_audit.ps1"
$wrapper = Join-Path $ScriptDir "run_atomic_accuracy_with_agent.ps1"
$gapTests = Join-Path $ScriptDir "gap_4688_tests.json"

Write-Host "[GAP-4688] Enabling audit policy..."
powershell -NoProfile -ExecutionPolicy Bypass -File $auditScript

Start-Sleep -Seconds 2

Write-Host "[GAP-4688] Running gap Atomic cases..."
powershell `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $wrapper `
    -Set all `
    -SelectedTestsPath $gapTests `
    -ReportPath $ReportPath `
    -TimeoutSeconds 30 `
    -SettleSeconds 6

exit $LASTEXITCODE
