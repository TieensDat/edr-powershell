param(
    [switch]$SkipPipInstall,
    [switch]$EnableScriptBlockLogging
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$AgentDir = Join-Path $RepoRoot "PythonAgent"
$LogDir = Join-Path $AgentDir "logs"
$QuarantineDir = Join-Path $AgentDir "quarantine"
$RequirementsPath = Join-Path $AgentDir "requirements.txt"

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null

if (-not $SkipPipInstall) {
    if (-not (Test-Path $RequirementsPath)) {
        throw "requirements.txt not found: $RequirementsPath"
    }

    Write-Host "[SETUP] Installing Python dependencies..."
    python -m pip install --upgrade pip
    python -m pip install -r $RequirementsPath
}

if ($EnableScriptBlockLogging) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    if (-not $isAdmin) {
        Write-Warning "Script Block Logging requires Administrator. Re-run PowerShell as Administrator."
    }
    else {
        Write-Host "[SETUP] Enabling PowerShell Script Block Logging..."
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
    }
}

Write-Host "[SETUP] Runtime setup completed."
Write-Host "  Repo root: $RepoRoot"
Write-Host "  PythonAgent: $AgentDir"
Write-Host "  Logs: $LogDir"
Write-Host "  Quarantine: $QuarantineDir"
