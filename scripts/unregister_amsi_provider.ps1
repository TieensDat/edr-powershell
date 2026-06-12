param(
    [string]$DllPath = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")

if (-not $DllPath) {
    $DllPath = Join-Path $RepoRoot "bin\AmsiProvider.dll"
}

if (-not (Test-Path $DllPath)) {
    throw "AmsiProvider.dll not found: $DllPath"
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    throw "Unregistering AMSI Provider requires Administrator. Re-run PowerShell as Administrator."
}

Write-Host "[AMSI] Unregistering provider: $DllPath"
$regsvr32 = Join-Path $env:WINDIR "System32\regsvr32.exe"
$proc = Start-Process -FilePath $regsvr32 -ArgumentList @("/s", "/u", $DllPath) -Wait -PassThru -WindowStyle Hidden

if ($proc.ExitCode -ne 0) {
    throw "regsvr32 /u failed with exit code $($proc.ExitCode)"
}

Write-Host "[AMSI] Provider unregistered successfully."
