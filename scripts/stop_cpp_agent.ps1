$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$LogDir = Join-Path $RepoRoot "PythonAgent\logs"
$PidFile = Join-Path $LogDir "cpp_agent.pid"

if (-not (Test-Path $PidFile)) {
    Write-Host "C++ Agent PID file not found."
    exit 0
}

$pidValue = Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pidValue) {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "C++ Agent PID file was empty."
    exit 0
}

$proc = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
if ($proc) {
    Stop-Process -Id ([int]$pidValue) -Force
    Write-Host "C++ Agent stopped. PID=$pidValue"
}
else {
    Write-Host "C++ Agent is not running. PID=$pidValue"
}

Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
