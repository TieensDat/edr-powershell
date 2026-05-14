$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$LogDir = Join-Path $RepoRoot "PythonAgent\logs"
$PidFile = Join-Path $LogDir "python_agent.pid"

if (-not (Test-Path $PidFile)) {
    Write-Host "PID file not found. PythonAgent may not be running."
    exit 0
}

$pidValue = Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pidValue) {
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "PID file was empty."
    exit 0
}

$process = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
if ($process) {
    Stop-Process -Id ([int]$pidValue) -Force
    Write-Host "PythonAgent stopped. PID=$pidValue"
}
else {
    Write-Host "PythonAgent process not found. PID=$pidValue"
}

Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
