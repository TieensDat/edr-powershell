$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$LogDir = Join-Path $RepoRoot "PythonAgent\logs"
$PidFile = Join-Path $LogDir "python_agent.pid"

if (Test-Path $PidFile) {
    $pidValue = Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    $process = if ($pidValue) { Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue } else { $null }
    if ($process) {
        Write-Host "Process: running PID=$pidValue"
    }
    else {
        Write-Host "Process: PID file exists, but process is not running. PID=$pidValue"
    }
}
else {
    Write-Host "Process: no PID file"
}

try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:9001/health" -Method GET -TimeoutSec 3
    Write-Host "Health: OK"
    $health | ConvertTo-Json -Depth 4
}
catch {
    Write-Host "Health: unavailable"
    Write-Host $_.Exception.Message
}
