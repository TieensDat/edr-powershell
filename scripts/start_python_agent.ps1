param(
    [string]$WatchPaths = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$AgentDir = Join-Path $RepoRoot "PythonAgent"
$LogDir = Join-Path $AgentDir "logs"
$PidFile = Join-Path $LogDir "python_agent.pid"
$StdoutLog = Join-Path $LogDir "python_agent_stdout.log"
$StderrLog = Join-Path $LogDir "python_agent_stderr.log"

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

if (Test-Path $PidFile) {
    $existingPid = Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existingPid -and (Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue)) {
        if (-not $Force) {
            Write-Host "PythonAgent is already running. PID=$existingPid"
            exit 0
        }
        Stop-Process -Id ([int]$existingPid) -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

if ($WatchPaths) {
    $env:EDR_WATCH_PATHS = $WatchPaths
}

$process = Start-Process `
    -FilePath "python" `
    -ArgumentList @("-u", "PythonAgent.py") `
    -WorkingDirectory $AgentDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -PassThru

Set-Content -Path $PidFile -Value $process.Id -Encoding ASCII

Write-Host "PythonAgent started."
Write-Host "  PID: $($process.Id)"
Write-Host "  Health: http://127.0.0.1:9001/health"
Write-Host "  Stdout: $StdoutLog"
Write-Host "  Stderr: $StderrLog"
if ($WatchPaths) {
    Write-Host "  EDR_WATCH_PATHS: $WatchPaths"
}
