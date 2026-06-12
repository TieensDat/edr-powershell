param(
    [switch]$Hidden
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
$ExePath = Join-Path $RepoRoot "bin\AgentConsole.exe"
$LogDir = Join-Path $RepoRoot "PythonAgent\logs"
$PidFile = Join-Path $LogDir "cpp_agent.pid"

if (-not (Test-Path $ExePath)) {
    throw "AgentConsole.exe not found: $ExePath"
}

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

if (Test-Path $PidFile) {
    $existingPid = Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existingPid -and (Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue)) {
        Write-Host "C++ Agent is already running. PID=$existingPid"
        exit 0
    }
}

$windowStyle = "Normal"
if ($Hidden) {
    $windowStyle = "Hidden"
}

$process = Start-Process `
    -FilePath $ExePath `
    -WorkingDirectory (Split-Path -Parent $ExePath) `
    -WindowStyle $windowStyle `
    -PassThru

Set-Content -Path $PidFile -Value $process.Id -Encoding ASCII

Write-Host "C++ Agent started."
Write-Host "  PID: $($process.Id)"
Write-Host "  EXE: $ExePath"
