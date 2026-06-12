param(
    [ValidateSet("all", "tuning", "holdout")]
    [string]$Set = "tuning",
    [string]$SelectedTestsPath = "",
    [string]$ReportPath = "",
    [int]$TimeoutSeconds = 30,
    [int]$SettleSeconds = 5,
    [switch]$IncludeAdmin,
    [switch]$AdminOnly,
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$AgentUrl = "http://127.0.0.1:9001"
$AgentStartedByWrapper = $false
$AgentProcess = $null

function Test-AgentHealth {
    try {
        $health = Invoke-RestMethod -Uri "$AgentUrl/health" -Method GET -TimeoutSec 3
        return [bool]($health.status -eq "running")
    }
    catch {
        return $false
    }
}

if (-not (Test-AgentHealth)) {
    $logDir = Join-Path $ScriptDir "logs"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $stdoutLog = Join-Path $logDir "pythonagent_atomic_accuracy_$stamp.out.log"
    $stderrLog = Join-Path $logDir "pythonagent_atomic_accuracy_$stamp.err.log"
    $agentDir = Join-Path $RepoRoot "PythonAgent"

    $AgentProcess = Start-Process `
        -FilePath "python" `
        -ArgumentList "PythonAgent.py" `
        -WorkingDirectory $agentDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog `
        -PassThru

    $AgentStartedByWrapper = $true

    $ready = $false
    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Seconds 1
        if (Test-AgentHealth) {
            $ready = $true
            break
        }
    }

    if (-not $ready) {
        throw "PythonAgent did not become healthy within 25 seconds."
    }
}

try {
    if (-not $ReportPath) {
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $suffix = if ($AdminOnly) { "admin" } elseif ($IncludeAdmin) { "include_admin" } else { "non_admin" }
        $ReportPath = Join-Path $ScriptDir "atomic_accuracy_${Set}_${suffix}_report_$stamp.json"
    }

    $runner = Join-Path $ScriptDir "run_atomic_accuracy_tests.ps1"
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $runner,
        "-Set", $Set,
        "-ReportPath", $ReportPath,
        "-TimeoutSeconds", $TimeoutSeconds,
        "-SettleSeconds", $SettleSeconds
    )

    if ($SelectedTestsPath) {
        $args += @("-SelectedTestsPath", $SelectedTestsPath)
    }

    if ($IncludeAdmin) {
        $args += "-IncludeAdmin"
    }
    if ($AdminOnly) {
        $args += "-AdminOnly"
    }
    if ($SkipCleanup) {
        $args += "-SkipCleanup"
    }

    & "C:\Program Files\PowerShell\7\pwsh.exe" @args
    $exitCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }
    Write-Host "REPORT_PATH=$ReportPath"
    exit $exitCode
}
finally {
    if ($AgentStartedByWrapper -and $AgentProcess -and -not $AgentProcess.HasExited) {
        Stop-Process -Id $AgentProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "PYTHONAGENT_STOPPED=$($AgentProcess.Id)"
    }
}
