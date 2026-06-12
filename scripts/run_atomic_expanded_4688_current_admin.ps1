param(
    [ValidateSet("all", "tuning", "holdout")]
    [string]$Set = "all",
    [string]$ReportPath = "",
    [int]$TimeoutSeconds = 30,
    [int]$SettleSeconds = 5,
    [switch]$AdminOnly,
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script in a PowerShell session opened with Run as administrator."
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$AtomicDir = Join-Path $RepoRoot "tests\atomic_red_team"
$LogDir = Join-Path $AtomicDir "logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $ReportPath) {
    $ReportPath = Join-Path $AtomicDir "atomic_accuracy_${Set}_include_admin_current_admin_4688_report_$Stamp.json"
}
elseif (-not [System.IO.Path]::IsPathRooted($ReportPath)) {
    $ReportPath = Join-Path $RepoRoot $ReportPath
}

$TranscriptPath = Join-Path $LogDir "run_atomic_expanded_current_admin_4688_$Stamp.log"

Set-Location -LiteralPath $RepoRoot
Start-Transcript -Path $TranscriptPath -Force | Out-Null

try {
    Write-Host "[ADMIN-4688] Repo: $RepoRoot"
    Write-Host "[ADMIN-4688] Enabling Security Event ID 4688 process creation auditing..."
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\enable_process_creation_audit.ps1"
    if ($LASTEXITCODE -ne 0) {
        throw "enable_process_creation_audit.ps1 failed with exit code $LASTEXITCODE."
    }

    Write-Host "[ADMIN-4688] Stopping existing PythonAgent.py processes from this repo..."
    $agentDir = (Resolve-Path ".\PythonAgent").Path.ToLowerInvariant()
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.CommandLine -and
            $_.CommandLine.ToLowerInvariant().Contains("pythonagent.py") -and
            $_.CommandLine.ToLowerInvariant().Contains($agentDir)
        } |
        ForEach-Object {
            Write-Host "[ADMIN-4688] Stop PID $($_.ProcessId): $($_.CommandLine)"
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }

    Start-Sleep -Seconds 2

    $wrapper = Join-Path $AtomicDir "run_atomic_accuracy_with_agent.ps1"
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $wrapper,
        "-Set", $Set,
        "-TimeoutSeconds", $TimeoutSeconds,
        "-SettleSeconds", $SettleSeconds,
        "-ReportPath", $ReportPath
    )

    if ($AdminOnly) {
        $args += "-AdminOnly"
    }
    else {
        $args += "-IncludeAdmin"
    }

    if ($SkipCleanup) {
        $args += "-SkipCleanup"
    }

    Write-Host "[ADMIN-4688] Running Atomic accuracy set=$Set include-admin=$(-not $AdminOnly)..."
    & powershell @args
    $exitCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }
    Write-Host "[ADMIN-4688] Report: $ReportPath"
    Write-Host "[ADMIN-4688] Transcript: $TranscriptPath"

    if ($exitCode -ne 0) {
        throw "Atomic runner failed with exit code $exitCode."
    }
}
finally {
    Stop-Transcript | Out-Null
}
