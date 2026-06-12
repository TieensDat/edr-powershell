param(
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$LogDir = Join-Path $RepoRoot "tests\atomic_red_team\logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$InnerScript = Join-Path $LogDir "run_atomic_expanded_elevated_4688_$Stamp.ps1"
$TranscriptPath = Join-Path $LogDir "run_atomic_expanded_elevated_4688_$Stamp.log"

$inner = @"
`$ErrorActionPreference = "Stop"
Set-Location -LiteralPath "$RepoRoot"
Start-Transcript -Path "$TranscriptPath" -Force

try {
    `$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    `$isAdmin = `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not `$isAdmin) {
        throw "This script must run as Administrator."
    }

    Write-Host "[ELEVATED] Repo: $RepoRoot"
    Write-Host "[ELEVATED] Enabling 4688 process creation audit..."
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\enable_process_creation_audit.ps1"

    Write-Host "[ELEVATED] Stopping existing PythonAgent.py processes from this repo, if any..."
    `$repoAgentPath = (Resolve-Path ".\PythonAgent\PythonAgent.py").Path.ToLowerInvariant()
    Get-CimInstance Win32_Process |
        Where-Object {
            `$_.CommandLine -and
            `$_.CommandLine.ToLowerInvariant().Contains("pythonagent.py") -and
            `$_.CommandLine.ToLowerInvariant().Contains((Split-Path `$repoAgentPath -Parent).ToLowerInvariant())
        } |
        ForEach-Object {
            Write-Host "[ELEVATED] Stopping PID `$(`$_.ProcessId): `$(`$_.CommandLine)"
            Stop-Process -Id `$_.ProcessId -Force -ErrorAction SilentlyContinue
        }

    Start-Sleep -Seconds 2

    `$reportPath = Join-Path "$RepoRoot" ("tests\atomic_red_team\atomic_accuracy_all_include_admin_elevated_4688_report_$Stamp.json")
    Write-Host "[ELEVATED] Running Atomic expanded include-admin..."
    `$atomicArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ".\tests\atomic_red_team\run_atomic_accuracy_with_agent.ps1",
        "-Set", "all",
        "-IncludeAdmin",
        "-TimeoutSeconds", "30",
        "-SettleSeconds", "5",
        "-ReportPath", `$reportPath
    )
    & powershell @atomicArgs
    if (`$LASTEXITCODE -ne 0) {
        throw "Atomic expanded runner failed with exit code `$LASTEXITCODE."
    }

    Write-Host "[ELEVATED] Report path: `$reportPath"
}
catch {
    Write-Error `$_.Exception.Message
    exit 1
}
finally {
    Stop-Transcript
}

if (-not $NoPause) {
    Read-Host "Press Enter to close this elevated window"
}
"@

Set-Content -LiteralPath $InnerScript -Value $inner -Encoding UTF8

Write-Host "[LAUNCHER] Starting elevated PowerShell window..."
Write-Host "[LAUNCHER] Inner script: $InnerScript"
Write-Host "[LAUNCHER] Transcript: $TranscriptPath"

Start-Process `
    -FilePath "powershell.exe" `
    -Verb RunAs `
    -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$InnerScript`""
    )

Write-Host "[LAUNCHER] UAC prompt should appear. Accept it, then wait for the elevated window to finish."
Write-Host "[LAUNCHER] After it finishes, inspect: $TranscriptPath"
