param(
    [switch]$ExecuteInstall,
    [string]$ReportPath = ".\tests\chocolatey\selected_chocolatey_runtime_report.csv"
)

$ErrorActionPreference = "Stop"

$packages = @(
    [pscustomobject]@{ Name = "jdk8"; Version = "8.0.211"; Reason = "runtime helper common.ps1 raised static ALERT" },
    [pscustomobject]@{ Name = "openjdk"; Version = "25.0.0.1"; Reason = "beforeModify helper raised static ALERT" },
    [pscustomobject]@{ Name = "sysinternals"; Version = "2026.5.7"; Reason = "helper script raised static ALERT" }
)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell window in the VM checkpoint."
    }
}

function Assert-Chocolatey {
    $cmd = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Chocolatey is not installed or choco.exe is not in PATH."
    }
}

Assert-Administrator
Assert-Chocolatey

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportPath) | Out-Null

$mode = if ($ExecuteInstall) { "install" } else { "noop" }
Write-Host "[CHOCO-RUNTIME] Mode: $mode"
Write-Host "[CHOCO-RUNTIME] Use this only inside a VM checkpoint. Restore checkpoint after runtime validation."

$rows = @()

foreach ($pkg in $packages) {
    $started = Get-Date
    $args = @(
        "install",
        $pkg.Name,
        "--version=$($pkg.Version)",
        "-y",
        "--force",
        "--no-progress"
    )

    if (-not $ExecuteInstall) {
        $args += "--noop"
    }

    Write-Host "[CHOCO-RUNTIME] choco $($args -join ' ')"
    & choco.exe @args
    $exitCode = $LASTEXITCODE
    $finished = Get-Date

    $rows += [pscustomobject]@{
        Package = $pkg.Name
        Version = $pkg.Version
        Mode = $mode
        StartedAt = $started.ToString("s")
        FinishedAt = $finished.ToString("s")
        ExitCode = $exitCode
        Reason = $pkg.Reason
    }
}

$rows | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host "[CHOCO-RUNTIME] Report: $ReportPath"
Write-Host "[CHOCO-RUNTIME] Completed. Check PythonAgent logs and restore the VM checkpoint if ExecuteInstall was used."
