param(
    [switch]$DisableFailureAudit
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script in an elevated PowerShell session."
}

Write-Host "[AUDIT] Enabling Security Event ID 4688 process creation auditing..."
if ($DisableFailureAudit) {
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Host
}
else {
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Host
}

$auditPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $auditPolicyPath -Force | Out-Null
New-ItemProperty `
    -Path $auditPolicyPath `
    -Name "ProcessCreationIncludeCmdLine_Enabled" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null

Write-Host "[AUDIT] Done."
Write-Host "[AUDIT] Security 4688 is enabled and command line logging is requested."
Write-Host "[AUDIT] Restart PythonAgent after changing audit policy."
