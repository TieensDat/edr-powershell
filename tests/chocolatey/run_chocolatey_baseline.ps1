param(
    [string]$FilesManifest = ".\datasets\chocolatey\behavior_groups_80\metadata\files_manifest.csv",
    [string]$OutputRoot = ".\datasets\chocolatey\behavior_groups_80\reports",
    [string]$AgentPath = ".\PythonAgent\PythonAgent.py",
    [switch]$SkipSliceBaselines,
    [switch]$EnableML
)

$ErrorActionPreference = "Stop"

$categories = @(
    "browser_user_apps",
    "dev_tools",
    "runtime_language",
    "sysadmin_utilities",
    "security_tools_benign",
    "package_dependency_tools",
    "windows_maintenance_config"
)

$scriptTypes = @("install", "uninstall", "beforemodify", "helper")

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}

function Get-CountValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return 0
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return 0
    }

    return [int]$property.Value
}

function Invoke-ChocoEvaluation {
    param(
        [string]$OutDir,
        [string]$Category = "",
        [string]$ScriptType = ""
    )

    $arguments = @(
        ".\tests\chocolatey\evaluate_chocolatey_static.py",
        "--files-manifest", $FilesManifest,
        "--agent-path", $AgentPath,
        "--output-dir", $OutDir,
        "--max-bytes", "204800"
    )

    if ($Category) {
        $arguments += @("--category", $Category)
    }

    if ($ScriptType) {
        $arguments += @("--script-type", $ScriptType)
    }

    if ($EnableML) {
        $arguments += "--enable-ml"
    }

    & python @arguments
}

function Add-SummaryRowFromDir {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [string]$SummaryDir,
        [string]$SliceType,
        [string]$Category = "",
        [string]$ScriptType = ""
    )

    $summaryPath = Join-Path $SummaryDir "evaluation_summary.json"
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        return
    }

    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $finalCounts = $summary.final_verdict_counts
    $riskCounts = $summary.risk_level_counts

    $Rows.Add([pscustomobject]@{
        slice_type = $SliceType
        category = $Category
        script_type = $ScriptType
        evaluated_files = $summary.evaluated_files
        skipped_files = $summary.skipped_files
        allow = Get-CountValue -Object $finalCounts -Name "ALLOW"
        alert = Get-CountValue -Object $finalCounts -Name "ALERT"
        terminate = Get-CountValue -Object $finalCounts -Name "TERMINATE"
        low_risk = Get-CountValue -Object $riskCounts -Name "LOW"
        medium_risk = Get-CountValue -Object $riskCounts -Name "MEDIUM"
        high_risk = Get-CountValue -Object $riskCounts -Name "HIGH"
        alert_or_terminate = $summary.alert_or_terminate_count
        output_dir = $SummaryDir
    })
}

foreach ($category in $categories) {
    $outDir = Join-Path $OutputRoot $category
    Write-Host "[CHOCO-EVAL] Category: $category"
    Invoke-ChocoEvaluation -OutDir $outDir -Category $category
}

$summaryRows = New-Object System.Collections.Generic.List[object]
foreach ($category in $categories) {
    Add-SummaryRowFromDir -Rows $summaryRows -SummaryDir (Join-Path $OutputRoot $category) -SliceType "category" -Category $category
}

if (-not $SkipSliceBaselines) {
    foreach ($scriptType in $scriptTypes) {
        $outDir = Join-Path $OutputRoot ("script_type_" + $scriptType)
        Write-Host "[CHOCO-EVAL] Script type: $scriptType"
        Invoke-ChocoEvaluation -OutDir $outDir -ScriptType $scriptType
        Add-SummaryRowFromDir -Rows $summaryRows -SummaryDir $outDir -SliceType "script_type" -ScriptType $scriptType
    }

    foreach ($category in $categories) {
        foreach ($scriptType in $scriptTypes) {
            $outDir = Join-Path $OutputRoot ("category_script_type\" + $category + "_" + $scriptType)
            Write-Host "[CHOCO-EVAL] Category+ScriptType: $category $scriptType"
            Invoke-ChocoEvaluation -OutDir $outDir -Category $category -ScriptType $scriptType
            Add-SummaryRowFromDir -Rows $summaryRows -SummaryDir $outDir -SliceType "category_script_type" -Category $category -ScriptType $scriptType
        }
    }
}

$summaryCsv = Join-Path $OutputRoot "chocolatey_baseline_summary.csv"
$summaryJson = Join-Path $OutputRoot "chocolatey_baseline_summary.json"
$summaryRows | Export-Csv -LiteralPath $summaryCsv -NoTypeInformation -Encoding UTF8
$summaryRows | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryJson -Encoding UTF8

Write-Host ""
Write-Host "[CHOCO-EVAL] Baseline completed."
$summaryRows | Format-Table -AutoSize
