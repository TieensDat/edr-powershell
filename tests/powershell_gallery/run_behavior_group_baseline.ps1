param(
    [string]$FilesManifest = ".\datasets\powershell_gallery\behavior_groups_80\metadata\files_manifest.csv",
    [string]$OutputRoot = ".\datasets\powershell_gallery\behavior_groups_80\reports",
    [string]$AgentPath = ".\PythonAgent\PythonAgent.py",
    [switch]$SkipSliceBaselines,
    [switch]$EnableML
)

$ErrorActionPreference = "Stop"

$categories = @(
    "cloud_automation",
    "dsc_config_management",
    "package_module_management",
    "admin_windows_maintenance",
    "devops_build_test",
    "security_audit_compliance_benign",
    "utility_user_scripts"
)

$extensions = @(".ps1", ".psm1", ".psd1")

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

function Invoke-PsgEvaluation {
    param(
        [string]$OutDir,
        [string]$Category = "",
        [string]$ExtensionFilter = ""
    )

    $arguments = @(
        ".\tests\powershell_gallery\evaluate_powershell_gallery_static.py",
        "--files-manifest", $FilesManifest,
        "--agent-path", $AgentPath,
        "--output-dir", $OutDir,
        "--max-bytes", "204800"
    )

    if ($Category) {
        $arguments += @("--category", $Category)
    }

    if ($ExtensionFilter) {
        $arguments += @("--extensions", $ExtensionFilter)
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
        [string]$FileExtension = ""
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
        file_extension = $FileExtension
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
    Write-Host "[PSG-EVAL] Category: $category"
    Invoke-PsgEvaluation -OutDir $outDir -Category $category
}

$summaryRows = New-Object System.Collections.Generic.List[object]
foreach ($category in $categories) {
    Add-SummaryRowFromDir -Rows $summaryRows -SummaryDir (Join-Path $OutputRoot $category) -SliceType "category" -Category $category
}

if (-not $SkipSliceBaselines) {
    foreach ($extension in $extensions) {
        $safeExtension = $extension.TrimStart(".")
        $outDir = Join-Path $OutputRoot ("extension_" + $safeExtension)
        Write-Host "[PSG-EVAL] Extension: $extension"
        Invoke-PsgEvaluation -OutDir $outDir -ExtensionFilter $extension
        Add-SummaryRowFromDir -Rows $summaryRows -SummaryDir $outDir -SliceType "extension" -FileExtension $extension
    }

    foreach ($category in $categories) {
        foreach ($extension in $extensions) {
            $safeExtension = $extension.TrimStart(".")
            $outDir = Join-Path $OutputRoot ("category_extension\" + $category + "_" + $safeExtension)
            Write-Host "[PSG-EVAL] Category+Extension: $category $extension"
            Invoke-PsgEvaluation -OutDir $outDir -Category $category -ExtensionFilter $extension
            Add-SummaryRowFromDir -Rows $summaryRows -SummaryDir $outDir -SliceType "category_extension" -Category $category -FileExtension $extension
        }
    }
}

$summaryCsv = Join-Path $OutputRoot "behavior_group_baseline_summary.csv"
$summaryJson = Join-Path $OutputRoot "behavior_group_baseline_summary.json"
$summaryRows | Export-Csv -LiteralPath $summaryCsv -NoTypeInformation -Encoding UTF8
$summaryRows | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryJson -Encoding UTF8

Write-Host ""
Write-Host "[PSG-EVAL] Baseline completed."
$summaryRows | Format-Table -AutoSize
