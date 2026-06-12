param(
    [int]$MaxFilesPerPackage = 3,
    [int]$MaxFileSizeKB = 200,
    [int]$MaxPackageSizeMB = 50,
    [string]$OutputRoot = ".\datasets\powershell_gallery\behavior_groups_80"
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function ConvertTo-SafeName {
    param([string]$Value)
    $safe = ($Value -replace '[\\/:*?"<>|]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "unknown"
    }
    return $safe
}

function Get-AtomText {
    param(
        [System.Xml.XmlNode]$Node,
        [string]$XPath
    )
    $selected = $Node.SelectSingleNode($XPath, $script:Ns)
    if ($null -eq $selected) {
        return ""
    }
    return [System.Net.WebUtility]::HtmlDecode($selected.InnerText)
}

function Get-AtomPropertyText {
    param(
        [System.Xml.XmlNode]$Node,
        [string]$Name
    )
    return Get-AtomText -Node $Node -XPath ".//m:properties/d:$Name"
}

function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-NormalizedSha256 {
    param([string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($null -eq $text) {
        $text = ""
    }
    $normalized = (($text -replace "`0", "") -replace "\s+", "").ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace "-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-RelativePathCompat {
    param(
        [string]$BasePath,
        [string]$FullPath
    )
    $base = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $full = [System.IO.Path]::GetFullPath($FullPath)
    if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($base.Length)
    }
    return Split-Path -Path $full -Leaf
}

function Get-LatestPackageEntry {
    param([string]$PackageName)
    $escapedName = $PackageName.Replace("'", "''")
    $uri = "https://www.powershellgallery.com/api/v2/Packages()?`$filter=Id%20eq%20'$escapedName'%20and%20IsLatestVersion%20eq%20true&`$top=1"
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
    [xml]$feed = $response.Content
    return $feed.SelectSingleNode("//a:entry", $script:Ns)
}

function Select-RepresentativeScriptFiles {
    param(
        [string]$PackageExtractDir,
        [int]$MaxFiles,
        [int]$MaxSizeBytes
    )

    $all = Get-ChildItem -LiteralPath $PackageExtractDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension.ToLowerInvariant() -in @(".ps1", ".psm1", ".psd1") -and
            $_.Length -le $MaxSizeBytes
        } |
        ForEach-Object {
            $relative = Get-RelativePathCompat -BasePath $PackageExtractDir -FullPath $_.FullName
            $ext = $_.Extension.ToLowerInvariant()
            $priority = switch ($ext) {
                ".ps1" { 0 }
                ".psm1" { 1 }
                ".psd1" { 2 }
                default { 9 }
            }
            $testPenalty = if ($relative -match '(?i)(\\|/)?tests?(\\|/)|\.tests?\.ps1$') { 1 } else { 0 }
            [pscustomobject]@{
                File = $_
                RelativePath = $relative
                ExtensionPriority = $priority
                TestPenalty = $testPenalty
                Size = $_.Length
            }
        } |
        Sort-Object ExtensionPriority, TestPenalty, Size, RelativePath

    return $all | Select-Object -First $MaxFiles
}

$categoryConfigs = @(
    [pscustomobject]@{
        Category = "cloud_automation"
        Target = 15
        Candidates = @(
            "Az.Accounts", "Az.Resources", "Az.Compute", "Az.Storage", "Az.Network",
            "Az.KeyVault", "Az.Monitor", "Microsoft.Graph.Authentication", "Microsoft.Graph.Users",
            "Microsoft.Graph.Groups", "PnP.PowerShell", "ExchangeOnlineManagement",
            "AWS.Tools.Common", "AWS.Tools.S3", "AWS.Tools.EC2", "AWS.Tools.IdentityManagement",
            "AzureAD", "MSOnline"
        )
    },
    [pscustomobject]@{
        Category = "dsc_config_management"
        Target = 10
        Candidates = @(
            "ComputerManagementDsc", "NetworkingDsc", "SecurityPolicyDsc", "AuditPolicyDsc",
            "ActiveDirectoryDsc", "xNetworking", "xDnsServer", "WebAdministrationDsc",
            "SqlServerDsc", "StorageDsc", "PSDscResources", "xWindowsUpdate",
            "CertificateDsc", "SystemLocaleDsc"
        )
    },
    [pscustomobject]@{
        Category = "package_module_management"
        Target = 10
        Candidates = @(
            "PowerShellGet", "PackageManagement", "Microsoft.PowerShell.PSResourceGet",
            "Microsoft.WinGet.Client", "Evergreen", "PSDepend", "ModuleBuilder",
            "BuildHelpers", "PowerShellForGitHub", "Az.Tools.Installer",
            "ChocolateyGet", "WingetTools"
        )
    },
    [pscustomobject]@{
        Category = "admin_windows_maintenance"
        Target = 12
        Candidates = @(
            "PSWindowsUpdate", "DellBIOSProvider", "PendingReboot", "localaccount",
            "NTFSSecurity", "RunAsUser", "CredentialManager", "Carbon",
            "WindowsCompatibility", "HPWarranty", "LSUClient", "OSD",
            "DisplaySettings", "WifiTools", "QuserObject", "HPCMSL"
        )
    },
    [pscustomobject]@{
        Category = "devops_build_test"
        Target = 10
        Candidates = @(
            "Pester", "InvokeBuild", "psake", "PSScriptAnalyzer", "platyPS",
            "VSTeam", "posh-git", "dbatools", "Pode", "SqlChangeAutomation",
            "PSRule", "Bicep"
        )
    },
    [pscustomobject]@{
        Category = "security_audit_compliance_benign"
        Target = 10
        Candidates = @(
            "SpeculationControl", "Az.Security", "Az.SecurityInsights", "PS-SentinelOne",
            "Microsoft365DSC", "HardeningKitty", "ORCA", "DSInternals",
            "SecurityPolicy", "MSCloudLoginAssistant", "AuditPolicyDsc",
            "SecurityPolicyDsc", "Microsoft.Graph.Security"
        )
    },
    [pscustomobject]@{
        Category = "utility_user_scripts"
        Target = 13
        Candidates = @(
            "powershell-yaml", "PSWriteHTML", "ImportExcel", "SimplySql", "Pode",
            "PowerHTML", "PSIni", "NtpTime", "SQLite", "SHiPS", "ThreadJob",
            "Microsoft.PowerShell.ThreadJob", "PSFramework", "PSWriteColor",
            "PSSharedGoods", "Terminal-Icons", "oh-my-posh", "Posh-SSH"
        )
    }
)

$resolvedOutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
$rawPackageDir = Join-Path $resolvedOutputRoot "raw_packages"
$extractDir = Join-Path $resolvedOutputRoot "extracted_packages"
$scriptDir = Join-Path $resolvedOutputRoot "extracted_scripts"
$metadataDir = Join-Path $resolvedOutputRoot "metadata"

New-Directory $resolvedOutputRoot
New-Directory $rawPackageDir
New-Directory $extractDir
New-Directory $scriptDir
New-Directory $metadataDir

$script:Ns = New-Object System.Xml.XmlNamespaceManager((New-Object System.Xml.NameTable))
$script:Ns.AddNamespace("a", "http://www.w3.org/2005/Atom")
$script:Ns.AddNamespace("d", "http://schemas.microsoft.com/ado/2007/08/dataservices")
$script:Ns.AddNamespace("m", "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata")

$packages = New-Object System.Collections.Generic.List[object]
$files = New-Object System.Collections.Generic.List[object]
$skipped = New-Object System.Collections.Generic.List[object]
$seenPackageIds = @{}
$maxSizeBytes = $MaxFileSizeKB * 1024

Write-Host "[PSG-GROUP] Output root: $resolvedOutputRoot"
Write-Host "[PSG-GROUP] Max files/package: $MaxFilesPerPackage"
Write-Host "[PSG-GROUP] Max file size: $MaxFileSizeKB KB"

foreach ($config in $categoryConfigs) {
    $category = $config.Category
    $categoryCount = 0
    Write-Host ""
    Write-Host "[PSG-GROUP] Category: $category target=$($config.Target)"

    foreach ($candidate in $config.Candidates) {
        if ($categoryCount -ge $config.Target) {
            break
        }

        try {
            $entry = Get-LatestPackageEntry -PackageName $candidate
            if ($null -eq $entry) {
                $skipped.Add([pscustomobject]@{
                    category = $category
                    package_name = $candidate
                    version = ""
                    reason = "not_found"
                    error = ""
                })
                Write-Host "[PSG-GROUP] Not found: $candidate"
                continue
            }

            $id = Get-AtomPropertyText -Node $entry -Name "Id"
            $version = Get-AtomPropertyText -Node $entry -Name "Version"
            $packageKey = "$id@$version".ToLowerInvariant()
            if ($seenPackageIds.ContainsKey($packageKey)) {
                Write-Host "[PSG-GROUP] Duplicate package skipped: $id $version"
                continue
            }

            $content = $entry.SelectSingleNode("./a:content", $script:Ns)
            $downloadUrl = if ($content) { $content.GetAttribute("src") } else { "" }
            if (-not $downloadUrl) {
                $downloadUrl = "https://www.powershellgallery.com/api/v2/package/$id/$version"
            }

            $safeCategory = ConvertTo-SafeName $category
            $safeId = ConvertTo-SafeName $id
            $safeVersion = ConvertTo-SafeName $version
            $packageFileName = "$safeId.$safeVersion.nupkg"
            $packagePath = Join-Path $rawPackageDir $packageFileName
            $packageExtractDir = Join-Path $extractDir "$safeId.$safeVersion"

            if (Test-Path -LiteralPath $packagePath) {
                Write-Host "[PSG-GROUP] Reusing: [$category] $id $version"
            }
            else {
                Write-Host "[PSG-GROUP] Downloading: [$category] $id $version"
                Invoke-WebRequest -Uri $downloadUrl -OutFile $packagePath -UseBasicParsing -TimeoutSec 180
            }

            $actualSizeMb = [Math]::Round((Get-Item -LiteralPath $packagePath).Length / 1MB, 2)
            if ($actualSizeMb -gt $MaxPackageSizeMB) {
                $skipped.Add([pscustomobject]@{
                    category = $category
                    package_name = $id
                    version = $version
                    reason = "package_too_large"
                    size_mb = $actualSizeMb
                    error = ""
                })
                Write-Host "[PSG-GROUP] Skip large package: $id $version ($actualSizeMb MB)"
                continue
            }

            if (Test-Path -LiteralPath $packageExtractDir) {
                Remove-Item -LiteralPath $packageExtractDir -Recurse -Force
            }
            New-Directory $packageExtractDir
            [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $packageExtractDir)

            $selectedFiles = Select-RepresentativeScriptFiles -PackageExtractDir $packageExtractDir -MaxFiles $MaxFilesPerPackage -MaxSizeBytes $maxSizeBytes
            if (-not $selectedFiles -or $selectedFiles.Count -eq 0) {
                $skipped.Add([pscustomobject]@{
                    category = $category
                    package_name = $id
                    version = $version
                    reason = "no_script_files_under_size_limit"
                    size_mb = $actualSizeMb
                    error = ""
                })
                Write-Host "[PSG-GROUP] No eligible scripts: $id $version"
                continue
            }

            $packageRecord = [pscustomobject]@{
                category = $category
                package_name = $id
                version = $version
                title = Get-AtomText -Node $entry -XPath "./a:title"
                author = Get-AtomText -Node $entry -XPath "./a:author/a:name"
                summary = Get-AtomPropertyText -Node $entry -Name "Summary"
                description = Get-AtomPropertyText -Node $entry -Name "Description"
                tags = Get-AtomPropertyText -Node $entry -Name "Tags"
                license_url = Get-AtomPropertyText -Node $entry -Name "LicenseUrl"
                project_url = Get-AtomPropertyText -Node $entry -Name "ProjectUrl"
                download_count = Get-AtomPropertyText -Node $entry -Name "DownloadCount"
                published = Get-AtomPropertyText -Node $entry -Name "Published"
                last_updated = Get-AtomPropertyText -Node $entry -Name "LastUpdated"
                package_download_url = $downloadUrl
                package_file = $packagePath
                package_sha256 = Get-FileSha256 $packagePath
                package_size_mb = $actualSizeMb
                extracted_dir = $packageExtractDir
                selected_file_count = $selectedFiles.Count
            }
            $packages.Add($packageRecord)
            $seenPackageIds[$packageKey] = $true
            $categoryCount++

            foreach ($selected in $selectedFiles) {
                $scriptFile = $selected.File
                $relativePath = $selected.RelativePath
                $safeRelative = ConvertTo-SafeName ($relativePath -replace "[\\/]", "__")
                $destDir = Join-Path (Join-Path $scriptDir $safeCategory) "$safeId.$safeVersion"
                New-Directory $destDir
                $destPath = Join-Path $destDir $safeRelative
                Copy-Item -LiteralPath $scriptFile.FullName -Destination $destPath -Force

                $files.Add([pscustomobject]@{
                    sample_id = "psg_behavior_" + ($files.Count + 1).ToString("000000")
                    source_dataset = "PowerShellGallery"
                    label = "benign_provenance"
                    category = $category
                    package_name = $id
                    package_version = $version
                    author = $packageRecord.author
                    license_url = $packageRecord.license_url
                    project_url = $packageRecord.project_url
                    download_count = $packageRecord.download_count
                    original_relative_path = $relativePath
                    collected_path = $destPath
                    file_extension = $scriptFile.Extension.ToLowerInvariant()
                    file_size_bytes = $scriptFile.Length
                    raw_sha256 = Get-FileSha256 $destPath
                    normalized_sha256 = Get-NormalizedSha256 $destPath
                })
            }
        }
        catch {
            $skipped.Add([pscustomobject]@{
                category = $category
                package_name = $candidate
                version = ""
                reason = "download_or_extract_error"
                error = $_.Exception.Message
            })
            Write-Warning "[PSG-GROUP] Failed [$category] ${candidate}: $($_.Exception.Message)"
        }
    }

    Write-Host "[PSG-GROUP] Completed category $category with $categoryCount package(s)."
}

$packagesManifest = Join-Path $metadataDir "packages_manifest.csv"
$filesManifest = Join-Path $metadataDir "files_manifest.csv"
$skippedManifest = Join-Path $metadataDir "skipped_manifest.csv"
$summaryPath = Join-Path $metadataDir "collection_summary.json"

$packages | Export-Csv -LiteralPath $packagesManifest -NoTypeInformation -Encoding UTF8
$files | Export-Csv -LiteralPath $filesManifest -NoTypeInformation -Encoding UTF8
$skipped | Export-Csv -LiteralPath $skippedManifest -NoTypeInformation -Encoding UTF8

$categorySummary = $packages |
    Group-Object category |
    ForEach-Object {
        $categoryName = $_.Name
        [pscustomobject]@{
            category = $categoryName
            packages = $_.Count
            files = ($files | Where-Object { $_.category -eq $categoryName }).Count
        }
    }

$summary = [pscustomobject]@{
    created_at = (Get-Date).ToString("s")
    source = "PowerShell Gallery"
    requested_total_packages = ($categoryConfigs | Measure-Object -Property Target -Sum).Sum
    downloaded_packages = $packages.Count
    extracted_script_files = $files.Count
    skipped_items = $skipped.Count
    max_files_per_package = $MaxFilesPerPackage
    max_file_size_kb = $MaxFileSizeKB
    max_package_size_mb = $MaxPackageSizeMB
    output_root = $resolvedOutputRoot
    packages_manifest = $packagesManifest
    files_manifest = $filesManifest
    skipped_manifest = $skippedManifest
    category_summary = $categorySummary
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "[PSG-GROUP] Collection completed."
$summary | Format-List
