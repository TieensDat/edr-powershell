param(
    [int]$MaxFilesPerPackage = 3,
    [int]$MaxFileSizeKB = 200,
    [int]$MaxPackageSizeMB = 50,
    [string]$OutputRoot = ".\datasets\chocolatey\behavior_groups_80"
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

function Get-ChocolateyLatestPackageEntry {
    param([string]$PackageName)
    $escapedName = $PackageName.Replace("'", "''")
    $uri = "https://community.chocolatey.org/api/v2/FindPackagesById()?id='$escapedName'"
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
    [xml]$feed = $response.Content
    $entries = $feed.SelectNodes("//a:entry", $script:Ns)
    if ($null -eq $entries -or $entries.Count -eq 0) {
        return $null
    }

    foreach ($entry in $entries) {
        $isLatest = Get-AtomPropertyText -Node $entry -Name "IsLatestVersion"
        if ($isLatest -eq "true" -or $isLatest -eq "True") {
            return $entry
        }
    }

    return $entries[0]
}

function Get-ScriptType {
    param([string]$RelativePath)
    $leaf = (Split-Path -Path $RelativePath -Leaf).ToLowerInvariant()
    if ($leaf -eq "chocolateyinstall.ps1") {
        return "install"
    }
    if ($leaf -eq "chocolateyuninstall.ps1") {
        return "uninstall"
    }
    if ($leaf -eq "chocolateybeforemodify.ps1") {
        return "beforemodify"
    }
    return "helper"
}

function Select-RepresentativeScriptFiles {
    param(
        [string]$PackageExtractDir,
        [int]$MaxFiles,
        [int]$MaxSizeBytes
    )

    $all = Get-ChildItem -LiteralPath $PackageExtractDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension.ToLowerInvariant() -eq ".ps1" -and
            $_.Length -le $MaxSizeBytes
        } |
        ForEach-Object {
            $relative = Get-RelativePathCompat -BasePath $PackageExtractDir -FullPath $_.FullName
            $relativeLower = $relative.ToLowerInvariant()
            $scriptType = Get-ScriptType -RelativePath $relative
            $typePriority = switch ($scriptType) {
                "install" { 0 }
                "uninstall" { 1 }
                "beforemodify" { 2 }
                default { 3 }
            }
            $toolsPenalty = if ($relativeLower -like "tools\*" -or $relativeLower -like "tools/*") { 0 } else { 1 }
            [pscustomobject]@{
                File = $_
                RelativePath = $relative
                ScriptType = $scriptType
                TypePriority = $typePriority
                ToolsPenalty = $toolsPenalty
                Size = $_.Length
            }
        } |
        Sort-Object ToolsPenalty, TypePriority, Size, RelativePath

    return $all | Select-Object -First $MaxFiles
}

$categoryConfigs = @(
    [pscustomobject]@{
        Category = "browser_user_apps"
        Target = 10
        Candidates = @(
            "googlechrome", "firefox", "microsoft-edge", "brave", "opera",
            "vivaldi", "chromium", "tor-browser", "thunderbird", "vlc",
            "sumatrapdf", "notepadplusplus.install", "paint.net", "greenshot"
        )
    },
    [pscustomobject]@{
        Category = "dev_tools"
        Target = 12
        Candidates = @(
            "git", "vscode", "notepadplusplus.install", "cmake", "make",
            "llvm", "mingw", "visualstudio2022buildtools", "docker-desktop",
            "postman", "insomnia-rest-api-client", "fiddler", "sourcetree",
            "github-desktop", "dbeaver"
        )
    },
    [pscustomobject]@{
        Category = "runtime_language"
        Target = 10
        Candidates = @(
            "python", "python3", "nodejs-lts", "openjdk", "temurin17",
            "golang", "ruby", "php", "dotnet-sdk", "dotnet-8.0-sdk",
            "rustup.install", "maven", "gradle", "jdk8"
        )
    },
    [pscustomobject]@{
        Category = "sysadmin_utilities"
        Target = 12
        Candidates = @(
            "sysinternals", "procexp", "procmon", "autoruns", "tcpview",
            "putty", "winscp", "openssh", "nmap", "wireshark",
            "rdcman", "windirstat", "7zip.install", "everything"
        )
    },
    [pscustomobject]@{
        Category = "security_tools_benign"
        Target = 10
        Candidates = @(
            "sysmon", "wireshark", "nmap", "yara", "openssl",
            "gpg4win", "keepass", "keepassxc", "osquery", "microsoft-windows-terminal",
            "veracrypt", "putty", "winscp", "tcpview"
        )
    },
    [pscustomobject]@{
        Category = "package_dependency_tools"
        Target = 12
        Candidates = @(
            "chocolatey-core.extension", "chocolatey-compatibility.extension",
            "chocolatey-windowsupdate.extension", "nuget.commandline",
            "powershell-core", "powershell", "awscli", "azure-cli",
            "kubernetes-cli", "terraform", "packer", "helm",
            "jq", "curl", "wget"
        )
    },
    [pscustomobject]@{
        Category = "windows_maintenance_config"
        Target = 14
        Candidates = @(
            "adobereader", "jre8", "dotnetfx", "vcredist140", "vcredist2015",
            "vcredist2017", "vcredist2019", "vcredist-all", "microsoft-teams.install",
            "zoom", "everything", "bleachbit", "ccleaner", "autohotkey.install",
            "teamviewer", "powertoys", "rsat", "microsoft-windows-terminal"
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
$maxPackageSizeBytes = $MaxPackageSizeMB * 1MB

Write-Host "[CHOCO-COLLECT] Output root: $resolvedOutputRoot"
Write-Host "[CHOCO-COLLECT] Max files/package: $MaxFilesPerPackage"
Write-Host "[CHOCO-COLLECT] Max file size: $MaxFileSizeKB KB"
Write-Host "[CHOCO-COLLECT] Max package size: $MaxPackageSizeMB MB"

foreach ($config in $categoryConfigs) {
    $category = $config.Category
    $categoryCount = 0
    Write-Host ""
    Write-Host "[CHOCO-COLLECT] Category: $category target=$($config.Target)"

    foreach ($candidate in $config.Candidates) {
        if ($categoryCount -ge $config.Target) {
            break
        }

        try {
            $entry = Get-ChocolateyLatestPackageEntry -PackageName $candidate
            if ($null -eq $entry) {
                $skipped.Add([pscustomobject]@{
                    category = $category
                    package_name = $candidate
                    version = ""
                    reason = "not_found"
                    package_size_mb = ""
                    error = ""
                })
                Write-Host "[CHOCO-COLLECT] Not found: $candidate"
                continue
            }

            $id = Get-AtomPropertyText -Node $entry -Name "Id"
            if (-not $id) {
                $id = Get-AtomText -Node $entry -XPath "./a:title"
            }
            $version = Get-AtomPropertyText -Node $entry -Name "Version"
            $packageKey = "$id@$version".ToLowerInvariant()
            if ($seenPackageIds.ContainsKey($packageKey)) {
                Write-Host "[CHOCO-COLLECT] Duplicate package skipped: $id $version"
                continue
            }

            $packageSizeText = Get-AtomPropertyText -Node $entry -Name "PackageSize"
            [int64]$packageSizeBytes = 0
            [void][int64]::TryParse($packageSizeText, [ref]$packageSizeBytes)
            if ($packageSizeBytes -gt 0 -and $packageSizeBytes -gt $maxPackageSizeBytes) {
                $skipped.Add([pscustomobject]@{
                    category = $category
                    package_name = $id
                    version = $version
                    reason = "package_too_large_metadata"
                    package_size_mb = [Math]::Round($packageSizeBytes / 1MB, 2)
                    error = ""
                })
                Write-Host "[CHOCO-COLLECT] Skip large package by metadata: $id $version"
                continue
            }

            $content = $entry.SelectSingleNode("./a:content", $script:Ns)
            $downloadUrl = if ($content) { $content.GetAttribute("src") } else { "" }
            if (-not $downloadUrl) {
                $downloadUrl = "https://community.chocolatey.org/api/v2/package/$id/$version"
            }

            $safeCategory = ConvertTo-SafeName $category
            $safeId = ConvertTo-SafeName $id
            $safeVersion = ConvertTo-SafeName $version
            $packageFileName = "$safeId.$safeVersion.nupkg"
            $packagePath = Join-Path $rawPackageDir $packageFileName
            $packageExtractDir = Join-Path $extractDir "$safeId.$safeVersion"

            if (Test-Path -LiteralPath $packagePath) {
                Write-Host "[CHOCO-COLLECT] Reusing: [$category] $id $version"
            }
            else {
                Write-Host "[CHOCO-COLLECT] Downloading: [$category] $id $version"
                Invoke-WebRequest -Uri $downloadUrl -OutFile $packagePath -UseBasicParsing -TimeoutSec 180
            }

            $actualSizeMb = [Math]::Round((Get-Item -LiteralPath $packagePath).Length / 1MB, 2)
            if ($actualSizeMb -gt $MaxPackageSizeMB) {
                $skipped.Add([pscustomobject]@{
                    category = $category
                    package_name = $id
                    version = $version
                    reason = "package_too_large_after_download"
                    package_size_mb = $actualSizeMb
                    error = ""
                })
                Write-Host "[CHOCO-COLLECT] Skip large package: $id $version ($actualSizeMb MB)"
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
                    package_size_mb = $actualSizeMb
                    error = ""
                })
                Write-Host "[CHOCO-COLLECT] No eligible scripts: $id $version"
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
                package_source_url = Get-AtomPropertyText -Node $entry -Name "PackageSourceUrl"
                download_count = Get-AtomPropertyText -Node $entry -Name "DownloadCount"
                version_download_count = Get-AtomPropertyText -Node $entry -Name "VersionDownloadCount"
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
                    sample_id = "choco_behavior_" + ($files.Count + 1).ToString("000000")
                    source_dataset = "Chocolatey"
                    label = "benign_provenance"
                    category = $category
                    script_type = $selected.ScriptType
                    package_name = $id
                    package_version = $version
                    author = $packageRecord.author
                    license_url = $packageRecord.license_url
                    project_url = $packageRecord.project_url
                    package_source_url = $packageRecord.package_source_url
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
                package_size_mb = ""
                error = $_.Exception.Message
            })
            Write-Warning "[CHOCO-COLLECT] Failed [$category] ${candidate}: $($_.Exception.Message)"
        }
    }

    Write-Host "[CHOCO-COLLECT] Completed category $category with $categoryCount package(s)."
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
    source = "Chocolatey Community Package Feed"
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
Write-Host "[CHOCO-COLLECT] Collection completed."
$summary | Format-List
