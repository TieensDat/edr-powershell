param(
    [int]$TargetPackages = 100,
    [int]$CandidatePages = 5,
    [int]$PageSize = 100,
    [int]$MaxPackageSizeMB = 50,
    [string]$OutputRoot = ".\datasets\powershell_gallery\pilot_100"
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
        [xml]$Xml,
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

Write-Host "[PSG] Output root: $resolvedOutputRoot"
Write-Host "[PSG] Target downloaded packages: $TargetPackages"
Write-Host "[PSG] Max package size: $MaxPackageSizeMB MB"

for ($page = 0; $page -lt $CandidatePages -and $packages.Count -lt $TargetPackages; $page++) {
    $skip = $page * $PageSize
    $uri = "https://www.powershellgallery.com/api/v2/Packages()?`$filter=IsLatestVersion%20eq%20true&`$orderby=DownloadCount%20desc&`$skip=$skip&`$top=$PageSize"
    Write-Host "[PSG] Fetch metadata page $($page + 1): $uri"
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
    [xml]$feed = $response.Content
    $entries = $feed.SelectNodes("//a:entry", $script:Ns)

    foreach ($entry in $entries) {
        if ($packages.Count -ge $TargetPackages) {
            break
        }

        $id = Get-AtomPropertyText -Node $entry -Name "Id"
        $version = Get-AtomPropertyText -Node $entry -Name "Version"
        if (-not $id -or -not $version) {
            continue
        }

        $packageKey = "$id@$version".ToLowerInvariant()
        if ($seenPackageIds.ContainsKey($packageKey)) {
            continue
        }
        $seenPackageIds[$packageKey] = $true

        $content = $entry.SelectSingleNode("./a:content", $script:Ns)
        $downloadUrl = if ($content) { $content.GetAttribute("src") } else { "" }
        if (-not $downloadUrl) {
            $downloadUrl = "https://www.powershellgallery.com/api/v2/package/$id/$version"
        }

        $safeId = ConvertTo-SafeName $id
        $safeVersion = ConvertTo-SafeName $version
        $packageFileName = "$safeId.$safeVersion.nupkg"
        $packagePath = Join-Path $rawPackageDir $packageFileName
        $packageExtractDir = Join-Path $extractDir "$safeId.$safeVersion"

        try {
            if (Test-Path -LiteralPath $packagePath) {
                Write-Host "[PSG] Reusing $($packages.Count + 1)/${TargetPackages}: $id $version"
            }
            else {
                Write-Host "[PSG] Downloading $($packages.Count + 1)/${TargetPackages}: $id $version"
                Invoke-WebRequest -Uri $downloadUrl -OutFile $packagePath -UseBasicParsing -TimeoutSec 180
            }
            $actualSizeMb = [Math]::Round((Get-Item -LiteralPath $packagePath).Length / 1MB, 2)

            if ($actualSizeMb -gt $MaxPackageSizeMB) {
                Remove-Item -LiteralPath $packagePath -Force -ErrorAction SilentlyContinue
                $skipped.Add([pscustomobject]@{
                    package_name = $id
                    version = $version
                    reason = "package_too_large"
                    size_mb = $actualSizeMb
                    download_url = $downloadUrl
                })
                Write-Host "[PSG] Skip large package after download: $id $version ($actualSizeMb MB)"
                continue
            }

            if (Test-Path -LiteralPath $packageExtractDir) {
                Remove-Item -LiteralPath $packageExtractDir -Recurse -Force
            }
            New-Directory $packageExtractDir
            [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $packageExtractDir)

            $packageRecord = [pscustomobject]@{
                package_name = $id
                version = $version
                title = Get-AtomText -Node $entry -XPath "./a:title"
                author = Get-AtomText -Node $entry -XPath "./a:author/a:name"
                summary = Get-AtomPropertyText -Node $entry -Name "Summary"
                description = Get-AtomPropertyText -Node $entry -Name "Description"
                tags = Get-AtomPropertyText -Node $entry -Name "Tags"
                license_url = Get-AtomPropertyText -Node $entry -Name "LicenseUrl"
                project_url = Get-AtomPropertyText -Node $entry -Name "ProjectUrl"
                icon_url = Get-AtomPropertyText -Node $entry -Name "IconUrl"
                download_count = Get-AtomPropertyText -Node $entry -Name "DownloadCount"
                published = Get-AtomPropertyText -Node $entry -Name "Published"
                last_updated = Get-AtomPropertyText -Node $entry -Name "LastUpdated"
                package_download_url = $downloadUrl
                package_file = $packagePath
                package_sha256 = Get-FileSha256 $packagePath
                package_size_mb = $actualSizeMb
                extracted_dir = $packageExtractDir
            }
            $packages.Add($packageRecord)

            $scriptFiles = Get-ChildItem -LiteralPath $packageExtractDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLowerInvariant() -in @(".ps1", ".psm1", ".psd1") }
            foreach ($scriptFile in $scriptFiles) {
                $relativePath = Get-RelativePathCompat -BasePath $packageExtractDir -FullPath $scriptFile.FullName
                $safeRelative = ConvertTo-SafeName ($relativePath -replace "[\\/]", "__")
                $destDir = Join-Path $scriptDir "$safeId.$safeVersion"
                New-Directory $destDir
                $destPath = Join-Path $destDir $safeRelative
                Copy-Item -LiteralPath $scriptFile.FullName -Destination $destPath -Force

                $files.Add([pscustomobject]@{
                    sample_id = "psg_" + ($files.Count + 1).ToString("000000")
                    source_dataset = "PowerShellGallery"
                    label = "benign_provenance"
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
                package_name = $id
                version = $version
                reason = "download_or_extract_error"
                size_mb = ""
                download_url = $downloadUrl
                error = $_.Exception.Message
            })
            Write-Warning "[PSG] Failed package $id ${version}: $($_.Exception.Message)"
        }
    }
}

$packagesManifest = Join-Path $metadataDir "packages_manifest.csv"
$filesManifest = Join-Path $metadataDir "files_manifest.csv"
$skippedManifest = Join-Path $metadataDir "skipped_manifest.csv"
$summaryPath = Join-Path $metadataDir "collection_summary.json"

$packages | Export-Csv -LiteralPath $packagesManifest -NoTypeInformation -Encoding UTF8
$files | Export-Csv -LiteralPath $filesManifest -NoTypeInformation -Encoding UTF8
$skipped | Export-Csv -LiteralPath $skippedManifest -NoTypeInformation -Encoding UTF8

$summary = [pscustomobject]@{
    created_at = (Get-Date).ToString("s")
    source = "PowerShell Gallery"
    target_packages = $TargetPackages
    downloaded_packages = $packages.Count
    extracted_script_files = $files.Count
    skipped_packages = $skipped.Count
    output_root = $resolvedOutputRoot
    packages_manifest = $packagesManifest
    files_manifest = $filesManifest
    skipped_manifest = $skippedManifest
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "[PSG] Collection completed."
$summary | Format-List
