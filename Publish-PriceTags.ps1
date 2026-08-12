[CmdletBinding()]
param(
    [string]$ConfiguratorUrl = "http://127.0.0.1:5500/index.html",
    [string]$DataFolder = "",
    [string]$OutputFolder = "",
    [string]$BrandId = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DataFolder)) {
    $DataFolder = Join-Path $PSScriptRoot "data"
}

function Get-EdgePath {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    throw "Microsoft Edge was not found."
}

function Get-SafeFilePart([string]$Value) {
    $safe = $Value -replace '[<>:"/\\|?*]', '-'
    $safe = $safe -replace '\s+', ' '
    return $safe.Trim().TrimEnd('.')
}

function Get-PublisherFingerprint([string[]]$Paths) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($path in ($Paths | Sort-Object)) {
            $nameBytes = [Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant())
            [void]$sha.TransformBlock($nameBytes, 0, $nameBytes.Length, $nameBytes, 0)
            $bytes = [IO.File]::ReadAllBytes($path)
            [void]$sha.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return ([BitConverter]::ToString($sha.Hash) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

$requiredFiles = @(
"products.csv",
"promotions.csv",
"finance-programs.csv",
"freight-rules.csv"
)

$fingerprintFiles = foreach ($name in $requiredFiles) {
    $path = Join-Path $DataFolder $name
    if (-not (Test-Path -LiteralPath $path)) { throw "Required data file not found: $path" }
    $path
}

$publicProductsPath = Join-Path $DataFolder "products.csv"
$publicProducts = @(Import-Csv -LiteralPath $publicProductsPath)

if ([string]::IsNullOrWhiteSpace($BrandId)) {
    $brandIds = @(
        $publicProducts |
            ForEach-Object { ([string]$_.BrandID).Trim().ToUpperInvariant() } |
            Where-Object { $_ } |
            Select-Object -Unique
    )

    if ($brandIds.Count -ne 1) {
        throw "products.csv must contain exactly one nonblank BrandID. Found: $($brandIds -join ', ')"
    }

    $BrandId = $brandIds[0]
}

$BrandId = $BrandId.Trim().ToUpperInvariant()
if ($BrandId -notmatch '^[A-Z0-9_-]+$') {
    throw "BrandId may contain only letters, numbers, underscores, and hyphens."
}

if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = "G:\My Drive\Advertising\$BrandId\Price Tags"
}

$privateDataFolder =
    Join-Path $env:LOCALAPPDATA ("WestEndPower\ConfiguratorPrivate\" + $BrandId)

$privateFingerprintFiles = @(
    "products.csv",
    "finance-programs.csv"
)

foreach ($name in $privateFingerprintFiles) {

    $path =
        Join-Path $privateDataFolder $name

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required private pricing file not found: $path"
    }

    $fingerprintFiles += $path
}

$indexPath = Join-Path $PSScriptRoot "index.html"
if (-not (Test-Path -LiteralPath $indexPath)) { $indexPath = Join-Path $PSScriptRoot "index(23).html" }
if (-not (Test-Path -LiteralPath $indexPath)) { throw "index.html was not found beside this publisher." }
$fingerprintFiles += $indexPath

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$manifestPath = Join-Path $OutputFolder "price-tag-publisher.json"
$currentFingerprint = Get-PublisherFingerprint $fingerprintFiles
$previousFingerprint = ""

if (Test-Path -LiteralPath $manifestPath) {
    try { $previousFingerprint = (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).fingerprint }
    catch { $previousFingerprint = "" }
}

if (-not $Force -and $previousFingerprint -eq $currentFingerprint) {
    Write-Host "No price-tag data changed. Nothing was published."
    exit 0
}

try { Invoke-WebRequest -Uri $ConfiguratorUrl -UseBasicParsing -TimeoutSec 5 | Out-Null }
catch { throw "The configurator is not available at $ConfiguratorUrl. Start Live Server, then run the publisher again." }

$products = $publicProducts |
    Where-Object { ([string]$_.Active).Trim().ToUpperInvariant() -ne "F" -and ([string]$_.SKU).Trim() }
if (-not $products) { throw "No active products were found in products.csv." }

$edge = Get-EdgePath
$temporaryProfile = Join-Path $env:TEMP ("WestEndPriceTags-" + [guid]::NewGuid().ToString("N"))
$published = 0
$failed = [Collections.Generic.List[string]]::new()

try {
    foreach ($product in $products) {
        $sku = ([string]$product.SKU).Trim()
        $model = ([string]$product.Model).Trim()
        if (-not $model) { $model = ([string]$product.ProductName).Trim() }
        if (-not $model) { $model = $BrandId }

        $fileName = "{0} - {1}.pdf" -f (Get-SafeFilePart $model), (Get-SafeFilePart $sku)
        $pdfPath = Join-Path $OutputFolder $fileName
        $separator = if ($ConfiguratorUrl.Contains("?")) { "&" } else { "?" }
        $tagUrl = $ConfiguratorUrl + $separator + "priceTagBatch=1&priceTagSku=" + [Uri]::EscapeDataString($sku)
        Write-Host "Publishing $model ($sku)..."

        $arguments = @(
            "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--print-background",
            "--virtual-time-budget=12000", "--user-data-dir=`"$temporaryProfile`"",
            "--print-to-pdf=`"$pdfPath`"", $tagUrl
        )
        $process = Start-Process -FilePath $edge -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden

        if ($process.ExitCode -eq 0 -and (Test-Path -LiteralPath $pdfPath) -and (Get-Item -LiteralPath $pdfPath).Length -gt 1000) { $published++ }
        else { $failed.Add("$model ($sku)") }
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryProfile) {
        Remove-Item -LiteralPath $temporaryProfile -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failed.Count -gt 0) {
    Write-Warning ("Failed tags: " + ($failed -join "; "))
    throw "$($failed.Count) price tag(s) failed. The prior publish record was not changed."
}

[ordered]@{
    fingerprint = $currentFingerprint
    publishedAt = (Get-Date).ToString("o")
    productCount = $published
    configuratorUrl = $ConfiguratorUrl
} | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Published $published price tags to $OutputFolder."
