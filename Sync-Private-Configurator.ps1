[CmdletBinding()]
param(
    [string]$BrandId = "",
    [string]$ApiUrl = "https://westendpower-configurator-api.westendpower-nm.workers.dev",
    [string]$ProductsFile = "",
    [string]$InventoryWorkbook = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ProductsFile)) {
    $ProductsFile = Join-Path $PSScriptRoot "data\products.csv"
}

if ([string]::IsNullOrWhiteSpace($BrandId)) {
    if (-not (Test-Path -LiteralPath $ProductsFile)) {
        throw "Products file not found: $ProductsFile"
    }

    $brandIds = @(
        Import-Csv -LiteralPath $ProductsFile |
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

$privateFolder =
    Join-Path $env:LOCALAPPDATA ("WestEndPower\ConfiguratorPrivate\" + $BrandId)

if (-not (Test-Path -LiteralPath $privateFolder)) {
    throw "Private configurator folder not found: $privateFolder"
}

if (-not [string]::IsNullOrWhiteSpace($InventoryWorkbook)) {
    if (-not (Test-Path -LiteralPath $InventoryWorkbook)) {
        throw "Inventory workbook not found: $InventoryWorkbook"
    }

    $inventoryWorkbookPath =
        (Resolve-Path -LiteralPath $InventoryWorkbook).Path

    $inventoryCsv =
        Join-Path $privateFolder "inventory.csv"

    $excel = $null
    $workbook = $null
    $inventoryBook = $null
    $inventorySheet = $null

    try {
        $excel =
            New-Object -ComObject Excel.Application

        $excel.Visible = $false
        $excel.DisplayAlerts = $false

        $workbook =
            $excel.Workbooks.Open(
                $inventoryWorkbookPath,
                0,
                $true
            )

        $inventorySheet =
            $workbook.Worksheets.Item("Inventory")

        $excel.CalculateFull()

        $inventorySheet.Copy()

        $inventoryBook =
            $excel.ActiveWorkbook

        if (Test-Path -LiteralPath $inventoryCsv) {
            Remove-Item -LiteralPath $inventoryCsv
        }

        # 62 is the Excel UTF-8 CSV format.
        $inventoryBook.SaveAs(
            $inventoryCsv,
            62
        )

        Write-Host `
            "PASS  Inventory worksheet exported privately" `
            -ForegroundColor Green
    }
    finally {
        if ($inventoryBook) {
            $inventoryBook.Close($false)
        }

        if ($workbook) {
            $workbook.Close($false)
        }

        if ($excel) {
            $excel.Quit()
        }

        foreach ($comObject in @(
            $inventorySheet,
            $inventoryBook,
            $workbook,
            $excel
        )) {
            if ($comObject) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject(
                    $comObject
                )
            }
        }

        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

$datasets = @(
    "products",
    "attachments",
    "accessories",
    "batteries",
    "chargers",
    "parts",
    "promotions",
    "finance-programs",
    "bid-fleet-programs",
    "freight-rules",
    "dealer-rules",
    "inventory"
)

$admin = Get-Credential `
    -UserName "westend-admin" `
    -Message "Enter West End configurator admin password"

$pair =
    $admin.UserName + ":" +
    $admin.GetNetworkCredential().Password

$basic =
    [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($pair)
    )

$headers = @{
    "Authorization" = "Basic " + $basic
}

foreach ($dataset in $datasets) {

    $file =
        Join-Path $privateFolder ($dataset + ".csv")

    if (-not (Test-Path -LiteralPath $file)) {

        Write-Host `
            "SKIP  $dataset - file not found" `
            -ForegroundColor Yellow

        continue
    }

    $rows =
        @(Import-Csv -LiteralPath $file)

     $body = @{
        brandId = $BrandId
        dataset = $dataset
        payload = $rows
    } |
        ConvertTo-Json -Depth 20 -Compress

    $result =
        Invoke-RestMethod `
            -Uri ($ApiUrl.TrimEnd('/') + "/config-private-sync") `
            -Method Post `
            -ContentType "application/json" `
            -Headers $headers `
            -Body $body

    if ($result.ok) {

        Write-Host `
            ("PASS  {0}  {1} rows" -f `
                $dataset, `
                $rows.Count) `
            -ForegroundColor Green

    }
    else {

        throw "D1 sync failed for dataset: $dataset"
    }
}

Remove-Variable pair -ErrorAction SilentlyContinue
Remove-Variable basic -ErrorAction SilentlyContinue
Remove-Variable admin -ErrorAction SilentlyContinue

Write-Host ""
Write-Host `
    ("PRIVATE CONFIGURATOR D1 SYNC COMPLETE - " + $BrandId) `
    -ForegroundColor Green
