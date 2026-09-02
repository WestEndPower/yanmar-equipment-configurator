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

# Yanmar inventory lives in the private Inventory worksheet rather than in
# the public configurator CSV folder.  Older workbook macros call this script
# without -InventoryWorkbook, so locate the newest Yanmar master beside the
# sync script automatically.  An explicitly supplied path always wins.
if (
    [string]::IsNullOrWhiteSpace($InventoryWorkbook) -and
    $BrandId -eq "YANMAR"
) {
    $inventoryWorkbookCandidate =
        Get-ChildItem `
            -LiteralPath $PSScriptRoot `
            -File `
            -Filter "YANMAR-Master*.xlsm" `
            -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($inventoryWorkbookCandidate) {
        $InventoryWorkbook =
            $inventoryWorkbookCandidate.FullName

        Write-Host `
            ("INFO  Inventory workbook: " + $InventoryWorkbook) `
            -ForegroundColor Cyan
    }
    else {
        throw (
            "Yanmar inventory workbook was not found beside the sync " +
            "script. Save YANMAR-Master.xlsm in " + $PSScriptRoot +
            " or run this script with -InventoryWorkbook."
        )
    }
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
    $inventoryTable = $null
    $inventorySourceRange = $null
    $inventoryTargetSheet = $null
    $inventoryTargetRange = $null

    try {
        $excel =
            New-Object -ComObject Excel.Application

        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $excel.EnableEvents = $false
        $excel.AskToUpdateLinks = $false
        $excel.AutomationSecurity = 3

        $workbook =
            $excel.Workbooks.Open(
                $inventoryWorkbookPath,
                0,
                $true
            )

        $excel.CalculateFull()

        $inventorySheet =
            $workbook.Worksheets.Item("Inventory")

        $inventoryTable =
            $inventorySheet.ListObjects.Item("InventoryTable")

        $inventoryBook =
            $excel.Workbooks.Add()

        $inventoryTargetSheet =
            $inventoryBook.Worksheets.Item(1)

        $inventoryTargetSheet.Name = "Inventory"

        $inventorySourceRange =
            $inventoryTable.Range

        $inventoryTargetRange =
            $inventoryTargetSheet.Range("A1").Resize(
                $inventorySourceRange.Rows.Count,
                $inventorySourceRange.Columns.Count
            )

        # Preserve identifiers exactly as entered. Without text formatting,
        # Excel converts long numeric-looking serial numbers to scientific
        # notation and can remove leading zeroes during the temporary copy.
        for (
            $inventoryColumn = 1;
            $inventoryColumn -le $inventorySourceRange.Columns.Count;
            $inventoryColumn++
        ) {
            $inventoryHeader =
                [string]$inventorySourceRange.Cells.Item(
                    1,
                    $inventoryColumn
                ).Text

            if (
                $inventoryHeader -match
                '^(SKU|InventoryID|SerialNumber|IncludedInventoryID\d+)$'
            ) {
                $inventoryTargetSheet.Columns.Item(
                    $inventoryColumn
                ).NumberFormat = "@"
            }
        }

        # Values only: do not export worksheet formatting, unused columns,
        # formulas, workbook links, or macros to the protected CSV payload.
        $inventoryTargetRange.Value2 =
            $inventorySourceRange.Value2

        if (Test-Path -LiteralPath $inventoryCsv) {
            Remove-Item -LiteralPath $inventoryCsv
        }

        # 62 is the Excel UTF-8 CSV format.
        $inventoryBook.SaveAs(
            $inventoryCsv,
            62
        )

        Write-Host `
            ("PASS  Inventory worksheet exported privately: " + $inventoryCsv) `
            -ForegroundColor Green
    }
    finally {
        if ($inventoryBook) {
            try {
                $inventoryBook.Close($false)
            }
            catch {}
        }

        if ($workbook) {
            try {
                $workbook.Close($false)
            }
            catch {}
        }

        if ($excel) {
            try {
                $excel.Quit()
            }
            catch {}
        }

        foreach ($comObject in @(
            $inventoryTargetRange,
            $inventoryTargetSheet,
            $inventorySourceRange,
            $inventoryTable,
            $inventorySheet,
            $inventoryBook,
            $workbook,
            $excel
        )) {
            if ($comObject) {
                try {
                    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject(
                        $comObject
                    )
                }
                catch {}
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
