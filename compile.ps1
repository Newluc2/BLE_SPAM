#!/usr/bin/env pwsh
# BLE Spam v7.1 - Compilation script for Windows

$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot ".")).Path
$SdkDir = if ($env:FLIPPER_SDK) { $env:FLIPPER_SDK } else { "C:\flipperzero-firmware" }
$BuildDir = $SdkDir
$OutputDir = "$ProjectDir\dist"

Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║          BLE SPAM v7.1 - COMPILATION                           ║
║          Flipper Zero Production Build                          ║
╚════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Create directories
New-Item -ItemType Directory -Force -Path $BuildDir > $null
New-Item -ItemType Directory -Force -Path $OutputDir > $null

Write-Host "[*] Build directory: $BuildDir" -ForegroundColor Yellow
Write-Host "[*] Output directory: $OutputDir" -ForegroundColor Yellow
Write-Host ""

# Verify FBT exists
$FbtPath = Join-Path $SdkDir "fbt"
if (-not (Test-Path $FbtPath)) {
    Write-Host "❌ ERROR: Flipper firmware fbt not found!" -ForegroundColor Red
    Write-Host "   Expected: $FbtPath" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ FBT found: $FbtPath" -ForegroundColor Green
Write-Host ""

# Build with the official Flipper Build Tool
Write-Host "[1/2] Building FAP with FBT..." -ForegroundColor Cyan
Set-Location $SdkDir
python .\fbt fap_ble_spam "APPSRC=$ProjectDir"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ ERROR: FBT build failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ FBT build successful" -ForegroundColor Green
Write-Host ""

$BuildDir = $SdkDir
# Find and copy .fap
Write-Host "[2/2] Packaging FAP..." -ForegroundColor Cyan

$FapFile = Get-ChildItem -Path $BuildDir -Recurse -Filter "ble_spam.fap" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($FapFile) {
    $DestinationPath = "$OutputDir\ble_spam.fap"
    Copy-Item -Path $FapFile.FullName -Destination $DestinationPath -Force
    
    Write-Host ""
    Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                    ✅ SUCCESS!                                  ║
╚════════════════════════════════════════════════════════════════╝

Package created: $DestinationPath
Size: $([math]::Round($FapFile.Length / 1MB, 2)) MB

📱 NEXT STEPS:

1. Open qFlipper
2. Click: "Install from file"
3. Select: $DestinationPath
4. Install on Flipper
5. Launch: Apps → Bluetooth → BLE Spam

✨ v7.1:
   ✅ Built with the official Flipper Build Tool
   ✅ Manifest dependencies declared
   ✅ SD-card resources packaged correctly

🎉 Ready to deploy!
"@ -ForegroundColor Green
    
    Read-Host "Press Enter to open output folder"
    Invoke-Item $OutputDir
} else {
    Write-Host "❌ ERROR: .fap file not found in build output!" -ForegroundColor Red
    Write-Host "   Searched in: $BuildDir" -ForegroundColor Red
    Write-Host ""
    Write-Host "Found .fap files:" -ForegroundColor Yellow
    Get-ChildItem -Path $BuildDir -Recurse -Filter "*.fap" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "   - $($_.FullName)"
    }
    Read-Host "Press Enter to exit"
    exit 1
}
