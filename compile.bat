@echo off
REM Compilation script for BLE Spam FAP
REM Flipper Zero - Windows

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "SDK_DIR=%FLIPPER_SDK%"
if not defined SDK_DIR set "SDK_DIR=C:\flipperzero-firmware"
set OUTPUT_DIR=%PROJECT_DIR%\dist

echo.
echo ================================================
echo   BLE Spam v7.0 - Compilation Script
echo ================================================
echo.

REM Create build directories
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM Check FBT
if not exist "%SDK_DIR%\fbt" (
    echo ERROR: Flipper firmware fbt not found!
    echo Path: %SDK_DIR%\fbt
    pause
    exit /b 1
)

echo [*] FBT found: %SDK_DIR%\fbt
echo [*] Building BLE Spam v7.1...
echo.

cd /d "%SDK_DIR%"
echo [1/2] Building with FBT...
python fbt fap_ble_spam "APPSRC=%PROJECT_DIR%"

if errorlevel 1 (
    echo ERROR: FBT build failed!
    pause
    exit /b 1
)

echo.
echo [2/2] Packaging FAP...

REM Find and copy .fap file
for /r "%SDK_DIR%" %%f in (ble_spam.fap) do (
    echo Found: %%f
    copy "%%f" "%OUTPUT_DIR%\ble_spam.fap"
    if exist "%OUTPUT_DIR%\ble_spam.fap" (
        echo.
        echo ================================================
        echo   ✅ SUCCESS!
        echo ================================================
        echo.
        echo Package: %OUTPUT_DIR%\ble_spam.fap
        for %%A in ("%OUTPUT_DIR%\ble_spam.fap") do echo Size: %%~zA bytes
        echo.
        echo Next steps:
        echo 1. Open qFlipper
        echo 2. Install from file: %OUTPUT_DIR%\ble_spam.fap
        echo 3. Launch on Flipper!
        echo.
        pause
        exit /b 0
    )
)

echo.
echo ERROR: .fap file not found in build output!
echo Checked: %SDK_DIR%
dir /s /b "%SDK_DIR%\*.fap"
pause
exit /b 1
