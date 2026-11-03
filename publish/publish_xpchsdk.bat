@echo off
REM ============================================================================
REM publish_xpchsdk.bat - XpchSdk release packaging
REM
REM Product: XpchSdk (kernel capability SDK)
REM
REM This script SIGNS the driver and produces driver_pkg/ with three files:
REM     XPCHunterDrv.inf / XPCHunterDrv.sys / XPCHunterDrv.cat
REM It does NOT build a CAB. Pack those three files into a CAB yourself
REM (makecab or any MSZIP cabinet tool), then upload it to Microsoft.
REM
REM Release mode (default) - sign with your EV certificate:
REM   publish\publish_xpchsdk.bat -PfxPath D:\ev.pfx -PfxPassword ***
REM   -> output\XpchSdk-<ver>\driver_pkg\
REM
REM Internal test mode - self-signed, local VM/debug only:
REM   publish\publish_xpchsdk.bat -TestSign
REM   Target machine needs testsigning on or the exported cert installed.
REM   Do NOT distribute this build.
REM
REM Common options:
REM   -NoBuild               skip compile, pack existing artifacts
REM   -Zip                   also produce a .zip
REM   -OutputDir D:\dist     custom output root
REM   -Config Debug          use Debug configuration
REM
REM Arguments are forwarded verbatim to pack_xpchsdk.ps1.
REM ============================================================================
setlocal

set PUBLISH_DIR=%~dp0
set PACK_PS1=%PUBLISH_DIR%pack_xpchsdk.ps1

if not exist "%PACK_PS1%" (
    echo ERROR: pack_xpchsdk.ps1 not found at %PACK_PS1%
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PACK_PS1%" %*
set RC=%ERRORLEVEL%

if %RC% neq 0 (
    echo.
    echo ============================================
    echo PACKAGING FAILED, exit code %RC%
    echo ============================================
)

exit /b %RC%