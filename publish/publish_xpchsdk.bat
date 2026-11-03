@echo off
REM ============================================================================
REM publish_xpchsdk.bat - XpchSdk release packaging
REM
REM Product: XpchSdk (kernel capability SDK)
REM
REM Release mode (default) - produce a driver package for Microsoft signing:
REM   publish\publish_xpchsdk.bat -PfxPath D:\ev.pfx -PfxPassword ***
REM   -> output\XpchSdk-<ver>\submit\XPCHunterDrv.cab
REM   Upload that CAB to the Microsoft Hardware Dev Center. After Microsoft
REM   countersigns it, the returned CAB loads on end-user machines with no
REM   certificate install and no test signing.
REM
REM Internal test mode - self-signed, for local VM/debug only:
REM   publish\publish_xpchsdk.bat -TestSign
REM   -> same layout, but signed with the local test cert
REM   Target machine needs testsigning on or the exported cert installed.
REM   Do NOT distribute this build.
REM
REM Common options:
REM   -NoBuild               skip compile, pack existing artifacts
REM   -Zip                   also produce a .zip
REM   -OutputDir D:\dist     custom output root
REM   -Config Debug          use Debug configuration
REM   -NoSign                no signature at all (inspect contents only)
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