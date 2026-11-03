@echo off
REM ============================================================================
REM publish.bat - XpchSdk release packaging entry point
REM
REM Default: build driver + SDK + samples, then package into
REM          <repo>\output\XpchSdk-<version>\
REM
REM Usage:
REM   publish\publish.bat                    build and pack into .\output\
REM   publish\publish.bat -Zip               also produce a .zip archive
REM   publish\publish.bat -NoBuild           skip build, pack existing artifacts
REM   publish\publish.bat -OutputDir D:\dist custom output root
REM   publish\publish.bat -Config Debug      use Debug configuration
REM   publish\publish.bat -IncludeProbe      include the dev probe executable
REM
REM Arguments are forwarded verbatim to pack.ps1.
REM ============================================================================
setlocal

set PUBLISH_DIR=%~dp0
set PACK_PS1=%PUBLISH_DIR%pack.ps1

if not exist "%PACK_PS1%" (
    echo ERROR: pack.ps1 not found at %PACK_PS1%
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