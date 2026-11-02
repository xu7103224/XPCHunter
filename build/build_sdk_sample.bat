@echo off
REM ============================================
REM XpchSdk sample build script
REM
REM Requires: run build_sdk.bat first (produces XpchSdk.lib)
REM Output:   build\bin\%CFG%\sdk_x64\XpchSdkSample.exe
REM ============================================
setlocal enabledelayedexpansion

set BUILD_CFG=%1
if "%BUILD_CFG%"=="" set BUILD_CFG=Release

set VS2019_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools
set BASE_DIR=%~dp0..
set SDK_DIR=%BASE_DIR%\src\sdk
set LIB_DIR=%BASE_DIR%\build\bin\%BUILD_CFG%\sdk_x64
set OBJ_DIR=%BASE_DIR%\build\obj\%BUILD_CFG%\sdk_x64

call "%VS2019_DIR%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul

if not exist "%LIB_DIR%\XpchSdk.lib" (
    echo ERROR: XpchSdk.lib not found. Run build_sdk.bat first.
    exit /b 1
)

echo Compiling sample...
cl /nologo /W3 /O2 /GS /guard:cf- /utf-8 /DUNICODE /D_UNICODE ^
   /I"%SDK_DIR%\inc" ^
   /Fo"%OBJ_DIR%\\" ^
   /Fe"%LIB_DIR%\XpchSdkSample.exe" ^
   "%SDK_DIR%\samples\XpchSdkSample.c" ^
   "%LIB_DIR%\XpchSdk.lib" ^
   advapi32.lib wintrust.lib crypt32.lib psapi.lib

if errorlevel 1 (
    echo ERROR: sample build failed
    exit /b 1
)

echo Build complete: %LIB_DIR%\XpchSdkSample.exe
exit /b 0