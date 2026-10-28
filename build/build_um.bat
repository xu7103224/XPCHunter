@echo off
REM ============================================
REM XPCHunterUM build script (user-mode client)
REM ============================================
setlocal enabledelayedexpansion

set BUILD_CFG=%1
if "%BUILD_CFG%"=="" set BUILD_CFG=Release

set VS2019_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools
set BASE_DIR=%~dp0..
set SRC_DIR=%BASE_DIR%\XPCHunterUM\src
set INC_DIR=%BASE_DIR%\XPCHunterUM\inc
set OBJ_DIR=%BASE_DIR%\build\obj\%BUILD_CFG%\um_x64
set BIN_DIR=%BASE_DIR%\build\bin\%BUILD_CFG%\um_x64

call "%VS2019_DIR%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul

if /I "%BUILD_CFG%"=="Clean" (
    rmdir /s /q "%OBJ_DIR%" 2>nul
    rmdir /s /q "%BIN_DIR%" 2>nul
    echo Clean complete.
    exit /b 0
)

mkdir "%OBJ_DIR%" 2>nul
mkdir "%BIN_DIR%" 2>nul

echo Compiling user-mode client...
cl /nologo /c /W3 /O2 /GS /guard:cf- /utf-8 /DUNICODE /D_UNICODE ^
   /I"%INC_DIR%" ^
   /Fo"%OBJ_DIR%\\" ^
   "%SRC_DIR%\FeProcPage.c" "%SRC_DIR%\FeStartupPage.c" "%SRC_DIR%\FeServicePage.c" "%SRC_DIR%\FeNetworkPage.c" "%SRC_DIR%\FeRegistryPage.c" "%SRC_DIR%\FeFilePage.c" "%SRC_DIR%\FeOtherPage.c" "%SRC_DIR%\FeExamPage.c" "%SRC_DIR%\FeFireeyePage.c" "%SRC_DIR%\FeSettingPage.c" "%SRC_DIR%\FeTrojanPage.c" "%SRC_DIR%\FeHookPage.c" "%SRC_DIR%\FeKernelPage.c" "%SRC_DIR%\FeTheme.c" "%SRC_DIR%\FeDpi.c" "%SRC_DIR%\FeMenu.c" "%SRC_DIR%\FeSchedulePage.c" "%SRC_DIR%\FeCommonMenu.c" "%SRC_DIR%\FeFileTools.c" "%SRC_DIR%\FeFileDlg.c" "%SRC_DIR%\FeSystemViews.c" "%SRC_DIR%\Protocol.c" "%SRC_DIR%\ProcessList.c" "%SRC_DIR%\ProcessViews.c" "%SRC_DIR%\KernelViews.c" "%SRC_DIR%\StartupViews.c" "%SRC_DIR%\ServiceViews.c" "%SRC_DIR%\RegistryViews.c" "%SRC_DIR%\FileViews.c" "%SRC_DIR%\OtherViews.c" "%SRC_DIR%\ExaminationViews.c" "%SRC_DIR%\FireeyeViews.c" "%SRC_DIR%\SettingViews.c" "%SRC_DIR%\TrojanViews.c" "%SRC_DIR%\HookViews.c" "%SRC_DIR%\KernelHookViews.c" "%SRC_DIR%\NetworkViews.c" "%SRC_DIR%\DriverOps.c" "%SRC_DIR%\ProcessOps.c" "%SRC_DIR%\probe.c" "%SRC_DIR%\CliMain.c" "%SRC_DIR%\frontend.c"

if errorlevel 1 (
    echo ERROR: compile failed
    exit /b 1
)

echo Linking probe...
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OPT:REF /OPT:NOICF ^
     /OUT:"%BIN_DIR%\xpch_probe.exe" ^
     "%OBJ_DIR%\Protocol.obj" "%OBJ_DIR%\probe.obj" ^
     kernel32.lib user32.lib advapi32.lib

if errorlevel 1 (
    echo ERROR: link probe failed
    exit /b 1
)

echo Linking frontend...
link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OPT:REF /OPT:NOICF ^
     /OUT:"%BIN_DIR%\xpch_frontend.exe" ^
     "%OBJ_DIR%\FeProcPage.obj" "%OBJ_DIR%\FeStartupPage.obj" "%OBJ_DIR%\FeServicePage.obj" "%OBJ_DIR%\FeNetworkPage.obj" "%OBJ_DIR%\FeRegistryPage.obj" "%OBJ_DIR%\FeFilePage.obj" "%OBJ_DIR%\FeOtherPage.obj" "%OBJ_DIR%\FeExamPage.obj" "%OBJ_DIR%\FeFireeyePage.obj" "%OBJ_DIR%\FeSettingPage.obj" "%OBJ_DIR%\FeTrojanPage.obj" "%OBJ_DIR%\FeHookPage.obj" "%OBJ_DIR%\FeKernelPage.obj" "%OBJ_DIR%\FeTheme.obj" "%OBJ_DIR%\FeDpi.obj" "%OBJ_DIR%\FeMenu.obj" "%OBJ_DIR%\FeSchedulePage.obj" "%OBJ_DIR%\FeCommonMenu.obj" "%OBJ_DIR%\FeFileTools.obj" "%OBJ_DIR%\FeFileDlg.obj" "%OBJ_DIR%\FeSystemViews.obj" "%OBJ_DIR%\Protocol.obj" "%OBJ_DIR%\CliMain.obj" "%OBJ_DIR%\frontend.obj" "%OBJ_DIR%\ProcessList.obj" "%OBJ_DIR%\ProcessViews.obj" "%OBJ_DIR%\KernelViews.obj" "%OBJ_DIR%\StartupViews.obj" "%OBJ_DIR%\ServiceViews.obj" "%OBJ_DIR%\RegistryViews.obj" "%OBJ_DIR%\FileViews.obj" "%OBJ_DIR%\OtherViews.obj" "%OBJ_DIR%\ExaminationViews.obj" "%OBJ_DIR%\FireeyeViews.obj" "%OBJ_DIR%\SettingViews.obj" "%OBJ_DIR%\TrojanViews.obj" "%OBJ_DIR%\HookViews.obj" "%OBJ_DIR%\KernelHookViews.obj" "%OBJ_DIR%\NetworkViews.obj" "%OBJ_DIR%\DriverOps.obj" "%OBJ_DIR%\ProcessOps.obj" ^
     kernel32.lib user32.lib advapi32.lib comctl32.lib psapi.lib gdi32.lib version.lib shell32.lib wintrust.lib crypt32.lib netapi32.lib

if errorlevel 1 (
    echo ERROR: link frontend failed
    exit /b 1
)

echo Embedding DPI manifest...
set MT=
for /f "delims=" %%M in ('where mt.exe 2^>nul') do if not defined MT set MT=%%M
if not defined MT if exist "%ProgramFiles(x86)%\Windows Kits\10\bin" (
    for /d %%V in ("%ProgramFiles(x86)%\Windows Kits\10\bin\10.*") do (
        if not defined MT if exist "%%~V\x64\mt.exe" set MT=%%~V\x64\mt.exe
    )
)
if defined MT (
    "%MT%" -nologo -manifest "%BASE_DIR%\XPCHunterUM\res\xpch_frontend.manifest" -outputresource:"%BIN_DIR%\xpch_frontend.exe;#1"
    if errorlevel 1 echo WARNING: manifest embed failed
) else (
    echo WARNING: mt.exe not found - manifest not embedded
)

echo Build complete: %BIN_DIR%\xpch_probe.exe
echo Build complete: %BIN_DIR%\xpch_frontend.exe
exit /b 0