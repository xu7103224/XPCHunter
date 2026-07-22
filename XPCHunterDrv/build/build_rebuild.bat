@echo off
setlocal enabledelayedexpansion
echo Starting build...
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
echo.
echo ============================================
echo Step 1: msbuild Rebuild...
echo ============================================
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:m
echo EXIT_CODE_MSBUILD=%errorlevel%
if %errorlevel% neq 0 exit /b 1
echo.
echo ============================================
echo Step 2: Linking...
echo ============================================
set WDK_DIR=C:\Program Files (x86)\Windows Kits\10
set WDK_VER=10.0.19041.0
set OBJ_DIR=E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv\build\obj\Release\x64
set BIN_DIR=E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv\build\bin\Release\x64
link /nologo /kernel /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /driver /merge:.data=.text /manifest:no /LIBPATH:"%WDK_DIR%\Lib\%WDK_VER%\km\x64" /LIBPATH:"%WDK_DIR%\Lib\%WDK_VER%\km\x64\crt" /out:"%BIN_DIR%\XPCHunterDrv.sys" /pdb:"%BIN_DIR%\XPCHunterDrv.pdb" /map:"%BIN_DIR%\XPCHunterDrv.map" "%OBJ_DIR%\*.obj" ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib BufferOverflowK.lib bufferoverflowfastfailk.lib
echo EXIT_CODE_LINK=%errorlevel%
if %errorlevel% neq 0 exit /b 1
echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
dir "%BIN_DIR%\XPCHunterDrv.sys"