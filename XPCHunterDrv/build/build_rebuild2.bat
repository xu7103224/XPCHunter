@echo off
setlocal enabledelayedexpansion
cd /d "E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv"
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:m > E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv\build\msbuild_full.log 2>&1
echo EXIT_CODE=%errorlevel%