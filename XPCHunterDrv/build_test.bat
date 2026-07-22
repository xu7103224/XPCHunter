@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (echo vcvars failed & exit /b 1)
echo vcvars done
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:m
echo msbuild exit: %errorlevel%
