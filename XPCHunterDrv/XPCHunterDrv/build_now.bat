@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (echo vcvars failed > build_out.txt & exit /b 1)
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:m > build_out.txt 2>&1
echo msbuild_exit=%errorlevel% >> build_out.txt
