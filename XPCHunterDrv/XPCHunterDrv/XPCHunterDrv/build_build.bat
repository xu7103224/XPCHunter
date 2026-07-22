@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (echo vcvars failed > build_result.txt & exit /b 1)
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:m > build_result.txt 2>&1
echo msbuild_exit_code=%errorlevel% >> build_result.txt
