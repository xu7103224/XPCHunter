@echo off
echo "Starting build..."
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
echo vcvars_exit=%errorlevel%
if %errorlevel% neq 0 (echo vcvars failed & exit /b 1)
echo Running msbuild...
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:m > build_new.txt 2>&1
echo msbuild_exit=%errorlevel%
echo Done
