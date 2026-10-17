@echo off
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
set OUT=C:\Users\Public\sc8b.txt
echo === R8B RUN %DATE% %TIME% === > %OUT%
sc start RTZ8 >> %OUT% 2>&1
sc query RTZ8 >> %OUT% 2>&1
echo === DONE === >> %OUT%
