@echo off
set F=C:\Users\Public\xpch_frontend.exe
echo ===== G4 CLI SWEEP (current build) =====
echo.
for %%C in (
  "--g4-status-cli"
  "--os-cli"
  "--kernel-cli"
  "--kernel-extra-cli"
  "--idt-cli"
  "--gdt-cli"
  "--ioport-cli"
  "--ssdt-cli"
  "--ring0-cli"
  "--hiddendrv-cli"
  "--drivers-cli"
  "--setting-cli"
  "--forbid-cli"
  "--exam-cli"
  "--fireeye-cli"
  "--trojan-cli"
  "--services-cli"
  "--startup-cli"
  "--files-cli C:\Windows"
  "--filever-cli C:\Windows\System32\ntoskrnl.exe"
  "--filesig-cli C:\Windows\System32\ntoskrnl.exe"
  "--reghandles-cli"
  "--reghidden-cli"
  "--regkey-cli HKLM\SOFTWARE\Microsoft"
  "--hooks-cli 0"
) do (
  echo.
  echo ---------- %%C ----------
  %F% %%C 2>&1
)
echo.
echo ===== SWEEP DONE =====
