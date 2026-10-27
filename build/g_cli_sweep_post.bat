@echo off
set F=C:\Users\Public\xpch_frontend.exe
set OUT=C:\Users\Public\cli_base.txt
echo ===== CLI BASELINE SWEEP ===== > %OUT%
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
  "--proclist-cli"
  "--handles-cli 4"
  "--threads-cli 4"
  "--windows-cli 4"
  "--memory-cli 4"
  "--modules-cli 4"
  "--hotkeys-cli 4"
  "--modsearch-cli ntoskrnl.exe"
  "--regctx-cli"
  "--drvop-cli"
  "--startup-op-cli"
  "--proc-op-cli"
  "--dumpmem-cli 0xFFFFF78000000000"
  "--reg-cli"
  "--network-cli"
  "--scan-cli"
  "--cbtable-cli"
  "--ssdt-restore-cli 999999"
  "--kill-cli 999999"
  "--kill28-cli 999999"
) do (
  echo.>> %OUT%
  echo ---------- %%C ---------- >> %OUT%
  %F% %%C 2>&1 >> %OUT%
)
echo ===== SWEEP DONE ===== >> %OUT%
copy /y %OUT% C:\Users\Public\cli_post_split.txt > nul
echo DONE > C:\Users\Public\cli_flag.txt
