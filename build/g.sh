#!/bin/bash
# Run a command in the win10dev guest over VMware Tools guest-ops and print its output.
# Usage: g.sh "command line"    -> wraps it in a .bat with output redirect, runs, prints output
# Output kept at build/g_out.txt.
set -u
export MSYS_NO_PATHCONV=1
V='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMR='E:/Apps/VMware/VMware Workstation/vmrun.exe'
BASE="$(cd "$(dirname "$0")" && pwd)"
WBASE="$(cygpath -w "$BASE")"
OUT="$BASE/g_out.txt"
WOUT="$WBASE\\g_out.txt"
BAT="$BASE/g_run.bat"
WBAT="$WBASE\\g_run.bat"

{
  echo '@echo off'
  echo "($*) > C:\\Users\\Public\\g_out.txt 2>&1"
  echo 'if errorlevel 1 echo [exit=%errorlevel%] >> C:\Users\Public\g_out.txt'
} | sed 's/$/\r/' > "$BAT"

"$VMR" -T ws -gu xuq -gp 123 copyFileFromHostToGuest "$V" "$WBAT" 'C:\Users\Public\g_run.bat' >/dev/null 2>&1
"$VMR" -T ws -gu xuq -gp 123 runProgramInGuest "$V" 'C:\Windows\System32\cmd.exe' /c 'C:\Users\Public\g_run.bat' >/dev/null 2>&1
rm -f "$OUT"
"$VMR" -T ws -gu xuq -gp 123 copyFileFromGuestToHost "$V" 'C:\Users\Public\g_out.txt' "$WOUT" >/dev/null 2>&1
cat "$OUT" 2>/dev/null
