#!/bin/bash
# Run a command in the win10dev guest over VMware Tools guest-ops and print its output.
# Usage: g.sh "command line"    -> wraps it in a .bat with output redirect, runs, prints output
# Output kept at build/g_out.txt.
#
# 每次用唯一的 bat/out 文件名：guest 里卡住的旧 cmd 会锁住同名 .bat，
# 复用 g_run.bat 时推送后运行看到的还是旧内容。
set -u
export MSYS_NO_PATHCONV=1
V='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMR='E:/Apps/VMware/VMware Workstation/vmrun.exe'
BASE="$(cd "$(dirname "$0")" && pwd)"
WBASE="$(cygpath -w "$BASE")"
TAG="zq$$"
OUT="$BASE/g_out.txt"
WOUT="$WBASE\\g_out.txt"
BAT="$BASE/g_run_$TAG.bat"
WBAT="$WBASE\\g_run_$TAG.bat"
GBAT="C:\\Users\\Public\\g_run_$TAG.bat"
GOUT="C:\\Users\\Public\\g_out_$TAG.txt"

{
  echo '@echo off'
  echo "($*) > $GOUT 2>&1"
  echo "if errorlevel 1 echo [exit=%errorlevel%] >> $GOUT"
} | sed 's/$/\r/' > "$BAT"

"$VMR" -T ws -gu xuq -gp 123 copyFileFromHostToGuest "$V" "$WBAT" "$GBAT" >/dev/null 2>&1
"$VMR" -T ws -gu xuq -gp 123 runProgramInGuest "$V" 'C:\Windows\System32\cmd.exe' /c "$GBAT" >/dev/null 2>&1
sleep 3
rm -f "$OUT"
"$VMR" -T ws -gu xuq -gp 123 copyFileFromGuestToHost "$V" "$GOUT" "$WOUT" >/dev/null 2>&1
cat "$OUT" 2>/dev/null
rm -f "$BAT"
