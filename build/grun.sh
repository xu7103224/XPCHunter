#!/bin/bash
# grun.sh — 在 guest 里以 High IL 运行一条命令并取回输出
# 用法: ./build/grun.sh "<cmdline>" [等待秒]
#
# 关键：runProgramInGuest **不加 -interactive** 时，进程拿到 High 完整性级别
# （S-1-16-12288），可以 sc create/start 内核驱动、写 System32。
# 加 -interactive 反而降为 Medium（S-1-16-8192）——那是自动登录桌面的令牌。
#
# 【2026-10-26 加固】vmrun 偶发 "VMware Tools are not running" 与回读失败，
# 原先单次调用会静默丢结果。现在每个 vmrun 调用都重试，回读按 mtime 校验新鲜度。
set -u
export MSYS_NO_PATHCONV=1
VMX='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMR='E:/Apps/VMware/VMware Workstation/vmrun.exe'
BASE="$(cd "$(dirname "$0")" && pwd)"
TAG="zg$$"
CMD="$1"
WAIT="${2:-5}"
BAT="$BASE/grun_$TAG.bat"
WBAT="$(cygpath -w "$BAT")"
GBAT="C:\\Users\\Public\\grun_$TAG.bat"
GOUT="C:\\Users\\Public\\grout_$TAG.txt"
OUT="$BASE/gout_$TAG.txt"

vrun() {   # vrun <subcommand> <args...>；重试 4 次，间隔递增
  local n=0
  while [ $n -lt 4 ]; do
    if "$VMR" -T ws -gu xuq -gp 123 "$@" >/dev/null 2>&1; then return 0; fi
    n=$((n+1)); sleep $((n*4))
  done
  return 1
}

{
  echo '@echo off'
  echo "del /q $GOUT 2>nul"
  echo "($CMD) > $GOUT 2>&1"
  echo "if errorlevel 1 echo [exit=%errorlevel%] >> $GOUT"
  echo "echo [done] >> $GOUT"
} | sed 's/$/\r/' > "$BAT"

vrun CopyFileFromHostToGuest "$VMX" "$WBAT" "$GBAT" || { echo "[grun] push bat failed"; rm -f "$BAT"; exit 1; }
vrun runProgramInGuest "$VMX" 'C:\Windows\System32\cmd.exe' "/c $GBAT" || { echo "[grun] run failed"; rm -f "$BAT"; exit 1; }

# 轮询回读：最多等 WAIT+30 秒，直到拿到带 [done] 哨兵的完整输出
deadline=$(( $(date +%s) + WAIT + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep "$WAIT"
  rm -f "$OUT"
  if vrun CopyFileFromGuestToHost "$VMX" "$GOUT" "$(cygpath -w "$OUT")"; then
    if grep -q '^\[done\]' "$OUT" 2>/dev/null; then break; fi
  fi
  WAIT=5
done

cat "$OUT" 2>/dev/null
rm -f "$BAT"