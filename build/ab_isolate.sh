#!/bin/bash
# 逐条隔离 A/B 测试：每条命令前重新装载驱动，排除前序命令的状态级联。
#
# 用法: ab_isolate.sh <tag> <cmd...>
#   tag = mine | orig
# 每个命令独立跑一次，结果写到 build/audit/iso_<tag>_<cmd>.txt
set -u
export MSYS_NO_PATHCONV=1
V='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMR='E:/Apps/VMware/VMware Workstation/vmrun.exe'
TAG="${1:?tag}"; shift

if [ "$TAG" = "mine" ]; then START=XPCHunterDrv; OTHER=View++ByLinxer
else START=View++ByLinxer; OTHER=XPCHunterDrv; fi

for c in "$@"; do
  OUT="build/audit/iso_${TAG}_${c}.txt"
  rm -f "$OUT"
  echo "=== 0x$c ==="
  # 干净重启：停另一个，停+起目标
  timeout 60 ./build/g.sh "sc stop $OTHER > nul 2>&1 & sc stop $START > nul 2>&1 & timeout /t 4 >nul & sc start $START > nul 2>&1 & timeout /t 3 >nul & sc query $START | findstr STATE" >/dev/null 2>&1
  timeout 45 ./build/g.sh "C:\\Users\\Public\\xpch_probe.exe --live --handshake --ab --ab-lo 0x$c --ab-hi 0x$c --ab-out C:\\Users\\Public\\iso.txt > nul 2>&1 & echo GO" >/dev/null 2>&1
  sleep 10
  "$VMR" -T ws -gu xuq -gp 123 copyFileFromGuestToHost "$V" 'C:\Users\Public\iso.txt' \
      "$(cygpath -w "$OUT")" >/dev/null 2>&1
  if [ -s "$OUT" ]; then
    grep -E '^CMD' "$OUT" | head -1
  else
    echo "  NO-DATA (guest down or command crashed)"
  fi
done