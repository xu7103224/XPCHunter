#!/bin/bash
# 分段 A/B 采集：每段 16 条，成功落盘，失败记录并继续。
# 用法: ab_seg.sh <tag>   结果在 build/audit/abseg_<tag>_<lo>.txt
set -u
export MSYS_NO_PATHCONV=1
V='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMR='E:/Apps/VMware/VMware Workstation/vmrun.exe'
TAG="${1:-x}"
LO=32
HI=314
STEP=16
OUT="C:\Users\Public\abseg.txt"
while [ $LO -le $HI ]; do
  END=$((LO+STEP-1)); [ $END -gt $HI ] && END=$HI
  printf "seg 0x%02X-0x%02X ... " $LO $END
  timeout 90 ./build/g.sh "C:\Users\Public\xpch_probe.exe --live --handshake --ab --ab-lo $LO --ab-hi $END --ab-out $OUT > nul 2>&1 & echo GO" >/dev/null 2>&1
  sleep 12
  if timeout 40 ./build/g.sh "verify > nul 2>&1 & echo V" >/dev/null 2>&1; then
    rm -f "build/audit/abseg_${TAG}_${LO}.txt"
    "$VMR" -T ws -gu xuq -gp 123 copyFileFromGuestToHost "$V" "$OUT" "E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\abseg_${TAG}_${LO}.txt" >/dev/null 2>&1
    if [ -s "build/audit/abseg_${TAG}_${LO}.txt" ]; then
      echo "OK ($(grep -c '^CMD' build/audit/abseg_${TAG}_${LO}.txt) recs)"
    else
      echo "NO-DATA"
    fi
  else
    echo "GUEST-DOWN"
  fi
  LO=$((END+1))
done
