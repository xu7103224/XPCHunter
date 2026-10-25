#!/bin/bash
# A/B 单命令采集 —— 每条命令一个独立 probe 进程。
#
# 为什么这样：全量扫描时某条命令会 BSOD 0x50，一条崩掉整个采集就断了。
# 改成每条独立进程后，崩一条只损失一条，记 CRASH 0xNNN 后重启 guest 继续。
#
# 用法: ab_one.sh <tag> <lo> <hi>
#   tag = mine | orig
# 输出: build/audit/ab1_<tag>.txt   每行一条 CMD/IN/OUT，或 CRASH/NOGUEST
set -u
export MSYS_NO_PATHCONV=1
V='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMR='E:/Apps/VMware/VMware Workstation/vmrun.exe'
TAG="${1:?tag}"
LO="${2:?lo}"
HI="${3:?hi}"
OUT="build/audit/ab1_${TAG}.txt"
GUEST_OUT='C:\Users\Public\ab1.txt'

guest_alive() {
  timeout 25 ./build/g.sh "echo PING" 2>/dev/null | grep -q PING
}

restart_guest() {
  echo "    [restart guest]"
  # 用 ntDrive 硬重启；失败就重试一次
  timeout 300 bash -c 'true'  # 占位，真正的重启由外层 MCP 完成
}

pull() {
  rm -f "$OUT.tmp"
  "$VMR" -T ws -gu xuq -gp 123 copyFileFromGuestToHost "$V" "$GUEST_OUT" \
      "$(cygpath -w "$OUT.tmp")" >/dev/null 2>&1
  [ -s "$OUT.tmp" ] && cat "$OUT.tmp"
  rm -f "$OUT.tmp"
}

: > "$OUT"
echo "# A/B single-command collect  tag=$TAG  range=0x$(printf %02X $LO)..0x$(printf %02X $HI)" >> "$OUT"

c=$LO
while [ $c -le $HI ]; do
  hex=$(printf '0x%02X' $c)
  if ! guest_alive; then
    echo "CRASH $hex  (guest down before send)" >> "$OUT"
    echo "  $hex: GUEST-DOWN"
    c=$((c+1))
    continue
  fi

  # 单条采集
  timeout 60 ./build/g.sh "C:\\Users\\Public\\xpch_probe.exe --live --handshake --ab --ab-lo $c --ab-hi $c --ab-out $GUEST_OUT > nul 2>&1 & echo GO" >/dev/null 2>&1
  sleep 6

  got=$(pull)
  if [ -n "$got" ]; then
    echo "$got" | grep -E '^(CMD|IN|OUT)' >> "$OUT"
    echo "  $hex: OK"
  else
    echo "CRASH $hex" >> "$OUT"
    echo "  $hex: CRASH"
  fi
  c=$((c+1))
done
echo "# done" >> "$OUT"