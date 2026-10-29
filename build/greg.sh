#!/bin/bash
# greg.sh — 通过 vmrun guest 通道在 Win10_Dev 里跑批处理并取回输出
#
# 用法：
#   ./build/greg.sh <guest.bat> <host输出文件> [超时秒]
#
# <guest.bat> 是本机路径的 .bat，会被推到 C:\Users\Public\greg_\<basename>，
# 在 guest 里以交互方式执行，然后把 C:\Users\Public\greg_out.txt 取回到
# <host输出文件>。
#
# 背景：本 VM 的 OpenSSH 在 pre_g2hi 快照里不存在，SSH 通道不可用；
# vmrun 的 runProgramInGuest 是当前唯一可用的 guest 执行通道。

set -u
VMX='F:\VirtualMachine\Win10_x64_Dev_1903\Win10_1903\Windows 10 x64.vmx'
VMRUN='/e/Apps/VMware/VMware Workstation/vmrun.exe'
GU='xuq'
GP='123'
BASE=$(cd "$(dirname "$0")" && pwd)

BAT_LOCAL="$1"
OUT_LOCAL="$2"
WAIT="${3:-5}"

if [ ! -f "$BAT_LOCAL" ]; then echo "no such bat: $BAT_LOCAL" >&2; exit 1; fi
NAME=$(basename "$BAT_LOCAL")
GUEST_BAT="C:\\Users\\Public\\greg_$NAME"
GUEST_OUT='C:\Users\Public\greg_out.txt'

rm -f "$OUT_LOCAL" 2>/dev/null

"$VMRUN" -T ws -gu "$GU" -gp "$GP" CopyFileFromHostToGuest "$VMX" \
    "$BAT_LOCAL" "$GUEST_BAT" >/dev/null 2>&1
RC1=$?

"$VMRUN" -T ws -gu "$GU" -gp "$GP" runProgramInGuest "$VMX" -interactive \
    'C:\Windows\System32\cmd.exe' "/c $GUEST_BAT" >/dev/null 2>&1
RC2=$?

sleep "$WAIT"

"$VMRUN" -T ws -gu "$GU" -gp "$GP" CopyFileFromGuestToHost "$VMX" \
    "$GUEST_OUT" "$OUT_LOCAL" >/dev/null 2>&1
RC3=$?

if [ -f "$OUT_LOCAL" ]; then
    cat "$OUT_LOCAL"
    exit 0
fi
echo "greg: copy-back failed (push=$RC1 run=$RC2 copy=$RC3)" >&2
exit 1