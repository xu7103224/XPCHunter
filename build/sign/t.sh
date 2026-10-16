#!/bin/bash
# t.sh <标签> — 可靠的单次实机加载测试。
# 强制全量重建，并**断言产物大小**为 643584（否则判为 LTCG 退化产物并拒绝继续），
# 随后签名→唯一文件名推入 Guest→sc create/start→读状态。
# 用法： bash t.sh P1
set -u
TAG="${1:-T}"
MIN_SIZE=500000   # 健康产物约 643584；LTCG 删码退化会缩到 ~43520
ROOT=/e/Work/Dev/Windows/wmprotected/APK/XPCHunter
KD="C:/Users/Administrator/.agents/skills/kd-dual-debug/scripts/kd.py"
SVCT="RT$TAG"
GF="rt_$TAG.sys"

echo "=== [$TAG] 全量重建（含退化产物重试）==="
SZ=0
for TRY in 1 2 3 4 5; do
  rm -rf "$ROOT/build/obj/Release" "$ROOT/build/bin/Release"
  ( cd "$ROOT/build" && cmd //c "build.bat" > /tmp/rt_build_$TAG.log 2>&1 )
  SZ=$(stat -c %s "$ROOT/build/bin/Release/x64/XPCHunterDrv.sys" 2>/dev/null || echo 0)
  if [ "$SZ" -ge 500000 ] && [ "$SZ" -ne 2097152 ]; then break; fi
  echo "  [重试 $TRY] 产物 size=$SZ（LTCG 退化），kill 链接器后重来"
  cmd //c "taskkill /F /IM link.exe /IM cl.exe /IM MSBuild.exe /IM mspdbsrv.exe >nul 2>&1" || true
  sleep 6
done
echo "BUILD size=$SZ (min=$MIN_SIZE)"
if [ "$SZ" -lt "$MIN_SIZE" ]; then
  echo "RESULT=BUILD_DEGENERATE  (测试无效，中止)"
  grep -iE "error|warning C4715" /tmp/rt_build_$TAG.log | head -5
  exit 3
fi
if grep -qiE "error C" /tmp/rt_build_$TAG.log; then
  echo "RESULT=BUILD_ERROR"; grep -iE "error C" /tmp/rt_build_$TAG.log | head -5; exit 4
fi

echo "=== [$TAG] 签名 ==="
( cd "$ROOT/build/sign" && cmd //c "host_sign.bat" > /tmp/rt_sign_$TAG.log 2>&1 )
grep -q "SIGN_EXIT=0" /tmp/rt_sign_$TAG.log || { echo "RESULT=SIGN_FAIL"; tail -5 /tmp/rt_sign_$TAG.log; exit 5; }
HOSTSHA=$(sha1sum "$ROOT/build/sign/XPCHunterDrv_signed.sys" | cut -d" " -f1 | tr a-f A-F)
echo "HOST_SHA1=$HOSTSHA"

echo "=== [$TAG] 部署 ==="
cd "C:/Users/Administrator/.agents/skills/kd-dual-debug/scripts"
python "$KD" guest exec "sc stop $SVCT >nul 2>&1 & sc delete $SVCT >nul 2>&1 & exit /b 0" >/dev/null 2>&1
python "$KD" guest copy-in "E:\\Work\\Dev\\Windows\\wmprotected\\APK\\XPCHunter\\build\\sign\\XPCHunterDrv_signed.sys" "C:\\kd_tmp\\$GF" 2>&1 | tail -1

echo "=== [$TAG] 加载 ==="
python "$KD" guest exec "sc create $SVCT type= kernel start= demand binPath= \\??\\C:\\kd_tmp\\$GF & exit /b 0" >/dev/null 2>&1
python "$KD" guest exec "sc start $SVCT & exit /b 0" 2>&1 | grep -E "StartService|失败" | head -2
python "$KD" guest exec "sc query $SVCT | findstr /i \"STATE WIN32_EXIT\" & exit /b 0" 2>&1 | grep -E "STATE|EXIT"
python "$KD" guest exec "sc stop $SVCT >nul 2>&1 & timeout /t 1 >nul & sc delete $SVCT >nul 2>&1 & exit /b 0" >/dev/null 2>&1
echo "=== [$TAG] 完成 ==="