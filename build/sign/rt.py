#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rt.py — 可靠的双机加载测试台（Reliable Test）。

解决的关键问题：msbuild 会静默跳过重编译，导致"改了源码但产物没变"，
后续测试实际测的是陈旧二进制（本轮多次结论矛盾的根因）。

本脚本强制：
  1) 删掉 build/obj 与 build/bin，**保证真正重新编译**；
  2) 校验产物大小 == EXPECT_SIZE（否则视为 LTCG 退化产物，直接判无效并中止）；
  3) 校验 .map 中出现 PROBE_SYMBOL（证明本次改动确实编进去了）；
  4) 签名 → 用**唯一文件名**推入 Guest（避免文件锁）→ sc create/start → 读状态；
  5) 打印 BUILD_VERIFIED / MATCH / LOAD，供上层判断。

用法：python rt.py <标签> [期望符号名]
"""
import hashlib
import os
import re
import subprocess
import sys

sys.path.insert(0, r'C:\Users\Administrator\.agents\skills\kd-dual-debug\scripts')
import kd as K  # noqa: E402

ROOT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter'
BUILD = os.path.join(ROOT, 'build')
SIGN = os.path.join(BUILD, 'sign')
BUILT = os.path.join(BUILD, 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
MAP = os.path.join(BUILD, 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
SIGNED = os.path.join(SIGN, 'XPCHunterDrv_signed.sys')
EXPECT_SIZE = 643584          # 健康产物大小；偏小即 LTCG 删码退化


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, shell=False)
    so = p.stdout.decode('gbk', 'replace') if p.stdout else ''
    se = p.stderr.decode('gbk', 'replace') if p.stderr else ''
    return p.returncode, so + se


def sha1(path):
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 16), b''):
            h.update(b)
    return h.hexdigest().upper()


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else 't'
    sym = sys.argv[2] if len(sys.argv) > 2 else None
    svc = 'RT_' + tag
    gf = 'rt_%s.sys' % tag

    # ---- 1) 强制全量重建 ----
    for d in (os.path.join(BUILD, 'obj', 'Release'), os.path.join(BUILD, 'bin', 'Release')):
        subprocess.run(['cmd', '/c', 'rmdir', '/s', '/q', d], capture_output=True)
    rc, out = run(['cmd', '/c', 'build.bat'], cwd=BUILD)
    if not os.path.isfile(BUILT):
        print('RESULT=BUILD_FAIL'); print(out[-1200:]); return 2
    size = os.path.getsize(BUILT)

    # ---- 2) 产物大小校验 ----
    if size != EXPECT_SIZE:
        print('RESULT=BUILD_DEGENERATE  size=%d (期望 %d) —— LTCG 删码，测试无效'
              % (size, EXPECT_SIZE))
        print(out[-800:])
        return 3

    # ---- 3) 探针符号校验：证明改动确实编进去了 ----
    if sym:
        maptxt = open(MAP, encoding='latin1').read()
        if sym not in maptxt:
            print('RESULT=PROBE_MISSING  %s 不在 map 中 —— msbuild 未重编译该文件' % sym)
            return 4

    # ---- 4) 签名 + 部署 + 加载 ----
    rc, out = run(['cmd', '/c', 'host_sign.bat'], cwd=SIGN)
    if 'SIGN_EXIT=0' not in out:
        print('RESULT=SIGN_FAIL'); print(out[-600:]); return 5

    host = sha1(SIGNED)
    hsz = os.path.getsize(SIGNED)

    env, _ = K.load_env()

    def guest(bat, log, timeout=180):
        if 'exit /b 0' not in bat:
            bat = bat.rstrip() + chr(13) + chr(10) + 'exit /b 0' + chr(13) + chr(10)
        try:
            return K._guest_exec_impl(env, bat, log, timeout)
        except SystemExit:
            return '<exec-nonzero>'

    guest('sc stop %s >nul 2>&1\r\nsc delete %s >nul 2>&1\r\nexit /b 0\r\n'
          % (svc, svc), 'rt_%s_clean.log' % tag, 60)

    K.vmrun(env, '-gu', env['guest']['user'], '-gp', env['guest']['password'],
            'copyFileFromHostToGuest', env['vm']['vmx'], SIGNED, r'C:\kd_tmp\%s' % gf)

    log = guest('dir C:\\kd_tmp\\%s | findstr /i %s\r\n' % (gf, gf),
                'rt_%s_size.log' % tag, 90)
    m = re.search(r'([\d,]+)\s+%s' % re.escape(gf), log or '')
    gsz = int(m.group(1).replace(',', '')) if m else -1

    guest('sc create %s type= kernel start= demand binPath= \\??\\C:\\kd_tmp\\%s\r\n'
          'timeout /t 2 >nul\r\nsc start %s\r\n' % (svc, gf, svc),
          'rt_%s_load.log' % tag, 150)
    st = guest('sc query %s | findstr /i "STATE WIN32_EXIT"\r\n' % svc,
               'rt_%s_st.log' % tag, 90)
    stt = re.search(r'STATE\s*:\s*\d+\s+(\S+)', st or '')
    code = re.search(r'WIN32_EXIT_CODE\s*:\s*(\d+)', st or '')

    print('--- sc query 输出 ---'); print(repr(st))
    print('BUILD_VERIFIED=yes  size=%d  sha1=%s' % (size, host))
    print('MATCH=%s (host=%d guest=%d)' % ('yes' if gsz == hsz else 'NO', hsz, gsz))
    print('LOAD=%s%s' % (stt.group(1) if stt else '?',
                       '' if (code and code.group(1) == '0')
                       else ':err' + (code.group(1) if code else '?')))

    if stt and stt.group(1) == 'RUNNING':
        guest('sc stop %s\r\ntimeout /t 2 >nul\r\nsc delete %s\r\nexit /b 0\r\n'
              % (svc, svc), 'rt_%s_stop.log' % tag, 90)
    return 0


if __name__ == '__main__':
    sys.exit(main())