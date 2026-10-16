#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_test.py — 可靠地「编译→签名→部署→加载」一次，并**校验哈希**，
确保测的确实是刚编出来的那份（此前踩过的坑：旧文件被占用导致测到陈旧二进制）。

用法：
  python probe_test.py <标签>        # 标签用于生成唯一服务名/文件名
输出：
  HOST_SHA1=<..>  GUEST_SHA1=<..>  MATCH=<yes/no>  LOAD=<RUNNING|FAIL:<code>>
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, r'C:\Users\Administrator\.agents\skills\kd-dual-debug\scripts')
import kd as K  # noqa: E402

ROOT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter'
SIGN = os.path.join(ROOT, 'build', 'sign')
BUILT = os.path.join(ROOT, 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
SIGNED = os.path.join(SIGN, 'XPCHunterDrv_signed.sys')


def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, shell=False)
    so = p.stdout.decode('gbk', 'replace') if p.stdout else ''
    se = p.stderr.decode('gbk', 'replace') if p.stderr else ''
    return p.returncode, so + se


def sha1(path):
    import hashlib
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(65536), b''):
            h.update(b)
    return h.hexdigest().upper()


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else 'p'
    svc = 'Probe_' + tag
    gf = 'probe_%s.sys' % tag
    env, _ = K.load_env()

    def guest(bat, log='probe_%s.log' % tag, timeout=180):
        return K._guest_exec_impl(env, bat, log, timeout)

    # 清理旧服务（忽略错误；sc 报错会让 vmrun 返回非零，故必须 try 包住）
    try:
        guest('sc stop %s >nul 2>&1\r\nsc delete %s >nul 2>&1\r\nexit /b 0\r\n' % (svc, svc),
              'probe_%s_clean.log' % tag, 60)
    except SystemExit:
        print('(cleanup: 服务不存在，忽略)')

    rc, out = run(['cmd', '/c', 'build.bat'], cwd=os.path.join(ROOT, 'build'))
    if 'Build complete' not in out:
        print('BUILD_FAIL'); print(out[-1500:]); return 2
    host_built = sha1(BUILT)

    rc, out = run(['cmd', '/c', 'host_sign.bat'], cwd=SIGN)
    if 'SIGN_EXIT=0' not in out:
        print('SIGN_FAIL'); print(out[-800:]); return 3
    host_signed = sha1(SIGNED)

    # 推入 Guest（唯一文件名，避免锁）
    K.vmrun(env, '-gu', env['guest']['user'], '-gp', env['guest']['password'],
            'copyFileFromHostToGuest', env['vm']['vmx'], SIGNED,
            r'C:\kd_tmp\%s' % gf)

    # Guest 侧哈希
    log = guest('powershell -c "(Get-FileHash C:\\kd_tmp\\%s -Algorithm SHA1).Hash"\r\n'
                % gf, 'probe_%s_hash.log' % tag, 90)
    m = re.search(r'([0-9A-F]{40})', log or '')
    guest_sha = m.group(1) if m else '<none>'

    print('HOST_SHA1=%s' % host_signed)
    print('GUEST_SHA1=%s' % guest_sha)
    print('MATCH=%s' % ('yes' if guest_sha == host_signed else 'NO'))

    # 创建并加载
    guest('sc create %s type= kernel start= demand binPath= \\??\\C:\\kd_tmp\\%s\r\n'
          'timeout /t 2 >nul\r\nsc start %s\r\n'
          'timeout /t 2 >nul\r\nsc query %s\r\n' % (svc, gf, svc, svc),
          'probe_%s_load.log' % tag, 150)

    st = guest('sc query %s | findstr /i "STATE WIN32_EXIT"\r\n' % svc,
               'probe_%s_st.log' % tag, 90)
    state = re.search(r'STATE\s*:\s*\d+\s+(\S+)', st or '')
    code = re.search(r'WIN32_EXIT_CODE\s*:\s*(\d+)', st or '')
    print('LOAD=%s%s' % (state.group(1) if state else '?',
                         ('' if (code and code.group(1) == '0')
                          else ':' + (code.group(1) if code else '?'))))
    if (state and state.group(1) == 'RUNNING'):
        guest('sc stop %s\r\ntimeout /t 2 >nul\r\nsc delete %s\r\n' % (svc, svc),
              'probe_%s_stop.log' % tag, 90)
    return 0


if __name__ == '__main__':
    sys.exit(main())