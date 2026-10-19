#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 map 文件读出我方函数地址，自动同步到各 oracle 脚本的配置。

每次编译后地址都会移动，手工改配置易错；本脚本统一处理。
用法: python build/audit/sync_addrs.py
"""
import glob
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
MAP = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')

WANT = {
    'fsn':      'FindSyscallNumbers',
    'gtread':   'GtRead',
    'gtwrite':  'GtWrite',
    'exalloc':  'ExAlloc',
    'readpese': 'ReadPESectionEntry',
    'fkpsbt':   'FindKernelPESectionByType',
}


def read_map():
    got = {}
    for ln in open(MAP, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s+0001:[0-9a-f]{8}\s+(\w+)\s+([0-9a-f]{16})\s+f', ln)
        if m and m.group(1) in WANT.values():
            for k, v in WANT.items():
                if v == m.group(1):
                    got[k] = int(m.group(2), 16)
    return got


def main():
    got = read_map()
    print('map 中的我方地址:', {k: hex(v) for k, v in got.items()})
    n = 0
    for fp in glob.glob(os.path.join(HERE, 'oracle_*.py')):
        s = open(fp, encoding='utf-8').read()
        # 只改 'MINE': dict(...) 那一行 —— 原始驱动地址是固定常量，不可覆盖
        lines = s.splitlines(keepends=True)
        changed = False
        for i, ln in enumerate(lines):
            if "'MINE'" in ln and 'dict(' in ln:
                # MINE 配置可能跨多行，收集到右括号
                j, buf = i, ''
                depth = 0
                while j < len(lines):
                    buf += lines[j]
                    depth += lines[j].count('(') - lines[j].count(')')
                    lines[j] = ''
                    if depth <= 0:
                        break
                    j += 1
                for k, v in got.items():
                    buf = re.sub(r'\b' + k + r'=0x[0-9a-fA-F]+', '%s=0x%X' % (k, v), buf)
                lines[i] = buf
                changed = True
        if changed:
            open(fp, 'w', encoding='utf-8').write(''.join(lines))
            n += 1
            print('  已同步（仅 MINE 项）', os.path.basename(fp))
    print('共更新 %d 个脚本' % n)


if __name__ == '__main__':
    main()