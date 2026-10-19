#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对当前源码做一次**准确**的函数覆盖率统计。

方法：原始 1516 个函数的地址列表在 _orig_funcs_ida.json；
我方源码里每个函数都有 `// 对应原始驱动 ... 0x14XXXXXXXX` 形式的注释
（这是本项目 CLAUDE.md 强制的可追溯规则）。故用**地址**而非名字匹配，
避免同名/改名造成的假阳性。

输出：
  · 有原始地址注释的原始函数数（= 已落地复刻）
  · 缺失清单（可按 size 排序，定位高价值目标）
"""
import json
import os
import re
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..', '..')


def main():
    orig = json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))
    # 归一成 {addr:int -> name}
    if isinstance(orig, dict):
        pairs = []
        for k, v in orig.items():
            if isinstance(v, dict):
                a = v.get('start') or v.get('addr') or k
                pairs.append((int(a, 0) if isinstance(a, str) else int(a), v.get('name', str(k))))
            else:
                pairs.append((int(k, 0) if isinstance(k, str) else int(k), str(v)))
    else:
        pairs = [(int(x['start']), x['name']) for x in orig]
    oaddr = dict(pairs)
    print('原始函数总数: %d' % len(oaddr))

    # 我方源码中出现的原始地址（8/9/16 进制写法统一）
    src = ''
    for f in glob.glob(os.path.join(ROOT, 'XPCHunterDrv', 'src', '**', '*.c'), recursive=True):
        src += open(f, encoding='utf-8', errors='ignore').read()
    cited = set()
    # 本项目惯例：注释里写 `对应原始驱动 sub_140001580` 或 `0x140001580`
    for m in re.finditer(r'sub_(1400[0-9a-fA-F]{5})', src):
        cited.add(int(m.group(1), 16))
    for m in re.finditer(r'0x(1400[0-9a-fA-F]{5})', src):
        cited.add(int(m.group(1), 16))
    for m in re.finditer(r'\b(1400[0-9a-fA-F]{5})\b', src):
        cited.add(int(m.group(1), 16))

    have = [a for a in oaddr if a in cited]
    miss = sorted([a for a in oaddr if a not in cited])
    print('已落地（源码有原始地址注释）: %d' % len(have))
    print('未落地: %d' % len(miss))
    print()
    print('--- 未落地前 40（按地址）---')
    for a in miss[:40]:
        print('  0x%X  %s' % (a, oaddr[a]))
    json.dump([{'addr': hex(a), 'name': oaddr[a]} for a in miss],
              open(os.path.join(HERE, '_missing_accurate.json'), 'w'), indent=0)
    print('\nwrote _missing_accurate.json')


if __name__ == '__main__':
    main()