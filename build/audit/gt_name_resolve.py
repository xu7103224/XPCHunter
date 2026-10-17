#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从活体 GT 表 + kd `lm` 模块列表，反查「GT 槽 -> 真实模块名」。

用法:
  python gt_name_resolve.py <lm_output.txt> <gt_bin> <idx> [idx...]

`lm_output.txt` 为 kd 里 `lm` 的原文（含 "start end module" 行）。
输出每个槽的原始值、对应模块名与大小。
"""
import re
import struct
import sys


def parse_lm(path):
    mods = {}
    for line in open(path, encoding='utf-8', errors='ignore'):
        m = re.match(r'^\s*([0-9a-f`]+)\s+([0-9a-f`]+)\s+(\S+)', line)
        if not m:
            continue
        start = int(m.group(1).replace('`', ''), 16)
        end = int(m.group(2).replace('`', ''), 16)
        name = m.group(3)
        if re.fullmatch(r'[0-9a-f`]+', name):
            continue
        mods[start] = (name, end - start)
    return mods


def main():
    lm, gt = sys.argv[1], sys.argv[2]
    idxs = [int(x, 16) for x in sys.argv[3:]]
    mods = parse_lm(lm)
    d = open(gt, 'rb').read()

    def g(i):
        return struct.unpack_from('<Q', d, i * 8)[0]

    print('%-8s %-18s %-16s %s' % ('槽', '值', '模块', '大小'))
    for i in idxs:
        v = g(i)
        name = mods.get(v, ('', 0))[0]
        if not name:
            for s, (n, sz) in mods.items():
                if s <= v < s + sz:
                    name = n
                    break
        # 大小槽通常是 idx+1
        sz = mods.get(v, ('', 0))[1]
        print('0x%-6X 0x%-16X %-16s %s' % (
            i, v, name or ('(0)' if v == 0 else '?'), hex(sz) if sz else ''))


if __name__ == '__main__':
    main()