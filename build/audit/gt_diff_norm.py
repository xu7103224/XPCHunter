#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对比两份 GT 全表 dump（原始驱动 vs 我方），按槽分类：
  - MISSING : 原始非0 我方为0
  - EXTRA   : 原始0 我方非0
  - SELFPTR : 双方都是"内核映像内代码指针"（自映像），按 (value - kbase) 归一后比较
  - DIFF    : 归一后仍不同
kbase 由 GT[0x41D2]-GT[0x41D1] 推得（RVA/VA 对）。
用法: python gt_diff_norm.py <orig.bin> <mine.bin>
"""
import struct
import sys


def load(p):
    d = open(p, 'rb').read()
    n = len(d) // 8
    return [struct.unpack_from('<Q', d, i * 8)[0] for i in range(n)]


def kbase(v):
    # GT[0x41D2] - GT[0x41D1]
    va, rva = v[0x41D2], v[0x41D1]
    if va and rva and va > rva:
        return va - rva
    return 0


def is_img_ptr(v, base):
    # 内核映像内的代码/数据指针：落在 base .. base+0xC00000
    return base and base <= v < base + 0xC00000


def main():
    o = load(sys.argv[1])
    m = load(sys.argv[2])
    ob, mb = kbase(o), kbase(m)
    print('orig kbase = 0x%016X' % ob)
    print('mine kbase = 0x%016X' % mb)
    n = min(len(o), len(m))
    stats = dict(missing=0, extra=0, selfptr=0, diff=0, same=0)
    missing, extra, diff = [], [], []
    for i in range(n):
        a, b = o[i], m[i]
        if a == b:
            stats['same'] += 1
            continue
        if a and not b:
            stats['missing'] += 1
            missing.append(i)
            continue
        if b and not a:
            stats['extra'] += 1
            extra.append(i)
            continue
        # both nonzero, differ
        if is_img_ptr(a, ob) and is_img_ptr(b, mb) and (a - ob) == (b - mb):
            stats['selfptr'] += 1
            continue
        stats['diff'] += 1
        diff.append(i)
    print('slots compared:', n)
    print('same      :', stats['same'])
    print('selfptr   :', stats['selfptr'], '(归一后相同，属两编译正常差异)')
    print('missing   :', stats['missing'])
    print('extra     :', stats['extra'])
    print('diff      :', stats['diff'])
    print()
    print('--- MISSING (orig!=0, mine==0) 前60 ---')
    for i in missing[:60]:
        print('  0x%04X orig=0x%016X' % (i, o[i]))
    print('--- EXTRA (orig==0, mine!=0) 前40 ---')
    for i in extra[:40]:
        print('  0x%04X mine=0x%016X' % (i, m[i]))
    print('--- DIFF (归一后仍不同) 前60 ---')
    for i in diff[:60]:
        print('  0x%04X orig=0x%016X mine=0x%016X' % (i, o[i], m[i]))
    # 落盘
    import json
    json.dump({'missing': missing, 'extra': extra, 'diff': diff},
              open('gt_diff_norm.json', 'w'), indent=0)
    print('\nwrote gt_diff_norm.json')


if __name__ == '__main__':
    main()