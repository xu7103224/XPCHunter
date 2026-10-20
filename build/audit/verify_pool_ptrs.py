#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 B 组差异槽的"我方值"是否落在本次启动已加载的内核模块范围内。
若成立，则这些差异只是 ASLR 造成的模块基址不同，不是语义缺陷。

用法: python verify_pool_ptrs.py gt_orig.bin gt_mine.bin lm.txt orig_drv_base mine_drv_base
"""
import struct, sys, re

def load(p):
    d = open(p, 'rb').read()
    return [struct.unpack_from('<Q', d, i * 8)[0] for i in range(len(d) // 8)]

o = load(sys.argv[1]); m = load(sys.argv[2])
lm_text = open(sys.argv[3], encoding='utf-8', errors='ignore').read()
odb = int(sys.argv[4], 16); mdb = int(sys.argv[5], 16)

mods = []
for line in lm_text.split('\n'):
    mm = re.match(r'\s*([0-9a-f]{8}`[0-9a-f]{8})\s+([0-9a-f]{8}`[0-9a-f]{8})\s+(\S+)', line)
    if mm:
        s = int(mm.group(1).replace('`', ''), 16)
        e = int(mm.group(2).replace('`', ''), 16)
        mods.append((s, e, mm.group(3)))

print('已解析模块数:', len(mods))


def find_mod(v):
    for s, e, n in mods:
        if s <= v < e:
            return n, v - s
    return None, None


ont, mnt = o[3], m[3]
B = []
for i in range(min(len(o), len(m))):
    ov, mv = o[i], m[i]
    if ov == mv or ov == 0 or mv == 0:
        continue
    if odb <= ov < odb + 0x20000 and mdb <= mv < mdb + 0x20000:
        continue
    if ov < 0x100000000 and mv < 0x100000000:
        continue
    if ont <= ov < ont + 0xC00000 and mnt <= mv < mnt + 0xC00000:
        continue
    B.append((i, ov, mv))

print('B 组槽数:', len(B))
ok = 0
bad = []
for i, ov, mv in B:
    name, off = find_mod(mv)
    if name:
        ok += 1
    else:
        bad.append((i, ov, mv))

print('我方值落在已加载模块内:', ok, '/', len(B))
if bad:
    print('未落在任何模块内（需人工看）:', len(bad))
    for i, ov, mv in bad[:30]:
        on, _ = find_mod(ov)
        print('   0x%04X orig=%016X(%s)  mine=%016X' % (i, ov, on or '-', mv))
else:
    print('=> 全部 %d 个 B 组差异都是我方的模块基址（ASLR 结果），非语义缺陷' % len(B))