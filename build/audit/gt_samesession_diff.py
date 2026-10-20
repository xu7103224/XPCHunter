#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GT 同会话严格对比：两份 dump 必须在同一次 guest 启动内采集，
因此 GT[3]（ntoskrnl 基址）必须相同。分类输出：
  相同 / MISSING / EXTRA / 自映像指针 / 池指针 / 其他指针 / 小整数差异

用法:
  python gt_samesession_diff.py gt_orig_samesession.bin gt_mine_samesession.bin \
         <orig_drv_base> <orig_drv_end> <mine_drv_base> <mine_drv_end>
"""
import struct, sys

def load(p):
    d = open(p, 'rb').read()
    return [struct.unpack_from('<Q', d, i * 8)[0] for i in range(len(d) // 8)]

o = load(sys.argv[1]); m = load(sys.argv[2])
args = [int(x, 16) for x in sys.argv[3:7]]
if len(args) == 4:
    ODB, OEND, MDB, MEND = args
else:
    ODB = OEND = MDB = MEND = 0

print('orig GT[3] = %016X' % o[3])
print('mine GT[3] = %016X' % m[3])
print('同会话? %s' % ('是' if o[3] == m[3] else '否 —— 两份 dump 跨了启动，结论不可靠'))

n = min(len(o), len(m))
miss = []; extra = []; same = 0
selfptr = []; pool = []; small = []; other = []
for i in range(n):
    ov, mv = o[i], m[i]
    if ov == 0 and mv == 0:
        same += 1; continue
    if ov != 0 and mv == 0:
        miss.append(i); continue
    if ov == 0 and mv != 0:
        extra.append(i); continue
    if ov == mv:
        same += 1; continue
    if ov < 0x100000000 and mv < 0x100000000:
        small.append((i, ov, mv)); continue
    if OEND and ODB <= ov < OEND and MDB <= mv < MEND:
        selfptr.append((i, ov - ODB, mv - MDB)); continue
    if (ov >> 48) == 0xFFFF and (mv >> 48) == 0xFFFF:
        pool.append((i, ov, mv)); continue
    other.append((i, ov, mv))

print()
print('槽总数        : %d' % n)
print('逐字节相同    : %d  (%.2f%%)' % (same, 100.0 * same / n))
print('MISSING       : %d  %s' % (len(miss), [hex(x) for x in miss[:20]]))
print('EXTRA         : %d  %s' % (len(extra), [hex(x) for x in extra[:20]]))
print('自映像指针    : %d  (槽 0x%X..0x%X)' % (
    len(selfptr), min([x[0] for x in selfptr], default=0), max([x[0] for x in selfptr], default=0)))
print('池/其他指针   : %d' % len(pool))
print('小整数差异    : %d' % len(small))
print('未分类        : %d' % len(other))
print()
if small:
    print('--- 小整数差异（这些才是真正需要看的语义槽）---')
    for i, a, b in small:
        print('   0x%04X orig=%X mine=%X' % (i, a, b))
if other:
    print('--- 未分类 ---')
    for i, a, b in other[:40]:
        print('   0x%04X orig=%016X mine=%016X' % (i, a, b))
if pool:
    print('--- 池指针（每次分配天然不同）前 20 ---')
    for i, a, b in pool[:20]:
        print('   0x%04X orig=%016X mine=%016X delta=%X'
              % (i, a, b, (b - a) & 0xFFFFFFFFFFFFFFFF))
if selfptr:
    print('--- 自映像指针（LTCG 重排导致 RVA 不同）前 12 ---')
    for i, a, b in selfptr[:12]:
        print('   0x%04X orig=+0x%X mine=+0x%X' % (i, a, b))