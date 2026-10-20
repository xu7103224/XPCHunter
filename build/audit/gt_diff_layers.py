#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GT 分层甄别：把 DIFF 分成
  A) 自映像指针（落在驱动自身模块范围内）→ 用各自驱动模块基址归一
  B) ntoskrnl 映像/池缓冲指针（GT[0x20] 一族、池地址）→ 每次启动必然不同
  C) 小整数（< 2^32）→ 可逐值核对
  D) 其他内核指针 → 按 ntoskrnl 基址归一
用法: python gt_diff_layers.py <orig.bin> <mine.bin> <orig_drv_base> <mine_drv_base>
"""
import struct, sys

def load(p):
    d = open(p, 'rb').read()
    return [struct.unpack_from('<Q', d, i * 8)[0] for i in range(len(d) // 8)]

def in_range(v, base, size):
    return base <= v < base + size

o = load(sys.argv[1]); m = load(sys.argv[2])
odb = int(sys.argv[3], 16); mdb = int(sys.argv[4], 16)
DRV_SIZE = 0x20000
ont = o[3]; mnt = m[3]
NT_SIZE = 0xC00000

A = []; B = []; C = []; D = []
for i in range(min(len(o), len(m))):
    ov, mv = o[i], m[i]
    if ov == mv:
        continue
    if ov == 0 or mv == 0:
        C.append((i, ov, mv, 'zero-mismatch'))
        continue
    # A: 驱动自映像
    if in_range(ov, odb, DRV_SIZE) and in_range(mv, mdb, DRV_SIZE):
        if ov - odb != mv - mdb:
            A.append((i, ov, mv))
        continue
    # B: ntoskrnl 池缓冲（GT[0x20] 家族、0x2x/0x4x/0x5x 区间指向池）
    if ov < 0x100000000 and mv < 0x100000000:
        C.append((i, ov, mv))
        continue
    # D: 按 nt 基址归一
    if in_range(ov, ont, NT_SIZE) and in_range(mv, mnt, NT_SIZE):
        if ov - ont != mv - mnt:
            D.append((i, ov, mv))
        continue
    B.append((i, ov, mv))

print('槽总数', len(o))
print('A 自映像指针但 RVA 不同:', len(A))
for i, ov, mv in A[:30]:
    print('   0x%04X orig=+0x%X mine=+0x%X' % (i, ov - odb, mv - mdb))
print('B 池/其他指针（每次启动不同，不可直接比）:', len(B))
for i, ov, mv in B[:30]:
    print('   0x%04X orig=%016X mine=%016X' % (i, ov, mv))
print('C 小整数/零不匹配（可核对）:', len(C))
for i, ov, mv in C[:60]:
    print('   0x%04X orig=%X mine=%X' % (i, ov, mv))
print('D nt 内指针但 RVA 不同:', len(D))
for i, ov, mv in D[:30]:
    print('   0x%04X orig=nt+0x%X mine=nt+0x%X' % (i, ov - ont, mv - mnt))