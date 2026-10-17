#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线完整复现 FindNtOpenThreadTargetWin8 的两段扫描，原始 vs 我方，比对返回值。

第一段：从 Src+0x66EDC0 起最多 0x46 条，找 type==0x558 且 Entry[0x50]&0x4000000
        且 Entry[0x38]!=0 → TargetOffset = Entry[0x38] - ImageBase + (ReadPtr+f0)
第二段：从 ImageBase+TargetOffset 起最多 0x46 条，找 type==0x510 且 Entry[0x88]&0x40000
        → Target2 = Entry[0x78] - ImageBase + (ReadPtr+f0)
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim  # noqa: E402

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = open(os.path.join(HERE, 'nt4k.bin'), 'rb').read()

PROF = {
    'ORIG': dict(path=ORIG, read_entry=0x14008A54C, init_ctx=0x14008A7E4),
    'MINE': dict(path=MINE, read_entry=0x1400541E0, init_ctx=0x140054180),
}

IMAGE_BASE = 0x140000000  # 用模拟基址充当 ImageBase（Src 也放同区，便于算偏移）
SRC_OFFSET = 0x66EDC0


def scan(sim, p, start, size, max_entries, limit=0x46):
    """返回 [(off, f0, type, f50, f38, f88, f78)]"""
    uc = sim.uc
    ctx = sim.scratch(0x200)
    ent = sim.scratch(0x200)
    sim.call(p['init_ctx'], (start, size, 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx))
    out = []
    for i in range(limit):
        kind, res = sim.call(p['read_entry'], (ctx, ent), count=800000)
        if kind != 'OK' or res != 0:
            out.append(('STOP', res))
            break
        b = sim.read(ent, 0x120)
        rp = struct.unpack_from('<Q', sim.read(ctx, 0x48), 8)[0]
        f0 = struct.unpack_from('<I', b, 0xF0)[0]
        t118 = struct.unpack_from('<Q', b, 0x118)[0]
        ty = struct.unpack_from('<H', sim.read(t118, 8), 6)[0] if t118 else 0
        rec = dict(off=rp - start, f0=f0, ty=ty,
                   f50=struct.unpack_from('<Q', b, 0x50)[0],
                   f38=struct.unpack_from('<I', b, 0x38)[0],
                   f88=struct.unpack_from('<Q', b, 0x88)[0],
                   f78=struct.unpack_from('<I', b, 0x78)[0],
                   rp=rp)
        out.append(rec)
        uc.mem_write(ctx + 8, struct.pack('<Q', (rp + f0) & 0xFFFFFFFFFFFFFFFF))
        if len(out) >= max_entries:
            break
    return out


def two_pass(label, p):
    sim = KernelSim(p['path'])
    sim.skip_stack_cookie_check()
    sva = sim.scratch(0x4000, STREAM)
    # 用模拟基址做 ImageBase，Src 起点 = sva
    # 把 ImageBase 概念映射为 sva-0x66EDC0，使 (addr - ImageBase) 与真实一致
    pseudo_image_base = sva - SRC_OFFSET

    print(f'=== {label} ===')
    first = scan(sim, p, sva, len(STREAM), 0x46)
    for r in first:
        if isinstance(r, tuple):
            print('   first STOP', r); return
        hit = (r['ty'] == 0x558 and (r['f50'] & 0x4000000) and r['f38'])
        if hit:
            tgt_off = (r['f38'] - pseudo_image_base + r['rp'] + r['f0']) & 0xFFFFFFFF
            print(f"   FIRST HIT at off=0x{r['off']:x} type=0x{r['ty']:x} "
                  f"f50=0x{r['f50']:x} f38={r['f38']} -> TargetOffset=0x{tgt_off:x}")
            tgt_va = pseudo_image_base + tgt_off
            # 缓冲覆盖的 RVA 区间 = [SRC_OFFSET, SRC_OFFSET+len)
            if tgt_off == 0 or tgt_off >= SRC_OFFSET + len(STREAM):
                print(f'   TargetOffset 0x{tgt_off:x} 超出本缓冲覆盖范围 '
                      f'(0x{SRC_OFFSET:x}..0x{SRC_OFFSET+len(STREAM):x})，返回 0'); return
            avail = SRC_OFFSET + len(STREAM) - tgt_off
            print(f'   -> 第二段扫描起点 RVA 0x{tgt_off:x}，可用 0x{avail:x} 字节')
            second = scan(sim, p, tgt_va, avail, 0x46)
            for s in second:
                if isinstance(s, tuple):
                    print('   second STOP', s); return
                h2 = (s['ty'] == 0x510 and (s['f88'] & 0x40000))
                if h2:
                    t2 = (s['f78'] - pseudo_image_base + s['rp'] + s['f0']) & 0xFFFFFFFF
                    print(f"   SECOND HIT at off=0x{s['off']:x} type=0x{s['ty']:x} "
                          f"f88=0x{s['f88']:x} f78={s['f78']} -> Target2=0x{t2:x}")
                    return
            print('   second 无命中 -> 返回 0')
            return
    print('   first 无命中 -> 返回 0')


if __name__ == '__main__':
    two_pass('ORIG', PROF['ORIG'])
    two_pass('MINE', PROF['MINE'])