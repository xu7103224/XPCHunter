#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在真实 buf（ntoskrnl **镜像布局**）上，对比原始与我方 FindKernelPESectionByType 的返回值。

关键修正：驱动 GT[0x20] 指向的缓冲是**镜像布局**（活体已核对：live[0x1B9600] == image[0x1B9600]），
不是磁盘文件布局。旧 oracle 映射磁盘文件 → 读到错位字节 → 假象 stride=41。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim  # noqa: E402
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from pe_image_layout import image_layout  # noqa: E402

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

# 原始 / 我方 的 FindKernelPESectionByType 地址（我方按镜像基址 0x140000000）
ORIG_FKPSBT = 0x14007A6B8
MINE_FKPSBT = 0x1400773B0

GT20, GT21 = 0x20, 0x21
GT41D1, GT41D4 = 0x41D1, 0x41D4


def run(drv_path, fnaddr, label, bufbase, bufsize):
    sim = KernelSim(drv_path)
    sim.skip_stack_cookie_check()
    sim.enable_gt_trace()
    sim.set_gt(GT20, bufbase)
    sim.set_gt(GT21, bufsize)
    sim.set_gt(GT41D1, 0x1B9600)
    sim.set_gt(GT41D4, 0x1B90E0)
    sim.set_gt(0x914, 19045)
    out = {}
    for gt, tag in ((GT41D1, '0x41D1'), (GT41D4, '0x41D4')):
        kind, r = sim.call(fnaddr, (gt,), count=5000000)
        out[tag] = (kind, r)
        print('%s FindKernelPESectionByType(%s) -> %s %s' % (
            label, tag, kind, hex(r) if kind == 'OK' else r))
    if out[GT41D1][0] == 'OK' and out[GT41D4][0] == 'OK':
        st1, st2 = out['0x41D1'][1], out['0x41D4'][1]
        print('  ST1=0x%X ST2=0x%X  stride(ST2-ST1)=%d (need 472)' % (
            st1, st2, (st2 - st1) & 0xFFFFFFFF))
    if sim.notes:
        print('  notes:', sim.notes[:2])
    return out


def main():
    img, sizeimg, _ = image_layout(NT)
    print('image-layout buf size = 0x%X' % len(img))
    # 映射到两个 sim 各自的 SCRATCH（scratch 分配地址不同，故分别映射）
    for drv, fn, label in ((ORIG, ORIG_FKPSBT, 'ORIG'), (MINE, MINE_FKPSBT, 'MINE')):
        sim = KernelSim(drv)
        sim.skip_stack_cookie_check()
        base = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
        sim.uc.mem_write(base, img)
        # 复用同一 sim 跑（避免重复映射）
        sim.set_gt(GT20, base)
        sim.set_gt(GT21, len(img))
        sim.set_gt(GT41D1, 0x1B9600)
        sim.set_gt(GT41D4, 0x1B90E0)
        sim.set_gt(0x914, 19045)
        res = {}
        for gt, tag in ((GT41D1, '0x41D1'), (GT41D4, '0x41D4')):
            kind, r = sim.call(fn, (gt,), count=5000000)
            res[tag] = (kind, r)
        st1 = res['0x41D1'][1] if res['0x41D1'][0] == 'OK' else None
        st2 = res['0x41D4'][1] if res['0x41D4'][0] == 'OK' else None
        print('%s: ST1=%s ST2=%s' % (
            label,
            ('0x%X' % st1) if isinstance(st1, int) else st1,
            ('0x%X' % st2) if isinstance(st2, int) else st2))
        if isinstance(st1, int) and isinstance(st2, int):
            print('   stride = %d' % ((st2 - st1) & 0xFFFFFFFF))
        print('   raw:', res['0x41D1'], res['0x41D4'])
        if sim.notes:
            print('   notes:', sim.notes[:2])


if __name__ == '__main__':
    main()