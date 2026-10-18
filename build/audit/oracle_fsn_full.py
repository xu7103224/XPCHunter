#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在真实镜像布局缓冲上跑 ORIGINAL 的 FindSyscallNumbers，看它是否写 GT[0x62]。
若成功 → 离线模型完备，可与我方逐值对比；
若失败 → 离线缺环境要素，必须走活体断点。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim  # noqa: E402
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from pe_image_layout import image_layout  # noqa: E402

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

ORIG_FSN = 0x140052FDC
MINE_FSN = 0x14002EEB0

# 活体值（来自 kd 直读我方驱动）
LIVE = {0x20: None, 0x21: 0xAB2000, 0x42: 0x1D0, 0x41D1: 0x1B9600, 0x41D4: 0x1B90E0}


def run(drv, fn, label, img):
    sim = KernelSim(drv)
    sim.skip_stack_cookie_check()
    sim.enable_gt_trace()
    base = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(base, img)
    sim.set_gt(0x20, base)
    sim.set_gt(0x21, len(img))
    sim.set_gt(0x42, 0x1D0)
    sim.set_gt(0x41D1, 0x1B9600)
    sim.set_gt(0x41D4, 0x1B90E0)
    sim.set_gt(0x914, 19045)
    sim.set_gt(0x62, 0)

    # ExAlloc 桩：返回一块可写内存，好让 GtWrite(0x62) 有值
    alloc_base = sim.scratch(0x10000)
    if 'ExAlloc' in sim.img.stubs:
        sim.api_returns['ExAlloc'] = alloc_base

    kind, r = sim.call(fn, (), count=20000000)
    print('%s FindSyscallNumbers() -> %s %s' % (label, kind, r if not isinstance(r, int) else hex(r)))
    gt62 = sim._gt_values.get(0x62, 0)
    print('   GT[0x62] = 0x%X   (%s)' % (gt62, 'WROTE' if gt62 else 'still zero'))
    print('   gt_writes:', [(hex(i), hex(v)) for i, v in sim.gt_writes][:12])
    print('   gt_reads :', [(hex(i), hex(v)) for i, v in sim.gt_reads][:12])
    if sim.notes:
        print('   notes:', sim.notes[:3])


def main():
    img, sz, _ = image_layout(NT)
    print('buf size 0x%X' % len(img))
    run(ORIG, ORIG_FSN, 'ORIG', img)
    run(MINE, MINE_FSN, 'MINE', img)


if __name__ == '__main__':
    main()