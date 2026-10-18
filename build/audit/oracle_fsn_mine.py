#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在真实镜像布局缓冲上，把我方驱动的 GT 值写进**它的真实 g_GlobalTable**，
然后跑我方 FindSyscallNumbers，看是否命中原函数同样的扫描。

我方 g_GlobalTable 地址 = 0x1400a1060（来自 map）。
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

ORIG_FSN = 0x140052FDC
MINE_FSN = 0x14002EEB0
ORIG_GT = 0x1400A84F0
MINE_GT = 0x1400A1060


def run(drv, fn, gtbase, label, img, bufbase):
    sim = KernelSim(drv)
    sim.skip_stack_cookie_check()
    # 写进真实 g_GlobalTable
    vals = {0x20: bufbase, 0x21: len(img), 0x42: 0x1D0,
            0x41D1: 0x1B9600, 0x41D4: 0x1B90E0, 0x914: 19045, 0x62: 0}
    for idx, v in vals.items():
        sim.uc.mem_write(gtbase + idx * 8, struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF))
    kind, r = sim.call(fn, (), count=20000000)
    out = bytes(sim.uc.mem_read(gtbase + 0x62 * 8, 8))
    gt62 = struct.unpack('<Q', out)[0]
    # 读回几个关键槽
    dump = {}
    for idx in (0x4700, 0x4701, 0x4702, 0x4703, 0x4704, 0x4705, 0x4706,
                0x470A, 0x470B, 0x470C, 0x470D, 0x470E):
        dump[idx] = struct.unpack('<Q', bytes(sim.uc.mem_read(gtbase + idx * 8, 8)))[0]
    print('%s FindSyscallNumbers() -> %s %s' % (label, kind, hex(r) if isinstance(r, int) else r))
    print('   GT[0x62] = 0x%X (%s)' % (gt62, 'WROTE' if gt62 else 'zero'))
    if label == 'MINE':
        for k in sorted(dump):
            print('   DIAG[0x%04X] = 0x%X' % (k, dump[k]))
    if sim.notes:
        print('   notes:', sim.notes[:3])


def main():
    img, sz, _ = image_layout(NT)
    print('buf size 0x%X' % len(img))
    # 两个 sim 各自分配 scratch，分别映射
    s1 = KernelSim(ORIG)
    b1 = s1.scratch((len(img) + 0xFFF) & ~0xFFF)
    s1.uc.mem_write(b1, img)
    del s1
    s2 = KernelSim(MINE)
    b2 = s2.scratch((len(img) + 0xFFF) & ~0xFFF)
    s2.uc.mem_write(b2, img)
    del s2
    run(ORIG, ORIG_FSN, ORIG_GT, 'ORIG', img, b1)
    run(MINE, MINE_FSN, MINE_GT, 'MINE', img, b2)


if __name__ == '__main__':
    main()