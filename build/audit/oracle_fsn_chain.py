#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全链验证：在真实镜像缓冲上跑 FindSyscallNumbers，看是否命中扫描并写 GT[0x62]。

对两个驱动各自设 GT 读写桩（地址随编译不同）。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim, MASK64  # noqa: E402
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from pe_image_layout import image_layout  # noqa: E402

from unicorn.x86_const import (UC_X86_REG_RCX, UC_X86_REG_RDX,  # noqa: E402
                               UC_X86_REG_RAX, UC_X86_REG_RSP)

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

CFG = {
    'ORIG': dict(drv=ORIG, fsn=0x140052FDC, gtread=0x140029EFC, gtwrite=0x140029FF4,
                 exalloc=0x140077A00),
    'MINE': dict(drv=MINE, fsn=0x14002EA30, gtread=0x14001EDC0, gtwrite=0x14001EDD0,
                 exalloc=0x14002D9F0),
}


def run(cfg, label, img):
    sim = KernelSim(cfg['drv'])
    sim.skip_stack_cookie_check()
    log = []

    def gt_read(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(idx, 0) & MASK64)
        s._do_ret(uc)

    def gt_write(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        val = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s._gt_values[idx] = val
        log.append('GtWrite(0x%X)=0x%X' % (idx, val))
        uc.reg_write(UC_X86_REG_RAX, val & MASK64)
        s._do_ret(uc)

    def exalloc(uc, s):
        # 返回可写内存，让调用方继续
        log.append('ExAlloc(size=0x%X)' % uc.reg_read(UC_X86_REG_RDX))
        uc.reg_write(UC_X86_REG_RAX, s._scratch_alloc)
        s._do_ret(uc)

    sim.intercept(cfg['gtread'], gt_read)
    sim.intercept(cfg['gtwrite'], gt_write)
    sim.intercept(cfg['exalloc'], exalloc)

    base = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(base, img)
    sim._scratch_alloc = sim.scratch(0x80000)
    for gt, v in ((0x20, base), (0x21, len(img)), (0x42, 0x1D0),
                  (0x41D1, 0x1B9600), (0x41D4, 0x1B90E0), (0x914, 19045)):
        sim.set_gt(gt, v)

    kind, r = sim.call(cfg['fsn'], (), count=30000000)
    gt62 = sim._gt_values.get(0x62, 0)
    print('%s FindSyscallNumbers() -> %s  GT[0x62]=0x%X (%s)'
          % (label, kind, gt62, 'WROTE' if gt62 else 'zero'))
    print('   log:', log[:10])
    if sim.notes:
        print('   notes:', sim.notes[:3])


def main():
    img, sz, _ = image_layout(NT)
    print('buf size 0x%X' % len(img))
    for label in ('ORIG', 'MINE'):
        run(CFG[label], label, img)


if __name__ == '__main__':
    main()