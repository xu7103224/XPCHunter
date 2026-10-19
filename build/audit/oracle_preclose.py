#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MiniFilterPreClose 离线差分：原始 (0x1400152D4) vs 我方，比较 GT 写入。

输入 GT 取自原始活体 dump；GT[0x20] 换成模拟器映射的镜像布局缓冲。
调用约定：无参数（纯 GT 驱动）。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64  # noqa: E402
from pe_image_layout import image_layout  # noqa: E402
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX  # noqa

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

ORIG_FN = 0x1400152D4
GT = {
    'ORIG': dict(read=0x140029EFC, write=0x140029FF4),
    'MINE': dict(read=0x14001ED40, write=0x14001ED50),
}


def run(which, fn, bufbase, bufsize):
    drv = ORIG if which == 'ORIG' else MINE
    cfg = GT[which]
    sim = KernelSim(drv)
    sim.skip_stack_cookie_check()
    log = []

    def gr(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(i, 0) & MASK64)
        s._do_ret(uc)

    def gw(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        v = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s._gt_values[i] = v
        log.append((i, v))
        uc.reg_write(UC_X86_REG_RAX, v)
        s._do_ret(uc)

    sim.intercept(cfg['read'], gr)
    sim.intercept(cfg['write'], gw)

    d = open(os.path.join(HERE, 'gt_orig_live.bin'), 'rb').read()
    for i in range(len(d) // 8):
        v = struct.unpack_from('<Q', d, i * 8)[0]
        if v:
            sim.set_gt(i, v)
    sim.set_gt(0x20, bufbase)
    sim.set_gt(0x21, bufsize)

    kind, r = sim.call(fn, (), count=50000000)
    return kind, r, log


def mine_addr(name):
    import re
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+' + name + r'\s+([0-9a-f]{16})\s+f', ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})', ln).group(1), 16)
    return None


def main():
    img, sz, _ = image_layout(NT)
    s = KernelSim(ORIG)
    base = s.scratch((len(img) + 0xFFF) & ~0xFFF)
    s.uc.mem_write(base, img)
    del s
    print('buf=0x%X size=0x%X' % (base, len(img)))
    mva = mine_addr('MiniFilterPreClose')
    print('ORIG=0x%X  MINE=%s' % (ORIG_FN, hex(mva) if mva else None))
    if not mva:
        return
    ko, ro, lo = run('ORIG', ORIG_FN, base, len(img))
    km, rm, lm = run('MINE', mva, base, len(img))
    print('\nORIG %s writes=%d' % (ko, len(lo)))
    for i, v in lo:
        print('   GT[0x%X] = 0x%X' % (i, v))
    print('MINE %s writes=%d' % (km, len(lm)))
    for i, v in lm:
        print('   GT[0x%X] = 0x%X' % (i, v))
    print('=>', 'IDENTICAL' if {(i, v) for i, v in lo} == {(i, v) for i, v in lm} else 'DIFFERENT')


if __name__ == '__main__':
    main()