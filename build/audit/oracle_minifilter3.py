#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MiniFilter 三扫描器（PreClose / PreDirEnum / PreSetInfo）离线差分。

对同一函数分别跑原始与我方实现，比较 GT 写入。
输入 GT 取自原始活体 dump（gt_orig_live.bin）；GT[0x20] 换成模拟器映射的
**镜像布局** 缓冲（pe_image_layout.py），GT[0x21] 用该缓冲大小。

用法: python oracle_minifilter3.py [函数名...]
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64  # noqa: E402
from pe_image_layout import image_layout  # noqa: E402
from unicorn.x86_const import (UC_X86_REG_RCX, UC_X86_REG_RDX,  # noqa: E402
                               UC_X86_REG_RAX)

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')

def _map_sym(name):
    import re as _re, os as _os
    _mp = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for _ln in open(_mp, encoding='utf-8', errors='ignore'):
        _m = _re.match(r'\s+0001:[0-9a-f]{8}\s+' + name + r'\s+([0-9a-f]{16})\s+f', _ln)
        if _m:
            return int(_m.group(1), 16)
    return 0

MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

GT = {
    'ORIG': dict(read=0x140029EFC, write=0x140029FF4),
    'MINE': dict(read=_map_sym('GtRead'), write=_map_sym('GtWrite')),
}

TARGETS = [
    ('MiniFilterPreClose',   0x1400152D4),
    ('MiniFilterPreDirEnum', 0x140015A48),
    ('MiniFilterPreSetInfo', 0x140015F34),
]


def mine_addr(name):
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+' + name + r'\s+([0-9a-f]{16})\s+f', ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})', ln).group(1), 16)
    return None


def run(which, fn, img, imgsize):
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

    # 关键：缓冲必须写进**本实例**的地址空间（每个 KernelSim 各有独立 Uc）。
    bufbase = sim.scratch((imgsize + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(bufbase, img)
    sim.set_gt(0x20, bufbase)
    sim.set_gt(0x21, imgsize)

    # 上限必须足够大：真实内核上 PreDirEnum 需要 ~8.2 亿条指令才能扫完 0xAB2000 字节。
    # 用 2 亿会让 ORIG 在中途被截断，产生「两侧都写 0」的假一致。
    kind, r = sim.call(fn, (), count=3000000000)
    return kind, r, log


def main():
    want = set(sys.argv[1:]) if len(sys.argv) > 1 else None
    img, sz, _ = image_layout(NT)
    print('镜像大小: 0x%X' % len(img))

    allok = True
    for name, ova in TARGETS:
        if want and name not in want:
            continue
        mva = mine_addr(name)
        print('\n===== %s  ORIG=0x%X  MINE=%s =====' % (name, ova, hex(mva) if mva else None))
        if not mva:
            print('  我方地址未找到'); allok = False; continue
        ko, ro, lo = run('ORIG', ova, img, len(img))
        km, rm, lm = run('MINE', mva, img, len(img))
        print('  ORIG %s writes=%d' % (ko, len(lo)))
        for i, v in lo:
            print('     GT[0x%-4X] = 0x%X' % (i, v))
        print('  MINE %s writes=%d' % (km, len(lm)))
        for i, v in lm:
            print('     GT[0x%-4X] = 0x%X' % (i, v))
        ok = {(i, v) for i, v in lo} == {(i, v) for i, v in lm}
        print('  =>', 'IDENTICAL(槽+值)' if ok else 'DIFFERENT')
        allok = allok and ok
    print('\n总判定:', 'PASS' if allok else 'FAIL')


if __name__ == '__main__':
    main()