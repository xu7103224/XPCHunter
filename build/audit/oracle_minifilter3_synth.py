#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MiniFilter 三扫描器的**合成 PE 差分**：用构造的最小 PE 缓冲逐条触发
每个写块，比较原始与我方的 GT 写入。比真实内核更决定性（真实内核里两侧
都可能被 emu 截断，导致「都写 0」的假一致）。

用法: python oracle_minifilter3_synth.py
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')


def ma(name):
    import re
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+' + name + r'\s+([0-9a-f]{16})\s+f', ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})', ln).group(1), 16)


def mkpe(pat, off=0x100, size=0x1000):
    buf = bytearray(size)
    struct.pack_into('<H', buf, 0, 0x5A4D)
    struct.pack_into('<I', buf, 0x3C, 0x40)
    struct.pack_into('<I', buf, 0x40, 0x00004550)
    struct.pack_into('<H', buf, 0x44, 0x8664)
    struct.pack_into('<H', buf, 0x46, 0)          # NumberOfSections = 0 → 无 .PAGE
    struct.pack_into('<H', buf, 0x54, 0xE0)
    buf[off:off + len(pat)] = pat
    return bytes(buf)


def run(drv, fn, rd, wr, img):
    sim = KernelSim(drv); sim.skip_stack_cookie_check(); w = []

    def gr(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(i, 0) & MASK64); s._do_ret(uc)

    def gw(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        v = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s._gt_values[i] = v; w.append((i, v))
        uc.reg_write(UC_X86_REG_RAX, v); s._do_ret(uc)

    sim.intercept(rd, gr); sim.intercept(wr, gw)
    d = open(os.path.join(HERE, 'gt_orig_live.bin'), 'rb').read()
    for i in range(len(d) // 8):
        v = struct.unpack_from('<Q', d, i * 8)[0]
        if v: sim.set_gt(i, v)
    b = sim.scratch(0x2000)
    sim.uc.mem_write(b, img)
    sim.set_gt(0x20, b); sim.set_gt(0x21, len(img))
    k = sim.call(fn, (), count=20000000)
    return k, w


def pad(b):
    """补足到 0x40 字节，保证描述符可解码。"""
    return (b + bytes(0x40))[:0x40]


CASES = [
    # (名称, 目标函数, 字节模式)
    ('DirEnum/A1',   'MiniFilterPreDirEnum',
     bytes.fromhex('488d81b800000048894008488900488d81a0000000')),
    ('DirEnum/A2',   'MiniFilterPreDirEnum',
     bytes.fromhex('488d81b800000048894008488900')),
    ('DirEnum/B',    'MiniFilterPreDirEnum',
     bytes.fromhex('488b81b8000000')),
    ('SetInfo/1',    'MiniFilterPreSetInfo',
     bytes.fromhex('488d81b800000048894008488900')),
    ('SetInfo/2',    'MiniFilterPreSetInfo',
     bytes.fromhex('488d81b800000041f6')),
    ('SetInfo/3',    'MiniFilterPreSetInfo',
     bytes.fromhex('488d81b80000004805')),
]

FORIG = {'MiniFilterPreDirEnum': 0x140015A48, 'MiniFilterPreSetInfo': 0x140015F34,
         'MiniFilterPreClose': 0x1400152D4}


def main():
    bad = 0
    for label, fname, pat in CASES:
        img = mkpe(pat)
        m = ma(fname)
        ko = run(ORIG, FORIG[fname], 0x140029EFC, 0x140029FF4, img)
        km = run(MINE, m, 0x14001ED40, 0x14001ED50, img)
        so = ko[2] if isinstance(ko, tuple) and len(ko) > 2 else None
        print('%-14s ORIG=%s  MINE=%s' % (label, ko, km))
    print('\n（注：本脚本的 run() 只返回 call 结果；写入明细见下）')


if __name__ == '__main__':
    main()
