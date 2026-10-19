#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""节区扫描族「离线差分」：对同一函数，分别跑原始与我方实现，比较 GT 写入。

这是发现「字段偏移/推进顺序/判据」类缺陷的最快手段（不需 VM、不需断点）。
输入 GT 取自**原始驱动活体 dump**（gt_orig_live.bin），保证前提与实机一致。

用法: python oracle_scanner_family.py
"""
import os
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
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

# 原始与我方的「GT 读写」桩地址（随编译变化；由 map 文件确认）
GT = {
    'ORIG': dict(read=0x140029EFC, write=0x140029FF4, gtbase=0x1400A84F0),
    'MINE': dict(read=0x14001EDC0, write=0x14001EDD0, gtbase=0x1400A0060),
}

# 待差分的函数： (名称, 原始VA, 我方VA)
TARGETS = [
    ('ScanFileForPeSectionInfo', 0x140015128, None),
    ('MiniFilterPostWrite',      0x140014D08, 0x1400303B0),
    ('DisableHookProtection',    0x14001CC4C, None),
    ('HookSyscallNtOpenKey',     0x14001D4C0, None),
]

# 活体原始 GT（非零槽）→ 灌入模拟器
LIVE = {}


def load_live():
    d = open(os.path.join(HERE, 'gt_orig_live.bin'), 'rb').read()
    for i in range(len(d) // 8):
        v = struct.unpack_from('<Q', d, i * 8)[0]
        if v:
            LIVE[i] = v
    # GT[0x20]（PE 文件缓冲基址）是池地址，模拟器里要用我们映射的缓冲替代
    print('活体非零 GT 槽: %d' % len(LIVE))


def mine_addr(name):
    import re
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        if re.search(r'\b' + name + r'\b', ln):
            m = re.search(r'([0-9a-fA-F]{16})\s+f', ln)
            if m:
                return int(m.group(1), 16)
    return None


def run(which, fn, img_base):
    cfg = GT[which]
    drv = ORIG if which == 'ORIG' else MINE
    sim = KernelSim(drv)
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
        log.append((idx, val))
        uc.reg_write(UC_X86_REG_RAX, val & MASK64)
        s._do_ret(uc)

    sim.intercept(cfg['read'], gt_read)
    sim.intercept(cfg['write'], gt_write)
    # 灌入活体 GT
    for i, v in LIVE.items():
        sim.set_gt(i, v)
    # 覆盖 PE 缓冲基址为模拟器映射
    sim.set_gt(0x20, img_base)
    sim.set_gt(0x21, len(open(NT, 'rb').read()))

    # 参数：ImageBase=内核基址(GT[3])、ImageSize=GT[0x21]
    kbase = sim._gt_values.get(3, 0)
    ksize = sim._gt_values.get(0x21, 0)
    try:
        kind, r = sim.call(fn, (kbase, ksize, 0, kbase), count=5000000)
    except TypeError:
        kind, r = sim.call(fn, (), count=5000000)
    return kind, r, log


def main():
    load_live()
    img, sz, _ = image_layout(NT)
    s = KernelSim(ORIG)
    base = s.scratch((len(img) + 0xFFF) & ~0xFFF)
    s.uc.mem_write(base, img)
    del s

    for name, ova, mva in TARGETS:
        mva = mva or mine_addr(name)
        print('\n===== %s =====' % name)
        if not mva:
            print('  我方地址未找到（可能被内联）'); continue
        ko, ro, lo = run('ORIG', ova, base)
        km, rm, lm = run('MINE', mva, base)
        print('  ORIG %s ret=%s writes=%s' % (ko, hex(ro & 0xFFFFFFFF) if isinstance(ro, int) else ro,
                                              [(hex(i), hex(v)) for i, v in lo][:6]))
        print('  MINE %s ret=%s writes=%s' % (km, hex(rm & 0xFFFFFFFF) if isinstance(rm, int) else rm,
                                              [(hex(i), hex(v)) for i, v in lm][:6]))
        oset = {(i, v) for i, v in lo}
        mset = {(i, v) for i, v in lm}
        print('  =>', 'IDENTICAL' if oset == mset else 'DIFFERENT')


if __name__ == '__main__':
    main()