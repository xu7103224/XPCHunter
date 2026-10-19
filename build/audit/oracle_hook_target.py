#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线差分 FindHookTargetInExportWin8/Win7：原始 vs 我方，比较 GT 写入。

调用约定 __int64 f(ImageBase, ImageSize, UnusedParam, BaseAddress)
  → rcx=ImageBase, edx=ImageSize, r8=Unused, r9=BaseAddress

输入 GT 取自原始活体 dump（保证前提与实机一致）；GT[0x20] 换成模拟器映射的缓冲。
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

FUNCS = {
    'Win7': (0x14001C58C, None),
    'Win8': (0x14001C72C, None),
}
GTADDR = {
    'ORIG': dict(read=0x140029EFC, write=0x140029FF4),
    'MINE': dict(read=_map_sym('GtRead'), write=_map_sym('GtWrite')),
}


def mine_addr(name):
    import re
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        if re.search(r'\b' + name + r'\b', ln):
            m = re.search(r'([0-9a-fA-F]{16})\s+f', ln)
            if m:
                return int(m.group(1), 16)
    return None


def run(which, fn, bufbase, bufsize):
    drv = ORIG if which == 'ORIG' else MINE
    cfg = GTADDR[which]
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

    # 灌入活体 GT
    d = open(os.path.join(HERE, 'gt_orig_live.bin'), 'rb').read()
    for i in range(len(d) // 8):
        v = struct.unpack_from('<Q', d, i * 8)[0]
        if v:
            sim.set_gt(i, v)
    sim.set_gt(0x20, bufbase)
    sim.set_gt(0x21, bufsize)

    # 参数：rcx=ImageBase(GT[3])、edx=ImageSize(GT[0x21])、r8=0、r9=BaseAddress(GT[3])
    kbase = sim._gt_values.get(3, 0)
    kind, r = sim.call(fn, (kbase, bufsize, 0, kbase), count=20000000)
    return kind, r, log


def main():
    img, sz, _ = image_layout(NT)
    s = KernelSim(ORIG)
    base = s.scratch((len(img) + 0xFFF) & ~0xFFF)
    s.uc.mem_write(base, img)
    del s
    print('缓冲 base=0x%X size=0x%X' % (base, len(img)))

    for label, (ova, _) in FUNCS.items():
        mva = mine_addr('FindHookTargetInExport' + label)
        print('\n===== %s  原始=0x%X 我方=%s =====' % (label, ova, hex(mva) if mva else None))
        if not mva:
            print('  我方地址未找到'); continue
        ko, ro, lo = run('ORIG', ova, base, len(img))
        km, rm, lm = run('MINE', mva, base, len(img))
        print('  ORIG %s ret=%s writes=%s' % (ko, hex(ro & 0xFFFFFFFF) if isinstance(ro, int) else ro,
                                              [(hex(i), hex(v)) for i, v in lo]))
        print('  MINE %s ret=%s writes=%s' % (km, hex(rm & 0xFFFFFFFF) if isinstance(rm, int) else rm,
                                              [(hex(i), hex(v)) for i, v in lm]))
        print('  =>', 'IDENTICAL' if {(i, v) for i, v in lo} == {(i, v) for i, v in lm} else 'DIFFERENT')


if __name__ == '__main__':
    main()