#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全 .rdata 扫描差分：对原始与我方的 FindSyscallNumbers 做**端到端**对比。

价值：这是不依赖 VM 的最强验证 —— 只要两者产出的 syscall 表内容（每个
系统调用号 → 函数地址）逐项相同，就证明整条解码链在当前真实 ntoskrnl 上等价。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim, MASK64  # noqa: E402
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from pe_image_layout import image_layout  # noqa: E402
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX  # noqa

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

CFG = {
    'ORIG': dict(drv=ORIG, fsn=0x140052FDC, gtread=0x140029EFC, gtwrite=0x140029FF4,
                 exalloc=0x140077A00),
    'MINE': dict(drv=MINE, fsn=0x14002E9C0, gtread=0x14001ED50, gtwrite=0x14001ED60,
                 exalloc=0x14002D980),
}
SERVICE_COUNT = 0x1D0


def run(cfg, img):
    sim = KernelSim(cfg['drv'])
    sim.skip_stack_cookie_check()

    def gt_read(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(idx, 0) & MASK64)
        s._do_ret(uc)

    def gt_write(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        val = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s._gt_values[idx] = val
        uc.reg_write(UC_X86_REG_RAX, val & MASK64)
        s._do_ret(uc)

    def exalloc(uc, s):
        uc.reg_write(UC_X86_REG_RAX, s._pool)
        s._do_ret(uc)

    sim.intercept(cfg['gtread'], gt_read)
    sim.intercept(cfg['gtwrite'], gt_write)
    sim.intercept(cfg['exalloc'], exalloc)

    base = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(base, img)
    sim._pool = sim.scratch(0x10000)
    for gt, v in ((0x20, base), (0x21, len(img)), (0x42, SERVICE_COUNT),
                  (0x41D1, 0x1B9600), (0x41D4, 0x1B90E0), (0x914, 19045)):
        sim.set_gt(gt, v)

    kind, r = sim.call(cfg['fsn'], (), count=30000000)
    tbl = sim._gt_values.get(0x62, 0)
    if not tbl:
        return None
    return [struct.unpack('<Q', bytes(sim.uc.mem_read(sim._pool + 8 * i, 8)))[0]
            for i in range(SERVICE_COUNT)]


def main():
    img, sz, _ = image_layout(NT)
    a = run(CFG['ORIG'], img)
    b = run(CFG['MINE'], img)
    if a is None or b is None:
        print('ORIG table=%s MINE table=%s' % ('ok' if a else 'NULL', 'ok' if b else 'NULL'))
        return
    diff = [i for i in range(SERVICE_COUNT) if a[i] != b[i]]
    print('服务表条目: %d' % SERVICE_COUNT)
    print('逐项不同: %d' % len(diff))
    for i in diff[:10]:
        print('  [%d] orig=0x%X mine=0x%X' % (i, a[i], b[i]))
    print('结论:', 'IDENTICAL' if not diff else 'DIFFERENT')


if __name__ == '__main__':
    main()