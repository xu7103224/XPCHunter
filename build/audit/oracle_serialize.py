#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""直接差分 SerializeDataToBuffer（原始 sub_14008AA0C vs 我方）：
给定同一份合成 ContextArray + 描述符 + 缓冲，比较两实现写入操作数记录的字段。

若两者的操作数记录不同 → 确认「字段误读」缺陷在此函数同样存在。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim, MASK64  # noqa: E402

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')

# 原始 sub_14008AA0C；我方地址从 map 取（见下）
ORIG_FN = 0x14008AA0C
MINE_FN = 0x1400560F0   # 由 map 覆盖


def find_mine_addr():
    import re
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        if re.search(r'\bSerializeDataToBuffer\b', ln):
            m = re.search(r'([0-9a-fA-F]{16})', ln)
            if m:
                return int(m.group(1), 16)
    return None


def run(drv, fn, label, desc_off04, desc_off24):
    sim = KernelSim(drv)
    sim.skip_stack_cookie_check()
    ctxarr = sim.scratch(0x40)
    desc = sim.scratch(0x120)
    opnd = sim.scratch(0x38)
    buf = sim.scratch(0x20)
    sim.uc.mem_write(buf, bytes(range(0x20)))
    # 描述符：+0x04（原始读）与 +0x24（我方读）分别给不同值以便判别
    sim.uc.mem_write(desc + 0x04, struct.pack('<I', desc_off04))
    sim.uc.mem_write(desc + 0x24, struct.pack('<I', desc_off24))
    # ContextArray: [0]=读指针 [1]=结束 [2]=表条目 [3]=操作数记录 [4]=描述符
    sim.uc.mem_write(ctxarr, struct.pack('<QQQQQ', buf, buf + 0x20, 0, opnd, desc))
    kind, r = sim.call(fn, (ctxarr,), count=200000)
    after = bytes(sim.uc.mem_read(opnd, 0x38))
    print('%s -> %s ret=%s opnd=%s' % (label, kind, hex(r & 0xFFFFFFFF) if isinstance(r, int) else r, after.hex()))
    if sim.notes:
        print('   notes:', sim.notes[:2])


def main():
    fn = find_mine_addr()
    print('MINE SerializeDataToBuffer =', hex(fn) if fn else 'NOT FOUND')
    if not fn:
        return
    for o4, o24 in ((1, 3), (2, 3)):
        print('--- desc[+0x04]=%d desc[+0x24]=%d ---' % (o4, o24))
        run(ORIG, ORIG_FN, 'ORIG', o4, o24)
        run(MINE, fn, 'MINE', o4, o24)


if __name__ == '__main__':
    main()