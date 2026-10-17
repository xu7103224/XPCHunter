#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 DecodeOpcodeWithPrefix 入口 dump 它的入参 ContextArray[0..4]，原始 vs 我方。
这能直接看出递归 handler 传给它的 [0] 读指针 / [1] 结束边界 是否错。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel_sim import KernelSim  # noqa: E402
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RSP  # noqa: E402

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = bytes.fromhex(
    '48895c2418564883ec2048897c2438488bf265488b3c2588010000'
    '66ff8fe6010000b203e887000000488bd84885c0743548896c2430'
    'e885fba4fff7830c0300')

PROF = {
    'ORIG': dict(path=ORIG, read_entry=0x14008A54C, init_ctx=0x14008A7E4,
                 prefix=0x14008BCFC),
    'MINE': dict(path=MINE, read_entry=0x1400541E0, init_ctx=0x140054180,
                 prefix=0x140055710),
}


def run(label, p):
    sim = KernelSim(p['path'])
    sim.skip_stack_cookie_check()
    uc = sim.uc
    ctx_va = sim.scratch(0x200)
    entry_va = sim.scratch(0x200)
    sva = sim.scratch(0x2000, STREAM)
    sim.call(p['init_ctx'], (sva, len(STREAM), 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx_va))
    for s in (5, 1):
        cur = struct.unpack_from('<Q', uc.mem_read(ctx_va + 8, 8), 0)[0]
        uc.mem_write(ctx_va + 8, struct.pack('<Q', (cur + s) & 0xFFFFFFFFFFFFFFFF))

    info = []

    def on_prefix(uc_, sim_):
        arr = uc_.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFFFFFFFFFF
        vals = struct.unpack('<6Q', bytes(uc_.mem_read(arr, 48)))
        info.append(f'prefix ctxarr @ {hex(arr)}: ' +
                    ' '.join(f'[{i}]={hex(v)}' for i, v in enumerate(vals)))

    sim.intercept(p['prefix'], on_prefix)
    kind, res = sim.call(p['read_entry'], (ctx_va, entry_va), count=2000000)
    b = sim.read(entry_va, 0x120)
    print(f'=== {label} ===')
    for line in info:
        print('  ' + line)
    print(f'  entry ret={res} f0={struct.unpack_from("<I", b, 0xF0)[0]}')


if __name__ == '__main__':
    for lb in ('ORIG', 'MINE'):
        try:
            run(lb, PROF[lb])
        except Exception as e:  # noqa: BLE001
            print(f'{lb} EXC {e}')