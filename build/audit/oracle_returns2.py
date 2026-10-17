#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 UC_HOOK_CODE 在 dispatch 入口/出口记录 idx 与返回，定位 entry#2 分歧 handler。"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_R8,
)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = open(os.path.join(HERE, 'nt_stream.bin'), 'rb').read()

PROF = {
    'ORIG': dict(path=ORIG, read_entry=0x14008A54C, init_ctx=0x14008A7E4,
                 dispatch=0x14008C2D4),
    'MINE': dict(path=MINE, read_entry=0x1400541E0, init_ctx=0x140054180,
                 dispatch=0x140055C90),
}


def run(label, p):
    sim = KernelSim(p['path'])
    sim.skip_stack_cookie_check()
    uc = sim.uc
    ctx = sim.scratch(0x200)
    ent = sim.scratch(0x200)
    sva = sim.scratch(0x4000, STREAM)
    sim.call(p['init_ctx'], (sva, len(STREAM), 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx))
    for s in (5, 1):
        cur = struct.unpack_from('<Q', uc.mem_read(ctx + 8, 8), 0)[0]
        uc.mem_write(ctx + 8, struct.pack('<Q', (cur + s) & 0xFFFFFFFFFFFFFFFF))

    d = p['dispatch']
    depth = [0]
    log = []

    def on_code(uc_, address, size, ud):
        if address == d:
            r8 = uc_.reg_read(UC_X86_REG_R8)
            try:
                seq = bytes(uc_.mem_read(r8, 3))
            except Exception:
                seq = b'??'
            depth[0] += 1
            log.append(f'{"  "*depth[0]}ENTER dispatch seq={seq.hex()} '
                       f'tbl={hex(r8)}')
        elif address == d and False:
            pass

    # dispatch 的返回点：函数末尾 retn 地址（orig 0x14008C3F9, mine 0x140055DAB）
    ret_addr = {'ORIG': 0x14008C3F9, 'MINE': 0x140055DAB}[label]

    def on_code2(uc_, address, size, ud):
        if address == ret_addr:
            rax = uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFFFFFFFFFF
            log.append(f'{"  "*depth[0]}LEAVE dispatch ret={rax if rax != 0xFFFFFFFFFFFFFFFF else -1}')
            depth[0] = max(0, depth[0] - 1)

    uc.hook_add(UC_HOOK_CODE, on_code, begin=d, end=d + 1)
    uc.hook_add(UC_HOOK_CODE, on_code2, begin=ret_addr, end=ret_addr + 1)

    kind, res = sim.call(p['read_entry'], (ctx, ent), count=5000000)
    b = sim.read(ent, 0x120)
    print(f'=== {label} ret={res} f0={struct.unpack_from("<I", b, 0xF0)[0]} '
          f'f50=0x{struct.unpack_from("<Q", b, 0x50)[0]:x} ===')
    for l in log[:40]:
        print('  ' + l)


if __name__ == '__main__':
    run('ORIG', PROF['ORIG'])
    run('MINE', PROF['MINE'])