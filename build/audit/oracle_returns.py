#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐 handler 记录「入口 idx+参数」与「返回 RAX」，原始 vs 我方，定位 entry#2 的分歧 handler。"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = open(os.path.join(HERE, 'nt_stream.bin'), 'rb').read()

PROF = {
    'ORIG': dict(path=ORIG, read_entry=0x14008A54C, init_ctx=0x14008A7E4,
                 dispatch_call=0x14008C3A6, dispatch_ret=0x14008C3AA,
                 fntable=0x1400A3DD0),
    'MINE': dict(path=MINE, read_entry=0x1400541E0, init_ctx=0x140054180,
                 dispatch_call=0x140055D6B, dispatch_ret=0x140055D6F,
                 fntable=0x1400937A0),
}

NAMES = ['Prefix', 'ModrmInstr', 'ReadByte', 'FieldByte', 'ReadWord', 'SizeImm',
         'AsmField', 'Serialize', 'ClassifyV1', 'ReadDword', 'ReadQword',
         'Tbl16_32_64', 'TblOffset', 'Grp1', 'Grp2', 'Grp3', 'WithModrm',
         'Grp4', 'ByPrefix', 'Grp5', 'Grp6', 'OneByte', 'TwoByte0F',
         'TwoByte38', 'TwoByte3A', 'ModrmTbl', 'OpByte', 'StubZero', None, None,
         None, None, 'MultiByte', 'ReadImm', 'ReadField', 'TblWithPrefix',
         'TblDirect']


def run(label, p, maxdepth=8):
    sim = KernelSim(p['path'])
    sim.skip_stack_cookie_check()
    uc = sim.uc
    ctx = sim.scratch(0x200)
    ent = sim.scratch(0x200)
    sva = sim.scratch(0x4000, STREAM)
    sim.call(p['init_ctx'], (sva, len(STREAM), 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx))
    # 推进到 entry#2 的起点：entry0 f0=5，entry1 f0=1
    for s in (5, 1):
        cur = struct.unpack_from('<Q', uc.mem_read(ctx + 8, 8), 0)[0]
        uc.mem_write(ctx + 8, struct.pack('<Q', (cur + s) & 0xFFFFFFFFFFFFFFFF))

    depth = [0]
    log = []

    def on_call(uc_, s_):
        # 记录本次 dispatch 将调用的 handler idx 与目标
        r8v = uc_.reg_read(UC_X86_REG_R8)
        rax = uc_.reg_read(UC_X86_REG_RAX)
        try:
            idx = rax & 0xFF
            tgt = struct.unpack('<Q', uc_.mem_read(p['fntable'] + 8 * idx, 8))[0]
        except Exception:
            idx, tgt = -1, 0
        depth[0] += 1
        nm = NAMES[idx] if 0 <= idx < len(NAMES) else '?'
        log.append(f'{"  "*depth[0]}-> dispatch idx={idx}({nm}) tgt={hex(tgt)}')

    def on_ret(uc_, s_):
        rax = uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFFFFFFFFFF
        if rax == 0xFFFFFFFFFFFFFFFF:
            rax = -1
        log.append(f'{"  "*depth[0]}<- dispatch ret={rax}')
        depth[0] = max(0, depth[0] - 1)

    sim.intercept(p['dispatch_call'], on_call)
    sim.intercept(p['dispatch_ret'], on_ret)

    kind, res = sim.call(p['read_entry'], (ctx, ent), count=5000000)
    b = sim.read(ent, 0x120)
    print(f'=== {label} ret={res} f0={struct.unpack_from("<I", b, 0xF0)[0]} '
          f'f50=0x{struct.unpack_from("<Q", b, 0x50)[0]:x} '
          f'f88=0x{struct.unpack_from("<Q", b, 0x88)[0]:x} '
          f'f38={struct.unpack_from("<I", b, 0x38)[0]} fE4=0x{b[0xE4]:x} ===')
    for l in log[:60]:
        print('  ' + l)


if __name__ == '__main__':
    run('ORIG', PROF['ORIG'])
    run('MINE', PROF['MINE'])