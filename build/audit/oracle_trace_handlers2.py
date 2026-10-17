#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐 handler 差分：记录 DispatchInstructionDecode 每次分发的 idx/目标/返回值、
DecodeImmediateOperandValue 的参数与返回、以及描述符关键字段，原始 vs 我方。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel_sim import KernelSim  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RBX, UC_X86_REG_RDI,
)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = bytes.fromhex(
    '48895c2418564883ec2048897c2438488bf265488b3c2588010000'
    '66ff8fe6010000b203e887000000488bd84885c0743548896c2430'
    'e885fba4fff7830c0300')

PROFILES = {
    'ORIG': dict(path=ORIG, read_entry=0x14008A54C, init_ctx=0x14008A7E4,
                 dispatch=0x14008C2D4, imm=0x14008C598, modrm_byte=0x14008C3FC,
                 desc=0, descname=''),
    'MINE': dict(path=MINE, read_entry=0x1400541E0, init_ctx=0x140054180,
                 dispatch=0x140055C30, imm=0x140055920, modrm_byte=0x140055840,
                 desc=0, descname=''),
}


def run(label, prof, skip=(5, 1)):
    sim = KernelSim(prof['path'])
    sim.skip_stack_cookie_check()
    uc = sim.uc
    ctx_va = sim.scratch(0x200)
    entry_va = sim.scratch(0x200)
    sva = sim.scratch(0x2000, STREAM)
    sim.call(prof['init_ctx'], (sva, len(STREAM), 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx_va))
    for s in skip:
        cur = struct.unpack_from('<Q', uc.mem_read(ctx_va + 8, 8), 0)[0]
        uc.mem_write(ctx_va + 8, struct.pack('<Q', (cur + s) & 0xFFFFFFFFFFFFFFFF))

    log = []

    def r(name):
        return uc.reg_read(name) & 0xFFFFFFFFFFFFFFFF

    def on_dispatch(uc_, sim_):
        idx = r(UC_X86_REG_R8)
        rax = r(UC_X86_REG_RAX)
        try:
            tgt = struct.unpack('<Q', uc_.mem_read(rax + 8 * (idx % 256), 8))[0]
        except Exception:
            tgt = 0
        log.append([f'dispatch idx={idx} tgt={hex(tgt)}', None])

    def on_imm_ret(uc_, sim_):
        # 在 imm 函数的返回点不是直接可钩；改为记录入口参数
        pass

    sim.intercept(prof['dispatch'], on_dispatch)

    # 在 imm 函数入口记录参数（用 dispatch 里 call 的下一层：拦截 imm 地址本身）
    def on_imm(uc_, sim_):
        log.append([f'  imm(cx={hex(r(UC_X86_REG_RCX))} end={hex(r(UC_X86_REG_RDX))} '
                    f'r8={hex(r(UC_X86_REG_R8))} r9={hex(r(UC_X86_REG_R9))})', None])
    sim.intercept(prof['imm'], on_imm)

    kind, res = sim.call(prof['read_entry'], (ctx_va, entry_va), count=2000000)
    b = sim.read(entry_va, 0x120)
    print(f'=== {label} ===')
    for line, _ in log:
        print('  ' + line)
    print(f'  ret={res} f0={struct.unpack_from("<I", b, 0xF0)[0]} '
          f'f38={struct.unpack_from("<I", b, 0x38)[0]} '
          f'f50=0x{struct.unpack_from("<Q", b, 0x50)[0]:x} '
          f'f88=0x{struct.unpack_from("<Q", b, 0x88)[0]:x} '
          f'f78={struct.unpack_from("<I", b, 0x78)[0]} '
          f'f2a={struct.unpack_from("<H", b, 0x2A)[0]} '
          f'fE4={b[0xE4]:#x} fe0=0x{struct.unpack_from("<I", b, 0xE0)[0]:x}')
    print('  notes', sim.notes[:4])


if __name__ == '__main__':
    for lb in ('ORIG', 'MINE'):
        try:
            run(lb, PROFILES[lb])
        except Exception as e:  # noqa: BLE001
            print(f'{lb} EXC {e}')