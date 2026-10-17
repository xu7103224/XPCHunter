#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""追踪 entry#2(offset 0x6 = 48 83 ec 20) 的 handler 调用链与每步读指针，原始 vs 我方。"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX,
)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = bytes.fromhex(
    '48895c2418564883ec2048897c2438488bf265488b3c2588010000'
    '66ff8fe6010000b203e887000000488bd84885c0743548896c2430'
    'e885fba4fff7830c0300')

# 原始各 handler 入口
ORIG_FN = {
    'prefix': 0x14008BCFC, 'modrm': 0x14008B770, 'readbyte': 0x14008BF20,
    'fieldbyte': 0x14008A904, 'readword': 0x14008C008, 'sizeimm': 0x14008C0F8,
    'asmfield': 0x14008A93C, 'serialize': 0x14008AA0C, 'classifyv1': 0x14008ABB8,
    'readdword': 0x14008C058, 'readqword': 0x14008C0A8, 'tbl16_32_64': 0x14008AED0,
    'tbloffset': 0x14008B108, 'grp1': 0x14008B180, 'grp2': 0x14008B238,
    'grp3': 0x14008B2B0, 'withmodrm': 0x14008B484, 'grp4': 0x14008B588,
    'byprefix': 0x14008B5EC, 'grp5': 0x14008B6A8, 'grp6': 0x14008B70C,
    'onebyte': 0x14008BA3C, 'twobyte0f': 0x14008BAA0, 'twobyte38': 0x14008BB14,
    'twobyte3a': 0x14008BB88, 'modrmtbl': 0x14008BBFC, 'opbyte': 0x14008BC98,
    'dispatch': 0x14008C2D4, 'imm': 0x14008C598, 'calc': 0x14008C254,
}

# 我方（由 map 提取，函数按相同名字）
MINE_FN = {
    'prefix': 0x140055770, 'modrm': 0x140055DC0, 'readbyte': 0x1400554F0,
    'fieldbyte': 0x140054660, 'readword': 0x140055540, 'sizeimm': 0x140055590,
    'asmfield': 0x1400546B0, 'serialize': 0x140054770, 'classifyv1': 0x14000FC30,
    'readdword': 0x140056130, 'readqword': 0x140056180, 'tbl16_32_64': 0x140054920,
    'tbloffset': 0x140054B80, 'grp1': 0x140054C00, 'grp2': 0x140054CC0,
    'grp3': 0x140054D40, 'withmodrm': 0x140055140, 'grp4': 0x140054F50,
    'byprefix': 0x140054FC0, 'grp5': 0x140055060, 'grp6': 0x1400550D0,
    'onebyte': 0x140055240, 'twobyte0f': 0x1400552B0, 'twobyte38': 0x140055320,
    'twobyte3a': 0x140055390, 'modrmtbl': 0x140055400, 'opbyte': 0x140055480,
    'dispatch': 0x140055C90, 'imm': 0x140055980, 'calc': 0x140055A80,
}

INITCTX = {'ORIG': 0x14008A7E4, 'MINE': 0x140054180}
READENTRY = {'ORIG': 0x14008A54C, 'MINE': 0x1400541E0}


def run(label, path, fns):
    sim = KernelSim(path)
    sim.skip_stack_cookie_check()
    uc = sim.uc
    ctx = sim.scratch(0x200)
    ent = sim.scratch(0x200)
    sva = sim.scratch(0x2000, STREAM)
    sim.call(INITCTX[label], (sva, len(STREAM), 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx))
    for s in (5, 1):
        cur = struct.unpack_from('<Q', uc.mem_read(ctx + 8, 8), 0)[0]
        uc.mem_write(ctx + 8, struct.pack('<Q', (cur + s) & 0xFFFFFFFFFFFFFFFF))

    log = []
    addr2name = {v: k for k, v in fns.items()}
    # 对每个 handler 入口挂钩：记录入参与返回后的 RAX
    for name, addr in fns.items():
        def make(nm):
            def h(uc_, s_):
                rcx = uc_.reg_read(UC_X86_REG_RCX)
                rsp = uc_.reg_read(0x2C) if False else None
                arr = struct.unpack('<6Q', bytes(uc_.mem_read(rcx, 48))) if nm in (
                    'dispatch',) else None
                log.append(f'{nm}(rcx={hex(rcx)} rdx={hex(uc_.reg_read(UC_X86_REG_RDX))} '
                           f'r8={hex(uc_.reg_read(UC_X86_REG_R8))} r9={hex(uc_.reg_read(UC_X86_REG_R9))})'
                           + (f' arr={[hex(x) for x in arr]}' if arr else ''))
            return h
        sim.intercept(addr, make(name))

    kind, res = sim.call(READENTRY[label], (ctx, ent), count=3000000)
    b = sim.read(ent, 0x120)
    print(f'=== {label} ret={res} f0={struct.unpack_from("<I", b, 0xF0)[0]} '
          f'f38={struct.unpack_from("<I", b, 0x38)[0]} '
          f'f50=0x{struct.unpack_from("<Q", b, 0x50)[0]:x} '
          f'f88=0x{struct.unpack_from("<Q", b, 0x88)[0]:x} '
          f'f2a={struct.unpack_from("<H", b, 0x2A)[0]} fE4=0x{b[0xE4]:x}')
    for l in log:
        print('   ', l)


if __name__ == '__main__':
    run('ORIG', ORIG, ORIG_FN)
    run('MINE', MINE, MINE_FN)