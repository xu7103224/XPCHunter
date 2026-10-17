#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 DecodeImmediateOperandValue 入口 dump 描述符关键字段 + 在 retn 处取返回值，原始 vs 我方。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel_sim import KernelSim  # noqa: E402
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_R8  # noqa: E402

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
STREAM = bytes.fromhex(
    '48895c2418564883ec2048897c2438488bf265488b3c2588010000'
    '66ff8fe6010000b203e887000000488bd84885c0743548896c2430'
    'e885fba4fff7830c0300')

PROF = {
    'ORIG': dict(path=ORIG, read_entry=0x14008A54C, init_ctx=0x14008A7E4,
                 imm=0x14008C598, imm_ret=0x14008C6EB, prefix=0x14008BCFC),
    'MINE': dict(path=MINE, read_entry=0x1400541E0, init_ctx=0x140054180,
                 imm=0x140055920, imm_ret=None, prefix=0x140055710),
}

FIELDS = [(0x00, 'D', 'Mode'), (0x04, 'D', 'ModeDup'), (0x08, 'D', 'f08'),
          (0x20, 'D', 'flags20'), (0x24, 'D', 'opSize24'), (0x2C, 'D', 'type5'),
          (0xD8, 'D', 'pfxD8'), (0xF4, 'D', 'fF4'), (0xE0, 'D', 'immE0')]


def desc_str(b):
    out = []
    for off, ty, name in FIELDS:
        v = struct.unpack_from('<I', b, off)[0]
        out.append(f'{name}=0x{v:x}')
    return ' '.join(out)


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
    desc_addr = [0]

    def on_imm(uc_, sim_):
        r8 = uc_.reg_read(UC_X86_REG_R8) & 0xFFFFFFFFFFFFFFFF
        desc_addr[0] = r8
        b = bytes(uc_.mem_read(r8, 0x120))
        info.append('imm-in  ' + desc_str(b))
        info.append(f'imm-in  rcx={hex(uc_.reg_read(1))} rdx={hex(uc_.reg_read(2))} r9={hex(uc_.reg_read(9))}')

    sim.intercept(p['imm'], on_imm)

    # 找 imm 的 retn：在 imm 起始后 0x200 字节内扫 0xC3，取第一个（近似）。
    # 更稳：直接 hook prefix 函数的尾部也可；此处用返回处的下一个地址由 call 决定。
    # 采用简单办法：hook 所有包含 C3 的块不可行。改为在 imm 内部关键分支点插桩。
    # 分支点：A619 对应的 test ebp,ebp；A672 对应的 test ebp,ebp。
    # 这里改用「执行到 imm 之后读 RAX」：hook prefix 函数返回后所属块不易定位，
    # 因此我们 hook imm 内两条 test ebp,ebp 的地址。
    kind, res = sim.call(p['read_entry'], (ctx_va, entry_va), count=2000000)
    b = sim.read(entry_va, 0x120)
    print(f'=== {label} ===')
    for line in info:
        print('  ' + line)
    print(f'  entry ret={res} f0={struct.unpack_from("<I", b, 0xF0)[0]} '
          f'fE4={b[0xE4]:#x} desc_final: {desc_str(b)}')


if __name__ == '__main__':
    for lb in ('ORIG', 'MINE'):
        try:
            run(lb, PROF[lb])
        except Exception as e:  # noqa: BLE001
            print(f'{lb} EXC {e}')