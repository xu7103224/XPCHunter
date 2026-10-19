#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐轮比较「节区类型序列」：从给定文件偏移起，原始与我方各解 16 轮。

用于定位 FindHookTargetInExportWin8 不命中的根因（类型序列是否不同）。
用法: python oracle_type_seq.py <start_off_hex>
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
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

CFG = {
    'ORIG': dict(gtread=0x140029EFC, gtwrite=0x140029FF4,
                 init=0x14008A7E4, readpese=0x14008A54C),
    'MINE': dict(gtread=0x14001ED40, gtwrite=0x14001ED50,
                 init=0x140054580, readpese=0x140054790),
}


def run(which, img, bufbase, start_off, rounds=16):
    c = CFG[which]
    drv = ORIG if which == 'ORIG' else MINE
    sim = KernelSim(drv)
    sim.skip_stack_cookie_check()

    def gr(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(i, 0) & MASK64)
        s._do_ret(uc)

    def gw(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        s._gt_values[i] = uc.reg_read(UC_X86_REG_RDX) & MASK64
        uc.reg_write(UC_X86_REG_RAX, s._gt_values[i])
        s._do_ret(uc)

    sim.intercept(c['gtread'], gr)
    sim.intercept(c['gtwrite'], gw)

    ctx = sim.scratch(0x48)
    desc = sim.scratch(0x120)
    # InitPESectionReadContext(Base, Size, Mode, Param5,   ← rcx/rdx/r8/r9
    #                          ExtraField,Param6,Param7,Context) ← 栈 [rsp+0x28..0x40]
    # sim.call 的 stack_words 从 rsp+8 起写，故前面补 4 个 0 对齐 shadow space。
    MASK64 = (1 << 64) - 1
    # Windows x64：rcx/rdx/r8/r9 = 第 1..4 参；第 5..8 参在栈上
    #   [rsp+0x28]=arg5, [rsp+0x30]=arg6, [rsp+0x38]=arg7, [rsp+0x40]=arg8
    # sim.call 的 stack_words[0] 写在 rsp+8（shadow space 起点），
    # 故 arg5..arg8 对应下标 4..7。原始签名：
    #   (Base, Size, Mode, Param5, ExtraField, Param6, Param7, Context)
    # 调用点一般给 (…, 2, 0, -1, 0, 0, &ctx)
    kind, r = sim.call(c['init'],
                       (bufbase + start_off, len(img) - start_off, 2, 0),
                       stack_words=(0, 0, 0, 0, 0, MASK64 & ~0xFFFFFFFF, 0, ctx),
                       count=200000)
    if kind != 'OK':
        return ['INIT_ERR:' + str(r)]
    out = []
    for k in range(rounds):
        kind, r = sim.call(c['readpese'], (ctx, desc), count=3000000)
        if kind != 'OK':
            out.append('ERR:' + str(r)); break
        d = bytes(sim.uc.mem_read(desc, 0x120))
        typp = struct.unpack_from('<Q', d, 0x118)[0]
        ty = struct.unpack_from('<H', bytes(sim.uc.mem_read(typp + 6, 2)), 0)[0] if typp else -1
        f0 = struct.unpack_from('<I', d, 0xF0)[0]
        f50 = struct.unpack_from('<Q', d, 0x50)[0]
        f40 = struct.unpack_from('<I', d, 0x40)[0]
        f88 = struct.unpack_from('<Q', d, 0x88)[0]
        out.append('t=0x%X f0=0x%X f50=0x%X f40=0x%X f88=0x%X' % (ty, f0, f50, f40, f88))
        # 推进读指针
        rp = struct.unpack_from('<Q', bytes(sim.uc.mem_read(ctx, 0x48)), 8)[0]
        sim.uc.mem_write(ctx + 8, struct.pack('<Q', rp + f0))
    return out


def main():
    start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x764590
    img, sz, _ = image_layout(NT)
    s = KernelSim(ORIG)
    base = s.scratch((len(img) + 0xFFF) & ~0xFFF)
    s.uc.mem_write(base, img)
    del s
    print('start_off=0x%X  buf=0x%X  size=0x%X' % (start, base, len(img)))
    a = run('ORIG', img, base, start)
    b = run('MINE', img, base, start)
    print('\n%-42s | %s' % ('ORIG', 'MINE'))
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else ''
        y = b[i] if i < len(b) else ''
        mark = '' if x == y else '  <<< DIFF'
        print('%-42s | %s%s' % (x, y, mark))


if __name__ == '__main__':
    main()