#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐轮跟踪 FindKernelPESectionByType 的 ReadPESectionEntry 结果（真实镜像布局缓冲）。

关键：
  * GT 读写桩地址**随编译不同**，必须按各自 map 给的地址设桩；
  * 我方 g_GlobalTable 在 0x1400A1060，原始在 0x1400A84F0；
  * 不递归 emu_start：用 block 钩子捕获 ReadPESectionEntry 入口与其返回地址。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim, MASK64  # noqa: E402
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from pe_image_layout import image_layout  # noqa: E402

from unicorn.x86_const import (UC_X86_REG_RCX, UC_X86_REG_RDX,  # noqa: E402
                               UC_X86_REG_RSP, UC_X86_REG_RIP,
                               UC_X86_REG_RAX)

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

CFG = {
    'ORIG': dict(drv=ORIG, fkpsbt=0x14007A6B8, readpese=0x14008A54C,
                 gtread=0x140029EFC, gtwrite=0x140029FF4,
                 handlers={
                     0x14008A87C: 'ReadPESectionField',
                     0x14008A904: 'ReadPESectionFieldByte',
                     0x14008BF20: 'DecodeOpcodeReadByte',
                     0x14008C008: 'DecodeReadWordImmediate',
                     0x14008C0F8: 'DecodeReadSizeDepImm',
                     0x14008BF68: 'DecodeReadImmediateValue',
                 }),
    'MINE': dict(drv=MINE, fkpsbt=0x140075C10, readpese=0x1400539F0,
                 gtread=0x14001ED00, gtwrite=0x14001ED10,
                 handlers={
                     0x1400555A0: 'ReadPESectionField',
                     0x140055650: 'ReadPESectionFieldByte',
                     0x140056540: 'DecodeOpcodeReadByte',
                     0x140056590: 'DecodeReadWordImmediate',
                     0x1400565E0: 'DecodeReadSizeDepImm',
                     0x1400566A0: 'DecodeReadImmediateValue',
                 }),
}


def run(cfg, label, img):
    sim = KernelSim(cfg['drv'])
    sim.skip_stack_cookie_check()

    def gt_read(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        s.gt_reads.append((idx, s._gt_values.get(idx, 0)))
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(idx, 0) & MASK64)
        s._do_ret(uc)

    def gt_write(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        val = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s.gt_writes.append((idx, val))
        s._gt_values[idx] = val
        uc.reg_write(UC_X86_REG_RAX, val & MASK64)
        s._do_ret(uc)

    sim.intercept(cfg['gtread'], gt_read)
    sim.intercept(cfg['gtwrite'], gt_write)

    base = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(base, img)
    for gt, v in ((0x20, base), (0x21, len(img)), (0x41D1, 0x1B9600),
                  (0x41D4, 0x1B90E0), (0x914, 19045)):
        sim.set_gt(gt, v)

    state = {'pending': None, 'rows': [], 'calls': []}

    hset = set(cfg['handlers'].keys())

    def watch(uc, address, size, s):
        rip = address
        if rip in hset:
            state['calls'].append(cfg['handlers'][rip])
            return
        p = state['pending']
        if rip == cfg['readpese']:
            desc = uc.reg_read(UC_X86_REG_RDX)
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
            state['pending'] = {'desc': desc, 'ret': ret}
        elif p and rip == p['ret']:
            d = bytes(uc.mem_read(p['desc'], 0x120))
            ent70 = struct.unpack_from('<I', d, 0x70)[0]
            typp = struct.unpack_from('<Q', d, 0x118)[0]
            typ = struct.unpack_from('<H', uc.mem_read(typp + 6, 2), 0)[0] if typp else 0
            f88 = struct.unpack_from('<Q', d, 0x88)[0]
            f74 = struct.unpack_from('<I', d, 0x74)[0]
            f0f0 = struct.unpack_from('<I', d, 0xF0)[0]
            addr_size = struct.unpack_from('<I', d, 0x08)[0]
            op_size = struct.unpack_from('<I', d, 0x24)[0]
            st_flags = struct.unpack_from('<I', d, 0x28)[0]
            st00 = struct.unpack_from('<I', d, 0x00)[0]
            state['rows'].append((ent70, typ, f88, f74, f0f0, typp,
                                  addr_size, op_size, st_flags, st00))
            state['pending'] = None

    sim.uc.hook_add(8, watch)   # UC_HOOK_BLOCK = 8
    for gt, tag in ((0x41D1, '0x41D1'), (0x41D4, '0x41D4')):
        state['rows'].clear()
        state['pending'] = None
        state['calls'].clear()
        kind, r = sim.call(cfg['fkpsbt'], (gt,), count=8000000)
        print('%s %s -> %s %s' % (label, tag, kind, hex(r) if isinstance(r, int) else r))
        for i, row in enumerate(state['rows']):
            e70, typ, f88, f74, f0f0, typp, asz, osz, sf, st = row
            print('   it%02d ent70=0x%-6X type=%-6d f88=0x%-10X f0f0=%-3d asz=%-3d osz=%-3d sf=0x%-4X st=0x%X'
                  % (i, e70, typ, f88, f0f0, asz, osz, sf, st))
        print('   handler seq:', state['calls'])
        if sim.notes:
            print('   notes:', sim.notes[:3])


def main():
    img, sz, _ = image_layout(NT)
    print('buf size 0x%X' % len(img))
    for label in ('ORIG', 'MINE'):
        run(CFG[label], label, img)


if __name__ == '__main__':
    main()