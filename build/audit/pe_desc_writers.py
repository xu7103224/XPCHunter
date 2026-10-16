# -*- coding: utf-8 -*-
"""
在模拟内核里执行**原始驱动**的 ReadPESectionEntry，对描述符缓冲区挂
内存写钩子，记录「哪个 RIP 写了哪个偏移、写了多少字节、值是多少」。

用途：定位描述符各字段的真正写入者（静态扫描猜不到时用动态证据）。
"""
import csv
import json
import sys

sys.path.insert(0, r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts')
from wdrvemu import parse_file, DriverEmulator   # noqa: E402
import unicorn                                   # noqa: E402
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_RIP, UC_X86_REG_RSP)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
INP = 'build/audit/_pe_input.bin'
TABLE = 0x140097E50
COOKIE = 0x14008C8B0
READ = 0x14008A54C
M52 = (1 << 52) - 1

SYMS = {}
for f in json.load(open('build/audit/_orig_funcs_ida.json')):
    SYMS[f['start']] = f['name']
STARTS = sorted(SYMS)


def fname(va):
    import bisect
    i = bisect.bisect_right(STARTS, va) - 1
    return SYMS[STARTS[i]] if i >= 0 else '?'


def main():
    img = parse_file(ORIG)
    emu = DriverEmulator()
    emu.setup_kernel()
    lr = emu.load_image(img)
    uc = emu.uc
    delta = lr.base - img.image_base
    G = lambda x: (x + delta) & M52

    BUF = 0xfffffa0020000000
    CTX = 0xfffffa0020008000
    DESC = 0xfffffa0020009000
    SB = 0xfffffa0000000000
    data = open(INP, 'rb').read()
    emu.memory.map(BUF, 0x4000, 'in', 'data', unicorn.UC_PROT_ALL)
    emu.memory.write(BUF, data)
    emu.memory.map(CTX, 0x1000, 'ctx', 'data', unicorn.UC_PROT_ALL)
    emu.memory.map(DESC, 0x1000, 'desc', 'data', unicorn.UC_PROT_ALL)
    try:
        emu.memory.map(SB, 0x20000, 'stk', 'stack', unicorn.UC_PROT_ALL)
    except Exception:
        pass
    rsp = SB + 0x10000
    SENT = SB + 0x1000
    emu.memory.write(SENT, b'\xf4')

    def wr64(a, v):
        emu.memory.write(a, (v & M52).to_bytes(8, 'little'))

    wr64(CTX + 0x00, G(TABLE))
    wr64(CTX + 0x08, BUF)
    wr64(CTX + 0x10, BUF + len(data))
    for off, val in ((0x18, 2), (0x1C, 2), (0x20, 1)):
        emu.memory.write(CTX + off, val.to_bytes(4, 'little'))
    wr64(CTX + 0x28, 0)
    wr64(CTX + 0x30, 0)
    wr64(CTX + 0x38, 0)
    emu.memory.write(CTX + 0x40, (0xFFFFFFFF).to_bytes(4, 'little'))

    writes = []

    def on_code(u, address, size, ud):
        if (address & M52) == G(COOKIE):
            r = u.reg_read(UC_X86_REG_RSP)
            tgt = int.from_bytes(u.mem_read(r, 8), 'little')
            u.reg_write(UC_X86_REG_RSP, r + 8)
            u.reg_write(UC_X86_REG_RIP, tgt)

    def on_mem_w(u, access, address, size, value, ud):
        a = address & M52
        # 只记录对描述符缓冲区的写入
        base = DESC & M52
        if base <= a < base + 0x120:
            writes.append((a - base, size, value & ((1 << (8 * size)) - 1),
                           u.reg_read(UC_X86_REG_RIP), fname((u.reg_read(UC_X86_REG_RIP) - delta) & M52)))

    uc.hook_add(unicorn.UC_HOOK_CODE, on_code)
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_mem_w)

    # 挂 stub：ReadPESectionEntry 内部的 memset 等自有实现，无需额外处理
    emu.memory.write(DESC, b'\x00' * 0x200)
    emu.memory.write(rsp, SENT.to_bytes(8, 'little'))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX, CTX)
    uc.reg_write(UC_X86_REG_RDX, DESC)
    try:
        uc.emu_start(G(READ), SENT & M52, count=400000)
        ret = uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        print('ret = 0x%x' % ret)
    except Exception as e:
        print('EXC:', str(e)[:120])

    print('描述符写入序列（偏移, 字节数, 值, 写入者）:')
    for off, size, val, rip, nm in writes:
        print('  +0x%03X  %dB  0x%-12X  %s (0x%x)' % (off, size, val, nm, rip & M52))
    print('共 %d 次写入' % len(writes))


if __name__ == '__main__':
    main()
