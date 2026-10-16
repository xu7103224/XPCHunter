# -*- coding: utf-8 -*-
"""定位我方 ReadPESectionEntry 在描述符差分中的越界读（打印 RIP / 访问地址 / 调用栈）。"""
import json
import sys

sys.path.insert(0, r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts')
from wdrvemu import parse_file, DriverEmulator
import unicorn
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RBP)

REB = 'build/bin/Release/x64/XPCHunterDrv.sys'
INP = 'build/audit/_pe_input.bin'
SYM = json.load(open('build/audit/_sym_addr.json', encoding='utf-8'))
M52 = (1 << 52) - 1

img = parse_file(REB)
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
emu.memory.map(BUF, 0x4000, 'pe_input', 'data', unicorn.UC_PROT_ALL)
emu.memory.write(BUF, data)
emu.memory.map(CTX, 0x1000, 'ctx', 'data', unicorn.UC_PROT_ALL)
emu.memory.map(DESC, 0x1000, 'desc', 'data', unicorn.UC_PROT_ALL)
try:
    emu.memory.map(SB, 0x20000, 'stack', 'stack', unicorn.UC_PROT_ALL)
except Exception:
    pass
rsp = SB + 0x10000
SENT = SB + 0x1000
emu.memory.write(SENT, b'\xf4')


def wr64(a, v):
    emu.memory.write(a, (v & M52).to_bytes(8, 'little'))


TABLE = int(SYM['g_PeDecodeTableRegion'], 16) + 0x1420
wr64(CTX + 0x00, G(TABLE))
wr64(CTX + 0x08, BUF)
wr64(CTX + 0x10, BUF + len(data))
emu.memory.write(CTX + 0x18, (2).to_bytes(4, 'little'))
emu.memory.write(CTX + 0x1C, (2).to_bytes(4, 'little'))
emu.memory.write(CTX + 0x20, (1).to_bytes(4, 'little'))
wr64(CTX + 0x28, 0)
wr64(CTX + 0x30, 0)
wr64(CTX + 0x38, 0)
emu.memory.write(CTX + 0x40, (0xFFFFFFFF).to_bytes(4, 'little'))

COOKIE = G(int(SYM['__security_check_cookie'], 16))
READ = G(int(SYM['ReadPESectionEntry'], 16))
print('load base=%#x delta=%#x ReadPESectionEntry=%#x table=%#x' % (lr.base, delta, READ, G(TABLE)))

trace = []


def on_code(u, address, size, ud):
    a = address & M52
    trace.append(a)
    if a == COOKIE:
        r = u.reg_read(UC_X86_REG_RSP)
        print('[cookie] rsp=%#x' % r)
        try:
            tgt = int.from_bytes(u.mem_read(r & M52, 8), 'little')
        except Exception as e:
            print('[cookie] 读返回地址失败: %s' % e)
            raise
        u.reg_write(UC_X86_REG_RSP, (r + 8) & M52)
        u.reg_write(UC_X86_REG_RIP, tgt)


def on_fault(u, access, address, size, value, ud):
    print('\n[FAULT] access=%d addr=%#x size=%d rip=%#x' % (access, address, size, u.reg_read(UC_X86_REG_RIP)))
    rax, rcx, rdx, rsp, rbp = (u.reg_read(r) for r in
                               (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_RBP))
    print('  rax=%#x rcx=%#x rdx=%#x rsp=%#x rbp=%#x' % (rax, rcx, rdx, rsp, rbp))
    print('  最近 25 条 RIP:')
    for a in trace[-25:]:
        print('    %#x' % a)
    return False


uc.hook_add(unicorn.UC_HOOK_CODE, on_code)
uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED
            | unicorn.UC_HOOK_MEM_FETCH_UNMAPPED | unicorn.UC_HOOK_MEM_FETCH_PROT, on_fault)

for it in range(6):
    trace.clear()
    emu.memory.write(DESC, b'\x00' * 0x200)
    emu.memory.write(rsp, SENT.to_bytes(8, 'little'))
    uc.reg_write(UC_X86_REG_RSP, rsp & M52)
    uc.reg_write(UC_X86_REG_RCX, CTX)
    uc.reg_write(UC_X86_REG_RDX, DESC)
    try:
        uc.emu_start(READ, SENT & M52, count=200000)
        rax = uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        cons = int.from_bytes(emu.memory.read(DESC + 0xF0, 4), 'little')
        print('#%d 正常 ret=%#x cons=%d 指令数=%d' % (it, rax, cons, len(trace)))
        rp = int.from_bytes(emu.memory.read(CTX + 8, 8), 'little')
        wr64(CTX + 8, rp + cons)
        if rax:
            break
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('#%d 异常: %s  指令数=%d' % (it, e, len(trace)))
        from unicorn.x86_const import (UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RDI,
                                       UC_X86_REG_RSI, UC_X86_REG_RBX, UC_X86_REG_R12)
        for nm, r in (('rax', UC_X86_REG_RAX), ('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
                      ('rbx', UC_X86_REG_RBX), ('rsi', UC_X86_REG_RSI), ('rdi', UC_X86_REG_RDI),
                      ('r8', UC_X86_REG_R8), ('r9', UC_X86_REG_R9), ('r12', UC_X86_REG_R12),
                      ('rsp', UC_X86_REG_RSP), ('rbp', UC_X86_REG_RBP)):
            print('   %s=%#x' % (nm, uc.reg_read(r)))
        print('  最近 30 条 RIP:')
        for a in trace[-30:]:
            print('    %#x' % a)
        break
