#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GenerateEncryptionKey 离线差分（原始 0x140081314 vs 我方）。
入参为 L"View++ByLinxer"（DriverEntry 实际传入的 RegistryPath）。"""
import os, sys, struct, re
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
MP = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')


def sym(n, default=None):
    for ln in open(MP, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s+0001:[0-9a-f]{8}\s+' + n + r'\s+([0-9a-f]{16})\s+f', ln)
        if m:
            return int(m.group(1), 16)
    return default


def run(drv, fn, rd, wr, s):
    sim = KernelSim(drv); sim.skip_stack_cookie_check(); w = []

    def gr(uc, st):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, st._gt_values.get(i, 0) & MASK64); st._do_ret(uc)

    def gw(uc, st):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        v = uc.reg_read(UC_X86_REG_RDX) & MASK64
        st._gt_values[i] = v; w.append((i, v)); uc.reg_write(UC_X86_REG_RAX, v); st._do_ret(uc)

    sim.intercept(rd, gr); sim.intercept(wr, gw)
    # 字符串长度用真实实现
    buf = sim.scratch(0x200)
    sim.uc.mem_write(buf, s.encode('utf-16-le') + b'\x00\x00')
    k = sim.call(fn, (buf,), count=50000000)
    return k, w


tgt = L = 'View++ByLinxer'
ko, wo = run(ORIG, 0x140081314, 0x140029EFC, 0x140029FF4, L)
km, wm = run(MINE, sym('GenerateEncryptionKey'), sym('GtRead'), sym('GtWrite'), L)
print('ORIG', ko, [(hex(i), hex(v)) for i, v in wo])
print('MINE', km, [(hex(i), hex(v)) for i, v in wm])
print('=>', 'IDENTICAL' if {(i, v) for i, v in wo} == {(i, v) for i, v in wm} else 'DIFFERENT')
print('期望 GT[0x1E0]=0x5e00158  GT[0x1E1]=0xcf')