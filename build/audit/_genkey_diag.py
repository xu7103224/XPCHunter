#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断 ORIG GenerateEncryptionKey 在模拟器里为什么 ERR。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')

sim = KernelSim(ORIG, verbose=True)
sim.skip_stack_cookie_check()
w = []


def gr(uc, st):
    i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX, st._gt_values.get(i, 0) & MASK64); st._do_ret(uc)


def gw(uc, st):
    i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
    v = uc.reg_read(UC_X86_REG_RDX) & MASK64
    st._gt_values[i] = v; w.append((i, v)); uc.reg_write(UC_X86_REG_RAX, v); st._do_ret(uc)


sim.intercept(0x140029EFC, gr)
sim.intercept(0x140029FF4, gw)
buf = sim.scratch(0x200)
sim.uc.mem_write(buf, 'View++ByLinxer'.encode('utf-16-le') + b'\x00\x00')
print('buf =', hex(buf))
k = sim.call(0x140081314, (buf,), count=5000000)
print('result', k, 'writes', [(hex(i), hex(v)) for i, v in w])