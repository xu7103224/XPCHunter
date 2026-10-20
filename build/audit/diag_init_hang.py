#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线诊断：InitCallbackFunctions 是否会终止。

实机现象：发任何非 0x22 命令后 guest 硬挂起（不是蓝屏，kd 也连不上），
定位到 DispatchDeviceControl 里唯一会做重量级工作的调用就是
InitCallbackFunctions()。它内部调 InitProcessNotify / InitThreadNotify /
InitCallbackFunctionTable(0|1|2)。

本脚本在模拟器里直接调用它，带指令上限，用来判断是否死循环。
"""
import os, sys, struct, re
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX

MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
MAP = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')


def sym(n, default=None):
    for ln in open(MAP, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s+000[123]:[0-9a-f]{8}\s+' + n + r'\s+([0-9a-f]{16})\s+\S+', ln)
        if m:
            return int(m.group(1), 16)
    return default


def run(name, count=50_000_000):
    fn = sym(name)
    if not fn:
        print('%-32s 符号缺失' % name)
        return
    sim = KernelSim(MINE)
    sim.skip_stack_cookie_check()
    reads, writes = [], []

    def gr(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        reads.append(i)
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(i, 0) & MASK64)
        s._do_ret(uc)

    def gw(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        v = uc.reg_read(UC_X86_REG_RDX) & MASK64
        writes.append((i, v))
        s._gt_values[i] = v
        uc.reg_write(UC_X86_REG_RAX, v)
        s._do_ret(uc)

    sim.intercept(sym('GtRead'), gr)
    sim.intercept(sym('GtWrite'), gw)

    # 用实机 GT 基线填充，尽量贴近真实运行状态
    base = os.path.join(HERE, 'gt_orig_samesession.bin')
    if os.path.exists(base):
        d = open(base, 'rb').read()
        for i in range(len(d) // 8):
            v = struct.unpack_from('<Q', d, i * 8)[0]
            if v:
                sim.set_gt(i, v)

    kind, ret = sim.call(fn, (), count=count)
    n_reads = len(reads)
    n_writes = len(writes)
    if isinstance(ret, tuple):
        kind, val = ret
    else:
        kind, val = 'OK', ret
    status = 'TERMINATED' if kind == 'OK' else 'DID-NOT-TERMINATE(%s)' % val
    shown = (val & 0xFFFFFFFF) if isinstance(val, int) else 0
    print('%-32s %-24s ret=0x%X  gt_reads=%d gt_writes=%d'
          % (name, status, shown, n_reads, n_writes))
    if kind != 'OK':
        print('    !! 指令上限 %d 内未返回' % count)
        print('    最后 12 个 GT 读:', [hex(x) for x in reads[-12:]])
        print('    最后 8 个 GT 写:', [(hex(a), hex(b)) for a, b in writes[-8:]])
    return kind


if __name__ == '__main__':
    print('=== 逐个测试初始化函数是否终止 ===\n')
    for n in ('InitCallbackFunctions', 'InitProcessNotify', 'InitThreadNotify',
              'InitCallbackFunctionTable'):
        run(n)
        print()