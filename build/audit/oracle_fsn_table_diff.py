#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全 .rdata 扫描差分：对原始与我方的 FindSyscallNumbers 做**端到端**对比。

价值：这是不依赖 VM 的最强验证 —— 只要两者产出的 syscall 表内容（每个
系统调用号 → 函数地址）逐项相同，就证明整条解码链在当前真实 ntoskrnl 上等价。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim, MASK64  # noqa: E402
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from pe_image_layout import image_layout  # noqa: E402
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX  # noqa

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')

def _sym(name):
    import re as _re
    mp = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')
    for ln in open(mp, encoding='utf-8', errors='ignore'):
        m = _re.match(r'\s+0001:[0-9a-f]{8}\s+' + name + r'\s+([0-9a-f]{16})\s+f', ln)
        if m:
            return int(m.group(1), 16)
    return 0

def _find_import_thunk(fn):
    """在函数体内找第一个「单条 jmp [rip+x]」的导入 thunk 调用目标。"""
    import struct as _st
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    d = open(MINE, 'rb').read()
    pe = _st.unpack_from('<I', d, 0x3c)[0]
    n = _st.unpack_from('<H', d, pe + 6)[0]
    sc = pe + 24 + _st.unpack_from('<H', d, pe + 20)[0]
    text = None
    for i in range(n):
        o = sc + i * 40
        nm = d[o:o+8].rstrip(b'').decode('latin1')
        vsz, va, rsz, ra = _st.unpack_from('<IIII', d, o + 8)
        if nm == '.text':
            text = (d[ra:ra+rsz], 0x140000000 + va)
    if not text:
        return 0
    tb, tv = text
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(tb[fn-tv:fn-tv+0x400], fn):
        if ins.mnemonic != 'call':
            continue
        try:
            t = int(ins.op_str, 16)
        except ValueError:
            continue
        # thunk 特征：目标处是 jmp qword ptr [rip + x]
        to = t - tv
        if to < 0 or to + 6 > len(tb):
            continue
        for ins2 in md.disasm(tb[to:to+8], t):
            if ins2.mnemonic == 'jmp' and 'rip' in ins2.op_str:
                return t
            break
    return 0


CFG = {
    'ORIG': dict(drv=ORIG, fsn=0x140052FDC, gtread=0x140029EFC, gtwrite=0x140029FF4,
                 exalloc=0x140077A00),
    'MINE': dict(drv=MINE, fsn=_sym('FindSyscallNumbers'), gtread=_sym('GtRead'),
                 gtwrite=_sym('GtWrite'), exalloc=0),
}
SERVICE_COUNT = 0x1D0


def run(cfg, img):
    sim = KernelSim(cfg['drv'])
    sim.skip_stack_cookie_check()

    def gt_read(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(idx, 0) & MASK64)
        s._do_ret(uc)

    def gt_write(uc, s):
        idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        val = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s._gt_values[idx] = val
        uc.reg_write(UC_X86_REG_RAX, val & MASK64)
        s._do_ret(uc)

    def exalloc(uc, s):
        uc.reg_write(UC_X86_REG_RAX, s._pool)
        s._do_ret(uc)

    sim.intercept(cfg['gtread'], gt_read)
    sim.intercept(cfg['gtwrite'], gt_write)

    base = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(base, img)
    sim._pool = sim.scratch(0x10000)
    # 通过 import 名拦截分配（比硬编码 thunk 地址可靠：LTCG 每次编译都会移位）
    for _nm in ('ExAllocatePoolWithTag', 'ExAllocatePool', 'ExAllocatePool2'):
        sim.api_returns[_nm] = (lambda sm: sm._pool)
    for gt, v in ((0x20, base), (0x21, len(img)), (0x42, SERVICE_COUNT),
                  (0x41D1, 0x1B9600), (0x41D4, 0x1B90E0), (0x914, 19045)):
        sim.set_gt(gt, v)

    kind, r = sim.call(cfg['fsn'], (), count=30000000)
    tbl = sim._gt_values.get(0x62, 0)
    if not tbl:
        return None
    return [struct.unpack('<Q', bytes(sim.uc.mem_read(sim._pool + 8 * i, 8)))[0]
            for i in range(SERVICE_COUNT)]


def main():
    img, sz, _ = image_layout(NT)
    a = run(CFG['ORIG'], img)
    b = run(CFG['MINE'], img)
    if a is None or b is None:
        print('ORIG table=%s MINE table=%s' % ('ok' if a else 'NULL', 'ok' if b else 'NULL'))
        return
    diff = [i for i in range(SERVICE_COUNT) if a[i] != b[i]]
    print('服务表条目: %d' % SERVICE_COUNT)
    print('逐项不同: %d' % len(diff))
    for i in diff[:10]:
        print('  [%d] orig=0x%X mine=0x%X' % (i, a[i], b[i]))
    print('结论:', 'IDENTICAL' if not diff else 'DIFFERENT')


if __name__ == '__main__':
    main()