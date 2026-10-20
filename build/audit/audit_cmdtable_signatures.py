#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核对命令表（GT[0x921+i]）里每个处理函数的**参数使用位置**，
找出与命令分派约定不符的实现。

命令分派的实际调用约定（原始 DispatchDeviceControl 0x1400825AB..5BA）：
    rcx = ContextPointer   (req+0x10)
    rdx = OutputSize       (req+0x20)
    r8  = ExtraPointer     (req+0x18)
    r9d = ContextSize      (req+0x24)

所以处理函数的标准签名是
    (ContextPointer, OutputSize, OutputBuffer, OutputSize2)

但原始驱动里各函数的**实际用法并不统一**：有的把 rcx 当输入缓冲、
把 r8 当输出缓冲（如 MiniFilterCommPortReply：`mov rdi,r8`），
有的把 rcx 当输出缓冲（`mov rdi,rcx`）。

本工具从原始驱动的真实代码里提取「函数入口后 0x40 字节内对
rcx/rdx/r8/r9 的首次用法」，给出每个函数的参数角色建议。

用法: python audit_cmdtable_signatures.py
"""
import os, sys, struct, json
import capstone

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
HERE = os.path.join(ROOT, 'build', 'audit')
ORIG = os.path.join(ROOT, 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
IB = 0x140000000

d = open(ORIG, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
sec = pe + 24 + opt
secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    secs.append((nm, va, vsz, ra, rsz))


def va2off(va):
    for nm, sva, vsz, ra, rsz in secs:
        if sva <= va - IB < sva + rsz:
            return ra + (va - IB - sva)
    return None


tbl = json.load(open(os.path.join(HERE, '_orig_cmdtable.json'), encoding='utf-8'))
names = {x['start']: x['name'] for x in
         json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))}

REGALIAS = {'ecx': 'rcx', 'ecx_': 'rcx', 'edx': 'rdx', 'r8d': 'r8', 'r9d': 'r9',
            'cl': 'rcx', 'dl': 'rdx', 'r8b': 'r8', 'r9b': 'r9'}


def roles(va):
    """返回 {argreg: 首个用法描述}"""
    off = va2off(va)
    if off is None:
        return {}
    code = d[off:off + 0x60]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    seen = {}
    for ins in md.disasm(code, va):
        if len(ins.operands) != 2:
            continue
        dst, src = ins.operands[0], ins.operands[1]
        # mov rXX, reg   → 参数被搬走
        if ins.mnemonic in ('mov', 'lea') and dst.type == capstone.x86.X86_OP_REG \
                and src.type == capstone.x86.X86_OP_REG:
            s = ins.reg_name(src.reg)
            if s in ('rcx', 'rdx', 'r8', 'r9') and s not in seen:
                seen[s] = '%s %s,%s' % (ins.mnemonic, ins.reg_name(dst.reg), s)
        # 直接使用
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_REG:
                rn = ins.reg_name(op.reg)
                rn = REGALIAS.get(rn, rn)
                if rn in ('rcx', 'rdx', 'r8', 'r9') and rn not in seen:
                    seen[rn] = '%s %s' % (ins.mnemonic, ins.op_str)
    return seen


rows = []
for k in sorted(tbl, key=lambda x: int(x)):
    idx = int(k)
    va = tbl[k]
    nm = names.get(va, '?')
    r = roles(va)
    sig = 'rcx=%s | rdx=%s | r8=%s | r9=%s' % (
        r.get('rcx', '-'), r.get('rdx', '-'), r.get('r8', '-'), r.get('r9', '-'))
    rows.append((idx, va, nm, sig))

print('命令表 %d 项，逐项参数用法（函数入口 0x60 字节内首次用法）：' % len(rows))
print()
for idx, va, nm, sig in rows:
    print('[%3d] cmd=0x%02X %-40s 0x%X' % (idx, 0x20 + idx, nm, va))
    print('     ', sig)