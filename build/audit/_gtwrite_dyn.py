#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描原始驱动：找出所有 GtWrite 调用点，标记索引是「立即数」还是「动态寄存器」。
动态索引的调用点是 0x4474/0x4475 这类静态扫描找不到的写入者的候选。"""
import struct, capstone, sys, os, re

ORIG = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys'
GtWrite_VA = 0x140029FF4
IB = 0x140000000

d = open(ORIG, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
sec = pe + 24 + opt
sections = []
for i in range(nsec):
    o = sec + i * 40
    nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    sections.append((nm, va, vsz, ra, rsz))

# 建函数边界（从 map 或 IDA 导出）。这里先粗扫：找 call rel32 目标==GtWrite
res = []
for nm, va, vsz, ra, rsz in sections:
    if nm != '.text':
        continue
    code = d[ra:ra + rsz]
    base = IB + va
    i = 0
    # 线性解码找 E8 rel32
    while i < len(code) - 5:
        if code[i] == 0xE8:
            rel = struct.unpack_from('<i', code, i + 1)[0]
            tgt = base + i + 5 + rel
            if tgt == GtWrite_VA:
                res.append(base + i)
        i += 1
print('GtWrite 调用点总数:', len(res))
print([hex(x) for x in res[:10]], '...')

# 对每个调用点回看 40 字节，判断 ecx 是否来自立即数
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
dyn = []
for callsite in res:
    va = callsite - 0x40
    off = None
    for nm, sva, vsz, ra, rsz in sections:
        if sva <= (va - IB) < sva + rsz:
            off = ra + (va - IB - sva)
            break
    if off is None:
        continue
    buf = d[off:off + 0x40]
    idx_imm = None
    for ins in md.disasm(buf, va):
        if ins.mnemonic == 'mov' and len(ins.operands) == 2:
            op0, op1 = ins.operands
            if op0.type == capstone.x86.X86_OP_REG and ins.reg_name(op0.reg) == 'ecx':
                if op1.type == capstone.x86.X86_OP_IMM:
                    idx_imm = op1.imm
                else:
                    idx_imm = None
        if ins.address == callsite:
            break
    if idx_imm is None:
        dyn.append(callsite)
print('动态索引 GtWrite 调用点:', len(dyn))
for x in dyn:
    print('   ', hex(x))