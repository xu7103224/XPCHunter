#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从原始驱动提取 InitCommandHandlerTable 写入的命令表条目。

原始函数在 0x1400815B0 附近：分配 0x8D8 字节，逐条 `lea rdx,[rip+X]` /
`mov [rbx+i*8], rax` 填充。用 capstone 线性解码，识别
    mov qword ptr [rbx + N*8], rax
并把值追溯到最近的 lea rax,[rip+...] 目标。

输出：idx -> 原始函数 VA
"""
import struct, capstone, json, os, sys

ORIG = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys'
IB = 0x140000000
HERE = os.path.dirname(os.path.abspath(__file__))

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


def read_va(va, n):
    for nm, sva, vsz, ra, rsz in secs:
        if sva <= va - IB < sva + rsz:
            off = ra + (va - IB - sva)
            return d[off:off + n]
    return None


# InitCommandHandlerTable 的真实入口：先按 IDA 名字找，找不到就用 0x1400815B0
START = 0x1400815B0
SIZE = 0x1200

code = read_va(START, SIZE)
if code is None:
    print('读不到代码'); sys.exit(1)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

table = {}
last_lea = {}          # reg -> 目标 VA
for ins in md.disasm(code, START):
    # 记录 lea reg, [rip+X]
    if ins.mnemonic == 'lea' and len(ins.operands) == 2:
        dst, src = ins.operands
        if src.type == capstone.x86.X86_OP_MEM and src.mem.base == capstone.x86.X86_REG_RIP:
            tgt = ins.address + ins.size + src.mem.disp
            last_lea[ins.reg_name(dst.reg)] = tgt
    # mov [base + disp], reg  → 若 base 是表指针寄存器（rbx/r12/r13/r14/r15/rdi/rsi），记录
    if ins.mnemonic == 'mov' and len(ins.operands) == 2:
        dst, src = ins.operands
        if dst.type == capstone.x86.X86_OP_MEM and src.type == capstone.x86.X86_OP_REG:
            disp = dst.mem.disp
            if disp >= 0 and disp < 0x8D8 and disp % 8 == 0:
                sname = ins.reg_name(src.reg)
                if sname in last_lea:
                    table[disp // 8] = last_lea[sname]

print('从 0x%X 起解析，提取到 %d 条表项' % (START, len(table)))
names = {x['start']: x['name'] for x in
         json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))}
out = {}
for idx in sorted(table):
    va = table[idx]
    out[idx] = va
    print('  [%3d] 0x%X  %s' % (idx, va, names.get(va, '(导出/未命名)')))
json.dump({str(k): v for k, v in out.items()},
          open(os.path.join(HERE, '_orig_cmdtable.json'), 'w', encoding='utf-8'),
          indent=1)
print('已写 _orig_cmdtable.json')