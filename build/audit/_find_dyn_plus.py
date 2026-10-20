#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""找出原始驱动中所有 GtWrite 调用点，其中索引来自 `lea ecx,[reg+imm]` 的，
打印 imm。用于定位 GT[0x4474]/[0x4475] 这类动态索引写入者。"""
import struct, capstone

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


def off_of(va):
    for nm, sva, vsz, ra, rsz in sections:
        if sva <= (va - IB) < sva + rsz:
            return ra + (va - IB - sva)
    return None


# 1) 找所有 call GtWrite
calls = []
for nm, va, vsz, ra, rsz in sections:
    if nm != '.text':
        continue
    code = d[ra:ra + rsz]
    i = 0
    while i < len(code) - 5:
        if code[i] == 0xE8:
            rel = struct.unpack_from('<i', code, i + 1)[0]
            if IB + va + i + 5 + rel == GtWrite_VA:
                calls.append(IB + va + i)
        i += 1

md = capstoneervr = None
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# 2) 对每个调用点，回溯最多 6 条指令找 ecx 的定义
def back_disasm(va, n=6):
    o = off_of(va - 0x30)
    if o is None:
        return []
    buf = d[o:o + 0x30]
    out = []
    for ins in md.disasm(buf, va - 0x30):
        out.append(ins)
    return out


hits = []
for cs in calls:
    ins_list = back_disasm(cs)
    tail = [x for x in ins_list if x.address < cs][-6:]
    for ins in reversed(tail):
        if ins.mnemonic in ('mov', 'lea') and ',' in ins.op_str:
            parts = ins.op_str.split(',')
            if parts[0].strip() == 'ecx':
                if '+ 1' in ins.op_str or '+1' in ins.op_str:
                    hits.append((cs, ins.address, ins.mnemonic, ins.op_str))
                elif '+ 2' in ins.op_str or '+2' in ins.op_str:
                    hits.append((cs, ins.address, ins.mnemonic, ins.op_str))
                break

print('GtWrite 调用点:', len(calls))
print('索引为 [reg+1]/[reg+2] 的调用点:', len(hits))
for cs, ia, mn, op in hits:
    print('  call@0x%X  %s %s  (@0x%X)' % (cs, mn, op, ia))