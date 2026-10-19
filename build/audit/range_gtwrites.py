#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""列出某地址区间内 (mov ecx,imm ; [mov edx,...] ; call GtWrite/GtRead) 的槽号序列。

用法: python range_gtwrites.py <start_hex> <end_hex>
"""
import os, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
HERE = os.path.dirname(os.path.abspath(__file__))
ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
BASE = 0x140000000
GW, GR = 0x140029FF4, 0x140029EFC

def load_text():
    d = open(ORIG, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    sec = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
    for i in range(n):
        o = sec + i * 40
        nm = d[o:o+8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
        if nm == '.text':
            return d[ra:ra+rsz], BASE + va
    raise SystemExit('no .text')

start = int(sys.argv[1], 16); end = int(sys.argv[2], 16)
text, tva = load_text()
md = Cs(CS_ARCH_X86, CS_MODE_64)
insns = list(md.disasm(text[start-tva:end-tva], start))
for i, ins in enumerate(insns):
    if ins.mnemonic == 'mov' and ins.op_str.startswith('ecx, '):
        try: slot = int(ins.op_str.split(', ')[1], 0)
        except ValueError: continue
        for j in range(i+1, min(i+6, len(insns))):
            p = insns[j]
            if p.mnemonic == 'call':
                t = int(p.op_str, 16) if p.op_str.startswith('0x') else 0
                if t == GW: print('%08X  W GT[0x%X]' % (ins.address, slot)); break
                if t == GR: print('%08X  R GT[0x%X]' % (ins.address, slot)); break
                break
            if p.mnemonic in ('ret','jmp','call'): break
