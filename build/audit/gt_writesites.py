#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""静态扫描原始驱动：找出「mov ecx, <slot> ; ... ; call GtWrite」的写入点。

GtWrite = 0x140029FF4, GtRead = 0x140029EFC
用法: python gt_writesites.py [slot_hex ...]
"""
import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HERE = os.path.dirname(os.path.abspath(__file__))
ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
BASE = 0x140000000
GTWRITE = 0x140029FF4
GTREAD = 0x140029EFC


def load_text():
    d = open(ORIG, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    sec = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
    for i in range(n):
        o = sec + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
        if nm == '.text':
            return d[ra:ra + rsz], BASE + va
    raise SystemExit('no .text')


def main():
    targets = None
    if len(sys.argv) > 1:
        targets = {int(a, 16) for a in sys.argv[1:]}
    text, tva = load_text()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    insns = list(md.disasm(text, tva))

    funcs = json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))
    fmap = sorted((f['start'], f['end'], f['name']) for f in funcs)

    def owner(addr):
        lo, hi = 0, len(fmap) - 1
        best = None
        for s, e, nm in fmap:
            if s <= addr < e:
                return nm
        return '?'

    out = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'mov' or not ins.op_str.startswith('ecx, '):
            continue
        try:
            slot = int(ins.op_str.split(', ')[1], 0)
        except ValueError:
            continue
        if targets is not None and slot not in targets:
            continue
        # 往后 6 条内找 call GtWrite / GtRead
        for j in range(i + 1, min(i + 7, len(insns))):
            p = insns[j]
            if p.mnemonic == 'call':
                tgt = int(p.op_str, 16) if p.op_str.startswith('0x') else None
                if tgt == GTWRITE:
                    out.setdefault(slot, []).append(('W', ins.address, owner(ins.address)))
                    break
                if tgt == GTREAD:
                    out.setdefault(slot, []).append(('R', ins.address, owner(ins.address)))
                    break
                break
            if p.mnemonic in ('ret', 'jmp'):
                break
    for slot in sorted(out):
        print('GT[0x%X]:' % slot)
        for kind, addr, nm in out[slot]:
            print('   %s 0x%X  %s' % (kind, addr, nm))


if __name__ == '__main__':
    main()
