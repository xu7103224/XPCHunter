#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把原始函数里的 [rbp±X]/[rsp+X] 内存读换算成「描述符相对偏移」。

原理：调用 ReadPESectionEntry 前必有
    lea rdx, [rbp-0x70]     ← 描述符 SectionInfo（第 2 参）
    lea rcx, [rsp+0x40]     ← 上下文数组（第 1 参）
    call ReadPESectionEntry
据此确定描述符基址，再把函数体内所有 [rbp±X]/[rsp+X] 读映射为描述符偏移。

用法: python desc_offsets.py <func_addr_hex> <size_hex>
"""
import re
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
BASE = 0x140000000
READPESE = 0x14008A54C


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


MEM = re.compile(r'\[(rbp|rsp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]')


def main():
    start = int(sys.argv[1], 16)
    size = int(sys.argv[2], 16)
    text, tva = load_text()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(text[start - tva:start - tva + size], start))

    # 1) 找 ReadPESectionEntry 之前的 lea rdx,[...]
    desc_reg = None
    desc_off = None
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'call' and ('0x%x' % READPESE) in (ins.op_str or ''):
            for j in range(i - 1, max(-1, i - 4), -1):
                p = insns[j]
                if p.mnemonic == 'lea' and p.op_str.startswith('rdx,'):
                    m = MEM.search(p.op_str)
                    if m:
                        desc_reg, desc_off = m.group(1), int(m.group(3), 0)
                        if m.group(2) == '-':
                            desc_off = -desc_off
                    break
            break
    if desc_reg is None:
        print('未找到 ReadPESectionEntry 调用（描述符基址未知）')
        return
    print('描述符基址 = %s%+#x' % (desc_reg, desc_off))
    print('%-10s %-22s %s' % ('addr', 'insn', 'desc_off'))
    for ins in insns:
        m = MEM.search(ins.op_str or '')
        if not m or m.group(1) != desc_reg:
            continue
        off = int(m.group(3), 0)
        if m.group(2) == '-':
            off = -off
        doff = off - desc_off
        if not (0 <= doff < 0x120):
            continue
        print('%08X   %-22s +0x%X' % (ins.address, ins.mnemonic + ' ' + ins.op_str, doff))


if __name__ == '__main__':
    main()