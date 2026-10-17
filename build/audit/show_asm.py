#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把原始驱动某个函数反汇编到文本文件（便于精确、低上下文地阅读）。

用法: python dis.py <start_hex> <size_hex> [outfile]
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
BASE = 0x140000000


def load():
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
    start = int(sys.argv[1], 16)
    size = int(sys.argv[2], 16)
    out = sys.argv[3] if len(sys.argv) > 3 else 'build/audit/_dis.txt'
    text, tva = load()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    lines = []
    for i in md.disasm(text[start - tva:start - tva + size], start):
        lines.append('%08x  %-20s %s' % (i.address, i.bytes.hex(), i.mnemonic + ' ' + i.op_str))
    open(out, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print('wrote', len(lines), 'insns ->', out)


if __name__ == '__main__':
    main()