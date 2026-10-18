#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反汇编我方的已构建驱动的某函数（按 RVA/VA 给范围）。

用法: python dis_mine.py <start_va_hex> <size_hex> [outfile]
VA 以 0x140000000 为镜像基址（同 map 文件里的地址）。
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
BASE = 0x140000000


def load(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    sec = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
    secs = []
    for i in range(n):
        o = sec + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
        secs.append((nm, vsz, va, rsz, ra))
    return d, secs


def main():
    start = int(sys.argv[1], 16)
    size = int(sys.argv[2], 16)
    out = sys.argv[3] if len(sys.argv) > 3 else 'build/audit/_dis_mine.txt'
    d, secs = load(MINE)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    rva = start - BASE
    buf = None
    for nm, vsz, va, rsz, ra in secs:
        if va <= rva < va + max(vsz, rsz):
            off = rva - va
            buf = d[ra + off: ra + off + size]
            break
    if buf is None:
        raise SystemExit('no section contains %x' % rva)
    lines = []
    for i in md.disasm(buf, start):
        lines.append('%08x  %-20s %s' % (i.address, i.bytes.hex(), i.mnemonic + ' ' + i.op_str))
    open(out, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    print('wrote', len(lines), 'insns ->', out)


if __name__ == '__main__':
    main()