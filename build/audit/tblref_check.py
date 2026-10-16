# -*- coding: utf-8 -*-
"""校验 PEDecoder.c 中 `&g_Table[off] // unk_<orig_addr>` 形式的引用：
我们数组在该偏移处的 20 字节 是否等于 原始镜像在该地址处的 20 字节。
不等即为错引用。"""
import re
import struct

SRC = 'XPCHunterDrv/src/framework/PEDecoder.c'
TABSRC = 'XPCHunterDrv/src/framework/DecodeTables.c'
ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'


def orig_bytes():
    d = open(ORIG, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    sc = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
    secs = []
    for i in range(n):
        o = sc + i * 40
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
        secs.append((va, vsz, ra, rsz))

    def off(va):
        v = va - 0x140000000
        for sva, vsz, ra, rsz in secs:
            if sva <= v < sva + max(vsz, rsz):
                return ra + (v - sva)
    return d, off


def our_arrays():
    src = open(TABSRC, encoding='utf-8', errors='replace').read()
    out = {}
    for m in re.finditer(r'const\s+\w+\s+(\w+)\[(?:0x)?[0-9A-Fa-f]+\]\s*=\s*\{(.*?)\};', src, re.S):
        name = m.group(1)
        out[name] = bytes(int(t, 0) & 0xFF for t in re.findall(r'0x[0-9A-Fa-f]+|\b\d+\b', m.group(2)))
    return out


def main():
    d, off = orig_bytes()
    arrs = our_arrays()
    src = open(SRC, encoding='utf-8', errors='replace').read()
    pat = re.compile(r'&(\w+)\[([^\]]+)\][^\n]*//\s*unk_([0-9A-Fa-f]+)')
    for m in pat.finditer(src):
        arr, idx, uaddr = m.group(1), m.group(2), m.group(3)
        try:
            idxv = eval(idx, {}, {}) if idx.startswith('0x') or idx.isdigit() else None
        except Exception:
            idxv = None
        if idxv is None:
            print('  [跳过] %s[%s] // unk_%s  （偏移为表达式，需人工核）' % (arr, idx, uaddr))
            continue
        a = arrs.get(arr)
        if a is None:
            print('  [缺数组] %s' % arr)
            continue
        ours = a[idxv:idxv + 20]
        ova = int(uaddr, 16)
        org = d[off(ova):off(ova) + 20]
        ok = ours == org
        print('  %-28s[0x%-5X] vs unk_%s  %s' % (arr, idxv, uaddr, 'OK' if ok else 'MISMATCH'))
        if not ok:
            print('       ours: %s' % ' '.join('%02x' % b for b in ours))
            print('       orig: %s' % ' '.join('%02x' % b for b in org))


if __name__ == '__main__':
    main()
