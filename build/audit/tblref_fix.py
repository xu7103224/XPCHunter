# -*- coding: utf-8 -*-
"""对 PEDecoder.c 中所有 `&g_Table[off] // unk_<orig_addr>` 引用：
在**我方所有表**里搜出原始那 20 字节的真实位置，给出应改成的 (数组, 偏移)。
"""
import re
import struct

SRC = 'XPCHunterDrv/src/framework/PEDecoder.c'
TABSRC = 'XPCHunterDrv/src/framework/DecodeTables.c'
ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'


def main():
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

    tsrc = open(TABSRC, encoding='utf-8', errors='replace').read()
    arrs = {}
    for m in re.finditer(r'const\s+\w+\s+(\w+)\[(?:0x)?[0-9A-Fa-f]+\]\s*=\s*\{(.*?)\};', tsrc, re.S):
        arrs[m.group(1)] = bytes(int(t, 0) & 0xFF for t in re.findall(r'0x[0-9A-Fa-f]+|\b\d+\b', m.group(2)))
    # 也把 PEDecoder.c 里可能内联的小表算进来
    src = open(SRC, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'(?:const|static\s+const)\s+\w+\s+(\w+)\[(?:0x)?[0-9A-Fa-f]+\]\s*=\s*\{(.*?)\};', src, re.S):
        arrs.setdefault(m.group(1), bytes(int(t, 0) & 0xFF for t in re.findall(r'0x[0-9A-Fa-f]+|\b\d+\b', m.group(2))))

    seen = set()
    for m in re.finditer(r'&(\w+)\[([^\]]+)\][^\n]*//\s*unk_([0-9A-Fa-f]+)', src):
        arr, idx, uaddr = m.group(1), m.group(2), m.group(3)
        key = (arr, idx, uaddr)
        if key in seen:
            continue
        seen.add(key)
        ova = int(uaddr, 16)
        org = d[off(ova):off(ova) + 20]
        # 在数组里搜真实位置
        found = []
        for nm, blob in arrs.items():
            i = blob.find(org)
            if i >= 0:
                found.append('%s[0x%X]' % (nm, i))
        print('  %-26s[%-6s]  // unk_%s' % (arr, idx, uaddr))
        print('       原始字节: %s' % ' '.join('%02x' % b for b in org))
        print('       真实位置: %s' % (', '.join(found[:4]) if found else '（我方所有表里都没有这 20 字节！）'))


if __name__ == '__main__':
    main()
