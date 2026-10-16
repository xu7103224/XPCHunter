# -*- coding: utf-8 -*-
"""DecodeTables.c 全表核对：每个数组的内容是否等于原始镜像在「其声明注释地址」处的字节。
不等则报告，并给出应从哪个地址重新抽取（若能从原始代码引用推断）。"""
import re
import struct

TABSRC = 'XPCHunterDrv/src/framework/DecodeTables.c'
ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'

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
    return None


src = open(TABSRC, encoding='utf-8', errors='replace').read()
lines = src.split('\n')
ok = bad = 0
for m in re.finditer(r'//\s*(\w+)\s+at\s+(0x[0-9a-fA-F]+)([^\n]*)\n\s*const\s+\w+\s+(\w+)\[((?:0x)?[0-9A-Fa-f]+)\]\s*=\s*\{(.*?)\};',
                     src, re.S):
    name, addr, tail, arrname, size_s, body = m.groups()
    size = int(size_s, 0)
    vals = bytes(int(t, 0) & 0xFF for t in re.findall(r'0x[0-9A-Fa-f]+|\b\d+\b', body))
    a = int(addr, 16)
    o = off(a)
    org = d[o:o + size]
    status = 'OK' if vals == org else 'MISMATCH'
    if status == 'OK':
        ok += 1
    else:
        bad += 1
    print('  %-30s 源地址 %s  长度 %-6d %s' % (arrname, addr, size, status))
    if status == 'MISMATCH':
        # 差异位置
        dl = [i for i in range(min(len(vals), len(org))) if vals[i] != org[i]]
        print('       首个差异 @0x%X  （共 %d 处）' % (dl[0], len(dl)) if dl else '       （长度不同）')
print('OK=%d  MISMATCH=%d' % (ok, bad))
