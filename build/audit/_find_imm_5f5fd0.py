#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在原始驱动 .text 中搜索立即数 0x5F5FD0 的出现（GT[0x4474] 的值）。"""
import struct, capstone

ORIG = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys'
IB = 0x140000000
TARGETS = (0x5F5FD0, 0x005F5FD0)

d = open(ORIG, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
sec = pe + 24 + opt

for i in range(nsec):
    o = sec + i * 40
    nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    if nm != '.text':
        continue
    code = d[ra:ra + rsz]
    # 搜 4 字节小端立即数
    for t in TARGETS:
        pat = struct.pack('<I', t)
        start = 0
        while True:
            j = code.find(pat, start)
            if j < 0:
                break
            print('imm32 0x%X at VA 0x%X' % (t, IB + va + j))
            start = j + 1
    # 搜 8 字节
    pat8 = struct.pack('<Q', 0x5F5FD0)
    start = 0
    while True:
        j = code.find(pat8, start)
        if j < 0:
            break
        print('imm64 0x5F5FD0 at VA 0x%X' % (IB + va + j))
        start = j + 1