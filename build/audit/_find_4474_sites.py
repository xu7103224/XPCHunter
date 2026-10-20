#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在原始驱动中搜索 mov ecx, 0x4474 / 0x4475 的字节模式，确认是否存在写入点。"""
import struct

ORIG = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys'
IB = 0x140000000

d = open(ORIG, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
sec = pe + 24 + opt

pats = {}
for idx in (0x4474, 0x4475, 0x4473, 0x4476):
    pats[idx] = [
        ('mov ecx,imm32', b'\xB9' + struct.pack('<I', idx)),
        ('mov ecx,imm8-short?', None),
    ]

for i in range(nsec):
    o = sec + i * 40
    nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    code = d[ra:ra + rsz]
    for idx, plist in pats.items():
        pat = b'\xB9' + struct.pack('<I', idx)
        s = 0
        while True:
            j = code.find(pat, s)
            if j < 0:
                break
            print('%s: mov ecx,0x%X at %s VA 0x%X' % (nm, idx, nm, IB + va + j))
            s = j + 1
    # 也搜 8 字节 qword 引用（表指针偏移常量）
    for idx in (0x4474, 0x4475):
        pat = struct.pack('<I', idx * 8)
        s = 0
        cnt = 0
        while True:
            j = code.find(pat, s)
            if j < 0:
                break
            cnt += 1
            s = j + 1
        if cnt:
            print('%s: idx*8=0x%X 出现 %d 次' % (nm, idx * 8, cnt))