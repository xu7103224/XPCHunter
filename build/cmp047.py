#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对比两份 0x047 dump 的块结构与条目内容。"""
import re, sys

def parse(path):
    data = bytearray()
    for line in open(path, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s*([0-9A-F]{4}):\s+((?:[0-9A-F]{2}\s+){1,16})', line)
        if not m:
            continue
        off = int(m.group(1), 16)
        raw = bytes(int(b, 16) for b in m.group(2).split())
        if len(data) < off + len(raw):
            data.extend(b'\x00' * (off + len(raw) - len(data)))
        data[off:off+len(raw)] = raw
    return bytes(data)

def blocks(buf):
    out, p = [], 0
    while p + 0x18 <= len(buf):
        typ = int.from_bytes(buf[p:p+4], 'little')
        cnt = int.from_bytes(buf[p+0x10:p+0x14], 'little')
        if typ == 0 or typ > 0x40 or cnt > 0x10000:
            break
        ents, q = [], p + 0x18
        for _ in range(cnt):
            if q + 0x10 > len(buf):
                break
            ents.append((int.from_bytes(buf[q:q+8], 'little'),
                         int.from_bytes(buf[q+8:q+16], 'little')))
            q += 0x10
        out.append((typ, p, ents))
        p = q
    return out

a = parse(sys.argv[1])
b = parse(sys.argv[2])
la, lb = len(a), len(b)
print('长度: A=%d  B=%d  %s' % (la, lb, 'OK' if la == lb else '不同'))
A, B = blocks(a), blocks(b)
print('块数: A=%d  B=%d' % (len(A), len(B)))
print()
print('%-3s %-5s %-6s %-6s %-8s %s' % ('#', 'type', 'cntA', 'cntB', 'struct', 'entry-diff'))
for i in range(max(len(A), len(B))):
    ta, pa, ea = A[i] if i < len(A) else (None, None, [])
    tb, pb, eb = B[i] if i < len(B) else (None, None, [])
    struct = 'OK' if (ta == tb and pa == pb and len(ea) == len(eb)) else 'DIFF'
    same = sum(1 for x, y in zip(ea, eb) if x == y)
    print('%-3d %-5s %-6d %-6d %-8s %d/%d 相同' % (i + 1, ta, len(ea), len(eb), struct, same, len(ea)))
