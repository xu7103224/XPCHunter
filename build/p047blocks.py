#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 0x047 dump 输出的块结构，统计每个块的条目数。"""
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
    out = []
    p = 0
    while p + 0x18 <= len(buf):
        typ = int.from_bytes(buf[p:p+4], 'little')
        cnt = int.from_bytes(buf[p+0x10:p+0x14], 'little')
        if typ == 0 or typ > 0x40 or cnt > 0x10000:
            break
        ents = []
        q = p + 0x18
        for _ in range(cnt):
            if q + 0x10 > len(buf):
                break
            a = int.from_bytes(buf[q:q+8], 'little')
            b = int.from_bytes(buf[q+8:q+16], 'little')
            ents.append((a, b))
            q += 0x10
        out.append((typ, p, ents))
        p = q + 0x18 if (typ == 0) else q
        # 下一块头紧跟条目之后
        p = q
    return out

if __name__ == '__main__':
    buf = parse(sys.argv[1])
    print('总长度: %d (0x%X)' % (len(buf), len(buf)))
    p = 0
    idx = 0
    while p + 0x18 <= len(buf):
        typ = int.from_bytes(buf[p:p+4], 'little')
        cnt = int.from_bytes(buf[p+0x10:p+0x14], 'little')
        if typ == 0 or typ > 0x40 or cnt > 0x10000:
            print('  [停止] 偏移 0x%X 处 type=%d cnt=%d' % (p, typ, cnt))
            break
        idx += 1
        print('#%-2d type=%-2d count=%-5d @0x%04X' % (idx, typ, cnt, p))
        p += 0x18 + 0x10 * cnt
