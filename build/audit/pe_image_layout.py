#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把磁盘 PE 展开成**内存镜像布局**（节区按 VirtualAddress 摆放，SizeOfImage 大小）。

这正对应驱动 GT[0x20] 指向的那个缓冲（活体已核对：live[off] == disk[off - sec_delta]）。
"""
import struct


def image_layout(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    opt = struct.unpack_from('<H', d, pe + 20)[0]
    sizeimg = struct.unpack_from('<I', d, pe + 24 + 0x38)[0]
    buf = bytearray(sizeimg)
    # 头部
    hdr = min(struct.unpack_from('<I', d, pe + 24 + 0x3c)[0], sizeimg)
    buf[0:hdr] = d[0:hdr]
    sec = pe + 24 + opt
    for i in range(nsec):
        o = sec + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
        n = min(vsz, rsz) if vsz else rsz
        if va + n > sizeimg:
            n = sizeimg - va
        buf[va:va + n] = d[ra:ra + n]
    return bytes(buf), sizeimg, d


if __name__ == '__main__':
    import sys
    b, sz, d = image_layout(sys.argv[1] if len(sys.argv) > 1 else 'ntoskrnl_guest.exe')
    print('image size 0x%X, built %d' % (sz, len(b)))