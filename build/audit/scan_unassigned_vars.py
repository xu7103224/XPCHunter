#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描全源码树：局部变量「声明后从不赋值」却被当作指针/字段基址使用。

这类缺陷在实机会被 MSVC 折叠成绝对地址（如 [6]），导致 0x50 PAGE_FAULT。
实证：FindKernelInitSection 的 SectionName（本次验收抓到的 rtZ19+0x3bbdd）。
"""
import glob
import os
import re

SUSPECTS = [
    'SectionName', 'SectionFlags2', 'SectionDataPtr', 'RawSize', 'EntryFlags',
    'SectionAlign', 'TypeFlag', 'Characteristics', 'EntryCharacteristics',
    'InitSectionSize', 'SectionFlags', 'FieldValue', 'SectionSize', 'SubType',
    'DataSectionSize', 'VirtualSize', 'FieldValue2', 'FieldFlags',
]

DECL = (r'^\s+(?:__int64|unsigned int|ULONG64|int|char|short|__int16|ULONG|'
        r'unsigned __int8|unsigned __int16|UCHAR|USHORT|LONG|DWORD|BOOLEAN)\s+')

FUNC = re.compile(r'^(?:[A-Za-z_][\w \*]*)\s+(\w+)\s*\([^;{}]*?\)\s*\{(.*?)\n\}',
                  re.M | re.S)


def main():
    files = sorted(set(
        glob.glob('XPCHunterDrv/src/**/*.c', recursive=True)
        + glob.glob('XPCHunterDrv/src/*.c')))
    hits = 0
    for fp in files:
        try:
            src = open(fp, encoding='utf-8', errors='ignore').read()
        except OSError:
            continue
        for m in FUNC.finditer(src):
            name, body = m.group(1), m.group(2)
            for s in SUSPECTS:
                if not re.search(DECL + s + r'\s*;', body, re.M):
                    continue
                if re.search(r'\b' + s + r'\s*=[^=]', body):
                    continue
                # 是否被当作地址/字段基址使用
                if re.search(r'\b' + s + r'\b\s*\+\s*0x|\b' + s + r'\s*\+|\*\(' \
                             r'[^)]*\)\s*' + s + r'\b', body):
                    print('%s  %-48s UNASSIGNED %s'
                          % (os.path.basename(fp), name, s))
                    hits += 1
    print('total hits:', hits)


if __name__ == '__main__':
    main()