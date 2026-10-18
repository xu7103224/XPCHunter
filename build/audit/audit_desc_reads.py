#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描我方 PEDecoder.c 里所有「描述符字段读取」，列出 (函数, 行号, 偏移, 宏名)。

用途：人工/自动逐个核对原始反汇编，找同族「读错偏移」缺陷。
"""
import re
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', '..', 'XPCHunterDrv', 'src', 'framework', 'PEDecoder.c')

# 我方宏名 → 偏移
MACROS = {
    'DEC_CTX_DECODE_TABLE_PTR': 0x00,
    'DEC_CTX_MODE': 0x00,
    'DEC_CTX_MODE_DUP': 0x04,
    'DEC_CTX_ADDR_SIZE': 0x08,
    'DEC_CTX_PARAM6_DESC': 0x10,
    'DEC_CTX_PARAM7_DESC': 0x18,
    'DEC_CTX_STATE_FLAGS': 0x20,
    'DEC_CTX_OPERAND_SIZE': 0x24,
    'DEC_CTX_SUBTYPE_BYTE': 0x28,
    'DEC_CTX_TYPE5_VALUE': 0x2C,
    'DEC_CTX_OPERANDS': 0x30,
    'DEC_CTX_PREFIX_FLAGS': 0xD8,
    'DEC_CTX_MODRM_BYTE': 0xDC,
    'DEC_CTX_IMM_VALUE': 0xE0,
    'DEC_CTX_CONSUMED': 0xF0,
    'DEC_CTX_IMM_FLAG': 0xF4,
    'DEC_CTX_READ_FLAG': 0xF8,
    'DEC_CTX_STATUS_ACC': 0x100,
    'DEC_CTX_EXTRA_FIELD': 0x110,
    'DEC_CTX_CUR_TABLE_ENTRY': 0x118,
}


def main():
    lines = open(SRC, encoding='utf-8', errors='ignore').read().splitlines()
    cur_func = '?'
    pat = re.compile(r'CTX_[DQ]\(\s*\w+\s*,\s*(DEC_CTX_\w+|[0-9xXa-fA-F]+)\s*\)')
    hits = []
    for i, ln in enumerate(lines, 1):
        m = re.match(r'^(?:__int64|char|void|unsigned|ULONG64|int)\s+[^;]*?(\w+)\s*\(', ln)
        if m and '(' in ln and '{' not in ln and ';' not in ln:
            cur_func = m.group(1)
        if ln.strip().startswith('//'):
            continue
        for mm in pat.finditer(ln):
            field = mm.group(1)
            off = MACROS.get(field)
            if off is None:
                try:
                    off = int(field, 16) if field.lower().startswith('0x') else int(field)
                except ValueError:
                    off = -1
            hits.append((cur_func, i, field, off))
    # 按函数汇总
    from collections import defaultdict
    by = defaultdict(list)
    for f, i, fld, off in hits:
        by[f].append((i, fld, off))
    for f in sorted(by, key=lambda x: by[x][0][0]):
        offs = sorted({off for _, _, off in by[f]})
        print('== %s (行 %d)  读偏移: %s' % (
            f, by[f][0][0], ', '.join('0x%X' % o for o in offs)))
    print('\n总读取点:', len(hits))


if __name__ == '__main__':
    main()