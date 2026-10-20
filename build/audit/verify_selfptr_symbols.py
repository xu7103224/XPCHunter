#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自映像槽（GT 0x900..0xB00）的**符号名交叉验证**。

248 个槽存的是驱动内部函数地址。两次加载的模块基址与 LTCG 重排导致 RVA 不同，
但把地址各自解析成函数名后，名字应当一致——这才是语义等价的判据。

用法:
  python verify_selfptr_symbols.py gt_orig.bin gt_mine.bin \
         <orig_drv_base> <mine_drv_base> [槽下限] [槽上限]
默认槽范围 0x900..0xB00。
"""
import struct, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..', '..')


def load(p):
    d = open(p, 'rb').read()
    return [struct.unpack_from('<Q', d, i * 8)[0] for i in range(len(d) // 8)]


o = load(sys.argv[1]); m = load(sys.argv[2])
ODB = int(sys.argv[3], 16); MDB = int(sys.argv[4], 16)
LO = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x900
HI = int(sys.argv[6], 0) if len(sys.argv) > 6 else 0xB00

# 原始：IDA 导出的函数表（VA → 名字）
orig = json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))
of = {x['start'] - 0x140000000: x['name'] for x in orig}

# 我方：link.exe 的 .map（VA → 名字）
mp = {}
for ln in open(os.path.join(ROOT, 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.map'),
               encoding='utf-8', errors='ignore'):
    mm = re.match(r'\s+0001:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s+f\s+(\S+)', ln)
    if mm:
        mp[int(mm.group(2), 16) - 0x140000000] = mm.group(1)


def nearest(table, rva):
    ks = [k for k in table if k <= rva]
    if not ks:
        return None, None
    k = max(ks)
    return table[k], rva - k


same = []
prefix = []
diff = []
for i in range(LO, HI):
    if i >= len(o) or i >= len(m):
        break
    if not (o[i] and m[i] and o[i] != m[i]):
        continue
    # 只处理"确实落在各自驱动模块内"的槽
    na, da = nearest(of, o[i] - ODB)
    nb, db = nearest(mp, m[i] - MDB)
    if na is None or nb is None:
        continue
    if na == nb and da == db:
        same.append(i)
    elif na == nb or nb == 'Cmd' + na or na == 'Cmd' + nb or na.lstrip('Cmd') == nb.lstrip('Cmd'):
        prefix.append((i, na, da, nb, db))
    else:
        diff.append((i, na, da, nb, db))

total = len(same) + len(prefix) + len(diff)
print('自映像槽总数（槽 0x%X..0x%X）: %d' % (LO, HI, total))
print('  名字+偏移完全相同 : %d' % len(same))
print('  仅命名前缀差异    : %d' % len(prefix))
print('  指向不同函数      : %d' % len(diff))
if prefix:
    print()
    print('--- 仅命名差异（语义等价）---')
    for i, na, da, nb, db in prefix:
        print('  GT[0x%X] %-40s vs %s' % (i, na, nb))
if diff:
    print()
    print('--- 指向不同函数（需修复）---')
    for i, na, da, nb, db in diff:
        print('  GT[0x%X]  orig=%-38s(+0x%X)  mine=%-38s(+0x%X)'
              % (i, na, da, nb, db))
    print()
    print('结论: %d 个槽指向不同函数，需按原始反汇编逐个核对' % len(diff))
else:
    print()
    print('结论: 全部自映像槽语义等价')