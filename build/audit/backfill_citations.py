#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为已实现但缺原始地址注释的函数补上 `// 对应原始驱动 0x14XXXXXXX（N 字节）`。

规则（与 CLAUDE.md 的可追溯要求一致）：
  · 只在函数定义那一行**上方**插入一行注释；
  · 若上方 3 行内已有 "对应原始驱动" / "0x1400" 字样则跳过（避免重复）；
  · 只处理 _orig_funcs_ida.json 里 lib=False 的业务函数；
  · 不修改任何代码语句，只插入注释行。
用法: python backfill_citations.py [--apply]
"""
import json, os, re, glob, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
HERE = os.path.join(ROOT, 'build', 'audit')
APPLY = '--apply' in sys.argv

orig = json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))
byname = {}
for x in orig:
    if x.get('lib'):
        continue
    byname.setdefault(x['name'], []).append(x)

files = sorted(glob.glob(os.path.join(ROOT, 'XPCHunterDrv', 'src', '**', '*.c'), recursive=True))
total = 0
plan = []

for path in files:
    text = open(path, encoding='utf-8', errors='ignore').read()
    lines = text.split('\n')
    changed = False
    out = []
    for idx, line in enumerate(lines):
        # 去掉行尾 // 注释后再判断形态，避免把"声明 + 注释"误当定义
        code = line.split('//')[0].rstrip()
        if not code or code.startswith('#'):
            out.append(line)
            continue
        # 函数定义的粗略形态：行首类型 + 名字 + '(' + 行尾不是 ';'
        m = re.match(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(', code)
        if not m or code.endswith(';'):
            out.append(line)
            continue
        name = m.group(1)
        if name not in byname:
            out.append(line)
            continue
        # 上方 3 行已有引用则跳过
        ctx = '\n'.join(lines[max(0, idx - 3):idx])
        if '对应原始驱动' in ctx or re.search(r'0x1400[0-9A-Fa-f]{5}', ctx):
            out.append(line)
            continue
        e = byname[name][0]
        out.append('// 对应原始驱动 0x%X（%d 字节）' % (e['start'], e['size']))
        out.append(line)
        changed = True
        total += 1
        plan.append((os.path.relpath(path, ROOT), idx + 1, name, e['start']))
    if changed and APPLY:
        open(path, 'w', encoding='utf-8', newline='').write('\n'.join(out))

print('待补注释函数数:', total)
for p, ln, n, a in plan[:40]:
    print('  %s:%d  %-40s 0x%X' % (p, ln, n, a))
if not APPLY:
    print('\n（未写入；加 --apply 生效）')