#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 IDA MCP 的 entity_query 分页输出重建 _orig_funcs_ida.json。

背景：原有 _orig_funcs_ida.json 是改名审计之前的旧快照，导致
verify_selfptr_symbols.py 把「我方已按审计结论改名」的函数误判为"指向不同函数"。
本脚本用 IDA 当前的函数名重建快照，消除这类假阳性。

用法: python refresh_orig_funcs.py <mcp_entity_query_输出.json>
（先调用 entity_query kind=functions count=0，把返回的 json 存成文件）
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '_orig_funcs_ida.json')

src = sys.argv[1]
raw = json.load(open(src, encoding='utf-8'))
# MCP 返回形如 {"result":[{"kind":"functions","data":[...],"total":1516}]}
if isinstance(raw, dict) and 'result' in raw:
    raw = raw['result']
if isinstance(raw, list):
    block = raw[0] if raw else {}
    rows = block.get('data', raw)
else:
    rows = raw.get('data', [])

out = []
for r in rows:
    addr = r['addr']
    va = int(addr, 16) if isinstance(addr, str) else int(addr)
    size = r.get('size', 0)
    size = int(size, 16) if isinstance(size, str) else int(size)
    name = r.get('name', '')
    out.append({
        'name': name,
        'start': va,
        'end': va + size,
        'size': size,
        # 保守处理：段为 .text 且非导入 thunk 的一律按业务函数计
        'thunk': False,
        'lib': name.startswith('__') or name in ('memmove', 'memset', 'memcpy'),
        'segment': '.text',
    })

out.sort(key=lambda x: x['start'])
old = None
if os.path.exists(OUT):
    old = json.load(open(OUT, encoding='utf-8'))

json.dump(out, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('写入 %d 条 → %s' % (len(out), OUT))
if old:
    oldmap = {x['start']: x['name'] for x in old}
    newmap = {x['start']: x['name'] for x in out}
    changed = [(a, oldmap[a], newmap[a]) for a in newmap if a in oldmap and oldmap[a] != newmap[a]]
    print('名字有变化的函数: %d' % len(changed))
    for a, o, n in changed[:40]:
        print('   0x%X  %s → %s' % (a, o, n))
    gone = set(oldmap) - set(newmap)
    added = set(newmap) - set(oldmap)
    print('旧有新无: %d   新有旧无: %d' % (len(gone), len(added)))