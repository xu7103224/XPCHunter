"""修正 C 类中『引用落在不同函数内』的 18 条（源码名在 IDA 表中，取其真实起始地址）。
另有 21 条源码名不在 IDA 表中（复刻自建的转发层），不修改 —— 它们引用的是
被包装函数的表项地址，属合理但非标准写法，已在文档中说明。
用法: python build/audit/_fix_c2.py [--dry]
"""
import json, sys, os

dry = '--dry' in sys.argv
d = json.load(open('build/audit/_audit_citation.json', encoding='utf-8'))
orig = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))
byname = {f['name']: f for f in orig}

diff = [it for it in d['not_start'] if it['name'] != it['owner']]
targets = [it for it in diff if it['name'] in byname]

byfile = {}
for it in targets:
    byfile.setdefault(it['file'], []).append(it)

fixed = 0
missed = []
for path, items in byfile.items():
    p = path.replace('/', os.sep)
    if not os.path.exists(p):
        missed.append((p, '文件不存在'))
        continue
    txt = open(p, encoding='utf-8', errors='replace').read()
    lines = txt.split('\n')
    for it in items:
        ln = it['line'] - 1
        f = byname[it['name']]
        old = 'sub_%X' % int(it['cited'], 16)
        new = 'sub_%X（%d 字节）' % (f['start'], f['size'])
        hit = False
        for j in range(max(0, ln - 6), min(len(lines), ln + 1)):
            if old in lines[j]:
                lines[j] = lines[j].replace(old, new)
                hit = True
                fixed += 1
                break
        if not hit:
            missed.append((p, it['line'], old))
    if not dry:
        open(p, 'w', encoding='utf-8', newline='').write('\n'.join(lines))

print('%s② 类修正 %d 条（候选 %d），未命中 %d' % ('[dry] ' if dry else '', fixed, len(targets), len(missed)))
for m in missed:
    print('  ', m)