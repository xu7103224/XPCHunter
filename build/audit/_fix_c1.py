"""修正 C 类中『地址落在同名函数内』的 17 条引用（改为其真实起始地址）。
依据：_audit_citation.json 的 not_start 列表 + IDA 函数表。
每条必须在其函数定义前 6 行内找到旧 sub_XXXX 串（带上下文锚点，避免误替换）。
用法: python build/audit/_fix_c1.py [--dry]
"""
import json, sys, os

dry = '--dry' in sys.argv
d = json.load(open('build/audit/_audit_citation.json', encoding='utf-8'))
orig = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))
byname = {f['name']: f for f in orig}
same = [it for it in d['not_start'] if it['name'] == it['owner']]

byfile = {}
for it in same:
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
        real = byname[it['name']]['start']
        size = byname[it['name']]['size']
        cited = int(it['cited'], 16)
        old = 'sub_%X' % cited
        new = 'sub_%X（%d 字节）' % (real, size)
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

print('%s① 类修正 %d 条，未命中 %d' % ('[dry] ' if dry else '', fixed, len(missed)))
for m in missed:
    print('  ', m)