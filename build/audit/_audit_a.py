# 核查 A 类（无同名实现）的 143 个函数：按名称与地址两路在源码中检索
import json, re, glob, os

audit = json.load(open(r'build\audit\_audit_v2.json', encoding='utf-8'))
missing = audit['missing']
print(f'A 类待核查: {len(missing)}')

srctext = {}
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True) + glob.glob('XPCHunterDrv/inc/*.h'):
    srctext[f.replace(chr(92), '/')] = open(f, encoding='utf-8', errors='ignore').read()

whole = '\n'.join(srctext.values())

def find_name(n):
    hits = []
    pat = re.compile(r'\b' + re.escape(n) + r'\b')
    for f, t in srctext.items():
        for i, ln in enumerate(t.split('\n')):
            if pat.search(ln):
                hits.append(f"{os.path.basename(f)}:{i+1}")
    return hits

def find_addr(a):
    a = a.lower()
    forms = [a, a.replace('0x', '')]
    hits = []
    for f, t in srctext.items():
        for i, ln in enumerate(t.split('\n')):
            low = ln.lower()
            if any(x in low for x in forms):
                hits.append(f"{os.path.basename(f)}:{i+1}")
    return hits

exact, renamed, orphan = [], [], []
for r in missing:
    nm_hits = find_name(r['name'])
    ad_hits = find_addr(r['start'])
    if nm_hits:
        exact.append((r, nm_hits[:3]))
    elif ad_hits:
        renamed.append((r, ad_hits[:3]))
    else:
        orphan.append(r)

print(f'  名字出现（可能只是调用/声明）: {len(exact)}')
print(f'  名字无、但地址被引用         : {len(renamed)}')
print(f'  名字与地址都无               : {len(orphan)}')
print()
print('=' * 90)
print('【A-1】地址被引用（说明已实现但改了名或未建函数）')
print('=' * 90)
for r, h in renamed[:25]:
    print(f"  {r['size']:5d}B  {r['name']:46s} {r['start']}  引用: {', '.join(h)}")
print()
print('=' * 90)
print(f'【A-2】名字与地址都查不到（真缺口，按大小降序）共 {len(orphan)} 个')
print('=' * 90)
tot = sum(r['size'] for r in orphan)
for r in sorted(orphan, key=lambda x: -x['size'])[:45]:
    print(f"  {r['size']:5d}B  {r['name']:46s} {r['start']}")
print(f'  ... 合计 {len(orphan)} 个，{tot:,} 字节')

json.dump({'renamed': [{'name': r['name'], 'size': r['size'], 'addr': r['start'], 'hits': h} for r, h in renamed],
           'orphan': orphan, 'name_hits': [{'name': r['name'], 'size': r['size'], 'hits': h} for r, h in exact]},
          open(r'build\audit\_audit_a.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\_audit_a.json')
