# 地址引用专项审计 v2：把 "对应原始驱动 sub_XXXX" 注释归属到紧随其后的函数定义
import json, re, glob, os, collections

rows = json.load(open(r'build\audit\_orig_funcs_ida.json', encoding='utf-8'))
addr2name = {r['start']: r['name'] for r in rows}
name2addr = collections.defaultdict(list)
for r in rows:
    name2addr[r['name']].append(r['start'])
starts = sorted(addr2name)

def containing(addr):
    best = None
    for s in starts:
        if s <= addr:
            best = s
        else:
            break
    return None if best == addr else best

func_def_re = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
sub_re = re.compile(r'sub_([0-9A-Fa-f]{6,16})')

records = []
for path in sorted(glob.glob('XPCHunterDrv/src/**/*.c', recursive=True)):
    lines = open(path, encoding='utf-8', errors='ignore').read().split('\n')
    for i, ln in enumerate(lines):
        if not ln.strip() or ln.startswith((' ', '\t', '/', '#', '{', '}')):
            continue
        m = func_def_re.match(ln)
        if not m or ln.rstrip().endswith(';'):
            continue
        # 找到函数定义：向前最多 12 行找 sub_XXXX（注释紧邻其上）
        cited = None
        for back in range(1, 13):
            j = i - back
            if j < 0:
                break
            prev = lines[j]
            mm = sub_re.search(prev)
            if mm:
                a = int(mm.group(1), 16)
                if 0x140000000 <= a < 0x141000000:
                    cited = a
                    break
            # 越过空行/注释取，遇到其它代码行则停止
            if prev.strip() and not prev.lstrip().startswith(('//', '/*', '*')):
                break
        records.append((m.group(1), path.replace(chr(92), '/'), i + 1, cited))

withcite = [r for r in records if r[3]]
print(f'函数定义: {len(records)}，其中带地址引用: {len(withcite)}\n')

exact, addr_wrong, not_start, unknown = [], [], [], []
for name, path, line, addr in withcite:
    ida = addr2name.get(addr)
    if ida is None:
        owner = containing(addr)
        not_start.append((name, path, line, addr, None if owner is None else addr2name[owner]))
    elif ida == name:
        exact.append((name, addr))
    elif name in name2addr:
        addr_wrong.append((name, path, line, addr, ida, name2addr[name][0]))
    else:
        unknown.append((name, path, line, addr, ida))

print('=' * 96)
print(f'【A】引用正确（源码函数名 == 该地址的 IDA 名）: {len(exact)}')
print('=' * 96)
print()
print('=' * 96)
print(f'【B】地址写错（源码名在 IDA 中存在，但不在该地址）: {len(addr_wrong)}')
print('=' * 96)
for name, path, line, addr, ida, real in sorted(addr_wrong, key=lambda x: (x[1], x[2])):
    print(f'  {os.path.basename(path)}:{line}  {name}')
    print(f'      引用 {addr:#x} 实为 {ida}    正确应为 {real:#x}')
print()
print('=' * 96)
print(f'【C】引用的地址不是函数起始: {len(not_start)}')
print('=' * 96)
for name, path, line, addr, owner in sorted(not_start, key=lambda x: (x[1], x[2]))[:25]:
    print(f'  {os.path.basename(path)}:{line}  {name}  引用 {addr:#x} 落在 {owner} 内')
if len(not_start) > 25:
    print(f'  ... 其余 {len(not_start)-25} 个')
print()
print(f'【D】源码名不在 IDA 函数表（多为复刻自建辅助函数）: {len(unknown)}')

json.dump({'exact': [{"name": n, "addr": hex(a)} for n, a in exact],
           'addr_wrong': [{"name": n, "file": p, "line": l, "cited": hex(a), "ida_at_cited": i, "real": hex(r)}
                          for n, p, l, a, i, r in addr_wrong],
           'not_start': [{"name": n, "file": p, "line": l, "cited": hex(a), "owner": o}
                         for n, p, l, a, o in not_start],
           'unknown': [{"name": n, "file": p, "line": l, "cited": hex(a), "ida_at_cited": i}
                       for n, p, l, a, i in unknown]},
          open(r'build\audit\_audit_citation.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\audit\\_audit_citation.json')
