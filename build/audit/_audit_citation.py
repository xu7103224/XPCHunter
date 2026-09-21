# 地址引用专项审计：源码 "对应原始驱动 sub_XXXX" 注释 vs IDA 真实函数名
import json, re, glob, os, collections

FUNC_TABLE = r'build\audit\_orig_funcs_ida.json'
rows = json.load(open(FUNC_TABLE, encoding='utf-8'))

addr2name = {r['start']: r['name'] for r in rows}
name2addr = collections.defaultdict(list)
for r in rows:
    name2addr[r['name']].append(r['start'])
sizes = {r['start']: r['size'] for r in rows}

# 排好序的函数起始地址，用于判断某地址是否落在函数内部
starts = sorted(addr2name)

def containing(addr):
    """返回包含该地址的函数起始（若地址不是函数起始）"""
    lo, hi = 0, len(starts) - 1
    best = None
    for s in starts:
        if s <= addr:
            best = s
        else:
            break
    if best == addr:
        return None
    return best

# ---------- 解析源码 ----------
func_def_re = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_ \*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
sub_re = re.compile(r'sub_([0-9A-Fa-f]{6,16})')

records = []
for path in sorted(glob.glob('XPCHunterDrv/src/**/*.c', recursive=True)):
    lines = open(path, encoding='utf-8', errors='ignore').read().split('\n')
    cur_name, cur_line, cur_addr, cur_addr_line = None, 0, None, 0
    for i, ln in enumerate(lines):
        if ln.strip() and not ln.startswith((' ', '\t', '/', '#', '{', '}')):
            m = func_def_re.match(ln)
            if m and not ln.rstrip().endswith(';'):
                # 收尾上一个
                if cur_name:
                    records.append((cur_name, path.replace(chr(92), '/'), cur_line, cur_addr, cur_addr_line))
                cur_name, cur_line, cur_addr, cur_addr_line = m.group(1), i + 1, None, 0
        mm = sub_re.search(ln)
        if mm and cur_name:
            a = int(mm.group(1), 16)
            if 0x140000000 <= a < 0x141000000:
                cur_addr, cur_addr_line = a, i + 1
    if cur_name:
        records.append((cur_name, path.replace(chr(92), '/'), cur_line, cur_addr, cur_addr_line))

print(f'解析出带地址引用的函数: {sum(1 for r in records if r[3])} / {len(records)}\n')

# ---------- 分类 ----------
exact, addr_wrong, not_func_start, unknown_name = [], [], [], []
for name, path, line, addr, aline in records:
    if not addr:
        continue
    ida_name = addr2name.get(addr)
    if ida_name is None:
        owner = containing(addr)
        not_func_start.append((name, path, line, addr, None if owner is None else addr2name[owner]))
        continue
    if ida_name == name:
        exact.append((name, addr))
    elif name in name2addr:
        addr_wrong.append((name, path, line, addr, ida_name, name2addr[name][0]))
    else:
        unknown_name.append((name, path, line, addr, ida_name))

print('=' * 96)
print(f'【A】引用正确（源码函数名 == 该地址的 IDA 名）: {len(exact)} 个')
print('=' * 96)

print()
print('=' * 96)
print(f'【B】确证地址写错（源码函数名在 IDA 中存在，但在别的地址）: {len(addr_wrong)} 个')
print('=' * 96)
for name, path, line, addr, ida_name, real in sorted(addr_wrong, key=lambda x: x[1]):
    print(f'  {os.path.basename(path)}:{line}')
    print(f'      源码函数 {name}')
    print(f'      引用地址 {addr:#x} 实为 {ida_name}')
    print(f'      正确地址应为 {real:#x}')

print()
print('=' * 96)
print(f'【C】引用的地址不是函数起始（落在其它函数内部）: {len(not_func_start)} 个')
print('=' * 96)
for name, path, line, addr, owner in sorted(not_func_start, key=lambda x: x[1])[:30]:
    print(f'  {os.path.basename(path)}:{line}  {name}  引用 {addr:#x} -> 落在 {owner} ({hex(owner) if owner else "?"}) 内')
if len(not_func_start) > 30:
    print(f'  ... 其余 {len(not_func_start)-30} 个见 JSON')

print()
print(f'【D】源码函数名不在 IDA 函数表中（多为复刻自建辅助函数）: {len(unknown_name)} 个')

json.dump({'exact': [{"name": n, "addr": hex(a)} for n, a in exact],
           'addr_wrong': [{"name": n, "file": p, "line": l, "cited": hex(a), "ida_at_cited": i, "real": hex(r)}
                          for n, p, l, a, i, r in addr_wrong],
           'not_func_start': [{"name": n, "file": p, "line": l, "cited": hex(a), "owner": o}
                              for n, p, l, a, o in not_func_start],
           'unknown': [{"name": n, "file": p, "line": l, "cited": hex(a), "ida_at_cited": i}
                       for n, p, l, a, i in unknown_name]},
          open(r'build\audit\_audit_citation.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n结果写入 build\\audit\\_audit_citation.json')
