# 校验源码中"对应原始驱动 sub_XXXX"注释的地址映射是否正确
# 方法：比较【源码函数调用的函数集合】与【该地址处原始函数的被调用者集合】
import json, re, glob, os, math, collections

orig = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))
by_addr = {}
for name, v in orig.items():
    by_addr[int(v['start'], 16)] = (name, v)

# 源码函数：名称 -> (文件, 行, 调用集合, 声称的地址)
src = {}
sub_re = re.compile(r'sub_([0-9A-Fa-f]{6,16})')
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    lines = open(f, encoding='utf-8', errors='ignore').read().split('\n')
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip() and not ln.startswith((' ', '\t', '/', '#', '{', '}')) and '(' in ln:
            j, sig = i, ''
            while j < len(lines) and j < i + 6:
                sig += lines[j] + '\n'
                if ')' in lines[j]:
                    break
                j += 1
            m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', sig)
            k = j + 1
            while k < len(lines) and lines[k].strip() == '':
                k += 1
            if m and k < len(lines) and lines[k].strip() == '{':
                name = m.group(1)
                depth, body, p = 0, [], k
                while p < len(lines):
                    depth += lines[p].count('{') - lines[p].count('}')
                    body.append(lines[p])
                    if depth == 0 and p >= k:
                        break
                    p += 1
                txt = re.sub(r'//[^\n]*', '', '\n'.join(body))
                calls = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', txt))
                calls.discard(name)
                # 上方 8 行内声称的原始地址
                claimed = None
                for q in range(max(0, i - 8), i + 1):
                    mm = sub_re.search(lines[q])
                    if mm:
                        a = int(mm.group(1), 16)
                        if a >= 0x140000000:
                            claimed = a
                if name not in src or claimed:
                    src[name] = {'file': os.path.basename(f), 'line': i + 1,
                                 'calls': calls, 'claimed': claimed}
                i = p + 1
                continue
        i += 1

N = len(orig)
df = collections.Counter()
for v in orig.values():
    for c in set(v['callees']):
        df[c] += 1
idf = lambda c: math.log(N / (1 + df.get(c, 0))) + 0.05

suspect = []
checked = 0
for sname, sv in src.items():
    a = sv['claimed']
    if not a or a not in by_addr:
        continue
    oname, ov = by_addr[a]
    oset = set(ov['callees'])
    if not oset:
        continue
    checked += 1
    inter = oset & sv['calls']
    cov = sum(idf(c) for c in inter) / sum(idf(c) for c in oset)
    # 名称一致性
    name_ok = (sname == oname)
    if cov < 0.5 and len(inter) < 2:
        suspect.append({'src_name': sname, 'file': sv['file'], 'line': sv['line'],
                        'claimed_addr': hex(a), 'orig_name': oname,
                        'orig_size': ov['size'], 'cov': round(cov, 2),
                        'shared': sorted(inter)[:6], 'name_match': name_ok})

print(f'校验了 {checked} 个带地址映射的源码函数')
print(f'可疑（调用图与该地址原始函数几乎不匹配）: {len(suspect)} 个')
print()
print('=' * 104)
for s in sorted(suspect, key=lambda x: -x['orig_size'])[:45]:
    nm = '' if s['name_match'] else f"  [源码名={s['src_name']} vs IDA名={s['orig_name']}]"
    print(f"  {s['orig_size']:5d}B  {s['claimed_addr']} 覆盖={s['cov']:.2f}  {s['file']}:{s['line']}{nm}")
    if s['shared']:
        print(f"          共同调用: {s['shared']}")

json.dump(suspect, open(r'build\audit\_audit_mapping.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\_audit_mapping.json')
