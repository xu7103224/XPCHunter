# 用调用图相似度匹配 A 类"无同名"函数：判断是真缺失还是改了名
import json, re, glob, os, math, collections

orig_cg = json.load(open(r'build\audit\_orig_callgraph.json', encoding='utf-8'))
audit = json.load(open(r'build\audit\_audit_v2.json', encoding='utf-8'))
a_list = json.load(open(r'build\audit\_audit_a.json', encoding='utf-8'))
orphans = {o['name']: o for o in a_list['orphan']}

# ---------- 1. 解析源码函数体，提取被调用函数名 ----------
def strip_comments(t):
    t = re.sub(r'//[^\n]*', '', t)
    t = re.sub(r'/\*.*?\*/', '', t, flags=re.S)
    return t

src_funcs = {}
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
                txt = strip_comments('\n'.join(body))
                calls = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', txt))
                calls.discard(name)
                for kw in ('if', 'for', 'while', 'switch', 'return', 'sizeof', 'memset', 'memmove'):
                    calls.discard(kw)
                src_funcs.setdefault(name, {'file': f, 'line': i + 1, 'calls': calls})
                i = p + 1
                continue
        i += 1

print(f'源码函数: {len(src_funcs)}')

# ---------- 2. IDF 权重 ----------
N = len(orig_cg)
df = collections.Counter()
for v in orig_cg.values():
    for c in set(v['callees']):
        df[c] += 1
def idf(c):
    return math.log(N / (1 + df.get(c, 0))) + 0.1

# ---------- 3. 匹配 ----------
def match(orig_name):
    o = orig_cg.get(orig_name)
    if not o:
        return None
    oset = set(o['callees'])
    if not oset:
        return None
    otot = sum(idf(c) for c in oset)
    best, best_score, best_inter = None, 0.0, set()
    for sname, sv in src_funcs.items():
        inter = oset & sv['calls']
        if not inter:
            continue
        # 覆盖率：原始函数被调用者中，有多少（按 idf 加权）能在源码函数里找到
        cov = sum(idf(c) for c in inter) / otot
        # 精确率：源码函数调用集合中被覆盖的比例（鼓励两个集合相似）
        stot = sum(idf(c) for c in sv['calls']) or 1
        prec = sum(idf(c) for c in inter) / stot
        score = cov * 0.7 + prec * 0.3
        if score > best_score:
            best, best_score, best_inter = sname, score, inter
    return best, best_score, best_inter

print()
print('=' * 100)
print('A 类函数调用图匹配结果')
print('=' * 100)
matched, unmatched = [], []
for name, o in sorted(orphans.items(), key=lambda x: -x[1]['size']):
    r = match(name)
    if r and r[1] >= 0.55 and len(r[2]) >= 2:
        matched.append((name, o, r))
    else:
        unmatched.append((name, o, r))

print(f'\n【A-1】调用图匹配到源码函数（= 改名，非缺失）: {len(matched)} 个，'
      f'{sum(o["size"] for _, o, _ in matched):,} 字节')
for name, o, r in matched[:30]:
    best, score, inter = r
    print(f"  {o['size']:5d}B  {name:44s} -> {best:40s} 相似度={score:.2f} 共同={sorted(inter)[:4]}")

print(f'\n【A-2】调用图也匹配不上（= 很可能真缺失）: {len(unmatched)} 个，'
      f'{sum(o["size"] for _, o, _ in unmatched):,} 字节')
for name, o, r in unmatched:
    hint = ''
    if r:
        hint = f' 最佳={r[0]}({r[1]:.2f})'
    print(f"  {o['size']:5d}B  {name:44s}{hint}")

json.dump({'matched': [{'name': n, 'size': o['size'], 'best': r[0], 'score': round(r[1], 3),
                        'shared': sorted(r[2])} for n, o, r in matched],
           'unmatched': [{'name': n, 'size': o['size'],
                          'best': (r[0] if r else None), 'score': (round(r[1], 3) if r else 0)}
                         for n, o, r in unmatched]},
          open(r'build\audit\_audit_match.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\_audit_match.json')
