# 用「被调用函数集 + 立即数常量集」双指纹匹配 A 类函数（常量含全局表索引，区分度强）
import json, re, glob, os, math, collections

orig = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))
a_list = json.load(open(r'build\audit\_audit_a.json', encoding='utf-8'))
orphans = {o['name']: o for o in a_list['orphan']}

# ---------- 1. 解析 GT 枚举名 -> 数值 ----------
gt_env = {}
for hf in glob.glob('XPCHunterDrv/inc/*.h'):
    for m in re.finditer(r'\b(Gt[A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', open(hf, encoding='utf-8', errors='ignore').read()):
        try:
            gt_env[m.group(1)] = int(m.group(2), 0)
        except ValueError:
            pass
print(f'GT 枚举名: {len(gt_env)}')

def eval_const(expr):
    e = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\b', lambda m: str(gt_env.get(m.group(0), 'X')), expr)
    if 'X' in e or not re.fullmatch(r'[0-9a-fA-FxX\s\+\-\*\|\(\)]*', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
        return int(v)
    except Exception:
        return None

# ---------- 2. 源码函数指纹 ----------
def strip_comments(t):
    t = re.sub(r'//[^\n]*', '', t)
    return re.sub(r'/\*.*?\*/', '', t, flags=re.S)

src = {}
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
                for kw in ('if', 'for', 'while', 'switch', 'return', 'sizeof'):
                    calls.discard(kw)
                # GT 取值参数
                consts = set()
                for mm in re.finditer(r'Gt(?:Read|Write)\(\s*([^,\)]+)', txt):
                    v = eval_const(mm.group(1))
                    if v is not None and 0 < v < 0x100000:
                        consts.add(v)
                # 其它字面量
                for mm in re.finditer(r'\b(0x[0-9A-Fa-f]{2,6})\b', txt):
                    try:
                        v = int(mm.group(1), 16)
                        if 0 < v < 0x100000:
                            consts.add(v)
                    except ValueError:
                        pass
                src.setdefault(name, {'file': f, 'line': i + 1, 'calls': calls, 'consts': consts})
                i = p + 1
                continue
        i += 1
print(f'源码函数: {len(src)}')

# ---------- 3. IDF ----------
N = len(orig)
df_c, df_k = collections.Counter(), collections.Counter()
for v in orig.values():
    for c in set(v['callees']):
        df_c[c] += 1
    for k in set(v['consts']):
        df_k[k] += 1
idf_c = lambda c: math.log(N / (1 + df_c.get(c, 0))) + 0.05
idf_k = lambda k: math.log(N / (1 + df_k.get(k, 0))) + 0.05

# ---------- 4. 匹配 ----------
def match(name):
    o = orig.get(name)
    if not o:
        return None
    oc, ok = set(o['callees']), set(o['consts'])
    if not oc and not ok:
        return None
    oc_w = sum(idf_c(c) for c in oc)
    ok_w = sum(idf_k(k) for k in ok)
    best, best_score, info = None, 0.0, {}
    for sname, sv in src.items():
        ic, ik = oc & sv['calls'], ok & sv['consts']
        sc = (sum(idf_c(c) for c in ic) / oc_w) if oc_w else 0
        sk = (sum(idf_k(k) for k in ik) / ok_w) if ok_w else 0
        # 常量权重更高（全局表索引是强特征）
        cov = 0.35 * sc + 0.65 * sk
        spc = (sum(idf_k(k) for k in ik) / (sum(idf_k(k) for k in sv['consts']) or 1)) if ok_w else 0
        score = cov * 0.75 + spc * 0.25
        if score > best_score:
            best, best_score, info = sname, score, {'shared_consts': sorted(ik), 'shared_calls': sorted(ic)}
    return best, best_score, info

rows = []
for name, o in orphans.items():
    r = match(name)
    rows.append((name, o, r))
rows.sort(key=lambda x: -x[1]['size'])

STRONG = 0.55
strong = [r for r in rows if r[2] and r[2][1] >= STRONG]
weak = [r for r in rows if not (r[2] and r[2][1] >= STRONG)]
print()
print('=' * 104)
print(f'【A-1】强匹配（判定为"同函数不同名"）: {len(strong)} 个，{sum(o["size"] for _, o, _ in strong):,} 字节')
print('=' * 104)
for name, o, r in strong:
    best, score, info = r
    sc = info['shared_consts'][:6]
    print(f"  {o['size']:5d}B  {name:40s} -> {best:38s} {score:.2f}  共同常量={sc}")

print()
print('=' * 104)
print(f'【A-2】匹配不足（很可能真缺失）: {len(weak)} 个，{sum(o["size"] for _, o, _ in weak):,} 字节')
print('=' * 104)
for name, o, r in weak:
    hint = f"  最佳={r[0]}({r[1]:.2f}) 常量交={len(r[2]['shared_consts'])}" if r else ''
    print(f"  {o['size']:5d}B  {name:44s}{hint}")

json.dump({'strong': [{'name': n, 'size': o['size'], 'best': r[0], 'score': round(r[1], 3),
                       'shared_consts': r[2]['shared_consts']} for n, o, r in strong],
           'weak': [{'name': n, 'size': o['size'], 'best': (r[0] if r else None),
                     'score': (round(r[1], 3) if r else 0),
                     'shared_consts': (r[2]['shared_consts'] if r else [])} for n, o, r in weak]},
          open(r'build\audit\_audit_fp.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\_audit_fp.json')
