# 审计 v2：改进占位判定 + 为"缺失"函数寻找改名候选
import json, re, glob, collections

orig = json.load(open(r'build\audit\_orig_funcs_ida.json', encoding='utf-8'))

# ---------- 解析源码函数定义与函数体 ----------
src_defs = {}
src_bodies = {}
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    lines = open(f, encoding='utf-8', errors='ignore').read().split('\n')
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip() and not ln.startswith((' ', '\t', '/', '#', '{', '}')) and '(' in ln:
            j = i
            sig = ''
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
                if name not in ('if', 'for', 'while', 'switch', 'return', 'sizeof'):
                    src_defs.setdefault(name, (f, i + 1))
                    depth, body, p = 0, [], k
                    while p < len(lines):
                        depth += lines[p].count('{') - lines[p].count('}')
                        body.append(lines[p])
                        if depth == 0 and p >= k:
                            break
                        p += 1
                    src_bodies[name] = body
                    i = p + 1
                    continue
        i += 1

def body_src(name):
    b = src_bodies.get(name)
    if not b:
        return None, None
    txt = '\n'.join(b)
    txt = re.sub(r'//[^\n]*', '', txt)
    txt = re.sub(r'/\*.*?\*/', '', txt, flags=re.S).strip()
    raw = txt[1:-1].strip() if txt.startswith('{') else txt
    return raw, txt

# 判定：函数体是纯"返回常量/简单标识符"（不含任何函数调用）
def is_placeholder(name):
    raw, _ = body_src(name)
    if raw is None:
        return False
    if raw == '' or raw == 'return;':
        return True
    # 单条 return，且返回值里没有 '(' （即不调用任何函数）
    m = re.fullmatch(r'return\s+([^;]+);', raw)
    if not m:
        return False
    expr = m.group(1)
    if '(' in expr:
        return False
    return True

# ---------- 分类 ----------
LIB = lambda r: r['thunk'] or r['lib'] or r['name'].startswith('_')
present, missing, placeholder = [], [], []
for r in orig:
    if LIB(r):
        continue
    if r['name'] in src_defs:
        present.append(r)
        if is_placeholder(r['name']):
            placeholder.append(r)
    else:
        missing.append(r)

print(f'原始函数总数 {len(orig)}；排除 thunk/库函数 {sum(1 for r in orig if LIB(r))}')
print(f'  同名实现存在        : {len(present)}')
print(f'  同名实现不存在      : {len(missing)}')
print()

# ---------- 【B】占位函数（按原始大小降序） ----------
print('=' * 92)
print(f'【B】函数体是"直接返回常量"的（{len(placeholder)} 个）— 原始大小 >= 16B 的才是真缺陷')
print('=' * 92)
real, benign = [], []
for r in sorted(placeholder, key=lambda x: -x['size']):
    (real if r['size'] >= 16 else benign).append(r)
for r in real:
    f, ln = src_defs[r['name']]
    raw, _ = body_src(r['name'])
    print(f"  {r['size']:6d}B  {r['name']:46s} {f.split(chr(92))[-1]}:{ln}  ->  {raw[:46]}")
print()
print(f'  原始本身也是 3 字节桩（属忠实复刻，非缺陷）: {len(benign)} 个')
for r in benign:
    print(f"       {r['size']:3d}B  {r['name']}")
print(f'  >>> 真正的占位缺陷: {len(real)} 个，涉及原始代码 {sum(r["size"] for r in real):,} 字节')

# ---------- 【A】缺失函数 + 改名候选 ----------
print()
print('=' * 92)
print(f'【A】源码中找不到同名实现的原始函数（{len(missing)} 个）')
print('=' * 92)
names = list(src_defs.keys())
def candidates(n):
    out = []
    for s in names:
        if s == n:
            continue
        # 去掉 Ex/V2/V3/2/3 等后缀再比
        a = re.sub(r'(Ex|V\d|\d)$', '', n)
        b = re.sub(r'(Ex|V\d|\d)$', '', s)
        if a == b or (len(a) > 6 and (a in b or b in a)):
            out.append(s)
    return out[:3]

rows = []
for r in sorted(missing, key=lambda x: -x['size']):
    cand = candidates(r['name'])
    rows.append((r, cand))
    mark = ('  候选: ' + ', '.join(cand)) if cand else '  (无相近名称)'
    print(f"  {r['size']:6d}B  {r['name']:48s} {r['start']:#x}{mark}")

no_cand = [r for r, c in rows if not c]
print()
print(f'  >>> 无任何相近命名的: {len(no_cand)} 个，涉及原始代码 {sum(r["size"] for r in no_cand):,} 字节')

json.dump({'placeholder_real': real, 'placeholder_benign': benign,
           'missing': [{'name': r['name'], 'size': r['size'], 'start': hex(r['start']),
                        'candidates': c} for r, c in rows]},
          open(r'build\audit\_audit_v2.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n结果已写入 build\\_audit_v2.json')
