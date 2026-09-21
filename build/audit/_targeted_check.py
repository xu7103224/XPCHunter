# 用"稀有被调用者"定向定位：对每个弱匹配孤儿，找源码中共享其最稀有被调用者的函数
import json, re, glob, math, collections, os

orig = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))
a_list = json.load(open(r'build\audit\_audit_a.json', encoding='utf-8'))
orphans = {o['name']: o for o in a_list['orphan']}

# 源码函数调用集合
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
                txt = re.sub(r'//[^\n]*', '', '\n'.join(body))
                calls = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', txt))
                calls.discard(name)
                src.setdefault(name, {'file': os.path.basename(f), 'line': i + 1, 'calls': calls})
                i = p + 1
                continue
        i += 1

df = collections.Counter()
for v in orig.values():
    for c in set(v['callees']):
        df[c] += 1

# 源码中被调用者的使用频率
src_df = collections.Counter()
for v in src.values():
    for c in v['calls']:
        src_df[c] += 1

print('=' * 100)
print('用"稀有被调用者"定位弱匹配孤儿')
print('=' * 100)
for name, o in sorted(orphans.items(), key=lambda x: -x[1]['size'])[:30]:
    ov = orig.get(name)
    if not ov:
        continue
    # 该孤儿调用的、在原始中很稀有(df<=30)但在源码中存在的被调用者
    rare = [c for c in ov['callees'] if df[c] <= 30 and src_df.get(c, 0) > 0]
    rare.sort(key=lambda c: df[c])
    if not rare:
        print(f"\n{name} ({o['size']}B): 无稀有共同被调用者 -> 无法判定")
        continue
    # 找出同时调用多个稀有被调用者的源码函数
    scores = collections.Counter()
    for c in rare[:6]:
        for sn, sv in src.items():
            if c in sv['calls']:
                scores[sn] += 1
    top = scores.most_common(4)
    print(f"\n{name} ({o['size']}B)  稀有被调用者: {[(c, df[c]) for c in rare[:6]]}")
    for sn, cnt in top:
        print(f"     命中 {cnt}/{min(6,len(rare))}  -> {sn}  ({src[sn]['file']}:{src[sn]['line']})")
