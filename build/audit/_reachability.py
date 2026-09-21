# 决定性判据：A 类孤儿函数的"调用者可达性"
# 若一个函数的全部调用者在复刻里都是占位或同样缺失，则其功能确定不存在
import json, collections

orig = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))
audit = json.load(open(r'build\audit\_audit_v2.json', encoding='utf-8'))
a_list = json.load(open(r'build\audit\_audit_a.json', encoding='utf-8'))

placeholders = {r['name'] for r in audit['placeholder_real']}
missing_set = {r['name'] for r in audit['missing']}
orphans = {o['name']: o for o in a_list['orphan']}
benign = {r['name'] for r in audit['placeholder_benign']}

# 反查调用者
callers = collections.defaultdict(set)
for name, v in orig.items():
    for c in v['callees']:
        callers[c].add(name)

# 源码里有同名实现的函数（含占位）
src_names = placeholders | {r['name'] for r in audit['placeholder_real']}
# 从原 audit 结果读 present 名单
present = {r['name'] for r in json.load(open(r'build\audit\_audit_result.json', encoding='utf-8'))['present']}
src_has = present | placeholders | benign

def classify_caller(c):
    if c in orig:
        if c in placeholders:
            return 'PLACEHOLDER'
        if c in src_has:
            return 'OK'
        if c in orphans or c in missing_set:
            return 'MISSING'
        return 'OK'
    return 'EXTERNAL'

print('=' * 108)
print('A 类孤儿函数的调用者状态（决定其功能是否存在）')
print('=' * 108)
definitely_missing, partially, uncertain = [], [], []
for name, o in sorted(orphans.items(), key=lambda x: -x[1]['size']):
    cs = sorted(callers.get(name, set()))
    if not cs:
        cls = [('(无调用者)', 'EXTERNAL')]
    else:
        cls = [(c, classify_caller(c)) for c in cs]
    labels = [k for _, k in cls]
    if not cs or all(k in ('PLACEHOLDER', 'MISSING', 'EXTERNAL') for k in labels) or \
       (all(k in ('PLACEHOLDER', 'MISSING') for k in labels) and labels):
        definitely_missing.append((name, o, cls))
    elif any(k == 'OK' for k in labels):
        partially.append((name, o, cls))
    else:
        uncertain.append((name, o, cls))

print(f'\n【判定 1】调用者全为占位/缺失 -> 功能确定不存在: {len(definitely_missing)} 个，'
      f'{sum(o["size"] for _, o, _ in definitely_missing):,} 字节')
for name, o, cls in definitely_missing[:45]:
    cs = ', '.join(f'{c}[{k}]' for c, k in cls[:3])
    print(f"  {o['size']:5d}B  {name:44s} 调用者: {cs}")

print(f'\n【判定 2】存在"有同名实现"的调用者 -> 需逐个核对: {len(partially)} 个，'
      f'{sum(o["size"] for _, o, _ in partially):,} 字节')
for name, o, cls in partially[:25]:
    cs = ', '.join(f'{c}[{k}]' for c, k in cls[:3])
    print(f"  {o['size']:5d}B  {name:44s} 调用者: {cs}")

json.dump({'definitely_missing': [{'name': n, 'size': o['size'],
                                   'callers': [{'name': c, 'state': k} for c, k in cls]}
                                  for n, o, cls in definitely_missing],
           'need_review': [{'name': n, 'size': o['size'],
                            'callers': [{'name': c, 'state': k} for c, k in cls]}
                           for n, o, cls in partially]},
          open(r'build\audit\_audit_reach.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\_audit_reach.json')
