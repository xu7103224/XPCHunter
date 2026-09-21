# 摸清 InitImageNotify (0x1400723ec) 的依赖树，标注各节点在复刻源码中的实现状态
import json, collections

cg = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))

# 源码侧状态
res = json.load(open(r'build\audit\_audit_result.json', encoding='utf-8'))
present = {r['name'] for r in res['present']}          # 源码有同名实现
v2 = json.load(open(r'build\audit\_audit_v2.json', encoding='utf-8'))
ph = {r['name'] for r in v2['placeholder_real']}       # 占位（有同名但函数体是常量）
missing = {r['name'] for r in v2['missing']}           # 无同名实现

def status(n):
    if n in ph: return '占位'
    if n in present: return '已实现'
    if n in missing: return '缺失'
    return '未分类'

ROOT = 'InitImageNotify'
seen = set()
tree = []
def walk(name, depth, out):
    if depth > 3:
        return
    for c in cg.get(name, {}).get('callees', []):
        key = (depth, c)
        if key in seen:
            continue
        seen.add(key)
        sz = cg.get(c, {}).get('size')
        out.append((depth, c, sz, status(c)))
        walk(c, depth + 1, out)

walk(ROOT, 1, tree)

print(f'根: {ROOT} (大小 {cg[ROOT]["size"]}, 直接被调用者 {len(cg[ROOT]["callees"])} 个)')
print(f'展开至深度 3，共 {len(tree)} 个节点\n')
print('=' * 92)
cnt = collections.Counter()
size_by = collections.Counter()
for depth, n, sz, st in tree:
    cnt[st] += 1
    size_by[st] += sz or 0
    print(f"  {'  ' * (depth - 1)}{n:42s} {str(sz) + 'B' if sz else '?':>8s}  [{st}]")
print('=' * 92)
print('汇总:')
for st in ('已实现', '占位', '缺失', '未分类'):
    if cnt[st]:
        print(f'  {st:6s}: {cnt[st]:3d} 个, {size_by[st]:6,} 字节')
print(f'\n>>> 需要新实现的（占位 + 缺失）: {cnt["占位"] + cnt["缺失"]} 个, '
      f'{size_by["占位"] + size_by["缺失"]:,} 字节')
