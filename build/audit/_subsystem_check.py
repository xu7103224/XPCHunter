# 精确统计"真正的 InitKernelMemoryContext (0x14006BF2C)" 子树的实现状态
import json, re, glob, os

orig = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))
audit = json.load(open(r'build\audit\_audit_v2.json', encoding='utf-8'))
gap = json.load(open(r'build\audit\_FINAL_GAP.json', encoding='utf-8'))

placeholders = {r['name'] for r in audit['placeholder_real']}
A_missing = {r['name'] for r in gap['A_definite_missing']}
D_review = {r['name'] for r in gap['D_need_review']}

# 源码中存在的函数名
src_names = set()
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    for m in re.finditer(r'^[A-Za-z_][A-Za-z0-9_ \*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', open(f, encoding='utf-8', errors='ignore').read(), re.M):
        src_names.add(m.group(1))

root = 'InitKernelMemoryContext'
rv = orig.get(root)
print(f'原始 {root}: {rv["size"]}B, {len(rv["callees"])} 个被调用者')
print()
# 递归展开
seen = set()
def walk(name, depth=0, out=None):
    if out is None:
        out = []
    if name in seen or depth > 2:
        return out
    seen.add(name)
    v = orig.get(name)
    if not v:
        return out
    out.append((depth, name, v['size']))
    for c in v['callees']:
        walk(c, depth + 1, out)
    return out

tree = walk(root)
print(f'子树共 {len(tree)} 个函数（含自身，深度<=2）')
tot = sum(s for _, _, s in tree)
print(f'合计 {tot:,} 字节')
print()
print(f"{'状态':<12} {'大小':>7}  函数")
print('-' * 78)
stat_count = {'占位': 0, '确定缺失': 0, '待核对': 0, '源码有': 0}
stat_size = {'占位': 0, '确定缺失': 0, '待核对': 0, '源码有': 0}
for depth, name, size in tree:
    if name in placeholders:
        st = '占位'
    elif name in A_missing:
        st = '确定缺失'
    elif name in D_review:
        st = '待核对'
    elif name in src_names:
        st = '源码有'
    else:
        st = '确定缺失'
    stat_count[st] += 1
    stat_size[st] += size
    print(f"{st:<12} {size:>7}  {'  ' * depth}{name}")
print()
print('汇总:')
for k in stat_count:
    print(f'  {k:<8}: {stat_count[k]:3d} 个, {stat_size[k]:6,} 字节')

print()
print(f'>>> 其中"占位 + 确定缺失 + 待核对"（即该子系统未实现部分）: '
      f'{stat_count["占位"]+stat_count["确定缺失"]+stat_count["待核对"]} 个, '
      f'{stat_size["占位"]+stat_size["确定缺失"]+stat_size["待核对"]:,} 字节')
