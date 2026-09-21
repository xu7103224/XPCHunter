# 全局检查：原始驱动使用的常量（含 PE 节类型标记等特征值）在复刻源码中的覆盖率
import json, re, glob, collections

orig = json.load(open(r'build\audit\_orig_fingerprint.json', encoding='utf-8'))

# 原始所有函数的常量并集 + 每个常量被多少函数使用
df = collections.Counter()
for v in orig.values():
    for c in set(v['consts']):
        df[c] += 1

# 源码常量集合
gt_env = {}
for hf in glob.glob('XPCHunterDrv/inc/*.h'):
    for m in re.finditer(r'\b(Gt[A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', open(hf, encoding='utf-8', errors='ignore').read()):
        gt_env[m.group(1)] = int(m.group(2), 0)

src_consts = set()
src_text = ''
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    t = open(f, encoding='utf-8', errors='ignore').read()
    src_text += t
    for m in re.finditer(r'\b(0x[0-9A-Fa-f]+|\d{2,})\b', t):
        try:
            v = int(m.group(1), 0)
            if 0 < v < 0x100000:
                src_consts.add(v)
        except ValueError:
            pass
# GT 别名解析出的数值也算
for m in re.finditer(r'\b(Gt[A-Za-z0-9_]+)\b', src_text):
    v = gt_env.get(m.group(1))
    if v is not None:
        src_consts.add(v)

print(f'原始常量（去重）: {len(df)}')
print(f'源码常量（去重）: {len(src_consts)}')
print()

# 按"稀有度"分层看覆盖率：越稀有越能代表独特功能
buckets = [(1, 1, '仅 1 个函数使用（最独特）'),
           (2, 3, '2-3 个函数使用'),
           (4, 10, '4-10 个函数'),
           (11, 50, '11-50 个函数'),
           (51, 10**9, '>50 个函数（通用常量）')]
for lo, hi, label in buckets:
    cs = [c for c, n in df.items() if lo <= n <= hi]
    hit = [c for c in cs if c in src_consts]
    pct = len(hit) / len(cs) * 100 if cs else 0
    print(f'  {label:28s}: {len(hit):5d}/{len(cs):5d} = {pct:5.1f}%')

# 列出最独特且复刻中"缺失"的常量（可能是未实现功能的强信号）
rare_missing = sorted([c for c, n in df.items() if n <= 3 and c not in src_consts],
                      key=lambda c: df[c])
print()
print(f'原始中稀有(<=3 个函数用)但源码完全找不到的常量: {len(rare_missing)} 个')
print('样例（十进制, 十六进制, 使用它的函数）:')
for c in rare_missing[:25]:
    users = [k for k, v in orig.items() if c in set(v['consts'])][:3]
    print(f'  {c:6d} ({c:#x})  用于: {", ".join(users)}')
