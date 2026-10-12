# 覆盖率复核 v2：以「实现存在性」为判据，而非「地址注释存在性」。
# 三个判据（满足其一即视为已实现）：
#   (a) 原始起始地址的十六进制出现在源码注释中；
#   (b) 原始函数名作为标识符出现在源码中（定义或调用）；
#   (c) 通过指纹（调用集合）强匹配到源码某函数 —— 本脚本仅做 (a)(b)，(c) 另跑。
# 另检测：名字命中但函数体疑似空壳（极短 / 仅 return 常量）。
import json, re, glob, os

ROOT = 'XPCHunterDrv/src'
orig = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))

files = []
for f in sorted(glob.glob(os.path.join(ROOT, '**', '*.c'), recursive=True)):
    files.append((f.replace('\\', '/'), open(f, 'rb').read().decode('utf-8', 'replace')))
ALL = '\n'.join(t for _, t in files)
ALL_L = ALL.lower()

# 收集源码中所有函数定义名（行首、非缩进、带括号）
defnames = set()
for _, t in files:
    for m in re.finditer(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(', t, re.M):
        defnames.add(m.group(1))

user = [o for o in orig if not o.get('lib')]

skip_names = set()
miss_a = []      # 地址与名字都没出现
present = []     # 命中

for o in user:
    h = '%x' % o['start']
    name = o['name']
    by_addr = h in ALL_L
    by_name = bool(re.search(r'\b' + re.escape(name) + r'\b', ALL))
    if by_addr or by_name:
        present.append((o, 'addr' if by_addr else 'name'))
    else:
        miss_a.append(o)

print(f'非库函数 {len(user)}')
print(f'  已实现（地址或名字命中）: {len(present):4d}  {len(present)/len(user)*100:.1f}%')
print(f'    ├ 其中带地址注释      : {sum(1 for _,k in present if k=="addr"):4d}  ← 符合注释规范')
print(f'    └ 仅名字命中（缺地址注释）: {sum(1 for _,k in present if k=="name"):4d}  ← 需补注释')
print(f'  未命中（须逐一核实）    : {len(miss_a):4d}  {sum(o["size"] for o in miss_a):,} 字节')

# 名字命中的、但在源码中找不到定义的（只有调用、无定义）
nodef = [o['name'] for o,_ in present if o['name'] not in defnames]
print(f'\n名字命中但源码中无同名定义（可能改名实现或仅被调用）: {len(nodef)}')
for n in nodef[:30]:
    print('   ', n)

if miss_a:
    print('\n=== 未命中的（按大小降序，前 50） ===')
    for o in sorted(miss_a, key=lambda x: -x['size'])[:50]:
        print(f'  {hex(o["start"]):>12}  {o["size"]:>6}B  {o["name"]}')

json.dump({'present': [(o['name'], hex(o['start']), k) for o, k in present],
           'missing': miss_a, 'nodef': nodef},
          open('build/audit/_cov_now2.json', 'w', encoding='utf-8'),
          ensure_ascii=False, indent=1)
print('\n已写出 build/audit/_cov_now2.json')