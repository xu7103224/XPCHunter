# 合并三份分析，得出最终缺口清单
import json

reach = json.load(open(r'build\audit\_audit_reach.json', encoding='utf-8'))
fp = json.load(open(r'build\audit\_audit_fp.json', encoding='utf-8'))
audit = json.load(open(r'build\audit\_audit_v2.json', encoding='utf-8'))

strong = {r['name']: r for r in fp['strong']}
ph = audit['placeholder_real']
ph_real = {r['name']: r for r in ph}
definitely_missing = {r['name']: r for r in reach['definitely_missing']}
need_review = {r['name']: r for r in reach['need_review']}

# 分类
cat_definite = []      # 调用者全是占位/缺失 -> 确定缺失
cat_renamed = []       # 指纹强匹配 -> 改名实现
cat_review = []        # 其余

for name, r in definitely_missing.items():
    cat_definite.append(r)
for name, r in need_review.items():
    if name in strong:
        cat_renamed.append((r, strong[name]))
    else:
        cat_review.append(r)

print('=' * 100)
print('最终缺口清单')
print('=' * 100)
print(f"A. 确定缺失（调用链上游全是占位或缺失）: {len(cat_definite):3d} 个, "
      f"{sum(r['size'] for r in cat_definite):6,} 字节")
print(f"B. 占位函数（源码有同名，但函数体只返回常量）: {len(ph_real):3d} 个, "
      f"{sum(r['size'] for r in ph_real.values()):6,} 字节")
print(f"C. 仅改名（指纹强匹配到其他名字的实现）    : {len(cat_renamed):3d} 个, "
      f"{sum(r['size'] for r, _ in cat_renamed):6,} 字节  <- 不算缺口")
print(f"D. 待人工核对（调用者存在但无强匹配）      : {len(cat_review):3d} 个, "
      f"{sum(r['size'] for r in cat_review):6,} 字节")
print()
A = sum(r['size'] for r in cat_definite)
B = sum(r['size'] for r in ph_real.values())
D = sum(r['size'] for r in cat_review)
print(f"确定缺口（A+B）: {len(cat_definite)+len(ph_real)} 个函数, {A+B:,} 字节 "
      f"= 原始 .text 的 {(A+B)/572282*100:.1f}%")
print(f"加上待核实（D）的上限: {A+B+D:,} 字节 = {(A+B+D)/572282*100:.1f}%")
print()

print('-' * 100)
print('A. 确定缺失（按大小降序，前 50）')
print('-' * 100)
for r in sorted(cat_definite, key=lambda x: -x['size'])[:50]:
    c = r['callers'][0] if r['callers'] else {'name': '?', 'state': '?'}
    print(f"  {r['size']:5d}B  {r['name']:44s} <- {c['name']}[{c['state']}]")

print()
print('-' * 100)
print('D. 待人工核对（按大小降序，前 40）')
print('-' * 100)
for r in sorted(cat_review, key=lambda x: -x['size'])[:40]:
    c = r['callers'][0] if r['callers'] else {'name': '?', 'state': '?'}
    print(f"  {r['size']:5d}B  {r['name']:44s} <- {c['name']}[{c['state']}]")

json.dump({'A_definite_missing': cat_definite, 'B_placeholders': ph,
           'C_renamed': [{'name': r['name'], 'size': r['size'], 'maps_to': s['best'], 'score': s['score']}
                         for r, s in cat_renamed],
           'D_need_review': cat_review},
          open(r'build\audit\_FINAL_GAP.json', 'w', encoding='utf-8'), ensure_ascii=False)
print('\n写入 build\\_FINAL_GAP.json')
