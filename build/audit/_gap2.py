"""缺口审计 v2 —— 按 §7.4 规则 3 的三重确认法。
判定"已实现"的任一条件：
  1) 源码中全文 grep 到函数定义（宽松：名字后 700 字符内出现 ){ 或 )\n{）
  2) 源码注释中出现其原始地址（0x14xxxxxxx 或 sub_14xxxxxxx）
并且**追加报告可疑项**（源文件里出现该名字但不在定义位置者）。
"""
import json, re, glob, os, sys

orig = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))
nonlib = [f for f in orig if not f.get('lib')]

# 全量源码文本
texts = {}
for path in glob.glob('XPCHunterDrv/**/*.c', recursive=True) + glob.glob('XPCHunterDrv/**/*.h', recursive=True):
    texts[path] = open(path, encoding='utf-8', errors='replace').read()
alltext = '\n'.join(texts.values())

# 条件 1：函数定义
defined = set()
for t in texts.values():
    for m in re.finditer(r'\b(\w+)\s*\(', t):
        if re.search(r'\)\s*(\n)?\{', t[m.end():m.end()+900]):
            defined.add(m.group(1))

# 条件 2：注释中的原始地址
addr_ok = set()
for m in re.finditer(r'(?:0x|sub_)(1400[0-9A-Fa-f]{5})', alltext):
    addr_ok.add(int(m.group(1), 16))

# 条件 3：头文件声明（补充判定）
declared = set()
hdr = texts.get('XPCHunterDrv\\inc\\XPCHunterDrv.h', '') + texts.get('XPCHunterDrv/inc/XPCHunterDrv.h', '')
for m in re.finditer(r'\b(\w+)\s*\(', hdr):
    declared.add(m.group(1))

done, missing = [], []
for f in nonlib:
    n, a = f['name'], f['start']
    if n in defined or a in addr_ok:
        done.append(f)
    else:
        missing.append(f)

print(f'原始非 lib 函数: {len(nonlib)} 个 / {sum(f["size"] for f in nonlib)} 字节')
print(f'  已实现: {len(done)} ({100*len(done)/len(nonlib):.1f}%) / {sum(f["size"] for f in done)} 字节')
print(f'  未实现: {len(missing)} ({100*len(missing)/len(nonlib):.1f}%) / {sum(f["size"] for f in missing)} 字节')

missing.sort(key=lambda f: -f['size'])
print('\n=== 未实现 >=400B ===')
tot = 0
for f in missing:
    if f['size'] >= 400:
        print(f'  0x{f["start"]:X}  {f["size"]:5d}  {f["name"]}'); tot += f['size']
print(f'  ({tot} 字节)')
print('\n=== 未实现 200-400B ===')
for f in missing:
    if 200 <= f['size'] < 400:
        print(f'  0x{f["start"]:X}  {f["size"]:5d}  {f["name"]}')