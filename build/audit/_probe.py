"""探测未实现函数的可反编译性（计划中"多数可反编译"声明的核实）。
用法: python build/audit/_probe.py
"""
import json, re, glob

orig = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))
texts = {}
for path in glob.glob('XPCHunterDrv/**/*.c', recursive=True) + glob.glob('XPCHunterDrv/**/*.h', recursive=True):
    texts[path] = open(path, encoding='utf-8', errors='replace').read()
alltext = '\n'.join(texts.values())
defined = set()
for t in texts.values():
    for m in re.finditer(r'\b(\w+)\s*\(', t):
        if re.search(r'\)\s*(\n)?\{', t[m.end():m.end()+900]):
            defined.add(m.group(1))
addr_ok = set(int(m.group(1), 16) for m in re.finditer(r'(?:0x|sub_)(1400[0-9A-Fa-f]{5})', alltext))
missing = [f for f in orig if not f.get('lib') and f['name'] not in defined and f['start'] not in addr_ok]

# 生成待探测清单（地址, 名, 大小）
json.dump([{'addr': f['start'], 'name': f['name'], 'size': f['size']} for f in missing],
          open('build/audit/_missing_list.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(f'已写出 {len(missing)} 个待探测函数到 _missing_list.json')
print('前 6 个:')
for f in sorted(missing, key=lambda x: -x['size'])[:6]:
    print(f"  0x{f['start']:X}  {f['size']:5d}  {f['name']}")
