"""按簇统计未实现函数（供计划审计用）。
用法: python build/audit/_cluster.py
"""
import json, re, glob, sys

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

CLUSTERS = [
    ('WFP/KFD/NSI', r'^(Scan(Kfd|Wfp|Nsi)|Find(Kfd|Wfp|Nsi))'),
    ('VAD', r'^(Scan(Process)?Vad|EnumProcessObjectTypes|EnumerateVad)'),
    ('Minifilter', r'^(EnumMiniFilter|OpenMiniFilter)'),
    ('Debug', r'^(ParseNtDebug|ParseRsds)'),
    ('StorPort/USB', r'^(ParseStorPort|ParseUSBPort)'),
    ('PE/映射扫描', r'^(EnumerateFileMapping|ScanPESection|ParseNtSectionHeaders)'),
]
print(f'未实现总数: {len(missing)} 个 / {sum(f["size"] for f in missing)} 字节\n')
used = set()
for label, pat in CLUSTERS:
    rx = re.compile(pat)
    hit = [f for f in missing if rx.search(f['name'])]
    used |= {f['name'] for f in hit}
    print(f'{label:<16} {len(hit):3d} 个 / {sum(f["size"] for f in hit):6d} 字节')
    for f in sorted(hit, key=lambda x: -x['size']):
        print(f'      {f["size"]:5d}  {f["name"]}')

rest = [f for f in missing if f['name'] not in used]
print(f'\n其余 {len(rest)} 个 / {sum(f["size"] for f in rest)} 字节:')
for f in sorted(rest, key=lambda x: -x['size']):
    print(f'      {f["size"]:5d}  {f["name"]}')