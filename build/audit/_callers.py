# 统计源码中 InitPESectionReadContext / ReadPESectionEntry 的调用者
import re, glob, collections, os

TARGETS = ['InitPESectionReadContext', 'ReadPESectionEntry']
calls = {t: collections.defaultdict(list) for t in TARGETS}

for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    base = os.path.basename(f)
    lines = open(f, encoding='utf-8', errors='ignore').read().split('\n')
    cur = '?'
    for i, ln in enumerate(lines):
        if ln.strip() and not ln.startswith((' ', '\t', '/', '#', '{', '}')):
            m = re.match(r'^[A-Za-z_][A-Za-z0-9_ \*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', ln)
            if m:
                cur = m.group(1)
        for t in TARGETS:
            if t + '(' in ln and not ln.strip().startswith('//'):
                s = ln.strip()
                if s.startswith('extern') or s.rstrip().endswith(';'):
                    continue
                if re.match(r'^[A-Za-z_].*\b' + t + r'\s*\(', ln) and '(' in ln and ln.rstrip().endswith(')'):
                    continue  # 定义行
                calls[t][cur].append(f'{base}:{i+1}')

for t in TARGETS:
    print(f'=== {t}: 被 {len(calls[t])} 个函数调用')
    for k, v in sorted(calls[t].items(), key=lambda x: -len(x[1])):
        print(f'  {len(v):3d} 次  {k:46s} 例: {v[0]}')
    print()
