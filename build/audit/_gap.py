"""重算当前缺口清单（可重跑）。
判定：名字命中(宽松函数体) 或 地址命中(注释中提及) 即视为已实现。
用法: python build/audit/_gap.py [--min-size N]
"""
import json,re,glob,sys
orig=json.load(open('build/audit/_orig_funcs_ida.json',encoding='utf-8'))
addr_ok=set(); bodies=set()
for path in glob.glob('XPCHunterDrv/src/**/*.c',recursive=True):
    t=open(path,encoding='utf-8',errors='replace').read()
    for m in re.finditer(r'0x(1400[0-9A-Fa-f]{5})',t): addr_ok.add(int(m.group(1),16))
    for m in re.finditer(r'sub_(1400[0-9A-Fa-f]{5})',t): addr_ok.add(int('0x'+m.group(1),16))
    for m in re.finditer(r'\b(\w+)\s*\(',t):
        if re.search(r'\)\s*(\n)?\{',t[m.end():m.end()+700]): bodies.add(m.group(1))
mine=int(sys.argv[sys.argv.index('--min-size')+1]) if '--min-size' in sys.argv else 0
real=[(f['size'],f['name'],f['start']) for f in orig
      if not f.get('lib') and f['name'] not in bodies and f['start'] not in addr_ok]
real.sort(reverse=True)
sel=[r for r in real if r[0]>=mine]
print(f'真缺口 {len(real)} 个 / {sum(s for s,_,_ in real)} 字节')
print(f'(>= {mine}B: {len(sel)} 个 / {sum(s for s,_,_ in sel)} 字节)')
for s,n,a in sel: print(f'  0x{a:X}  {s:6d}  {n}')
