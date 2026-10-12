# 审计：PE_DECODE_CONTEXT 上下文缓冲区尺寸
# PE_DECODE_CONTEXT 为 0x48 字节（由 InitPESectionReadContext / ReadPESectionEntry
# 的反汇编访问偏移并集定案）。任何传给 InitPESectionReadContext 的上下文变量
# 若小于 0x48 字节，即为栈越界。
import re, os, glob

ROOT = r'XPCHunterDrv/src'
DECL = re.compile(
    r'^\s*(?:static\s+)?(?:(?:unsigned)\s+)?'
    r'(_DWORD|ULONG|DWORD|UCHAR|BYTE|char|_OWORD|PE_DECODE_CONTEXT|__int64|LONG64|_QWORD|ULONG64|int)\s+'
    r'([A-Za-z_]\w*)\s*(\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\])?\s*;')
CALL = re.compile(r'InitPESectionReadContext\s*\(')
TYPE_SIZE = {'_DWORD': 4, 'ULONG': 4, 'DWORD': 4, 'UCHAR': 1, 'BYTE': 1, 'char': 1,
             '_OWORD': 16, 'PE_DECODE_CONTEXT': 0x48, '__int64': 8, 'LONG64': 8,
             '_QWORD': 8, 'ULONG64': 8, 'int': 4}

problems = []
for path in glob.glob(os.path.join(ROOT, '**', '*.c'), recursive=True):
    raw = open(path, 'rb').read().decode('utf-8', 'replace')
    lines = raw.split('\n')
    for m in CALL.finditer(raw):
        ln = raw[:m.start()].count('\n')
        # 取这次调用的实参文本（到匹配括号）
        i = m.end(); depth = 1; start = i
        while i < len(raw) and depth:
            if raw[i] == '(': depth += 1
            elif raw[i] == ')': depth -= 1
            i += 1
        args = raw[start:i-1]
        last = args.rsplit(',', 1)[-1]
        vm = re.search(r'&?\s*([A-Za-z_]\w*)\s*$', last.strip())
        if not vm:
            continue
        ctx = vm.group(1)
        best = None
        for j in range(ln, max(-1, ln - 900), -1):
            dm = DECL.match(lines[j]) if j < len(lines) else None
            if dm and dm.group(2) == ctx:
                n = int(dm.group(3 or 0).strip('[] ') or '1', 0) if (dm.group(3)) else 1
                best = (j + 1, n * TYPE_SIZE.get(dm.group(1), 4), dm.group(1), dm.group(3), lines[j].strip())
                break
        if best is None:
            continue
        jline, nbytes, tk, dim, txt = best
        if nbytes < 0x48:
            problems.append((path.replace('\\', '/'), ln + 1, ctx, tk, dim, nbytes, jline, txt))

if not problems:
    print('OK: 所有 PE_DECODE_CONTEXT 均 >= 0x48')
else:
    print(f'发现 {len(problems)} 处上下文缓冲区 < 0x48：')
    for p in problems:
        print(f'  {p[0]}:{p[1]}  ctx={p[2]} {p[3]} {p[4] or ""} = {p[5]} 字节  <-- 声明在 :{p[6]}  {p[7]}')