# 审计：ReadPESectionEntry 的 sink 缓冲区尺寸
# ReadPESectionEntry 无条件 RtlZeroMemory(SectionInfo, 0x120) 并填充至 +0x118，
# 因此每个调用点的 sink 缓冲区必须 >= 0x120 字节。
# 本脚本只做检测（不修改代码）：解析每个调用点的 sink 变量名，
# 再在其所在函数体内查找最接近的声明，计算字节数。
import re, os, sys, glob

ROOT = r'XPCHunterDrv/src'
DECL = re.compile(
    r'^\s*(?:(?:unsigned)\s+)?(?:_DWORD|ULONG|DWORD|UCHAR|BYTE|char|_OWORD)\s+'
    r'([A-Za-z_]\w*)\s*\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]')
CALL = re.compile(r'ReadPESectionEntry\s*\(\s*\(?\s*PUCHAR\s*\)?\s*&?\s*([A-Za-z_]\w*)\s*,\s*&?\s*([A-Za-z_]\w*)')

TYPE_SIZE = {'_DWORD': 4, 'ULONG': 4, 'DWORD': 4, 'UCHAR': 1, 'BYTE': 1,
             'char': 1, '_OWORD': 16}

def funcs_of(lines):
    """按 0 列函数签名切分函数体，返回 (起始行, 结尾行, 名字) 列表。"""
    out = []
    for i, l in enumerate(lines):
        if re.match(r'^[A-Za-z_].*\b([A-Za-z_]\w*)\s*\(', l) and not l.startswith(' '):
            pass
    return out

problems = []
for path in glob.glob(os.path.join(ROOT, '**', '*.c'), recursive=True):
    raw = open(path, 'rb').read().decode('utf-8', 'replace')
    lines = raw.split('\n')
    for m in CALL.finditer(raw):
        sink = m.group(2)
        # 找到本行的行号
        ln = raw[:m.start()].count('\n')
        # 向上找最近的同变量声明
        best = None
        for j in range(ln, max(-1, ln - 900), -1):
            dm = DECL.match(lines[j]) if j < len(lines) else None
            if dm and dm.group(1) == sink:
                n = int(dm.group(2), 0)
                t = lines[j].split()[0] if not lines[j].split()[0] in ('unsigned',) else lines[j].split()[1]
                # 从声明行里取类型关键字
                tk = None
                for k in TYPE_SIZE:
                    if re.search(r'\b' + k + r'\b', lines[j]):
                        tk = k
                        break
                best = (j + 1, n * TYPE_SIZE.get(tk, 4), n, tk, lines[j].strip())
                break
        if best is None:
            continue
        jline, nbytes, n, tk, txt = best
        if nbytes < 0x120:
            problems.append((path.replace('\\', '/'), ln + 1, sink, n, tk, nbytes, jline, txt))

if not problems:
    print('OK: 所有 ReadPESectionEntry sink 均 >= 0x120')
else:
    print(f'发现 {len(problems)} 处 sink 缓冲区 < 0x120：')
    for p in problems:
        print(f'  {p[0]}:{p[1]}  sink={p[2]} [{p[3]}] {p[4]} = {p[5]} 字节  <-- 声明在 :{p[6]}  {p[7]}')