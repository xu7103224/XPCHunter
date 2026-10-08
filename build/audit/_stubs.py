import re, glob, os, sys

sus = []
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    t = open(f, encoding='utf-8', errors='replace').read()
    lines = t.split('\n')
    i = 0
    while i < len(lines):
        m = re.match(r'^(?:static\s+)?(?:__int64|char|void|bool|unsigned int|ULONG64|NTSTATUS|int|ULONG|BOOLEAN|PVOID|_DWORD \*|ULONG_PTR|PWSTR)\s+(?:__fastcall\s+)?(\w+)\s*\(', lines[i])
        if m:
            name = m.group(1)
            j = i
            while j < len(lines) and '{' not in lines[j]:
                j += 1
            if j < len(lines):
                k = j; depth = 0; body = []
                while k < len(lines):
                    depth += lines[k].count('{') - lines[k].count('}')
                    body.append(lines[k])
                    if depth <= 0 and k > j:
                        break
                    k += 1
                b = '\n'.join(body)
                stmts = [l.strip() for l in body if l.strip() and not l.strip().startswith('//')
                         and l.strip() not in ('{', '}')]
                real = [s for s in stmts if not re.match(
                    r'^(?:unsigned |signed )?(?:int|char|void|bool|__int64|ULONG|ULONG64|NTSTATUS|BOOLEAN|PVOID|_OWORD|_DWORD|WORD|BYTE|struct |P\w+)\b[^=;]*$', s)]
                if len(real) <= 2 and re.search(r'return\s+(0|1|STATUS_SUCCESS|-1|Result)\s*;', b):
                    sus.append((os.path.basename(f), name, len(body), real[:3]))
        i += 1

print(f'可疑空壳 {len(sus)} 个：')
for f, n, ln, st in sus:
    print(f'  {f}:{n}  体{ln}行  {st}')