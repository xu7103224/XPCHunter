# 对 SsdtHook.c 中所有"疑似 PE 解码上下文"变量逐处定性
# 判据：
#   A. 真上下文  —— 其地址被传给 InitPESectionReadContext，且自身不被从内存赋值
#   B. 表元素    —— 被从内存赋值（= p[i] / = *( ... )），且地址未被传给初始化函数
#   C. 别名      —— 两种特征同时具备（尺寸与读指针语义需一起处理）
#   D. 待人工看  —— 两者都不明显
import os
import re
import sys

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                    "XPCHunterDrv", "src", "services", "SsdtHook.c")
PATH = os.path.normpath(PATH)

NAMES = ("ReadContext", "ReadCtx", "ReadCtx2", "ReadCtx3", "SectionContext",
         "SectionReadContext", "PESectionContext", "PeContext")
DECL = re.compile(r'^\s*(?:__int64|ULONG64|char|_DWORD|_QWORD)\s+(.*?);')
FUNC = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')

lines = open(PATH, encoding="utf-8", errors="replace").read().splitlines()

# 1) 划分函数区间
funcs = []          # (name, start_idx, end_idx)
depth = 0
cur = None
for i, l in enumerate(lines):
    if depth <= 0:
        m = FUNC.match(l)
        if m and not l.rstrip().endswith(';'):
            cur = [m.group(1), i, None]
    depth += l.count('{') - l.count('}')
    if cur and cur[2] is None and depth <= 0 and '{' in ''.join(lines[cur[1]:i + 1]):
        if i > cur[1]:
            cur[2] = i
            funcs.append(tuple(cur))
            cur = None


def enclosing(idx):
    for name, s, e in funcs:
        if s <= idx <= (e if e is not None else len(lines)):
            return name
    return "<未识别>"


# 2) 收集声明
targets = []        # (line_no, name, decl_text, func_name)
for i, l in enumerate(lines):
    m = DECL.match(l)
    if not m:
        continue
    m2 = re.match(r'^\s*(?:__int64|ULONG64|char|_DWORD|_QWORD)\s+(.*?)(\s*=[^;]*)?;', l)
    if not m2:
        continue
    for part in m2.group(1).split(','):
        toks = part.strip().split()
        if not toks:
            continue
        nm = toks[-1].split('[')[0]
        if nm in NAMES:
            targets.append((i + 1, nm, l.strip(), enclosing(i)))

# 3) 逐个定性
print("SsdtHook.c 共 %d 处候选声明，涉及 %d 个函数\n" % (len(targets), len(funcs)))
rows = []
for ln, nm, decl, fn in targets:
    fs, fe = next(((s, e) for n, s, e in funcs if n == fn), (0, len(lines)))
    body = "\n".join(lines[fs:(fe or len(lines)) + 1])
    is_ctx = ("InitPESectionReadContext(" in body and
              re.search(r'&\s*' + nm + r'\b', body) is not None and
              re.search(r'InitPESectionReadContext\([^;]*&\s*' + nm + r'\b', body, re.S) is not None)
    # 用作 ReadPESectionEntry 的上下文
    is_desc_ctx = re.search(r'ReadPESectionEntry\(\(PUCHAR\)&\s*' + nm + r'\b', body) is not None
    # 从内存取值（表元素特征）
    is_elem = re.search(r'\b' + nm + r'\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\[', body) is not None \
        or re.search(r'\b' + nm + r'\s*=\s*\*\(', body) is not None \
        or re.search(r'\b' + nm + r'\s*=\s*[_A-Za-z][A-Za-z0-9_]*\s*->', body) is not None
    # 被直接当上下文用（不含 &）
    bare_ctx = re.search(r'ReadPESectionEntry\(\(PUCHAR\)' + nm + r'\b', body) is not None
    if is_ctx or is_desc_ctx:
        verdict = "A 真上下文→改尺寸" if not is_elem else "C 别名→尺寸+语义"
    elif is_elem:
        verdict = "B 表元素→改名"
    else:
        verdict = "D 待人工看"
    rows.append((ln, fn, nm, verdict, decl, "&" if (is_ctx or is_desc_ctx) else ("裸" if bare_ctx else "")))

w = max(len(r[1]) for r in rows) if rows else 10
print("%-6s %-*s %-14s %-22s %s" % ("行号", w, "所在函数", "变量", "定性", "声明"))
print("-" * (w + 60))
for ln, fn, nm, verdict, decl, mark in rows:
    print("%-6d %-*s %-14s %-22s %s" % (ln, w, fn, nm, verdict, decl))

from collections import Counter
print()
for k, v in Counter(r[3] for r in rows).most_common():
    print("  %-22s %d 处" % (k, v))
