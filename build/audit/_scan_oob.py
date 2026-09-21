# 按"实参"而非"名字"扫描 PE 解码相关的栈越界（全项目）
#  1) ReadPESectionEntry 的第 2 实参 = 描述符 SectionInfo，需要 0x120 字节
#  2) InitPESectionReadContext 的第 8 实参 = 解码上下文，需要 0x48 字节
# 对每个实参解析其局部声明的字节大小，小于需求即报越界。
import os
import re

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "..", "XPCHunterDrv", "src"))
BASE = {"__int64": 8, "ULONG64": 8, "unsigned __int64": 8, "char": 1, "_DWORD": 4,
        "DWORD": 4, "ULONG": 4, "int": 4, "unsigned int": 4, "short": 2,
        "_WORD": 2, "BYTE": 1, "UCHAR": 1, "void": 1, "size_t": 8, "SIZE_T": 8, "PE_DECODE_CONTEXT": 72}
FUNC = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
# 声明：  类型 名字 [N] ;  或  类型 名字 ;   或 类型 名字[4] = {..};
DECL = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\[([^\]]*)\])?\s*(=|;)')

DESC = 0x120
CTX = 0x48

report_desc, report_ctx, unresolved = [], [], []


def decls_in(lines, s, e):
    """返回该函数内 名字->字节数 的映射"""
    out = {}
    for k in range(s, min(e + 1, len(lines))):
        m = DECL.match(lines[k])
        if not m:
            continue
        ty, nm, arr = m.group(1).strip(), m.group(2), m.group(4)
        base = None
        for b, sz in sorted(BASE.items(), key=lambda x: -len(x[0])):
            if ty.endswith(b):
                base = sz
                break
        if base is None:
            continue
        n = 1
        if arr is not None:
            a = arr.strip()
            if a and re.fullmatch(r'0x[0-9A-Fa-f]+|\d+', a):
                n = int(a, 0)
            else:
                continue
        out[nm] = (base * n, k + 1, ty + (('[' + arr + ']') if arr else ''))
    return out


for dp, _, fns in os.walk(ROOT):
    for fn in sorted(fns):
        if not fn.endswith(".c"):
            continue
        p = os.path.join(dp, fn)
        rel = os.path.relpath(p, ROOT)
        lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
        # 函数区间
        funcs, depth, cur = [], 0, None
        for i, l in enumerate(lines):
            if depth <= 0:
                m = FUNC.match(l)
                if m and not l.rstrip().endswith(';'):
                    cur = [m.group(1), i, None]
            depth += l.count('{') - l.count('}')
            if cur and cur[2] is None and depth <= 0 and i > cur[1] and '{' in ''.join(lines[cur[1]:i + 1]):
                cur[2] = i
                funcs.append(tuple(cur))
                cur = None
        for name, s, e in funcs:
            e = e or len(lines)
            dm = decls_in(lines, s, e)
            body = lines[s:e + 1]
            for j, l in enumerate(body):
                # ReadPESectionEntry(..., 2nd_arg, ...) 与 Init(..., 8th)
                if "ReadPESectionEntry(" in l:
                    m = re.search(r'ReadPESectionEntry\(\s*\(?[^,]*,\s*([^,]+)', l)
                    idx = 2
                    kind = "desc"
                elif "InitPESectionReadContext(" in l:
                    m = re.search(r'InitPESectionReadContext\(([^;]*)', l, re.S)
                    idx = 8
                    kind = "ctx"
                else:
                    continue
                if not m:
                    continue
                if kind == "desc":
                    arg = m.group(1).strip().rstrip(')')
                else:
                    parts = [x.strip() for x in m.group(1).split(',')]
                    if len(parts) < 8:
                        continue
                    arg = parts[7]
                nm = re.sub(r'^\([^)]*\)', '', arg).strip().lstrip('&').strip()
                nm = nm.strip('()').strip()
                if nm not in dm:
                    unresolved.append((rel, name, idx, arg, lines[s + j].strip()[:60]))
                    continue
                sz, dln, dty = dm[nm]
                need = DESC if kind == "desc" else CTX
                if sz < need:
                    rec = (rel, name, s + j + 1, nm, dty, dln, sz, need)
                    (report_desc if kind == "desc" else report_ctx).append(rec)

print("=" * 100)
print("【一类】描述符（ReadPESectionEntry 第 2 实参）小于 0x%X 字节" % DESC)
print("%-28s %-34s %6s %-16s %8s %6s" % ("文件", "函数", "行", "变量(声明)", "声明行", "字节"))
for r in sorted(set(report_desc), key=lambda x: (x[0], x[2])):
    print("%-28s %-34s %6d %-16s %8d %6d" % (r[0], r[1], r[2], r[3] + ":" + r[4], r[5], r[6]))
print("小计 %d 处" % len(set(report_desc)))

print()
print("=" * 100)
print("【二类】上下文（InitPESectionReadContext 第 8 实参）小于 0x%X 字节" % CTX)
print("%-28s %-34s %6s %-16s %8s %6s" % ("文件", "函数", "行", "变量(声明)", "声明行", "字节"))
for r in sorted(set(report_ctx), key=lambda x: (x[0], x[2])):
    print("%-28s %-34s %6d %-16s %8d %6d" % (r[0], r[1], r[2], r[3] + ":" + r[4], r[5], r[6]))
print("小计 %d 处" % len(set(report_ctx)))

print()
print("未解析到局部声明的实参（可能是参数、全局或成员表达式）：", len(unresolved))
from collections import Counter
for arg, c in Counter(u[3] for u in unresolved).most_common(12):
    print("   %3d x %s" % (c, arg[:70]))
