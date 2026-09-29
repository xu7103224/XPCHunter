# 扫描"空壳占位"：函数体仅 return 常量/空返回，但可能被真实调用
# 判据：
#   1) 函数体（注释与空行除外）只有 1 条语句，且形如 return <数字/常量表达式>;  或 return;
#   2) 统计该函数名在其它文件中的调用次数（排除声明行与定义行）
#   3) 与原始函数体积对照（体积大 = 原本有真实逻辑，却实现成空壳 = 危险占位）
import json
import os
import re

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "..", "XPCHunterDrv"))
SRC = os.path.join(ROOT, "src")

DEF = re.compile(r'^(?:static\s+)?([A-Za-z_][A-Za-z0-9_ \t\*]*?)\s+\**([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{]*)\)\s*$')
STMT = re.compile(r'^\s*(return\b[^;]*;|;)\s*$')
COMMENT = re.compile(r'^\s*(//|/\*|\*)')

funcs = []          # (file, name, start_line, body_size_bytes, ret_stmt)
files = {}
for dp, _, fns in os.walk(SRC):
    for fn in sorted(fns):
        if not fn.endswith(".c"):
            continue
        p = os.path.join(dp, fn)
        files[p] = open(p, encoding="utf-8", errors="replace").read().splitlines()

for p, lines in files.items():
    n = len(lines)
    for i, l in enumerate(lines):
        if l.rstrip().endswith(';') or not l.rstrip().endswith(')'):
            continue
        m = DEF.match(l)
        if not m:
            continue
        ty, name, args = m.group(1), m.group(2), m.group(3)
        # 找函数体
        j = i + 1
        while j < n and not lines[j].strip():
            j += 1
        if j >= n or lines[j].strip() != '{':
            continue
        depth = 0
        stmts = []
        k = j
        while k < n:
            s = lines[k].strip()
            depth += lines[k].count('{') - lines[k].count('}')
            if k > j and s and not COMMENT.match(s) and s not in ('{', '}'):
                stmts.append(s)
            if depth <= 0 and k > j:
                break
            k += 1
        if len(stmts) == 1 and STMT.match(stmts[0]):
            funcs.append((p, name, i + 1, k, stmts[0]))

# 调用者统计
decl_pat = lambda name: re.compile(r'\b' + re.escape(name) + r'\s*\(')
rows = []
for p, name, sline, eline, ret in funcs:
    callers = set()
    for q, qlines in files.items():
        for idx, ql in enumerate(qlines):
            if not decl_pat(name).search(ql):
                continue
            if ql.rstrip().endswith(';'):      # 声明/函数指针
                continue
            if q == p and sline <= idx + 1 <= eline:   # 自身
                continue
            if COMMENT.match(ql):
                continue
            if re.match(r'^\s*(if|while|for|switch|return|else)\b', ql):
                continue
            callers.add(os.path.relpath(q, ROOT))
    rows.append((p, name, ret, sorted(callers)))

# 与原始体积对照
orig = {}
try:
    O = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "_orig_funcs_ida.json"), encoding="utf-8"))
    for it in O:
        orig[it["name"]] = it["size"]
except Exception:
    pass

print("=== 全项目空壳占位（函数体仅 1 条 return，且被其它文件调用）===")
print("%-34s %-8s %-22s %s" % ("函数", "原始B", "函数体", "调用者(文件数)"))
print("-" * 100)
withcall = [r for r in rows if r[3]]
withcall.sort(key=lambda r: -(orig.get(r[1], 0)))
for p, name, ret, callers in withcall:
    sz = orig.get(name)
    print("%-34s %-8s %-22s %d 个: %s" % (
        name, (str(sz) if sz else "?"), ret[:22], len(callers),
        ", ".join(c[:22] for c in callers[:3]) + ("…" if len(callers) > 3 else "")))

print()
print("小计：空壳总数 %d，其中**被其它文件调用**的 %d 个" % (len(rows), len(withcall)))
big = [(n, orig.get(n, 0)) for _, n, _, c in withcall if orig.get(n, 0) >= 300]
print("其中原始体积 >= 300 字节（原本有实逻辑）的 %d 个：" % len(big))
for n, s in sorted(big, key=lambda x: -x[1])[:25]:
    print("   %-40s %d B" % (n, s))