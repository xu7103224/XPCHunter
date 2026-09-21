# 反汇编导出工具：按函数名从原始 .i64 导出反汇编（供人工逆向阅读）
# 用法: python _dump2.py <FuncName> [FuncName2 ...]
import json
import sys
import os

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)

import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")
OUT = os.path.join(ROOT, "build", "audit", "_dump")

names = sys.argv[1:]
orig = json.load(open(os.path.join(ROOT, "build", "audit", "_orig_funcs_ida.json"), encoding="utf-8"))
if isinstance(orig, dict):
    items = [{"name": k, "ea": v} if not isinstance(v, dict) else dict(v, name=k) for k, v in orig.items()]
else:
    items = orig

os.makedirs(OUT, exist_ok=True)
idapro.open_database(I64, True)

import ida_funcs, ida_lines, ida_bytes, idc, idautils, ida_hexrays  # noqa: E402

for nm in names:
    cands = [it for it in items if it.get("name") == nm]
    if not cands:
        print("NOT FOUND:", nm)
        continue
    ea = cands[0].get("start") or cands[0].get("ea") or cands[0].get("addr")
    f = ida_funcs.get_func(ea)
    if not f:
        print("NO FUNC:", nm, hex(ea))
        continue
    lines = []
    lines.append("# %s  ea=0x%X  size=%d" % (nm, f.start_ea, f.end_ea - f.start_ea))
    for h in idautils.Heads(f.start_ea, f.end_ea):
        lines.append("0x%X: %s" % (h, ida_lines.tag_remove(idc.generate_disasm_line(h, 0))))
    txt = "\n".join(lines)
    p = os.path.join(OUT, nm + ".asm")
    open(p, "w", encoding="utf-8").write(txt)
    print("OK", nm, hex(f.start_ea), f.end_ea - f.start_ea, p)

idapro.close_database()
