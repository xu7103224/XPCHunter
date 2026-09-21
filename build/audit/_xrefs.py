# 查引用：列出指向给定地址的代码引用（被调用方 → 调用方）
# 用法: python _xrefs.py 0x1400731F4 [0x地址2 ...]
import json
import os
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)

import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")

targets = [int(a, 16) for a in sys.argv[1:]]
orig = json.load(open(os.path.join(ROOT, "build", "audit", "_orig_funcs_ida.json"), encoding="utf-8"))
byname = {}
for it in orig:
    byname[it["start"]] = it["name"]


def owner(ea):
    """返回包含该地址的函数名与起始地址"""
    f = ida_funcs.get_func(ea)
    if not f:
        return ("<无>", 0)
    return (byname.get(f.start_ea, ida_funcs.get_func_name(f.start_ea) or "<未命名>"), f.start_ea)


idapro.open_database(I64, True)

import ida_funcs, idautils, idc  # noqa: E402

for t in targets:
    print("=== 引用 0x%X ===" % t)
    for x in idautils.XrefsTo(t):
        nm, st = owner(x.frm)
        print("  0x%X  %s  (函数 %s @0x%X)" % (x.frm, idc.generate_disasm_line(x.frm, 0).strip(), nm, st))

idapro.close_database()
