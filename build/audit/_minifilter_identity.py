# 批量提取 Minifilter.c 中所有 MiniFilter* 函数在**原始 IDA** 中的真实签名与首行功能注释
# 用于建立"名字 ↔ 真实功能"对照表（改名依据）
import json
import os
import re
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")
SRC = os.path.join(ROOT, "XPCHunterDrv", "src", "kernel", "Minifilter.c")

O = {x["name"]: x for x in json.load(open(os.path.join(ROOT, "build", "audit", "_orig_funcs_ida.json"), encoding="utf-8"))}

# 从源码取函数名 -> 注释里的原始地址
txt = open(SRC, encoding="utf-8", errors="replace").read()
pairs = []  # (源码名, 原始地址)
for m in re.finditer(r'//\s*(MiniFilter\w+)\s*—[^\n]*\n(?://[^\n]*\n)*?[^\n]*\n?', txt):
    pass
# 更简单：直接扫描"// <name> — ... 对应原始驱动 <addr>"模式
for m in re.finditer(r'//\s*(MiniFilter\w+)\s*—[^\n]*\n((?://[^\n]*\n)*)', txt):
    name, cmts = m.group(1), m.group(2)
    a = re.search(r'(0x[0-9A-Fa-f]{6,}|sub_[0-9A-Fa-f]+)', cmts)
    if a:
        s = a.group(1)
        ea = int(s[2:], 16) if s.startswith('0x') else int(s[4:], 16)
        pairs.append((name, ea))

idapro.open_database(I64, True)
import ida_hexrays  # noqa: E402

print("%-42s %-10s %-8s %s" % ("源码名", "注释地址", "原始名", "伪代码签名（真实身份）"))
print("-" * 150)
seen = set()
for name, ea in pairs:
    if name in seen:
        continue
    seen.add(name)
    it = None
    for k, v in O.items():
        if v["start"] == ea:
            it = (k, v)
            break
    origname, origsz = (it[0], it[1]["size"]) if it else ("<地址不存在!>", 0)
    sig = "（不可反编译）"
    try:
        cf = ida_hexrays.decompile(ea)
        if cf is not None:
            for l in str(cf).splitlines():
                if "(" in l and ")" in l and not l.strip().startswith("//"):
                    sig = l.strip()[:90]
                    break
    except Exception:
        pass
    print("%-42s 0x%-8X %-8s %s" % (name, ea, origname if len(origname) < 8 else origname[:7], sig))

idapro.close_database()