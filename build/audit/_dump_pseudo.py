# 批量导出可反编译函数的伪代码到文件（供实现时逐条对照，避免刷屏）
import json
import os
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")
OUT = os.path.join(ROOT, "build", "audit", "_pseudo")
names = sys.argv[1:]

O = {x["name"]: x for x in json.load(open(os.path.join(ROOT, "build", "audit", "_orig_funcs_ida.json"), encoding="utf-8"))}
os.makedirs(OUT, exist_ok=True)

idapro.open_database(I64, True)
import ida_hexrays  # noqa: E402

for n in names:
    it = O.get(n)
    if not it:
        print("NOT FOUND:", n)
        continue
    try:
        cf = ida_hexrays.decompile(it["start"])
    except Exception as e:  # noqa: BLE001
        print("FAIL %s: %s" % (n, e))
        continue
    if cf is None:
        print("NO PSEUDO:", n)
        continue
    src = str(cf)
    p = os.path.join(OUT, n + ".c")
    with open(p, "w", encoding="utf-8") as f:
        f.write("// %s  0x%X  %d bytes\n" % (n, it["start"], it["size"]))
        f.write(src)
    print("OK %-44s 0x%X %5dB  %3d 行 -> %s" % (n, it["start"], it["size"], len(src.splitlines()), p))

idapro.close_database()