# 反编译指定函数并只打印与目标调用相关的上下文（避免整篇伪代码占用上下文）
# 用法: python _decomp_call.py 0x140074418 SendReadMemoryIoControl [上下文行数]
import os
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")

ea = int(sys.argv[1], 16)
target = sys.argv[2]
ctx = int(sys.argv[3]) if len(sys.argv) > 3 else 6

idapro.open_database(I64, True)
import ida_hexrays, ida_funcs  # noqa: E402

f = ida_funcs.get_func(ea)
if not f:
    print("NO FUNC at", hex(ea))
    sys.exit(1)
try:
    cf = ida_hexrays.decompile(f.start_ea)
except Exception as e:  # noqa: BLE001
    print("DECOMPILE FAILED:", e)
    sys.exit(1)
if cf is None:
    print("DECOMPILE FAILED (None)")
    sys.exit(1)

lines = str(cf).splitlines()
hits = [i for i, l in enumerate(lines) if target in l]
print("=== %s 在 0x%X 的伪代码中出现 %d 次 ===" % (target, f.start_ea, len(hits)))
for i in hits:
    lo = max(0, i - ctx)
    hi = min(len(lines), i + ctx + 1)
    print("---- 第 %d 行附近 ----" % (i + 1))
    for k in range(lo, hi):
        print("%5d: %s" % (k + 1, lines[k]))

idapro.close_database()
