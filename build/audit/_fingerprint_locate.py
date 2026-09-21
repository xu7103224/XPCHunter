# 指纹定位：判断原始函数是否已实现（可能挂在别的名字下）
# 做法：从原始函数反汇编中提取"特征 token"（调用的函数名 + GT 索引/立即数），
#       再在复刻源码里检索每个 token；出现次数最少者即为该逻辑的落点线索。
import os
import re
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
SRC = os.path.join(ROOT, "XPCHunterDrv")
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")

TARGETS = [
    ("RegisterCommPortReplyCallback", 0x140019898, 62),
    ("FindWin32kSectionByType", 0x1400888FC, 356),
    ("SendReadMemoryIoControl", 0x140072B64, 866),
    ("ParseNtSectionHeaders2", 0x1400485F0, 1303),
    ("ParseShadowSyscallExportSections", 0x14003D034, 781),
    ("ParseSyscallFileExportSections", 0x14003D7F4, 819),
    ("CollectTwoSyscallTables", 0x140086740, 295),
    ("ReadWriteCallbackPhysicalMemory", 0x1400709C4, 374),
    ("QueryAllocFilePath", 0x1400197BC, 220),
]

LIB = re.compile(r"^(GtRead|GtWrite|GtAlloc|memset|memmove|memcpy|strlen|Rtl|Ke|Ps|Mm|Io|Ob|Zw|Flt|Ex|__|_|$)"
                 r"|^j_|^unknown")

# 收集复刻源码
srctext = {}
for dp, _, fns in os.walk(SRC):
    for fn in fns:
        if fn.endswith((".c", ".h")):
            p = os.path.join(dp, fn)
            srctext[p.replace(ROOT + os.sep, "")] = open(p, encoding="utf-8", errors="replace").read()

idapro.open_database(I64, True)
import idautils, idc, ida_lines, ida_funcs  # noqa: E402

for name, start, size in TARGETS:
    tokens = set()
    insns = list(idautils.Heads(start, start + size))
    for h in insns:
        line = ida_lines.tag_remove(idc.generate_disasm_line(h, 0))
        m = re.search(r"call\s+(\S+)", line)
        if m:
            t = m.group(1).strip()
            if not LIB.match(t):
                tokens.add(t)
        m2 = re.search(r"mov\s+ecx,\s*([0-9A-F]+)h", line)
        if m2:
            tokens.add("0x" + m2.group(1).upper())
    # 统计每个 token 在源码里的出现次数
    scored = []
    for t in sorted(tokens):
        cnt = 0
        where = []
        for p, txt in srctext.items():
            c = txt.count(t)
            if c:
                cnt += c
                where.append(p)
        scored.append((cnt, t, where))
    scored.sort(key=lambda x: (x[0], x[1]))
    print("=== %s (0x%X, %dB) 特征 token 由稀有到常见 ===" % (name, start, size))
    for cnt, t, where in scored[:6]:
        print("   %4d x %-46s %s" % (cnt, t, ",".join(sorted(set(os.path.basename(w) for w in where))[:4])))
    if not scored:
        print("   （无可提取特征）")

idapro.close_database()
