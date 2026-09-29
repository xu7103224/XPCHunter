# 按 §11.2 方案批量改名（代码侧 + IDB 侧双向同步）
# 代码侧：inc/*.h、src/**/*.c 全量替换（含调用点与命令表）
# IDB 侧：按真实地址写回新名 + 证据注释
import json
import os
import re
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
SRC = os.path.join(ROOT, "XPCHunterDrv")

# (现名, 真实地址, 新名, 证据)
RENAMES = [
    ("MiniFilterInstanceSetup",         0x1400129CC, "CmdOpenFilterVolumeFile",      "体内调 OpenMiniFilterVolumeFile（打开 minifilter 卷文件）"),
    ("MiniFilterInstanceQuery",         0x140012B78, "CmdRemoveFilterContextNode",   "体内调 RemoveMiniFilterContextNode"),
    ("MiniFilterPreFastIo",             0x14001B2B4, "CmdEnumAleEndpointLayers",     "体内调 EnumerateAleEndpointLayers（ALE 网络端点层枚举）"),
    ("MiniFilterPostFastIo",            0x14001BC08, "CmdInitFwpsDispatchTables",    "体内调 InitFwpsDispatchTables"),
    ("MiniFilterAcquireForModWrite",    0x14001BD44, "CmdInitFwpsDispatchTables2",   "体内调 InitFwpsDispatchTables（另一入口）"),
    ("MiniFilterReleaseForModWrite",    0x14001C048, "CmdCollectGdtrEntries",        "ReadGdtr 取 GDTR 并把 GDT 条目写入上下文缓冲"),
    ("MiniFilterAcquireForCcFlush",     0x14001C130, "CmdClearGdtPresentBit",        "清除指定 GDT 选择子的 Present 位(0x8000)"),
    ("MiniFilterReleaseForCcFlush",     0x14001C1B4, "CmdForEachCpuClearGdtBit",     "ForEachProcessor 调 AcquireForCcFlush"),
    ("MiniFilterAcquireForSectionSync", 0x14001C274, "CmdCollectAllCpuGdtEntries",   "ForEachProcessor 调 ReleaseForModWrite 收集 GDT"),
    ("MiniFilterStreamHandle",          0x14001AB5C, "CmdHandleStreamProcessInput",  "解析 40 字节输入(Pid/EProcess/流上下文)并转调 Ex"),
    ("MiniFilterNormalizeName",         0x140019DD8, "CmdCreateFileForPathAdd",      "添加操作时创建文件对象并设路径信息"),
    ("MiniFilterNotifyRoutineEx",       0x14001A39C, "RegisterFilterUnloadCallback", "读注册函数指针并注册 MiniFilterFilterUnload"),
    ("MiniFilterFormatFileName",        0x14001A030, "RegisterFormatNameCallback",   "注册回调并置位 GtMiniFilterFormatNameReady"),
    ("MiniFilterFormatFileNameWithPath",0x14001A068, "RegisterFormatPathCallback",   "注册回调并置位另一槽"),
    ("MiniFilterQueryIdleRoutine",      0x14001A210, "CmdPatchPeHeaderOnFlag",       "按标志位 0x100 且 IRQL<2 时调 PatchPeHeaderMagic"),
    ("MiniFilterServerContext",         0x140019A44, "CmdSetCallbackFlagFalse",      "写 GtCallbackField23 = 0"),
    ("MiniFilterClientContext",         0x140019A5C, "CmdSetCallbackFlagTrue",       "写 GtCallbackField23 = 1"),
]

# ---------- 1) 代码侧替换 ----------
changed = {}
for dp, _, fns in os.walk(SRC):
    for fn in sorted(fns):
        if not fn.endswith((".c", ".h")):
            continue
        p = os.path.join(dp, fn)
        s = open(p, encoding="utf-8", errors="replace").read()
        orig = s
        for old, _, new, _ in RENAMES:
            if re.search(r"\b" + re.escape(old) + r"\b", s):
                s = re.sub(r"\b" + re.escape(old) + r"\b", new, s)
        if s != orig:
            open(p, "w", encoding="utf-8").write(s)
            changed[os.path.relpath(p, ROOT)] = True
print("=== 代码侧已改文件 ===")
for k in sorted(changed):
    print("   " + k)

# ---------- 2) IDB 侧写回 ----------
import idapro  # noqa: E402
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")
idapro.open_database(I64, True)
import ida_name, ida_bytes, ida_funcs, ida_loader, idc  # noqa: E402

print("=== IDB 侧写回 ===")
for old, ea, new, ev in RENAMES:
    f = ida_funcs.get_func(ea)
    if not f:
        print("   ⚠ 0x%X 非函数" % ea)
        continue
    ok = ida_name.set_name(ea, new, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    note = (u"【命名依据 2026-09-29，方案 A 按功能命名】原 IDA 名 %s 与实物不符：%s。"
            u"证据来自 Hex-Rays 伪代码的 API 调用链。改名 %s。"
            u"（同族问题见 docs/reversing/命名审计.md §11）" % (old, ev, new))
    prev = ida_bytes.get_cmt(f.start_ea, 0) or ""
    ida_bytes.set_cmt(f.start_ea, note, 0)
    print("   0x%X %-36s -> %-32s %s" % (ea, old, new, "OK" if ok else "FAIL"))
ida_loader.save_database(I64, 0)
idapro.close_database()
print("IDB 已保存")