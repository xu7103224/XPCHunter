# 把本轮逆向得到的新名字同步写回 IDB（并保留证据注释），最后保存数据库
# 只写回有充分反汇编证据的项，避免"猜着改名"污染 IDB。
import os
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

I64 = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64"

# (地址, 新名, 证据注释)
RENAMES = [
    (0x140014078, "FindKernelDataSectionV4",
     u"【2026-09-21 改名，原 IDA 名 MiniFilterPreCreate 不成立】"
     u"本函数无参数（不从 rcx/rdx/r8/r9 读任何值），而 minifilter 的 PreCreate 回调"
     u"必须接收 3 个参数，故不可能是 FLT 回调。163 条指令逐条还原后确认其功能是："
     u"在 ntoskrnl.exe 的 PE 文件缓冲区中按类型序列(0x512/0x558/0x420/0x4DF)扫描"
     u"并定位内核数据节，结果写 GT 0x17C。实参由子函数 SendReadMemoryIoControl 的"
     u"调用点标定，11 参数。复刻中对应 Minifilter.c 的 FindKernelDataSectionV4。"),
    (0x1400130A4, "FindKernelDataSectionV2Dispatch",
     u"【2026-09-21 证据补充】构建号 >= 0x1DB0(7600, Win7) 时调用 "
     u"FindKernelDataSectionV2(0x1400130C4)，否则原样返回构建号。31 字节。"),
    (0x14001356C, "FindKernelDataSectionV3Dispatch",
     u"【2026-09-21 证据补充】构建号 >= 0x1DB0 时调用 "
     u"ParseNtKernelDataSectionsV2(0x1400137BC)，否则原样返回构建号。31 字节。"),
]

idapro.open_database(I64, True)

import ida_name, ida_bytes, ida_funcs, ida_loader, idc  # noqa: E402

for ea, new, note in RENAMES:
    old = idc.get_func_name(ea) or "<无名>"
    f = ida_funcs.get_func(ea)
    if not f:
        print("跳过 0x%X：不是函数" % ea)
        continue
    ok = ida_name.set_name(ea, new, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    print("0x%X: %s -> %s  (%s)" % (ea, old, new, "成功" if ok else "失败"))
    # 证据写成函数注释（可重复执行：先清再写）
    prev = ida_bytes.get_cmt(f.start_ea, 0) or ""
    ida_bytes.set_cmt(f.start_ea, note, 0)

print("保存数据库...")
ida_loader.save_database(I64, 0)
idapro.close_database()
print("完成")
