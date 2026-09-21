# 把本轮分析的"证据注释"批量写回 IDB（命名同步规则的执行）
# 只写注释、不改名（除已确认的改名外），最后保存数据库。
import os
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

I64 = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64"

# (地址, 可选新名(None=不改名), 证据注释)
ITEMS = [
    (0x1400130C4, None,
     u"【2026-09-21 证据】节区扫描器家族成员。三分支扫描 PE 描述符，"
     u"结果写 GT 0x180。命名正确，无需改名。复刻：Minifilter.c FindKernelDataSectionV2。"),
    (0x1400132EC, None,
     u"【2026-09-21 证据】节区扫描器家族成员。以构建号 0x42EE(17134, Win10 1803) 分岔；"
     u"三段匹配类型码 0x512/0x558/0x420；结果写 GT 0x17A；循环上限 0x200。"
     u"复刻：Minifilter.c FindKernelDataSectionV3。"),
    (0x1400137BC, None,
     u"【2026-09-21 证据】节区扫描器家族成员，本族中唯一读 ntoskrnl.exe 的 PE 文件缓冲区"
     u"(GT 0x20/0x21)而非内核镜像者；三段类型码 0x512/0x558/0x510；"
     u"循环上限 0x300；结果写 GT 0x17B。194 条指令逐条还原。"
     u"复刻：Minifilter.c ParseNtKernelDataSectionsV2。"),
    (0x140012E0C, None,
     u"【2026-09-21 证据】节区扫描器家族成员。扫描起点读 GT 0x175；结果写 GT 0x17F；"
     u"含\"候选值 == GT 0x446B 则提前命中\"路径；确认节区类型码 0x53D/0x512。"
     u"174 条指令逐条还原。复刻：Minifilter.c FindKernelPageSection。"),
    (0x140014ACC, None,
     u"【2026-09-21 证据】节区扫描器家族成员（与 0x140014078 同族）。"
     u"三段类型码 0x43E/0x558/0x53D；结果写 GT 0x17E。"
     u"注：函数名中的 MiniFilter 含义未确证（其结果为内核数据节偏移），故暂不改名。"
     u"复刻：Minifilter.c ParseMiniFilterDataSection。"),
    (0x140075A9C, None,
     u"【2026-09-21 证据】真实签名 8 参数："
     u"(a1 HandlerFunc, a2, a3, a4, a5, Dst(_BYTE*), NumberOfBytes(SIZE_T), a8(size_t*))。"
     u"依据是 IDA 对本题的伪代码（可反编译）：体内 memmove(Dst, PoolWithQuotaTag, v11) 与 "
     u"*(_DWORD*)a8 = MaxCount，据此判定 Dst 是搬运目的地、a8 是输出大小指针。"
     u"构建号 >= 0x42EE 时用配额池分配中间缓冲，否则用栈上 64 字节缓冲。"
     u"复刻声明与之逐位一致（Protocol.c SendIoControlWithQuotaBuffer）。"),
    (0x140072B64, None,
     u"【2026-09-21 证据】11 参数函数（非 10）。参数语义取自唯一调用方 "
     u"CmdReadProcessMemoryStr(0x140074418) 的伪代码实参序列，与调用点 0x14007461B "
     u"存栈的第 5..11 实参按序吻合。含\"保存并清零当前线程字节(gs:188h + GT 0x27)后恢复\""
     u"技巧，以及按 *(DWORD*)(Buffer5+0xC)+0x10 推进读指针的数据搬运循环。"
     u"两次调用 SendIoControlWithBufferSwap。213 条指令逐条还原。"
     u"复刻：Protocol.c SendReadMemoryIoControl。"),
    (0x1400731F4, None,
     u"【2026-09-21 证据】名字中的 IoControl 只描述了后半段：前半段是宽字符路径拼接"
     u"（搬入前缀 → 强制末宽字符改写为 0x005C → 追加名字 → 补 0 宽字符结尾），"
     u"随后以 0x20019(KEY_READ) 走注册表键 IOCTL。名字沿用 IDA，含义已在复刻注释说明。"
     u"复刻：Protocol.c SendIoControlWithBufferSwap。"),
    (0x140074418, None,
     u"【2026-09-21 证据】命令处理器（复刻注册于 Table[58]）。关键结构："
     u"在 ProbeForWrite 之后调用 SendReadMemoryIoControl(0x140072B64)，"
     u"并**仅在「返回 0 且出标志 == 1」时**才进入后续处理（伪代码 115/127 行）。"
     u"复刻：Utility.c ReadProcessMemoryString（2026-09-21 已按此结构重构，"
     u"此前是扁平化实现、跳过了该调用）。"),
    (0x140019898, None,
     u"【2026-09-21 证据】函数体：GtRead(0x42CE) 取注册函数指针 → 以 "
     u"(MiniFilterCommPortReplyDone, 0, &g_CommPortContext) 调用 → 返回 (eax >= 0)。"
     u"【命名同步 2026-09-21 已核实】复刻中该函数体此前被错误地挂在 "
     u"MiniFilterCommPortConnect 名下。经比对本地址(0x140019898)与 0x140019784 两者反汇编，"
     u"确认原始是**两个独立函数**：0x140019898 只做注册（本函数），"
     u"0x140019784 是\"只做一次\"的守卫包装（GT 0x8F2 作标志）并调用本函数。"
     u"复刻已按此拆分：RegisterCommPortReplyCallback + MiniFilterCommPortConnect。"),
    (0x140019784, None,
     u"【2026-09-21 证据】\"只做一次\"守卫包装（54 字节），原始函数体："
     u"if (GtRead(0x8F2) == 0) { if (RegisterCommPortReplyCallback() == 1) "
     u"{ GtWrite(0x8F2, 1); 返回 1; } } 否则返回 0。"
     u"即本函数负责一次性守卫（GT 0x8F2），注册动作在 0x140019898。"
     u"复刻：Minifilter.c MiniFilterCommPortConnect（2026-09-21 补齐，此前被合并且丢了守卫）。"),
]

idapro.open_database(I64, True)
import ida_name, ida_bytes, ida_funcs, ida_loader, idc  # noqa: E402

for ea, new, note in ITEMS:
    f = ida_funcs.get_func(ea)
    if not f:
        print("跳过 0x%X：不是函数" % ea)
        continue
    if new:
        ok = ida_name.set_name(ea, new, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        print("0x%X 改名 -> %s (%s)" % (ea, new, "成功" if ok else "失败"))
    prev = ida_bytes.get_cmt(f.start_ea, 0) or ""
    ida_bytes.set_cmt(f.start_ea, (prev + "\n" if prev and note not in prev else "") + note, 0)
    print("0x%X  %-38s 注释已写" % (ea, idc.get_func_name(ea)))

print("保存数据库...")
ida_loader.save_database(I64, 0)
idapro.close_database()
print("完成")
