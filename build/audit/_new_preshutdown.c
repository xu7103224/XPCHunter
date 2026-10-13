// MiniFilterPreShutdown — FltMgr 关机前指针修补（0x1400188D8）
// 对应原始驱动 0x1400188D8（937 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：一段通用的
//   "遍历 ServicePtr 数组、检查每项是否为有效内核地址"的循环，
//   与原始函数体毫无关系。注释称"从 ServicePtr 读取服务表，遍历服务条目
//   执行关机前清理"亦不符。
//   发现方式：静态 GT 核查工具 `_gtwrites2.py` 报该函数原始读
//   {3,2,0x89A,0x87E,0x88D,0x896,0x88F,0x891,0x893,0x895,0x897,0x887,0x914}
//   而我方一个都没有；逐条反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写（IDA 无伪代码）。
// 【语义】把 FltMgr 各 PE 节里指向某个"旧指针值"的槽原位替换为新指针，
//   属 minifilter 卸载/关机时的指针修正（与 GtFltmgrBase 系列 GT 配合）。
// 【原始汇编骨架】
//   ① 读 GT 3 → [rsp+0x50]（模块基址）；读 GT 2 → [rsp+0x58]（模块大小）；
//   ② r14 = GT 0x89A；若为 0 → call 0x1400164C8 后重读 0x89A。
//      0x89A = 待替换的"旧指针值"。
//   ③ [rsp+0x48] = GT 0x87E（FltMgr 基址）
//   ④ r15d = 0x88D；rbx = GT 0x88D；同时读 GT (0x88D+9)=0x896；
//      若两者都为 0 → call 0x14001763C（初始化 FltMgr 节表），随后重读 0x88D → r12。
//   ⑤ 依次读 0x88F/[+0x28]、0x891/[+0x30]、0x893/[+0x38]、0x895/[+0x40]、
//      0x897 → r15、0x887 → r13。（六个 FltMgr 节地址）
//   ⑥ 前置校验：r14 非 0；[rsp+0x48] 非 0；r13 非 0；r12 或 r15 至少一个非 0；
//      r14 落在 (Gt3, Gt3+Gt2) 区间内且 r14+8 仍 < 上界；
//      rsi(第 1 参) 非 0 且位于 MmUserProbeAddress 之下（含 +8）；
//      第 2 参（[rsp+0x98]）必须等于 8。
//   ⑦ ProbeForRead(rsi, 8, 8)；目标值 = *(rsi)（预期是被替换的旧指针）；
//      要求该值 > MmSystemRangeStart。
//   ⑧ rbx = *(r14)；若 rbx == 目标值 → 直接 `xchg [r14], r13`（换成 0x887 节地址）
//      并成功返回。
//   ⑨ 否则按构建号分支（0x914）：
//        < 0x23F0            → 只补 1 处：若 *rbx == 目标值 且 r15 非 0 → 写 r15
//        >= 0x4A61           → 补 6 处：偏移 0/8/0x10/0x18/0x20/0x28 分别尝试
//                              用 r12/r15/[+0x28]/[+0x30]/[+0x38] 替换
//        否则(0x23F0..0x4A60) → 补 5 处：偏移 0/8/0x10/0x18/0x20
//   ⑩ 每次替换 = WritePhysicalMemoryQword(槽地址, 新值)（0x140083180），
//      成功则置标志 dil=1。
//   ⑪ 返回 dil。
__int64 MiniFilterPreShutdown(_QWORD *ServicePtr, int InputSize)
{
    char    Result = 0;                 // dil
    __int64 ModuleBase;                 // [rsp+0x50] = GT 3
    ULONG   ModuleSize;                 // [rsp+0x58] = GT 2
    __int64 OldValue;                   // r14 = GT 0x89A
    __int64 FltMgrBase;                 // [rsp+0x48] = GT 0x87E
    __int64 Sect88D;                    // rbx / r12
    __int64 Sect896;
    __int64 Sect88F, Sect891, Sect893, Sect895, Sect897, Sect887;
    __int64 Expected;                   // rsi 解引用所得
    __int64 Cur;                        // rbx
    ULONG   Build;
    ULONG64 ProbeLimit;
    __int64 i;

    /* ① 模块基址/大小 */
    ModuleBase = GtRead((GLOBAL_TABLE_INDEX)3);              // 0x140018902
    ModuleSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)2);       // 0x140018911

    /* ② 旧指针值（懒初始化） */
    OldValue = GtRead((GLOBAL_TABLE_INDEX)0x89A);            // 0x140018922
    if (!OldValue)                                           // 0x14001892A
    {
        FindPeExecutableSection();                           // 0x14001892F（call 0x1400164C8）
        OldValue = GtRead((GLOBAL_TABLE_INDEX)0x89A);        // 0x140018936
    }

    /* ③ FltMgr 基址 */
    FltMgrBase = GtRead((GLOBAL_TABLE_INDEX)0x87E);          // 0x140018943

    /* ④ 0x88D 节地址（两者皆空则先初始化） */
    Sect88D = GtRead((GLOBAL_TABLE_INDEX)0x88D);             // 0x140018956
    Sect896 = GtRead((GLOBAL_TABLE_INDEX)0x896);             // 0x140018962（0x88D+9）
    if (!Sect88D && !Sect896)                                // 0x140018967/96C
        InitFsFilterExportTable();                           // 0x140018971（call 0x14001763C）
    Sect88D = GtRead((GLOBAL_TABLE_INDEX)0x88D);             // 0x140018979（r12）

    /* ⑤ 六个 FltMgr 节地址 */
    Sect88F = GtRead((GLOBAL_TABLE_INDEX)0x88F);             // 0x140018986
    Sect891 = GtRead((GLOBAL_TABLE_INDEX)0x891);             // 0x140018995
    Sect893 = GtRead((GLOBAL_TABLE_INDEX)0x893);             // 0x1400189A4
    Sect895 = GtRead((GLOBAL_TABLE_INDEX)0x895);             // 0x1400189B3
    Sect897 = GtRead((GLOBAL_TABLE_INDEX)0x897);             // 0x1400189C2（r15）
    Sect887 = GtRead((GLOBAL_TABLE_INDEX)0x887);             // 0x1400189CF（r13）

    /* ⑥ 前置校验 */
    if (!OldValue || !FltMgrBase || !Sect887)                // 0x1400189D7 / 9E0 / 9EC
        return Result;
    if (!Sect88D && !Sect897)                                // 0x1400189F5/9FA
        return Result;
    if ((ULONG64)OldValue <= (ULONG64)ModuleBase)            // 0x140018A03/0A08
        return Result;
    if ((ULONG64)OldValue >= (ULONG64)ModuleBase + ModuleSize)   // 0x140018A11/0A15/0A18
        return Result;
    if ((ULONG64)OldValue + 8 >= (ULONG64)ModuleBase + ModuleSize)  // 0x140018A21/0A25
        return Result;
    if (!ServicePtr || InputSize != 8)                       // 0x140018A2E / A3C
        return Result;
    ProbeLimit = *(ULONG64 *)MmUserProbeAddress;             // 0x140018A49/0A50
    if ((ULONG64)ServicePtr >= ProbeLimit                    // 0x140018A53
        || (ULONG64)ServicePtr + 8 >= ProbeLimit)            // 0x140018A5C
        return Result;

    /* ⑦ 读取预期旧值 */
    ProbeForRead((PVOID)ServicePtr, 8, 8);                   // 0x140018A6F
    Expected = *(__int64 *)ServicePtr;                       // 0x140018A75
    if ((ULONG64)Expected <= *(ULONG64 *)MmSystemRangeStart)  // 0x140018A7D/0A84/0A87
        return Result;

    /* ⑧ 首槽特判 */
    Cur = *(__int64 *)OldValue;                              // 0x140018A90
    if (Cur == Expected)                                     // 0x140018A93
    {
        *(__int64 *)OldValue = Sect887;                      // 0x140018A98（xchg [r14], r13）
        return 1;
    }
    if (!Cur || (ULONG64)Cur <= *(ULONG64 *)MmSystemRangeStart)  // 0x140018AA0 / AA9
        return Result;
    if (((ULONG64)Cur & 7) != 0)                             // 0x140018AB2
        return Result;

    /* ⑨ 按构建号决定要补几处 */
    Build = (ULONG)GtRead(GtWindowsBuildNumber);             // 0x140018AC4（0x914）

    if (Build >= 0x23F0 && Build < 0x4A61)                   // 0x140018AC9 / ADC
    {
        /* 5 处：偏移 0/8/0x10/0x18/0x20 */
        struct { ULONG Off; __int64 Val; } slots[5] = {
            { 0x00, Sect88D }, { 0x08, Sect897 }, { 0x10, Sect88F },
            { 0x18, Sect891 }, { 0x20, Sect893 }
        };
        for (i = 0; i < 5; ++i)                              // 0x140018AF1..0x140018B8B
        {
            __int64 *p = (__int64 *)(Cur + slots[i].Off);
            if (Expected == *p && slots[i].Val)
            {
                WritePhysicalMemoryQword((unsigned __int64)p, slots[i].Val);   // 0x140018AF7 等
                Result = 1;
            }
            (void)p;
        }
    }
    else if (Build >= 0x4A61)                                // 0x140018AE1
    {
        /* 6 处：偏移 0/8/0x10/0x18/0x20/0x28 */
        struct { ULONG Off; __int64 Val; } slots[6] = {
            { 0x00, Sect88D }, { 0x08, Sect897 }, { 0x10, Sect88F },
            { 0x18, Sect891 }, { 0x20, Sect893 }, { 0x28, Sect895 }
        };
        for (i = 0; i < 6; ++i)                              // 0x140018B90..0x140018C34
        {
            __int64 *p = (__int64 *)(Cur + slots[i].Off);
            if (Expected == *p && slots[i].Val)
            {
                WritePhysicalMemoryQword((unsigned __int64)p, slots[i].Val);
                Result = 1;
            }
        }
    }
    else
    {
        /* 构建号 < 0x23F0：只补首槽 */
        if (Expected == *(__int64 *)Cur && Sect897)          // 0x140018C3D / C42
        {
            WritePhysicalMemoryQword((unsigned __int64)Cur, Sect897);   // 0x140018C4D
            Result = 1;
        }
    }

    return Result;                                           // 0x140018C64
}
