// ScanKfdDriverSections — 扫描 KFD 驱动节区（类型 1296/1298/1049 三段确认）
// 对应原始驱动 0x1400687D0（550 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取的调用序：首读 0x7BE（配对 Find* 的导出偏移槽）
//   → 0x1A1（模块基址）→ 循环内两处 GtRead(0x7BA) 作比对 → 命中写 0x7C0。
// 【算法】
//   ① Offset = GtRead(0x7BE)；为 0 → FindKfdDeregisterLayerCallbackExport 后再取；
//   ② ModuleBase = GtRead(0x1A1)；三者齐备且 Offset < PeSize → 初始化上下文；
//   ③ 循环上限 0x64；每轮：类型 0x558 时计数器 +1，> 1 即返回 0（只允许一次）；
//      类型 0x510(1296) 且 字段+0x88==0x40000 且 字段+0x78!=0 且 字段+0x50==64
//        → 记候选 RVA(v9) 与 字段+0x8C(v8)（须尚未记录）；
//      类型 1298 且 (字段+0x88 & 0x10000) 且 (int)字段+0x78 > 0 且 字段+0x50==64
//        → 若 候选非0 且 (基址+候选) == GtRead(0x7BA) 且 v8 == 字段+0x78
//          → 写 GT 0x7C0 = 字段+0x78，返回 1；
//      类型 1049 且 字段+0x50==64 且 字段+0x88==0x2000000 且 候选非0
//        且 (基址+候选) == GtRead(0x7BA) 且 v8 == 字段+0x40
//        → 写 GT 0x7C0 = 字段+0x40，返回 1。
char __fastcall ScanKfdDriverSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Count558 = 0;         // v5
    ULONG64 SavedField = 0;       // v8（候选对应的 字段+0x8C / 字段+0x40）
    ULONG   SavedRva = 0;         // v9
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7BE);            // 0x14006881D
    if (!Offset)
    {
        FindKfdDeregisterLayerCallbackExport(PeBase, PeSize);     // 0x140068829
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7BE);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140068842
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140068858
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006888A
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x64; ++i)                                    // 0x140068896
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F40, F50, F78, F88, F8C;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x1400688A2
            return Result;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x1400688BA
        Ctx.ReadPtr += Len;                                       // 0x1400688C4

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400688C9
        if (Type == 0x558 && (ULONG)(++Count558) > 1)             // 0x1400688DE
            return Result;

        F40 = *(ULONG *)((PUCHAR)Entry + 0x40);
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);
        F8C = *(ULONG *)((PUCHAR)Entry + 0x8C);

        if (Type == 0x510 && F88 == 0x40000ULL && F78 != 0 && F50 == 64)   // 0x14006890C
        {
            ULONG Rva = Cumul + F78 - (ULONG)(ULONG_PTR)PeBase;   // 0x140068912
            if (Rva && Rva < PeSize && !SavedRva)                 // 0x140068924
            {
                SavedField = F8C;                                 // 0x14006892A
                SavedRva = Rva;                                   // 0x14006892E
            }
        }
        else if (Type == 1298 && (F88 & 0x10000ULL) != 0          // 0x14006894B
                 && (int)F78 > 0 && F50 == 64)
        {
            if (SavedRva                                          // 0x14006896C
                && (ULONG64)(ModuleBase + (__int64)SavedRva)
                       == (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x7BA)
                && SavedField == (ULONG64)F78)
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x7C0, (__int64)F78);      // LABEL_35
                return 1;
            }
        }
        else if (Type == 1049 && F50 == 64 && F88 == 0x2000000ULL // 0x1400689AB
                 && SavedRva
                 && (ULONG64)(ModuleBase + (__int64)SavedRva)
                        == (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x7BA)
                 && SavedField == (ULONG64)F40)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x7C0, (__int64)F40);      // LABEL_35
            return 1;
        }
    }
    return Result;                                                // 0x1400689CC
}