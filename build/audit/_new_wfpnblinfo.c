// ScanWfpNblInfoSections — 扫描 WFP NBL Info 节区（类型 1298 两段组合）
// 对应原始驱动 0x14006A794（468 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7B2（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7B4 / 0x7B5 / 0x7B6（本函数的三个结果槽）。
// 【#define 展开】原伪代码里的复合表达式对应：
//   GtMsrvTokenTable|GtEprocessField134 = 0x7B2（配对 Find 的偏移槽）
//   GtEprocessField151|0x100            = 0x1A1（模块基址）
//   GtMsrvTebTable|GtEprocessField134   = 0x7B4（本函数结果槽 1）
//   GtMsrvTebTable|GtEprocessField135   = 0x7B5（本函数结果槽 2）
//   GtMsrvTebTable|GtEprocessField136   = 0x7B6（本函数结果槽 3）
// 【算法】取 GT 0x7B2；为 0 则调 FindWfpNblInfoDispatchTableClear 再取；
//   取 GT 0x1A1 作基址；三者齐备且偏移 < PeSize → 初始化上下文；
//   循环上限 0x1E：类型 1349(0x545) 结束；
//     类型 1298(0x512) 两段：
//       (a) 字段+0x70==32 且 字段+0x74==8 且 (int)字段+0x78 > 0
//           → v7 = 字段+0x78 >> 3（条目计数）
//       (b) 字段+0x88==0x40000 且 字段+0x78 != 0 且 字段+0x70==64 且 字段+0x74==1
//           → 算 RVA，非 0 且 < PeSize 且 v8==0 时 v8 = RVA；
//     每轮末尾若 v7 与 v8 均非 0 → 写 GT 0x7B4=v8、0x7B5=基址+v8、0x7B6=v7，返回 1。
char __fastcall ScanWfpNblInfoSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Cnt = 0;              // v7
    ULONG   Rva = 0;              // v8
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7B2);            // 0x14006A7D2
    if (!Offset)
    {
        FindWfpNblInfoDispatchTableClear(PeBase, PeSize);         // 0x14006A7DE
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7B2);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x14006A7F6
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x14006A80C
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006A83E
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x1E; ++i)                                    // 0x14006A847
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F70, F74, F78, F88;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006A857
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x14006A870
        Ctx.ReadPtr += Len;                                       // 0x14006A87B

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x14006A880
        if (Type == 0x545)                                        // 0x14006A88C
            break;

        if (Type == 0x512)                                        // 0x14006A89A
        {
            F70 = *(ULONG *)((PUCHAR)Entry + 0x70);
            F74 = *(ULONG *)((PUCHAR)Entry + 0x74);
            F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
            F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);

            if (F70 == 32 && F74 == 8 && (int)F78 > 0)            // 0x14006A8BA
            {
                Cnt = F78 >> 3;                                   // 0x14006A8BE
            }
            else if (F88 == 0x40000ULL)                           // 0x14006A8CF
            {
                if (F78 != 0 && F70 == 64 && F74 == 1)            // 0x14006A8D3 / 8E8
                {
                    ULONG r = Cumul + F78 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A8ED
                    if (r && r < PeSize && !Rva)                  // 0x14006A8EF / 8F7
                        Rva = r;
                }
            }
        }

        if (Cnt && Rva)                                           // 0x14006A900
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x7B4, (__int64)Rva);          // 0x14006A919
            GtWrite((GLOBAL_TABLE_INDEX)0x7B5,
                    ModuleBase + (__int64)Rva);                        // 0x14006A927
            GtWrite((GLOBAL_TABLE_INDEX)0x7B6, (__int64)Cnt);          // 0x14006A933
            return 1;                                              // 0x14006A938
        }
    }
    return Result;                                                 // 0x14006A93C
}