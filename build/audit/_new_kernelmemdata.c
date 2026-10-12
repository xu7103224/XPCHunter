// ScanKernelMemoryDataSection — 四层嵌套扫描内核内存数据节区
// 对应原始驱动 0x140068ABC（912 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7D7（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7D9（本函数结果槽）。
// 【字段映射】描述符 0x120 布局；用到 +0x38(v29) +0x50(v30) +0x58(v31)
//   +0x70(v32) +0x78(v33) +0x88(v34) +0xF0(v35) +0x118(v36)。
// 【算法】四层嵌套（层级由 类型序列 1341→1368 / 1298→1368 / 1332..1347→1368 / 1298 驱动）：
//   L1（上限 0x64）：类型 1341(0x53D) 且 字段+0x70==2 → 置标记；
//       类型 1368(0x558) 且 标记已置 → 由 字段+0x38 算 RVA(v8)，合法则 break；
//   L2（上限 0x64）：类型 1298(0x512) 且 字段+0x78!=0 且 字段+0x50==64
//       且 字段+0x58==8 → 置标记2；类型 0x558 且 标记2 → 算 RVA(v16) 进入 L3；
//   L3（上限 0x64）：类型 1332..1347 且 字段+0x70==1 → 置标记3；
//       类型 0x558 且 标记3 → 算 RVA(v21) 进入 L4；
//   L4（上限 0x1E）：类型 1298 且 字段+0x88==0x40000 且 字段+0x78!=0
//       且 字段+0x50==64 → 算 RVA(v24)，合法则写 GT 0x7D9 = 基址 + v24，返回 1。
char __fastcall ScanKernelMemoryDataSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Rva1 = 0;             // v8
    ULONG   Rva2 = 0;             // v16
    ULONG   Rva3 = 0;             // v21
    UCHAR   M1 = 0, M2 = 0, M3 = 0;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D7);            // 0x140068B01
    if (!Offset)
    {
        FindNmrRegisterProviderExport(PeBase, PeSize);            // 0x140068B0D
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D7);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140068B26
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140068B3C
        return Result;

    /* ---- L1：1341(字段+0x70==2) → 1368 ---- */
    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x140068B6E
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )                                               // 0x140068B8B
    {
        USHORT Type;
        ULONG  Len, Cumul, F38, F70;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068B98
        Ctx.ReadPtr += Len;                                       // 0x140068BA2
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068BA7
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F70 = *(ULONG *)((PUCHAR)Entry + 0x70);

        if (Type == 0x53D && F70 == 2)                            // 0x140068BBA
        {
            M1 = 1;                                               // 0x140068BBC
        }
        else if (Type == 0x558 && M1 == 1)                        // 0x140068BDD
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;
            if (r && r < PeSize)                                  // 0x140068BDD 内联判据
            {
                Rva1 = r;                                         // 0x140068BEA
                break;
            }
        }
        if ((ULONG)(++i) >= 0x64)                                 // 0x140068BE6
            break;
    }

    if (!Rva1 || Rva1 >= PeSize)                                  // 0x140068BF6
        return Result;

    /* ---- L2：1298(字段+0x78/0x50/0x58) → 1368 ---- */
    InitPESectionReadContext(PeBase + Rva1, PeSize - Rva1,        // 0x140068C28
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )                                               // 0x140068C48
    {
        USHORT Type;
        ULONG  Len, Cumul, F38, F50, F58, F78;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068C59
        Ctx.ReadPtr += Len;                                       // 0x140068C63
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068C68
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F58 = *(ULONG *)((PUCHAR)Entry + 0x58);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);

        if (Type == 0x512 && F78 != 0 && F50 == 64 && F58 == 8)    // 0x140068C82
        {
            M2 = 1;                                               // 0x140068C84
        }
        else if (Type == 0x558 && M2 == 1)                        // 0x140068C99
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;      // 0x140068CA1
            if (r && r < PeSize)                                  // 0x140068CA3 / CA7
            {
                Rva2 = r;
                break;
            }
        }
        if ((ULONG)(++i) >= 0x64)                                 // 0x140068CB4
            return Result;
    }

    if (!Rva2 || Rva2 >= PeSize)                                  // 0x140068CC1
        return Result;

    /* ---- L3：1332..1347(字段+0x70==1) → 1368 ---- */
    InitPESectionReadContext(PeBase + Rva2, PeSize - Rva2,        // 0x140068CF3
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )                                               // 0x140068D0D
    {
        USHORT Type;
        ULONG  Len, Cumul, F38, F70;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068D24
        Ctx.ReadPtr += Len;                                       // 0x140068D2E
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068D33
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F70 = *(ULONG *)((PUCHAR)Entry + 0x70);

        if ((USHORT)(Type - 1332) <= 0xF && F70 == 1)             // 0x140068D49
        {
            M3 = 1;                                               // 0x140068D4B
        }
        else if (Type == 0x558 && M3 == 1)                        // 0x140068D5A
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;      // 0x140068D62
            if (r && r < PeSize)                                  // 0x140068D64 / D68
            {
                Rva3 = r;
                break;
            }
        }
        if ((ULONG)(++i) >= 0x64)                                 // 0x140068D6F
            return Result;
    }

    if (!Rva3 || Rva3 >= PeSize)                                  // 0x140068D68
        return Result;

    /* ---- L4：1298(字段+0x88==0x40000 等) → 写 GT ---- */
    InitPESectionReadContext(PeBase + Rva3, PeSize - Rva3,        // 0x140068DA3
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; i < 0x1E; ++i)                                    // 0x140068DC0
    {
        USHORT Type;
        ULONG  Len, Cumul, F50, F78, F88;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            return Result;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068DCD
        Ctx.ReadPtr += Len;                                       // 0x140068DD7
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068DDE
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);

        if (Type == 0x512 && F88 == 0x40000ULL                    // 0x140068DEB
            && F78 != 0 && F50 == 64)                             // 0x140068DF2 / DF9
        {
            ULONG r = Cumul + F78 - (ULONG)(ULONG_PTR)PeBase;      // 0x140068DFE
            if (r && r < PeSize)                                  // 0x140068E00 / E04
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x7D9,                 // 0x140068E19
                        ModuleBase + (__int64)r);
                return 1;                                         // 0x140068E1E
            }
        }
    }
    return Result;                                                 // 0x140068E22
}