// ScanWfpStreamShimSections — 扫描 WFP Stream Shim 节区（多类型组合，写 3 个 GT）
// 对应原始驱动 0x14006A508（652 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7C1（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7C5 / 0x7C6 / 0x7C7（本函数的三个结果槽）。
// 【字段映射】描述符 0x120 布局；本函数用到 +0x40(v22) +0x70(v23) +0x78(v24)
//   +0x80(v25) +0xF0 +0x118。初值 v6 = 0xFFFFFFFF（-1，用于求"最小偏移"）。
// 【算法】循环（上限 0x64，末尾计数 v17）：
//   · 类型 1349(0x545) → 若 v7(计数) 与 v9 均非 0 且 v6 落在 (0,0xFFFFFFFE] 内，
//       写 GT 0x7C5 = v7、GT 0x7C6 = 基址+v6、GT 0x7C7 = 基址+v9，返回 1；
//       否则返回 0；
//   · 类型 1139/1140 → v8 = v15 = 1（bound import 标志）
//   · 类型 0x558    → ++v16
//   · 类型 1294(0x50E) 且 v16==1 且 !v8 且 字段+0x70==0x40000
//       且 字段+0x40!=0 且 字段+0x80==64 → 算 RVA，合法则 ++v7 并更新最小 v6
//   · 类型 1351(0x547) 且 v8==1 且 字段+0x70==0x40000
//       且 字段+0x40!=0 且 字段+0x80==0x800000 且 字段+0x78==1 → 算 RVA，
//       合法且 (构建号 >= 0x585D 或 v9==0) 时 v9 = RVA；随后 v8 = v15
char __fastcall ScanWfpStreamShimSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   MinRva = 0xFFFFFFFF;  // v6：1294 的最小偏移
    ULONG   Cnt1294 = 0;          // v7
    UCHAR   BoundMark = 0;        // v8
    UCHAR   BoundSaved = 0;       // v15
    ULONG   Rva1351 = 0;          // v9
    ULONG   Cnt558 = 0;           // v16
    ULONG   Iter = 0;             // v17
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7C1);            // 0x14006A54D
    if (!Offset)
    {
        FindWfpStartStreamShimExport(PeBase, PeSize);             // 0x14006A559
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7C1);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x14006A572
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x14006A58A
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006A5C0
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (;;)                                                      // 0x14006A5EA
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F40, F70, F78, F80;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x14006A5FB
        Ctx.ReadPtr += Len;                                       // 0x14006A605

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x14006A60A

        if (Type == 0x545)                                        // 0x14006A616
        {
            if (Cnt1294 && (MinRva - 1) <= 0xFFFFFFFD && Rva1351)  // 0x14006A72F
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x7C5, (__int64)Cnt1294);      // 0x14006A739
                GtWrite((GLOBAL_TABLE_INDEX)0x7C6,
                        ModuleBase + (__int64)MinRva);                     // 0x14006A74E
                GtWrite((GLOBAL_TABLE_INDEX)0x7C7,
                        ModuleBase + (__int64)Rva1351);                    // 0x14006A75E
                return 1;
            }
            return Result;                                        // 0x14006A763
        }

        F40 = *(ULONG *)((PUCHAR)Entry + 0x40);
        F70 = *(ULONG *)((PUCHAR)Entry + 0x70);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F80 = *(ULONG64 *)((PUCHAR)Entry + 0x80);

        if ((USHORT)(Type - 1139) <= 1)                           // 0x14006A633
        {
            BoundMark = 1;                                        // 0x14006A714
            BoundSaved = 1;                                       // 0x14006A717
        }
        else if (Type == 0x558)                                   // 0x14006A641
        {
            ++Cnt558;                                             // 0x14006A643
        }
        else if (Type == 0x50E)                                   // 0x14006A655
        {
            if (Cnt558 == 1 && !BoundMark && F70 == 0x40000)      // 0x14006A673
            {
                if (F40 != 0 && F80 == 64)                        // 0x14006A67E / 685
                {
                    ULONG Rva = Cumul + F40 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A68A
                    if (Rva && Rva < PeSize)                      // 0x14006A68C / 690
                    {
                        ++Cnt1294;                                // 0x14006A692
                        if (Rva < MinRva)                         // 0x14006A698
                            MinRva = Rva;                         // 0x14006A69A
                    }
                }
            }
        }
        else if (Type == 0x547 && BoundMark == 1 && F70 == 0x40000)   // 0x14006A6B6
        {
            if (F40 != 0 && F80 == 0x800000ULL && F78 == 1)       // 0x14006A6BD / 6CD
            {
                ULONG Rva = Cumul + F40 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A6D2
                if (Rva && Rva < PeSize                            // 0x14006A6D4 / 6F4
                    && ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x585D || !Rva1351))
                    Rva1351 = Rva;                                // 0x14006A6F6
            }
            BoundMark = BoundSaved;                               // 0x14006A6F9
        }

        if ((ULONG)(++Iter) >= 0x64)                              // 0x14006A70C
            return Result;
    }
    return Result;                                                // 0x14006A76A
}