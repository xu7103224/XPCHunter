// ScanKfdDriverSectionV2 — 四层嵌套扫描 KFD 驱动节区（V2）
// 对应原始驱动 0x140069D54（982 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7DA（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7DC / 0x7DD（本函数的两个结果槽）。
// 【字段映射】描述符 0x120 布局；用到 +0x38(v29) +0x50(v30) +0x58(v31)
//   +0x70(v32) +0x78(v33) +0x88(v34) +0xA0(v28，byte) +0xF0(v35) +0x118(v36)。
// 【算法】四层（每层"先找 0x558 算 RVA，再按类型+条件推进"）：
//   L1（上限 0x64）：类型 1349 直接返回 0；类型 0x558 且 RVA 合法 → v7；
//   L2（上限 0x64）：类型 0x558 → 记 v12；否则若
//       (类型 1065 且 (字段+0xA0 & 4) 且 字段+0x88==0x400000000 且 字段+0x70==1)
//       或 (类型 1137 且 (字段+0xA0 & 4))，且 v12 合法 → v11 = v12，break；
//   L3（上限 0x64）：类型 1245 且 字段+0x0C==1 → 若 字段+0x58==1 且
//       (字段+0x88 & 0x10000) 且 (int)字段+0x78 > 0 且 !v16 → v16 = 字段+0x78；
//       类型 1277 或 318 且 v16 非零 → 由 字段+0x38 算 RVA(v20) 进入 L4；
//   L4（上限 0x1E）：类型 1296(0x510) 且 字段+0x88==0x40000 且 字段+0x78!=0
//       且 字段+0x50==64 且 !字段+0x58 → 算 RVA(v23)，合法则
//       写 GT 0x7DC = v16、GT 0x7DD = 基址 + v23，返回 1。
char __fastcall ScanKfdDriverSectionV2(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Rva1 = 0, Rva2 = 0, Save = 0, Rva3 = 0;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7DA);            // 0x140069D99
    if (!Offset)
    {
        FindKfdGetRefCalloutExport(PeBase, PeSize);               // 0x140069DA5
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7DA);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140069DBE
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140069DD4
        return Result;

    /* ---- L1（0x140069E26）：找 0x558 ---- */
    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x140069E06
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )
    {
        USHORT Type; ULONG Len, Cumul, F38;
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) break;
        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069E33
        Ctx.ReadPtr += Len;                                       // 0x140069E3D
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069E42
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);

        if (Type == 0x545)                                        // 0x140069E4E
            return Result;
        if (Type == 0x558)                                        // 0x140069E66
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;
            if (r && r < PeSize) { Rva1 = r; break; }              // 0x140069E73
        }
        if ((ULONG)(++i) >= 0x64) break;                          // 0x140069E6F
    }

    if (!Rva1 || Rva1 >= PeSize)                                  // 0x140069E82
        return Result;

    /* ---- L2（0x140069ECE）：1368 → 1065/1137 ---- */
    InitPESectionReadContext(PeBase + Rva1, PeSize - Rva1,        // 0x140069EB4
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )
    {
        USHORT Type; ULONG Len, Cumul, F70, F78; ULONG64 F88; UCHAR A0;
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) break;
        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069EDF
        Ctx.ReadPtr += Len;                                       // 0x140069EE9
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069EEE
        F70  = *(ULONG *)((PUCHAR)Entry + 0x70);
        F78  = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88  = *(ULONG64 *)((PUCHAR)Entry + 0x88);
        A0   = *(UCHAR *)((PUCHAR)Entry + 0xA0);

        if (Type == 0x558)                                        // 0x140069EFA
        {
            Rva2 = Cumul + *(ULONG *)((PUCHAR)Entry + 0x38) - (ULONG)(ULONG_PTR)PeBase;
        }
        else if (((Type == 1065 && (A0 & 4) != 0 && F88 == 0x400000000ULL && F70 == 1)
                  || (Type == 1137 && (A0 & 4) != 0))             // 0x140069F42
                 && Rva2 && Rva2 < PeSize)
        {
            Save = Rva2;                                          // 0x140069F52
            break;
        }
        if ((ULONG)(++i) >= 0x64) break;                          // 0x140069F4B
    }

    if (!Save || Save >= PeSize)                                  // 0x140069F64
        return Result;

    /* ---- L3（0x140069FB2）：1245 / 1277 / 318 ---- */
    InitPESectionReadContext(PeBase + Save, PeSize - Save,        // 0x140069F9B
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )
    {
        USHORT Type; ULONG Len, Cumul, F38, F58, F78; ULONG64 F88;
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) break;
        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069FC3
        Ctx.ReadPtr += Len;                                       // 0x140069FCD
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069FD2
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F58 = *(ULONG *)((PUCHAR)Entry + 0x58);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);

        if (Type == 1245 && *(ULONG *)((PUCHAR)Entry + 0x0C) == 1)// 0x140069FE4
        {
            if (F58 == 1 && (F88 & 0x10000ULL) != 0
                && (int)F78 > 0 && !Rva3)                          // 0x140069FFE
                Rva3 = F78;                                        // 0x14006A000
        }
        else if ((Type == 1277 && Rva3) || (Type == 318 && Rva3))  // 0x14006A022
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;      // 0x14006A02A
            if (r && r < PeSize)                                  // 0x14006A02C / 030
            {
                /* ---- L4（0x14006A086）：1296 ---- */
                InitPESectionReadContext(PeBase + r, PeSize - r,   // 0x14006A06E
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                for (ULONG k = 0; k < 0x1E; ++k)                  // 0x14006A0DC
                {
                    USHORT T4; ULONG L4, C4, F58b, F78b; ULONG64 F50b, F88b;
                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
                        return Result;

                    L4 = *(ULONG *)((PUCHAR)Entry + 0xF0);
                    C4 = L4 + (ULONG)Ctx.ReadPtr;                 // 0x14006A098
                    Ctx.ReadPtr += L4;                            // 0x14006A0A2
                    T4   = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);
                    F50b = *(ULONG64 *)((PUCHAR)Entry + 0x50);
                    F58b = *(ULONG *)((PUCHAR)Entry + 0x58);
                    F78b = *(ULONG *)((PUCHAR)Entry + 0x78);
                    F88b = *(ULONG64 *)((PUCHAR)Entry + 0x88);

                    if (T4 == 0x510 && F88b == 0x40000ULL          // 0x14006A0B5
                        && F78b != 0 && F50b == 64 && !F58b)       // 0x14006A0BC / 0C8
                    {
                        ULONG r3 = C4 + F78b - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A0CD
                        if (r3 && r3 < PeSize)                     // 0x14006A0CF / 0D3
                        {
                            GtWrite((GLOBAL_TABLE_INDEX)0x7DC, (__int64)Rva3);      // 0x14006A0E8
                            GtWrite((GLOBAL_TABLE_INDEX)0x7DD,
                                    ModuleBase + (__int64)r3);                      // 0x14006A0F7
                            return 1;
                        }
                    }
                }
                return Result;                                    // 0x14006A086
            }
        }
        if ((ULONG)(++i) >= 0x64) return Result;                  // 0x14006A037
    }
}