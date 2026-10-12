// ScanNsiGetModuleDataSection — 双层嵌套扫描 NSI GetModule 数据节区
// 对应原始驱动 0x140069238（715 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】原始序言 `mov ecx,7CAh`（GT 调用序经寄存器跟踪提取）：
//   首读 0x7CA（配对 Find* 的导出偏移槽）→ 再读 0x1A1（模块基址）
//   → 命中写 0x7CC / 0x7CD（本函数的结果槽）。
// 【字段映射】描述符仍为 0x120 布局：+0x38 +0x40 +0x50 +0x58 +0x70 +0x78 +0x88 +0xF0 +0x118。
// 【算法】外层（上限 0x1E）：类型 1334 且 字段+0x70 == 1 → 置标记；
//   类型 0x558 且 标记已置 → 由 字段+0x38 算 RVA，合法则进入内层。
//   内层（上限 0x64）：类型 0x558 → 置标记2；其余分支按 1243 / 1298 / 其它 分流，
//   记录两个候选 RVA 并在两者相符时写 GT 0x7CC/0x7CD（= 基址 + 各候选），返回 1。
char __fastcall ScanNsiGetModuleDataSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i, j;
    UCHAR   Mark1 = 0;            // v7（外层标记）
    UCHAR   Mark2 = 0;            // v12（内层标记）
    ULONG   Cand1 = 0;            // v13：候选1
    ULONG   Cand2 = 0;            // v14：候选2
    ULONG   Cand2Saved = 0;       // v20：候选2 的上次值
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7CA);            // 0x14006927D
    if (!Offset)
    {
        FindNsiGetModuleHandle(PeBase, PeSize);                   // 0x140069289
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7CA);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x1400692A2
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x1400692B8
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x1400692EE
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; ; )                                               // 0x140069308（外层 while）
    {
        USHORT Type;
        ULONG  Len, Cumul;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069319
        Ctx.ReadPtr += Len;                                       // 0x140069323
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069328

        if (Type == 1334 && *(ULONG64 *)((PUCHAR)Entry + 0x70) == 1)   // 0x14006933B
        {
            Mark1 = 1;                                            // 0x14006933D
        }
        else if (Type == 0x558 && Mark1 == 1)                     // 0x140069350
        {
            ULONG Rva = Cumul + *(ULONG *)((PUCHAR)Entry + 0x38) - (ULONG)(ULONG_PTR)PeBase;
            if (Rva && Rva < PeSize)                              // 0x140069358 / 35A / 35E
            {
                InitPESectionReadContext(PeBase + Rva, PeSize - Rva,   // 0x140069399
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                Mark2 = 0; Cand1 = 0; Cand2 = 0; Cand2Saved = 0;

                for (j = 0; ; )                                   // 0x1400693BE（内层 while）
                {
                    USHORT T2;
                    ULONG  L2, C2;

                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
                        return Result;

                    L2 = *(ULONG *)((PUCHAR)Entry + 0xF0);
                    C2 = L2 + (ULONG)Ctx.ReadPtr;                 // 0x1400693CF
                    Ctx.ReadPtr += L2;                            // 0x1400693D9
                    T2 = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400693DE

                    if (T2 == 0x558)                              // 0x1400693EA
                    {
                        Mark2 = 1;                                // 0x1400693EC
                    }
                    else if (T2 != 1298 || Mark2)                 // 0x1400693FE
                    {
                        if (T2 == 1243)                           // 0x14006943B
                        {
                            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000ULL)   // 0x140069445
                            {
                                if (*(ULONG *)((PUCHAR)Entry + 0x40) != 0)          // 0x14006944C
                                {
                                    if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 64    // 0x140069459
                                        && Mark2 == 1 && Cand1)
                                    {
                                        ULONG v14 = C2 + *(ULONG *)((PUCHAR)Entry + 0x40)
                                                    - (ULONG)(ULONG_PTR)PeBase;   // 0x140069463
                                        if (v14 && v14 < PeSize)                      // 0x140069465/469
                                        {
                                            GtWrite((GLOBAL_TABLE_INDEX)0x7CC,
                                                    ModuleBase + (__int64)Cand1);   // LABEL_49
                                            GtWrite((GLOBAL_TABLE_INDEX)0x7CD,
                                                    ModuleBase + (__int64)v14);
                                            return 1;
                                        }
                                    }
                                }
                                Cand2 = Cand2Saved;                   // 0x14006946B
                            }
                        }
                        else if (Mark2 == 1
                                 && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL
                                 && *(ULONG *)((PUCHAR)Entry + 0x78) != 0
                                 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64)     // 0x14006949F
                        {
                            ULONG v18 = C2 + *(ULONG *)((PUCHAR)Entry + 0x78)
                                        - (ULONG)(ULONG_PTR)PeBase;               // 0x1400694A4
                            if (v18 == Cand2 && v18)                              // 0x1400694AC
                            {
                                GtWrite((GLOBAL_TABLE_INDEX)0x7CC,
                                        ModuleBase + (__int64)Cand1);             // LABEL_49
                                GtWrite((GLOBAL_TABLE_INDEX)0x7CD,
                                        ModuleBase + (__int64)Cand2);
                                return 1;
                            }
                            Cand2 = Cand2Saved = v18;                   // 0x1400694AE / 4B0
                        }
                    }
                    else if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)  // 0x140069408
                    {
                        if (*(ULONG *)((PUCHAR)Entry + 0x78) != 0)               // 0x14006940F
                        {
                            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 64
                                && *(ULONG *)((PUCHAR)Entry + 0x58) == 1)            // 0x14006941C
                            {
                                ULONG v17 = C2 + *(ULONG *)((PUCHAR)Entry + 0x78)
                                            - (ULONG)(ULONG_PTR)PeBase;          // 0x140069421
                                if (v17 && v17 < PeSize && !Cand1)                   // 0x140069423 / 42C
                                    Cand1 = v17;                                     // 0x14006942E
                            }
                        }
                    }

                    if ((ULONG)(++j) >= 0x64)                                 // 0x14006947C
                        return Result;
                }
            }
        }

        if ((ULONG)(++i) >= 0x1E)                                     // 0x140069365
            return Result;
    }
    return Result;                                                    // 0x1400694D9
}