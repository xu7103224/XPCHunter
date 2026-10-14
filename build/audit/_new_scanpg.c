// ScanKernelModulePageOrRsrcSection — 扫描内核模块 PAGE/RSRC 节区（0x14006E52C）
// 对应原始驱动 0x14006E52C（545 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：读 GT 0x20/0x21 做有效性检查后
//   直接 `return 1`，与原始函数体无关。注释称"扫描 ntoskrnl 的 PAGE/RSRC 节区，
//   查找页面相关的保护数据"虽方向对，但没有任何扫描动作。
//   发现方式：差分显示原始读 GT 0x4312 并写 GT 0x2E6，我方只读 0x20/0x21；
//   逐条反汇编核对确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写（IDA 无伪代码）。
// 【语义】两段式 PE 节区扫描：
//   段 1：从 (GT20 + GT4312) 起，遍历最多 10 个条目，按类型 1368/1369(0x558/0x559)
//         且 字段+0x38 非零 定位出"第一个候选 RVA"（记入 ebx）。
//   段 2：从该 RVA 起再遍历最多 0x64 个条目，统计第 2 个满足
//         「类型 1298(0x512) 且 字段+0x88==0x40000 且 字段+0x08 非零
//           且 字段+0x50==64」的条目，算出其 RVA；
//   命中则写 GT 0x2E6 = ntoskrnl基址(GT3) + 该 RVA。
// 【原始汇编要点（含帧偏移 → 描述符字段的换算）】
//   上下文 = [rsp+0x40]（0x48 字节）；描述符 = [rbp-0x70]；rbp = rsp+0x130
//   → 描述符起始 = rsp+0xC0。
//     字段+0x38 = [rbp-0x38]（段1判别）      → rsp+0xC0+0x38 = rbp-0x38 ✓
//     字段+0x08 = [rbp+0x08]（段2判别，非零）→ 即描述符+0x08
//     字段+0x50 = [rbp-0x20]（==64）         → 描述符+0x50
//     字段+0x88 = [rbp+0x18]（==0x40000）    → 描述符+0x88
//   （上述换算与 0x120 描述符布局逐项吻合。）
__int64 ScanKernelModulePageOrRsrcSection(void)
{
    __int64  NtoskrnlBase;      // rsi = GT 0x20
    ULONG    NtoskrnlSize;      // edi = GT 0x21
    __int64  Base3;             // r15 = GT 3
    ULONG    StartRva;          // ebx = GT 0x4312
    ULONG    CandidateRva = 0;  // ebx
    ULONG    Cumul;             // rdx：累计读指针
    ULONG    i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];

    NtoskrnlBase = GtRead(GtEprocessField22);                    // 0x14006E563（0x20）
    NtoskrnlSize = (ULONG)GtRead(GtEprocessField23);             // 0x14006E575（0x21）
    Base3        = GtRead(GtNtoskrnlModuleBase);                 // 0x14006E582（3）

    if (!NtoskrnlBase || !NtoskrnlSize || !Base3)                 // 0x14006E58A/593/59B
        return 0;

    StartRva = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4312);        // 0x14006E5A9
    if (!StartRva || StartRva >= NtoskrnlSize)                   // 0x14006E5B1/5B9
        return 0;

    /* ---- 段 1：定位第一个候选 RVA（上限 10） ---- */
    InitPESectionReadContext(NtoskrnlBase + StartRva,            // 0x14006E5F3
                             NtoskrnlSize - StartRva,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    Cumul = (ULONG)Ctx.ReadPtr;                                  // 初始化后即基址
    for (i = 0; i < 0xA; ++i)                                    // 0x14006E655
    {
        USHORT Type;
        ULONG  Len, Calculated;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))      // 0x14006E604
            break;

        Len  = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul += Len;                                            // 0x14006E613
        Ctx.ReadPtr = Cumul;                                     // 同步读指针
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006E62D

        // 类型 0x558 或 0x559（原始：sub cx,0x558; cmp cx,1 → 即 (type-0x558)<=1）
        if ((USHORT)(Type - 0x558) <= 1
            && *(ULONG *)((PUCHAR)Entry + 0x38) != 0)            // 0x14006E641
        {
            ULONG F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
            Calculated = Cumul + F38 - (ULONG)NtoskrnlBase;      // 0x14006E648/64A
            if (Calculated && Calculated < NtoskrnlSize)         // 0x14006E64C/650
            {
                CandidateRva = Calculated;                       // 0x14006E65D
                break;
            }
        }
    }

    if (!CandidateRva)                                           // ebx 仍为 0 → 无候选
        return 0;

    /* ---- 段 2：从候选 RVA 起找第 2 个匹配条目（上限 0x64） ---- */
    InitPESectionReadContext(NtoskrnlBase + CandidateRva,        // 0x14006E68C
                             NtoskrnlSize - CandidateRva,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    Cumul = (ULONG)Ctx.ReadPtr;
    {
        ULONG MatchCount = 0;                                    // r14d
        for (i = 0; i < 0x64; ++i)                               // 0x14006E6FD
        {
            USHORT Type;
            ULONG  Len, F8;

            if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))  // 0x14006E69F
                return 0;                                        // 0x14006E71D

            Len  = *(ULONG *)((PUCHAR)Entry + 0xF0);
            Cumul += Len;                                        // 0x14006E6AE
            Ctx.ReadPtr = Cumul;
            Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006E6C2

            if (Type == 0x545)                                   // 0x14006E6CE（1349）
                break;
            if (Type == 0x512                                  // 0x14006E6D8（1298）
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL   // 0x14006E6DA
                && (F8 = *(ULONG *)((PUCHAR)Entry + 0x08)) != 0       // 0x14006E6E4
                && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40)        // 0x14006E6EB
            {
                if (++MatchCount == 2)                           // 0x14006E6F2/6F5
                {
                    ULONG Rva = Cumul + F8 - (ULONG)NtoskrnlBase;    // 0x14006E704/706
                    if (Rva && Rva < NtoskrnlSize)               // 0x14006E708/70A
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x2E6,       // 0x14006E718
                                Base3 + (__int64)Rva);
                    }
                    break;
                }
            }
        }
    }
    return 0;
}
