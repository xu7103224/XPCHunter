// ScanKernelModuleSectionForWin10 — 扫描内核模块节区（Win10 分支，0x14006DD80）
// 对应原始驱动 0x14006DD80（561 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（读 GT 0x20/0x21 校验后 return 1）。
//   发现方式：差分报原始读 GT 0x812（懒初始化 0x14006E750）/0x914/0x42C7/0x445C
//   并写 0x1C9/0x1CA。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【与同族的差异】新增**构建号分支**选取匹配值：
//     构建号 < 0x3AD7 → r15 = GT 0x42C7（全 64 位）
//     构建号 >= 0x3AD7 → r15d = (ULONG)GT 0x445C
//   目标槽 GT 0x812（懒初始化传 (0x43AE, 0x812)）；写出 GT 0x1C9/0x1CA；
//   第一个写值基址用 PE 头 ImageBase（r13）、第二个用 GT 3（rdi）；
//   0x510 分支要求 字段+0x58 == 2；扫描上限 0x100。
__int64 ScanKernelModuleSectionForWin10(void)
{
    __int64  TargetAddr;        // rbx = GT 0x812
    __int64  ImageBase;         // rsi = GT 0x20
    ULONG    ImageSize;         // r14 = GT 0x21
    __int64  ModuleBase;        // rdi = GT 3
    __int64  MatchVal;          // r15 / r15d
    ULONG    Build;
    __int64  HeaderImageBase;   // r13：PE 头 ImageBase
    ULONG    Candidate = 0;     // ebx
    ULONG    Rva;
    ULONG    i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];

    TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x812);               // 0x14006DDBE
    if (!TargetAddr)                                              // 0x14006DDC6
    {
        ResolveAndStoreKernelModuleAddress(0x43AE, 0x812);        // 0x14006DDD2（call 0x14006E750）
        TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x812);           // 0x14006DDD9
        if (!TargetAddr)                                          // 0x14006DDE1
            return 0;
    }

    ImageBase  = GtRead(GtEprocessField22);                       // 0x14006DDEF（0x20）
    ImageSize  = (ULONG)GtRead(GtEprocessField23);                // 0x14006DDFC（0x21）
    ModuleBase = GtRead(GtNtoskrnlModuleBase);                    // 0x14006DE09（3）

    Build = (ULONG)GtRead(GtWindowsBuildNumber);                  // 0x14006DE16（0x914）
    if (Build < 0x3AD7)                                           // 0x14006DE1B
        MatchVal = GtRead((GLOBAL_TABLE_INDEX)0x42C7);            // 0x14006DE27（全 64 位）
    else
        MatchVal = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x445C);     // 0x14006DE36（取低 32 位）

    if (!ImageBase || !ImageSize || !ModuleBase)                  // 0x14006DE3E/47/50
        return 0;
    if (TargetAddr <= ModuleBase)                                 // 0x14006DE59
        return 0;
    if ((ULONG)MatchVal == 0)                                     // 0x14006DE62
        return 0;
    if ((ULONG)(TargetAddr - ModuleBase) >= ImageSize)            // 0x14006DE6B/6F
        return 0;

    Rva = (ULONG)(TargetAddr - ModuleBase);                       // 0x14006DE78

    // PE 可选头 ImageBase
    HeaderImageBase = *(ULONG64 *)(ImageBase + *(int *)(ImageBase + 0x3C) + 0x30);  // 0x14006DE86/8F

    InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva,    // 0x14006DEBB
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x100; ++i)                                   // 0x14006DFA3
    {
        USHORT Type;
        ULONG  Len, F38;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006DECE
            return 0;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                       // 0x14006DEE5
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006DEF1

        if (Type == 0x558)                                        // 0x14006DEFA（1368）
        {
            if ((*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000ULL) != 0   // 0x14006DEFF
                && (F38 = *(ULONG *)((PUCHAR)Entry + 0x38)) != 0)          // 0x14006DF09
            {
                ULONG r = (ULONG)Ctx.ReadPtr + F38 - (ULONG)ImageBase;
                if (r == (ULONG)MatchVal)                                  // 0x14006DF14
                {
                    if (Candidate && Candidate < ImageSize)                // 0x14006DF1D/DF21
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x1C9,
                                HeaderImageBase + Candidate);              // 0x14006DF2F
                        GtWrite((GLOBAL_TABLE_INDEX)0x1CA,
                                ModuleBase + Candidate);                   // 0x14006DF3D
                        return 0;
                    }
                }
            }
        }
        else if (Type == 0x510)                                   // 0x14006DF77（1296）
        {
            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40             // 0x14006DF7C
                && *(ULONG *)((PUCHAR)Entry + 0x58) == 2               // 0x14006DF83
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL    // 0x14006DF89
                && *(ULONG *)((PUCHAR)Entry + 0x08) != 0)              // 0x14006DF93
            {
                Candidate = *(ULONG *)((PUCHAR)Entry + 0x08)
                            - (ULONG)ImageBase + (ULONG)Ctx.ReadPtr;   // 0x14006DF9A/9C/9E
            }
        }
    }
    return 0;
}
