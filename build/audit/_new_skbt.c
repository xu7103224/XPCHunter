// ScanKernelModuleSectionByType — 按类型扫描内核模块节区（0x14006E26C）
// 对应原始驱动 0x14006E26C（563 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（读 GT 0x20/0x21 校验后 return 1）。
//   发现方式：差分报原始读 GT 0x1C1（含懒初始化）/0x439F/0x41C5 并写 0x1C2/0x1C3。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【与同族（ScanKernelModuleInitSection）的差异】
//   1) 目标槽是 **GT 0x1C1**（不是 0x4322），且带懒初始化：
//      为空则调 0x14006E750(GT 0x4240, 0x1C1) 重新解析后再取；
//   2) 扫描上限为 **0x12C**（不是 0x100）；
//   3) 命中时写 **GT 0x1C2 / 0x1C3**（不是 0x431B/0x431C）；
//   4) 写第一个值时基址取自 **PE 头 [r15+0x3C] → +0x30**（即
//      `*(QWORD*)(ImageBase + e_lfanew + 0x30)`，PE32+ 的 ImageBase 字段），
//      而 InitSection 版用的是 GT 3；第二个值仍用 GT 3（rdi）。
// 【帧换算】上下文 = [rsp+0x50]；描述符 = [rbp-0x60]；rbp = rsp+0x138
//   → 描述符起始 = rsp+0xD8。故
//     字段+0x38=[rbp-0x28]、+0x50=[rbp-0x10]、+0x58=[rbp-8]、+0x88=[rbp+0x28]、
//     字段+0x08=[rbp+0x18]、+0xF0=[rbp+0x90]、+0x118=[rbp+0xB8]。
__int64 ScanKernelModuleSectionByType(void)
{
    __int64  TargetAddr;        // rbx = GT 0x1C1
    __int64  ImageBase;         // r15 = GT 0x20
    ULONG    ImageSize;         // esi = GT 0x21
    __int64  ModuleBase;        // rdi = GT 3
    ULONG    MatchA;            // r13d = GT 0x439F
    ULONG    MatchB;            // r12d = GT 0x41C5
    ULONG    Candidate = 0;     // ebx
    ULONG    Rva;
    ULONG    i;
    __int64  HeaderImageBase;   // [rsp+0x40]：PE 可选头 ImageBase
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];

    TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x1C1);               // 0x14006E2AA
    if (!TargetAddr)                                              // 0x14006E2B2
    {
        // 懒初始化：以 (GT 0x4240, 0x1C1) 重新解析
        ResolveAndStoreKernelModuleAddress(0x4240, 0x1C1);        // 0x14006E2BE（call 0x14006E750）
        TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x1C1);           // 0x14006E2C5
        if (!TargetAddr)                                          // 0x14006E2D0
            return 0;
    }

    ImageBase  = GtRead(GtEprocessField22);                       // 0x14006E2DB（0x20）
    ImageSize  = (ULONG)GtRead(GtEprocessField23);                // 0x14006E2E8（0x21）
    ModuleBase = GtRead(GtNtoskrnlModuleBase);                    // 0x14006E2F5（3）
    MatchA     = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x439F);       // 0x14006E302
    MatchB     = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41C5);       // 0x14006E30F

    if (!ImageBase || !ImageSize || !ModuleBase)                  // 0x14006E317/320/328
        return 0;
    if (TargetAddr <= ModuleBase)                                 // 0x14006E331
        return 0;
    if (!MatchA || !MatchB)                                       // 0x14006E33A / E343
        return 0;
    if ((ULONG)(TargetAddr - ModuleBase) >= ImageSize)            // 0x14006E34B/34F
        return 0;

    Rva = (ULONG)(TargetAddr - ModuleBase);                       // 0x14006E357

    // PE 可选头 ImageBase（PE32+：e_lfanew 后 +0x30 处的 8 字节）
    HeaderImageBase = *(ULONG64 *)(ImageBase + *(int *)(ImageBase + 0x3C) + 0x30);  // 0x14006E365/36F

    InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva,    // 0x14006E39F
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x12C; ++i)                                   // 0x14006E491
    {
        USHORT Type;
        ULONG  Len, F38;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006E3B2
            return 0;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                       // 0x14006E3C9
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006E3D5

        if (Type == 0x558)                                        // 0x14006E3DE（1368）
        {
            if ((*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000ULL) != 0   // 0x14006E3E3
                && (F38 = *(ULONG *)((PUCHAR)Entry + 0x38)) != 0)          // 0x14006E3ED
            {
                ULONG r = (ULONG)Ctx.ReadPtr + F38 - (ULONG)ImageBase;
                if (r == MatchA || r == MatchB)                            // 0x14006E3F9/3FE
                {
                    if (Candidate && Candidate < ImageSize)                // 0x14006E407/40B
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x1C2,
                                HeaderImageBase + Candidate);              // 0x14006E41C（用 PE 头基址）
                        GtWrite((GLOBAL_TABLE_INDEX)0x1C3,
                                ModuleBase + Candidate);                   // 0x14006E42A（用 GT3）
                        return 0;
                    }
                }
            }
        }
        else if (Type == 0x510)                                   // 0x14006E464（1296）
        {
            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40             // 0x14006E469
                && *(ULONG *)((PUCHAR)Entry + 0x58) == 8               // 0x14006E470
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL    // 0x14006E476
                && *(ULONG *)((PUCHAR)Entry + 0x08) != 0)              // 0x14006E480
            {
                Candidate = *(ULONG *)((PUCHAR)Entry + 0x08)
                            - (ULONG)ImageBase + (ULONG)Ctx.ReadPtr;   // 0x14006E487/489/48C
            }
        }
    }
    return 0;
}
