// ScanKernelModuleDataSectionEx — 扫描内核模块数据节区（扩展版，0x14006DB78）
// 对应原始驱动 0x14006DB78（520 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（读 GT 0x20/0x21 校验后 return 1）。
//   发现方式：差分报原始读 GT 0x2E9（含懒初始化 call 0x14006E87C）/0x41EF
//   并写 0x2EA/0x2EB。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【与同族的差异】
//   目标槽 GT **0x2E9**（懒初始化器 0x14006E87C）；额外读 GT 0x41EF（单匹配值）；
//   命中写 GT **0x2EA/0x2EB**；第一个写值的基址取自 **PE 头 ImageBase**
//   （`*(QWORD*)(ImageBase + e_lfanew + 0x30)`），第二个用 GT 3；
//   0x510 分支要求 `字段+0x58 == 2`（InitSection 版是 8）；
//   扫描上限 0x100。
// 【帧换算】上下文 = [rsp+0x40]；描述符 = [rbp-0x70]；rbp = rsp+0x130
//   → 描述符起始 = rsp+0xC0，与 InitSection 版一致。
__int64 ScanKernelModuleDataSectionEx(void)
{
    __int64  TargetAddr;        // rbx = GT 0x2E9
    __int64  ImageBase;         // r14 = GT 0x20
    ULONG    ImageSize;         // esi = GT 0x21
    __int64  ModuleBase;        // rdi = GT 3
    ULONG    MatchVal;          // r12d = GT 0x41EF
    __int64  HeaderImageBase;   // r13：PE 头 ImageBase
    ULONG    Candidate = 0;     // ebx
    ULONG    Rva;
    ULONG    i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];

    TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x2E9);               // 0x14006DBB6
    if (!TargetAddr)                                              // 0x14006DBBE
    {
        ResolveKernelModuleIndexAddress(0, 0);                    // 0x14006DBC3（call 0x14006E87C，原驱动无参传值）
        TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x2E9);           // 0x14006DBCA
        if (!TargetAddr)                                          // 0x14006DBD2
            return 0;
    }

    ImageBase  = GtRead(GtEprocessField22);                       // 0x14006DBE0（0x20）
    ImageSize  = (ULONG)GtRead(GtEprocessField23);                // 0x14006DBED（0x21）
    ModuleBase = GtRead(GtNtoskrnlModuleBase);                    // 0x14006DBFA（3）
    MatchVal   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41EF);       // 0x14006DC07

    if (!ImageBase || !ImageSize || !ModuleBase)                  // 0x14006DC0F/18/20
        return 0;
    if (TargetAddr <= ModuleBase)                                 // 0x14006DC29
        return 0;
    if (!MatchVal)                                                // 0x14006DC32
        return 0;
    if ((ULONG)(TargetAddr - ModuleBase) >= ImageSize)            // 0x14006DC3A/3E
        return 0;

    Rva = (ULONG)(TargetAddr - ModuleBase);                       // 0x14006DC46

    // PE 可选头 ImageBase
    HeaderImageBase = *(ULONG64 *)(ImageBase + *(int *)(ImageBase + 0x3C) + 0x30);  // 0x14006DC54/5E

    InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva,    // 0x14006DC89
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x100; ++i)                                   // 0x14006DD72
    {
        USHORT Type;
        ULONG  Len, F38;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006DC9C
            return 0;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                       // 0x14006DCB3
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006DCBF

        if (Type == 0x558)                                        // 0x14006DCC8（1368）
        {
            if ((*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000ULL) != 0   // 0x14006DCCD
                && (F38 = *(ULONG *)((PUCHAR)Entry + 0x38)) != 0)          // 0x14006DCD7
            {
                ULONG r = (ULONG)Ctx.ReadPtr + F38 - (ULONG)ImageBase;
                if (r == MatchVal)                                         // 0x14006DCE3
                {
                    if (Candidate && Candidate < ImageSize)                // 0x14006DCEC/DCF0
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x2EA,
                                HeaderImageBase + Candidate);              // 0x14006DCFD（PE 头基址）
                        GtWrite((GLOBAL_TABLE_INDEX)0x2EB,
                                ModuleBase + Candidate);                   // 0x14006DD0B（GT3）
                        return 0;
                    }
                }
            }
        }
        else if (Type == 0x510)                                   // 0x14006DD45（1296）
        {
            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40             // 0x14006DD4A
                && *(ULONG *)((PUCHAR)Entry + 0x58) == 2               // 0x14006DD51
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL    // 0x14006DD57
                && *(ULONG *)((PUCHAR)Entry + 0x08) != 0)              // 0x14006DD61
            {
                Candidate = *(ULONG *)((PUCHAR)Entry + 0x08)
                            - (ULONG)ImageBase + (ULONG)Ctx.ReadPtr;   // 0x14006DD68/6A/6D
            }
        }
    }
    return 0;
}
