// ScanKernelModuleInitSection — 扫描内核模块 INIT 节区（0x14006D974）
// 对应原始驱动 0x14006D974（515 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：读 GT 0x20/0x21 校验后 `return 1`。
//   原始是完整的 PE 节区扫描器（栈帧 0x1C0、两段扫描、写 GT 0x431B/0x431C）。
//   发现方式：差分报原始读 GT 0x4322/0x439F/0x41C5 并写 0x431B/0x431C，我方仅读 0x20/0x21。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【帧换算】描述符基址 = [rbp-0x70]；故 字段+0x38=[rbp-0x38]、
//   字段+0x50=[rbp-0x20]、字段+0x58=[rbp-0x18]、字段+0x88=[rbp+0x18]、
//   字段+0x08=[rbp+0x08]、字段+0xF0=[rbp+0x80]、字段+0x118=[rbp+0xA8]。
// 【流程】
//   ① rbx = GT 0x4322（目标绝对地址，非 0）；r15 = GT 0x20（映像基址）；
//      esi = GT 0x21（大小）；rdi = GT 3（模块加载基址）；
//      r13 = GT 0x439F；r12 = GT 0x41C5。全部须非 0，且 rbx > rdi、(rbx-rdi) < esi。
//   ② 以 (r15 + (rbx-rdi), esi - (rbx-rdi)) 初始化读取上下文。
//   ③ 循环（上限 0x100）：
//      - 类型 0x558(1368) 且 (字段+0x50 & 0x4000000) 且 字段+0x38 != 0：
//          rva = 累计 + 字段+0x38 - 基址；若 rva 等于 GT0x439F 或 GT0x41C5 →
//          此时若"候选"(ebx) 已由下方 0x510 分支设过且 < 大小 →
//            写 GT 0x431B = ebx、GT 0x431C = 模块基址 + ebx，返回；
//          否则继续。
//      - 类型 0x510(1296) 且 字段+0x50==0x40 且 字段+0x58==8 且
//        字段+0x88==0x40000 且 字段+0x08 != 0 →
//          候选 ebx = 字段+0x08 - 基址 + 累计（记下待上面的 0x558 分支确认）。
// 【返回值】原始恒为 0（结果通过 GT 写出）。
__int64 ScanKernelModuleInitSection(void)
{
    __int64  TargetAddr;        // rbx = GT 0x4322
    __int64  ImageBase;         // r15 = GT 0x20
    ULONG    ImageSize;         // esi = GT 0x21
    __int64  ModuleBase;        // rdi = GT 3
    ULONG    MatchA;            // r13d = GT 0x439F
    ULONG    MatchB;            // r12d = GT 0x41C5
    ULONG    Candidate = 0;     // ebx
    ULONG    Rva;
    ULONG    i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];

    TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x4322);              // 0x14006D9B0
    if (!TargetAddr)                                              // 0x14006D9B8
        return 0;

    ImageBase  = GtRead(GtEprocessField22);                       // 0x14006D9C6（0x20）
    ImageSize  = (ULONG)GtRead(GtEprocessField23);                // 0x14006D9D3（0x21）
    ModuleBase = GtRead(GtNtoskrnlModuleBase);                    // 0x14006D9E0（3）
    MatchA     = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x439F);       // 0x14006D9ED
    MatchB     = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41C5);       // 0x14006D9FA

    if (!ImageBase || !ImageSize || !ModuleBase)                  // 0x14006DA02/0A0B/0A13
        return 0;
    if (TargetAddr <= ModuleBase)                                 // 0x14006DA1C
        return 0;
    if (!MatchA || !MatchB)                                       // 0x14006DA25 / DA2E
        return 0;
    if ((ULONG)(TargetAddr - ModuleBase) >= ImageSize)            // 0x14006DA36/3A
        return 0;

    Rva = (ULONG)(TargetAddr - ModuleBase);                       // 0x14006DA42
    /* 原始在此有一处恒定成立的自校验（`add rax,rdi; cmp rbx,rax; jne`），不表。 */

    InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva,    // 0x14006DA7C
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x100; ++i)                                   // 0x14006DB69
    {
        USHORT Type;
        ULONG  Len, F38;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006DA8F
            return 0;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                       // 0x14006DAA6
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006DAB2

        if (Type == 0x558)                                        // 0x14006DABB（1368）
        {
            if ((*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000ULL) != 0   // 0x14006DAC0
                && (F38 = *(ULONG *)((PUCHAR)Entry + 0x38)) != 0)          // 0x14006DACA
            {
                ULONG r = (ULONG)Ctx.ReadPtr + F38 - (ULONG)ImageBase;    // 0x14006DAD1/DA74
                if (r == MatchA || r == MatchB)                            // 0x14006DAD6/DADB
                {
                    if (Candidate && Candidate < ImageSize)                // 0x14006DAE4/DAE8
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x431B, Candidate);    // 0x14006DAF4
                        GtWrite((GLOBAL_TABLE_INDEX)0x431C,
                                ModuleBase + Candidate);                   // 0x14006DB02
                        return 0;
                    }
                }
            }
        }
        else if (Type == 0x510)                                   // 0x14006DB37（1296）
        {
            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40             // 0x14006DB41
                && *(ULONG *)((PUCHAR)Entry + 0x58) == 8               // 0x14006DB48
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL    // 0x14006DB4E
                && *(ULONG *)((PUCHAR)Entry + 0x08) != 0)              // 0x14006DB58
            {
                Candidate = *(ULONG *)((PUCHAR)Entry + 0x08)
                            - (ULONG)ImageBase + (ULONG)Ctx.ReadPtr;   // 0x14006DB5F/61/64
            }
        }
    }
    return 0;
}
