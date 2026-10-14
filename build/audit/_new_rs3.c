// ScanKernelModuleSectionForWin10RS3 — 扫描内核模块节区（Win10 RS3 分支，0x14006DFB4）
// 对应原始驱动 0x14006DFB4（696 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（读 GT 0x20/0x21 校验后 return 1）。
//   发现方式：差分报原始读 GT 0x1C4（懒初始化 (0x4237,0x1C4)）/0x914/0x41EF/0x4450
//   并写 0x1C5/0x1C6，且含一个 memset。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【与 ForWin10 版（0x14006DD80）的差异】
//   1) 目标槽 GT **0x1C4**（懒初始化传 (0x4237, 0x1C4)）；
//   2) 构建号判据不同：`构建号 == 0x3FAB` 或 `>= 0x4F7C` → 用 GT 0x4450（低32位）；
//      否则用 GT 0x41EF（全 64 位）；
//   3) 多一个 **0x40 字节局部数组** `[rbp+0xB0]`，循环前 memset 清零；
//      循环内当遇到 `类型1296 且 字段+0x50==0x40 且 字段+0x88==0x40000
//      且 字段+0x08 非零` 时，把该条目的 RVA 存入 `数组[字段+0x58]`；
//   4) 末尾多一段**回退查找**：再次读到 `类型1296 且 字段+0x50==0x40 且
//      字段+0x58==2 且 字段+0x88==字段+0x50` 时，用
//      `数组[字段+0x20]`（若非零）覆盖候选；
//   5) 写出 GT **0x1C5/0x1C6**。
// 【帧换算】上下文 = [rsp+0x40]；描述符 = [rbp-0x70]；rbp = rsp+0x168
//   → 描述符起始 = rsp+0xF8。故 字段+0x38=[rbp-0x38]、+0x50=[rbp-0x20]、
//   +0x58=[rbp-0x18]、+0x88=[rbp+0x18]、+0x08=[rbp+8]、+0x20=[rbp+0x20]、
//   +0xF0=[rbp+0x80]、+0x118=[rbp+0xA8]。
__int64 ScanKernelModuleSectionForWin10RS3(void)
{
    __int64  TargetAddr;        // rbx = GT 0x1C4
    __int64  ImageBase;         // rsi = GT 0x20
    ULONG    ImageSize;         // r14 = GT 0x21
    __int64  ModuleBase;        // rdi = GT 3
    __int64  MatchVal;          // r15 / r15d
    ULONG    Build;
    __int64  HeaderImageBase;   // r13：PE 头 ImageBase
    ULONG    Candidate = 0;     // ebx
    ULONG    Rva;
    ULONG    i;
    ULONG    SlotTable[0x10];   // [rbp+0xB0]，0x40 字节
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];

    TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x1C4);               // 0x14006DFF2
    if (!TargetAddr)                                              // 0x14006DFFA
    {
        ResolveAndStoreKernelModuleAddress(0x4237, 0x1C4);        // 0x14006E006（call 0x14006E750）
        TargetAddr = GtRead((GLOBAL_TABLE_INDEX)0x1C4);           // 0x14006E00D
        if (!TargetAddr)                                          // 0x14006E015
            return 0;
    }

    ImageBase  = GtRead(GtEprocessField22);                       // 0x14006E023（0x20）
    ImageSize  = (ULONG)GtRead(GtEprocessField23);                // 0x14006E030（0x21）
    ModuleBase = GtRead(GtNtoskrnlModuleBase);                    // 0x14006E03D（3）

    Build = (ULONG)GtRead(GtWindowsBuildNumber);                  // 0x14006E04E（0x914）
    if (Build == 0x3FAB || Build >= 0x4F7C)                       // 0x14006E053/062
        MatchVal = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4450);     // 0x14006E07D（低 32 位）
    else
        MatchVal = GtRead((GLOBAL_TABLE_INDEX)0x41EF);            // 0x14006E06E（全 64 位）

    if (!ImageBase || !ImageSize || !ModuleBase)                  // 0x14006E085/08E/097
        return 0;
    if (TargetAddr <= ModuleBase)                                 // 0x14006E0A0
        return 0;
    if ((ULONG)MatchVal == 0)                                     // 0x14006E0A9
        return 0;
    if ((ULONG)(TargetAddr - ModuleBase) >= ImageSize)            // 0x14006E0B2/0B6
        return 0;

    Rva = (ULONG)(TargetAddr - ModuleBase);                       // 0x14006E0BF

    // PE 可选头 ImageBase
    HeaderImageBase = *(ULONG64 *)(ImageBase + *(int *)(ImageBase + 0x3C) + 0x30);  // 0x14006E0CD/0D6

    InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva,    // 0x14006E102
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    memset(SlotTable, 0, sizeof(SlotTable));                      // 0x14006E116（40h 字节）

    for (i = 0; i < 0x100; ++i)                                   // 0x14006E209
    {
        USHORT Type;
        ULONG  Len, F38, F80;
        ULONG64 F50, F88;
        ULONG  F58, F8;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006E127
            return 0;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                       // 0x14006E151
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);                 // [rbp+0x18]
        F8  = *(ULONG *)((PUCHAR)Entry + 0x08);                   // [rbp+8]
        F58 = *(ULONG *)((PUCHAR)Entry + 0x58);                   // [rbp-0x18]
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);                 // [rbp-0x20]
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006E15D

        if (Type == 0x558)                                        // 0x14006E167（1368）
        {
            if ((F50 & 0x4000000ULL) != 0                         // 0x14006E16D（bt r8,0x1a）
                && (F38 = *(ULONG *)((PUCHAR)Entry + 0x38)) != 0) // 0x14006E174
            {
                ULONG r = (ULONG)Ctx.ReadPtr + F38 - (ULONG)ImageBase;
                if (r == (ULONG)MatchVal)                         // 0x14006E17F
                {
                    if (Candidate && Candidate < ImageSize)       // 0x14006E217/21B
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x1C5,
                                HeaderImageBase + Candidate);     // 0x14006E229
                        GtWrite((GLOBAL_TABLE_INDEX)0x1C6,
                                ModuleBase + Candidate);          // 0x14006E237
                        return 0;
                    }
                }
            }
        }
        else if (Type == 0x510)                                   // 0x14006E194（1296）
        {
            // 子分支 1：把 RVA 存入 SlotTable[字段+0x58]
            if (F50 == 0x40 && F58 == 2 && F88 == 0x40000ULL && F8 != 0)  // 0x14006E19A..1B1
            {
                Candidate = F8 - (ULONG)ImageBase + (ULONG)Ctx.ReadPtr;   // 0x14006E1B3/1B5/1B7
            }
            // 子分支 2：把 RVA 存入 SlotTable[字段+0x58]
            if (F50 == 0x40 && F88 == 0x40000ULL && F8 != 0)              // 0x14006E1BF..1D0
            {
                ULONG r2 = F8 - (ULONG)ImageBase + (ULONG)Ctx.ReadPtr;    // 0x14006E1D2/1D4
                if (F58 < 0x10) SlotTable[F58] = r2;                      // 0x14006E1D6
            }
            // 子分支 3：若 `字段+0x50 == 字段+0x88` 且 字段+0x58==2，
            //   用 SlotTable[字段+0x20]（非零时）覆盖候选
            if (F50 == 0x40 && F58 == 2 && F88 == F50)                    // 0x14006E1E6..1F5
            {
                F80 = *(ULONG *)((PUCHAR)Entry + 0x20);                   // 0x14006E1F7 [rbp+0x20]
                if (F80 < 0x10)
                {
                    ULONG v = SlotTable[F80];                             // 0x14006E1FA
                    if (v) Candidate = v;                                 // 0x14006E203
                }
            }
        }
    }
    return 0;
}
