// ScanKernelModulePESectionsEx — 扫描内核模块 PE 节区（扩展版，0x14007DAB8）
// 对应原始驱动 0x14007DAB8（818 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（读 GT 0x20/0x21 校验后 return 1）。
//   发现方式：差分报原始读 GT 0x20/0x21/3/2/0x41C5/0x439F/0x914/0x909/0x1DE/0x1DD
//   并写 0x2D6/0x2D7。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【语义】**两段顺序扫描**，每段上限 0x50，各写一个结果槽：
//   段 1 → GT 0x2D6；段 2 → GT 0x2D7。
//   每段的入口 RVA 分别来自 GT 0x1DE 与 GT 0x1DD（两次独立读取）。
// 【构建号分支】
//   `构建号 >= 0x3AD7` → r14 = GT 0x909（额外匹配值）
//   否则             → r14 = 0（不参与匹配）
// 【匹配值集合（两段相同）】
//   某条目的 RVA 若不等于 GT 0x439F、不等于 GT 0x914、也不等于 r14，
//   则该条目被记为"待写"（r15b=1）；随后一条满足
//   「类型 1368 且 (字段+0x50 & 0x4000000) 且 字段+0x38 非零」的条目
//   会把"待写"置位；**只有待写已置位时**才写出该条目 RVA。
// 即：先用一个任意条目"武装"标志，再用下一个 1368 条目触发写出。
// 【帧换算】上下文 = [rsp+0x50]；描述符 = [rbp-0x60]；rbp = rsp+0x168
//   → 描述符起始 = rsp+0x108。故 字段+0x50=[rbp-0x10]、+0x38=[rbp-0x28]、
//   +0xF0=[rbp+0x90]、+0x118=[rbp+0xB8]。
static void ScanPESectionsOnePhase(__int64 ImageBase, ULONG ImageSize, __int64 ModuleBase,
                                   __int64 EntryRva, ULONG Match1, ULONG MatchBuild,
                                   ULONG MatchExtra, ULONG OutIndex)
{
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];
    UCHAR   Armed = 0;              // r15b
    ULONG   i;

    InitPESectionReadContext(ImageBase + EntryRva, ImageSize - EntryRva,   // 0x14007DBFA / 0x14007DD09
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x50; ++i)                                             // 0x14007DDCD / 0x14007DDE0
    {
        USHORT Type;
        ULONG  Len, F38;
        ULONG  Rva;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))                 // 0x14007DC0D
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                                // 0x14007DC2D
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);     // 0x14007DC39

        if (Type == 0x558)                                                 // 0x14007DC3D
        {
            if ((*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000ULL) != 0  // 0x14007DC43
                && (F38 = *(ULONG *)((PUCHAR)Entry + 0x38)) != 0)          // 0x14007DC51
            {
                Rva = (ULONG)Ctx.ReadPtr + F38 - (ULONG)ImageBase;         // 0x14007DC5C/5F
                if (Rva)                                                   // 0x14007DC61
                {
                    if (Rva < ImageSize)                                   // 0x14007DC69
                    {
                        if (Rva == Match1                                 // 0x14007DC72（GT 0x439F）
                            || Rva == MatchBuild                          // 0x14007DC7C（GT 0x914）
                            || (MatchExtra && Rva == MatchExtra))         // 0x14007DC87
                        {
                            Armed = 1;                                    // 0x14007DDC8 / 0x14007DDDB
                            continue;
                        }
                        if (Armed == 1)                                   // 0x14007DC90
                        {
                            GtWrite((GLOBAL_TABLE_INDEX)OutIndex,          // 0x14007DCA4 / 0x14007DD93
                                    ModuleBase + Rva);
                            return;
                        }
                    }
                }
            }
        }
    }
}

__int64 ScanKernelModulePESectionsEx(void)
{
    __int64  ImageBase;         // r12 = GT 0x20
    ULONG    ImageSize;         // esi = GT 0x21
    __int64  ModuleBase;        // rbx = GT 3
    __int64  Base2;             // rdi = GT 2
    ULONG    Match1;            // r13d = GT 0x41C5
    ULONG    MatchBuild;        // [rsp+0x40] = GT 0x914（构建号）
    ULONG    MatchExtra;        // r14 = GT 0x909（构建号 >= 0x3AD7 时）
    __int64  EntryRvaA;         // rcx = GT 0x1DE（段 1 入口）
    __int64  EntryRvaB;         // rax = GT 0x1DD（段 2 入口）

    ImageBase  = GtRead(GtEprocessField22);                       // 0x14007DAF4（0x20）
    ImageSize  = (ULONG)GtRead(GtEprocessField23);                // 0x14007DB01（0x21）
    ModuleBase = GtRead(GtNtoskrnlModuleBase);                    // 0x14007DB0E（3）
    Base2      = GtRead((GLOBAL_TABLE_INDEX)2);                   // 0x14007DB1B（2）
    Match1     = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41C5);       // 0x14007DB28

    MatchBuild = (ULONG)GtRead(GtWindowsBuildNumber);             // 0x14007DB47（0x914）
    if (MatchBuild >= 0x3AD7)                                     // 0x14007DB4C
        MatchExtra = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x909);    // 0x14007DB58
    else
        MatchExtra = 0;                                           // 0x14007DB62

    EntryRvaA = GtRead((GLOBAL_TABLE_INDEX)0x1DE);                // 0x14007DB6A

    if (!ImageBase || !ImageSize || !Match1 || !MatchBuild        // 0x14007DB72..DB98
        || !Base2 || !EntryRvaA)
        return 0;

    /* 段 1 → GT 0x2D6 */
    {
        ULONG Rva = (ULONG)(EntryRvaA - Base2);                   // 0x14007DBAF
        if (Rva == 0 || Rva >= ImageSize)                          // 0x14007DBB1/DBB9
            goto PHASE2;
        ScanPESectionsOnePhase(ImageBase, ImageSize, ModuleBase,   // 0x14007DBFA
                               Rva, Match1, MatchBuild, MatchExtra, 0x2D6);
    }

PHASE2:
    /* 段 2 → GT 0x2D7（入口 RVA 独立取自 GT 0x1DD） */
    EntryRvaB = GtRead((GLOBAL_TABLE_INDEX)0x1DD);                // 0x14007DCAE
    if (EntryRvaB)
    {
        ULONG Rva = (ULONG)(EntryRvaB - (ULONG)ModuleBase);        // 0x14007DCBC
        if (Rva != 0 && Rva < ImageSize)                          // 0x14007DCC0/DCC8
        {
            ScanPESectionsOnePhase(ImageBase, ImageSize, ModuleBase,  // 0x14007DD09
                                   Rva, Match1, MatchBuild, MatchExtra, 0x2D7);
        }
    }
    return 0;
}
