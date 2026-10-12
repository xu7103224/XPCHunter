// ParseNtImageSections — 解析 NT/fltmgr 镜像节区并填充全局表
// 对应原始驱动 0x1400166EC（3005 字节 / 807 条指令）
// 【逆向来源】人工阅读 capstone + IDA 反汇编**逐条转写** —— IDA `decompile` 返回 None
//   （属 91 个不可反编译函数之一，已复验），故走"读反汇编 → 按寄存器/栈槽归属转写"。
//   代码内以 `L_<原始地址>` 标注各基本块，便于逐块回查。
//
// 【帧定基（原始序言）】
//   mov rax,rsp → push rbp,r12,r13,r14,r15(0x28) → lea rbp,[rax-0x168] → sub rsp,0x240
//   故 rbp = 入口 rsp - 0x168，rbp = rsp + 0x100。
//   - 节区描述符（ReadPESectionEntry 输出，0x120 字节）基址 = rbp-0x30，即 desc+N ≡ rbp+(N-0x30)
//   - PE_DECODE_CONTEXT（0x48 字节）基址 = rbp-0x80
//   - 读取上下文 +0x08（读指针）= [rbp-0x78]，由主循环按 desc+0xF0（指令长度）推进
//   - Dst[0x10]（ULONG）基址 = rbp+0xF0（= 描述符 +0x120 之后）
//   【11 处锚点自洽】desc+0x50/0x58/0x70/0x74/0x78/0x88/0x90/0xD8/0xDC/0xF0/0x118
//   分别对应 [rbp+0x20/0x28/0x40/0x44/0x48/0x58/0x60/0xA8/0xAC/0xC0/0xE8]，
//   反解基址全部 = rbp-0x30 —— 描述符布局与 ReadPESectionEntry 的 0x120 字节定义一致。
//
// 【rsp 内联槽（非叶帧；按函数内自洽 + 角色命名）】
//   +0x40 CtxTableVal  +0x44 Flag44(0x42A)  +0x45 Flag45(FMdi)  +0x46 Flag46(数据节偏移已写)
//   +0x48 SavedEsi     +0x4C CtxDupVal      +0x50 SavedEsi2
//   +0x54 SkipCount    +0x58 Flag58         +0x5C DataSectionOfs
//   +0x60 Counter60    +0x64 IterCount      +0x68 SavedEbx
//   +0x70 MainTable(=GtAlloc 0x1EC8)        +0x78 FillTable(=GtAlloc 0x1F76)
//
// 【闭环自校验】本函数 0x14001672E 读 GtFltmgrBase(0x87E) 作模块基址，该槽由本函数之前的
//   InitFltmgrBase 系列写入（DriverStartup: 先探 fltmgr → 再解析节区），属完整初始化链成员。

#define DSC32(o)  (*(ULONG   *)(Desc + (o)))
#define DSC64(o)  (*(ULONG64 *)(Desc + (o)))

__int64 ParseNtImageSections(PUCHAR ImageBase, ULONG ImageSize)
{
    PUCHAR Desc;                    // rbp-0x30：节区描述符
    ULONG  CumulativeSize;          // rbp-0x78：= 读取上下文 +0x08（读指针）
    INT64  ReadContext;             // rbp-0x80：PE_DECODE_CONTEXT（0x48 字节）
    ULONG  Dst[0x10];               // rbp+0xF0

    ULONG  CtxTableVal;             // +0x40
    ULONG  Flag44;                  // +0x44
    ULONG  Flag45;                  // +0x45
    ULONG  Flag46;                  // +0x46
    ULONG  SavedEsi;                // +0x48
    ULONG  CtxDupVal;               // +0x4C
    ULONG  SavedEsi2;               // +0x50
    ULONG  SkipCount;               // +0x54
    ULONG  Flag58;                  // +0x58
    ULONG  DataSectionOfs;          // +0x5C
    ULONG  Counter60;               // +0x60
    ULONG  IterCount;               // +0x64
    ULONG  SavedEbx;                // +0x68
    __int64 MainTable;              // +0x70 = GtAlloc(0x1EC8)
    __int64 FillTable;              // +0x78 = GtAlloc(0x1F76)

    __int64 FltMgrBase;             // r13
    __int64 ImageBaseVal;           // r15：可选头优先基址
    ULONG  ChunkBase;               // ebx：阶段 1 求出的扫描起点
    ULONG  EntryPoint;              // ebx：AddressOfEntryPoint
    ULONG  SectionType;             // ecx / r8w
    ULONG  Ofs;                     // ecx：候选偏移
    ULONG  BuildNumber;
    ULONG  ScanIndex;
    ULONG  i;
    ULONG  t;
    UCHAR  InitSeen;                // dil：阶段 1 的 0x510 命中标志
    __int64 Val64;
    __int64 Row;

    UCHAR  DescBuf[0x120];
    Desc = DescBuf;
    ReadContext = 0;
    RtlZeroMemory(Dst, sizeof(Dst));
    CumulativeSize = 0;
    ChunkBase = 0;
    InitSeen = 0;

    FltMgrBase = GtRead(GtFltmgrBase);                          // 0x14001672E  ecx=0x87E
    MainTable  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x1EC8);  // 0x14001673B
    FillTable  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x1F76);  // 0x14001674A

    if (!FltMgrBase)                                            // 0x140016757
        return 0;

    // PE 头：AddressOfEntryPoint(NT+0x28) 与 ImageBase(NT+0x30)
    // 【关键】原始读的是 AddressOfEntryPoint，**不是 SizeOfCode**（0x140016761）。
    Row = (__int64)(ImageBase + *(LONG *)(ImageBase + 0x3C));
    EntryPoint   = *(ULONG *)(Row + 0x28);
    ImageBaseVal = *(__int64 *)(Row + 0x30);

    // ===== 阶段 1：在 AddressOfEntryPoint 处扫 INIT(0x559) 定 ChunkBase =====
    if (EntryPoint < ImageSize && EntryPoint + 0x1000 < ImageSize)   // 0x14001676B/77A
    {
        InitPESectionReadContext(
            (__int64)(ImageBase + EntryPoint),
            ImageSize - ((ULONG)(ULONG_PTR)ImageBase + EntryPoint) + 0x1000 + EntryPoint,
            2, 0, -1, 0, 0, (__int64)&ReadContext);             // 0x1400167B8

        for (ScanIndex = 0; ScanIndex < 20; ++ScanIndex)        // 0x1400167BF  cmp esi,14h
        {
            if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc))   // 0x1400167C7
                break;

            CumulativeSize += DSC32(0xF0);                      // 0x1400167D4/DE
            SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);      // 0x1400167EC
            Ofs = (ULONG)ImageBaseVal + CumulativeSize;         // 0x1400167FA
            Ofs -= (ULONG)(ULONG_PTR)ImageBase;

            if (SectionType == 0x559)                           // 0x1400167F5
            {
                if (Ofs != 0 && Ofs < ImageSize)                // 0x140016802/807
                    ChunkBase = Ofs;                            // 0x14001685E
            }
            else if (SectionType == 0x510)                      // 0x140016824
            {
                if (DSC64(0x50) == 0x40UL && DSC32(0x58) == 1)  // 0x140016829/830
                    InitSeen = 1;                               // 0x140016836
            }
            else if (SectionType == 0x558)                      // 0x140016840
            {
                if (InitSeen == 1)                              // 0x140016845
                {
                    if (Ofs != 0 && Ofs < ImageSize)            // 0x14001684A~857
                    {
                        ChunkBase = Ofs;
                        break;                                  // 0x14001685E
                    }
                    InitSeen = 0;                               // 0x140016859
                }
                else
                {
                    InitSeen = 0;
                }
            }
        }
    }

    if (!ChunkBase || ChunkBase >= ImageSize || ChunkBase + 0x1000 >= ImageSize)
        return 0;                                               // 0x140016862/86B/87A

    // ===== 阶段 2 =====
    memset(Dst, 0, sizeof(Dst));                                // 0x1400168E1
    CtxTableVal = 0;  Flag44 = 0;  Flag45 = 0;  Flag46 = 0;     // 0x1400168D3~906
    SavedEsi = 0;     SavedEsi2 = 0;  CtxDupVal = 0;
    SkipCount = 0;    Flag58 = 0;     DataSectionOfs = 0;
    Counter60 = 0;    IterCount = 0;  SavedEbx = 0;
    CumulativeSize = 0;

    InitPESectionReadContext(
        (__int64)(ImageBase + ChunkBase),
        ImageSize - ((ULONG)(ULONG_PTR)ImageBase + ChunkBase) + 0x1000 + ChunkBase,
        2, 0, -1, 0, 0, (__int64)&ReadContext);                 // 0x1400168B3

    for (;;)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc))   // L_190A  0x140016912
            return 0;

        CumulativeSize += DSC32(0xF0);                          // 0x140016925
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x140016930

        // ---- 0x558：数据节偏移登记（写 0x884） ----
        if (SectionType == 0x558)                               // 0x140016939
        {
            if (Flag46 == 0)                                    // 0x14001693E
            {
                ++Counter60;                                    // 0x140016952
                if (Counter60 == 1 && DataSectionOfs != 0)      // 0x140016958/960
                {
                    GtWrite(GtFltDataSectionOffset,
                            DataSectionOfs + FltMgrBase);       // 0x14001696D  0x884
                    Flag46 = 1;                                 // 0x140016978
                }
            }
            DataSectionOfs = 0;                                 // 0x14001697D
        }
        // ---- 0x512：候选偏移登记 ----
        else if (SectionType == 0x512                           // 0x140016984
                 && DSC64(0x88) == 0x40000UL && DSC32(0x78) != 0
                 && DSC64(0x50) == 0x40UL && DSC32(0x58) == 1)  // 0x14001698E~AE
        {
            t = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;  // 0x1400169B0
            if (t != 0)                                         // 0x1400169B6
            {
                if (t < ImageSize)                              // 0x1400169BC
                    DataSectionOfs = t;                         // 0x1400169BF cmovb
            }
            Counter60 = 0;                                      // 0x1400169C8
        }

    L_19CC:
        if (IterCount >= 0x32)                                  // 0x1400169CC
            goto L_1DBF;

        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x1400169DC
        if (BuildNumber >= 0x4A61)                              // 0x1400169ED
            goto L_1A9B;

        // ---------- build < 0x4A61 ----------
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x1400169F3
        if (SectionType == 0x42A && DSC64(0x50) == 1)           // 0x1400169FC/0A06
        {
            Flag44 = 1;                                         // 0x140016A0C
            goto L_17222;                                       // 0x140016A10
        }
        if (SectionType == 0x50E && DSC64(0x50) == 0x40000UL    // 0x140016A1B~30
            && DSC64(0x88) == 0x20UL)
        {
            Flag44 = 1;                                         // 0x140016A32
            goto L_17222;                                       // 0x140016A3C
        }
        if (Flag44 == 1)                                        // 0x140016A41
        {
            if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL
                && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL
                && DSC32(0x58) == 1)                            // 0x140016A4B~80
            {
                Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;
                if (Ofs != 0 && Ofs < ImageSize)                // 0x140016A88/8D
                {
                    if (SavedEbx == 0)                          // 0x140016A8F
                    {
                        SavedEbx = Ofs;                         // 0x140016A93
                        CtxTableVal = Ofs;                      // 0x140016A95
                    }
                    else
                    {
                        goto L_1B05;                            // 0x140016A91
                    }
                }
            }
        }
        goto L_1AFD;                                            // 0x140016AFD

    L_1A9B:                                                     // build >= 0x4A61
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x140016A9B
        if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL
            && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL
            && DSC32(0x58) == 1)                                // 0x140016AA4~C9
        {
            Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;
            if (Ofs != 0 && Ofs < ImageSize)                    // 0x140016AD1/D6
                SavedEbx = Ofs;                                 // 0x140016AD8
            goto L_1AFD;
        }
        if ((USHORT)(SectionType - 0x473) <= 1)                 // 0x140016ADE~EE
        {
            CtxTableVal = SavedEbx;                             // 0x140016AF6 cmovne + 0x140016AF9
        }

    L_1AFD:
        if (SavedEbx == 0)                                      // 0x140016AFD
            goto L_1DBF;

    L_1B05:
        if (GtRead(GtFltPeSectionOfs0) != 0)                    // 0x140016B0A  0x886
            goto L_1DBF;

        GtWrite(GtFltPeSectionOfs0,  SavedEbx);                 // 0x140016B21
        GtWrite(GtFltPeSectionAddr0, FltMgrBase + SavedEbx);    // 0x140016B2F

        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x140016B3B
        if (BuildNumber < 0x23F0)                               // 0x140016B40
            goto L_1D7F;

        if ((ULONG)(SavedEbx + 0x30) >= ImageSize)              // 0x140016B4F
            goto L_1DBF;

        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x140016B5A
        if (BuildNumber >= 0x4A61)                              // 0x140016B68
            goto L_1C76;

        // 0x23F0 <= build < 0x4A61：偏移 0/8/0x10/0x18/0x20 → 0x88C,0x88E,0x890,0x892,0x894
        // (0x140016B5F..0x140016C34，五段展开)
        Val64 = *(__int64 *)(ImageBase + SavedEbx);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs3, Ofs);  GtWrite(GtFltPeSectionAddr3, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 8);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs4, Ofs);  GtWrite(GtFltPeSectionAddr4, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x10);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs5, Ofs);  GtWrite(GtFltPeSectionAddr5, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x18);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs6, Ofs);  GtWrite(GtFltPeSectionAddr6, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x20);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs7, Ofs);  GtWrite(GtFltPeSectionAddr7, FltMgrBase + Ofs);
        }
        goto L_1DBF;                                            // 0x140016C6D

    L_1C76:                                                     // build >= 0x4A61
        // 偏移 0/8/0x10/0x18/0x20/0x28 → 0x88C,0x896,0x88E,0x890,0x892,0x894
        Val64 = *(__int64 *)(ImageBase + SavedEbx);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs3, Ofs);  GtWrite(GtFltPeSectionAddr3, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 8);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs8, Ofs);  GtWrite(GtFltPeSectionAddr8, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x10);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs4, Ofs);  GtWrite(GtFltPeSectionAddr4, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x18);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs5, Ofs);  GtWrite(GtFltPeSectionAddr5, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x20);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs6, Ofs);  GtWrite(GtFltPeSectionAddr6, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x28);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs7, Ofs);  GtWrite(GtFltPeSectionAddr7, FltMgrBase + Ofs);
        }
        goto L_1DBF;                                            // 0x140016C6D

    L_1D7F:                                                     // build < 0x23F0
        if ((ULONG)(SavedEbx + 8) >= ImageSize)                 // 0x140016D83
            goto L_1DBF;
        Val64 = *(__int64 *)(ImageBase + SavedEbx);             // 0x140016D88
        if (Val64 > (ULONG64)ImageBaseVal
            && Val64 < (ULONG64)(ImageBaseVal + ImageSize))     // 0x140016D8C~98
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs8, Ofs);                   // 0x140016DA8  0x896
            GtWrite(GtFltPeSectionAddr8, FltMgrBase + Ofs);     // 0x140016DB6  0x897
        }

    // ===== 0x53C / 0x473 / 0x50E / 0x53D 段 =====
    L_1DBF:                                                     // 0x140016DBF
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x140016DC6
        if (SectionType == 0x53C                                 // 0x140016DD0
            && DSC32(0x70) == 0x69664D46UL                       // "FMdi"
            && DSC32(0x74) == 0)                                 // 0x140016DE1/DE7
        {
            Flag45 = 1;                                          // 0x140016DF6
            // 落到 SkipCount 判定
        }
        else if ((USHORT)(SectionType - 0x473) <= 1)             // 0x140016EF9~F0D
        {
            if (Flag45 == 1)                                     // 0x140016F13~F21
                SkipCount = 1;
        }

        if (SkipCount != 0)                                      // 0x140016DFE
            goto L_1700C;

        // ---------- SkipCount == 0 主体 ----------
        // 0x512 → Dst 填
        if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL     // 0x140016E06~27
            && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL)
        {
            Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;  // 0x140016E2B
            if (Ofs != 0 && Ofs < ImageSize)                     // 0x140016E2F/34
            {
                i = DSC32(0x58);                                 // 0x140016E36
                if (i < 0x10)                                    // 0x140016E39
                    Dst[i] = Ofs;                                // 0x140016E3E
            }
        }

        // 0x50E → 以 Dst[desc+0x90] 填 MainTable 的 28 组（步长 0x30）
        if (SectionType == 0x50E                                 // 0x140016E58
            && (DSC32(0xD8) & 0x300) == 0x100                    // 0x140016E62~71
            && DSC32(0x40) == 0x70                               // 0x140016E7C
            && (DSC32(0xDC) & 0x300) == 0x300                    // 0x140016E85~8A
            && DSC64(0x88) == 0x40UL                             // 0x140016E93
            && DSC32(0x90) < 0x10)                               // 0x140016E9E
        {
            if (CtxDupVal == 0)                                  // 0x140016EA8
            {
                Ofs = Dst[DSC32(0x90)];                          // 0x140016EB3
                CtxDupVal = Ofs;                                 // 0x140016EBB
                if (Ofs != 0 && Ofs < ImageSize)                 // 0x140016EBF/CB
                {
                    Row = MainTable + 4;                         // 0x140016ED0
                    for (i = 0x1C; i != 0; --i)                  // 0x140016EE1 循环 28 次
                    {
                        *(ULONG *)Row = Ofs;                     // 0x140016EE1
                        *(__int64 *)(Row + 4) = FltMgrBase + Ofs;// 0x140016EE4
                        Row += 0x30;
                    }
                }
            }
            SavedEbx = CtxTableVal;                              // 0x140016EF0
            goto L_17222;
        }

        // 0x53D → 以 desc+0xF0 填 MainTable 的 28 组
        if (SectionType == 0x53D                                 // 0x140016F2A
            && DSC64(0x50) == 0x20UL                             // 0x140016F35
            && DSC64(0x70) == 0x1CUL                             // 0x140016F3C
            && CtxDupVal == 0)                                   // 0x140016F43
        {
            Ofs = DSC32(0xF0);                                   // 0x140016F4A
            CtxDupVal = Ofs;                                     // 0x140016F51
            if (Ofs != 0 && Ofs < ImageSize)                     // 0x140016F56/F5B
            {
                Row = MainTable + 4;                             // 0x140016F60
                for (i = 0x1C; i != 0; --i)                      // 0x140016F72 循环 28 次
                {
                    *(ULONG *)Row = Ofs;
                    *(__int64 *)(Row + 4) = FltMgrBase + Ofs;
                    Row += 0x30;
                }
            }
            SavedEbx = CtxTableVal;                              // 0x140016F82
            goto L_16A36;
        }

        // 0x50E → MainTable 行槽回填（槽非零且等于 CtxDupVal 时才写）
        if (SectionType == 0x50E                                 // 0x140016F8B
            && (DSC64(0x50) & 0x14000UL)                         // 0x140016F91/95
            && (DSC64(0x50) & 0x40UL)                            // 0x140016F9D
            && (DSC32(0xDC) & 0xF) != 4                          // 0x140016FA1~A7
            && DSC64(0x88) == 0x40UL                             // 0x140016FA9
            && (DSC32(0x40) - 0x70) <= 0xD8                      // 0x140016FB0~B9
            && (DSC32(0x40) & 7) == 0                            // 0x140016FBB~C0
            && ((DSC32(0x40) - 0x70) >> 3) <= 0x1B)              // 0x140016FC2~C8
        {
            Ofs = Dst[DSC32(0x90)];                              // 0x140016FCA
            if (Ofs != 0)                                        // 0x140016FD2
            {
                i = (DSC32(0x40) - 0x70) >> 3;                   // 0x140016FC2
                Row = MainTable + 0x30 * i;                      // 0x140016FDB~DF
                if (*(ULONG *)(Row + 4) != 0)                    // 0x140016FE2
                {
                    if (*(ULONG *)(Row + 4) == CtxDupVal)        // 0x140016FEF
                    {
                        *(ULONG *)(Row + 4)   = Ofs;             // 0x140016FFD
                        *(__int64 *)(Row + 8) = FltMgrBase + Ofs;// 0x140017002
                    }
                }
                goto L_17222;
            }
        }
        SavedEbx = CtxTableVal;                                  // 0x140016F82
        goto L_17222;

    L_1700C:                                                     // SkipCount != 0   0x14001700C
        if (Flag58 == 0)                                         // 0x140017010
        {
            // 0x512 → Dst 填
            if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL
                && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL)    // 0x140017018~39
            {
                Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;
                if (Ofs != 0 && Ofs < ImageSize)                 // 0x140017041/47
                {
                    i = DSC32(0x58);
                    if (i < 0x10)                                // 0x140017053
                        Dst[i] = Ofs;                            // 0x140017058
                }
            }
            // 0x50E → 填 FillTable（无条件写）
            if (SectionType == 0x50E                              // 0x140017061
                && (DSC64(0x50) & 0x14000UL)                      // 0x14001706C
                && (DSC64(0x50) & 0x40UL)                         // 0x140017078
                && (DSC32(0xDC) & 0xF) != 4                       // 0x140017082~87
                && DSC64(0x88) == 0x40UL                          // 0x140017089
                && (DSC32(0x40) - 8) <= 0xB8                      // 0x140017090~9C
                && (DSC32(0x40) & 7) == 0                         // 0x14001709E~A3
                && ((DSC32(0x40) - 8) >> 3) < 0x1B)               // 0x1400170A5~AB
            {
                Ofs = Dst[DSC32(0x90)];                           // 0x1400170AD/B0
                if (Ofs != 0)                                     // 0x1400170B7
                {
                    i = (DSC32(0x40) - 8) >> 3;
                    Row = FillTable + 0x30 * i;                   // 0x1400170BB~C8
                    *(ULONG *)(Row + 4)   = Ofs;                  // 0x1400170CB
                    *(__int64 *)(Row + 8) = FltMgrBase + Ofs;     // 0x1400170D0
                }
            }
        }

        // ---- 版本标志：决定 Flag58 ----
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);        // 0x1400170DA
        if (BuildNumber >= 0x4A61)                                // 0x1400170EB
        {
            if (*(USHORT *)((__int64)DSC64(0x118) + 6) == 0x50E    // 0x14001712B
                && (DSC64(0x50) & 0x10000UL) == 0x10000UL         // 0x140017131
                && (DSC64(0x50) & 0x40UL) == 0x40UL)              // 0x14001713B
            {
                if (DSC64(0x88) == 0x40UL)                        // 0x140017141
                    Flag58 = (DSC32(0x40) == 0xB8) ? 1 : 0;       // 0x14001714E cmove
                else
                    Flag58 = 0;                                   // 0x140017164
            }
            else
            {
                Flag58 = 0;
            }
        }
        else
        {
            if (*(USHORT *)((__int64)DSC64(0x118) + 6) == 0x547)  // 0x1400170F2
            {
                BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
                Flag58 = (BuildNumber >= 0x3AD7)
                         ? ((DSC64(0x70) == 0x78UL) ? 1 : 0)      // 0x14001711F
                         : ((DSC64(0x70) == 0x68UL) ? 1 : 0);     // 0x14001710F
            }
            else
            {
                Flag58 = 0;                                       // 0x14001715E
            }
        }

        if (Flag58 != 1)                                          // 0x140017164
            goto L_16EF0;

        // ---- Flag58 == 1：登记 0x888 / 0x88A 候选 ----
        if (*(USHORT *)((__int64)DSC64(0x118) + 6) == 0x512       // 0x14001717D
            && DSC64(0x88) == 0x40000UL && DSC32(0x78) != 0
            && DSC64(0x50) == 0x40UL)                             // 0x14001718C~95
        {
            Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize; // 0x140017197
            if (Ofs != 0 && Ofs < ImageSize)                      // 0x14001719D/A2
            {
                BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
                if (BuildNumber >= 0x4A61 && BuildNumber <= 0x4F7C)   // 0x1400171AE/BF
                {
                    if (SavedEsi == 0)                            // 0x1400171C6
                    {
                        if (Dst[1] != 0)                          // 0x1400171CA
                            SavedEsi = Dst[1];                    // 0x1400171D2
                    }
                    if (SavedEsi2 == 0)                           // 0x1400171D9
                        SavedEsi2 = Ofs;                          // 0x1400171DD
                }
                else if (BuildNumber >= 0x4A61)                   // 0x1400171E5
                {
                    if (SavedEsi == 0)
                        SavedEsi = Ofs;                           // 0x1400171E9
                }
                else                                              // 0x1400171F1
                {
                    if (SavedEsi == 0)
                        SavedEsi = Ofs;
                    else if (SavedEsi2 == 0 && Ofs != SavedEsi)   // 0x1400171F5
                        SavedEsi2 = Ofs;                          // 0x1400171F7
                }
            }
        }

    L_16EF0:                                                      // 0x140016EF0
        SavedEbx = CtxTableVal;
        goto L_17222;

    L_16A36:                                                      // 0x140016A36
        goto L_17222;

    L_17222:                                                      // 0x14001721F / 0x140017222
        ++IterCount;                                              // 0x140017226
        if (IterCount >= 0x1F4)                                   // 0x14001722D
            return 0;

        // 0x1400171FE：类型为 0x473/0x474 时收尾写 0x888 / 0x88A
        if ((USHORT)(*(USHORT *)((__int64)DSC64(0x118) + 6) - 0x473) <= 1)  // 0x140017209
        {
            if (SavedEsi2 != 0 && SavedEsi != 0)                  // 0x14001723B/23F
            {
                GtWrite(GtFltPeSectionOfs1,  SavedEsi);           // 0x14001724A  0x888
                GtWrite(GtFltPeSectionAddr1, FltMgrBase + SavedEsi);
                GtWrite(GtFltPeSectionOfs2,  SavedEsi2);          // 0x140017266  0x88A
                GtWrite(GtFltPeSectionAddr2, FltMgrBase + SavedEsi2);
            }
            return 0;
        }
        SavedEbx = CtxTableVal;                                   // 0x14001721B
    }
}
#undef DSC32
#undef DSC64