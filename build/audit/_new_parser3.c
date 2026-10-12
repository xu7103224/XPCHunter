// ParseNtDebugSection — 定位 ntoskrnl 的 INIT(0x559) 节区，扫描并填充上下文索引表
// 对应原始驱动 0x140056BD0（1089 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— 该函数是 _FINAL_GAP.json 的
//   A_definite_missing（源码中此前完全缺失，导致 InitThreadContextTable 装入后
//   LNK2001）。代码内标注 `L_<地址>`。
//
// 【帧定基（序言 + 描述符锚点交叉验证）】
//   push rbp,rsi,rdi,r12,r13,r14,r15(0x38) → lea rbp,[rsp-0x120] → sub rsp,0x220
//   故 rbp = 入口 rsp - 0x158。
//   - 节区描述符基址 = rbp-0x50（0x140056C8B `lea rdx,[rbp-0x50]` 作第 2 参）
//     故 desc+N ≡ rbp+(N-0x50)。实测锚点自洽：
//       desc+0xF0(推进量)=rbp+0xA0  desc+0x118(类型指针)=rbp+0xC8
//       desc+0x88=rbp+0x38  desc+0x78=rbp+0x28   desc+0x58=rbp+0x08
//       desc+0x50=rbp+0x00  desc+0x40=rbp-0x10   desc+0x3C=rbp-0x14
//       desc+0xDC=rbp+0x8C  desc+0x90=rbp+0x40   desc+0x20=rbp-0x30
//   - 索引表 = rbp+0xD0（0x140056D37 memset 0x40）
//   - 读取上下文 = rsp+0x60；读指针 = rsp+0x68 = ctx+8
//   - OutTable = 第 3 实参（r8）→ [rsp+0x50]；Loaded = GtRead(0x905) → [rsp+0x58]
//   - 局部计数器：[rsp+0x44]=LastRva（已写入的候选 RVA）、[rsp+0x40]=Written 标志、
//     [rsp+0x48]=外层次数、esi=首候选 RVA
//
// 【算法】
//   ① Loaded = GtRead(0x905)，为 0 即返回 0；
//   ② 读 PE 头 e_lfanew、EntryPoint=[nt+0x28]；要求 EntryPoint < ImageSize
//      且 EntryPoint+0x1000 < ImageSize；
//   ③ 外层（最多 0x14 次）：逐条 ReadPESectionEntry 找类型 0x559/0x510/0x558，
//      记录 INIT 节区 RVA（dil 标记 0x510 命中）；
//   ④ 内层（最多 0xC8 次）：从 INIT RVA 起再初始化上下文并扫描：
//      · 0x512 且 desc+0x88==0x40000、desc+0x78!=0、desc+0x50==0x40、
//        desc+0x58==0 → 算出 RVA 作为候选（首候选存入 esi）；
//      · 0x52F 且 desc+0x20 的 bit4 置位且有候选 → 以 0x1C 组把 (候选, 候选+Loaded)
//        填入 OutTable；
//      · 0x473 → memset(索引表, 0, 0x40)；
//      · 0x50E 且 desc+0x50 的 bit14/bit6 置位、(desc+0x8C&0xF)!=4、desc+0x88==0x40、
//        (desc+0x40-0x70)<=0xD8 且对齐、k<=0x1B、索引表[desc+0x90] 非零 →
//        若输出表槽空或等于 LastRva 则（构建号==0x23F0 且未 Written 且有候选时先填
//        0x1C 组）写入 (候选, 候选+Loaded)，置 Found=1、LastRva=候选。
//   ⑤ 返回 Found（r13b）。
UCHAR ParseNtDebugSection(PUCHAR ImageBase, ULONG ImageSize, __int64 OutTable)
{
    UCHAR   Desc[0x120];             // rbp-0x50
    PE_DECODE_CONTEXT ReadContext;   // rsp+0x60
    ULONG   IndexTable[16];          // rbp+0xD0（0x40 字节）
    ULONG64 Loaded;                  // [rsp+0x58] = GtRead(0x905)
    ULONG   InitRva;                 // ebx
    ULONG   FirstCand;               // esi
    ULONG   LastRva;                 // [rsp+0x44]
    UCHAR   Written;                 // [rsp+0x40]
    UCHAR   Found;                   // r13b
    UCHAR   Flag510;                 // dil（外层用）
    ULONG   i, j;
    BOOLEAN Build23F0;

    Loaded = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x905);      // 0x140056C1F
    Found = 0;
    if (!Loaded)                                             // 0x140056C29
        return Found;

    {
        PUCHAR Nt = ImageBase + *(LONG *)(ImageBase + 0x3C);  // 0x140056C00
        InitRva = *(ULONG *)(Nt + 0x28);                      // 0x140056C32
    }
    if (InitRva >= ImageSize)                                // 0x140056C37
        return Found;
    if (InitRva + 0x1000 >= ImageSize)                       // 0x140056C40
        goto L_INNER_LOOP;                                   // 0x140056C49 → 0x140056CE2

    // ---- 外层：定位 INIT(0x559) 节区 ----
    {
        ULONG Base = (ULONG)(ULONG_PTR)ImageBase + InitRva;  // 0x140056C4F/5C
        ULONG Size = ImageSize - Base + InitRva;             // 0x140056C56/65
        InitPESectionReadContext((__int64)Base, Size,
                                 2, 0, -1, 0, 0, (__int64)&ReadContext);   // 0x140056C83
        Flag510 = 0;
        for (i = 0; i < 0x14; ++i)                           // 0x140056E17 cmp esi,14h
        {
            ULONG Type;

            if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc) != 0)   // 0x140056C94
                goto L_INNER_LOOP;

            ReadContext.ReadPtr += *(ULONG *)(Desc + 0xF0);   // 0x140056C9D~CB2
            Type = *(USHORT *)(*(ULONG64 *)(Desc + 0x118) + 6);   // 0x140056CB7

            if (Type == 0x559)                               // 0x140056CC3
            {
                ULONG r = *(ULONG *)(Desc + 0x38) - (ULONG)(ULONG_PTR)ImageBase
                          + (ULONG)ReadContext.ReadPtr;      // 0x140056CC9~CCF
                if (r == 0 || r >= ImageSize)                // 0x140056CD1/CD7
                    goto L_INNER_LOOP;
                InitRva = r;                                 // 0x140056CE0
                goto L_INNER_LOOP;                           // 0x140056CE2
            }
            else if (Type == 0x510)                          // 0x140056DD8
            {
                if (*(ULONG64 *)(Desc + 0x50) == 0x40UL      // 0x140056DDD
                    && *(ULONG *)(Desc + 0x58) == 1)         // 0x140056DE4
                    Flag510 = 1;                             // 0x140056DEA
            }
            else if (Type == 0x558)                          // 0x140056DF4
            {
                if (Flag510 == 1)                            // 0x140056DF9
                {
                    ULONG r = *(ULONG *)(Desc + 0x38) - (ULONG)(ULONG_PTR)ImageBase
                              + (ULONG)ReadContext.ReadPtr;  // 0x140056DFF~E07
                    if (r != 0 && r < ImageSize)             // 0x140056E07/E09
                    {
                        InitRva = r;                         // 0x140056CE0
                        goto L_INNER_LOOP;
                    }
                }
                Flag510 = 0;                                 // 0x140056E12
            }
        }
    }

L_INNER_LOOP:                                                // 0x140056CE2
    if (InitRva >= ImageSize)                                // 0x140056CE2
        return Found;
    if (InitRva + 0x1000 >= ImageSize)                       // 0x140056CEB
        return Found;

    // ---- 内层 ----
    {
        ULONG Base = (ULONG)(ULONG_PTR)ImageBase + InitRva;  // 0x140056D06/0C
        ULONG Size = ImageSize - Base + InitRva;             // 0x140056CFD/D11
        InitPESectionReadContext((__int64)Base, Size,
                                 2, 0, -1, 0, 0, (__int64)&ReadContext);   // 0x140056D2C
        memset(IndexTable, 0, sizeof(IndexTable));           // 0x140056D3E

        FirstCand = 0;                                       // esi
        LastRva   = 0;                                       // [rsp+0x44]
        Written   = 0;                                       // [rsp+0x40]
        i = 0;

        for (;;)                                             // L_d56
        {
            ULONG   Type;
            ULONG64 Chk50;
            ULONG   Cand;                                    // edi

            if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc) != 0)   // 0x140056D5F
                return Found;

            {
                ULONG64 TypePtr = *(ULONG64 *)(Desc + 0x118);       // r10
                ULONG64 D88  = *(ULONG64 *)(Desc + 0x88);           // r13
                ULONG   D78  = *(ULONG *)(Desc + 0x78);             // ecx
                ULONG   f58  = *(ULONG *)(Desc + 0x58);             // r11d
                ULONG64 D50  = *(ULONG64 *)(Desc + 0x50);           // r15

                ReadContext.ReadPtr += *(ULONG *)(Desc + 0xF0);     // 0x140056D6C/8D/90
                Type = *(USHORT *)(TypePtr + 6);                    // 0x140056D95

                Cand = 0;
                if (Type == 0x512 && D88 == 0x40000ULL && D78 != 0
                    && D50 == 0x40ULL && f58 == 0)                  // 0x140056D9A~DB9
                {
                    ULONG r = D78 - (ULONG)(ULONG_PTR)ImageBase
                              + (ULONG)ReadContext.ReadPtr;         // 0x140056DBB~DC0
                    Cand = (r < ImageSize) ? r : 0;                 // 0x140056DC3/DC6
                }

                // 0x140056E67~EA0：第二段 0x512（记录候选并记首候选）
                if (Type == 0x512 && D88 == 0x40000ULL && D78 != 0
                    && D50 == 0x40ULL)                              // 0x140056E71~E87
                {
                    ULONG r = D78 - (ULONG)(ULONG_PTR)ImageBase
                              + (ULONG)ReadContext.ReadPtr;         // 0x140056E89~E8C
                    if (r != 0 && r < ImageSize)                    // 0x140056E8F/E91
                    {
                        IndexTable[f58] = r;                        // 0x140056E98
                        if (FirstCand == 0)                         // 0x140056E96 cmove
                            FirstCand = r;                          // 0x140056EA0
                    }
                }

                if (Type == 0x473)                                  // 0x140056EA8
                    memset(IndexTable, 0, sizeof(IndexTable));      // 0x140056EBA

                if (Type == 0x50E                                      // 0x140056EC4
                    && (D50 & 0x14000ULL) != 0                          // 0x140056ECD
                    && (D50 & 0x40ULL) != 0                             // 0x140056EDA
                    && (*(ULONG *)(Desc + 0x8C) & 0xF) != 4             // 0x140056EE4~EED
                    && D88 == 0x40ULL                                   // 0x140056EF5
                    && (*(ULONG *)(Desc + 0x40) - 0x70) <= 0xD8         // 0x140056EFF~F0B
                    && (*(ULONG *)(Desc + 0x40) & 7) == 0               // 0x140056F11/F14
                    && ((*(ULONG *)(Desc + 0x40) - 0x70) >> 3) <= 0x1B) // 0x140056F1C/F1F
                {
                    ULONG k = (*(ULONG *)(Desc + 0x40) - 0x70) >> 3;     // 0x140056F1C
                    ULONG sel = *(ULONG *)(Desc + 0x90);                 // 0x140056F28
                    if (IndexTable[sel] != 0)                            // 0x140056F2B/F33
                    {
                        ULONG *slot = (ULONG *)(OutTable + (ULONG64)k * 0x30 + 4);  // 0x140056F3E~F45
                        ULONG  cur = *slot;                              // 0x140056F45
                        if (cur != 0)                                    // 0x140056F4A
                        {
                            if (LastRva == 0 || LastRva != cur)          // 0x140056F53~F5B
                                goto L_NEXT_INNER;                       // 0x140056FC4
                        }

                        // 0x140056F62：构建号 == 0x23F0 且未 Written 且有首候选时先填 0x1C 组
                        Build23F0 = ((ULONG)GtRead(GtWindowsBuildNumber) == 0x23F0);  // 0x140056F67
                        if (Build23F0 && Written == 0 && FirstCand != 0)              // 0x140056F71/78/7C
                        {
                            ULONG64 cur60 = OutTable + 8;
                            for (j = 0x1C; j != 0; --j)                  // 0x140056F98
                            {
                                *(ULONG *)(cur60 - 4) = FirstCand;       // 0x140056F8E
                                *(__int64 *)cur60 = (__int64)FirstCand + (__int64)Loaded;  // 0x140056F91
                                cur60 += 0x30;
                            }
                            LastRva = FirstCand;                        // 0x140056F9D
                        }

                        Found = 1;                                      // 0x140056FA4
                        Written = 1;                                    // 0x140056FAE
                        *slot = IndexTable[*(ULONG *)(Desc + 0x40)];    // 0x140056FA7/FB3
                        *(ULONG64 *)(OutTable + (ULONG64)k * 0x30 + 8) =
                            (ULONG64)*slot + Loaded;                    // 0x140056FB8/FBD
                        goto L_NEXT_INNER;
                    }
                }

            L_NEXT_INNER:                                            // 0x140056FC4
                (void)Cand;
                ++i;                                                 // 0x140056FC9
                if (i >= 0xC8)                                       // 0x140056FD3 cmp ebx,0C8h
                    return Found;
            }
        }
    }
    return Found;                                                // 0x140056FE4
}