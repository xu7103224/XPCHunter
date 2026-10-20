// EnumerateProcessCallbackContext — 枚举进程回调节区
// 对应原始驱动 0x14003EAA8（809 字节 / 125 条指令）
//
// 【重写 2026-10-20】旧实现是**完全虚构的**：它假设存在一个 `DecodeUnicodeChar`
//   字符解码器，并用 `TokenType = *pTokenType;`（pTokenType 从未赋值 → 未初始化栈
//   指针）、`CharOffset`、`CharSize` 三个同样未赋值的局部。
//   实机后果：RTZ59 在 `mov r15,[r15+0x30]` 处 0xC0000005 蓝屏（0x3B），
//   r15=0 —— 正是未初始化指针被解引用。
//
// 原始实现用的是 **PE 节区扫描**（InitPESectionReadContext + ReadPESectionEntry），
// 与 MiniFilter 三扫描器同一套路。逐条对照：
//
//   0x14003EADF  GtRead(0x61)               ; 目标 EPROCESS，非 0 则 KeStackAttachProcess
//   0x14003EB03  r14d = GtRead(0x42D0)      ; CurrentOffset
//   0x14003EB0D  rbx  = GtRead(0x43A8)      ; SectionBase
//   0x14003EB1A  r12  = GtRead(0x20)        ; SectionSize
//   0x14003EB27  edi  = GtRead(0x21)        ; （低 32 位）
//   0x14003EB34  r13  = GtRead(3)           ; NtoskrnlImageBase
//   0x14003EB41  eax  = GtRead(2)           ; （低 32 位）
//   0x14003EB4E..B8C  八个非零/边界守卫
//   0x14003EBB3  InitPESectionReadContext(r14+rbx, r12-(r14+rbx)+edi, 2, 0, -1, 0, 0, ctx)
//
//   第一段（最多 0xC8 轮，0x14003EBCE..CC7）：
//     ReadPESectionEntry 失败 → 结束
//     Cumul += Entry[0xF0]
//     类型 == 0x545 → 结束
//     类型 == 0x512 且 +0x50==0x40 且 +0x58==2 且 +0x90==4
//        → 再读下一个条目；若类型仍为 0x512 且 +0x50==0x40 且 +0x58==1 且
//          +0x88==0x40000：Cand = (+0x78 - SectionSize + Cumul)；
//                          Cand != 0 && Cand < edi → 写 GT[0x2B8] = Cand + ImageBase
//   第二段（最多 0x12C 轮，0x14003ECE6..ED74）：
//     ReadPESectionEntry 失败 → 结束
//     Cumul += Entry[0xF0]
//     Loaded = GtRead(0x914)
//     若 Loaded < 0x55F0 且 类型 == 0x545 → 结束
//     类型 ∈ {0x4B1, 0x175, 0x472} 且 (+0x28 & 4) 且 +0x50==0x40000
//        Cand = (+0x70 - SectionSize + Cumul)
//        Cand != 0 && Cand < edi → 写 GT[0x2BA] = Cand + ImageBase，Result = 1
//   0x14003ED8D  有 APC 则 KeUnstackDetachProcess，返回 Result
//
// 描述符字段（0x120 字节）：+0xF0 消耗长度、+0x118 类型指针（+6 为类型号）、
//   +0x28 标志位、+0x50 段特性、+0x58 段号、+0x70 / +0x78 RVA、+0x88 / +0x90 标志。
__int64 EnumerateProcessCallbackContext(void)
{
    __int64 Result = 0;                 /* r15b */
    struct _KPROCESS *TargetProcess;    /* rsi  */
    ULONG   CurrentOffset;              /* r14d */
    ULONG64 SectionBase;                /* rbx  */
    ULONG   SectionSize;                /* r12d */
    ULONG   ImageSizeLow;               /* edi  */
    ULONG64 NtoskrnlImageBase;          /* r13  */
    ULONG   Guard2;                     /* eax  */
    ULONG   LoopIndex;
    ULONG   Cumul;                      /* [rsp+var_1C8] */
    ULONG   Cand;                       /* ebx  */
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];            /* 0x120 字节描述符 */
    struct _KAPC_STATE ApcState;
    USHORT  Type;
    ULONG   EntrySize;

    TargetProcess = (struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)0x61);
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    CurrentOffset      = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x42D0);
    SectionBase        = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x43A8);
    SectionSize        = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x20);
    ImageSizeLow       = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);
    NtoskrnlImageBase  = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);
    Guard2             = (ULONG)GtRead((GLOBAL_TABLE_INDEX)2);

    /* 0x14003EB4E..B8C：八道守卫 */
    if (!CurrentOffset || CurrentOffset >= ImageSizeLow) goto Done;
    if (!SectionSize   || SectionSize   >= ImageSizeLow) goto Done;
    if (!(ULONG64)SectionBase) goto Done;
    if (!ImageSizeLow) goto Done;
    if (!NtoskrnlImageBase) goto Done;
    if (!Guard2) goto Done;

    /* 0x14003EBB3：窗口 = SectionBase + CurrentOffset，长度 = SectionSize - 该值 + ImageSizeLow */
    InitPESectionReadContext((__int64)(SectionBase + CurrentOffset),
                             (ULONG)(SectionSize - (ULONG)(SectionBase + CurrentOffset) + ImageSizeLow),
                             2, 0, -1, 0, 0, (__int64)&ReadContext);

    Cumul = 0;
    Cand  = 0x512;                       /* ebx 初值，仅用于第一段的类型比较 */

    /* ===== 第一段：0x14003EBCE..CC7，最多 0xC8 轮 ===== */
    for (LoopIndex = 0; LoopIndex < 0xC8; LoopIndex++)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry) != 0)
            break;

        /* 0x14003EBE4..BEA：先累加消耗长度 */
        EntrySize = *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
        Cumul += EntrySize;

        Type = *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (Type == 0x545)               /* 0x14003EBFA..C02：结束标记 */
            break;

        if (Cand != Type)                /* 0x14003EC08：只有 0x512 才深入 */
            continue;

        if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40 ||   /* 0x14003EC11 */
            *(ULONG   *)((PUCHAR)SectionEntry + 0x58) != 2    ||   /* 0x14003EC1C */
            *(ULONG   *)((PUCHAR)SectionEntry + 0x90) != 4)        /* 0x14003EC26 */
            continue;

        /* 0x14003EC30：再看紧邻的下一个条目 */
        if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry) != 0)
            continue;

        EntrySize = *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
        Cumul += EntrySize;

        if (*(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) != 0x512 ||
            *(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40 ||
            *(ULONG   *)((PUCHAR)SectionEntry + 0x58) != 1    ||
            *(ULONG64 *)((PUCHAR)SectionEntry + 0x88) != 0x40000)
            continue;

        /* 0x14003EC79：Cand = (+0x78 - SectionSize) + Cumul */
        {
            ULONG Raw = *(ULONG *)((PUCHAR)SectionEntry + 0x78) - (ULONG)SectionSize + Cumul;
            Cand = Raw;
            if (Raw == 0 || Raw >= ImageSizeLow)
                goto NextIter;
            GtWrite((GLOBAL_TABLE_INDEX)0x2B8, NtoskrnlImageBase + Raw);   /* 0x14003ECD4 */
        }
    NextIter:;
    }

    /* ===== 第二段：0x14003ECE6..ED74，最多 0x12C 轮 ===== */
    for (LoopIndex = 0; LoopIndex < 0x12C; LoopIndex++)
    {
        ULONG Loaded;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry) != 0)
            break;

        EntrySize = *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
        Cumul += EntrySize;

        Loaded = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x914);            /* 0x14003ED02 */
        Type = *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        /* 0x14003ED18..ED28：低于 0x55F0 时遇 0x545 即结束 */
        if (Loaded < 0x55F0 && Type == 0x545)
            break;

        /* 0x14003ED2E..ED4A：类型 ∈ {0x4B1, 0x175, 0x472} */
        if (!(Type == 0x4B1 || Type == 0x175 || Type == 0x472))
            continue;

        if ((*(ULONG *)((PUCHAR)SectionEntry + 0x28) & 4) == 0 ||      /* 0x14003ED4C */
            *(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40000)      /* 0x14003ED52 */
            continue;

        /* 0x14003ED5C：Cand = (+0x70 - SectionSize) + Cumul */
        {
            ULONG Raw = *(ULONG *)((PUCHAR)SectionEntry + 0x70) - (ULONG)SectionSize + Cumul;
            if (Raw == 0 || Raw >= ImageSizeLow)
                continue;
            GtWrite((GLOBAL_TABLE_INDEX)0x2BA, NtoskrnlImageBase + Raw);  /* 0x14003ED7D */
            Result = 1;
        }
    }

Done:
    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}