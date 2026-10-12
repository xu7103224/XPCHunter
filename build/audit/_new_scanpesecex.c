// ScanPESectionPatternsEx — 扩展版 PE 节区特征码扫描（两种模式匹配算法）
// 对应原始驱动 0x14007A048（600 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整且带地址注释），
//   按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
//   该函数是 _FINAL_GAP.json 的 D_need_review（源码中此前完全缺失）。
// 【与 ScanPESectionPatterns(0x14007B4B0 族) 的差异（逐条比对）】
//   本函数（Ex）与普通版结构同型，但**常量不同**，故是两个独立函数：
//     标记节区类型：Ex = 1141(0x475)/长度7、1356(0x54C)/长度1、计数阈值 5
//                   普通版 = 1139/长度7、239/长度5
//     线性特征：    Ex = `48 FF 25` + 其后 +7 处 != 5×0xCC（int3 填充）
//                   普通版 = `48 FF 21` + 其后 +7 处 == 0F 1F 44 00 00（NOP）
//     收尾比对类型：Ex = 1296/1369，普通版 = 1296/1368
// 【入参】PeBuffer=PE 缓冲；PatternBuffer=参照缓冲（可空）；BufferSize；UsePESectionParser
char __fastcall ScanPESectionPatternsEx(_BYTE *PeBuffer, char *PatternBuffer,
                                        int BufferSize, char UsePESectionParser)
{
    ULONG   MaxSearchSize = (ULONG)(BufferSize - 12);
    char    Result = 0;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[20];
    ULONG   CurOfs;
    char    FoundMarker;
    int     PatternCount;
    ULONG64 MatchOffset;
    _BYTE  *p;
    __int64 EntryFieldAt40, EntryFieldAt50, EntryFieldAt88;

    // 5 字节 int3 填充模板（原始 byte_14008CAA0 = CC CC CC CC CC）
    _BYTE Int3Pad[5] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };

    EntryFieldAt40 = 0; EntryFieldAt50 = 0; EntryFieldAt88 = 0;

    if (MaxSearchSize > 0x27F3)                                        // 0x14007A08A
        return Result;

    if (UsePESectionParser == 1)                                      // 0x14007A099
    {
        InitPESectionReadContext((__int64)PeBuffer, (ULONG)BufferSize,
                                 2, 0, -1, 0, 0, (__int64)&Ctx);       // 0x14007A0C6
    L_LABEL4:                                                         // 0x14007A0CB
        FoundMarker = 0;
        PatternCount = 0;
        while (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))        // 0x14007A0E1
        {
            USHORT Type;
            ULONG  EntryLen = *(ULONG *)((PUCHAR)Entry + 0xF0);

            CurOfs = EntryLen + (ULONG)Ctx.ReadPtr;                    // 0x14007A0F9
            Ctx.ReadPtr += EntryLen;                                   // 0x14007A0FC

            Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14007A101

            if (Type == 0x475 && EntryLen == 7)                        // 0x14007A112
            {
                FoundMarker = 1;                                       // 0x14007A114
            }
            else
            {
                if (Type != 0x54C || EntryLen != 1)                    // 0x14007A12A
                    goto L_LABEL4;
                ++PatternCount;                                        // 0x14007A12C
                if ((ULONG)PatternCount >= 5 && FoundMarker == 1)      // 0x14007A12F/135
                {
                    Result = 1;                                        // 0x14007A13C
                    MatchOffset = (ULONG)(CurOfs - (ULONG)(ULONG_PTR)PeBuffer - 12);  // 0x14007A142
                    goto L_LABEL22;                                    // 0x14007A145
                }
                goto L_LABEL4;
            }
        }
        return Result;
    }

    // ---- 线性特征搜索分支（0x14007A147） ----
    for (MatchOffset = 0, p = PeBuffer; ; ++p)                         // 0x14007A149
    {
        if (*p == 0x48                                                 // 0x14007A14C
            && PeBuffer[(ULONG)MatchOffset + 1] == 0xFF                // 0x14007A158
            && PeBuffer[(ULONG)MatchOffset + 2] == 0x25                // 0x14007A15E
            && MemoryCompare((__int64)&PeBuffer[(ULONG)MatchOffset + 7],
                             (char *)Int3Pad, 5u) != 0)                // 0x14007A16A
            break;
        MatchOffset = (ULONG)(MatchOffset + 1);                        // 0x14007A18C
        if ((ULONG)MatchOffset > MaxSearchSize)                        // 0x14007A18F
            return Result;
    }
    Result = 1;                                                        // 0x14007A19A

L_LABEL22:                                                             // 0x14007A1A0
    if (PatternBuffer)                                                 // 0x14007A1A6
    {
        Result = 0;                                                    // 0x14007A1AC
        if ((ULONG)MatchOffset == 0                                    // 0x14007A1BC
            || MemoryCompare((__int64)PeBuffer, PatternBuffer,
                             (unsigned int)MatchOffset) == 0)
        {
            InitPESectionReadContext((__int64)&PatternBuffer[MatchOffset], 12,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);   // 0x14007A1F3
            if (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)        // 0x14007A234
                && *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6) == 1296
                && *(ULONG *)((PUCHAR)Entry + 0xF0) == 7
                && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64            // EntryField (v18)
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)   // SectionAlignment (v20)
            {
                EntryFieldAt40 = *(ULONG *)((PUCHAR)Entry + 0x40);      // EntrySize (v19)
                if (EntryFieldAt40)                                    // 0x14007A23B
                {
                    if (*(ULONG *)&PeBuffer[MatchOffset + 3] == (ULONG)EntryFieldAt40)  // 0x14007A241
                    {
                        Ctx.ReadPtr += 7;                              // 0x14007A243
                        if (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)   // 0x14007A26B
                            && *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6) == 1369)
                            return (*(ULONG *)((PUCHAR)Entry + 0xF0) == 5) ? 1 : 0;  // 0x14007A278
                    }
                }
            }
        }
    }
    (void)EntryFieldAt50; (void)EntryFieldAt88;
    return Result;                                                     // 0x14007A27F
}