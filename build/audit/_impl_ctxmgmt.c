// ParseNtExportSectionsForProcessContext — 解析 ntoskrnl 节区并按节序号批填两张表
// 对应原始驱动 0x140039214（972 字节，253 行反汇编）
// 【逆向来源】人工阅读反汇编**按原始地址逐标签机械转写**（goto + L<地址>），
//   依据 build/audit/_pnepc_listing.txt。IDA 无法分析该函数（Hex-Rays 失败）。
// 【参数】rcx = ntoskrnl PE 文件缓冲、edx = 文件大小（**无第三参**）
// 【输出表】本函数自己 GtAlloc 两处：GT 0x2024（r15，0x30 字节/项）
//   与 GT 0x20D2（var_1F0，0x30 字节/项）
// 【结构】
//   段 1（上限 0x14）：用节头 +0x28 定位首个目标节；类型 0x559 记录偏移；
//     类型 0x510(且 +0x38==0x40 且 +0x58==1) 置 FlagDil；0x558 在 FlagDil 置位后记录偏移。
//   段 2（上限 0x1F4）：先 memset Dst[0x40]；类型 0x512(且 +0x88==0x40000 且
//     +0x38!=0 且 +0x50==0x40 且 +0x58 < 0x10) → Dst[+0x58] = 偏移；
//     类型 0x50E 分两条路径：
//       a) +0xB8 的 0x300 位 == 0x100、+0x38 == 0x70、+0xDC 的 0x300 位 == 0x300、
//          +0x88 == 0x40、Dst 序号 < 0x10 → 对 Dst[序号] 连续写
//          (+0x88 - 0x24) 个 0x30 字节条目（每项 +0 = 偏移、+4 = 偏移 + 节 VA 基址）
//       b) +0x50 带 0x14000/0x40、+0xDC 低 4 位 != 4、+0x88 == 0x40、+0x38 == 0x50、
//          Dst[+0x100] 有效、偏移 + 0xE0 <= 文件大小 → 写 (+0x88 - 0x25) 个 0x30 字节条目
//          （从 缓冲 + 偏移 + 8 读 QWORD，减去节 VA 后若有效则写 +0 = 差值、+4 = 差值 + 基址）
ULONG64 ParseNtExportSectionsForProcessContext(__int64 FileBuffer, unsigned int FileSize)
{
    ULONG64 Base = (ULONG64)FileBuffer;   // r12
    ULONG   Size = FileSize;              // esi
    ULONG64 VaBase;                       // r13 <- GT 0x8C4
    ULONG64 Tab1;                         // r15 / var_1F8 <- GtAlloc(0x2024)
    ULONG64 Tab2;                         // var_1F0 <- GtAlloc(0x20D2)
    UCHAR   Result = 0;                   // dil
    UCHAR   FlagDil = 0;                  // r14b
    ULONG   SecOff;                       // ebx
    ULONG   Count;                        // r15d / ebx
    ULONG64 PeHdrOff;
    ULONG   SecType;
    ULONG64 SecFlags, SecFlags88;
    ULONG   v;
    ULONG   i, n;
    ULONG64 p, q;
    ULONG64 SectionVa;                    // r14 / var_200
    PE_DECODE_CONTEXT Ctx;                // var_1E0
    _DWORD  SectionInfo[112];             // var_190
    UCHAR   Dst[0x40];

    VaBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C4);
    Tab1 = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
    Tab2 = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x20D2);
    if (!VaBase) goto L1400394C3;

    PeHdrOff = (ULONG64)(LONG)*(LONG *)(Base + 0x3C);
    SecOff = *(ULONG *)(PeHdrOff + Base + 0x28);
    SectionVa = *(ULONG64 *)(PeHdrOff + Base + 0x30);
    if (SecOff >= Size) goto L14003934F;
    if (SecOff + 0x1000 >= Size) goto L14003934F;

    InitPESectionReadContext((__int64)(Base + SecOff), 0x1000, 2, 0, -1, 0, 0, (__int64)&Ctx);
    Count = 0; FlagDil = 0;
    goto L1400392EF;

L1400392EF:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L140039345;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    SecType = *(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6);
    if (SecType != 0x559) goto L1400394F6;
    v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)Base + (ULONG)Ctx.ReadPtr;
    if (v == 0) goto L140039537;
    if (v >= Size) goto L140039537;
    SecOff = v;

L140039345:
    Tab1 = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
L14003934F:
    if (SecOff == 0) goto L1400394C3;
    if (SecOff >= Size) goto L1400394C3;
    if (SecOff + 0x1000 >= Size) goto L1400394C3;
    InitPESectionReadContext((__int64)(Base + SecOff), 0x1000, 2, 0, -1, 0, 0, (__int64)&Ctx);
    memset(Dst, 0, 0x40);
    Count = 0;

L1400393B8:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L1400394C3;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    SecType = *(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6);
    SecFlags88 = *(__int64 *)((char *)SectionInfo + 0x88);
    SecFlags = *(__int64 *)((char *)SectionInfo + 0x50);

    if (SecType == 0x512 && SecFlags88 == 0x40000 &&
        *(ULONG *)((char *)SectionInfo + 0x38) != 0 && SecFlags == 0x40)
    {
        ULONG idx = *(ULONG *)((char *)SectionInfo + 0x58);
        v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)Base + (ULONG)Ctx.ReadPtr;
        if (v != 0 && v < Size && idx < 0x10) Dst[idx] = (UCHAR)v;
    }

    if (SecType != 0x50E) goto L1400395CD;

    // ---- 路径 a ----
    if (((*(ULONG *)((char *)SectionInfo + 0xB8) & 0x300) == 0x100) &&
        (*(ULONG *)((char *)SectionInfo + 0x38) == 0x70) &&
        ((*(ULONG *)((char *)SectionInfo + 0xDC) & 0x300) == 0x300) &&
        (SecFlags88 == 0x40))
    {
        ULONG idx = *(ULONG *)((char *)SectionInfo + 0x100);
        if (idx < 0x10)
        {
            v = Dst[idx];
            if (v != 0 && v < Size)
            {
                p = Tab1 + 4;
                q = (ULONG64)v + VaBase;
                n = (ULONG)(SecFlags88 - 0x24);
                for (i = 0; i < n; i++, p += 0x30)
                {
                    *(ULONG *)(p - 4) = v;
                    *(ULONG64 *)p = q;
                }
                Result = 1;
            }
        }
        goto L1400395CD;
    }
    goto L140039549;

L140039549:
    // ---- 路径 b ----
    if ((*(ULONG64 *)((char *)SectionInfo + 0x50) & 0x14000) &&
        (*(ULONG64 *)((char *)SectionInfo + 0x50) & 0x40) &&
        ((*(ULONG *)((char *)SectionInfo + 0xDC) & 0xF) != 4) &&
        (SecFlags88 == 0x40) &&
        (*(ULONG64 *)((char *)SectionInfo + 0x38) == 0x50))
    {
        ULONG idx = *(ULONG *)((char *)SectionInfo + 0x100);
        v = Dst[idx];
        if (v != 0 && v < Size && (ULONG64)v + 0xE0 <= Size)
        {
            p = Tab2 + 8;
            q = (ULONG64)v + 8 + Base;
            n = (ULONG)(SecFlags88 - 0x25);
            for (i = 0; i < n; i++, p += 0x30, q += 8)
            {
                ULONG64 w = *(ULONG64 *)q;
                if ((w > SectionVa) && (Size > (ULONG)(w - (ULONG)SectionVa)))
                {
                    *(ULONG *)(p - 4) = (ULONG)(w - (ULONG)SectionVa);
                    *(ULONG64 *)p = (w - SectionVa) + VaBase;
                }
            }
            Result = 1;
        }
    }

L1400395CD:
    Count++;
    if (Count >= 0x1F4) goto L1400394C3;
    goto L1400393B8;

L1400394F6:
    if (SecType == 0x510 && *(__int64 *)((char *)SectionInfo + 0x38) == 0x40 &&
        *(__int64 *)((char *)SectionInfo + 0x58) == 1)
    {
        FlagDil = 1;
        goto L140039537;
    }
    if (SecType == 0x558 && FlagDil == 1)
    {
        v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)Base + (ULONG)Ctx.ReadPtr;
        if (v != 0 && v < Size) { SecOff = v; goto L140039343; }
    }
    FlagDil = 0;
L140039537:
    Count++;
    if (Count >= 0x14) goto L140039345;
    goto L1400392EF;

L140039343:
    goto L140039345;

L1400394C3:
    (void)Tab2; (void)PeHdrOff;
    return (ULONG64)Result;
}

// InitProcessContextHookTable — 初始化进程上下文 Hook 表（补全空壳）
// 对应原始驱动 0x140039728（322 字节）
// 【逆向来源】人工阅读反汇编逐条还原
// 【⚠ 修正记录】此前本函数是空壳（`return;`），而它在 Operation.c:291 被真实调用。
// 【逻辑】GtRead(GT 0x8C4) 取 ntoskrnl 缓冲；为空则先调 InitThreadNotify 再重取，
//   仍为空则退出。ReadNtoskrnlToBuffer(&buf, &size) 读 PE 文件；
//   依次 ParseNtExportSectionsForProcessContext / ParseNtExportDir(...,0)；
//   然后遍历 GtAlloc(GT 0x2024) 的 0x1C 项与 GtAlloc(GT 0x20D2) 的 0x1B 项
//   （步长 0x30；条目 +0 = 命中标志、+4 = 节偏移、+0x0C 起 16 字节为节头副本）：
//   若偏移非 0 且 偏移+0x10 <= 文件大小，则 GtWrite(GT 0x8C6/0x8C7, 1)、
//   把标志置 1，并从 PE 缓冲该偏移处拷 16 字节到条目 +0x0C。最后 ExFree 缓冲区。
void InitProcessContextHookTable(void)
{
    ULONG64 Ctx8C4;                       // rbx
    unsigned int FileSize = 0;            // [rsp+arg_0]
    ULONG64 FileBuf = 0;                  // [rsp+arg_8]
    ULONG64 Tab;
    ULONG64 p;
    ULONG   i;

    Ctx8C4 = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C4);
    if (!Ctx8C4)
    {
        InitThreadNotify();
        Ctx8C4 = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C4);
        if (!Ctx8C4)
            return;
    }

    if (!ReadNtoskrnlToBuffer((void **)&FileBuf, &FileSize))
        return;

    ParseNtExportSectionsForProcessContext((__int64)FileBuf, FileSize);
    ParseNtExportDir((__int64)FileBuf, FileSize, Ctx8C4, 0);

    Tab = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
    for (i = 0, p = Tab; i < 0x1C; i++, p += 0x30)
    {
        ULONG off = *(ULONG *)(p + 4);
        *(ULONG *)p = 0;
        if (off != 0 && off + 0x10 <= FileSize)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x8C6, 1);
            *(ULONG *)p = 1;
            memcpy((void *)(p + 0x0C), (void *)(FileBuf + off), 0x10);
        }
    }

    Tab = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x20D2);
    for (i = 0, p = Tab; i < 0x1B; i++, p += 0x30)
    {
        ULONG off = *(ULONG *)(p + 4);
        *(ULONG *)p = 0;
        if (off != 0 && off + 0x10 <= FileSize)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x8C7, 1);
            *(ULONG *)p = 1;
            memcpy((void *)(p + 0x0C), (void *)(FileBuf + off), 0x10);
        }
    }

    ExFree((PVOID)FileBuf);
}