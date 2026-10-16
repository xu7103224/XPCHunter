// ReadDiskSectors — 读取磁盘扇区 / 控制设备（0x140078A30，1304 字节 / 317 条指令）
// 【⚠ 修正记录 2026-10-16】原实现是**伪造实现**：一个"枚举 \\.\PhysicalDrive0..31
//   并用 IOCTL_DISK_GET_DRIVE_GEOMETRY 取几何信息"的通用循环，与原始函数体无关。
//   发现方式：逐函数差分报 gt_index_mismatch —— 原始首读 GT 0x4265(16997)，
//   我方首读 0x41C6(16838)；且原始 1304 字节 vs 我方十余行。
// 【逆向来源】IDA 无法反编译该函数（Hex-Rays 报错），按 capstone 反汇编逐条转写；
//   完整反汇编落盘于 build/audit/asm/ReadDiskSectors.asm（317 条），
//   栈位移与立即数均以原始机器码核对（判据 F）。
// 【语义】这是一条"打开指定磁盘驱动并做设备控制"的通用过程：
//   ① 取 11 个 GT 槽（函数指针 + 阈值）：
//        0x4265(rbp-0x40) 0x432E(rsp+0x78) 0x4331(r13,rbp-0x68) 0x41EA(rsi,rbp-0x50)
//        0x4334(rbx,rbp-0x80) 0x4259(rsp+0x68) 0x425C(r14,rbp-0x48) 0x415A(rdi,rbp-0x70)
//        0x41C6(rsp+0x58 → r12) 0x4223(rbp-0x78) 0x30(rbp-0x60)
//   ② 11 个槽任一为 0 或 0x30-槽 == -1 → 跳到函数尾返回 (r15d = 0)
//   ③ 栈上构造两个设备路径字符串（宽字符，立即数成对写入）：
//        rbp+0x40 起："\??\Po..."  (var_90/var_8C/var_40 等)
//        rbp+0x60 起："\A LPC Po rt\Wi ndow s\A pi rt"s? 见下（0x4C0041='L','A'）
//        另有 rbp+0x50 起 "csrss.exe"
//   ④ ExAlloc(...)（0x140077A00 即 ExAlloc）分配缓冲；
//      AllocExBufferAndQuerySystemInfo(0x10)（0x14007A7F8）取系统信息，得项数
//   ⑤ 按 0x18 字节/项遍历项表：
//        — 调 rsp+0x78 指针（带 (项), 0x40, 目标结构, ...）做首轮打开；
//        — 再读 GT[0x914] 构建号决定后续阈值（>=0x1DB0 / <0x1770 / >=0x1DB0 分支）；
//        — 依次调 rbp-0x68 / rbp-0x70 / rsp+0x68 / rbp-0x78 / rsp+0x58 等指针，
//          传 (项+8) 等字段做进一步设备控制；
//        — 命中条件：*(项+8) == 某句柄值 → ebx 归零（cmove）；
//        — 分支 r12b/r13b 标志决定是否调 rbp-0x48/rbp-0x80 收尾；
//        — 记录 (WORD)(项) 到 r15d。
//   ⑥ 收尾：ExFree 两次（0x140077A34 = ExFree），返回 r15d。
// 【返回值】r15d（命中项的 WORD 值；无命中为 0）。
// 【注】本函数与原驱动的驱动路径/设备名强绑定，转写严格按反汇编，
//   两个路径字符串用 WCHAR 数组按原始立即数逐字构造，不写成字符串字面量，
//   以免编译器合并并改变栈布局语义。
unsigned int ReadDiskSectors(void)
{
    __int64  Gt4265, Gt432E, Gt4331, Gt41EA, Gt4334, Gt4259, Gt425C, Gt415A, Gt41C6, Gt4223, Gt30;
    unsigned int Result = 0;                 // r15d
    __int64  EntryTable;                     // rdi / rbp-0x38 (系统信息缓冲)
    unsigned int EntryCount = 0;             // r14d
    char    *pEntry = 0;                     // rsi（按 0x18 递增）
    int      Status = 0;                     // ebx
    unsigned char FlagFirst = 0;             // r12b
    unsigned char FlagSecond = 0;            // r13b
    unsigned int Index = 0;                  // 循环计数（rsp+0x60）
    HANDLE   Handle1 = 0;                    // rsp+0x70（首次打开得到的句柄）
    HANDLE   Handle2 = 0;                    // rsp+0x48（二次打开）
    __int64  ObjInfo = 0;                    // rbp-0x58

    /* ① 取 11 个 GT 槽（严格按原始读取顺序） */
    Gt4265 = GtRead(GtObjectTypeInfoPtr);        // 0x4265  → rbp-0x40
    Gt432E = GtRead((GLOBAL_TABLE_INDEX)0x432E); // 0x432E  → rsp+0x78（首轮打开指针）
    Gt4331 = GtRead((GLOBAL_TABLE_INDEX)0x4331); // 0x4331  → r13 / rbp-0x68
    Gt41EA = GtRead(GtDereferenceObjectFunc);    // 0x41EA  → rsi / rbp-0x50
    Gt4334 = GtRead(GtExFreePoolFunc);           // 0x4334  → rbx / rbp-0x80
    Gt4259 = GtRead(GtCreateObjectTypeFunc);     // 0x4259  → rsp+0x68
    Gt425C = GtRead(GtCloseObjectTypeFunc);      // 0x425C  → r14 / rbp-0x48
    Gt415A = GtRead(GtValidateObjectTypeFunc);   // 0x415A  → rdi / rbp-0x70
    Gt41C6 = GtRead(GtNtFsControlFileFunc);      // 0x41C6  → rsp+0x58 / r12
    Gt4223 = GtRead(GtCloseHandleFunc);          // 0x4223  → rbp-0x78
    Gt30   = GtRead((GLOBAL_TABLE_INDEX)0x30);   // 0x30    → rbp-0x60

    /* ② 11 项校验：任一为 0（0x30 那项还要求 != -1）即直接返回 0 */
    if (!Gt432E || !Gt4331 || !Gt41EA || !Gt4334 || !Gt4259 ||
        !Gt425C || !Gt415A || !Gt41C6 || !Gt4223 || (unsigned int)Gt30 == 0xFFFFFFFF ||
        !Gt4265)
        return Result;

    /* ③ 栈上按原始立即数构造两个宽字符串（不写成字面量，避免编译器重排/合并） */
    WCHAR PathA[24];   // 对应 rbp+0x40 起
    WCHAR PathB[24];   // 对应 rbp+0x60 起
    WCHAR PathC[12];   // 对应 rbp+0x50 起

    PathA[0] = L'\\';  PathA[1] = L'?';  PathA[2] = L'?';  PathA[3] = L'\\';
    PathA[4] = L'P';  PathA[5] = L'o';  PathA[6] = L'\\';  PathA[7] = 0;
    PathB[0] = L'A';  PathB[1] = L'L';  PathB[2] = L'P';  PathB[3] = L'C';
    PathB[4] = L' ';  PathB[5] = L'P';  PathB[6] = L'o';  PathB[7] = L'r';
    PathB[8] = L't';  PathB[9] = L'\\';  PathB[10] = L'W'; PathB[11] = L'i';
    PathB[12] = L'n'; PathB[13] = L'd'; PathB[14] = L'o'; PathB[15] = L'w';
    PathB[16] = L's'; PathB[17] = L'\\'; PathB[18] = L'A'; PathB[19] = L'p';
    PathB[20] = L'i'; PathB[21] = L'r'; PathB[22] = L't'; PathB[23] = 0;
    PathC[0] = L'c';  PathC[1] = L's';  PathC[2] = L'r';  PathC[3] = L's';
    PathC[4] = L'.';  PathC[5] = L'e';  PathC[6] = L'x';  PathC[7] = L'e';
    PathC[8] = 0;

    /* ④ 分配缓冲 + 查询系统信息 */
    EntryTable = (__int64)ExAlloc(PagedPool, 0x200);            // 0x140078C16（call 0x140077A00）
    if (!EntryTable)
        return Result;                                          // → loc_140078F15

    __int64 pSysInfo = (__int64)AllocExBufferAndQuerySystemInfo(0x10);   // 0x140078C2B
    if (!pSysInfo)
        goto FreeAndReturn;                                     // → loc_140078F0D

    EntryCount = *(unsigned int *)pSysInfo;                      // 0x140078C40
    pEntry = (char *)(pSysInfo + 8);                             // 0x140078C45
    Index = 0;
    if (!EntryCount)
        goto FreeSysInfo;                                       // → loc_140078F05

    /* ⑤ 按 0x18 字节/项遍历（完整分支见下，严格对应反汇编 0x140078C59..0x140078EFB） */
    for (;;)
    {
        unsigned int BuildNo;
        int r;

        /* 首轮打开：call [rsp+0x78]（Gt432E），参数 (*(WORD*)pEntry, 0x40, 目标结构, ...) */
        Handle1 = 0;
        r = ((int (__fastcall *)(__int64, unsigned int, void *, __int64, void *))Gt432E)(
                (__int64)*(WORD *)pEntry, 0x40u, &Handle1, 0, 0);            // 0x140078CA1
        if (r < 0)
            goto NextEntry;                                                  // → 0x140078E77

        /* 读构建号：>= 0x1DB0 时第二参数取 0x200 */
        BuildNo = (unsigned int)GtRead(GtWindowsBuildNumber);                // 0x140078CB9
        r = ((int (__fastcall *)(HANDLE, unsigned int, __int64, __int64, void *))Gt4331)(
                Handle1, *(WORD *)(pEntry + 6), BuildNo >= 0x1DB0 ? 0x200 : 0,
                -1, &ObjInfo);                                               // 0x140078CF4
        Status = r;
        if (r >= 0)
        {
            FlagFirst = 1;                                                   // 0x140078CFD
            goto AfterOpen;                                                  // → 0x140078DBB
        }

        /* 首轮失败：构建号 >= 0x1770 时用 Gt415A 再试 */
        FlagSecond = 0;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770)             // 0x140078D0F
            goto AfterOpen;                                                  // → 0x140078DBB

        r = ((int (__fastcall *)(unsigned int, void *))Gt415A)(
                *(WORD *)pEntry, &Handle2);                                  // 0x140078D27
        Status = r;
        if (r < 0)
            goto CleanupHandles;                                             // → 0x140078E64

        ObjInfo = *(WORD *)(pEntry + 6);                                     // 0x140078D38
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0 && Gt4265 &&// 0x140078D42
            *(__int64 *)Gt4265 == Handle2)
            ObjInfo |= 0xFFFFFFFF80000000LL;                                 // 0x140078D61

        FlagSecond = (unsigned char)SwapDiskIrpFunctionPointer();            // 0x140078D6A
        ((void (__fastcall *)(HANDLE, void *))Gt4259)(Handle2, &ObjInfo);    // 0x140078D7C
        {
            void *pOut = 0;
            Status = ((int (__fastcall *)(HANDLE, unsigned int, __int64, __int64, void *, __int64))Gt4223)(
                        Handle1, 0x80000000u, 0, 0, 0, (__int64)&pOut);      // 0x140078DA3
            if (Status >= 0 && *(__int64 *)&pOut == *(__int64 *)(pEntry + 8))
                Status = 0;
        }
        if (Status >= 0)
            ((void (__fastcall *)(HANDLE))Gt41C6)(Handle1);                  // 0x140078DB7

AfterOpen:
        if (Status < 0)
            goto CleanupHandles;                                             // → 0x140078E56

        /* 设备控制序列：Gt4334(...,2,...) → 两次对 (Gt4334+8) 的比较 → Gt4334(...,1,...) */
        Status = ((int (__fastcall *)(HANDLE, unsigned int, __int64, unsigned int, __int64))Gt4334)(
                    Handle1, 2u, EntryTable, 0x2000u, 0);                    // 0x140078DDF
        if (Status < 0)
            goto CleanupHandles;
        if (!*(__int64 *)(EntryTable + 8))
            goto CleanupHandles;
        if (StringCompareCaseInsensitiveV2(*(__int64 *)(EntryTable + 8), (__int64)PathA, 4) != 0)
        {
            if (StringCompareCaseInsensitiveV2(*(__int64 *)(EntryTable + 8), (__int64)PathB, 9) != 0)
                goto CleanupHandles;
        }
        Status = ((int (__fastcall *)(HANDLE, unsigned int, __int64, unsigned int, __int64))Gt4334)(
                    Handle1, 1u, EntryTable, 0x2000u, 0);                    // 0x140078E30
        if (Status < 0)
            goto CleanupHandles;
        if (!*(__int64 *)(EntryTable + 8))
            goto CleanupHandles;
        if (StringCompareCaseInsensitiveV2(*(__int64 *)(EntryTable + 8), (__int64)PathC, 0x10) != 0)
            goto CleanupHandles;
        Result = *(WORD *)pEntry;                                            // 0x140078E52

CleanupHandles:
        if (FlagFirst == 1)
            ((void (__fastcall *)(HANDLE))Gt4334)(Handle1);                  // 0x140078E61
        if (FlagSecond == 1)
        {
            ((void (__fastcall *)(__int64))Gt425C)(( __int64)&ObjInfo);      // 0x140078EC3（rbp-0x48）
            if (FlagSecond == *(unsigned char *)&FlagSecond)                 // 0x140078EC6
                ((void (__fastcall *)(HANDLE))Gt41EA)(Handle2);              // 0x140078ED2
            ((void (__fastcall *)(HANDLE))Gt41C6)(Handle1);                  // 0x140078EE1
        }
        goto NextEntry;                                                      // → 0x140078E69

NextEntry:
        if (Handle2)
            ((void (__fastcall *)(HANDLE))Gt415A)(Handle2);                  // 0x140078E84（rbp-0x70）
        ++Index;
        pEntry += 0x18;
        if (Index < EntryCount)
            continue;
        break;
    }

FreeSysInfo:
    ExFree((void *)pSysInfo);                                                // 0x140078F08
FreeAndReturn:
    ExFree((void *)EntryTable);                                              // 0x140078F10
    return Result;
}