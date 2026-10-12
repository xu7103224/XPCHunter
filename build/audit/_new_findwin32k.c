// FindWin32kSectionByType — 按节区类型 1298 查找 Win32k 数据节区
// 对应原始驱动 0x1400888FC（356 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取的调用序：
//   读 0x20（GtEprocessField22 = Win32k 映像基址）
//   读 0x21（GtEprocessField23 = Win32k 映像大小）
//   读 0x21 复用为循环边界比较；
//   读 0x4348（GtTotalSize|GtNtCreateFileSyscallResult = 节区起始偏移）
//   命中写 0x31A（GtCallbackField73 = 结果槽）。
// 【算法】四个 GT 值齐备且 偏移 < 大小 → 以 (基址+偏移, 大小-偏移) 初始化上下文；
//   循环上限 0x64：类型 1298(0x512) 且 字段+0x88 == 0x40000 且 字段+0x40 非零
//   且 字段+0x50 == 64 → 算 RVA = 累计 + 字段+0x40 - 基址，非 0 且 < 大小 →
//   写 GT 0x31A = ntoskrnl 模块基址 + RVA。
// 【返回值】伪代码里是 `result`（读条目失败时为 ReadPESectionEntry 的返回值，
//   命中时为 GtWrite 的返回值）。此处按项目惯例以 __int64 返回同一表达式。
__int64 FindWin32kSectionByType(void)
{
    __int64  Win32kBase;         // v0 = GtRead(0x20)
    ULONG    Win32kSize;         // v1 = GtRead(0x21)
    __int64  NtoskrnlBase;       // v2 = GtRead(3)
    __int64  result;             // = GtRead(0x4348)
    ULONG    i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[20];

    Win32kBase   = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x20);      // 0x140088934（GtEprocessField22=32）
    Win32kSize   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);        // 0x140088941（GtEprocessField23=33）
    NtoskrnlBase = (__int64)GtRead(GtNtoskrnlModuleBase);          // 0x14008894E（3）
    result       = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4348);    // 0x140088951

    if (!Win32kBase || !Win32kSize || !NtoskrnlBase                 // 0x14008897A
        || (ULONG)result == 0 || (ULONG)result >= Win32kSize)
        return result;

    InitPESectionReadContext(Win32kBase + (ULONG)result,           // 0x1400889AD
                             Win32kSize - (ULONG)result,
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x64; ++i)                                     // 0x1400889B2
    {
        USHORT Type;
        ULONG  Len, Cumul, F40;
        ULONG64 F50, F88;

        result = (__int64)ReadPESectionEntry((PUCHAR)&Ctx, Entry);  // 0x1400889C1
        if ((ULONG)result != 0)                                     // 0x1400889C8
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                          // 0x1400889DB
        Ctx.ReadPtr += Len;                                        // 0x1400889E6

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400889DE
        F40  = *(ULONG *)((PUCHAR)Entry + 0x40);
        F50  = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F88  = *(ULONG64 *)((PUCHAR)Entry + 0x88);

        if (Type == 0x512 && F88 == 0x40000ULL)                    // 0x1400889FD
        {
            if (F40 != 0                                            // 0x140088A08
                && F50 == 64)                                       // 0x140088A13
            {
                ULONG r = Cumul + F40 - (ULONG)(ULONG_PTR)Win32kBase;   // 0x140088A17
                if (r && r < Win32kSize)                            // 0x140088A19 / A1D
                {
                    return (__int64)GtWrite(GtCallbackField73,      // 0x140088A32
                                            NtoskrnlBase + (__int64)r);
                }
            }
        }
    }
    return result;                                                  // 0x140088A37
}