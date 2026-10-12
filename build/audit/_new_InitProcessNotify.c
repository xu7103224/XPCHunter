// InitProcessNotify — 按驱动名识别内核模块并把基址/大小登记到全局表
// 对应原始驱动 0x14001EFA0（2369 字节 / 501 条指令）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— IDA `decompile` 返回 None
//   （91 个不可反编译函数之一，已复验），故走"读反汇编 → 按寄存器/栈槽归属转写"。
//
// 【算法】取全局表条目 1（模块链表头结构），从 +0x28 得环形链表头，自 +0x00 取首节点，
//   遍历至回到表头为止；对每节点按 `Type = *(USHORT*)(node+0x58)` 分派名字比对：
//   - 名字指针 = node+0x60，基址字段 = node+0x50（任一为 0 则跳过该节点）；
//   - 比较函数 StringCompare3Way @0x14007DA0C，**大小写不敏感**
//     （把小写 a-z 减 0x20 后逐字符比较），返回 0 表示相等；
//   - 每组的**比较长度恰为 `Type >> 1`**（即该类型节点名字的字符数）——
//     第一分支用即时数（等价 Type>>1），后续分支显式 `movzx r8d,[rbx+58h]; shr r8d,1`；
//   - 命中即写 (基址 = node+0x30, 大小 = *(ULONG*)(node+0x40)) 到一对 GT。
//   0x14 组首分支与 0x1C 组首分支之外的若干分支会置 Found=1，末尾返回该标志。
//
// 【Type → 名字 → GT 对照表（逐条自反汇编提取）】
//   0x14  L"win32k.sys"    (10 字) → 0x50 / 0x51  (Found=1)
//   0x14  L"fltmgr.sys"    (10 字) → 0x87E / 0x87F  (Found=1)
//   0x1C  L"win32kbase.sys"(14 字) → 0x8F4 / 0x8F5
//   0x1C  L"win32kfull.sys"(14 字) → 0x8F6 / 0x8F7
//   0x16  L"fastfat.sys"   (11 字) → 0x52 / 0x53
//   0x16  L"ataport.sys"   (11 字) → 0x2F8 / 0x2F9
//   0x18  L"kbdc.sys"      (12 字) → 0x2D8 / 0x2D9  (Found=1)
//   0x18  L"mouc.sys"      (12 字) → 0x317 / 0x318  (Found=1)
//   0x18  L"nsiproxy.sys"  (12 字) → 0x31F / 0x320
//   0x18  L"classpnp.sys"  (12 字) → 0x2F1 / 0x2F2
//   0x18  L"storport.sys"  (12 字) → 0x309 / 0x30A
//   0x18  L"scsiport.sys"  (12 字) → 0x307 / 0x308
//   0x18  L"fwpkclnt.sys"  (12 字) → 0x7F8 / 0x7F9
//   0x10  L"ntfs.sys"      (8 字)  → 0x54 / 0x55
//   0x10  L"acpi.sys"      (8 字)  → 0x2FD / 0x2FE
//   0x10  L"ndis.sys"      (8 字)  → 0x361 / 0x362
//   0x0E  L"hal.dll"       (7 字)  → 0x56 / 0x57
//   0x0E  L"tdx.sys"       (7 字)  → 0x322 / 0x323
//   0x0E  L"td.sys"        (7 字)  → 0x802 / 0x803
//   0x12  L"exfat.sys"     (9 字)  → 0x2A1 / 0x2A2
//   0x12  L"Tcpip.sys"     (9 字)  → 0x192 / 0x193
//   0x12  L"netio.sys"     (9 字)  → 0x1A1 / 0x1A2
//   0x12  L"atapi.sys"     (9 字)  → 0x2F6 / 0x2F7
//
// 【与 InitThreadNotify(0x14001F8E4) 的关系】同族孪生：同样的遍历骨架与名字集合；
//   本函数（Process）额外维护 Found 标志，且 0x12/0x10 分支更完整。
__int64 InitProcessNotify(void)
{
    // 原始把各名字以即时数写满 rbp-0xe0..rbp+0x170 的连续 UTF-16 区（共享后缀会被覆盖）。
    // 此处以等价的具名宽字符串给出，内容与原始最终栈镜像逐字符一致。
    static const WCHAR S_win32k[]    = L"win32k.sys";
    static const WCHAR S_fltmgr[]    = L"fltmgr.sys";
    static const WCHAR S_win32kbase[]= L"win32kbase.sys";
    static const WCHAR S_win32kfull[]= L"win32kfull.sys";
    static const WCHAR S_fastfat[]   = L"fastfat.sys";
    static const WCHAR S_ataport[]   = L"ataport.sys";
    static const WCHAR S_kbdc[]      = L"kbdc.sys";
    static const WCHAR S_mouc[]      = L"mouc.sys";
    static const WCHAR S_nsiproxy[]  = L"nsiproxy.sys";
    static const WCHAR S_classpnp[]  = L"classpnp.sys";
    static const WCHAR S_storport[]  = L"storport.sys";
    static const WCHAR S_scsiport[]  = L"scsiport.sys";
    static const WCHAR S_fwpkclnt[]  = L"fwpkclnt.sys";
    static const WCHAR S_ntfs[]      = L"ntfs.sys";
    static const WCHAR S_acpi[]      = L"acpi.sys";
    static const WCHAR S_ndis[]      = L"ndis.sys";
    static const WCHAR S_hal[]       = L"hal.dll";
    static const WCHAR S_tdx[]       = L"tdx.sys";
    static const WCHAR S_td[]        = L"td.sys";
    static const WCHAR S_exfat[]     = L"exfat.sys";
    static const WCHAR S_tcpip[]     = L"Tcpip.sys";
    static const WCHAR S_netio[]     = L"netio.sys";
    static const WCHAR S_atapi[]     = L"atapi.sys";

    ULONG64 ListHead;
    ULONG64 Node;
    UCHAR   Found;
    ULONG   Type;
    ULONG   Len;            // 比较长度 = Type >> 1

    Found = 0;

    ListHead = GtRead((GLOBAL_TABLE_INDEX)1);               // 0x14001EFE1
    if (!ListHead)
        return 0;

    Node = *(ULONG64 *)(ListHead + 0x28);                   // 0x14001EFEF 表头
    Node = *(ULONG64 *)Node;                                // 0x14001EFFD 首节点

    if (Node == *(ULONG64 *)(ListHead + 0x28))              // 0x14001F395 空链
        return Found;

L_LOOP:                                                     // 0x14001F3A3
    if (Node <= (ULONG64)MmSystemRangeStart)                // 0x14001F3AA
        return Found;

    if (*(ULONG64 *)(Node + 0x60) == 0                      // 0x14001F3B3
        || *(ULONG64 *)(Node + 0x50) == 0)                  // 0x14001F3C0
        goto L_NEXT;

    Type = *(USHORT *)(Node + 0x58);                        // 0x14001F3D0
    Len  = Type >> 1;

    if (Type == 0x14)                                       // 0x14001F3D6
    {
        if (StringCompare3Way(S_win32k, *(ULONG64 *)(Node + 0x60), 10) == 0)   // 0x14001F3DE
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x50, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x51, *(ULONG *)(Node + 0x40));
            Found = 1;
            goto L_NEXT;
        }
        if (StringCompare3Way(S_fltmgr, *(ULONG64 *)(Node + 0x60), Len) == 0)   // 0x14001F40A
        {
            GtWrite(GtFltmgrBase, *(ULONG64 *)(Node + 0x30));                   // 0x87E
            GtWrite(GtFltmgrBaseBackup, *(ULONG *)(Node + 0x40));               // 0x87F
            Found = 1;
            goto L_NEXT;
        }
        goto L_NEXT;
    }

    if (Type == 0x1C)                                       // 0x14001F43D
    {
        if (StringCompare3Way(S_win32kbase, *(ULONG64 *)(Node + 0x60), 14) == 0) // 0x14001F44D
        {
            GtWrite(GtHalModuleBase, *(ULONG64 *)(Node + 0x30));                // 0x8F4
            GtWrite((GLOBAL_TABLE_INDEX)0x8F5, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        if (StringCompare3Way(S_win32kfull, *(ULONG64 *)(Node + 0x60), Len) == 0) // 0x14001F481
        {
            GtWrite(GtNtoskrnlFileBase, *(ULONG64 *)(Node + 0x30));             // 0x8F6
            GtWrite((GLOBAL_TABLE_INDEX)0x8F7, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        goto L_NEXT;
    }

    if (Type == 0x16)                                       // 0x14001F4AE
    {
        if (StringCompare3Way(S_fastfat, *(ULONG64 *)(Node + 0x60), 11) == 0)   // 0x14001F4BC
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x52, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x53, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        if (StringCompare3Way(S_ataport, *(ULONG64 *)(Node + 0x60), Len) == 0)  // 0x14001F4EB
        {
            GtWrite(GtCallbackField42, *(ULONG64 *)(Node + 0x30));              // 0x2F8
            GtWrite(GtCallbackField43, *(ULONG *)(Node + 0x40));                // 0x2F9
            goto L_NEXT;
        }
        goto L_NEXT;
    }

    if (Type == 0x18)                                       // 0x14001F518
    {
        if (StringCompare3Way(S_kbdc, *(ULONG64 *)(Node + 0x60), 12) == 0)      // 0x14001F52D
        {
            GtWrite(GtCallbackField13, *(ULONG64 *)(Node + 0x30));              // 0x2D8
            GtWrite(GtCallbackField14, *(ULONG *)(Node + 0x40));                // 0x2D9
            Found = 1;
            goto L_NEXT;
        }
        if (StringCompare3Way(S_mouc, *(ULONG64 *)(Node + 0x60), Len) == 0)     // 0x14001F567
        {
            GtWrite(GtCallbackField70, *(ULONG64 *)(Node + 0x30));              // 0x317
            GtWrite(GtCallbackField71, *(ULONG *)(Node + 0x40));                // 0x318
            Found = 1;
            goto L_NEXT;
        }
        if (StringCompare3Way(S_nsiproxy, *(ULONG64 *)(Node + 0x60), Len) == 0) // 0x14001F59E
        {
            GtWrite(GtCallbackField78, *(ULONG64 *)(Node + 0x30));              // 0x31F
            GtWrite(GtCallbackField79, *(ULONG *)(Node + 0x40));                // 0x320
            goto L_NEXT;
        }
        if (StringCompare3Way(S_classpnp, *(ULONG64 *)(Node + 0x60), Len) == 0) // 0x14001F5D2
        {
            GtWrite(GtFsFilterExportTable, *(ULONG64 *)(Node + 0x30));          // 0x2F1
            GtWrite(GtCallbackField36, *(ULONG *)(Node + 0x40));                // 0x2F2
            goto L_NEXT;
        }
        if (StringCompare3Way(S_storport, *(ULONG64 *)(Node + 0x60), Len) == 0) // 0x14001F603
        {
            GtWrite(GtCallbackField59, *(ULONG64 *)(Node + 0x30));              // 0x309
            GtWrite(GtCallbackField60, *(ULONG *)(Node + 0x40));                // 0x30A
            goto L_NEXT;
        }
        if (StringCompare3Way(S_scsiport, *(ULONG64 *)(Node + 0x60), Len) == 0) // 0x14001F637
        {
            GtWrite(GtCallbackField57, *(ULONG64 *)(Node + 0x30));              // 0x307
            GtWrite(GtCallbackField58, *(ULONG *)(Node + 0x40));                // 0x308
            goto L_NEXT;
        }
        if (StringCompare3Way(S_fwpkclnt, *(ULONG64 *)(Node + 0x60), Len) == 0) // 0x14001F66B
        {
            GtWrite(GtFwpsModuleBase, *(ULONG64 *)(Node + 0x30));               // 0x7F8
            GtWrite((GLOBAL_TABLE_INDEX)0x7F9, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        goto L_NEXT;
    }

    if (Type == 0x10)                                       // 0x14001F698
    {
        if (StringCompare3Way(S_ntfs, *(ULONG64 *)(Node + 0x60), 8) == 0)       // 0x14001F6AA
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x54, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x55, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        if (StringCompare3Way(S_acpi, *(ULONG64 *)(Node + 0x60), Len) == 0)     // 0x14001F6DA
        {
            GtWrite(GtCallbackField47, *(ULONG64 *)(Node + 0x30));              // 0x2FD
            GtWrite(GtCallbackField48, *(ULONG *)(Node + 0x40));                // 0x2FE
            goto L_NEXT;
        }
        if (StringCompare3Way(S_ndis, *(ULONG64 *)(Node + 0x60), Len) == 0)     // 0x14001F70B
        {
            GtWrite(GtEprocessExtField11, *(ULONG64 *)(Node + 0x30));           // 0x361
            GtWrite(GtEprocessExtField12, *(ULONG *)(Node + 0x40));             // 0x362
            goto L_NEXT;
        }
        goto L_NEXT;
    }

    if (Type == 0x0E)                                       // 0x14001F730（r15w＝0x73-0x65）
    {
        if (StringCompare3Way(S_hal, *(ULONG64 *)(Node + 0x60), 7) == 0)        // 0x14001F749
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x56, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x57, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        if (StringCompare3Way(S_tdx, *(ULONG64 *)(Node + 0x60), Len) == 0)      // 0x14001F779
        {
            GtWrite(GtCallbackField81, *(ULONG64 *)(Node + 0x30));              // 0x322
            GtWrite(GtCallbackField82, *(ULONG *)(Node + 0x40));                // 0x323
            goto L_NEXT;
        }
        if (StringCompare3Way(S_td, *(ULONG64 *)(Node + 0x60), Len) == 0)       // 0x14001F7AB
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x802, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x803, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        goto L_NEXT;
    }

    if (Type == 0x12)                                       // 0x14001F7D5
    {
        if (StringCompare3Way(S_exfat, *(ULONG64 *)(Node + 0x60), 9) == 0)      // 0x14001F7ED
        {
            GtWrite(GtKernelDataField15, *(ULONG64 *)(Node + 0x30));            // 0x2A1
            GtWrite(GtKernelDataField16, *(ULONG *)(Node + 0x40));              // 0x2A2
            goto L_NEXT;
        }
        if (StringCompare3Way(S_tcpip, *(ULONG64 *)(Node + 0x60), Len) == 0)    // 0x14001F81F
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x192, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x193, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        if (StringCompare3Way(S_netio, *(ULONG64 *)(Node + 0x60), Len) == 0)    // 0x14001F84D
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x1A1, *(ULONG64 *)(Node + 0x30));
            GtWrite((GLOBAL_TABLE_INDEX)0x1A2, *(ULONG *)(Node + 0x40));
            goto L_NEXT;
        }
        if (StringCompare3Way(S_atapi, *(ULONG64 *)(Node + 0x60), Len) == 0)    // 0x14001F87B
        {
            GtWrite(GtCallbackField40, *(ULONG64 *)(Node + 0x30));              // 0x2F6
            GtWrite(GtCallbackField41, *(ULONG *)(Node + 0x40));                // 0x2F7
            goto L_NEXT;
        }
        goto L_NEXT;
    }

L_NEXT:                                                     // 0x14001F8A2
    Node = *(ULONG64 *)Node;
    if (Node != *(ULONG64 *)(ListHead + 0x28))              // 0x14001F8A5
        goto L_LOOP;
    return Found;
}