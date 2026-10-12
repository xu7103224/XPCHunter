// ============================================================
// Minifilter 缺失族（L2-3）—— 上下文枚举依赖链
//
// 拓扑：MiniFilterInstanceSetup → OpenMiniFilterVolumeFile
//       → EnumMiniFilterContextList
// 三者依次在 _FINAL_GAP.json 中均为 A_definite_missing，必须成链实现。
// 以下按原始反汇编逐条转写，代码内标注 `L_<地址>`。
// ============================================================

// EnumMiniFilterContextList — 枚举对象类型条目、按类型分组并填表
// 对应原始驱动 0x140012620（938 字节）
// 【帧定基】`mov rax,rsp` → 存 4 个实参到 home（[rax+8]=rcx, [rax+0x10]=edx,
//   [rax+0x18]=r8, [rax+0x20]=r9）→ push 8 个寄存器(0x40) → `sub rsp,0x68`
//   故 rsp = 入口 rsp - 0xA8，rax = rsp + 0xA8。实参槽（由 rax 换算）：
//     [rsp+0xB0] = rcx = OutArray   （输出数组基址）
//     [rsp+0xB8] = edx = MaxEntries （条目上限，调用方传 0x20000）
//     [rsp+0xC0] = r8  = OutCount   （输出计数指针，命中时 +1）
//     [rsp+0xC8] = r9  = Limit      （输出边界，用于越界校验）
//   —— 与调用方 OpenMiniFilterVolumeFile 的
//      `EnumMiniFilterContextList(Buf, 0x20000, OutStruct, OutStruct+OutSize)` 完全一致。
// 【算法】取 GT 0x41DB / 0x360，任一为 0 即返回；要求 MaxEntries > 1；
//   沿 OutArray[0] 起的对象列表最多走 0x25 项：
//     用 CheckMemoryValid 校验对象 → 按构建号取对象类型（<=0x1772 取 [obj-0x20]，
//     否则 CheckObjectTypeFlagWrapper(obj-0x30)）→ 遍历该对象的上下文链（首项 [obj]，后继 [node]）：
//       · 类型相同 → 追加到 OutArray[++Written]；
//       · 否则 FindContextEntry 尝试合并，未合并则用 SkipContextEntries 取条目位并
//         ValidateAddressWithSize 校验后填 {节点, 名字截断 0x40 字节, 字段计数}，
//         再逐条把 (Cur+0x10, Cur+0x28, Cur+0x30) 三个字段拷入表尾；
//         若本条目无子项则不动 OutCount，有则 +1。
void EnumMiniFilterContextList(__int64 OutArray, ULONG MaxEntries,
                               ULONG *OutCount, ULONG64 Limit)
{
    __int64 ObjList;              // rbp = rcx（OutArray 起点，逐轮 +8）
    ULONG   OuterIdx;             // ebx
    ULONG   InnerIdx;             // edx
    ULONG64 R12;                  // Written（初值 -1）
    ULONG64 R15;                  // Written 的 64 位伴随（OutArray 索引）
    __int64 ObjEntry;             // rdi
    ULONG64 Cur;                  // 当前对象
    ULONG64 TypeA;                // 参照类型
    ULONG64 EntryBase;            // 条目位（SkipContextEntries 结果）
    UCHAR   Done;                 // [rsp+0x20]

    ULONG64 G41DB = (ULONG64)GtRead(GtObjectTypeCheckFlag);        // 0x140012651
    ULONG64 G360  = (ULONG64)GtRead(GtEprocessExtField10);         // 0x140012668

    Done = 0;

    if (!G41DB || !G360)                                     // 0x140012672/67B
        return;
    if ((int)MaxEntries <= 1)                                // 0x140012687
        return;

    ObjList = OutArray;
    ObjEntry = *(__int64 *)ObjList;                          // 0x140012690 [rbp]
    R12 = (ULONG64)-1;                                       // 0x140012694
    R15 = R12;
    OuterIdx = 0;
    InnerIdx = 0;

    if (!ObjEntry)                                           // 0x1400126A8
        return;

L_OUTER:                                                     // 0x1400126B4
    if (CheckMemoryValid((void *)ObjEntry) != 1)              // 0x1400126BA（原始 bl=1）
        return;
    if (OuterIdx >= 0x100000)                                // 0x1400126C8
        return;

    // 参照类型（0x1400126D4~6F4）
    if ((ULONG)GtRead(GtWindowsBuildNumber) <= 0x1772)
        TypeA = *(ULONG64 *)(ObjEntry - 0x20);
    else
        TypeA = (UCHAR)CheckObjectTypeFlagWrapper(ObjEntry - 0x30);

    EntryBase = (ULONG64)SkipContextEntries((_DWORD *)OutArray);   // 0x140012703
    Cur = *(ULONG64 *)ObjEntry;                              // 0x140012710
    InnerIdx = 0;

    if (!Cur)                                                // 0x14001271E
        goto L_OUTER_NEXT;

L_INNER:                                                     // 0x140012727
    if ((ULONG64)EntryBase >= Limit)                         // 0x140012727 cmp rsi,[rsp+0xc8]
        goto L_INNER_END;
    if (InnerIdx >= 0x10000)                                 // 0x140012735
        goto L_INNER_END;

    {
        ULONG64 CtxHdr = *(ULONG64 *)(Cur + 8);              // 0x140012741
        ULONG64 NodeType;

        if ((ULONG)GtRead(GtWindowsBuildNumber) <= 0x1772)   // 0x140012745~75A
            NodeType = *(ULONG64 *)(CtxHdr - 0x20);
        else
            NodeType = (UCHAR)CheckObjectTypeFlagWrapper(CtxHdr - 0x30);

        if (TypeA == NodeType)                               // 0x14001276B
        {
            // 类型相同 → 追加到 OutArray[++Written]（0x14001276D~79B）
            ULONG CapMinus1 = MaxEntries - 1;
            if ((int)R12 < (int)CapMinus1)
            {
                ++R12;
                ++R15;
                ((ULONG64 *)(ULONG_PTR)OutArray)[R15] = CtxHdr;
            }
        }
        else
        {
            // 0x1400127A0：先尝试合并
            if (FindContextEntry((__int64)CtxHdr, (_DWORD *)OutArray) != 0)  // 0x1400123C8
                goto L_INNER_NEXT;

            // 0x1400127B3：取新条目位并做边界检查（OutArray 作为游标推进）
            EntryBase = (ULONG64)SkipContextEntries((_DWORD *)OutArray);
            if (EntryBase + 0x68 >= Limit)                   // 0x1400127BE/7C2
            {
                Done = 1;
                goto L_OUTER_NEXT;
            }

            *(ULONG64 *)EntryBase = CtxHdr;                  // 0x1400127D2
            *(USHORT *)(EntryBase + 8) = 0;                  // 0x1400127D8

            // 0x1400127DC：取名字并截断拷贝（至多 0x40 字节）
            {
                __int64 Name = (__int64)ValidateAddressWithSize((char *)CtxHdr);  // 0x1400798F8
                if (Name)
                {
                    ULONG n = *(USHORT *)Name;
                    if (n > 1)                               // 0x1400127EE
                    {
                        ULONG64 Src = *(ULONG64 *)(Name + 8);
                        if ((UCHAR)CheckMemoryValid((void *)Src) != 0        // 0x1400127FD
                            && (UCHAR)CheckMemoryValid((void *)(Src - 1)) != 0)  // 0x140012813
                        {
                            ULONG cp = (n < 0x40) ? n : 0x40;    // 0x140012828 cmova
                            memmove((void *)(EntryBase + 8), (void *)Src, cp);  // 0x140012836
                            *(USHORT *)(EntryBase + 8 + ((ULONG64)cp >> 1) * 2) = 0;  // 0x140012840
                        }
                    }
                }
                *(ULONG *)(EntryBase + 0x4C) = 0;            // 0x14001284A
            }

            // 0x14001284D：遍历子链（Sub = CtxHdr + G360）
            {
                ULONG64 Sub = (ULONG64)CtxHdr + G360;        // 0x140012853
                if (CheckMemoryValid((void *)Sub) == 1)      // 0x14001285C
                {
                    ULONG64 S = *(ULONG64 *)Sub;             // 0x14001286A
                    ULONG   cnt = 0;

                    while (S && S != Sub)                    // 0x14001287B/884
                    {
                        ULONG64 need;
                        ULONG   idx;
                        ULONG64 slot;

                        idx = *(ULONG *)(EntryBase + 0x4C);  // 0x140012889
                        need = EntryBase + ((ULONG64)idx * 3 + 0xD) * 8;
                        if (need > Limit) break;             // 0x140012898

                        if (CheckMemoryValid((void *)S) != 1) break;               // 0x1400128A3
                        if (CheckMemoryValid((void *)(S + 0x3F)) != 1) break;      // 0x1400128B4

                        ++cnt;                               // 0x1400128C1
                        idx = *(ULONG *)(EntryBase + 0x4C);
                        slot = (ULONG64)idx * 3;
                        *(ULONG  *)(EntryBase + slot * 8 + 0x50)    = *(ULONG  *)(S + 0x10); // 0x1400128CB
                        *(ULONG64*)(EntryBase + slot * 8 + 0x58)    = *(ULONG64*)(S + 0x28); // 0x1400128DA
                        *(ULONG64*)(EntryBase + (slot + 4) * 8)     = *(ULONG64*)(S + 0x30); // 0x1400128EE
                        ++*(ULONG *)(EntryBase + 0x4C);      // 0x1400128F2
                        S = *(ULONG64 *)S;                   // 0x1400128F6
                        if (cnt >= 0x10000) break;           // 0x1400128F9
                    }
                }
            }

            // 0x14001290F：本条目产出了子项才递增 OutCount
            if (*(ULONG *)(EntryBase + 0x4C) != 0)           // 0x140012919
                ++*OutCount;                                 // 0x14001291E
        }

    L_INNER_NEXT:                                            // 0x140012926
        Cur = *(ULONG64 *)Cur;                               // 0x14001292F
        ++InnerIdx;                                          // 0x140012932
        if (Cur)
            goto L_INNER;                                    // 0x140012942
    }

L_INNER_END:                                                 // 0x140012950
L_OUTER_NEXT:                                                // 0x140012954
    if (Done == 1)                                           // 0x14001295D/95F
        return;
    ++OuterIdx;                                              // 0x140012961
    ObjList += 8;                                            // 0x140012963
    ObjEntry = *(__int64 *)ObjList;                          // 隐含：rdi += 8 后重取
    if (OuterIdx >= 0x25)                                    // 0x140012970 cmp ebx,25h
        return;
    if (!ObjEntry)                                           // 0x1400129B0
        return;
    goto L_OUTER;
}

// OpenMiniFilterVolumeFile — 打开 L"\ObjectTypes" 并枚举过滤器上下文
// 对应原始驱动 0x14001241C（515 字节）
// 【帧定基】存 rbx/rsi 到 [rsp+0x10/0x18] → push rdi,r12,r13,r14,r15(0x28) → sub rsp,0xC0
// 【算法】取 5 个 GT 函数指针（0x421D 打开 / 0x4238 查询 / 0x41C6 初始化 /
//   0x4223 关闭 / 0x4334 释放），任一为 0 则整体跳过；
//   构造 UNICODE_STRING L"\ObjectTypes"（栈 rsp+0x98）→ FnOpen(&Handle, &Name)
//   → 布置 OBJECT_ATTRIBUTES{rsp+0x68=0x30, rsp+0x80=0x240, rsp+0x78=&Name}
//   → FnQuery(&QueryOut, 1, &Attr)，非负则 FnInit(Handle, 0xF000F, 0, 0, &QueryOut)，
//   非负则 ExAlloc(1, 0x100000) 取缓冲、写入查询结果、调 EnumMiniFilterContextList
//   → ExFree 缓冲 → FnClose(查询结果) → FnFree(句柄)。恒返回 0。
UCHAR OpenMiniFilterVolumeFile(__int64 OutStruct, ULONG OutSize)
{
    __int64 FnOpen, FnQuery, FnInit, FnClose, FnFree;
    UCHAR   Name[32];
    UCHAR   ObjAttr[0x30];
    ULONG64 Handle;
    ULONG64 QueryOut;
    ULONG64 Buf;

    FnOpen  = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x421D);   // 0x140012453
    FnQuery = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4238);   // 0x140012460
    FnInit  = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x41C6);   // 0x14001246D
    FnClose = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4223);   // 0x14001247A
    FnFree  = (__int64)GtRead(GtExFreePoolFunc);             // 0x14001248C ecx=0x4334

    if (!FnOpen || !FnQuery || !FnInit || !FnClose || !FnFree)   // 0x140012499~4C0
        return 0;

    // L"\ObjectTypes"（0x1400124C6~508）
    memset(Name, 0, sizeof(Name));
    *(ULONG *)&Name[0]  = 0x4F005C;      // \\O
    *(ULONG *)&Name[4]  = 0x6A0062;      // bj
    *(ULONG *)&Name[8]  = 0x630065;      // ec
    *(ULONG *)&Name[12] = 0x540074;      // tT
    *(ULONG *)&Name[16] = 0x700079;      // yp
    *(ULONG *)&Name[20] = 0x730065;      // es

    ((void(__fastcall *)(ULONG64 *, void *))FnOpen)(&Handle, Name);   // 0x14001251D

    // OBJECT_ATTRIBUTES（0x140012520~546）
    memset(ObjAttr, 0, 0x28);
    *(ULONG   *)&ObjAttr[0x00] = 0x30;                                  // Length
    *(ULONG64 *)&ObjAttr[0x10] = (ULONG64)(ULONG_PTR)Name;              // ObjectName
    *(ULONG   *)&ObjAttr[0x18] = 0x240;                                 // Attributes

    if ((int)((__int64(__fastcall *)(ULONG64 *, ULONG, void *))FnQuery)(
            &QueryOut, 1, ObjAttr) < 0)                     // 0x140012562/565/567
        return 0;

    if ((int)((__int64(__fastcall *)(ULONG64, ULONG, ULONG, ULONG, ULONG64 *))FnInit)(
            Handle, 0xF000F, 0, 0, &QueryOut) < 0)          // 0x14001258D/591
        goto L_CLOSE_HANDLE;

    Buf = (ULONG64)ExAlloc(1, 0x100000);                    // 0x14001259B（rcx=1, edx=0x100000）
    if (!Buf)                                               // 0x1400125A8
        goto L_FREE_QUERY;

    *(ULONG64 *)Buf = QueryOut;                             // 0x1400125B2

    EnumMiniFilterContextList((__int64)Buf, 0x20000,         // 0x1400125C4
                              (ULONG *)OutStruct, (ULONG64)(OutStruct + OutSize));

    ExFree((void *)Buf);                                    // 0x1400125DD

L_FREE_QUERY:
    ((void(__fastcall *)(ULONG64))FnClose)(QueryOut);       // 0x1400125E7
L_CLOSE_HANDLE:
    ((void(__fastcall *)(ULONG64))FnFree)(Handle);          // 0x1400125EE
    return 0;                                               // 0x1400125F0 xor al,al
}

// MiniFilterInstanceSetup — FLT 实例安装回调：校验用户缓冲并按构建号分发
// 对应原始驱动 0x1400129CC（179 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return STATUS_SUCCESS;` 空壳。
UCHAR MiniFilterInstanceSetup(void *FltFilter, void *Instance, void *Buffer, ULONG BufferSize)
{
    UCHAR Result = 0;

    (void)FltFilter; (void)Instance;

    if (!Buffer)                                             // 0x1400129ED
        return Result;
    if (BufferSize <= 0x70)                                  // 0x1400129F2
        return Result;
    if ((ULONG64)Buffer >= MmUserProbeAddress)               // 0x1400129F7/2A01
        return Result;
    if ((ULONG64)Buffer + BufferSize >= MmUserProbeAddress)  // 0x140012A06/0A0A
        return Result;

    ProbeForWrite(Buffer, BufferSize, 1);                    // 0x140012A1B
    memset(Buffer, 0, BufferSize);                           // 0x140012A29
    *(ULONG *)Buffer = 0;                                    // 0x140012A2E

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1771)        // 0x140012A30/3A
        return Result;

    OpenMiniFilterVolumeFile((__int64)Buffer, BufferSize);   // 0x140012A46

    Result = (*(ULONG *)Buffer != 0) ? 1 : 0;                // 0x140012A4E cmovne
    return Result;
}

// MiniFilterPreFastIo — 快速 IO 预处理：校验用户缓冲并按结构尺寸分发枚举
// 对应原始驱动 0x14001B2B4（176 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return STATUS_SUCCESS;` 空壳。
// 【要点】用魔数 0xA41A41A41A41A41B 实现无符号除法：
//   条目数 = (BufferSize - 0x278) / 0x278 + 1。
UCHAR MiniFilterPreFastIo(void *Filter, void *CallbackData, void *Buffer, ULONG BufferSize)
{
    UCHAR Result = 0;
    ULONG64 T, Q, R, Entries;

    (void)Filter; (void)CallbackData;

    if (!Buffer)                                             // 0x14001B2C8
        return Result;
    if (BufferSize < 0x278)                                  // 0x14001B2D1
        return Result;
    if ((ULONG64)Buffer >= MmUserProbeAddress)               // 0x14001B2DA/2E4
        return Result;
    if ((ULONG64)Buffer + BufferSize >= MmUserProbeAddress)  // 0x14001B2EC/2F0
        return Result;

    ProbeForWrite(Buffer, BufferSize, 8);                    // 0x14001B2FE
    memset(Buffer, 0, BufferSize);                           // 0x14001B30C
    *(ULONG *)Buffer = 0;                                    // 0x14001B311

    T = (ULONG64)BufferSize - 0x278;
    Q = (ULONG64)(((unsigned __int128)T * 0xA41A41A41A41A41BULL) >> 64);  // 0x14001B324 mul
    R = T - Q;
    R >>= 1;
    Entries = ((Q + R) >> 9) + 1;                            // 0x14001B32D~335

    if (EnumerateAleEndpointLayers((_DWORD *)Buffer, (__int64)Buffer + 8, (int)Entries))  // 0x14001B33F
        Result = 1;                                          // 0x14001B344
    return Result;
}