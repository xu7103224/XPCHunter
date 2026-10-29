// ============================================================================
// KernelHookViews.c — Ring0 Hooks / Kernel SSDT 数据层（0x117 CmdEnumHookInfo）
//
// 【0x117 的输出布局（实机解码 + 原始反汇编双向确认）】
//   +0x00 DWORD  WindowsBuildNumber
//   +0x04 DWORD  Count1   第一张表条目数（GT[0x8B7]）
//   +0x08 DWORD  Count2   第二张表条目数（GT[0x8BA]）
//   +0x10 起     条目数组，每条 **40 字节**，先 Count1 条再 Count2 条
//
// 条目内（基址 = 0x10 + 40*index）：
//   +0x00 BYTE   flagAddrChanged  —— ValidateHookEntries 写：
//                                   `*CurrentEntry != CurrentEntry[1]`，即"表项当前值
//                                   已不等于磁盘原始值" → 该函数被改写
//   +0x01 BYTE   flagBytesChanged —— ValidateHookEntries 写：内存前 16 字节
//                                   与磁盘 16 字节不同 → 该函数被 inline patch
//   +0x04 DWORD  Index            —— CopyHookEntryArray 写的 `Index`
//   +0x08 QWORD  CurrentAddress   —— FilterActiveHookEntries 写的 `*pSrc`
//   +0x10 QWORD  OriginalAddress  —— CopyHookEntryArray 写的 `pSourceArray[Index]`
//   +0x18 16B    OriginalBytes    —— CollectTwoSyscallTables 从磁盘文件拷的
//                                   原始指令前 16 字节
//
// 【这两张表是什么】
// 原始 `ParseSyscallTableExportDir`(0x1400865C8) 从 GT[0x8AE]（wdf01000.sys 基址）
// 出发，解析该模块 .data 节里"计数 384..512 的地址表"描述符，写入
// GT[0x8B7]/[0x8B9]（第一张）与 GT[0x8BA]/[0x8BC]（第二张）。
// 原始收集函数名就是 `CollectTwoSyscallTables` —— 两张系统调用表。
// 因此：
//   * Ring0 Hooks 页     = 这两张表的全部条目 + 两个改写标志
//   * Kernel→SSDT        = 第一张表（GT[0x8B7]）
//   * Kernel→Shadow SSDT = 第二张表（GT[0x8BA]）
// 本机 build 18362 实测 Count1=454、Count2=0（wdf01000.sys 只命中一处描述符）。
// Count2=0 是真实结果，界面照实显示，不伪造。
//
// 【缓冲要求（踩过的坑）】
//     BufferSize >= 40 * (Count1 - 1) + 56
// Count1=454 时为 18176 字节；给 0x2000(8192) 会让条目拷贝判定失败、返回 0。
// 这里固定申请 0x20000（可容纳 3274 条）。
// ============================================================================
#include "XPCHunterUM.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FE_RING0_INIT_BUF    0x20000u
#define FE_RING0_MAX_ENTRIES 4096u

static void FeDecodeEntryDisasm(FE_RING0_HOOK_ENTRY *e)
{
    int pos = 0, n = 0;

    e->Disasm[0] = 0;
    while (pos < 16 && n < 4) {
        FE_INSN ins;
        int len;
        if (!FeDisasmOne(e->Bytes + pos, 16 - pos, &ins))
            break;
        len = ins.Length > 0 ? ins.Length : 1;
        if ((int)strlen(e->Disasm) + (int)strlen(ins.Mnemonic) + 4 >= (int)sizeof(e->Disasm))
            break;
        if (n)
            strcat_s(e->Disasm, sizeof(e->Disasm), " ; ");
        strcat_s(e->Disasm, sizeof(e->Disasm), ins.Mnemonic);
        pos += len;
        n++;
    }
    if (n == 0)
        strcpy_s(e->Disasm, sizeof(e->Disasm), "(undecoded)");
}

/* 解析 0x117 的输出缓冲。成功返回 TRUE 并填 List。 */
BOOL FeParseRing0Hooks(const BYTE *Buf, ULONG BufSize, FE_RING0_HOOK_LIST *List)
{
    ULONG Count1, Count2, Total, i, off;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!Buf || BufSize < 0x10)
        return FALSE;

    List->Build  = *(const ULONG *)(Buf + 0x00);
    Count1       = *(const ULONG *)(Buf + 0x04);
    Count2       = *(const ULONG *)(Buf + 0x08);
    List->Count1 = Count1;
    List->Count2 = Count2;

    Total = Count1 + Count2;
    if (Total == 0)
        return FALSE;                    /* 真·空表：调用方如实显示 */
    if (Total > FE_RING0_MAX_ENTRIES)
        return FALSE;
    if (0x10 + 40ULL * Total > BufSize)
        Total = (ULONG)((BufSize - 0x10) / 40);
    if (Total == 0)
        return FALSE;

    List->Items = (FE_RING0_HOOK_ENTRY *)calloc(Total, sizeof(FE_RING0_HOOK_ENTRY));
    if (!List->Items)
        return FALSE;
    List->Capacity = Total;

    off = 0x10;
    for (i = 0; i < Total; i++, off += 40)
    {
        FE_RING0_HOOK_ENTRY *e = &List->Items[List->Count++];

        e->TableIndex = (i < Count1) ? 1 : 2;
        e->FlagAddr   = Buf[off + 0x00];
        e->FlagBytes  = Buf[off + 0x01];
        e->Index      = *(const ULONG *)(Buf + off + 0x04);
        e->Current    = *(const ULONG64 *)(Buf + off + 0x08);
        e->Original   = *(const ULONG64 *)(Buf + off + 0x10);
        memcpy(e->Bytes, Buf + off + 0x18, 16);
        if (e->FlagAddr || e->FlagBytes)
            List->ModifiedCount++;
        FeDecodeEntryDisasm(e);
    }
    return TRUE;
}

void FeFreeRing0Hooks(FE_RING0_HOOK_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* 通过驱动 0x117 取全部条目。
 * OutSize 必须 >= 40*(Count1-1)+56；Count1=454 时需 18176，故申请 0x20000。 */
BOOL FeLoadRing0Hooks(XPCH_CLIENT *Client, FE_RING0_HOOK_LIST *List)
{
    PUCHAR buf;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!Client || !Client->Opened)
        return FALSE;

    buf = (PUCHAR)calloc(1, FE_RING0_INIT_BUF);
    if (!buf)
        return FALSE;

    /* 结果字节不作为判据：条目内容才是事实（驱动在 Count2 为空时仍可能返 0） */
    (void)XpchInvoke(Client, 0x117, NULL, 0, buf, FE_RING0_INIT_BUF, NULL);
    if (!FeParseRing0Hooks(buf, FE_RING0_INIT_BUF, List)) {
        free(buf);
        return FALSE;
    }
    free(buf);
    return List->Count != 0;
}

BOOL FePrintRing0Hooks(XPCH_CLIENT *Client)
{
    FE_RING0_HOOK_LIST list;
    ULONG i;

    if (!FeLoadRing0Hooks(Client, &list)) {
        printf("ring0 hooks: query failed (Count1=%lu Count2=%lu)\n",
               list.Count1, list.Count2);
        return FALSE;
    }
    printf("=== Ring0 Hooks (build %lu) ===\n", list.Build);
    printf("table1(GT[0x8B7]): %lu entries   table2(GT[0x8BA]): %lu entries   total: %lu\n",
           list.Count1, list.Count2, list.Count);
    printf("modified entries (addr-changed or bytes-changed): %lu\n", list.ModifiedCount);
    for (i = 0; i < list.Count; i++) {
        const FE_RING0_HOOK_ENTRY *e = &list.Items[i];
        printf("  t%lu[%04lu] cur=%016I64X orig=%016I64X %s%s  %s\n",
               (unsigned long)e->TableIndex, (unsigned long)e->Index,
               e->Current, e->Original,
               e->FlagAddr  ? "[ADDR]" : "",
               e->FlagBytes ? "[BYTES]" : "",
               e->Disasm);
    }
    FeFreeRing0Hooks(&list);
    return TRUE;
}

/* ============================================================================
 * Ring0 恢复操作 1：0x118 CmdCheckBytePattern → RestoreSyscallHookByIndex
 *
 * 入参 8 字节（驱动侧 InputSize 必须 == 8）：
 *   byte0 == 1  → 全索引循环：Index 0..0x1FF，逐个 TableType = SBYTE1 恢复
 *   否则        → 单个：TableType = SBYTE1，Index = HIDWORD
 *
 * 驱动侧恢复条件是「表项当前值 != 磁盘原始值」，即只有被改写的条目才会被写回。
 * 本机实测 908 条 Hook 条目的 flagAddr/flagBytes 全为 0（没有待恢复项），
 * 因此该命令返回 0 是**正确行为**，界面必须把这个状态说清楚，
 * 不能简单显示成"失败"。
 * ========================================================================== */

BOOL FeRestoreOverHooks(XPCH_CLIENT *Client, int AllTables, FE_HOOK_RESTORE_RESULT *Out)
{
    BYTE in[8];
    UCHAR res = 0;
    BOOL ok;

    if (!Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    Out->TablesTried = AllTables ? 2 : 1;
    if (!Client || !Client->Opened) {
        Out->State = FE_HOOK_RESTORE_NOT_CONNECTED;
        return FALSE;
    }

    /* byte0 = 1（全索引）或 0（单条，此处不用），byte1 = TableType */
    ZeroMemory(in, sizeof(in));
    in[0] = AllTables ? 1 : 0;
    in[1] = 1;                       /* TableType 1 = 第一张表 */
    if (!AllTables) {
        /* 单条模式需要 HIDWORD = 索引；界面默认走全索引，这里留 0 */
        in[4] = 0; in[5] = 0; in[6] = 0; in[7] = 0;
    }

    ok = XpchInvoke(Client, 0x118, in, (ULONG)sizeof(in), NULL, 0, &res);
    Out->ResultByte = res;
    Out->DriverOk = ok;

    /* result=0 有两种含义，必须区分：
     *   a) 没有任何条目被改写 → 无需恢复（正常）
     *   b) 确实有被改写的条目 → 恢复成功但驱动仍可能返回 0（取决于写入结果）
     * 前端先查 0x117 的 ModifiedCount 来判断属于哪一种。 */
    if (ok && res == 1) {
        Out->State = FE_HOOK_RESTORE_RESTORED;
    } else {
        FE_RING0_HOOK_LIST list;
        if (FeLoadRing0Hooks(Client, &list)) {
            Out->ModifiedCount = list.ModifiedCount;
            Out->TotalEntries  = list.Count;
            FeFreeRing0Hooks(&list);
        }
        Out->State = (Out->ModifiedCount == 0)
                   ? FE_HOOK_RESTORE_NOTHING_TO_DO
                   : FE_HOOK_RESTORE_ATTEMPTED_NO_EFFECT;
    }
    return TRUE;
}

/* ============================================================================
 * Ring0 恢复操作 2：内核回调表（0x131 枚举 + 0x132 设置）
 *
 * 0x131 CmdEnumCallbackContext：OutSize 必须 == 1352（0x548）
 *   原始实现先取 GT[GtHookTableCount]，为 0 则 BuildCallbackContextHookTargets()，
 *   再 EnumCallbackContextTable / CopyCallbackContextHookTable / Validate…；
 *   三者都成功才把 out[0] 置 1 并把 build 号写 out[2]（即 +8 字节处）。
 * 0x132 CmdSetCallbackContext：InSize 必须 == 48（0x30）
 *   [24] == 1 且 *(QWORD*)(in+8) 非零 → InstallCallbackContextHookEntry（装 Hook）
 *   [25] == 1 → 校验目标在内核区后 WritePhysicalMemoryBuffer 写 16 字节补丁
 *   两者都做 → 返回 HookResult & PatchResult。
 * ========================================================================== */

BOOL FeLoadCallbackTable(XPCH_CLIENT *Client, FE_CB_TABLE *Out)
{
    BYTE *buf;
    UCHAR res = 0;
    BOOL ok;
    ULONG i;

    if (!Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    if (!Client || !Client->Opened) {
        Out->State = FE_CB_NOT_CONNECTED;
        return FALSE;
    }
    buf = (BYTE *)calloc(1, 1352);
    if (!buf) {
        Out->State = FE_CB_NOT_CONNECTED;
        return FALSE;
    }
    ok = XpchInvoke(Client, 0x131, NULL, 0, buf, 1352, &res);
    Out->ResultByte = res;
    Out->Ready      = buf[0];
    Out->Build      = *(const ULONG *)(buf + 8);
    if (ok && buf[0] == 1) {
        /* 【2026-10-23 修正】条目区布局是从原版输出实测出来的，此前按
           「+4 起、步长 32、取首 8 字节」扫描是错的（既错位又读错字段）：
             0x000  UCHAR  就绪标志（三项校验全过才为 1）
             0x001  UCHAR  -
             0x002  UCHAR  -
             0x003  UCHAR  -
             0x004  ULONG  保留（恒 0）
             0x008  28 条 × 0x30 字节条目
           条目内（对应驱动 pTargetTable 的 48 字节结构）：
             +0x00 ULONG   索引 0..27
             +0x04 ULONG   目标 RVA（ParseNtExportSectionsV3 命中项或 FillExportEntrySlot 默认值）
             +0x08 ULONG64 目标 VA = ntoskrnl 基址 + RVA
             +0x10 ULONG64 当前回调函数指针（EnumCallbackContextTable 从上下文 +0x70+8i 拷入）
             +0x18 QWORD   原始代码前 8 字节
             +0x20 QWORD   原始代码后 8 字节
           依据：orig_131.txt 中 entry0 = idx 0 / rva 0x1450 / va 0xfffff80585ac1450 /
                 +0x10 同 VA / +0x18 0xc93328ec83480000 / +0x20 "48 8b c2 89 4a 30..."
           （原始代码在结构里是 +0x1A 起的连续 16 字节，只是前 8 字节落在 +0x18
             这个 QWORD 的后 6 字节上 —— 这里按 16 字节整块读出，保持与原版一致。） */
        static const ULONG EntryBase = 8;
        static const ULONG EntryStride = 0x30;
        static const ULONG EntryCount = 28;
        Out->Count = 0;
        for (i = 0; i < EntryCount; i++) {
            const BYTE *e = buf + EntryBase + i * EntryStride;
            if (EntryBase + (i + 1) * EntryStride > 1352)
                break;
            Out->Slot[i].Offset      = *(const ULONG *)(e + 0x00);
            Out->Slot[i].Rva         = *(const ULONG *)(e + 0x04);
            Out->Slot[i].Va          = *(const ULONG64 *)(e + 0x08);
            Out->Slot[i].Current     = *(const ULONG64 *)(e + 0x10);
            memcpy(Out->Slot[i].Original, e + 0x1A, 16);
            /* 只有当 Va 有效时快照才有意义 */
            Out->Slot[i].HasOriginal = (Out->Slot[i].Va != 0);
            Out->Count++;
        }
        Out->State = FE_CB_ENUMERATED;
    } else {
        /* 驱动返回 0 有两种成因，需要分开呈现：
         *   ok == FALSE  → 分派器/处理器直接拒绝（ResultByte 也为 0）
         *   ok == TRUE   → 处理器执行了，但 EnumCallbackContextTable 没成功
         *                  （回调上下文链表未构建），这是环境状态而非"失败"
         * 注意 XpchInvoke 的 ok 判定的是结果字节非零，所以这里两者等价；
         * 真正的区分靠 EnumCallbackContextTable 的内部原因，用户态不可见。
         * 统一按「未初始化」呈现，并把 resultByte 一起显示。 */
        Out->State = FE_CB_NOT_INITIALIZED;
    }
    free(buf);
    /* 返回 TRUE 表示"查询本身完成"，是否枚举到数据看 State */
    return TRUE;
}

/* 用 0x132 把某个回调槽写回原值（恢复被替换的回调）。
 *   SlotAddr   原版语义里的目标地址（in+8）
 *   Original16 要写回的 16 字节补丁（in+26 起）
 * 只置 in[25]=1（打补丁），不置 in[24]（不额外装 Hook）。 */
BOOL FeRestoreCallbackSlot(XPCH_CLIENT *Client, ULONG64 SlotAddr,
                           const BYTE *Original16, FE_CB_RESTORE_RESULT *Out)
{
    BYTE in[48];
    UCHAR res = 0;
    BOOL ok;

    if (!Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    if (!Client || !Client->Opened) {
        Out->State = FE_CB_RESTORE_NOT_CONNECTED;
        return FALSE;
    }
    if (!SlotAddr || !Original16) {
        Out->State = FE_CB_RESTORE_BAD_INPUT;
        return FALSE;
    }
    ZeroMemory(in, sizeof(in));
    *(ULONG64 *)(in + 8) = SlotAddr;
    in[25] = 1;                       /* 打补丁路径 */
    memcpy(in + 26, Original16, 16);

    ok = XpchInvoke(Client, 0x132, in, (ULONG)sizeof(in), NULL, 0, &res);
    Out->ResultByte = res;
    Out->DriverOk   = ok;
    if (ok && res == 1)      Out->State = FE_CB_RESTORE_OK;
    else if (ok)             Out->State = FE_CB_RESTORE_NO_EFFECT;
    else                     Out->State = FE_CB_RESTORE_REJECTED;
    return TRUE;
}

const char *FeHookRestoreStateText(FE_HOOK_RESTORE_RESULT *R)
{
    if (!R) return "(null)";
    switch (R->State) {
    case FE_HOOK_RESTORE_RESTORED:            return "restored";
    case FE_HOOK_RESTORE_NOTHING_TO_DO:       return "nothing to restore";
    case FE_HOOK_RESTORE_ATTEMPTED_NO_EFFECT: return "sent, driver reported no change";
    case FE_HOOK_RESTORE_NOT_CONNECTED:       return "not connected";
    default:                                  return "unknown";
    }
}

const char *FeCbStateText(FE_CB_TABLE *T)
{
    if (!T) return "(null)";
    switch (T->State) {
    case FE_CB_ENUMERATED:      return "enumerated";
    case FE_CB_NOT_INITIALIZED: return "callback table not initialized";
    case FE_CB_REJECTED:        return "driver rejected";
    case FE_CB_NOT_CONNECTED:   return "not connected";
    default:                    return "unknown";
    }
}

/* ============================================================================
 * Kernel 页 Device / Object 子页数据层
 *
 * Device → 0x056 CmdEnumObjectAllTypes
 *   输出：条目不带头，按 0x838 字节步进，直到某条目的 type 与 device 都为空。
 *   条目内（由 CopySectionString 写入，见驱动侧 QueryDriver.c）：
 *     +0x000 DWORD  DeviceType（1=驱动对象设备 / 2=文件系统 / 3=其他路径）
 *     +0x008 QWORD  保留
 *     +0x010 QWORD  设备对象地址
 *     +0x018 WCHAR  驱动名（最长 0x103 字符）
 *     +0x220 WCHAR  设备名
 *     +0x428 WCHAR  对象名
 *     +0x630 WCHAR  文件路径
 *   缓冲：驱动按 OutSize/0x838 决定最多几条，给 0x20000 可得全部（实测 6 条）。
 *
 * Object → 0x0D5 CmdEnumKernelObjectTable
 *   输出：+0x00 DWORD build、+0x04 DWORD 条数、+0x08 起每项 0xC8 字节，
 *         条目首字段是对象头指针。实测 build 18362、14 条。
 * ========================================================================== */

static void FeWideToAnsi(const WCHAR *Src, char *Dst, int DstChars)
{
    int i = 0;
    if (!Src || !Dst || DstChars <= 0)
        return;
    for (; i < DstChars - 1 && Src[i]; i++)
        Dst[i] = (Src[i] < 0x80) ? (char)Src[i] : '?';
    Dst[i] = 0;
}

BOOL FeLoadDeviceObjects(XPCH_CLIENT *Client, FE_DEVICE_LIST *Out, ULONG BufSize)
{
    BYTE *buf;
    UCHAR res = 0;
    BOOL ok;
    ULONG off, idx;

    if (!Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    if (!Client || !Client->Opened) {
        Out->State = 0;
        return FALSE;
    }
    if (BufSize < 0x838)
        BufSize = 0x20000;
    buf = (BYTE *)calloc(1, BufSize);
    if (!buf)
        return FALSE;

    ok = XpchInvoke(Client, 0x56, NULL, 0, buf, BufSize, &res);
    Out->DriverOk = ok;
    Out->ResultByte = res;
    if (!ok) {
        Out->State = 0;                 /* 驱动拒绝 */
        free(buf);
        return TRUE;
    }
    Out->Capacity = BufSize / 0x838;
    Out->Items = (FE_DEVICE_ENTRY *)calloc(Out->Capacity ? Out->Capacity : 1,
                                           sizeof(FE_DEVICE_ENTRY));
    if (!Out->Items) {
        free(buf);
        return FALSE;
    }
    for (idx = 0, off = 0; idx < Out->Capacity; idx++, off += 0x838) {
        ULONG type = *(const ULONG *)(buf + off + 0x000);
        ULONG64 dev = *(const ULONG64 *)(buf + off + 0x010);
        if (!type && !dev)
            break;                      /* 驱动没写满：后面全零 */
        Out->Items[Out->Count].Type = type;
        Out->Items[Out->Count].DeviceObject = dev;
        FeWideToAnsi((const WCHAR *)(buf + off + 0x018),
                     Out->Items[Out->Count].DriverName,
                     (int)sizeof(Out->Items[Out->Count].DriverName));
        FeWideToAnsi((const WCHAR *)(buf + off + 0x220),
                     Out->Items[Out->Count].DeviceName,
                     (int)sizeof(Out->Items[Out->Count].DeviceName));
        FeWideToAnsi((const WCHAR *)(buf + off + 0x428),
                     Out->Items[Out->Count].ObjectName,
                     (int)sizeof(Out->Items[Out->Count].ObjectName));
        FeWideToAnsi((const WCHAR *)(buf + off + 0x630),
                     Out->Items[Out->Count].FilePath,
                     (int)sizeof(Out->Items[Out->Count].FilePath));
        Out->Count++;
    }
    Out->State = 1;
    free(buf);
    return TRUE;
}

void FeFreeDeviceList(FE_DEVICE_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* 0x056 条目的 Type 字段语义名。
 * 依据见 XPCHunterUM.h 里 FeDeviceTypeName 上方的注释表：
 * 2/5/6/7/8/9/10/11/12 是各 QueryDriverObjectByPath 的路径长度，
 * 1/3/4 是 EnumDeviceObjects / QueryDriverObjectDevice 内部的固定字面量。 */
const char *FeDeviceTypeName(ULONG Type)
{
    switch (Type) {
    case 1:  return "Device Link";
    case 2:  return "FileSystem";
    case 3:  return "Driver Object";
    case 4:  return "Device Object";
    case 5:  return "Tcpip";
    case 6:  return "Nsiproxy";
    case 7:  return "Tdx";
    case 8:  return "KbdClass";
    case 9:  return "Mouclass";
    case 10: return "i8042prt";
    case 11: return "NDIS";
    case 12: return "PnpManager";
    default: return "Other";
    }
}

/* 统计属于某一 Type 的条目数。Type=0 表示全部。
 * 原版「File System Item」树就是按这个维度把 0x056 的拼接段拆开的。 */
ULONG FeDeviceListGroupCount(const FE_DEVICE_LIST *List, ULONG Type)
{
    ULONG i, n = 0;

    if (!List || !List->Items)
        return 0;
    for (i = 0; i < List->Count; i++)
        if (Type == 0 || List->Items[i].Type == Type)
            n++;
    return n;
}

/* 大小写不敏感的子串匹配（不引入 strstr 的大小写变体依赖）。 */
static BOOL FeContainsI(const char *Hay, const char *Needle)
{
    size_t hn, nn, i;
    if (!Hay || !Needle)
        return FALSE;
    hn = strlen(Hay);
    nn = strlen(Needle);
    if (!nn)
        return TRUE;
    if (nn > hn)
        return FALSE;
    for (i = 0; i + nn <= hn; i++) {
        size_t k;
        for (k = 0; k < nn; k++) {
            char a = Hay[i + k], b = Needle[k];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b)
                break;
        }
        if (k == nn)
            return TRUE;
    }
    return FALSE;
}

/* 按 Type + 驱动名子串筛选条目下标。
 * 用于实现原版那些"按驱动对象筛一类"的节点：实测 volmgr / volsnap / fvevol
 * 都出现在 Driver Object(3) 段，而不是各自的独立段（那些段用的
 * \Driver\<name> 路径在本机打不开，原版驱动同样打不开，见对照实验）。 */
ULONG FeDeviceListMatchDriver(const FE_DEVICE_LIST *List,
                              ULONG Type, const char *NameSub,
                              ULONG *OutIndices, ULONG MaxOut)
{
    ULONG i, n = 0;

    if (!List || !List->Items)
        return 0;
    for (i = 0; i < List->Count; i++) {
        if (Type && List->Items[i].Type != Type)
            continue;
        if (NameSub && NameSub[0]) {
            /* 驱动名与设备名任一命中即可（不同段填的字段不同：
               Driver Object 段的 dev= 才是真实驱动名，drv= 是上级）。 */
            if (!FeContainsI(List->Items[i].DriverName, NameSub) &&
                !FeContainsI(List->Items[i].DeviceName, NameSub) &&
                !FeContainsI(List->Items[i].ObjectName, NameSub))
                continue;
        }
        if (OutIndices && n < MaxOut)
            OutIndices[n] = i;
        n++;
    }
    return n;
}

BOOL FeLoadKernelObjectTable(XPCH_CLIENT *Client, FE_KOBJ_LIST *Out)
{
    BYTE *buf;
    UCHAR res = 0;
    BOOL ok;
    ULONG count, i, cap;

    if (!Out)
        return FALSE;
    ZeroMemory(Out, sizeof(*Out));
    if (!Client || !Client->Opened)
        return FALSE;

    buf = (BYTE *)calloc(1, 0x8000);
    if (!buf)
        return FALSE;
    ok = XpchInvoke(Client, 0xD5, NULL, 0, buf, 0x8000, &res);
    Out->DriverOk = ok;
    Out->ResultByte = res;
    if (!ok) {
        free(buf);
        return TRUE;
    }
    Out->Build = *(const ULONG *)(buf + 0x00);
    count      = *(const ULONG *)(buf + 0x04);
    cap = (0x8000 - 8) / 0xC8;
    if (count > cap)
        count = cap;
    Out->Items = (FE_KOBJ_ENTRY *)calloc(count ? count : 1, sizeof(FE_KOBJ_ENTRY));
    if (!Out->Items) {
        free(buf);
        return FALSE;
    }
    for (i = 0; i < count; i++) {
        ULONG base = 8 + 0xC8 * i;
        Out->Items[i].ObjectHeader = *(const ULONG64 *)(buf + base + 0x00);
        Out->Items[i].Field1       = *(const ULONG64 *)(buf + base + 0x08);
        Out->Items[i].Field2       = *(const ULONG64 *)(buf + base + 0x10);
        Out->Count++;
    }
    Out->State = 1;
    free(buf);
    return TRUE;
}

void FeFreeKernelObjectList(FE_KOBJ_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
}

/* ------------------------------------------------------- IDT（0x046）
 * 驱动侧的调用约定是 Handler(InPtr, OutSize, OutPtr, InSize)，而 0x046
 * 的实现把第 2 个参数当"输出缓冲大小"用 —— 也就是客户端的 InSize。
 * 所以必须同时给 InSize >= 0x3808 和足够大的输出缓冲，否则它直接返回 0。
 *
 * 输出布局：
 *   +0x00 DWORD 上下文数 n（= 处理器数），0 表示链条没解析出来
 *   +0x08 起     n 个 0x3800 字节上下文
 * 每个上下文第 i 条（56 字节）：
 *   +0  DWORD 中断向量号
 *   +4  DWORD 段选择器
 *   +8  QWORD 处理函数地址 - ntoskrnlBase（0 = 空门）
 *   +16 BYTE  异常标志（RPL != 0 / 选择器 != 2 / 选择器越界 时置 1）
 */
BOOL FeLoadIdt(XPCH_CLIENT *Client, FE_IDT_LIST *List)
{
    BYTE *in = NULL, *out = NULL;
    UCHAR res = 0;
    BOOL ok;
    ULONG i, count;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!Client || !Client->Opened)
        return FALSE;

    in = (BYTE *)calloc(1, 0x3808);
    out = (BYTE *)calloc(1, 0x3808);
    if (!in || !out) {
        free(in);
        free(out);
        return FALSE;
    }
    ok = XpchInvoke(Client, 0x46, in, 0x3808, out, 0x3808, &res);
    List->DriverOk = ok;
    List->ResultByte = res;
    if (!ok) {
        free(in);
        free(out);
        return FALSE;
    }

    count = *(ULONG *)out;
    List->ContextCount = count;
    if (count == 0) {
        free(in);
        free(out);
        return TRUE;       /* 参数通过但链条没解析出来，如实返回空表 */
    }
    List->Items = (FE_IDT_ENTRY *)calloc(FE_IDT_MAX, sizeof(FE_IDT_ENTRY));
    if (!List->Items) {
        free(in);
        free(out);
        return FALSE;
    }
    for (i = 0; i < FE_IDT_MAX; i++) {
        BYTE *slot = out + 8 + (ULONG64)i * 56;
        List->Items[i].Vector = *(ULONG *)slot;
        List->Items[i].HandlerRva = *(ULONG64 *)(slot + 8);
        List->Count++;
    }
    free(in);
    free(out);
    return TRUE;
}

void FeFreeIdt(FE_IDT_LIST *List)
{
    if (!List)
        return;
    free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->ContextCount = 0;
}

BOOL FePrintIdt(XPCH_CLIENT *Client)
{
    FE_IDT_LIST list;
    ULONG i, shown = 0, nonEmpty = 0;

    if (!FeLoadIdt(Client, &list)) {
        printf("IDT (0x046): query failed\n");
        return FALSE;
    }
    printf("IDT (0x046): contexts=%lu entries=%lu\n",
           list.ContextCount, list.Count);
    for (i = 0; i < list.Count; i++) {
        if (!list.Items[i].HandlerRva)
            continue;
        nonEmpty++;
        if (shown < 24) {
            printf("  vec %-3lu handler RVA %016I64X\n",
                   (unsigned long)list.Items[i].Vector, list.Items[i].HandlerRva);
            shown++;
        }
    }
    printf("  non-empty gates: %lu\n", nonEmpty);
    FeFreeIdt(&list);
    return TRUE;
}
