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
