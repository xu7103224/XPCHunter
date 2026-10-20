// ============================================================================
// XPCHunter Frontend — 进程列表（Process 页的数据层）
//
// 数据来源（均已实机校准，见 docs/reversing/命令可用性校准_2026-10-21.md）：
//
//   0xE4  CmdEnumProcessListWin10
//         入参：无（In=NULL / InSize=0）
//         输出：N 个 0x298(664) 字节条目；处理器要求 OutSize >= 0x298，
//               按剩余空间填尽可能多的条目（缓冲区先被清零）。
//         条目布局（Win10 18362 / NDIS 0x60053 布局）：
//             +0x000 QWORD EPROCESS
//             +0x108 QWORD UniqueProcessId   （映射自 EPROCESS+0x2E8）
//             +0x290 BYTE  1 = 还有后继条目  （最后一项为 0）
//
//   0x2A  CmdEnumThreads —— 名字叫枚举线程，实际实现是**进程映像路径查询**
//         入参：8 字节 = PID
//         输出：520(0x208) 字节 = WCHAR[260] 路径
//         成功返回 1；PID 不存在时返回 0。
//
// 这两条命令的结果字节语义不同（0xE4 成功返回 1，0x2A 成功返回 1，
// 但很多命令成功也返回 0），所以判定一律以"返回 TRUE + 输出结构合理"为准。
// ============================================================================

#include "XPCHunterUM.h"
#include <stdio.h>
#include <string.h>

BOOL FeLoadProcessList(XPCH_CLIENT *Client, ULONG MaxCount, FE_PROCESS_LIST *List)
{
    ULONG maxEntries;
    SIZE_T outSize;
    BYTE *buf;
    ULONG i;
    UCHAR res = 0;
    BOOL ok;

    if (!Client || !List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!Client->Opened)
        return FALSE;

    maxEntries = MaxCount ? MaxCount : FE_PROC_DEFAULT_MAX;
    if (maxEntries > FE_PROC_HARD_MAX)
        maxEntries = FE_PROC_HARD_MAX;
    outSize = (SIZE_T)maxEntries * FE_PROC_ENTRY_SIZE;

    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outSize);
    if (!buf)
        return FALSE;

    ok = XpchInvoke(Client, XPCH_CMD_ENUM_PROCESS_WIN10,
                    NULL, 0, buf, (ULONG)outSize, &res);
    if (!ok) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    List->Items = (FE_PROCESS *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          (SIZE_T)maxEntries * sizeof(FE_PROCESS));
    if (!List->Items) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    List->Capacity = maxEntries;

    for (i = 0; i < maxEntries; i++) {
        const BYTE *entry = buf + (SIZE_T)i * FE_PROC_ENTRY_SIZE;
        ULONG64 eprocess = *(const ULONG64 *)entry;

        if (!eprocess)
            break;                                  /* 缓冲区已清零，说明列表到头 */
        List->Items[i].Eprocess = eprocess;
        List->Items[i].Pid = *(const ULONG *)(entry + FE_PROC_PID_OFFSET);
        List->Items[i].Path[0] = 0;
        /* 驱动在条目 +0x08 写了 EPROCESS.ImageFileName（15 字节 ANSI + 0） */
        memcpy(List->Items[i].Name, entry + FE_PROC_NAME_OFFSET, 15);
        List->Items[i].Name[15] = 0;
        List->Count++;

        if (*(const BYTE *)(entry + FE_PROC_NEXT_OFFSET) == 0)
            break;                                  /* 处理器标记的最后一项 */
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}

void FeFreeProcessList(FE_PROCESS_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FeLoadProcessPath(XPCH_CLIENT *Client, ULONG Pid, WCHAR *Path, ULONG PathChars)
{
    ULONG64 inPid;
    BYTE out[FE_PROC_PATH_BYTES];
    UCHAR res = 0;
    BOOL ok;
    ULONG i;

    if (!Client || !Path || !PathChars)
        return FALSE;
    Path[0] = 0;
    if (!Client->Opened)
        return FALSE;

    inPid = (ULONG64)Pid;
    ZeroMemory(out, sizeof(out));
    ok = XpchInvoke(Client, XPCH_CMD_QUERY_PROCESS_PATH,
                    &inPid, sizeof(inPid), out, sizeof(out), &res);
    if (!ok)
        return FALSE;

    /* 输出是 WCHAR[260]，确保按 PathChars 截断并补 0 */
    for (i = 0; i + 1 < PathChars && i < FE_PROC_PATH_CHARS; i++) {
        Path[i] = ((const WCHAR *)out)[i];
        if (!Path[i])
            return TRUE;
    }
    Path[i] = 0;
    return TRUE;
}

/* 宽字符 → 本地代码页（控制台/日志用）。转换失败时给 "?"。 */
void FeWideToAnsi(const WCHAR *Wide, char *Ansi, size_t AnsiChars)
{
    int n;
    if (!Ansi || !AnsiChars)
        return;
    Ansi[0] = 0;
    if (!Wide)
        return;
    if (!Wide[0]) {
        strcpy_s(Ansi, AnsiChars, "(?)");
        return;
    }
    n = WideCharToMultiByte(CP_ACP, 0, Wide, -1, Ansi, (int)AnsiChars - 1, NULL, NULL);
    if (n <= 0)
        strcpy_s(Ansi, AnsiChars, "(?)");
}

BOOL FePrintProcessList(XPCH_CLIENT *Client)
{
    FE_PROCESS_LIST list;
    ULONG i;

    if (!FeLoadProcessList(Client, FE_PROC_DEFAULT_MAX, &list)) {
        printf("process list: 0xE4 failed\n");
        return FALSE;
    }

    printf("processes: %lu\n", list.Count);
    for (i = 0; i < list.Count; i++) {
        char path[FE_PROC_PATH_CHARS * 2];

        /* 短名来自条目 +0x08（驱动从 EPROCESS.ImageFileName 拷来）；
           完整路径用 0x2A 逐个查询（入 8 字节 PID，出 WCHAR[260]）。 */
        if (!FeLoadProcessPath(Client, list.Items[i].Pid,
                               list.Items[i].Path, FE_PROC_PATH_CHARS))
            list.Items[i].Path[0] = 0;
        FeWideToAnsi(list.Items[i].Path, path, sizeof(path));
        printf("  pid=%-6lu eprocess=%p name=%-16s path=%s\n",
               list.Items[i].Pid, (void *)(ULONG_PTR)list.Items[i].Eprocess,
               list.Items[i].Name[0] ? list.Items[i].Name : "(?)", path);
    }

    FeFreeProcessList(&list);
    return TRUE;
}
