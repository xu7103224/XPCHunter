/* ============================================================================
 * process.c —— 进程与线程枚举
 *
 * 数据源：
 *   进程  —— 0xE4 CmdEnumProcessListWin10，条目 0x298 字节
 *   路径  —— 0x2A（函数名叫 CmdEnumThreads，实际实现是路径查询）
 *   可访问性 —— 0x27 CmdCheckProcessAccess
 *   线程  —— 0x2A 的线程分支（需要 EPROCESS）
 * ==========================================================================*/
#include "XpchSdk_internal.h"

/* 0xE4 的条目布局（Win10 18362，实机校准）：
 *   +0x000 QWORD EPROCESS
 *   +0x008 BYTE[16] EPROCESS.ImageFileName（ANSI，驱动兜底写入）
 *   +0x108 QWORD UniqueProcessId
 *   +0x290 BYTE 1=还有后继条目，最后一项为 0
 */
#define PROC_ENTRY_SIZE     0x298u
#define PROC_EPROCESS_OFF   0x000u
#define PROC_NAME_OFF       0x008u
#define PROC_PID_OFF        0x108u
#define PROC_NEXT_OFF       0x290u
#define PROC_MAX_ENTRIES    1024u

XPCH_STATUS XpchEnumProcesses(XPCH_SESSION *Session,
                              XPCH_PROCESS_INFO **Processes,
                              ULONG *Count)
{
    XPCH_SESSION_IMPL *Impl;
    BYTE *Buf;
    SIZE_T OutSize;
    XPCH_STATUS St;
    XPCH_PROCESS_INFO *Items;
    ULONG i, n = 0;

    if (!Session || !Processes || !Count)
        return XPCH_E_INVALID_ARG;
    *Processes = NULL;
    *Count = 0;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    OutSize = (SIZE_T)PROC_MAX_ENTRIES * PROC_ENTRY_SIZE;
    Buf = (BYTE *)XpchAlloc(OutSize);
    if (!Buf)
        return XPCH_E_NO_MEMORY;

    St = XpchInvokeRaw(Session, CMD_ENUM_PROCESS_WIN10, NULL, 0,
                       Buf, (ULONG)OutSize);
    if (St != XPCH_OK) {
        XpchFreeInternal(Buf);
        return St;
    }

    Items = (XPCH_PROCESS_INFO *)XpchAlloc(
                (SIZE_T)PROC_MAX_ENTRIES * sizeof(XPCH_PROCESS_INFO));
    if (!Items) {
        XpchFreeInternal(Buf);
        return XPCH_E_NO_MEMORY;
    }

    for (i = 0; i < PROC_MAX_ENTRIES; i++) {
        const BYTE *Entry = Buf + (SIZE_T)i * PROC_ENTRY_SIZE;
        ULONG64 Eprocess = *(const ULONG64 *)(Entry + PROC_EPROCESS_OFF);

        if (!Eprocess)
            break;                       /* 缓冲区已清零，列表到头 */

        Items[n].Eprocess = Eprocess;
        Items[n].Pid = (ULONG)*(const ULONG64 *)(Entry + PROC_PID_OFF);

        /* ImageFileName 最长 15 字符 + 结尾 0 */
        memcpy(Items[n].Name, Entry + PROC_NAME_OFF, XPCH_PROC_NAME_CHARS - 1);
        Items[n].Name[XPCH_PROC_NAME_CHARS - 1] = 0;
        n++;

        if (*(const BYTE *)(Entry + PROC_NEXT_OFF) == 0)
            break;                       /* 驱动标记的最后一项 */
    }

    XpchFreeInternal(Buf);

    if (n == 0) {
        XpchFreeInternal(Items);
        return XPCH_E_NO_DATA;
    }

    *Processes = Items;
    *Count = n;
    return XPCH_OK;
}

XPCH_STATUS XpchGetProcessPath(XPCH_SESSION *Session, ULONG Pid,
                               WCHAR *Path, ULONG PathChars)
{
    XPCH_SESSION_IMPL *Impl;
    ULONG64 InPid;
    BYTE Out[520];
    XPCH_STATUS St;
    int i;

    if (!Session || !Path || PathChars < 8)
        return XPCH_E_INVALID_ARG;
    Path[0] = 0;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    /* 0x2A 要求 inSize == 8（PID），outSize == 520（WCHAR[260]） */
    InPid = (ULONG64)Pid;
    ZeroMemory(Out, sizeof(Out));
    St = XpchInvokeRaw(Session, CMD_ENUM_THREADS, &InPid, sizeof(InPid),
                       Out, sizeof(Out));
    if (St != XPCH_OK)
        return St;

    /* 输出是 WCHAR[260]；拷贝到调用方缓冲并按需截断 */
    {
        const WCHAR *Src = (const WCHAR *)Out;
        for (i = 0; i < (int)PathChars - 1 && i < 260 && Src[i]; i++)
            Path[i] = Src[i];
        Path[i] = 0;
    }

    /* 空路径不是错误：PID 0/4 这类系统进程没有用户态映像 */
    return XPCH_OK;
}

XPCH_STATUS XpchIsProcessAccessible(XPCH_SESSION *Session, ULONG Pid,
                                    BOOL *Accessible)
{
    XPCH_SESSION_IMPL *Impl;
    XPCH_PROCESS_INFO *Procs = NULL;
    ULONG N = 0, i;
    ULONG64 In[2];
    BYTE Out[16];
    ULONG64 Eprocess = 0;
    XPCH_STATUS St;

    if (!Session || !Accessible || !Pid)
        return XPCH_E_INVALID_ARG;
    *Accessible = FALSE;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    /* 先枚举进程拿 EPROCESS。0x27 的判定依赖它：
       处理器比较 GT[0x185]（"当前进程"，由 0x20 写入 IoGetCurrentProcess，
       即驱动所在的系统进程）与 TargetProcess；不等时走
       ValidateProcessObject 分支。只传 PID 且 EPROCESS 留 0 时，驱动自己
       PsLookupProcessByProcessId 解析，结果与传 EPROCESS 一致，但显式传入
       可以避免解析失败时把 NULL 当成有效对象。
       实测：不传 EPROCESS 时连自身进程都判 0，传了之后判定正常。 */
    St = XpchEnumProcesses(Session, &Procs, &N);
    if (St != XPCH_OK)
        return St;
    for (i = 0; i < N; i++) {
        if (Procs[i].Pid == Pid) {
            Eprocess = Procs[i].Eprocess;
            break;
        }
    }
    XpchFree(Procs);
    if (!Eprocess)
        return XPCH_E_NOT_FOUND;

    In[0] = (ULONG64)Pid;
    In[1] = Eprocess;
    ZeroMemory(Out, sizeof(Out));
    St = XpchInvokeRaw(Session, CMD_CHECK_PROCESS_ACCESS, In, sizeof(In),
                       Out, sizeof(Out));

    if (St == XPCH_OK) {
        *Accessible = TRUE;
        return XPCH_OK;
    }
    if (St == XPCH_E_REJECTED) {
        /* 驱动执行了、判定为不可访问 —— 有效结论，不是错误 */
        *Accessible = FALSE;
        return XPCH_OK;
    }
    return St;
}

/* ---------------------------------------------------------------------------
 * 线程枚举
 *
 * 这里用纯用户态的 Toolhelp 快照而不是驱动命令。
 * 原因：驱动侧的线程枚举需要 EPROCESS 指针，而 0x2A 已被"路径查询"占用，
 * 真正的线程命令（0x25/0x3E 等）在老版本上输出布局不稳定。
 * Toolhelp 能拿到 Tid/OwnerPid/优先级，且不需要驱动。
 * 需要"驱动视角的线程"（含隐藏线程）时应单独扩展。
 * -------------------------------------------------------------------------*/
#include <tlhelp32.h>

XPCH_STATUS XpchEnumThreads(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_THREAD_INFO **Threads, ULONG *Count)
{
    HANDLE Snap;
    THREADENTRY32 Te;
    XPCH_THREAD_INFO *Items;
    ULONG n = 0, Cap = 256;

    UNREFERENCED_PARAMETER(Session);

    if (!Threads || !Count)
        return XPCH_E_INVALID_ARG;
    *Threads = NULL;
    *Count = 0;

    Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Snap == INVALID_HANDLE_VALUE)
        return XPCH_E_NO_DATA;

    Items = (XPCH_THREAD_INFO *)XpchAlloc(Cap * sizeof(XPCH_THREAD_INFO));
    if (!Items) {
        CloseHandle(Snap);
        return XPCH_E_NO_MEMORY;
    }

    ZeroMemory(&Te, sizeof(Te));
    Te.dwSize = sizeof(Te);
    if (Thread32First(Snap, &Te)) {
        do {
            if (Te.th32OwnerProcessID != Pid)
                continue;
            if (n >= Cap) {
                XPCH_THREAD_INFO *Grown = (XPCH_THREAD_INFO *)XpchAlloc(
                        (SIZE_T)(Cap * 2) * sizeof(XPCH_THREAD_INFO));
                if (!Grown)
                    break;
                memcpy(Grown, Items, (SIZE_T)n * sizeof(XPCH_THREAD_INFO));
                XpchFreeInternal(Items);
                Items = Grown;
                Cap *= 2;
            }
            ZeroMemory(&Items[n], sizeof(Items[n]));
            Items[n].Tid = Te.th32ThreadID;
            Items[n].OwnerPid = Te.th32OwnerProcessID;
            Items[n].BasePriority = Te.tpBasePri;
            Items[n].DeltaPriority = (ULONG)Te.tpDeltaPri;
            n++;
        } while (Thread32Next(Snap, &Te));
    }
    CloseHandle(Snap);

    if (n == 0) {
        XpchFreeInternal(Items);
        return XPCH_E_NO_DATA;
    }

    *Threads = Items;
    *Count = n;
    return XPCH_OK;
}