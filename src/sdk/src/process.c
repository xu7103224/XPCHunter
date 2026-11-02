/* ============================================================================
 * process.c —— 进程 / 线程 / 进程内存读写 / 进程模块
 *
 * 【2026-11-03 内核化改造】按目标"全部基础访问能力走内核"，本文件
 * 已移除全部三环依赖：
 *   - 进程内存读/写      → 0x023 / 0x081（SDK 扩展命令，attach 拷贝）
 *   - 线程枚举           → 0x09A（EPROCESS 线程链，不再用 Toolhelp）
 *   - 进程模块枚举       → 0x09B（PEB→Ldr，不再用 psapi）
 * 保留的内核命令：0xE4 进程列表、0x2A 路径查询、0x27 访问判定。
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
            break;

        Items[n].Eprocess = Eprocess;
        Items[n].Pid = (ULONG)*(const ULONG64 *)(Entry + PROC_PID_OFF);
        memcpy(Items[n].Name, Entry + PROC_NAME_OFF, XPCH_PROC_NAME_CHARS - 1);
        Items[n].Name[XPCH_PROC_NAME_CHARS - 1] = 0;
        n++;

        if (*(const BYTE *)(Entry + PROC_NEXT_OFF) == 0)
            break;
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

    InPid = (ULONG64)Pid;
    ZeroMemory(Out, sizeof(Out));
    St = XpchInvokeRaw(Session, CMD_QUERY_PROCESS_PATH, &InPid, sizeof(InPid),
                       Out, sizeof(Out));
    if (St != XPCH_OK)
        return St;

    {
        const WCHAR *Src = (const WCHAR *)Out;
        for (i = 0; i < (int)PathChars - 1 && i < 260 && Src[i]; i++)
            Path[i] = Src[i];
        Path[i] = 0;
    }
    return XPCH_OK;
}

XPCH_STATUS XpchIsProcessAccessible(XPCH_SESSION *Session, ULONG Pid,
                                    BOOL *Accessible)
{
    XPCH_SESSION_IMPL *Impl;
    ULONG64 In[2];
    BYTE Out[16];
    XPCH_STATUS St;

    if (!Session || !Accessible || !Pid)
        return XPCH_E_INVALID_ARG;
    *Accessible = FALSE;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    /* 0x27 要求 InputSize == 16：{ QWORD PID, QWORD EPROCESS }。
       用返回值表示可访问性（1 = 可访问）；"不可访问"表现为结果字节 0，
       即 XPCH_E_REJECTED —— 有效结论而非错误。 */
    In[0] = (ULONG64)Pid;
    In[1] = 0;
    ZeroMemory(Out, sizeof(Out));
    St = XpchInvokeRaw(Session, CMD_CHECK_PROCESS_ACCESS, In, sizeof(In),
                       Out, sizeof(Out));

    if (St == XPCH_OK) {
        *Accessible = TRUE;
        return XPCH_OK;
    }
    if (St == XPCH_E_REJECTED) {
        *Accessible = FALSE;
        return XPCH_OK;
    }
    return St;
}

/* ============================================================
 * 进程内存读写（内核扩展命令 0x023 / 0x081）
 * ============================================================*/
XPCH_STATUS XpchReadProcessMemory(XPCH_SESSION *Session, ULONG Pid,
                                  ULONG64 Address, ULONG Size,
                                  BYTE **Buffer, ULONG *Read)
{
    XPCH_SESSION_IMPL *Impl;
#pragma pack(push, 1)
    struct {
        ULONG64 Pid;
        ULONG64 Address;
        ULONG   Size;
        ULONG   Pad;
    } Req;
#pragma pack(pop)
    BYTE *Out;
    ULONG OutSize;
    XPCH_STATUS St;
    ULONG64 Copied;
    BYTE *Data;

    if (!Session || !Buffer || !Read)
        return XPCH_E_INVALID_ARG;
    *Buffer = NULL;
    *Read = 0;
    if (!Pid || !Address || !Size)
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    OutSize = sizeof(ULONG64) + Size;
    Out = (BYTE *)XpchAlloc(OutSize);
    if (!Out)
        return XPCH_E_NO_MEMORY;

    ZeroMemory(&Req, sizeof(Req));
    Req.Pid = Pid;
    Req.Address = Address;
    Req.Size = Size;

    St = XpchInvokeRaw(Session, CMD_X_READ_PROC_MEM,
                       &Req, sizeof(Req), Out, OutSize);
    if (St != XPCH_OK) {
        XpchFreeInternal(Out);
        return St;
    }

    Copied = *(ULONG64 *)Out;
    if (Copied == 0) {
        XpchFreeInternal(Out);
        return XPCH_E_ACCESS_DENIED;
    }

    Data = (BYTE *)XpchAlloc((SIZE_T)Copied);
    if (!Data) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_MEMORY;
    }
    memcpy(Data, Out + sizeof(ULONG64), (SIZE_T)Copied);
    XpchFreeInternal(Out);
    *Buffer = Data;
    *Read = (ULONG)Copied;
    return XPCH_OK;
}

XPCH_STATUS XpchWriteProcessMemory(XPCH_SESSION *Session, ULONG Pid,
                                   ULONG64 Address, const void *Data, ULONG Size)
{
    XPCH_SESSION_IMPL *Impl;
    BYTE *In;
    ULONG InSize;
    XPCH_STATUS St;

    if (!Session || !Data || !Size || !Pid || !Address)
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    InSize = 24 + Size;
    In = (BYTE *)XpchAlloc(InSize);
    if (!In)
        return XPCH_E_NO_MEMORY;

    ZeroMemory(In, 24);
    *(ULONG64 *)(In + 0) = Pid;
    *(ULONG64 *)(In + 8) = Address;
    *(ULONG *)(In + 16) = Size;
    memcpy(In + 24, Data, Size);

    St = XpchInvokeRaw(Session, CMD_X_WRITE_PROC_MEM, In, InSize, NULL, 0);
    XpchFreeInternal(In);
    return St;
}

XPCH_STATUS XpchReadKernelMemory(XPCH_SESSION *Session, ULONG64 Address,
                                 ULONG Size, BYTE **Buffer, ULONG *Read)
{
    XPCH_SESSION_IMPL *Impl;
#pragma pack(push, 1)
    struct {
        ULONG64 Address;
        ULONG   Size;
        ULONG   Pad;
    } Req;
#pragma pack(pop)
    BYTE *Out;
    ULONG OutSize;
    XPCH_STATUS St;
    ULONG64 Copied;
    BYTE *Data;

    if (!Session || !Buffer || !Read)
        return XPCH_E_INVALID_ARG;
    *Buffer = NULL;
    *Read = 0;
    if (!Address || !Size)
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    OutSize = sizeof(ULONG64) + Size;
    Out = (BYTE *)XpchAlloc(OutSize);
    if (!Out)
        return XPCH_E_NO_MEMORY;

    ZeroMemory(&Req, sizeof(Req));
    Req.Address = Address;
    Req.Size = Size;

    St = XpchInvokeRaw(Session, CMD_X_READ_KERNEL_MEM,
                       &Req, sizeof(Req), Out, OutSize);
    if (St != XPCH_OK) {
        XpchFreeInternal(Out);
        return St;
    }

    Copied = *(ULONG64 *)Out;
    if (Copied == 0) {
        XpchFreeInternal(Out);
        return XPCH_E_ACCESS_DENIED;
    }

    Data = (BYTE *)XpchAlloc((SIZE_T)Copied);
    if (!Data) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_MEMORY;
    }
    memcpy(Data, Out + sizeof(ULONG64), (SIZE_T)Copied);
    XpchFreeInternal(Out);
    *Buffer = Data;
    *Read = (ULONG)Copied;
    return XPCH_OK;
}

XPCH_STATUS XpchWriteKernelMemory(XPCH_SESSION *Session, ULONG64 Address,
                                  const void *Data, ULONG Size)
{
    XPCH_SESSION_IMPL *Impl;
    BYTE *In;
    ULONG InSize;
    XPCH_STATUS St;

    if (!Session || !Data || !Size || !Address)
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    InSize = 16 + Size;
    In = (BYTE *)XpchAlloc(InSize);
    if (!In)
        return XPCH_E_NO_MEMORY;

    ZeroMemory(In, 16);
    *(ULONG64 *)(In + 0) = Address;
    *(ULONG *)(In + 8) = Size;
    memcpy(In + 16, Data, Size);

    St = XpchInvokeRaw(Session, CMD_X_WRITE_KERNEL_MEM, In, InSize, NULL, 0);
    XpchFreeInternal(In);
    return St;
}

/* ============================================================
 * 线程枚举（0x09A：EPROCESS 线程链，内核视角）
 * ============================================================*/
XPCH_STATUS XpchEnumThreads(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_THREAD_INFO **Threads, ULONG *Count)
{
    XPCH_SESSION_IMPL *Impl;
    ULONG64 InPid;
    BYTE *Out;
    ULONG OutSize = 4 + 4096 * 16;
    XPCH_STATUS St;
    XPCH_THREAD_INFO *Items;
    ULONG i, N;

    if (!Session || !Threads || !Count)
        return XPCH_E_INVALID_ARG;
    *Threads = NULL;
    *Count = 0;
    if (!Pid)
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    Out = (BYTE *)XpchAlloc(OutSize);
    if (!Out)
        return XPCH_E_NO_MEMORY;

    InPid = (ULONG64)Pid;
    St = XpchInvokeRaw(Session, CMD_X_ENUM_PROC_THREADS,
                       &InPid, sizeof(InPid), Out, OutSize);
    if (St == XPCH_E_REJECTED)
        St = XPCH_E_NOT_SUPPORTED;   /* 驱动侧暂禁用 */
    if (St != XPCH_OK) {
        XpchFreeInternal(Out);
        return St;
    }

    N = *(ULONG *)Out;
    if (N == 0) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_DATA;
    }

    Items = (XPCH_THREAD_INFO *)XpchAlloc((SIZE_T)N * sizeof(XPCH_THREAD_INFO));
    if (!Items) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_MEMORY;
    }

    /* 驱动条目 16 字节：{ u32 Tid; u32 Flags; u64 Start; u64 Teb } */
    for (i = 0; i < N; i++) {
        const BYTE *E = Out + 4 + (SIZE_T)i * 16;
        ZeroMemory(&Items[i], sizeof(Items[i]));
        Items[i].Tid = *(const ULONG *)(E + 0);
        Items[i].OwnerPid = Pid;
        Items[i].StartAddress = *(const ULONG64 *)(E + 8);
        Items[i].Teb = *(const ULONG64 *)(E + 16);
    }

    XpchFreeInternal(Out);
    *Threads = Items;
    *Count = N;
    return XPCH_OK;
}

/* ============================================================
 * 进程模块枚举（0x09B：PEB→Ldr，内核视角，可枚举不可访问进程）
 * ============================================================*/
XPCH_STATUS XpchEnumModules(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_MODULE_INFO **Modules, ULONG *Count)
{
    XPCH_SESSION_IMPL *Impl;
    ULONG64 InPid;
    BYTE *Out;
    ULONG OutSize = 4 + 2048 * 80;
    XPCH_STATUS St;
    XPCH_MODULE_INFO *Items;
    ULONG i, N;

    if (!Session || !Modules || !Count)
        return XPCH_E_INVALID_ARG;
    *Modules = NULL;
    *Count = 0;
    if (!Pid)
        return XPCH_E_INVALID_ARG;

    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    Out = (BYTE *)XpchAlloc(OutSize);
    if (!Out)
        return XPCH_E_NO_MEMORY;

    InPid = (ULONG64)Pid;
    St = XpchInvokeRaw(Session, CMD_X_ENUM_PROC_MODULES,
                       &InPid, sizeof(InPid), Out, OutSize);
    if (St == XPCH_E_REJECTED)
        St = XPCH_E_NOT_SUPPORTED;   /* 驱动侧暂禁用 */
    if (St != XPCH_OK) {
        XpchFreeInternal(Out);
        return St;
    }

    N = *(ULONG *)Out;
    if (N == 0) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_DATA;
    }

    Items = (XPCH_MODULE_INFO *)XpchAlloc((SIZE_T)N * sizeof(XPCH_MODULE_INFO));
    if (!Items) {
        XpchFreeInternal(Out);
        return XPCH_E_NO_MEMORY;
    }

    /* 驱动条目 80 字节：{ u64 Base; u32 SizeOfImage; WCHAR Name[32] } */
    for (i = 0; i < N; i++) {
        const BYTE *E = Out + 4 + (SIZE_T)i * 80;
        ZeroMemory(&Items[i], sizeof(Items[i]));
        Items[i].Base = *(const ULONG64 *)(E + 0);
        Items[i].Size = *(const ULONG *)(E + 8);
        memcpy(Items[i].Name, E + 16, 32 * sizeof(WCHAR));
        Items[i].Name[XPCH_MOD_NAME_CHARS - 1] = 0;
    }

    XpchFreeInternal(Out);
    *Modules = Items;
    *Count = N;
    return XPCH_OK;
}