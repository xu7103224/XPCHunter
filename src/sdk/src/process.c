/* ============================================================================
 * process.c —— 进程 / 线程 / 进程内存读写 / 进程模块
 *
 * 【2026-11-03 内核化改造】按目标"全部基础访问能力走内核"，本文件
 * 已移除全部三环依赖：
 *   - 进程内存读/写      → 0x023 / 0x081（SDK 扩展命令，attach 拷贝）
 *   - 线程枚举           → SDK 侧 EPROCESS→ThreadListHead 遍历（经 0x099）
 *   - 进程模块枚举       → SDK 侧 EPROCESS→PEB→Ldr 遍历（0x099 + 0x023）
 * 【2026-11-01 稳定性改造】0x09A/0x09B 驱动命令因 attach 后用户态访问
 * 蓝屏(0x3B)已删除；遍历全部改到 SDK 侧，驱动只提供逐次安全读原语，
 * 单次读失败仅返回错误码。偏移量为 Win10 18362 x64 实机 kd 核实值。
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
 * 内核结构偏移（Win10 18362 x64，2026-11-01 实机 kd `dt` 核实）
 *
 * 线程/模块遍历全部在 SDK 侧完成：
 *   内核内存（EPROCESS/ETHREAD/PEB 指针）经 0x099 读；
 *   目标进程用户内存（PEB→Ldr 链）经 0x023 读。
 * 驱动只提供逐次安全读原语，不做任何用户态内存访问，
 * 因此单次读失败只是返回错误，不会蓝屏（0x09A/0x09B 的教训）。
 * ============================================================*/
#define XPCH_OFF_KPROC_THREADLISTHEAD   0x030u  /* _KPROCESS.ThreadListHead */
#define XPCH_OFF_KTHREAD_LISTENTRY      0x2F8u  /* _KTHREAD.ThreadListEntry */
#define XPCH_OFF_KTHREAD_TEB            0x0F0u  /* _KTHREAD.Teb */
#define XPCH_OFF_KTHREAD_BASEPRIO       0x233u  /* _KTHREAD.BasePriority (CHAR) */
#define XPCH_OFF_ETHREAD_CID            0x648u  /* _ETHREAD.Cid（+0 UniqueProcess, +8 UniqueThread） */
#define XPCH_OFF_ETHREAD_WIN32START     0x6A0u  /* _ETHREAD.Win32StartAddress */
#define XPCH_OFF_EPROC_PEB              0x3F8u  /* _EPROCESS.Peb */
#define XPCH_OFF_PEB_LDR                0x018u  /* _PEB.Ldr */
#define XPCH_OFF_LDR_INLOADLIST         0x010u  /* _PEB_LDR_DATA.InLoadOrderModuleList */
#define XPCH_OFF_LDRE_BLOCK             0x000u  /* 条目头：InLoadOrderLinks @0 */
#define XPCH_OFF_LDRE_DLLBASE           0x030u
#define XPCH_OFF_LDRE_SIZEOFIMAGE       0x040u
#define XPCH_OFF_LDRE_FULLDLLNAME       0x048u  /* UNICODE_STRING（Len@0, Buf@8） */
#define XPCH_OFF_LDRE_BASEDLLNAME       0x058u
#define XPCH_LDRE_BLOCK_SIZE            0x68u   /* 头到 BaseDllName 结束的整块 */
#define XPCH_WALK_MAX                   4096u   /* 链表环路保险 */
#define XPCH_BUILD_1903                 18362u  /* 已核实的唯一构建 */

/* 按构建号放行。构建号在握手时取回并缓存；没有偏移表的构建不支持。 */
static XPCH_STATUS XpProcBuildGate(XPCH_SESSION *Session)
{
    XPCH_SESSION_IMPL *Impl = XPCH_IMPL(Session);
    XPCH_STATUS St;

    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;
    if (Impl->Build == 0) {
        ULONG Build = 0;
        St = XpchGetBuildNumber(Session, &Build);
        if (St != XPCH_OK || Build == 0)
            return XPCH_E_NOT_SUPPORTED;
        Impl->Build = Build;
    }
    if (Impl->Build != XPCH_BUILD_1903)
        return XPCH_E_NOT_SUPPORTED;
    return XPCH_OK;
}

/* 一次安全读：内核地址走 0x099，用户地址（目标进程）走 0x023。
   任何失败都只返回错误码，绝不崩溃。 */
static XPCH_STATUS XpProcRead(XPCH_SESSION *Session, ULONG Pid,
                              ULONG64 Address, BOOL Kernel,
                              void *Out, ULONG Size)
{
    XPCH_STATUS St;
    BYTE *Buf = NULL;
    ULONG Got = 0;

    if (Kernel)
        St = XpchReadKernelMemory(Session, Address, Size, &Buf, &Got);
    else
        St = XpchReadProcessMemory(Session, Pid, Address, Size, &Buf, &Got);
    if (St != XPCH_OK)
        return St;
    if (Got != Size) {
        XpchFreeInternal(Buf);
        return XPCH_E_BAD_RESPONSE;
    }
    memcpy(Out, Buf, Size);
    XpchFreeInternal(Buf);
    return XPCH_OK;
}

/* 从进程枚举结果里找 EPROCESS 地址 */
static XPCH_STATUS XpProcFindEprocess(XPCH_SESSION *Session, ULONG Pid,
                                      ULONG64 *Eprocess)
{
    XPCH_PROCESS_INFO *Procs = NULL;
    ULONG N = 0, i;
    XPCH_STATUS St;

    *Eprocess = 0;
    St = XpchEnumProcesses(Session, &Procs, &N);
    if (St != XPCH_OK)
        return St;
    for (i = 0; i < N; i++) {
        if (Procs[i].Pid == Pid) {
            *Eprocess = Procs[i].Eprocess;
            break;
        }
    }
    XpchFreeInternal(Procs);
    if (!*Eprocess)
        return XPCH_E_NOT_FOUND;
    return XPCH_OK;
}

/* ============================================================
 * 线程枚举：SDK 侧走 EPROCESS→ThreadListHead→ETHREAD
 * （驱动只提供 0x099 内核读；本函数不碰任何用户态内存）
 * ============================================================*/
XPCH_STATUS XpchEnumThreads(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_THREAD_INFO **Threads, ULONG *Count)
{
    XPCH_STATUS St;
    ULONG64 Eproc = 0, Node = 0, HeadAddr;
    XPCH_THREAD_INFO *Items = NULL, *Grown;
    ULONG N = 0, Cap = 0;
    BYTE Head[8];

    if (!Session || !Threads || !Count)
        return XPCH_E_INVALID_ARG;
    *Threads = NULL;
    *Count = 0;
    if (!Pid)
        return XPCH_E_INVALID_ARG;

    St = XpProcBuildGate(Session);
    if (St != XPCH_OK)
        return St;

    St = XpProcFindEprocess(Session, Pid, &Eproc);
    if (St != XPCH_OK)
        return St;

    /* KPROCESS.ThreadListHead.Flink = 第一个线程的 KTHREAD.ThreadListEntry */
    HeadAddr = Eproc + XPCH_OFF_KPROC_THREADLISTHEAD;
    St = XpProcRead(Session, Pid, HeadAddr, TRUE, Head, sizeof(Head));
    if (St != XPCH_OK)
        return St;
    Node = *(ULONG64 *)Head;

    while (Node != HeadAddr && N < XPCH_WALK_MAX) {
        ULONG64 Ethread = Node - XPCH_OFF_KTHREAD_LISTENTRY;
        BYTE Cid[16];               /* { UniqueProcess, UniqueThread } */
        ULONG64 Start = 0, Teb = 0, Next = 0;
        BYTE Prio = 0;
        XPCH_THREAD_INFO *Slot;

        /* Flink 节点读不到 = 链上有悬空指针，到这里为止 */
        St = XpProcRead(Session, Pid, Node, TRUE, &Next, sizeof(Next));
        if (St != XPCH_OK)
            break;

        if (XpProcRead(Session, Pid, Ethread + XPCH_OFF_ETHREAD_CID,
                       TRUE, Cid, sizeof(Cid)) != XPCH_OK)
            break;
        if (*(ULONG64 *)(Cid + 0) != (ULONG64)Pid) {
            /* 归属校验失败：链已损坏，停止（不记录脏条目） */
            break;
        }

        /* Win32StartAddress / Teb / BasePriority 读失败不致命，留 0 */
        (void)XpProcRead(Session, Pid, Ethread + XPCH_OFF_ETHREAD_WIN32START,
                         TRUE, &Start, sizeof(Start));
        (void)XpProcRead(Session, Pid, Ethread + XPCH_OFF_KTHREAD_TEB,
                         TRUE, &Teb, sizeof(Teb));
        (void)XpProcRead(Session, Pid, Ethread + XPCH_OFF_KTHREAD_BASEPRIO,
                         TRUE, &Prio, 1);

        if (N == Cap) {
            Cap = Cap ? Cap * 2 : 16;
            Grown = (XPCH_THREAD_INFO *)XpchAlloc(
                (SIZE_T)Cap * sizeof(XPCH_THREAD_INFO));
            if (!Grown) {
                XpchFreeInternal(Items);
                return XPCH_E_NO_MEMORY;
            }
            if (Items) {
                memcpy(Grown, Items, (SIZE_T)N * sizeof(XPCH_THREAD_INFO));
                XpchFreeInternal(Items);
            }
            Items = Grown;
        }
        Slot = &Items[N++];
        ZeroMemory(Slot, sizeof(*Slot));
        Slot->Tid          = (ULONG)*(ULONG64 *)(Cid + 8);
        Slot->OwnerPid     = Pid;
        Slot->BasePriority = (ULONG)(LONG)(signed char)Prio;
        Slot->StartAddress = Start;
        Slot->Teb          = Teb;

        Node = Next;
    }

    if (N == 0) {
        XpchFreeInternal(Items);
        return XPCH_E_NO_DATA;
    }
    *Threads = Items;
    *Count = N;
    return XPCH_OK;
}

/* ============================================================
 * 进程模块枚举：SDK 侧走 EPROCESS→PEB→Ldr→InLoadOrderModuleList
 * （EPROCESS.Peb 经 0x099 内核读；Ldr 链是目标进程用户内存，经 0x023 读。
 *   每一步都是独立的安全读，读不到即停，不蓝屏。）
 * ============================================================*/
XPCH_STATUS XpchEnumModules(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_MODULE_INFO **Modules, ULONG *Count)
{
    XPCH_STATUS St;
    ULONG64 Eproc = 0, Peb = 0, Ldr = 0, Node = 0, HeadAddr = 0;
    XPCH_MODULE_INFO *Items = NULL, *Grown;
    ULONG N = 0, Cap = 0;
    BYTE Head[8];

    if (!Session || !Modules || !Count)
        return XPCH_E_INVALID_ARG;
    *Modules = NULL;
    *Count = 0;
    if (!Pid)
        return XPCH_E_INVALID_ARG;

    St = XpProcBuildGate(Session);
    if (St != XPCH_OK)
        return St;

    St = XpProcFindEprocess(Session, Pid, &Eproc);
    if (St != XPCH_OK)
        return St;

    /* System 等无 PEB 进程：读不到就返回空 */
    if (XpProcRead(Session, Pid, Eproc + XPCH_OFF_EPROC_PEB, TRUE,
                   &Peb, sizeof(Peb)) != XPCH_OK || !Peb)
        return XPCH_E_NO_DATA;
    if (XpProcRead(Session, Pid, Peb + XPCH_OFF_PEB_LDR, FALSE,
                   &Ldr, sizeof(Ldr)) != XPCH_OK || !Ldr)
        return XPCH_E_NO_DATA;

    HeadAddr = Ldr + XPCH_OFF_LDR_INLOADLIST;
    St = XpProcRead(Session, Pid, HeadAddr, FALSE, Head, sizeof(Head));
    if (St != XPCH_OK)
        return XPCH_E_NO_DATA;
    Node = *(ULONG64 *)Head;

    while (Node != HeadAddr && N < XPCH_WALK_MAX) {
        BYTE Block[XPCH_LDRE_BLOCK_SIZE];       /* 0x00..0x67 整块 */
        ULONG64 Next = 0, FullBuf = 0, BaseBuf = 0;
        ULONG FullLen, BaseLen, CopyLen;
        XPCH_MODULE_INFO *Slot;

        /* Flink 读不到 = 链上有悬空指针（DLL 正在卸载等），到此为止 */
        St = XpProcRead(Session, Pid, Node, FALSE, Block, sizeof(Block));
        if (St != XPCH_OK)
            break;
        Next = *(ULONG64 *)(Block + XPCH_OFF_LDRE_BLOCK);

        if (N == Cap) {
            Cap = Cap ? Cap * 2 : 16;
            Grown = (XPCH_MODULE_INFO *)XpchAlloc(
                (SIZE_T)Cap * sizeof(XPCH_MODULE_INFO));
            if (!Grown) {
                XpchFreeInternal(Items);
                return XPCH_E_NO_MEMORY;
            }
            if (Items) {
                memcpy(Grown, Items, (SIZE_T)N * sizeof(XPCH_MODULE_INFO));
                XpchFreeInternal(Items);
            }
            Items = Grown;
        }
        Slot = &Items[N++];
        ZeroMemory(Slot, sizeof(*Slot));
        Slot->Base = *(ULONG64 *)(Block + XPCH_OFF_LDRE_DLLBASE);
        Slot->Size = *(ULONG *)(Block + XPCH_OFF_LDRE_SIZEOFIMAGE);

        /* FullDllName = Path，BaseDllName = Name。长度异常按 0 处理。 */
        FullLen = *(USHORT *)(Block + XPCH_OFF_LDRE_FULLDLLNAME);
        BaseLen = *(USHORT *)(Block + XPCH_OFF_LDRE_BASEDLLNAME);
        FullBuf = *(ULONG64 *)(Block + XPCH_OFF_LDRE_FULLDLLNAME + 8);
        BaseBuf = *(ULONG64 *)(Block + XPCH_OFF_LDRE_BASEDLLNAME + 8);

        if (FullLen & 1)
            FullLen = 0;
        if (BaseLen & 1)
            BaseLen = 0;

        CopyLen = FullLen;
        if (CopyLen > (XPCH_MOD_PATH_CHARS - 1) * 2)
            CopyLen = (XPCH_MOD_PATH_CHARS - 1) * 2;
        if (CopyLen && FullBuf)
            (void)XpProcRead(Session, Pid, FullBuf, FALSE,
                             Slot->Path, CopyLen);

        CopyLen = BaseLen;
        if (CopyLen > (XPCH_MOD_NAME_CHARS - 1) * 2)
            CopyLen = (XPCH_MOD_NAME_CHARS - 1) * 2;
        if (CopyLen && BaseBuf)
            (void)XpProcRead(Session, Pid, BaseBuf, FALSE,
                             Slot->Name, CopyLen);

        Node = Next;
    }

    if (N == 0) {
        XpchFreeInternal(Items);
        return XPCH_E_NO_DATA;
    }
    *Modules = Items;
    *Count = N;
    return XPCH_OK;
}