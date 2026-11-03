/* ============================================================================
 * XpchExtensions.c — SDK 扩展命令（占用原版空槽，文档化偏离）
 *
 * 【为什么存在】
 * 需求：SDK 的全部基础访问能力必须走内核，不允许回退到三环 API
 * （Toolhelp / psapi / SCM / ReadProcessMemory / OpenProcess）。
 * 原版 249 条命令里缺少"语义干净的通用读写原语"：
 *   - 0xFB 名为 CmdWriteKernelMemoryRange，实际是句柄表追加，不是内核写；
 *   - 0x5A 读引擎依赖内部句柄/挂钩状态，不适合作为通用读接口；
 *   - 每进程模块/线程映射没有命令（前端一直用 psapi/Toolhelp）。
 * 因此在【原版同样为空的槽位】上补一组自有命令，原则与 0x13A 一致：
 * 原版前端从不发送这些命令号，占用它们不影响任何原版行为的复现。
 *
 * 【命令与入出参】（全部走标准 0x30 字节加密请求）
 *   0x023  读指定进程内存
 *          In  : { u64 Pid; u64 Address; u32 Size; u32 Pad }        (24B)
 *          Out : { u64 Copied; BYTE Data[Size] }                    (8+Size)
 *   0x081  写指定进程内存
 *          In  : { u64 Pid; u64 Address; u32 Size; u32 Pad;
 *                  BYTE Data[Size] }                                (24+Size)
 *   0x082  写内核虚拟内存（复用 WritePhysicalMemoryBuffer 的 MDL 映射）
 *          In  : { u64 Address; u32 Size; u32 Pad; BYTE Data[Size] }(16+Size)
 *   0x089  读内核虚拟内存
 *          In  : { u64 Address; u32 Size; u32 Pad }                 (16B)
 *          Out : { u64 Copied; BYTE Data[Size] }                    (8+Size)
 *   0x08C  枚举内核模块（从本驱动 DriverSection 沿 InLoadOrderLinks 遍历）
 *          In  : 无
 *          Out : { u32 Count; { u64 Base; u32 SizeOfImage;
 *                              CHAR Name[64] } [] }                  (80B/条)
 *
 * 【实现风格】与本工程一致：__try + MmIsAddressValid + 逐页推进。
 * 【2026-11-01】0x08A/0x08B（枚举进程线程/模块）删除：attach 后访问
 * 用户态内存在 18362 实机蓝屏(0x3B)，MmIsAddressValid 对用户地址不可靠。
 * 两项遍历改由 SDK 侧经 0x099/0x023 逐次安全读完成，驱动只做内核读。
 * 【2026-11-03】0x09A 重新启用为「Token 特权调整」（提权/降权/查询），
 * 0x09B 重新启用为「进程原语子命令」（分配/释放/改保护/远程线程，
 * 供 SDK 侧注入映射 PE 使用）。两者均只用导出 API，零结构偏移。
 * ==========================================================================*/
#include "..\inc\XPCHunterDrv.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE          0x0001
#define PROCESS_CREATE_THREAD      0x0002
#define PROCESS_VM_OPERATION       0x0008
#define PROCESS_QUERY_INFORMATION  0x0400
#define THREAD_ALL_ACCESS          0x1FFFFF
#endif
#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#endif


/* 内部原语（MemoryOps.c） */
extern char WritePhysicalMemoryBuffer(unsigned __int64 TargetAddress,
                                      const void *SourceBuffer,
                                      unsigned int BufferSize,
                                      char ProcessorMode, void *pReadBack);

/* 驱动全局对象（DriverEntry.c） */
extern PDRIVER_OBJECT g_DriverObject;

/* ------------------------------------------------------------------ */
/* 内部工具                                                            */
/* ------------------------------------------------------------------ */

/* 跨进程内存拷贝：MmCopyVirtualMemory（ntoskrnl 导出，ntoskrnl.lib 链接）。
 * 正确处理跨页、demand paging、访问权限 —— 不用 attach+memcpy
 * （大块 memcpy 的 rep movsb 跨无效页时 x64 SEH 无法恢复，会蓝屏）。 */
extern NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

static BOOLEAN XpAttachCopy(PKPROCESS Target, void *DstUser,
                            const void *SrcUser, SIZE_T Size)
{
    PSIZE_T ReturnSize;
    SIZE_T Got = 0;
    NTSTATUS Status;

    if (!Target || !DstUser || !SrcUser || !Size)
        return FALSE;

    /* SrcUser 是目标进程的用户态地址，DstUser 是调用方进程的用户态地址。
       MmCopyVirtualMemory 从当前进程上下文调用即可正确处理跨进程。 */
    ReturnSize = &Got;
    Status = MmCopyVirtualMemory(
        (PEPROCESS)Target,          /* SourceProcess（目标进程） */
        (PVOID)SrcUser,             /* SourceAddress */
        IoGetCurrentProcess(),      /* TargetProcess（调用方） */
        DstUser,                    /* TargetAddress */
        Size,                       /* BufferSize */
        KernelMode,                 /* PreviousMode */
        &Got);                      /* ReturnSize */

    return Status >= 0 && Got == Size;
}

/* 内核地址安全读：按页推进，失败即停，返回已拷贝字节数 */
static SIZE_T XpKernelCopyOut(void *DstUser, const void *KernelAddr, SIZE_T Size)
{
    SIZE_T Done = 0;
    SIZE_T Chunk;
    const UCHAR *Src = (const UCHAR *)KernelAddr;
    UCHAR *Dst = (UCHAR *)DstUser;

    __try {
        while (Done < Size) {
            ULONG64 PageEnd = (((ULONG64)(ULONG_PTR)(Src + Done)) | 0xFFF) + 1;
            Chunk = (SIZE_T)(PageEnd - (ULONG64)(ULONG_PTR)(Src + Done));
            if (Chunk > Size - Done)
                Chunk = Size - Done;

            if (MmIsAddressValid(Src + Done) != 1)
                break;
            if (MmIsAddressValid(Src + Done + Chunk - 1) != 1)
                break;

            __try {
                memcpy(Dst + Done, Src + Done, Chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }
            Done += Chunk;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* 返回已完成部分 */
    }
    return Done;
}

/* 内核地址安全写（复用工程的物理映射写原语，支持只读页绕过） */
static BOOLEAN XpKernelWrite(unsigned __int64 Address, const void *Data, unsigned int Size)
{
    if (!Address || !Data || !Size)
        return FALSE;
    if (Address < (unsigned __int64)MmSystemRangeStart)
        return FALSE;
    if (MmIsAddressValid((PVOID)Address) != 1)
        return FALSE;
    if (MmIsAddressValid((PVOID)(Address + Size - 1)) != 1)
        return FALSE;
    return WritePhysicalMemoryBuffer(Address, Data, Size, 0, NULL) == 1;
}

#pragma pack(push, 1)
typedef struct _XPCH_RW_PROC_REQ {
    unsigned __int64 Pid;
    unsigned __int64 Address;
    unsigned int     Size;
    unsigned int     Pad;
} XPCH_RW_PROC_REQ;

typedef struct _XPCH_WRITE_KERN_REQ {
    unsigned __int64 Address;
    unsigned int     Size;
    unsigned int     Pad;
    /* BYTE Data[];  紧随其后 */
} XPCH_WRITE_KERN_REQ;
#pragma pack(pop)

/* ============================================================
 * 0x023  读指定进程内存
 * ============================================================*/
__int64 CmdXpchReadProcessMemory(void *InputBuffer, int InputSize,
                                 void *OutputBuffer, unsigned int OutputSize)
{
    XPCH_RW_PROC_REQ Req;
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    unsigned __int64 Want;
    SIZE_T Got = 0;
    unsigned __int64 *OutHdr;

    if (!InputBuffer || InputSize != (int)sizeof(Req))
        return 0;
    if (!OutputBuffer || OutputSize < sizeof(unsigned __int64) + 1)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)OutputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, sizeof(Req), 1);
    ProbeForWrite(OutputBuffer, OutputSize, 1);
    memcpy(&Req, InputBuffer, sizeof(Req));

    if (!Req.Pid || !Req.Address || !Req.Size)
        return 0;
    Want = sizeof(unsigned __int64) + (unsigned __int64)Req.Size;
    if (Want > OutputSize)
        return 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req.Pid, &Process);
    if (Status < 0 || !Process)
        return 0;

    OutHdr = (unsigned __int64 *)OutputBuffer;
    if (XpAttachCopy((PKPROCESS)Process,
                     (void *)(OutHdr + 1),
                     (const void *)(ULONG_PTR)Req.Address,
                     Req.Size))
        Got = Req.Size;

    __try {
        *OutHdr = (unsigned __int64)Got;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Got = 0;
    }

    ObfDereferenceObject(Process);
    return Got != 0;
}

/* ============================================================
 * 0x081  写指定进程内存
 * ============================================================*/
__int64 CmdXpchWriteProcessMemory(void *InputBuffer, int InputSize,
                                  void *OutputBuffer, unsigned int OutputSize)
{
    XPCH_RW_PROC_REQ Req;
    unsigned int Size;
    void *DataUser;
    PEPROCESS Process = NULL;
    NTSTATUS Status;
    BOOLEAN Ok;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputSize);

    if (!InputBuffer || InputSize < (int)sizeof(Req))
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, (unsigned int)InputSize, 1);
    memcpy(&Req, InputBuffer, sizeof(Req));

    Size = Req.Size;
    if (!Req.Pid || !Req.Address || !Size)
        return 0;
    if (InputSize < (int)(sizeof(Req) + (int)Size))
        return 0;

    DataUser = (void *)((char *)InputBuffer + sizeof(Req));
    if ((unsigned __int64)DataUser >= MmUserProbeAddress)
        return 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req.Pid, &Process);
    if (Status < 0 || !Process)
        return 0;

    {
        SIZE_T Got = 0;
        NTSTATUS MmSt = MmCopyVirtualMemory(
            IoGetCurrentProcess(),      /* SourceProcess（调用方） */
            DataUser,                   /* SourceAddress */
            Process,                    /* TargetProcess（目标） */
            (PVOID)(ULONG_PTR)Req.Address,
            Size, KernelMode, &Got);
        Ok = (MmSt >= 0 && Got == Size);
    }

    ObfDereferenceObject(Process);
    return Ok;
}

/* ============================================================
 * 0x082  写内核虚拟内存
 * ============================================================*/
__int64 CmdXpchWriteKernelMemory(void *InputBuffer, int InputSize,
                                 void *OutputBuffer, unsigned int OutputSize)
{
    XPCH_WRITE_KERN_REQ Req;
    unsigned int Size;
    const void *DataUser;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputSize);

    if (!InputBuffer || InputSize < (int)sizeof(Req))
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, (unsigned int)InputSize, 1);
    memcpy(&Req, InputBuffer, sizeof(Req));

    Size = Req.Size;
    if (!Req.Address || !Size)
        return 0;
    if (InputSize < (int)(sizeof(Req) + (int)Size))
        return 0;

    DataUser = (const void *)((char *)InputBuffer + sizeof(Req));
    if ((unsigned __int64)DataUser >= MmUserProbeAddress)
        return 0;

    return XpKernelWrite(Req.Address, DataUser, Size);
}

/* ============================================================
 * 0x089  读内核虚拟内存
 * ============================================================*/
__int64 CmdXpchReadKernelMemory(void *InputBuffer, int InputSize,
                                void *OutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 Address;
    unsigned int Size;
    SIZE_T Got;
    unsigned __int64 *OutHdr;

    if (!InputBuffer || InputSize != 16)
        return 0;
    if (!OutputBuffer || OutputSize < sizeof(unsigned __int64) + 1)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)OutputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, 16, 1);
    ProbeForWrite(OutputBuffer, OutputSize, 1);

    Address = *(unsigned __int64 *)InputBuffer;
    Size    = *(unsigned int *)((char *)InputBuffer + 8);

    if (!Address || !Size)
        return 0;
    if (sizeof(unsigned __int64) + (unsigned __int64)Size > OutputSize)
        return 0;
    if (Address < (unsigned __int64)MmSystemRangeStart)
        return 0;

    OutHdr = (unsigned __int64 *)OutputBuffer;
    Got = XpKernelCopyOut((void *)(OutHdr + 1),
                          (const void *)(ULONG_PTR)Address, Size);
    __try {
        *OutHdr = (unsigned __int64)Got;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Got = 0;
    }
    return Got != 0;
}

/* ============================================================
 * 0x08C  枚举内核模块
 *
 * 从本驱动自身的 DriverObject->DriverSection（KLDR_DATA_TABLE_ENTRY）
 * 沿 InLoadOrderLinks 遍历，收集全部已加载内核模块。
 * 输出条目 80 字节：{ u64 Base; u32 SizeOfImage; CHAR Name[64] }
 * ============================================================*/
__int64 CmdXpchEnumKernelModules(void *InputBuffer, int InputSize,
                                 void *OutputBuffer, unsigned int OutputSize)
{
    PLIST_ENTRY Head, Entry;
    unsigned int Count = 0, MaxCount;
    char *Cursor;
    ULONG64 EntryBase;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputSize);

    if (!OutputBuffer || OutputSize < 4 + 80)
        return 0;
    if ((unsigned __int64)OutputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(OutputBuffer, OutputSize, 1);
    __try { *(unsigned int *)OutputBuffer = 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    if (!g_DriverObject || !g_DriverObject->DriverSection)
        return 0;
    EntryBase = (ULONG64)(ULONG_PTR)g_DriverObject->DriverSection;
    if (EntryBase <= (unsigned __int64)MmSystemRangeStart)
        return 0;
    Head = (PLIST_ENTRY)(ULONG_PTR)EntryBase;      /* InLoadOrderLinks @0 */
    if (MmIsAddressValid(Head->Flink) != 1)
        return 0;

    Count = 0;
    MaxCount = (OutputSize - 4) / 80;
    Cursor = (char *)OutputBuffer + 4;

    /* KLDR_DATA_TABLE_ENTRY x64（18362 实机 kd `dt nt!_KLDR_DATA_TABLE_ENTRY`
       核实；此前误用 +0x38/+0x48/+0x60/+0x68，读到 EntryPoint/Flags 等
       邻近字段当字符串指针，曾在实机蓝屏 0x3B）：
       +0x30 DllBase  +0x40 SizeOfImage
       +0x58 BaseDllName.Length  +0x60 BaseDllName.Buffer */
    Entry = Head->Flink;
    while (Entry && Entry != Head) {
        ULONG64 Base = (ULONG64)(ULONG_PTR)Entry;
        ULONG64 DllBase, NameBuf, Next = 0;
        ULONG SizeOfImage;
        USHORT NameLen, i;
        ULONG64 *Q;
        char *OutName;
        WCHAR *NameSrc;

        if (Base <= (unsigned __int64)MmSystemRangeStart)
            break;
        if (Count >= MaxCount)
            break;
        if (MmIsAddressValid((PVOID)Base) != 1 ||
            MmIsAddressValid((PVOID)(Base + 0x60)) != 1)
            break;

        /* 一次读出全部字段含 Flink；链上出现坏节点即停（带已收集数据） */
        __try {
            DllBase     = *(ULONG64 *)(ULONG_PTR)(Base + 0x30);
            SizeOfImage = *(ULONG *)(ULONG_PTR)(Base + 0x40);
            NameLen     = *(USHORT *)(ULONG_PTR)(Base + 0x58);
            NameBuf     = *(ULONG64 *)(ULONG_PTR)(Base + 0x60);
            Next        = (ULONG64)(ULONG_PTR)Entry->Flink;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        if (!Next || MmIsAddressValid((PVOID)Next) != 1)
            break;

        if (!DllBase || DllBase < (unsigned __int64)MmSystemRangeStart)
            goto NextEntry;
        /* 名字缓冲必须是可读的内核地址，否则跳过（不盲解引用） */
        if (!NameLen || NameBuf < (unsigned __int64)MmSystemRangeStart)
            goto NextEntry;
        if (MmIsAddressValid((PVOID)NameBuf) != 1 ||
            MmIsAddressValid((PVOID)((char *)(ULONG_PTR)NameBuf + NameLen - 1)) != 1)
            goto NextEntry;

        Q = (ULONG64 *)Cursor;
        Q[0] = DllBase;
        ((unsigned int *)Cursor)[2] = SizeOfImage;
        OutName = Cursor + 16;
        __try {
            USHORT k2, LastSep = 0;
            NameSrc = (WCHAR *)(ULONG_PTR)NameBuf;
            for (k2 = 0; k2 < NameLen; k2++)
                if (NameSrc[k2] == L'\\') LastSep = k2 + 1;
            if (NameLen - LastSep > 63) NameLen = LastSep + 63;
            for (i = LastSep; i < NameLen; i++)
                OutName[i - LastSep] = (char)NameSrc[i];
            OutName[NameLen - LastSep] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            goto NextEntry;
        }
        Cursor += 80;
        Count++;

    NextEntry:
        Entry = (PLIST_ENTRY)(ULONG_PTR)Next;
    }

    __try { *(unsigned int *)OutputBuffer = Count; }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    return Count != 0;
}

/* ============================================================
 * 0x09A  调整指定进程 Token 特权（提权/降权/查询）
 *
 * 【跨版本兼容】全程只用导出 API，零结构偏移：
 *   PsLookupProcessByProcessId → PsReferencePrimaryToken →
 *   ObOpenObjectByPointer(SeTokenObjectType) →
 *   ZwQueryInformationToken(TokenPrivileges) → 改 Attributes →
 *   ZwSetInformationToken(TokenPrivileges)。
 *   这些符号从 Vista 起稳定导出（18362 实机 x nt! 已核实），
 *   任何构建无需偏移表，ntifs.h 直接提供声明。
 *
 *   In  : { u64 Pid; u32 Mode; u32 Pad }                     (16B)
 *         Mode: 0=全部启用  1=全部禁用  2=仅查询
 *   Out : { u32 PrivCount; u32 EnabledCount; }               (8B)
 *         PrivCount=Token 内特权总数；EnabledCount=含 ENABLED 属性的条数
 *         （0/1 模式返回调整后的值，2 模式返回调整前的值）
 * ============================================================*/
typedef struct _XPCH_TOKEN_REQ {
    unsigned __int64 Pid;
    unsigned int     Mode;
    unsigned int     Pad;
} XPCH_TOKEN_REQ;

__int64 CmdXpchAdjustTokenPrivileges(void *InputBuffer, int InputSize,
                                     void *OutputBuffer, unsigned int OutputSize)
{
    XPCH_TOKEN_REQ Req;
    PEPROCESS Process = NULL;
    HANDLE TokenHandle = NULL;
    unsigned char *Buf = NULL;
    unsigned long Len = 0;
    unsigned int PrivCount = 0, EnabledCount = 0;
    unsigned int i;
    NTSTATUS Status;
    BOOLEAN Ok = FALSE;
    PTOKEN_PRIVILEGES Tp;

    if (!InputBuffer || InputSize != (int)sizeof(Req))
        return 0;
    if (!OutputBuffer || OutputSize < 8)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)OutputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, sizeof(Req), 1);
    memcpy(&Req, InputBuffer, sizeof(Req));
    ProbeForWrite(OutputBuffer, 8, 1);
    if (!Req.Pid || Req.Mode > 2)
        return 0;

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req.Pid, &Process);
    if (Status < 0 || !Process)
        return 0;

    /* 取 Token 句柄：ZwOpenProcess + ZwOpenProcessTokenEx。
       两者都是稳定导出，KernelMode 下不做访问检查，受保护进程同样适用。
       （不用 ObOpenObjectByPointer+SeTokenObjectType：内核里 SeTokenObjectType
         是“对象类型指针的地址”，直接当类型传入会返回
         STATUS_OBJECT_TYPE_MISMATCH=0xC0000024，实机已验证。） */
    {
        HANDLE ProcessHandle = NULL;
        OBJECT_ATTRIBUTES ObjAttr;
        CLIENT_ID Cid;
        InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        Cid.UniqueProcess = (HANDLE)(ULONG_PTR)Req.Pid;
        Cid.UniqueThread = NULL;
        Status = ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_INFORMATION,
                               &ObjAttr, &Cid);
        if (Status >= 0 && ProcessHandle) {
            HANDLE h = NULL;
            Status = ZwOpenProcessTokenEx(ProcessHandle,
                                          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                          OBJ_KERNEL_HANDLE, &h);
            if (Status >= 0)
                TokenHandle = h;
            ZwClose(ProcessHandle);
        }
    }
    if (!TokenHandle)
        goto Cleanup;

    /* 定长预查询：不同构建返回 STATUS_BUFFER_TOO_SMALL /
       STATUS_INFO_LENGTH_MISMATCH / STATUS_BUFFER_OVERFLOW 不等，
       因此不校验状态码，只认它带回的长度。 */
    Status = ZwQueryInformationToken(TokenHandle, TokenPrivileges, NULL, 0, &Len);
    if (!Len || Len > 0x100000)
        goto Cleanup;
    Buf = (unsigned char *)ExAlloc(PagedPool, Len);
    if (!Buf)
        goto Cleanup;
    Status = ZwQueryInformationToken(TokenHandle, TokenPrivileges, Buf, Len, &Len);
    if (Status < 0)
        goto Cleanup;

    Tp = (PTOKEN_PRIVILEGES)Buf;
    PrivCount = Tp->PrivilegeCount;
    if (PrivCount > (Len - FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges))
                     / sizeof(LUID_AND_ATTRIBUTES))
        PrivCount = (unsigned int)((Len - FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges))
                                   / sizeof(LUID_AND_ATTRIBUTES));

    if (Req.Mode == 0 || Req.Mode == 1) {
        /* 逐条设置：整批设置时只要有一个特权不可授予，部分构建会整批
           失败；逐条能让可授予的全部生效，不可授予的静默跳过。
           降权用 Attributes=0（禁用而非 SE_PRIVILEGE_REMOVED 删除），
           这样后续还能再提回来，语义与 AdjustTokenPrivileges 一致。 */
        {
            /* 调整他人 Token 需要调用方持有 SeTcbPrivilege。驱动线程
               默认未启用，先在本进程主 Token 上临时打开，退出时还原。
               SeExports->SeTcbPrivilege 是 ntoskrnl 导出结构，LUID 在
               所有 Windows 版本都是固定值(0,7)，不随构建变化。 */
            HANDLE SelfTok = NULL;
            TOKEN_PRIVILEGES Tcb;
            TOKEN_PRIVILEGES OldTcb;
            ULONG OldLen = sizeof(OldTcb);
            BOOLEAN TcbWasOn = FALSE;
            BOOLEAN TcbAdjusted = FALSE;

            if (NT_SUCCESS(ZwOpenProcessTokenEx(ZwCurrentProcess(),
                                                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                                OBJ_KERNEL_HANDLE, &SelfTok))
                && SelfTok)
            {
                Tcb.PrivilegeCount = 1;
                Tcb.Privileges[0].Luid.HighPart = 0;
                Tcb.Privileges[0].Luid.LowPart = 7;    /* SeTcbPrivilege */
                Tcb.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (NT_SUCCESS(ZwAdjustPrivilegesToken(SelfTok, FALSE,
                        &Tcb, sizeof(Tcb), &OldTcb, &OldLen)))
                {
                    TcbAdjusted = TRUE;
                    if (OldLen >= sizeof(TOKEN_PRIVILEGES) &&
                        OldTcb.PrivilegeCount == 1 &&
                        (OldTcb.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED))
                        TcbWasOn = TRUE;
                }
            }

            /* 用 ZwAdjustPrivilegesToken 直接操作目标 Token 句柄：
               这是调整特权的标准 API（ZwSetInformationToken 的
               TokenPrivileges 类在部分构建上不生效）。
               DisableAllPrivileges=FALSE 表示按 Privileges 数组精确设置。
               返回 STATUS_NOT_ALL_ASSIGNED 表示部分特权不可授予，
               属正常（可授予的已生效）。 */
            for (i = 0; i < PrivCount; i++) {
                TOKEN_PRIVILEGES One;
                One.PrivilegeCount = 1;
                One.Privileges[0].Luid = Tp->Privileges[i].Luid;
                One.Privileges[0].Attributes =
                    (Req.Mode == 0) ? SE_PRIVILEGE_ENABLED : 0;
                (void)ZwAdjustPrivilegesToken(TokenHandle, FALSE,
                                              &One, sizeof(One), NULL, NULL);
            }

            /* 还原 SeTcbPrivilege 到调用前状态 */
            if (TcbAdjusted && !TcbWasOn) {
                Tcb.Privileges[0].Attributes = 0;
                (void)ZwAdjustPrivilegesToken(SelfTok, FALSE, &Tcb,
                                             sizeof(Tcb), NULL, NULL);
            }
            if (SelfTok)
                ZwClose(SelfTok);
        }

        /* 重新查询，按 Token 实际状态计数（本地缓冲只是"期望值"） */
        Len = 0;
        (void)ZwQueryInformationToken(TokenHandle, TokenPrivileges, NULL, 0, &Len);
        if (Len && Len <= 0x100000) {
            unsigned char *Buf2 = (unsigned char *)ExAlloc(PagedPool, Len);
            if (Buf2) {
                ULONG L2 = Len;
                if (ZwQueryInformationToken(TokenHandle, TokenPrivileges,
                                            Buf2, L2, &L2) >= 0) {
                    PTOKEN_PRIVILEGES T2 = (PTOKEN_PRIVILEGES)Buf2;
                    ULONG C2 = T2->PrivilegeCount;
                    if (C2 > (L2 - FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges))
                             / sizeof(LUID_AND_ATTRIBUTES))
                        C2 = (ULONG)((L2 - FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges))
                                     / sizeof(LUID_AND_ATTRIBUTES));
                    PrivCount = C2;
                    for (i = 0; i < C2; i++)
                        if (T2->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                            EnabledCount++;
                }
                ExFree(Buf2);
            }
        }
    } else {
        for (i = 0; i < PrivCount; i++)
            if (Tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                EnabledCount++;
    }
        if (Tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
            EnabledCount++;

    __try {
        ((unsigned int *)OutputBuffer)[0] = PrivCount;
        ((unsigned int *)OutputBuffer)[1] = EnabledCount;
        Ok = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

Cleanup:
    if (Buf)
        ExFree(Buf);
    if (TokenHandle)
        ZwClose(TokenHandle);
    if (Process)
        ObfDereferenceObject(Process);
    return Ok ? 1 : 0;
}

/* ============================================================
 * 0x09B  进程原语子命令（注入所需的通用原语，映射逻辑在 SDK 侧）
 *
 *   In  : { u64 Pid; u32 Op; u32 Pad; u64 A1; u64 A2; u64 A3 } (40B)
 *   Op=0 分配  : A1=Size                 -> Out { u64 Base }
 *                ZwAllocateVirtualMemory COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
 *   Op=1 释放  : A1=Base                 -> ZwFreeVirtualMemory MEM_RELEASE
 *   Op=2 改保护: A1=Base A2=Size A3=Prot -> Out { u64 OldProtect }
 *   Op=3 建线程: A1=Start A2=Param       -> Out { u64 Tid }
 *                ZwCreateThreadEx（ntoskrnl 导出、ntifs.h 无声明，运行时解析）
 * ============================================================*/
typedef struct _XPCH_PROCOP_REQ {
    unsigned __int64 Pid;
    unsigned int     Op;
    unsigned int     Pad;
    unsigned __int64 A1;
    unsigned __int64 A2;
    unsigned __int64 A3;
} XPCH_PROCOP_REQ;

/* 子命令号（与 SDK inject.c 的 XPCH_PROCOP_* 对应） */
#define XPCH_OP_ALLOC          0u
#define XPCH_OP_FREE           1u
#define XPCH_OP_PROTECT        2u
#define XPCH_OP_CREATE_THREAD  3u


__int64 CmdXpchProcessOp(void *InputBuffer, int InputSize,
                         void *OutputBuffer, unsigned int OutputSize)
{
    XPCH_PROCOP_REQ Req;
    unsigned __int64 OutValue = 0;
    HANDLE ProcessHandle = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    CLIENT_ID Cid;
    NTSTATUS Status;
    BOOLEAN Ok = FALSE;

    if (!InputBuffer || InputSize != (int)sizeof(Req))
        return 0;
    if (!OutputBuffer || OutputSize < 8)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)OutputBuffer >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, sizeof(Req), 1);
    memcpy(&Req, InputBuffer, sizeof(Req));
    ProbeForWrite(OutputBuffer, 8, 1);
    if (!Req.Pid || Req.Op > 3)
        return 0;

    InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Cid.UniqueProcess = (HANDLE)(ULONG_PTR)Req.Pid;
    Cid.UniqueThread = NULL;
    /* 按子命令申请最小权限集（写/分配只需 VM_OPERATION，
       建线程另需 CREATE_THREAD；不带 TERMINATE 等无关权限）。 */
    {
        ACCESS_MASK Need = PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        if (Req.Op == XPCH_OP_CREATE_THREAD)
            Need |= PROCESS_CREATE_THREAD;
        Status = ZwOpenProcess(&ProcessHandle, Need, &ObjAttr, &Cid);
    }
    if (Status < 0 || !ProcessHandle)
        return 0;

    if (Req.Op == 0)                        /* 分配：RWX */
    {
        PVOID Base = NULL;
        SIZE_T Size = (SIZE_T)Req.A1;
        if (Size && Size <= 0x10000000)
        {
            Status = ZwAllocateVirtualMemory(ProcessHandle, &Base, 0, &Size,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
            if (Status >= 0)
                OutValue = (unsigned __int64)(ULONG_PTR)Base;
        }
    }
    else if (Req.Op == 1)                   /* 释放 */
    {
        PVOID Base = (PVOID)(ULONG_PTR)Req.A1;
        SIZE_T Size = 0;
        if (Base)
            Status = ZwFreeVirtualMemory(ProcessHandle, &Base, &Size, MEM_RELEASE);
    }
    else if (Req.Op == 2)                   /* 改保护 */
    {
        PVOID Base = (PVOID)(ULONG_PTR)Req.A1;
        SIZE_T Size = (SIZE_T)Req.A2;
        ULONG OldProt = 0;
        if (Base && Size)
        {
            Status = ZwProtectVirtualMemory(ProcessHandle, &Base, &Size,
                                            (ULONG)Req.A3, &OldProt);
            if (Status >= 0)
                OutValue = OldProt;
        }
    }
    else                                    /* Op=3 远程线程 */
    {
        /* ZwCreateThreadEx / ZwResumeThread 都不在 ntoskrnl.lib 导入库里
           （map 只有 __imp_ZwQueryInformationThread），运行时用
           MmGetSystemRoutineAddress 解析 Zw/Nt 别名实测也返回 NULL。
           改用 RtlCreateUserThread：它在导入库中（已验证），是内核创建
           用户态线程的标准 API，线程真正归属目标进程，可执行其用户内存。
           （PsCreateSystemThread+attach 方案实机验证会 0xFC：系统线程
             没有目标进程的用户页表，执行映射区即触发不可执行页。） */
        HANDLE ThreadHandle = NULL;
        CLIENT_ID Cid;
        NTSTATUS St2;
        /* RtlCreateUserThread 原型（ntifs.h 未声明，导入库有符号）：
           NTSTATUS RtlCreateUserThread(
               HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
               BOOLEAN CreateSuspended, ULONG StackZeroBits,
               SIZE_T StackReserved, SIZE_T StackCommit,
               PVOID StartAddress, PVOID Parameter,
               PHANDLE ThreadHandle, PCLIENT_ID ClientId);
           之前少传 SecurityDescriptor 造成整个参数表移位，
           StartAddress 被当成 CreateSuspended → STATUS_INVALID_PARAMETER
           (0xC000000D)。 */
        typedef NTSTATUS (NTAPI *PFN_RtlCreateUserThread)(
            HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
            SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID);

        /* 编译器看不到原型（头文件未声明），用导入库符号地址直接调用 */
        {
            UNICODE_STRING RtlName;
            PFN_RtlCreateUserThread pRtlCreate = NULL;
            RtlInitUnicodeString(&RtlName, L"RtlCreateUserThread");
            pRtlCreate = (PFN_RtlCreateUserThread)
                MmGetSystemRoutineAddress(&RtlName);
            if (!pRtlCreate) {
                OutValue = 0xDEAD0006ULL;
                goto OpDone;
            }
            RtlZeroMemory(&Cid, sizeof(Cid));
            St2 = pRtlCreate(
                ProcessHandle, NULL,
                FALSE,                      /* CreateSuspended */
                0, 0, 0,                    /* StackZeroBits/Reserved/Commit */
                (PVOID)(ULONG_PTR)Req.A1,   /* StartAddress */
                (PVOID)(ULONG_PTR)Req.A2,   /* Parameter */
                &ThreadHandle, &Cid);
        }
        if (NT_SUCCESS(St2) && ThreadHandle) {
            OutValue = (unsigned __int64)(ULONG_PTR)Cid.UniqueThread;
            if (!OutValue)
                OutValue = 1;
            ZwClose(ThreadHandle);
        } else {
            OutValue = 0xDEAD0005ULL | ((unsigned __int64)(ULONG)St2 << 32);
        }
    }

OpDone:
    __try {
        *(unsigned __int64 *)OutputBuffer = OutValue;
        Ok = (Req.Op == 1) ? TRUE : (OutValue != 0);
        /* 诊断：Op=3 创建失败时 OutValue 存放 NTSTATUS（最高位为 1）
           或诊断标记（0xDEAD....），都不能算成功。 */
        if (Req.Op == 3 && ((OutValue & 0x8000000000000000ULL) ||
                            (OutValue & 0xFFFF0000ULL) == 0xDEAD0000ULL))
            Ok = FALSE;
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    if (ProcessHandle)
        ZwClose(ProcessHandle);
    return Ok ? 1 : 0;
}
