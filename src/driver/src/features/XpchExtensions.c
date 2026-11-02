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
 * ==========================================================================*/
#include "..\inc\XPCHunterDrv.h"

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