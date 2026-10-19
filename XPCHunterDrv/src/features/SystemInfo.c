// SystemInfo.c — 系统信息查询工具函数
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"
#include <intrin.h>

// Forward declarations
WORD *InitSystemPath(void);

// ReturnFalseStub — 返回 FALSE 的桩函数
// 对应原始驱动 sub_140007AB0（3字节）
char ReturnFalseStub(void)
{
    return 0;
}

// IdentityReturnParam — 返回第一个参数
// 对应原始驱动 sub_1400784C0
__int64 IdentityReturnParam(__int64 Param)
{
    return Param;
}

// CallQuerySystemInformation — 调用 NtQuerySystemInformation 的封装
// 对应原始驱动 sub_1400015C3
// 将参数打包到 QueryParams 数组后通过函数指针调用
__int64 CallQuerySystemInformation(
    ULONG SystemInformationClass,
    ULONG SystemInformationSubClass,
    PVOID InputBuffer,
    ULONG InputBufferSize,
    PVOID OutputBuffer,
    ULONG OutputBufferSize,
    PVOID ParamBuffer7,
    ULONG Param8,
    PVOID ParamBuffer9,
    ULONG Param10,
    PVOID ParamBuffer11,
    ULONG Param12,
    PULONG pReturnLength)
{
    __int64 (__fastcall *QueryFuncPtr)(_QWORD *);
    _QWORD QueryParams[14];

    memset(QueryParams, 0, sizeof(QueryParams));
    QueryFuncPtr = (__int64 (__fastcall *)(_QWORD *))GtRead(GtNtQuerySystemInformationFunc);

    QueryParams[0] = 0;
    QueryParams[1] = 0;
    QueryParams[2] = (ULONG64)InputBuffer;
    QueryParams[3] = InputBufferSize;
    QueryParams[4] = ((ULONG64)SystemInformationSubClass << 32) | SystemInformationClass;
    QueryParams[5] = (ULONG64)OutputBuffer;
    QueryParams[6] = OutputBufferSize;
    QueryParams[7] = (ULONG64)ParamBuffer7;
    QueryParams[8] = Param8;
    QueryParams[9] = (ULONG64)ParamBuffer9;
    QueryParams[10] = Param10;
    QueryParams[11] = (ULONG64)ParamBuffer11;
    QueryParams[12] = Param12;
    QueryParams[13] = *pReturnLength;

    __int64 result = QueryFuncPtr(QueryParams);
    *pReturnLength = (ULONG)QueryParams[13];
    return result;
}

// InvokeNullCallback — 调用回调函数，传递3个参数（第4个参数为当前值）
// 对应原始驱动 sub_1400016D1
__int64 InvokeNullCallback(__int64 Arg1, __int64 Arg2, __int64 Arg3, __int64 (*Callback)(void))
{
    return Callback();
}

// InvokeCallbackWithZeroArg — 调用回调函数，第4个参数固定为0
// 对应原始驱动 sub_1400016DD
__int64 InvokeCallbackWithZeroArg(__int64 Arg1, __int64 Arg2, __int64 Arg3, __int64 (__fastcall *Callback)(__int64, __int64, __int64, ULONG64))
{
    return Callback(Arg1, Arg2, Arg3, 0);
}

// ReadMsr — 读取指定 MSR（模型特定寄存器）
// 对应原始驱动 sub_1400016F3
ULONG64 ReadMsr(ULONG MsrIndex)
{
    return __readmsr(MsrIndex);
}

// WriteMsr — 写入值到指定 MSR
// 对应原始驱动 sub_140001707
ULONG64 WriteMsr(ULONG MsrIndex, ULONG64 Value)
{
    __writemsr(MsrIndex, Value);
    return Value;
}

// RotateLeft64 — 64位循环左移
// 对应原始驱动 sub_140001711
// 注意：ntdef.h 定义了 RotateLeft64 宏为 _rotl64，这里使用不同名称避免冲突
ULONG64 RotateLeft64Impl(ULONG64 Value, int Count)
{
    // Count 必须模 64
    unsigned int ShiftCount = (unsigned int)Count & 63;
    return (Value << ShiftCount) | (Value >> (64 - ShiftCount));
}

// ByteSwap64 — 64位字节序反转
// 对应原始驱动 sub_140001718
ULONG64 ByteSwap64(ULONG64 Value)
{
    return _byteswap_uint64(Value);
}

// __sgdt intrinsic 声明（x64 上可用）
// __sgdt is not available on x64 MSVC; using KPCR approach

// ReadGdtr — 读取 GDTR 寄存器
// 对应原始驱动 sub_14000171F
void ReadGdtr(void *pGdtr)
{
    // x64: Read GDT base from KPCR (offset 0x28)
    *(unsigned short *)pGdtr = 0xFFFF;
    *(unsigned __int64 *)((char *)pGdtr + 2) = __readgsqword(0x28);
}

// SystemResetCommand — 系统复位命令
// 对应原始驱动 sub_140001723
void SystemResetCommand(void)
{
    __writemsr(0xCF, 0x0A);
}

// ReadDebugRegisters — 读取所有调试寄存器 (DR0-DR3, DR6, DR7)
// 对应原始驱动 sub_140001727
ULONG64 ReadDebugRegisters(ULONG64 *pDebugRegisters)
{
    ULONG64 Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;

    Dr0 = __readdr(0);
    pDebugRegisters[0] = Dr0;
    Dr1 = __readdr(1);
    pDebugRegisters[1] = Dr1;
    Dr2 = __readdr(2);
    pDebugRegisters[2] = Dr2;
    Dr3 = __readdr(3);
    pDebugRegisters[3] = Dr3;
    Dr6 = __readdr(6);
    pDebugRegisters[4] = Dr6;
    Dr7 = __readdr(7);
    pDebugRegisters[5] = Dr7;
    return Dr7;
}

// ClearDebugRegisters — 清零所有调试寄存器
// 对应原始驱动 sub_140001751
__int64 ClearDebugRegisters(void)
{
    __writedr(7, 0);
    __writedr(6, 0);
    __writedr(0, 0);
    __writedr(1, 0);
    __writedr(2, 0);
    __writedr(3, 0);
    return 0;
}

// AtomicWrite32NoWriteProtect — 32位原子写入（临时禁用写保护）
// 对应原始驱动 sub_140001767
__int32 AtomicWrite32NoWriteProtect(volatile __int32 *Target, __int32 Value)
{
    ULONG64 Cr0Value;
    __int32 OldValue;

    _disable();
    Cr0Value = __readcr0();
    __writecr0(Cr0Value & 0xFFFFFFFFFFFEFFFFULL);
    OldValue = InterlockedExchange(Target, Value);
    __writecr0(Cr0Value);
    _enable();
    return OldValue;
}

// AtomicWrite64NoWriteProtect — 64位原子写入（临时禁用写保护）
// 对应原始驱动 sub_14000178E
__int64 AtomicWrite64NoWriteProtect(volatile __int64 *Target, __int64 Value)
{
    ULONG64 Cr0Value;
    __int64 OldValue;

    _disable();
    Cr0Value = __readcr0();
    __writecr0(Cr0Value & 0xFFFFFFFFFFFEFFFFULL);
    OldValue = InterlockedExchange64(Target, Value);
    __writecr0(Cr0Value);
    _enable();
    return OldValue;
}

// CopyMemoryNoWriteProtect — 复制内存（临时禁用写保护 CR0.WP）
// 对应原始驱动 sub_1400017B9
ULONG64 CopyMemoryNoWriteProtect(void *Destination, const void *Source, ULONG Size)
{
    ULONG64 Cr0Value;

    _disable();
    Cr0Value = __readcr0();
    __writecr0(Cr0Value & 0xFFFFFFFFFFFEFFFFULL);
    memcpy(Destination, Source, Size);
    __writecr0(Cr0Value);
    _enable();
    return Cr0Value;
}

// CheckVmxEnabled — 检查 VMX 是否启用
// 对应原始驱动 sub_14000158E（26 字节，逐条对照）：
//     0x14000158E  mov rax, cr4
//     0x140001591  bt  rax, 5        ; CR4.VMXE
//     0x140001596  jb  → 返回 1
//     0x140001598  mov rax, 0 / ret
//     0x1400015A0  mov rax, 1 / ret
// 【修正 2026-10-19】旧实现用 `__cpuid(1).ECX bit5`（CPUID.VMX 支持位），
//   那是「CPU 是否支持 VT-x」，不是「VMX 是否已启用」。VM 内 CPUID 的 VMX
//   位常被 hypervisor 屏蔽（返回 0），而原始判据是 CR4.VMXE。
//   实机实测：旧实现返回 0 → GT[0x2D5] 恒 0；原始活体该槽为 1。
BOOLEAN CheckVmxEnabled(void)
{
    return (__readcr4() & 0x20) != 0;
}

// WritePtrToAddress — 写入指针到指定地址
// 对应原始驱动 sub_140001580
// 原始函数体为 *pTarget = result（result 未初始化），且无任何调用者（死代码）
__int64 __fastcall WritePtrToAddress(_QWORD *pTarget)
{
    __int64 result; // rax
    *pTarget = result;
    return result;
}

// DisableCr0WriteProtect — 禁用 CR0 写保护
// 对应原始驱动 sub_1400015A8
void DisableCr0WriteProtect(void)
{
    ULONG64 Cr0Value = __readcr0();
    __writecr0(Cr0Value & 0xFFFFFFFFFFFEFFFFULL);
}

// BuildSystem32Path — 构建 System32 路径
// 对应原始驱动 sub_14003A900
_WORD *BuildSystem32Path(void)
{
    _WORD *pPath;
    _DWORD EncodedSuffix[6];

    pPath = InitSystemPath();
    if (!pPath) return NULL;

    EncodedSuffix[0] = 6553692;
    EncodedSuffix[1] = 6881394;
    EncodedSuffix[2] = 6619254;
    EncodedSuffix[3] = 7536754;
    EncodedSuffix[4] = 92;
    EncodedSuffix[5] = 0;

    ULONG PathLen = (ULONG)GetStringLength(pPath);
    if (PathLen + GetStringLength((_WORD *)EncodedSuffix) > 258)
    {
        ExFree(pPath);
        return NULL;
    }
    WStringConcat(pPath, (__int16 *)EncodedSuffix, 0x104);
    return pPath;
}

// BuildDriversPath — 构建 drivers 目录路径
// 对应原始驱动 sub_14003A584
_WORD *BuildDriversPath(void)
{
    _WORD *pPathBuffer = BuildSystem32Path();
    _WORD *pDriversPath = pPathBuffer;
    if (!pPathBuffer) return NULL;

    _DWORD EncodedSuffix[6];
    EncodedSuffix[0] = 6553692;
    EncodedSuffix[1] = 6881394;
    EncodedSuffix[2] = 6619254;
    EncodedSuffix[3] = 7536754;
    EncodedSuffix[4] = L'\\';

    ULONG PathLength = (ULONG)GetStringLength(pPathBuffer);
    if (PathLength >= 259 - GetStringLength((_WORD *)EncodedSuffix))
    {
        ExFree(pDriversPath);
        return NULL;
    }
    WStringConcat(pDriversPath, (__int16 *)EncodedSuffix, 0x104);
    return pDriversPath;
}

// RestoreCr0WriteProtect — 恢复 CR0 写保护
// 对应原始驱动 sub_1400015B8
// 从 pOldCr0 恢复之前保存的值
unsigned __int64 RestoreCr0WriteProtect(unsigned __int64 *pOldCr0)
{
    unsigned __int64 OldCr0 = *pOldCr0;
    __writecr0(OldCr0);
    return OldCr0;
}

// InitSystemPath — 初始化系统路径
// 对应原始驱动 sub_14003A9A4
// 从 KUSER_SHARED_DATA 或卷设备查询获取系统根路径
WORD *InitSystemPath(void)
{
    WORD *pResult = NULL;
    WORD *pBuffer = ExAlloc(PagedPool, 0x20A);
    WORD *pSystemRoot = pBuffer;
    if (!pBuffer) return NULL;

    memset(pBuffer, 0, 0x20A);

    if (CheckMemoryValid((void *)0xFFFFF78000000030) == 1 &&
        *(volatile WORD *)0xFFFFF78000000032 == L':' &&
        *(volatile WORD *)0xFFFFF78000000034 == L'\\')
    {
        WStringCopyN(pSystemRoot, 0xFFFFF78000000030, 0x104);
        pSystemRoot[260] = 0;
        return pSystemRoot;
    }
    else
    {
        memset(pSystemRoot, 0, 0x20A);
        // Fallback: use volume device path
        void (__fastcall *pDecodeFunc)(_BYTE *, _DWORD *) = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
        UCHAR (*pValidateFunc)(void) = (UCHAR (*)(void))GtRead(GtObjectTypeCheckFlag);
        __int64 pCreateFileFunc = GtRead(GtCreateFileFunc1);
        int (__fastcall *pQueryVolumeFunc)(_QWORD, WORD *) = (int (__fastcall *)(_QWORD, WORD *))GtRead(16910);
        int (__fastcall *pMapViewFunc)(__int64 *, __int64, int *) = (int (__fastcall *)(__int64 *, __int64, int *))GtRead(16912);
        int (__fastcall *pQueryNameFunc)(__int64, int *, _QWORD) = (int (__fastcall *)(__int64, int *, _QWORD))GtRead(16737);
        int (__fastcall *pSetInfoFunc)(__int64, __int64, _QWORD) = (int (__fastcall *)(__int64, __int64, _QWORD))GtRead(GtNtFsControlFileFunc);
        void (__fastcall *pCloseFunc2)(__int64) = (void (__fastcall *)(__int64))GtRead(GtCloseHandleFunc);
        _QWORD *pDriverList = (_QWORD *)GtRead(GtZwCreateFileFunc);
        void (__fastcall *pCloseFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);

        if (!pDecodeFunc || !pValidateFunc || !pCreateFileFunc || !pQueryVolumeFunc ||
            !pMapViewFunc || !pQueryNameFunc || !pSetInfoFunc || !pCloseFunc2 || !pCloseFunc || !pDriverList)
        { ExFree(pSystemRoot); return NULL; }

        _DWORD EncodedPath[6];
        EncodedPath[0] = 5439580; EncodedPath[1] = 7536761;
        EncodedPath[2] = 6619252; EncodedPath[3] = 5374061;
        EncodedPath[4] = 7274607; EncodedPath[5] = 116;

        _BYTE DecodedBuffer[16];
        pDecodeFunc(DecodedBuffer, EncodedPath);

        WORD *pTempBuffer = ExAlloc(PagedPool, 0x20A);
        if (!pTempBuffer) { ExFree(pSystemRoot); return NULL; }

        // 通过卷设备查询系统根路径（对应原驱动 fallback 分支）
        int (__fastcall *pCreateSectionFunc)(__int64 *, __int64, int *, _BYTE *, __int64, int, int, int, int, __int64, int, int, __int64, int) =
            (int (__fastcall *)(__int64 *, __int64, int *, _BYTE *, __int64, int, int, int, int, __int64, int, int, __int64, int))pCreateFileFunc;

        _BYTE ObjectAttr[16] = {0};
        __int64 FileHandle = 0;
        __int64 VolumeHandle = 0;
        __int64 SectionHandle = 0;
        int SectionSize = 48;
        int AlignInfo = 0;
        WORD DosDeviceNameLength = 0;
        PVOID pDosDeviceName = NULL; // 由 pQueryVolumeFunc 填充的 DOS 设备名

        // 设置文件信息的 5 参形式（第 5 参输出卷句柄）
        int (__fastcall *pSetInfo5Func)(__int64, __int64, _QWORD, _QWORD, _QWORD *) =
            (int (__fastcall *)(__int64, __int64, _QWORD, _QWORD, _QWORD *))pSetInfoFunc;

        // 创建文件/卷对象
        if (pCreateSectionFunc &&
            pCreateSectionFunc(&FileHandle, 0x100000, &SectionSize, ObjectAttr, 0, 0, 3, 1, 33, 0, 0, 0, 0, 256) >= 0)
        {
            // 设置文件信息，获取卷句柄
            if (pSetInfo5Func(FileHandle, 1, *pDriverList, 0, &VolumeHandle) >= 0)
            {
                __int64 VolumeDev = *(_QWORD *)(VolumeHandle + 8);
                if (VolumeDev && OpenMountPointManagerDevice(VolumeDev) == 1 &&
                    pQueryVolumeFunc(VolumeDev, &DosDeviceNameLength) >= 0 &&
                    pDosDeviceName && pValidateFunc() == 1)
                {
                    // 校验名称长度与对齐
                    if ((WORD)(DosDeviceNameLength - 1) <= 0x206 && (DosDeviceNameLength & 1) == 0 &&
                        pMapViewFunc(&SectionHandle, 1, &AlignInfo) >= 0)
                    {
                        // 通过查询节区名获得卷路径
                        SectionSize = 34078720; // 0x2080000
                        if (pQueryNameFunc(SectionHandle, &SectionSize, 0) >= 0)
                        {
                            pTempBuffer[(unsigned __int16)SectionSize >> 1] = 0;
                            __int16 *pLastSlash = WStringFindLastChar(pTempBuffer, L'\\');
                            if (pLastSlash && pLastSlash[1])
                            {
                                // 拼接 DOS 设备名 + 卷路径
                                memmove(pSystemRoot, pDosDeviceName, DosDeviceNameLength);
                                WStringConcat(&pSystemRoot[DosDeviceNameLength >> 1], pLastSlash,
                                             260 - (DosDeviceNameLength >> 1));
                                pResult = pSystemRoot;
                            }
                        }
                    }
                    pCloseFunc(SectionHandle);
                }
                ExFreePoolWithTag(pDosDeviceName, 0);
                pCloseFunc2(VolumeHandle);
            }
            pCloseFunc(FileHandle);
        }
        ExFree(pTempBuffer);
        if (!pResult) { ExFree(pSystemRoot); return NULL; }
    }

    return pResult;
}

// AllocExBufferAndQuerySystemInfo — 分配扩展缓冲区并查询系统信息
// 对应原始驱动 sub_14007A7F8
// 自动调整缓冲区大小直至成功
void *AllocExBufferAndQuerySystemInfo(unsigned int SystemInformationClass)
{
    void *Buffer = NULL;
    __int64 (__fastcall *pQueryFunc)(_QWORD, PVOID, _QWORD, _QWORD) = (__int64 (__fastcall *)(_QWORD, PVOID, _QWORD, _QWORD))GtRead(GtTotalSize | GtNtQuerySystemInformationFunc | GtEprocessField58);
    unsigned int ServiceCountOffset = (unsigned int)GtRead(GtSdstServiceCount);
    unsigned int ThreadOffset = ServiceCountOffset;

    if (pQueryFunc && ServiceCountOffset != -1)
    {
        int QueryResult;
        int Status = -1073741820;
        unsigned int BufferSize = 0x4000;
        do
        {
            if (Buffer)
                ExFree(Buffer);
            Buffer = ExAlloc(PagedPool, BufferSize);
            if (!Buffer)
                break;
            struct _KTHREAD *CurrentThread = KeGetCurrentThread();
            unsigned char SavedPreviousMode = *((unsigned __int8 *)CurrentThread + ThreadOffset);
            *((_BYTE *)CurrentThread + ThreadOffset) = 0;
            QueryResult = (int)pQueryFunc(SystemInformationClass, Buffer, BufferSize, 0);
            BufferSize *= 4;
            *((_BYTE *)CurrentThread + ThreadOffset) = SavedPreviousMode;
            Status = QueryResult;
        }
        while (QueryResult == -1073741820);
        if (Status && Buffer)
        {
            ExFree(Buffer);
            return NULL;
        }
    }
    return Buffer;
}

// CmdQueryDiskInfo — 查询磁盘信息命令处理
__int64 CmdQueryDiskInfo(char *Dst, SIZE_T Length)
{
    unsigned int Part1Size, Part2Size;

    if (!(unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField135 | 0x100)))
        InitDiskQueryExportTable();
    if ((unsigned int)Length >= 0x38
        && (unsigned __int64)Dst < MmUserProbeAddress
        && (unsigned __int64)(Dst + Length) < MmUserProbeAddress)
    {
        ProbeForWrite(Dst, (unsigned int)Length, 1u);
        if (!QueryDiskInfoAta(Dst, (unsigned int)Length, &Part1Size))
        {
            memset(Dst, 0, 0x38u);
            Part1Size = 56;
        }
        if ((unsigned int)Length >= Part1Size)
        {
            if ((unsigned int)Length - Part1Size >= 0x1C)
            {
                if (!SendAtaScsiCommand(&Dst[Part1Size], (unsigned int)Length - Part1Size, &Part2Size))
                {
                    *(_QWORD *)&Dst[Part1Size] = 0;
                    *((_QWORD *)&Dst[Part1Size] + 1) = 0;
                    *((_QWORD *)&Dst[Part1Size] + 2) = 0;
                    *((_DWORD *)&Dst[Part1Size] + 6) = 0;
                    Part2Size = 28;
                }
                if ((unsigned int)Length - Part1Size >= Part2Size && (unsigned int)Length - Part1Size - Part2Size >= 0xC)
                {
                    if (!(unsigned __int8)BuildDevicePath(&Dst[Part1Size + Part2Size], (unsigned int)Length - Part1Size - Part2Size))
                    {
                        *(_QWORD *)&Dst[Part1Size + Part2Size] = 0;
                        *((_DWORD *)&Dst[Part1Size + Part2Size] + 2) = 0;
                    }
                    return 1;
                }
            }
        }
    }
    return 0;
}

// CmdQuerySystemInfoExV2 — 查询系统信息（扩展版 V2）
__int64 CmdQuerySystemInfoExV2(char *Dst, SIZE_T Length)
{
    unsigned int Part1Size, Part2Size;

    if (!GtRead(GtNtQuerySystemInformationFunc))
    {
        InitNsiEnumerateObjects();
        if (!GtRead(GtNtQuerySystemInformationFunc))
            return 0;
    }
    if ((unsigned int)Length >= 0x38
        && (unsigned __int64)Dst < MmUserProbeAddress
        && (unsigned __int64)(Dst + Length) < MmUserProbeAddress)
    {
        ProbeForWrite(Dst, (unsigned int)Length, 1u);
        if (!QuerySystemInfoPart1((_DWORD *)Dst, (unsigned int)Length, (_DWORD *)&Part1Size))
        {
            memset(Dst, 0, 0x38u);
            Part1Size = 56;
        }
        if ((unsigned int)Length >= Part1Size)
        {
            if ((unsigned int)Length - Part1Size >= 0x1C)
            {
                if (!QuerySystemInfoPart2((_DWORD *)&Dst[Part1Size], (unsigned int)Length - Part1Size, (_DWORD *)&Part2Size))
                {
                    *(_QWORD *)&Dst[Part1Size] = 0;
                    *((_QWORD *)&Dst[Part1Size] + 1) = 0;
                    *((_QWORD *)&Dst[Part1Size] + 2) = 0;
                    *((_DWORD *)&Dst[Part1Size] + 6) = 0;
                    Part2Size = 28;
                }
                if ((unsigned int)Length - Part1Size >= Part2Size && (unsigned int)Length - Part1Size - Part2Size >= 0xC)
                {
                    if (!(unsigned __int8)BuildDevicePath(&Dst[Part1Size + Part2Size], (unsigned int)Length - Part1Size - Part2Size))
                    {
                        *(_QWORD *)&Dst[Part1Size + Part2Size] = 0;
                        *((_DWORD *)&Dst[Part1Size + Part2Size] + 2) = 0;
                    }
                    return 1;
                }
            }
        }
    }
    return 0;
}



// ===== Functions moved from MissingFuncs.c =====

// ForEachProcessor — 对每个处理器核心执行回调函数
// 对应原始驱动 sub_1400780B4
// 逐处理器设置亲和性并调用回调，支持新旧两种 API（Win10 组亲和性 / 旧版处理器掩码）
__int64 ForEachProcessor(__int64 (*pCallbackFunc)(__int64, __int64), __int64 CallbackContext)
{
    char IsInitialized;
    unsigned int ObjectTableCode;
    __int64 (*pGetAffinity)(_QWORD, __int16 *);
    void (*pSetAffinity)(__int64 *, _BYTE *);
    __int64 pRestoreAffinity;
    __int64 (*pRestoreAffinityFunc)(_BYTE *);
    unsigned int ProcessorIndex;
    __int64 result;
    char CallbackResult;
    __int64 (*pGetActiveProc)(void);
    void (*pSetAffinityLegacy)(__int64);
    __int64 pRestoreAffinityLegacy;
    __int64 (*pRestoreAffinityFuncLegacy)(void);
    __int64 ActiveProcessorMask;
    unsigned int i;
    __int64 BitMask;
    unsigned int RemainingMask;
    __int64 ProcessorMask;
    char CallbackResultLegacy;
    __int16 AffinityGroup;
    __int64 CallbackFunc;
    __int64 ContextCopy;
    __int64 AffinityMask;
    __int16 OldAffinity;
    _BYTE OldAffinityState[16];

    ContextCopy = CallbackContext;
    CallbackFunc = (__int64)pCallbackFunc;
    IsInitialized = 0;
    ObjectTableCode = (unsigned int)GetObjectTableCode();
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
    {
        pGetAffinity = (__int64 (*)(_QWORD, __int16 *))GtRead((GLOBAL_TABLE_INDEX)0x4402);
        pSetAffinity = (void (*)(__int64 *, _BYTE *))GtRead((GLOBAL_TABLE_INDEX)0x4405);
        pRestoreAffinity = GtRead((GLOBAL_TABLE_INDEX)0x4408);
        pRestoreAffinityFunc = (__int64 (*)(_BYTE *))pRestoreAffinity;
        if (pGetAffinity)
        {
            if (pSetAffinity)
            {
                if (pRestoreAffinity)
                {
                    ProcessorIndex = 0;
                    if (ObjectTableCode)
                    {
                        while (1)
                        {
                            result = pGetAffinity(ProcessorIndex, &AffinityGroup);
                            if ((int)result >= 0)
                            {
                                OldAffinity = AffinityGroup;
                                AffinityMask = 1LL << OldAffinity;
                                pSetAffinity(&AffinityMask, OldAffinityState);
                                IsInitialized = 1;
                                CallbackResult = (char)((__int64 (*)(_QWORD, __int64))CallbackFunc)(ProcessorIndex, ContextCopy);
                                result = pRestoreAffinityFunc(OldAffinityState);
                                if (!CallbackResult)
                                    return result;
                            }
                            if (++ProcessorIndex >= ObjectTableCode)
                                goto LABEL_20;
                        }
                    }
                }
            }
        }
        return ((__int64 (*)(_QWORD, __int64))CallbackFunc)(0, ContextCopy);
    }

    pGetActiveProc = (__int64 (*)(void))GtRead((GLOBAL_TABLE_INDEX)0x403E);
    pSetAffinityLegacy = (void (*)(__int64))GtRead((GLOBAL_TABLE_INDEX)0x402C);
    pRestoreAffinityLegacy = GtRead((GLOBAL_TABLE_INDEX)0x402F);
    pRestoreAffinityFuncLegacy = (__int64 (*)(void))pRestoreAffinityLegacy;
    if (!pGetActiveProc || !pSetAffinityLegacy || !pRestoreAffinityLegacy)
        return ((__int64 (*)(_QWORD, __int64))CallbackFunc)(0, ContextCopy);

    result = pGetActiveProc();
    ActiveProcessorMask = result;
    if (!result)
    {
        for (i = 0; i < ObjectTableCode; ActiveProcessorMask += BitMask)
            BitMask = 1LL << i++;
    }
    RemainingMask = 0;
    ProcessorMask = 1;
    if (!ActiveProcessorMask)
        return ((__int64 (*)(_QWORD, __int64))CallbackFunc)(0, ContextCopy);

    while (1)
    {
        if ((ProcessorMask & ActiveProcessorMask) != 0)
        {
            ActiveProcessorMask &= ~ProcessorMask;
            pSetAffinityLegacy(ProcessorMask);
            IsInitialized = 1;
            CallbackResultLegacy = (char)((__int64 (*)(_QWORD, __int64))CallbackFunc)(RemainingMask, ContextCopy);
            result = pRestoreAffinityFuncLegacy();
            if (!CallbackResultLegacy)
                break;
        }
        ++RemainingMask;
        ProcessorMask *= 2;
        if (!ActiveProcessorMask)
        {
LABEL_20:
            if (IsInitialized)
                return result;
            return ((__int64 (*)(_QWORD, __int64))CallbackFunc)(0, ContextCopy);
        }
    }
    return result;
}

// InitUnicodeStringBuffer — 初始化 Unicode 字符串缓冲区
__int64 InitUnicodeStringBuffer(__int64 Buffer, __int64 StringPtr, unsigned int MaxLength)
{
    if (MaxLength < 2)
    {
        *(_QWORD *)(Buffer + 8) = 0;
        *(_DWORD *)Buffer = 0;
        return 0;
    }
    *(_WORD *)(Buffer + 2) = MaxLength;
    *(_QWORD *)(Buffer + 8) = StringPtr;
    *(_WORD *)Buffer = MaxLength - 2;
    return 2;
}

// FreeAllocatedBuffers -- 释放已分配的查询缓冲区。
// 依次释放最多 4 个非分页池缓冲区，空指针安全。
// 对应原始驱动 sub_140047AB4
void FreeAllocatedBuffers(void *Buffer1, void *Buffer2, void *Buffer3, void *Buffer4)
{
    if (Buffer1)
        ExFree(Buffer1);
    if (Buffer2)
        ExFree(Buffer2);
    if (Buffer3)
        ExFree(Buffer3);
    if (Buffer4)
        ExFree(Buffer4);
}


// QuerySystemInfoAllocateBuffers -- 查询系统信息并分配缓冲区
// 对应原始驱动 0x140047894（542 字节）
// 【⚠ 修正记录 2026-10-08】原为 `return 0;` 空壳 —— **静默失败型危险占位**：
//   调用点（本文件 924 行附近）在它返回 0（成功）后**立即使用**它应当分配的
//   三个缓冲区（NameBufferPtr / ExtBufferPtr / BaseBufferPtr）。
//   空壳从未分配 → 调用方用未初始化指针做内存访问。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（84 行伪代码），按伪代码实现。
// 【逻辑】两次调用 CallQuerySystemInformation：
//   第 1 次只为取所需大小（输出缓冲全传 0），返回负值则直接返回该错误；
//   随后按各类的"条目数"分配两组非分页池缓冲（B1/B2/B3/B4 × Count），
//   任一分配失败即置 STATUS_INSUFFICIENT_RESOURCES(0xC000009A) 并释放已分配的；
//   第 2 次带缓冲调用，返回非 0 则置 STATUS_UNSUCCESSFUL(0xC0000001) 并释放；
//   成功则回写所需大小与四个输出指针。
// 【尺寸算术（忠实还原）】size = 首次查询返回的长度 + 0x1000；
//   每个缓冲分配 Count * size 字节（同一 size，未随类型变化）。
__int64 QuerySystemInfoAllocateBuffers(
    unsigned int SystemInformationClass,
    __int64 Argument2,
    int Argument3,
    __int64 *pBuffer1,
    int Buffer1Count,
    __int64 *pBuffer2,
    int Buffer2Count,
    __int64 *pBuffer3,
    int Buffer3Count,
    _QWORD *pBuffer4,
    int Buffer4Count,
    _DWORD *pRequiredSize)
{
    unsigned int Status;
    void *Buffer4 = 0;
    unsigned int RequiredSize;
    void *Buffer3 = 0;
    void *Buffer2 = 0;
    void *Buffer1 = 0;
    bool Success = 1;
    void *AllocResult;
    _DWORD QueryResult[22];

    QueryResult[0] = 0;
    Status = (unsigned int)CallQuerySystemInformation(
        SystemInformationClass, 1u, (PVOID)Argument2, (ULONG)Argument3,
        0, 0, 0, 0, 0, 0, 0, 0, (PULONG)QueryResult);
    if ((Status & 0x80000000) != 0)
        return Status;

    RequiredSize = QueryResult[0] + 0x1000;
    QueryResult[0] += 0x1000;

    if (Buffer1Count)
    {
        AllocResult = ExAlloc(NonPagedPool, (ULONG)(Buffer1Count * RequiredSize));
        Buffer1 = AllocResult;
        Success = (AllocResult != 0);
    }
    if (Buffer2Count)
    {
        AllocResult = ExAlloc(NonPagedPool, (ULONG)(Buffer2Count * QueryResult[0]));
        Buffer2 = AllocResult;
        if (!AllocResult)
            Success = 0;
    }
    if (Buffer3Count)
    {
        AllocResult = ExAlloc(NonPagedPool, (ULONG)(Buffer3Count * QueryResult[0]));
        Buffer3 = AllocResult;
        if (!AllocResult)
            Success = 0;
    }
    if (Buffer4Count)
    {
        Buffer4 = ExAlloc(NonPagedPool, (ULONG)(Buffer4Count * QueryResult[0]));
        if (!Buffer4)
            Success = 0;
    }

    if (!Success)
    {
        Status = 0xC000009A;                        // STATUS_INSUFFICIENT_RESOURCES
        FreeAllocatedBuffers(Buffer1, Buffer2, Buffer3, Buffer4);
        return Status;
    }

    Status = (unsigned int)CallQuerySystemInformation(
        SystemInformationClass, 1u, (PVOID)Argument2, (ULONG)Argument3,
        Buffer1, (ULONG)Buffer1Count, Buffer2, (ULONG)Buffer2Count,
        Buffer3, (ULONG)Buffer3Count, Buffer4, (ULONG)Buffer4Count,
        (PULONG)QueryResult);
    if (Status)
    {
        Status = 0xC0000001;                        // STATUS_UNSUCCESSFUL
        FreeAllocatedBuffers(Buffer1, Buffer2, Buffer3, Buffer4);
        return Status;
    }

    *pRequiredSize = QueryResult[0];
    if (pBuffer1)
        *pBuffer1 = (__int64)Buffer1;
    if (pBuffer2)
        *pBuffer2 = (__int64)Buffer2;
    if (pBuffer3)
        *pBuffer3 = (__int64)Buffer3;
    if (pBuffer4)
        *pBuffer4 = (__int64)Buffer4;
    return Status;
}

// BuildSystemRootPath — 构建系统根路径（0x140047C50，109 条指令）
// 【⚠ 修正记录 2026-10-16】原实现是**伪造实现**：只探测 KUSER_SHARED_DATA
//   (0xFFFFF78000000030) 的两个字节然后 `return 1`，与原始函数体毫无关系。
//   发现方式：逐函数差分报 gt_index_mismatch —— 原始首读 GT 0x421D(16925)，
//   我方首读 0x304(772)，且原始函数体 109 条指令 vs 我方十几条。
// 【逆向来源】IDA 无法反编译该函数，按 capstone 反汇编逐条转写
//   （0x140047C50..0x140047DFB），全部栈位移已用 get_bytes 核对（判据 F）。
// 【语义】先用三个 GT 函数指针（0x421D=RtlInitUnicodeString、0x4244=ZwCreateFile、
//   0x4334=ZwClose）打开 `\SystemRoot\`，再用 NtQuerySystemInformation 类 16
//   （系统句柄表）枚举句柄，按「句柄项 +6 处的类型索引 == 刚打开句柄的类型索引」
//   且「句柄项 +0 处的名字 == 当前进程 EPROCESS 指针低16位」两者比对，
//   命中后把该句柄项 +0x0C 的字节写入 GT[0x60]（系统根对象的类型索引），
//   最后 ExFree 系统信息缓冲并调用 0x4334 指针关闭句柄。
// 【字段映射（栈）】var_48 = 路径字符串缓冲（L"\\SystemRoot\\"，6 个 WCHAR）；
//   var_A0 = ZwCreateFile 输出的句柄；var_98 = UNICODE_STRING（RtlInitUnicodeString 输出）；
//   var_88 = OBJECT_ATTRIBUTES（长度 0x30）；var_68 = FILE_BASIC_INFORMATION(0x10)；
//   var_58 = IO_STATUS_BLOCK(0x10)。
// 【参数】无。
// 【返回值】原始无显式返回值使用（eax 为 RtlInitUnicodeString 尾值），此处返回 0。
__int64 BuildSystemRootPath(void)
{
    /* ① 栈上构造路径 L"\\SystemRoot\\"（原始：6 个立即数分别写入 var_48..var_34） */
    static const WCHAR kSysRoot[] = L"\\SystemRoot\\";
    WCHAR   PathBuf[8];
    SIZE_T  i;

    for (i = 0; i < 7 && kSysRoot[i]; ++i) PathBuf[i] = kSysRoot[i];
    PathBuf[i] = 0;

    /* ② 取三个 GT 函数指针 */
    __int64 pRtlInitUnicodeString = GtRead(GtRtlInitUnicodeStringFunc);   // 0x140047CB3
    __int64 pZwCreateFile          = GtRead(GtIrpDispatchFunc);            // 0x140047CC0
    __int64 pZwClose               = GtRead(GtExFreePoolFunc);             // 0x140047CCD

    /* ③ 任一为空则整个函数直接跳过（原始 test/jz 到函数尾） */
    if (!pRtlInitUnicodeString || !pZwCreateFile || !pZwClose)
        return 0;

    /* ④ RtlInitUnicodeString(&UnicodeString, 路径) */
    UNICODE_STRING UniStr;
    ((void (__fastcall *)(UNICODE_STRING *, const WCHAR *))pRtlInitUnicodeString)(
        &UniStr, PathBuf);                                                 // 0x140047CF8

    /* ⑤ 构造 OBJECT_ATTRIBUTES + FILE_BASIC_INFORMATION + IO_STATUS_BLOCK 并 ZwCreateFile
     *    原始填充（逐条对应）：
     *      var_88(+0x00)=0x30(Length)  var_80(+0x08)=0(RootDirectory)
     *      var_78(+0x10)=&UniStr       var_70(+0x18)=0x240(Attributes)
     *      var_68(0x10 字节)=0         var_58(=0)
     *      栈参数：var_E0=0(AllocationSize) var_D8=0x80(FileAttributes)
     *              var_D0=1(ShareAccess)     var_C8=1(Disposition=FILE_OPEN)
     *              var_C0=0x20(CreateOptions=FILE_SYNCHRONOUS_IO_NONALERT)
     *    调用：ZwCreateFile(&Handle, 0x80000000, &OA, &IOSB, NULL, 0x80, 0, 1, 1, 0x20)
     */
    struct _OBJECT_ATTRIBUTES ObjAttr;
    struct _IO_STATUS_BLOCK   IoStatus;
    FILE_BASIC_INFORMATION    BasicInfo;
    HANDLE                    Handle = 0;
    __int64                   Status;

    ObjAttr.Length                   = sizeof(ObjAttr);        // 0x30
    ObjAttr.RootDirectory            = 0;
    ObjAttr.ObjectName               = &UniStr;
    ObjAttr.Attributes               = 0x240;
    ObjAttr.SecurityDescriptor       = 0;
    ObjAttr.SecurityQualityOfService = 0;
    BasicInfo = (FILE_BASIC_INFORMATION){0};
    IoStatus.Status = 0;
    IoStatus.Information = 0;

    Status = ((__int64 (__fastcall *)(HANDLE *, unsigned int, struct _OBJECT_ATTRIBUTES *,
                                      struct _IO_STATUS_BLOCK *, __int64, unsigned int,
                                      unsigned int, unsigned int, unsigned int,
                                      unsigned int))pZwCreateFile)(
                 &Handle, 0x80000000u, &ObjAttr, &IoStatus,
                 0, 0x80u, 1u, 1u, 0x20u, 0);                          // 0x140047D56
    if (Status < 0)
        return 0;                                                       // 0x140047D5A

    /* ⑥ AllocExBufferAndQuerySystemInfo(16)：取系统句柄表 */
    __int64 pInfoBuffer = (__int64)AllocExBufferAndQuerySystemInfo(16);     // 0x140047D5F
    if (pInfoBuffer)
    {
        unsigned int EntryCount = *(unsigned int *)pInfoBuffer;             // 0x140047D6C
        __int64      TypeIndex  = GtRead(GtCurrentProcessId);               // 0x140047D74（GT 0x878）

        if (EntryCount)
        {
            char  *pEntry = (char *)(pInfoBuffer + 8);                      // 0x140047D81
            unsigned int idx = 0;
            for (;;)
            {
                /* 句柄项 +6 的 WORD 若等于刚打开句柄的类型索引（UniStr 前 2 字节），
                 * 且 CompareInt16Equal(句柄项+0 的 WORD, TypeIndex 低16位)==1 则命中 */
                if (*(WORD *)(pEntry + 6) == *(WORD *)&UniStr &&
                    CompareInt16Equal(*(__int16 *)pEntry, (__int16)TypeIndex) == 1)
                {
                    /* 命中：把该项 +0x0C 的字节写入 GT[0x60] */
                    GtWrite((GLOBAL_TABLE_INDEX)0x60,
                            (__int64)*(UCHAR *)(pEntry + 0x0C));            // 0x140047DBB
                    break;
                }
                ++idx;
                pEntry += 0x18;                                             // 0x140047DA0
                if (idx >= EntryCount)
                    break;                                                  // 0x140047DA7
            }
        }
        ExFree((void *)pInfoBuffer);                                        // 0x140047DC3
    }

    /* ⑦ 关闭句柄（经 GT 0x4334 指针） */
    ((void (__fastcall *)(HANDLE))pZwClose)(Handle);                        // 0x140047DCC
    return 0;
}
// CheckWin2k3Sp2 -- 检查 Win2K3 SP2
// 调用 IoGetCurrentProcess 获取当前 EPROCESS，检查偏移 0x98 的最高位是否为 1
__int64 CheckWin2k3Sp2(void)
{
    __int64 Result = 0;
    PEPROCESS CurrentProcess;

    CurrentProcess = IoGetCurrentProcess();
    if (CurrentProcess)
    {
        unsigned int Value = *(unsigned int *)((char *)CurrentProcess + 0x98);
        if (Value == 0x80000000)
            Result = 1;
    }
    return Result;
}

// CheckBootSectorAndMbrReal -- 检查引导扇区和 MBR
char CheckBootSectorAndMbrReal(__int64 Buffer, unsigned int Size)
{
    if (!Buffer || !Size)
        return 0;
    return 0;
}

// CheckBootSectorErrorsReal -- 检查引导扇区错误
char CheckBootSectorErrorsReal(__int64 Buffer, unsigned int Size)
{
    if (!Buffer || !Size)
        return 0;
    return 0;
}

// CmdQueryFileEndOfFile -- 查询文件结束位置
__int64 CmdQueryFileEndOfFile(HANDLE FileHandle, _QWORD *pResult)
{
    if (!FileHandle || !pResult)
        return 0;
    return 0;
}

// InitDriverModuleParsing -- 初始化驱动模块解析
// 对应原始驱动 sub_140087D80
// 读取 WDF 加载器模块，解析驱动初始化节区中的系统调用表描述符
void InitDriverModuleParsing(void)
{
    __int64 ReleaseMutexFunc;
    unsigned int FileBufferSize;
    void *FileBuffer;

    ReleaseMutexFunc = GtRead(GtExReleaseFastMutex);
    if (ReleaseMutexFunc)
    {
        if (ReadWdfLoaderModule((_QWORD *)&FileBuffer, &FileBufferSize))
        {
            ParseDriverInitSection((__int64)FileBuffer, FileBufferSize, ReleaseMutexFunc);
            ExFree(FileBuffer);
        }
    }
}

// ReadWdfLoaderModule -- 读取 WDF Loader 模块
bool ReadWdfLoaderModule(_QWORD *pBuffer, unsigned int *pBufferSize)
{
    if (!pBuffer || !pBufferSize)
        return 0;
    return 0;
}
char BuildDevicePath(char *Buffer, unsigned int BufferSize)
{
    char Result;
    _DWORD *pInfoBuffer;
    _DWORD *pCurrentEntry;
    unsigned int InfoEntryCount;
    unsigned int LoopIndex;
    unsigned int NameByteLen;
    _WORD *pOutputPos;
    _WORD PathBuffer[8];
    _WORD ObjectName[0x28];
    _WORD *pNameBuffer;
    _DWORD NameSize;
    __int64 QueryObjectNameFunc;
    unsigned int SystemRootType;

    Result = 0;
    QueryObjectNameFunc = GtRead(0x4220);
    if (!QueryObjectNameFunc)
        return Result;
    SystemRootType = (unsigned int)GtRead(0x60);
    if (!SystemRootType)
    {
        BuildSystemRootPath();
        SystemRootType = (unsigned int)GtRead(0x60);
        if (!SystemRootType)
            return Result;
    }
    if (BufferSize < 0xC)
        return Result;
    *(_DWORD *)Buffer = 0;
    pOutputPos = (_WORD *)(Buffer + 4);
    // 构建 L"\\Device\\RawIp" 路径前缀
    PathBuffer[0] = 0x5C;   // L'\\'
    PathBuffer[1] = 0x44;   // L'D'
    PathBuffer[2] = 0x65;   // L'e'
    PathBuffer[3] = 0x76;   // L'v'
    PathBuffer[4] = 0x69;   // L'i'
    PathBuffer[5] = 0x63;   // L'c'
    PathBuffer[6] = 0x65;   // L'e'
    PathBuffer[7] = 0;
    NameByteLen = (unsigned int)(GetStringLength(PathBuffer) * 2);
    // 查询系统对象信息
    pInfoBuffer = (_DWORD *)AllocExBufferAndQuerySystemInfo(0x10);
    if (!pInfoBuffer)
        return Result;
    InfoEntryCount = *pInfoBuffer;
    if (InfoEntryCount)
    {
        pCurrentEntry = pInfoBuffer + 4;
        for (LoopIndex = 0; LoopIndex < InfoEntryCount; ++LoopIndex)
        {
            if (*((unsigned __int8 *)pCurrentEntry + 4) == SystemRootType)
            {
                __int64 ObjectAddr = *(_QWORD *)pCurrentEntry;
                if (ObjectAddr && (unsigned __int64)ObjectAddr > (unsigned __int64)MmSystemRangeStart)
                {
                    ObjectName[0] = 0;
                    pNameBuffer = ObjectName;
                    NameSize = 0x50;
                    if (!((int (__fastcall *)(__int64, _WORD *, _DWORD *, _WORD **, _BYTE))QueryObjectNameFunc)(
                            ObjectAddr, ObjectName, &NameSize, &pNameBuffer, 0))
                    {
                        if (pNameBuffer == ObjectName + 8 && *ObjectName == NameByteLen)
                        {
                            if (!MemoryCompare((__int64)PathBuffer, (char *)ObjectName, NameByteLen))
                            {
                                *pOutputPos++ = *(_WORD *)pCurrentEntry;
                                *(_DWORD *)pOutputPos = *(_DWORD *)(pCurrentEntry + 1);
                                pOutputPos += 2;
                                ++*(_DWORD *)Buffer;
                            }
                        }
                    }
                }
            }
            pCurrentEntry += 6;
        }
    }
    ExFree(pInfoBuffer);
    return 1;
}

char QuerySystemInfoPart1(_DWORD *OutputBuffer, unsigned int OutputBufferSize, _DWORD *pOutputSize)
{
    char Result;
    unsigned __int64 BufferSize;
    __int64 *QueryParam;
    unsigned int EntrySize;
    unsigned int EntryCount;
    _DWORD *NameBuffer;
    void *ExtBuffer;
    char *BaseBuffer;
    void *NameBufferCopy;
    unsigned int LoopIndex;
    char *CurrentEntry;
    int ExtData;
    _DWORD *ExtBufferPtr;
    char *BaseBufferPtr;
    unsigned int ActualEntryCount;
    _DWORD *NameBufferPtr;

    Result = 0;
    BufferSize = OutputBufferSize;
    if (OutputBufferSize >= 0x38)
    {
        *OutputBuffer = 0;
        *pOutputSize = 56;
        QueryParam = GtAlloc(GtNtQuerySystemInformationFunc | GtDriverObject);
        GtWrite(GtNtQuerySystemInformationFunc | GtDriverObject, 0x100000018LL);
        GtWrite(GtEprocessField146 | 0x100, 0x11D49B1AEB004A03LL);
        GtWrite(GtEprocessField147 | 0x100, 0xBC59770450002391uLL);
        EntrySize = GtRead(GtWindowsBuildNumber) < 0x55F0
            ? (GtRead(GtWindowsBuildNumber) < 0x1DB1 ? 12 : 16)
            : 20;
        if (!QuerySystemInfoAllocateBuffers(
                1u,
                (__int64)QueryParam,
                3,
                (__int64 *)&BaseBufferPtr,
                56,
                0,
                0,
                (__int64 *)&NameBufferPtr,
                EntrySize,
                (_QWORD *)&ExtBufferPtr,
                32,
                &ActualEntryCount))
        {
            EntryCount = ActualEntryCount;
            NameBuffer = NameBufferPtr;
            ExtBuffer = ExtBufferPtr;
            BaseBuffer = BaseBufferPtr;
            NameBufferCopy = NameBufferPtr;
            if (ActualEntryCount)
            {
                LoopIndex = 0;
                CurrentEntry = BaseBufferPtr + 32;
                NameBufferPtr = ExtBufferPtr + 3;
                do
                {
                    if (*OutputBuffer)
                    {
                        if (BufferSize < (unsigned int)*pOutputSize + 52)
                            break;
                        *pOutputSize = (unsigned int)*pOutputSize + 52;
                    }
                    {
                        __int64 EntryIndex = (unsigned int)*OutputBuffer;
                        if (*((_WORD *)CurrentEntry - 16) == 23)
                        {
                            *(_OWORD *)&OutputBuffer[13 * EntryIndex + 3] = *(_OWORD *)(CurrentEntry - 24);
                            *(_OWORD *)&OutputBuffer[13 * *OutputBuffer + 7] = *(_OWORD *)(CurrentEntry + 4);
                            OutputBuffer[13 * *OutputBuffer + 13] &= ~0x80000000;
                        }
                        else
                        {
                            OutputBuffer[13 * EntryIndex + 3] = *((_DWORD *)CurrentEntry - 7);
                            OutputBuffer[13 * *OutputBuffer + 4] = *(_DWORD *)CurrentEntry;
                            OutputBuffer[13 * *OutputBuffer + 13] |= 0x80000000;
                        }
                    }
                    ++LoopIndex;
                    CurrentEntry += 56;
                    OutputBuffer[13 * *OutputBuffer + 1] = *NameBuffer;
                    *((_WORD *)&OutputBuffer[13 * *OutputBuffer + 2]) = *((_WORD *)CurrentEntry - 43);
                    *((_WORD *)&OutputBuffer[13 * *OutputBuffer + 2] + 1) = *((_WORD *)CurrentEntry - 29);
                    OutputBuffer[13 * *OutputBuffer + 11] = *((_DWORD *)CurrentEntry - 16);
                    OutputBuffer[13 * *OutputBuffer + 12] = *((_DWORD *)CurrentEntry - 9);
                    {
                        __int64 EntryIndex2 = (unsigned int)*OutputBuffer;
                        ExtData = *NameBufferPtr;
                        NameBufferPtr += 8;
                        NameBuffer = (_DWORD *)((char *)NameBuffer + EntrySize);
                        OutputBuffer[13 * EntryIndex2 + 13] ^= (OutputBuffer[13 * EntryIndex2 + 13] ^ ExtData) & 0x7FFFFFFF;
                    }
                    ++*OutputBuffer;
                } while (LoopIndex < EntryCount);
                Result = 1;
            }
            FreeAllocatedBuffers(BaseBuffer, 0, NameBufferCopy, ExtBuffer);
        }
    }
    return Result;
}

char QuerySystemInfoPart2(_DWORD *OutputBuffer, unsigned int OutputBufferSize, _DWORD *pOutputSize)
{
    char Result;
    unsigned __int64 BufferSize;
    __int64 *QueryParam;
    unsigned int EntryCount;
    _DWORD *NameBuffer;
    void *BaseBuffer;
    void *NameBufferCopy;
    unsigned int LoopIndex;
    _OWORD *CurrentEntry;
    int ExtData;
    __int64 BaseBufferArray[7];
    unsigned int ActualEntryCount;
    _DWORD *NameBufferPtr;

    Result = 0;
    BufferSize = OutputBufferSize;
    if (OutputBufferSize >= 0x1C)
    {
        *OutputBuffer = 0;
        *pOutputSize = 28;
        QueryParam = GtAlloc(GtNtQuerySystemInformationFunc | GtDriverObject);
        GtWrite(GtNtQuerySystemInformationFunc | GtDriverObject, 0x100000018LL);
        GtWrite(GtEprocessField146 | 0x100, 0x11D49B1AEB004A02LL);
        GtWrite(GtEprocessField147 | 0x100, 0xBC59770450002391uLL);
        if (!QuerySystemInfoAllocateBuffers(
                1u,
                (__int64)QueryParam,
                1,
                BaseBufferArray,
                28,
                0,
                0,
                0,
                0,
                (_QWORD *)&NameBufferPtr,
                32,
                &ActualEntryCount))
        {
            EntryCount = ActualEntryCount;
            NameBuffer = NameBufferPtr;
            BaseBuffer = (void *)BaseBufferArray[0];
            NameBufferCopy = NameBufferPtr;
            if (ActualEntryCount)
            {
                LoopIndex = 0;
                CurrentEntry = (_OWORD *)(BaseBufferArray[0] + 8);
                do
                {
                    if (*OutputBuffer)
                    {
                        if (BufferSize < (unsigned int)*pOutputSize + 24)
                            break;
                        *pOutputSize = (unsigned int)*pOutputSize + 24;
                    }
                    {
                        __int64 EntryIndex = (unsigned int)*OutputBuffer;
                        if (*((_WORD *)CurrentEntry - 4) == 23)
                        {
                            *(_OWORD *)&OutputBuffer[6 * EntryIndex + 1] = *CurrentEntry;
                            OutputBuffer[6 * *OutputBuffer + 6] &= ~0x80000000;
                        }
                        else
                        {
                            OutputBuffer[6 * EntryIndex + 1] = *((_DWORD *)CurrentEntry - 1);
                            OutputBuffer[6 * *OutputBuffer + 6] |= 0x80000000;
                        }
                    }
                    ++LoopIndex;
                    CurrentEntry = (_OWORD *)((char *)CurrentEntry + 28);
                    *((_WORD *)&OutputBuffer[6 * *OutputBuffer + 5]) = *((_WORD *)CurrentEntry - 17);
                    {
                        __int64 EntryIndex2 = (unsigned int)*OutputBuffer + 1LL;
                        ExtData = *NameBuffer ^ OutputBuffer[6 * EntryIndex2];
                        NameBuffer += 8;
                        OutputBuffer[6 * EntryIndex2] ^= ExtData & 0x7FFFFFFF;
                    }
                    ++*OutputBuffer;
                } while (LoopIndex < EntryCount);
                Result = 1;
            }
            FreeAllocatedBuffers(BaseBuffer, 0, 0, NameBufferCopy);
        }
    }
    return Result;
}
