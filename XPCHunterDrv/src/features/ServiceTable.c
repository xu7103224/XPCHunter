// MissingFuncs.c — 暂未分配到各源文件的函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"

// C4700 抑制：各种函数中变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)
#include <intrin.h>

// 前向声明 — 定义在 Protocol.c 中
extern NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// 前向声明 — 内部辅助函数
extern char OpenDeviceTarget(__int64 EncodedPath, __int64 *pDeviceHandle, __int64 *pDeviceObjectHandle);
extern __int64 GetDeviceObjectFromContext(__int64 DeviceHandle);
extern char GetDiskDriverInfo(char State, void *pBuffer, __int64 *pFuncTable);
extern char SetDiskDriverInfo(char State, char Flags, void *pBuffer);
extern char FindPeSectionByType0x510(__int64 Base, unsigned int Size, int SectionType, unsigned int SectionFlags);
extern char FindPeSectionByTypeRsrc(__int64 Buffer, unsigned int Size, __int64 Address);
extern char FindPatchThreadWindowsExport(__int64 FileBuffer, unsigned int FileSize);
extern void QueryProcessModuleFilePath(__int64 ProcessId, __int64 Address, _WORD *pBuffer, unsigned int MaxLen);
extern __int64 ResolveKernelModuleIndexAddress(int ModuleId, int GtIndex);
extern __int64 ResolveAndStoreKernelModuleAddress(int ModuleId, int GtIndex);
extern __int64 ReadIoPortDataForProcess(__int64 CpuIndex, __int64 IoPortContext);
extern char BuildFsFilterDriverPath1(void);
extern char BuildFsFilterDriverPath2(void);
extern __int64 ReadWriteKernelMemory(void);

// =======================================================================
// 简单函数实现
// =======================================================================

char ParseServiceTableWin7(char *Src, size_t MaxCount)
{
    char Result;
    unsigned int ServiceCount;
    _DWORD *ServiceTable;
    _DWORD *ServiceTableCopy;
    unsigned __int64 ImageBase;
    unsigned int Win32kServiceTable;
    unsigned __int64 TableSize;
    char *ServiceTablePtr;
    unsigned int EntryIndex;
    _DWORD *CurrentEntry;
    unsigned __int64 FuncAddr;

    Result = 0;
    VerifyServiceTableDriverFile((__int64)Src, MaxCount);
    ServiceCount = GtRead(GtEprocessField57);
    if (ServiceCount)
    {
        if (!(unsigned int)GtRead(GtCallbackField53))
        {
            ServiceTable = (_DWORD *)ExAlloc(PagedPool, 4LL * ServiceCount);
            ServiceTableCopy = ServiceTable;
            if (ServiceTable)
            {
                memset(ServiceTable, 0, 4LL * ServiceCount);
                ImageBase = *(_QWORD *)&Src[*((int *)Src + 15) + 48];
                Win32kServiceTable = FindWin32kServiceTable((__int64)Src, (unsigned int)MaxCount);
                if (!Win32kServiceTable)
                    goto LABEL_FREE;
                if (Win32kServiceTable >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                TableSize = 8LL * ServiceCount;
                if (TableSize >= (unsigned int)MaxCount || Win32kServiceTable + TableSize >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                ServiceTablePtr = &Src[Win32kServiceTable];
                if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600)
                {
                    FuncAddr = *(_QWORD *)&ServiceTablePtr[8 * (ServiceCount - 1)];
                    if (FuncAddr <= ImageBase || (unsigned int)MaxCount + ImageBase <= FuncAddr)
                    {
                        --ServiceCount;
                        GtWrite(GtEprocessField57, ServiceCount);
                        GtWrite(GtEncryptionKeyByte | GtPathBuffer04, (unsigned int)(GtRead(GtEncryptionKeyByte | GtPathBuffer04) - 1));
                    }
                }
                EntryIndex = 0;
                if (ServiceCount)
                {
                    CurrentEntry = ServiceTableCopy;
                    do
                    {
                        FuncAddr = *(_QWORD *)ServiceTablePtr;
                        if (*(_QWORD *)ServiceTablePtr <= ImageBase || (unsigned int)MaxCount + ImageBase <= FuncAddr)
                            break;
                        ++EntryIndex;
                        ServiceTablePtr += 8;
                        *CurrentEntry++ = FuncAddr - ImageBase;
                    } while (EntryIndex < ServiceCount);
                    if (EntryIndex < ServiceCount)
                        goto LABEL_FREE;
                }
                if (ParseServiceTableExportEntry(Src, (unsigned int)MaxCount, (__int64)ServiceTableCopy) == 1)
                {
                    GtWrite(GtIrpBufferSize | GtEprocessField14, (__int64)ServiceTableCopy);
                    return 1;
                }
                else
                {
LABEL_FREE:
                    ExFree(ServiceTableCopy);
                }
            }
        }
    }
    return Result;
}

char ParseServiceTableWin8(char *Src, size_t MaxCount)
{
    char Result;
    unsigned int ServiceCount;
    unsigned __int64 TableSize;
    unsigned int *ServiceTable;
    unsigned int *ServiceTableCopy;
    unsigned int Win32kServiceTable;
    unsigned int EntryIndex;
    unsigned int *CurrentEntry;
    char *ServiceTablePtr;
    unsigned int FuncValue;

    Result = 0;
    VerifyServiceTableDriverFile((__int64)Src, MaxCount);
    ServiceCount = GtRead(GtEprocessField57);
    if (ServiceCount)
    {
        if (!(unsigned int)GtRead(GtCallbackField53))
        {
            TableSize = 4LL * ServiceCount;
            ServiceTable = (unsigned int *)ExAlloc(PagedPool, TableSize);
            ServiceTableCopy = ServiceTable;
            if (ServiceTable)
            {
                memset(ServiceTable, 0, 4LL * ServiceCount);
                Win32kServiceTable = FindWin32kServiceTable((__int64)Src, (unsigned int)MaxCount);
                if (!Win32kServiceTable)
                    goto LABEL_FREE;
                if (Win32kServiceTable >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                if (TableSize >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                if (Win32kServiceTable + TableSize >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                EntryIndex = 0;
                CurrentEntry = ServiceTableCopy;
                ServiceTablePtr = (char *)(&Src[Win32kServiceTable] - (char *)ServiceTableCopy);
                do
                {
                    FuncValue = *(unsigned int *)((char *)CurrentEntry + (__int64)ServiceTablePtr);
                    if (!FuncValue)
                        break;
                    if ((unsigned int)MaxCount <= FuncValue)
                        break;
                    ++EntryIndex;
                    *CurrentEntry++ = FuncValue;
                } while (EntryIndex < ServiceCount);
                if (EntryIndex >= ServiceCount && ParseServiceTableExportEntry(Src, (unsigned int)MaxCount, (__int64)ServiceTableCopy) == 1)
                {
                    GtWrite(GtIrpBufferSize | GtEprocessField14, (__int64)ServiceTableCopy);
                    return 1;
                }
                else
                {
LABEL_FREE:
                    ExFree(ServiceTableCopy);
                }
            }
        }
    }
    return Result;
}
