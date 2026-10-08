#pragma once

// ============================================================
// XPCHunterDrv.h — PCHunter 内核驱动主头文件（伞形头）
// 1:1 复刻 View++_Driver64.sys (Linxer)
// ============================================================

#include "xpc_basic.h"
#include "xpc_gt_enum.h"
#include "xpc_ioctl.h"
#include "xpc_structs.h"

// ============================================================
// 全局函数声明
// ============================================================

// ===== Auto-generated function declarations =====
void AcquireMiniFilterMutex(void);
void AcquireMiniFilterMutexEx(void);
char AcquireVolumeChangeLock(__int64 DeviceObject);
__int64 AdjustKernelModuleSectionPointers(void);
__int64 __fastcall AllocBufferAndQuerySystemInfo( __int64 (__fastcall *QueryFunc)(__int64, __int64, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *),

    __int64 Arg2,
    __int64 Arg3,
    int Arg4,
    _BYTE *OutputBuffer,
    SIZE_T BufferSize,
    size_t *ReturnSize);
void *AllocExBufferAndQuerySystemInfo(unsigned int SystemInformationClass);

__int64 AllocateIrpStackAndCallDriver(__int64 (*pCallDriver)(__int64, ULONG_PTR, __int64), __int64 DeviceObject, ULONG_PTR Irp);
__int64 AllocateNtHandleEntry(void);
char AtomicExchange16Bytes(__int64 Source, _OWORD *ExchangeData);
char AtomicWrite16Bytes(ULONG64 Context, void *Buffer);
__int64 AtomicWrite64NoWriteProtect(volatile __int64 *Target, __int64 Value);
__int32 AtomicWrite32NoWriteProtect(volatile __int32 *Target, __int32 Value);
// InterlockedExchange / InterlockedExchange64 使用 WDK 宏（_InterlockedExchange 族），不在此声明
ULONG64 CopyMemoryNoWriteProtect(void *Destination, const void *Source, ULONG Size);
__int64 AttachToProcessAndInitKernelMemory(void);
char __fastcall BtreeSearchByKey(unsigned __int8 *pKeyData, unsigned int *pOutOrdinal, unsigned int EntryCount);
char BugcheckCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, ULONG64 OutputBuffer);

void BuildContextTableFromNtFile(void);
__int64 BuildDriverInfoEntries(unsigned int *EntryArray, unsigned int BufferSize);

__int64 BuildExportIndexTable( __int64 PeBase, unsigned int PeSize, _BYTE *OutTable, unsigned int MaxEntries, unsigned char (__fastcall *FilterFunc)(__int64));

char BuildExportServiceTable(PUCHAR ImageBase, ULONG ImageSize, PUCHAR ServiceTable, ULONG TableSize);
char BuildExportServiceTableForProcess( __int64 ImageBase, struct _KPROCESS *TargetProcess, char Is64Bit, _QWORD *OutServiceTable);

void BuildHookTable(void);
char BuildJmpPatchStub(int PatchBase, __int64 TargetAddress, __int64 StubBuffer, unsigned int BufferSize, int Flags);
__int64 BuildPeServiceNumberTable(__int64 ImageBase, unsigned int ImageSize, unsigned int ServiceTableOffset, char Is64Bit);

__int64 BuildServiceTableFromNtKernel(_QWORD PeFileBuffer, _QWORD PeFileSize);
__int64 BuildSyscallDriverPath(void);
__int64 CalcDiskPartitionOffset(int *PartitionEntry, unsigned int EntryCount);
__int64 CalcOpcodeSize(PUCHAR DecodeCtx, PULONG OperandInfo);
__int64 CalcPESectionFieldSize(PUCHAR Context);
__int64 CalcPESectionFieldSizeAlt(PUCHAR Context);
unsigned int __fastcall CalcSectionAlignedSize(unsigned __int64 Address, unsigned __int64 LimitAddress);
unsigned int __fastcall CalcSectionRangeSize(unsigned __int64 StartAddress, unsigned __int64 EndAddress);
char CallKernelCleanupEntryV3(_QWORD *VirtualAddress);
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
    PULONG pReturnLength);
char CheckAddressInModuleRange(__int64 TargetAddress);
char CheckAddressInPhysicalMemoryRange(unsigned __int64 Address);
char CheckAddressInSystemModuleRange(unsigned __int64 Address);
char CheckExportEntryFlags(PUCHAR ExportEntry);
char __fastcall CheckExportNamePrefixCombined(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize);
char __fastcall CheckExportNamePrefixWin10V2(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize);
__int64 CheckFilePathFilter(__int64 FilePath, unsigned int FilePathLength);
BOOLEAN CheckMemoryValid(void *Address);
char CheckObjectTypeFlag(__int64 ObjectHeader);
char CheckObjectTypeFlagWrapper(__int64 ObjectHeader);
char *ValidateAddressWithSize(char *VirtualAddress);
__int64 CheckProcessJobObject(__int64 ProcessHandle);
__int64 CheckProcessObjectFlag(__int64 ProcessObject);
char CheckProcessProtection(__int64 ProcessObject, _DWORD *OutProtectionType);
__int64 CheckProtectedEntry(__int64 Entry);
char CheckSsdtHookIntegrity(ULONG64 ProcessId, ULONG64 BufferSize, _DWORD *OutputBuffer, int OutputSize);
char CheckVolumeFileExists(PUNICODE_STRING FileName, __int64 VolumeContext);
bool CheckHandleEntryValid(__int64 Process);
BOOLEAN CheckVmxEnabled(void);
__int64 CheckWin2k3Sp2(void);
char __fastcall ClassifyModuleTypeHalOrNt(const char *ModuleName, __int64 *pExportDirBase, unsigned int *pExportDirCount);
__int64 __fastcall BtreeInsertExportEntry(unsigned __int8 *Name, int Ordinal, unsigned int Key);
_DWORD *BtreeBufferAllocator(__int64 *pAllocator, unsigned int RequestSize, unsigned int BlockSize);
_DWORD *RBTreeInsertFixup(__int64 Node, _QWORD *Root);
__int64 __fastcall RBTreeRotateLeft(__int64 Node, _QWORD *Root);
__int64 __fastcall RBTreeRotateRight(__int64 Node, _QWORD *Root);
char __fastcall CheckExportNamePrefixWin10(_BYTE *pBuffer1, char *pBuffer2, unsigned int CompareSize);
_DWORD *SkipContextEntries(_DWORD *ContextEntry);
char __fastcall FindContextEntry(__int64 TargetObject, _DWORD *ContextTable);
void CleanupHashTable(void);
__int64 CleanupNtoskrnlFile(void);
__int64 CleanupProcessMemoryEntry(_QWORD *pTargetEntry);
char CleanupProcessThreads(struct _KPROCESS *Process, unsigned int *OutputBuffer, unsigned int BufferSize);
void CleanupThreadWithBuffer(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 ClearDebugRegisters(void);
char ClearKernelMemoryPointer(void);
__int64 ClearKernelObjectEntry(__int64 TargetAddress);
__int64 ClearImageNotifySectionOffset(void);
__int64 ClearSsdtRelatedEntry(__int64 TargetAddress);
__int64 CmdCallKernelMemoryFunction(unsigned int *Address, int InputSize);
__int64 CmdCallSystemRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCallbackControl(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCheckBytePattern(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCheckFileExist(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCheckProcessAccess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCheckProcessHideDetect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdClearKernelBase(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCloseHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCloseProcessHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int BufferSize);
char CmdCloseProcessHandleEx(__int64 InputBuffer);
__int64 CmdCopyFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCreateFile(_QWORD *Address, int InputSize);
__int64 CmdCreateFileWithPath(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDeleteFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDeviceIoControl(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDeviceIoControlEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDeviceIoControlSimple(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDeviceIoControlWithBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDeviceIoControlWithString(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDiskOperationDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDiskReadSector(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDiskSectorReadWrite(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDispatchSsdtByVersion(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdDriverLoadUnload(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDriverProtectOp(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDriverProtectStatus(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumCallbackContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
char CmdEnumDriverObjects(unsigned int *pOutputBuffer, unsigned int OutputSize, char Flags, char Flags2);
__int64 CmdEnumFileSystemContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumGdiObjects(__int64 InputBuffer, __int64 InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumHandles(__int64 InputBuffer, __int64 InputSize, volatile void *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumHandlesByPid(volatile void *Address, SIZE_T Length, char *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumHookDetail(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumHookInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelDriver(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelDrivers(__int64 InputBuffer, __int64 InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumKernelHandleTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelMemoryDetail(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelModuleInfoEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelModules(_OWORD *Address, int InputSize, volatile void *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumKernelObjectTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectAllTypes(__int64 OutputBuffer, __int64 OutputSize, char *UserBuffer, unsigned int UserBufferSize);
__int64 CmdEnumObjectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectHandles(__int64 InputBuffer, __int64 InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumObjectTypeDetail(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectTypeDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectTypeInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectTypeTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectTypes(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjects(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumObjectsEx(__int64 InputBuffer, unsigned int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 CmdEnumObjectsLegacy(__int64 InputBuffer, unsigned int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 CmdEnumProcessContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessContextWin7(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessContextWin8(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessHandles(__int64 Address, int InputSize, _DWORD *OutputBuffer, unsigned int OutputBufferSize);
__int64 CmdEnumProcessListEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessListWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessListWin7(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessListWin8(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessModules(__int64 DeviceObject, __int64 Irp, _DWORD *pOutputBuffer, unsigned int BufferSize);
__int64 CmdEnumProcessProtectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumProcessorInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumRegistry(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumRegistryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumServiceTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumServices(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumShadowSyscallEntries(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSsdtEntryTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputBufferSize);
__int64 CmdEnumSyscallEntries(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable2(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable3(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable4(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable5(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable6(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable7(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable8(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable9(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumThreadContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumThreads(char **InputBuffer, int InputSize, _DWORD *OutputBuffer, int OutputSize);
__int64 CmdEnumThreadsEx(void **Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumUSBPortSyscallTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdFixProcessEProcess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdFixSsdtEntryAddress(unsigned int *pSyscallIndex, int FieldSize);
__int64 CmdFsctlOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdGetHookEntryInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdGetKernelBaseLegacy(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdGetModuleCount(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdGetSsdtTableInfo(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 CmdHandleMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdInitKernelMemoryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdInitSsdtTable(__int64 InputBuffer, __int64 InputSize, _DWORD *OutputBuffer, int BufferSize);
__int64 CmdInstallShadowHook(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook2(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook3(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook4(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook5(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook6(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook7(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook8(char *pInputBuffer, int InputSize);
__int64 CmdInstallSyscallHook9(char *pInputBuffer, int InputSize);
__int64 CmdInstallSystemHook(char *pInputBuffer, int InputSize);
__int64 CmdInstallUSBPortSyscallHook(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdIoPortOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdKernelMemoryOpDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdKernelMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdKernelObjectMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdLookupObjectTypeByAddr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdMemoryQueryOp(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdModuleOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdObjectOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);

__int64 CmdObjectOperationDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdOpenFileForEnum(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdOpenFileHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdOpenSectionObject(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdProcessMemoryOpDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdProcessMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdProcessMonitor(_OWORD *Address, int InputSize);
__int64 CmdProcessOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdProtectStatus(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryDiskInfo(char *Dst, SIZE_T Length);
__int64 CmdQueryFileAllocationSize(void *FileHandle, _QWORD *pAllocationSize);
__int64 CmdQueryFileInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryFileStandardInfo(void *FileHandle, _QWORD *pStandardInfo);
__int64 CmdQueryHookStatus(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryMemoryInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryModuleInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryObjectInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryProcessInfo(__int64 ProcessId, __int64 BufferSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryProcessInfoEx(__int64 Address, int InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryProcessNameByPid(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQuerySsdtDetails(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 CmdQuerySsdtInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQuerySystemInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQuerySystemInfoEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQuerySystemInfoExV2(char *Dst, SIZE_T Length);
__int64 CmdReadCpuBaseAddr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadCpuBaseAddrEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadCpuId(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadCpuInfoEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadCpuMsr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadExportDirectory(__int64 InputBuffer, __int64 InputSize, char *OutputBuffer, unsigned int BufferSize);
__int64 CmdReadFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadFileInfo(void *FileHandle, _DWORD *pFileInfo);
__int64 CmdReadFileSize(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadKernelBase(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadKernelMemoryRange(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadKernelMemoryRangeSize(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadMsrValue(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadPhysicalMemory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadProcessMemory(__int64 Address, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadProcessMemoryBlock(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadProcessMemoryEx(_OWORD *Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdReadProcessMemoryStr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadSsdtEntryTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputBufferSize);
__int64 CmdReadSsdtEntryTableEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputBufferSize);
__int64 CmdRegistryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdRegistryProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdRenameFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdResetDriverState(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdResetProcessContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdRestoreDriverDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdRestoreExportTable(void);
__int64 CmdRestoreSsdtTable(void);
__int64 CmdSendRenameFileIrp(void *FileHandle, const void *RenameBuffer, unsigned int BufferSize);
__int64 CmdSetCallbackContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetFileAttributes(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetFileBasicInfo(void *FileHandle, struct _IRP *FileBasicInfo);
__int64 CmdSetFileSystemContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetKernelModuleInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetModuleInfoInternal(__int64 InputBuffer);
__int64 CmdSetObjectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetProcessContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetProcessContextWin7(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetProcessContextWin8(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetProcessProtectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetProcessorField(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetRegistryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdSetSsdtEntry(_DWORD *pInputBuffer, int InputSize);
__int64 CmdSetThreadContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdStubAlwaysTrue(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdTerminateProcessByEProcess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdThreadMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdThreadOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdThreadProtectStatus(__int64 Address, int InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdUpdateExportEntry(__int64 *pInputBuffer, int InputSize);
__int64 CmdVirtualMemoryOp(_OWORD *Address, int InputSize);
__int64 CmdWriteFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdWriteKernelMemoryRange(void);
__int64 CmdWriteKernelObjectField(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdWriteMsrValue(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdWriteProcessMemoryEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
void CollectObjectDirAndTypeEntries(unsigned int *OutputBuffer, _DWORD *pCount);
unsigned int __fastcall CompareExportNamePrefix(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned __int64 LimitAddress);
__int64 CompleteIrpAndCleanupMdl(__int64 DeviceObject, __int64 Irp, __int64 Context);
__int64 CopyCallbackContextHookTable(__int64 pSourceTable);
__int64 CopyCallbackContextTable(__int64 pSourceTable, int ContextType);
__int64 CopyCallbackContextV3Table(__int64 pSourceTable);
__int64 CopyContextTableEntries(__int64 pOutputTable);
__int64 CopyFsFilterEntryTable(__int64 OutputBuffer, char Is64Bit);
__int64 CopyHookEntryArray(__int64 DestBuffer, _QWORD *pSourceArray, unsigned int EntryCount);
__int64 CopyKernelArrayToUserBuffer(__int64 UnusedParam1, __int64 UnusedParam2, unsigned int *pOutputBuffer, unsigned int BufferSize);
__int64 CopyKernelDualArrayToUserBuffer(__int64 UnusedParam1, __int64 UnusedParam2, unsigned int *pOutputBuffer, unsigned int BufferSize);
__int64 CopyObjectContextHookTable(__int64 pSourceTable);
char CopyObjectEntryToBuffer(__int64 Entry, unsigned int Type, unsigned int Flags, unsigned int *OutputBuffer, _DWORD *pCount);
__int64 CopyPhysicalMemoryContextTable(__int64 pSourceTable, int ContextType);
__int64 CopyProcessContextTable1(__int64 pTargetTable);
__int64 CopyProcessContextTable2(__int64 pTargetTable);
__int64 CopyProcessContextTableWin7(__int64 pSourceTable);
__int64 CopyProcessContextV2HookTable(__int64 pSourceTable);
__int64 CopyProcessContextV3HookTable(__int64 pSourceTable);
__int64 CopyRegistryContextEntryArray(__int64 pOutputTable);
__int64 CopyThreadContextTable(__int64 pSourceTable);
__int64 CopyUSBPortServiceTable(__int64 pOutputBuffer);
char CopyValidServiceEntries(__int64 OutputBuffer, char Is64Bit);
__int64 CreateFileObject(__int64 UnicodeString, unsigned int DesiredAccess, int FileAttributes, USHORT ShareAccess, int Disposition, int CreateOptions, struct _DEVICE_OBJECT *DeviceObject, __int64 DeviceObjectBase, _QWORD *pFileObject);

__int64 CreateFileWithPath( __int16 *FilePath, const WCHAR *RelativePath, void **pFileHandle, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions);

__int64 DecodeCheckBound1Byte(PUCHAR *Context);
__int64 DecodeCheckBound2Byte(PUCHAR *Context);
__int64 DecodeCheckBound4Byte(PUCHAR *Context);
__int64 DecodeCheckBound8Byte(PUCHAR *Context);
__int64 DecodeImmediateOperandSize(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx, PULONG pSize);
__int64 DecodeImmediateOperandValue(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx, PULONG pSize);
__int64 DecodeModrmAddressingMode(PULONG Context, ULONG64 UnusedParam, INT OperandType, PUCHAR OperandOut, INT Flag);

__int64 DecodeModrmByte(ULONG64 BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx);
__int64 DecodeModrmByteSimple(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx);
__int64 DecodeModrmInstruction(PULONG64 ContextArray);
__int64 DecodeModrmOpcodeTable(PUCHAR Context);
__int64 DecodeMultiByteOpcode(PUCHAR Context, ULONG64 Param2, ULONG64 UnusedParam);
__int64 DecodeOneByteOpcodeTable(PUCHAR Context);
__int64 DecodeOpcodeByPrefixGroup(PUCHAR Context);
__int64 DecodeOpcodeByte(PUCHAR Context);
__int64 DecodeOpcodeReadByte(PUCHAR *Context);
__int64 DecodeOpcodeStubZero(void);
__int64 DecodeOpcodeTable16_32_64(PUCHAR Context);
__int64 DecodeOpcodeTableDirect(PUCHAR Context);
__int64 DecodeOpcodeTableGroup1(PUCHAR Context);
__int64 DecodeOpcodeTableGroup2(PUCHAR Context);
__int64 DecodeOpcodeTableGroup3(PUCHAR Context);
__int64 DecodeOpcodeTableGroup4(PUCHAR Context);
__int64 DecodeOpcodeTableGroup5(PUCHAR Context);
__int64 DecodeOpcodeTableGroup6(PUCHAR Context);
__int64 DecodeOpcodeTableWithOffset(PUCHAR Context);
__int64 DecodeOpcodeTableWithPrefix(PUCHAR Context);
__int64 DecodeOpcodeWithModrm(PUCHAR Context);
__int64 DecodeOpcodeWithPrefix(PUCHAR *Context);
__int64 DecodeOpcodeWithPrefixEx(PUCHAR *Context);
__int64 DecodeReadDwordImmediate(PUCHAR *Context);
__int64 DecodeReadImmediateValue(PUCHAR *Context);
__int64 DecodeReadQwordImmediate(PUCHAR *Context);
__int64 DecodeReadSizeDependentImmediate(PUCHAR *Context);
__int64 DecodeReadWordImmediate(PUCHAR *Context);
__int64 DecodeTwoByteOpcode0F(PUCHAR Context);
__int64 DecodeTwoByteOpcode0F38(PUCHAR Context);
__int64 DecodeTwoByteOpcode0F3A(PUCHAR Context);
char __fastcall DecodeUnicodeChar( unsigned __int8 *InputBuffer, unsigned __int64 BufferSize, _WORD *OutputChar);

__int64 __fastcall DecodeUtf8Buffer(unsigned __int8 *InputBuffer, unsigned __int64 BufferSize);
__int64 __fastcall DecodeUtf8Sequence( unsigned __int8 *InputBuffer, unsigned __int64 BufferSize, _DWORD *StateFlags, __int64 OutputStruct);

void DecryptAndCompareStrings(__int64 Process, unsigned int *OutputBuffer, unsigned int StartIndex);
__int64 DecryptDiskDeviceContextStr(void);
__int64 DecryptInputBuffer(PUCHAR Buffer);
void DereferenceObjectSafe(__int64 Object);
void DisableCr0WriteProtect(void);
__int64 DisableHookProtection(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 DisableObjectCallback(__int16 *DevicePath, _QWORD *pResult);
char __fastcall DisableObjectCallbackWithFallback(__int16 *DeviceId, _QWORD *Context);
char __fastcall DisableObjectCallbackViaDevice(__int16 *DevicePath, _QWORD *pResult);
char InstallObjectPreCallbackHooks(void);
char RestoreObjectPreCallbackHooks(void);
char __fastcall InitObjectCallbackEntries(__int64 TableBase);
char DisableObjectProtect(__int64 DeviceObject, __int64 Irp, _DWORD *OutputBuffer, unsigned int BufferSize);
char DisableObjectProtectEx(_DWORD *OutputBuffer, unsigned int BufferSize);
__int64 DisableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
char DisableProcessProtect(_OWORD *Address, int InputSize);
char DisableThreadProtect(unsigned int *Address, int ContextSize);
__int64 DiskOperationDispatcher(void *Address, unsigned int Length);
__int64 DispatchFreeProcessMemory(char *VirtualAddress);
__int64 __fastcall DispatchHookSwapByVersion(__int64 Handle, __int64 *OriginalValue);
char SendIoControlWithBufferSwap(unsigned char *PrefixDesc, unsigned char *NameDesc, unsigned char *OutputBuffer, unsigned int OutputSize);
char SendReadMemoryIoControl(unsigned char *OutFlag, __int64 IoctlHandle, unsigned char ModeByte, unsigned int Type, unsigned char *Buffer5, unsigned int BufferSize, __int64 Arg7, unsigned char Arg8, unsigned char *Address, __int64 OutBuffer10, unsigned int OutSize11);
__int64 DispatchInstructionDecode( ULONG64 BufferPos, ULONG64 BufferEnd, ULONG64 TableEntry, ULONG64 DecodeCtx);

__int64 __fastcall DispatchIoControlByBuildNumber( __int64 (__fastcall *HandlerFunc)(__int64, __int64),

    __int64 Arg2,
    __int64 Arg3,
    unsigned __int8 Arg4,
    unsigned int Arg5);
__int64 __fastcall DispatchIoControlForServer2022(
    __int64 (__fastcall *IoControlFunc)(__int64, _QWORD, __int64, _QWORD, __int64, char),
    __int64 DeviceHandle, unsigned int IoControlCode, __int64 InputBuffer,
    unsigned int Arg5, __int64 Arg6, char Arg7);
char __fastcall SendIoControlWithVersionCheck(__int64 DeviceHandle, unsigned int IoControlCode, __int64 InputBuffer);
__int64 __fastcall SendIoControlWithQuotaBuffer(
    __int64 (__fastcall *HandlerFunc)(__int64, __int64, _QWORD, _QWORD, _BYTE *, _DWORD, size_t *),
    __int64 Arg2, __int64 Arg3, unsigned int Arg4, unsigned int Arg5,
    _BYTE *Dst, SIZE_T NumberOfBytes, size_t *pOutSize);
// 【签名 2026-09-30】双缓冲版：处理函数 9 参，需额外一个"输入字符串"缓冲。
//   a3 是输入描述符（+0 = WORD 长度、+8 = 数据指针）。
__int64 __fastcall AllocDualBufferAndSendIoControl(
    __int64 (__fastcall *a1)(__int64, _WORD *, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *, _BYTE *),
    __int64 a2, const void **a3, int a4, _BYTE *a5, SIZE_T NumberOfBytes, size_t *a7);
__int64 __fastcall AllocBufferAndSendIoControl(
    __int64 (__fastcall *a1)(__int64, __int64, _QWORD, _QWORD, int, _BYTE *, _DWORD, size_t *, _QWORD),
    __int64 a2, __int64 a3, unsigned int a4, int a5,
    _BYTE *Dst, SIZE_T NumberOfBytes, size_t *a8);
__int64 __fastcall SendIoControlWithQuotaBufferEx(
    __int64 (__fastcall *HandlerFunc)(__int64, _QWORD, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *),
    __int64 Arg2, unsigned int Arg3, int Arg4,
    _BYTE *Dst, SIZE_T NumberOfBytes, size_t *pOutSize);
__int64 DispatchKernelMemoryCleanup(_QWORD *VirtualAddress);
__int64 DispatchParseNtExportFunctions(void);
__int64 DispatchWin32kPatternMatching(__int64 Buffer, unsigned int BufferSize);
__int64 DuplicateUSBPortSyscallOutput(__int64 pSourceTable);
char EnableDeviceObjectProtection(void);
__int64 EnableHookProtection(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
char EnableObjectCallback(PVOID ObjectName, SIZE_T Length);
char EnableObjectProtect(_OWORD *Address, int BufferSize);
__int64 EnableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableProcessProtect(PVOID *Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize);
char EnableThreadProtect(__int64 *Address, int InputSize, _QWORD *OutputBuffer, int OutputSize);
__int64 EnumCallbackContextOperation(__int64 InputBuffer, __int64 InputSize, _WORD *pOutputBuffer, int OutputSize);
__int64 EnumCallbackContextTable(__int64 pOutputTable);
__int64 EnumCallbackContextV3Table(__int64 pOutputTable);
__int64 EnumDeviceObjectTypeList(int DeviceIndex, __int64 pOutputTable);

void EnumHandleTableToBuffer(unsigned int *OutputBuffer, _DWORD *pCount);
__int64 EnumHandlesByType(WORD *TargetName, ULONG NameLen, _DWORD *TypeTable, _DWORD *OutputBuffer, int MaxEntries);
__int64 EnumKernelDriverObjects(_DWORD *pOutputArray, unsigned int MaxCount);
__int64 EnumKernelMemoryContext(__int64 UnusedParam1, __int64 UnusedParam2, _DWORD *pOutputBuffer, unsigned int BufferSize);
char EnumKernelModules(__int64 UnusedParam1, __int64 UnusedParam2, _DWORD *pOutputBuffer, unsigned int BufferSize);
__int64 EnumObjectContextTable(__int64 pOutputBuffer);
__int64 EnumObjectDirectoryEntries(unsigned __int16 *pDirectoryPath, _DWORD *pDirectoryInfo, __int64 OutputBuffer, int MaxCount);
__int64 EnumObjectTypeCleanupList(PVOID *pTargetObject);
char EnumObjectTypeFilterCallback(__int64 ObjectEntry, __int64 Context, __int64 TypeFilter);
char EnumObjectTypeList(unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessAndInitObjects(__int64 Process, char Flags);
__int64 EnumProcessContextSsdtTable(__int64 pOutputTable);
__int64 EnumProcessContextTable(__int64 pOutputTable);
__int64 EnumProcessContextV2Table(__int64 pOutputTable);
__int64 EnumProcessContextV3Table(__int64 pOutputTable);
__int64 EnumProcessContextV3TableWin7(__int64 pOutputTable);

char EnumProcessModules(ULONG64 pProcessId, int InputSize, volatile void *OutputBuffer, unsigned int OutputSize);
char EnumProcessThreadInfo(PRKPROCESS PROCESS, char IsUserMode, int *OutputBuffer, unsigned int BufferSize);
__int64 EnumServiceTableWin10(__int64 *pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount);
__int64 EnumServiceTableWin1020H1(_QWORD **pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount);
__int64 EnumServiceTableWin7(__int64 *pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount);
__int64 EnumServiceTableWin8(_QWORD **pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount);
__int64 EnumSsdtHooks(__int64 OutputBuffer, unsigned int BufferSize);
__int64 EnumThreadContextTable(__int64 OutputBuffer);
void EnumVadMemoryRegions(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateDriverFiles(_DWORD *pOutputBuffer);
char EnumerateDriverList(unsigned int *pOutputBuffer, unsigned int OutputSize);
char __fastcall EnumerateDriverObjectTable(__int64 pEntry, __int64 TargetObject);
char EnumerateDriverObjects(unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumerateDriverObjectsFull(unsigned int *pOutputBuffer, unsigned int OutputSize);
void EnumerateFileMappingSectionIterativeV1(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateFileMappingSectionRecursiveV1(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
char __fastcall EnumerateKernelDrivers( PVOID *pObjectStack, int StackSize, unsigned int *pOutputBuffer, int OutputSize);

void EnumerateProcessHandleTableData(struct _KPROCESS *Process, __int64 OutputBuffer, unsigned int BufferSize);
char EnumerateProcessInformation(__int64 Process, __int64 InfoBuffer, unsigned int BufferSize);
void EnumerateProcessListEntry(_QWORD **ListHead, unsigned int Offset, __int64 OutputBuffer, unsigned int BufferSize);
__int64 EnumerateProcessObjectTable(__int64 ProcessObject, __int64 OutputFlags);
char EnumerateProcessObjects( struct _KPROCESS *PROCESS, struct _KPROCESS *AlternateProcess, _DWORD *OutputBuffer, unsigned int BufferSize, char MarkType, char ValidateFlag, char PathFlag);

__int64 EnumerateRegistryContextTable(__int64 pOutputTable);
__int64 EnumerateSyscallContextVector(__int64 pOutputTable);
char EnumerateThreadsInProcess(ULONG64 BaseAddr, struct _KPROCESS *Process, char Use8ByteStep, int *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV1(_QWORD *VirtualAddress, __int64 Buffer, int MaxSize, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV2(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV3(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV4(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV1(_QWORD *VirtualAddress, int Depth, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV2(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV3(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV4(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadWithBufferV1(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadWithBufferV2(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadWithBufferV3(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadWithBufferV4(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
void *ExAlloc(ULONG PoolType, ULONG Size);
__int64 FileSystemFilterCallback(char *PatchBuffer, int BufferSize);
char FillProcessInformationEntry(char *VirtualAddress, char *AlternateAddr, __int64 OutputBuffer, unsigned int BufferSize, char ValidateFlag, char EntryType, char CheckFlag);

__int64 FilterActiveHookEntries(__int64 OutputBuffer, unsigned int EntryCount, enum _GLOBAL_TABLE_INDEX TableIndex);
__int64 __fastcall FindDeleteValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, __int64 *pResult);
__int64 FindExportByNameInPeBody(PUCHAR PeBase, ULONG PeSize, PCHAR FuncName, int Is64Bit);
char __fastcall FindExportEntryByAddress(__int64 TargetAddress, __int64 FilterTable, unsigned int FilterTableSize);
void *FindExportEntryByName(char *Dst);
void __fastcall FindHalDllInDriverList( unsigned int *pDriverArray, __int64 ArraySize, _QWORD *pImageBase, _DWORD *pImageSize);

__int64 FindHookTargetDataSection(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
__int64 FindKernelPESectionByType(enum _GLOBAL_TABLE_INDEX TypeIndex);
char FindKernelRdataSection(__int64 ImageBase, unsigned int ImageSize);
char FindMatchingEntryInArray(__int64 Entry, unsigned int Type, unsigned int *Array);
__int64 FindNdisExportsBySectionScanV2(__int64 ImageBase, unsigned int ImageSize);
__int64 FindNtOpenThreadTargetWin7(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset);
__int64 FindNtOpenThreadTargetWin8(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset);
__int64 FindNtoskrnlExportsInThreadEnv(void);
__int64 FindOpenProcessTokenOffset(__int64 TargetBase, unsigned int TargetSize);
__int64 FindOpenProcessTokenTarget(__int64 TargetBase, unsigned int TargetSize);
__int64 FindPESectionByName(__int64 PeBase, unsigned int PeSize, __int64 SectionName);
__int64 FindPESectionByNameReturnVa(__int64 PeBase, unsigned int PeSize, __int64 SectionName);
__int64 __fastcall FindPESectionByRva(__int64 PeBase, unsigned int PeSize, unsigned int TargetRva);
__int64 FindPeExecutableSection(void);
char FindRegCallbackEntry(__int64 RegEntry);
__int64 FindRenameKeyTargetEx(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);

__int64 FindSetValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, __int64 *pResultOffset, _QWORD *pResultOffset2);

__int64 FindSetValueKeyTargets(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, _QWORD *pResult1, __int64 *pResult2);

char FindSyscallNumbers(void);
char FindThreadEntry(_DWORD *OutputBuffer, __int64 Target, unsigned int *OutIndex, __int64 ExtraParam);
__int64 FixCreateFileRelocs(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
void FreeDiskBufferContext(void);
void FreeDriverProtectBuffer(void);
char FreeDriverUnloadBuffer(void);
void FreeFsCallbackBuffer(void);
void FreeListAllocation(_QWORD *Allocation);
__int64 FreeObjectByCallback(_QWORD *pObjectEntry);
__int64 FreeProcessMemoryAllocation(__int64 TargetAddress);
__int64 FreeProcessMemoryAllocationEx(_QWORD *pTargetEntry);
__int64 FreeProcessMemoryBuffer(PVOID VirtualAddress);
void FreeServiceTableEntries(void);
__int64 GenerateEncryptionKey(PWSTR RegistryPath);
__int64 GetDeleteValueKeyCtx(_QWORD *pContext);
__int64 GetExportDirSize(__int64 PeBase, unsigned int PeSize);
__int64 __fastcall FinalizeDataType(__int64 Context);
__int64 __fastcall GetDataElementSize(__int64 Context);
char GetExportEntrySignBit(PUCHAR ExportEntry);
char GetIrpMonitorContext(__int64 DeviceObject, unsigned int IrpMajorFunc, _OWORD *pContextBuffer, _QWORD *pCallDriver);
__int64 GetKernelObjectTypeInfo(__int64 ObjectHeader);
__int64 GetProcessFromHandleEntry(__int64 HandleTableEntry);
char GetProcessImagePath(PRKPROCESS PROCESS, HANDLE ProcessId, void **OutBuffer, _DWORD *OutSize, int Flags);
char GetProcessImagePathByAttach(PRKPROCESS PROCESS, HANDLE ProcessId, void **pImagePathBuffer, _DWORD *pImagePathSize);
char GetProcessVirtualizationContextFallback(_DWORD *OutputBuffer, unsigned int BufferSize);
char GetSectionObjectNameFromHandle(PRKPROCESS PROCESS, HANDLE Handle, _QWORD *pNameBuffer, _DWORD *pNameLength);
__int64 GetSetValueKeyCtx(_QWORD *pContext, _QWORD *pResult);
__int64 GetSsdtFunctionBase2(void);
__int64 GetSsdtFunctionBase4(void);
__int64 GetObjectTableCode(void);
__int64 GetStringLength(_WORD *String);
__int64 GetWin7Sp1EprocessOffset(void);
__int64 HookSyscallNtClose(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtCreateFile(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
__int64 HookSyscallNtCreateKey(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 HookSyscallNtCreateProcess(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 HookSyscallNtCreateThread(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 HookSyscallNtCreateToken(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtDeleteKey(unsigned __int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 HookSyscallNtDeleteValueKey(unsigned __int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset);
__int64 HookSyscallNtDuplicateObject(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtLoadDriver(__int64 TargetBase, signed int TargetSize, __int64 Context, __int64 RelocBase);
__int64 HookSyscallNtOpenFile(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtOpenKey(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 HookSyscallNtOpenKeyEx(__int64 ImageBase, unsigned int ImageSize);
__int64 HookSyscallNtOpenProcess(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 HookSyscallNtOpenProcessToken(__int64 TargetAddress, unsigned int TargetSize);
__int64 HookSyscallNtOpenThread(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset);
__int64 HookSyscallNtOpenThreadToken(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtQueryInformationProcess(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtQueryInformationThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtQuerySystemInfo(unsigned __int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
__int64 HookSyscallNtReadFile(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtResumeProcess(void);
__int64 HookSyscallNtResumeThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSetInformationProcess(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSetInformationThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSetValueKey(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset);
__int64 HookSyscallNtSuspendProcess(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSuspendThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtWriteFile(__int64 TargetBase, unsigned int TargetSize);
__int64 IdentityReturnParam(__int64 Param);
char ImageLoadCallbackRoutine(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
__int64 InitAllHookSubsystems(void);
void InitCallbackContextHookTable(void);
__int64 InitCommandHandlerTable(void);
__int64 InitDataTypeByIndex( PUCHAR DecodeCtx, ULONG64 TableEntry, ULONG DataIndex, PUCHAR OperandOut);

__int64 InitEprocessFieldOffsets(void);
__int64 InitEprocessOffsetsWin10_10240(void);
__int64 InitEprocessOffsetsWin10_14393(void);
__int64 InitEprocessOffsetsWin10_15063(void);
__int64 InitEprocessOffsetsWin10_17134(void);
__int64 InitEprocessOffsetsWin10_18362(void);
__int64 InitEprocessOffsetsWin10_19041(void);
__int64 InitEprocessOffsetsWin11(void);
__int64 InitEprocessOffsetsWin7(void);
__int64 InitEprocessOffsetsWin8(void);
__int64 InitEprocessOffsetsWin81(void);
__int64 InitEprocessOffsetsWin81_Update(void);
__int64 InitEprocessTokenOffset(void);
char InitFileSystemCallback(__int64 ContextArg1, __int64 ContextArg2, _DWORD *OutputBuffer, ULONG OutputBufferSize);
__int64 InitFileSystemExportTable(char Is64Bit);
char InitFileSystemFilter(__int64 OutputBuffer, __int64 OutputSize, _BYTE *UserBuffer, int InputSize);
__int64 InitFileSystemFilterCallbacks(__int64 FilterExtensionObject, _QWORD *FastIoDispatchPtr, char Is64Bit);
void InitFsFilterExportTable(void);
char ReadFsFilterDriverFile(PUCHAR *FileBuffer, PULONG FileSize);
char ResolveFltEnumerateFilters(PUCHAR ExportBase, ULONG ExportSize);
char ResolveFltUnregisterFilter(PUCHAR ExportBase, ULONG ExportSize);
__int64 ScanFltMgrExportTable(PUCHAR ExportBase, ULONG ExportSize);
__int64 ParseNtImageSections(PUCHAR ImageBase, ULONG ImageSize);
__int64 InitHandleTypeTable(void);
__int64 InitHookSyscall(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
char InitImageLoadCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
ULONG64 InitImageNotify(void);
__int64 InitImageNotifyCallbackWin7(void);
__int64 InitKernelMemoryContext(void);
__int64 InitKernelMemoryContextOperation();
__int64 InitKernelModuleSectionScan(void);
void InitMd5Context(PMD5_CONTEXT Context);
__int64 InitMsrTable(void);
__int64 InitObjectAndQueryName(__int64 VirtualAddress, int Flags);
char InitObjectCallback(__int64 UnusedParam, __int64 UnusedParam2, _DWORD *OutputBuffer, unsigned int OutputBufferSize);
__int64 InitObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InitObjectTypeTable(_QWORD InputName);
// ============================================================
// PE_DECODE_CONTEXT — PE 指令解码上下文（0x48 字节）
// ============================================================
// 【逆向来源】原始驱动 0x14008A7E4(InitPESectionReadContext, 95 字节) 与
//   0x14008A54C(ReadPESectionEntry, 662 字节) 的反汇编直接读出：
//   两个函数对上下文访问的偏移并集恰为
//     0x00/0x08/0x10/0x18/0x1C/0x20/0x28/0x30/0x38/0x40
//   故上下文共 0x48 字节。
// 【关键语义】+0x08 是「当前读指针」，不是累计大小：
//   1) InitPESectionReadContext 把第 1 个参数(Base)写入 +0x08，把 Base+Size 写入 +0x10；
//   2) ReadPESectionEntry 对上下文**只读**（全部 14 处 [rdi+..] 访问都是读），
//      它以 +0x08 为操作码指针、以 +0x10 为结束边界，自身不推进；
//   3) 因此推进读指针的责任在调用方 —— 调用方的
//      `累计变量 += *(DWORD*)(条目+0xF0)` 实际改写的正是 +0x08。
//      调用方帧布局可证：上下文起始于 rsp+0x50，该变量位于 rsp+0x58，
//      而条目缓冲区起点为 rsp+0xA0（= 上下文 0x48 字节后按 16 字节对齐），
//      两者之间没有第三个变量可放（V1/V2/V3 三个函数帧布局一致）。
// 【注意】早期重建把 `DEC_CTX_*` 这一套宏同时用于本上下文和 0x120 字节的
//   指令描述符，导致上下文写入偏移错位到 0xDC/0xF0/0xF8/0x100（那是描述符的
//   布局），而调用点只声明 8 字节 —— 既栈越界又会破坏描述符。此处按反汇编改正。
typedef struct _PE_DECODE_CONTEXT
{
    ULONG64 DecodeTablePtr;   // +0x00 解码表指针（Mode==2 用 g_PeDataDescrambleTable，否则 g_PeLegacyDescrambleTable）
    ULONG64 ReadPtr;          // +0x08 当前读指针（初值 Base，由调用方按解码长度推进）
    ULONG64 EndPtr;           // +0x10 缓冲区结束（Base + (int)Size）
    ULONG   Mode;             // +0x18 模式（2 = 64 位）
    ULONG   ModeDup;          // +0x1C 模式副本
    ULONG   AddrSize;         // +0x20 地址大小（Mode==2 时为 1，否则为 Mode）
    ULONG   Reserved24;       // +0x24 原始驱动未写入
    ULONG64 Param4;           // +0x28 第 4 参数（r9）
    ULONG64 Param6;           // +0x30 第 6 参数
    ULONG64 Param7;           // +0x38 第 7 参数
    ULONG   ExtraField;       // +0x40 第 5 参数（栈上传入）
    ULONG   Reserved44;       // +0x44 原始驱动未写入
} PE_DECODE_CONTEXT, *PPE_DECODE_CONTEXT;

void InitPESectionReadContext(__int64 Base, ULONG Size, INT Mode, LONG64 Param5, INT ExtraField, LONG64 Param6, LONG64 Param7, __int64 Context);

__int64 InitPhysicalMemoryContextTable(int DeviceIndex, __int64 pOutputTable);
char InitPowerCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
char InitProcessCallback(struct _KPROCESS **ProcessPtr, int BufferSize);
void InitProcessContextExportTableWin7(void);
ULONG64 ParseNtExportSectionsForProcessContext(__int64 FileBuffer, unsigned int FileSize);
void InitProcessContextHookTable(void);
__int64 InitProcessNotify(void);
char InitRegCallback(void *OutputBuffer, int OutputSize, volatile void *UserBuffer, unsigned int UserBufferSize);
char InitRegFilter(__int64 DeviceObject, __int64 Irp, _OWORD *OutputBuffer, int OutputSize);
char InitRegNotify(void);
__int64 InitSdstServiceCount(void);
char InitSdstTable(void);
char InitShutdownCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
__int64 InitSyscallNumberTable(void);
char InitThreadCallback(__int64 InputBuffer, unsigned __int64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
void InitThreadContextTable(void);
__int64 InitThreadNotify(void);
void InitUSBPortSyscallTable(void);
__int64 InitUnicodeStringBuffer(__int64 Buffer, __int64 StringPtr, unsigned int MaxLength);
void InitWin32kServiceTableEntries(void);
void ResolveWin32kSyscallAddresses(void);
void ResolveWin32kExportAddresses(__int64 FileBuffer, unsigned int FileSize);
bool ReadNtoskrnlForCallbackContext(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadNtoskrnlForCallbackCtx(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadNtFileForContextTable(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadNtFileForCallbackTable(_QWORD *pFileBuffer, unsigned int *pFileSize, int VersionType);
bool __fastcall ReadNtFileSyscall(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool __fastcall ReadSyscallDriverFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool __fastcall ReadNtoskrnlNlsFile(_QWORD *OutBuffer, unsigned int *OutSize);
char __fastcall FindFwpsTcpIpDispatchTableStr(__int64 ModuleBase, unsigned int ModuleSize);
char __fastcall FindFwpsTcpIpDispatchTable(__int64 a1, unsigned int a2);
char __fastcall FindFwpsL2DispatchTable(__int64 ModuleBase, unsigned int ModuleSize);
char __fastcall FindFwpsDispatchTableWin8(__int64 a1, unsigned int a2);
void InitFwpsDispatchTables(void);
char __fastcall ParseSyscallFileExportSections(__int64 PeBase, unsigned int PeSize, __int64 OutTable);
char __fastcall ParseShadowSyscallExportSections(__int64 pFileBuffer, unsigned int FileSize, __int64 pExportTable);
char __fastcall ParseWin32kSyscallStubs(__int64 FileBuffer, unsigned int FileSize, __int64 pOutputTable);
void InitWin32kTableByVersion(void);
__int64 InstallCallbackContextHookEntry(unsigned int *pInputEntry);
__int64 InstallHookSyscall(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
char InstallSsdtHookForThreadProtect(__int64 pInputEntry);
__int64 InvokeCallbackWithZeroArg(__int64 Arg1, __int64 Arg2, __int64 Arg3, __int64 (__fastcall *Callback)(__int64, __int64, __int64, ULONG64));
__int64 InvokeNullCallback(__int64 Arg1, __int64 Arg2, __int64 Arg3, __int64 (*Callback)(void));
char InvokeRegisteredCallbackWithUserData(unsigned int *Address, int InputSize);
__int64 IoPortOperationDispatch(void *InputBuffer, int BufferSize);
__int64 KernelMemoryOperationDispatch(void *InputBuffer, int BufferSize);
__int64 IrpFileSystemControl(void *FileHandle, struct _IRP *FsctlBuffer, ULONG BufferSize, ULONG FsControlCode);
__int64 IrpFsctlGetVolumeData(void *FileHandle, __int64 *pVolumeData);
__int64 IrpFsctlVolumeDismount(void *FileObject);
__int64 IrpReadFile(void *FileHandle, struct _IRP *AssociatedIrp, ULONG Length, ULONG CreateOptions);
int IrpReadFileEx(void *FileHandle, LARGE_INTEGER *ByteOffset, ULONG Length, void *Buffer, PLARGE_INTEGER Timeout, struct _IO_STATUS_BLOCK *IoStatusBlock);
__int64 IrpReadFileWithOffset( void *FileHandle, DWORD ByteOffset, void *Buffer, ULONG Length, PLARGE_INTEGER Timeout, _DWORD *pBytesRead, char WaitForLock, char UseSecondary);

__int64 IrpSetupBufferMdl(PIRP Irp, __int64 StackLocation, void *Buffer, ULONG BufferSize, char ProbeAndLock, char WriteOperation, _DWORD *pFlags);

__int64 IrpWriteFile( void *FileHandle, LARGE_INTEGER *ByteOffset, ULONG Length, void *Buffer, PLARGE_INTEGER Timeout, struct _IO_STATUS_BLOCK *IoStatusBlock);

char IsExportForwarder(PUCHAR ExportEntry);
char IsProcessThreadInList(__int64 Process, __int64 Thread, __int64 ListHead, char CheckFlag);

__int64 KernelNotifyRoutine(void *NotificationBuffer, size_t BufferSize);
__int64 KernelNotifyRoutineEx(void *NotificationBuffer, size_t BufferSize);
__int64 LookupDriverHashTable(__int64 DriverName, _DWORD *pResultIndex);
char LookupDriverObjectEntry( unsigned int *pDriverArray, unsigned __int64 TargetAddress, __int64 pDriverEntry, __int64 EntrySize);

char LookupExportByName(PUCHAR PeBase, ULONG PeSize, PCHAR FuncName, PULONG OutRva);
__int64 LookupExportFuncAddr(__int64 ExportIndexTable, unsigned int EntryCount, int HashValue);
__int64 *LookupModuleByName(const char *ModuleName, __int64 *OutBaseAddress);
__int64 LookupMsrTableEntry(void);
char EnumObjectTypeDirectory(_QWORD **DirectoryStack, int MaxDepth, __int64 OutputBuffer, unsigned int OutputSize);
char MatchObjectTypeEntry(__int64 Target, __int64 TableBase);
__int64 MatchObjectTypeFilterCallback(_QWORD *ObjectEntry, _QWORD *Context, __int64 TypeFilter);
__int64 MatchObjectTypeFilterCallbackV2(_QWORD *ObjectEntry, _QWORD *Context, __int64 TypeFilter);
__int64 MatchSystemProcessName(_QWORD *Process);
void Md5Final(PMD5_CONTEXT Context, PUCHAR Digest);
void Md5Final2(PMD5_CONTEXT Context, PUCHAR Digest);
void Md5Transform(ULONG State[4], PUCHAR Block);
void Md5Transform2(ULONG State[4], PUCHAR Block);
void Md5Update(PMD5_CONTEXT Context, PUCHAR Input, ULONG Length);
void Md5Update2(PMD5_CONTEXT Context, PUCHAR Input, ULONG Length);
unsigned int MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size);
char CmdClearGdtPresentBit(int ProcessorNumber, __int64 ContextBuffer);
char __fastcall MiniFilterAcquireForModWrite(__int64 FilterObject, __int64 CallbackData, unsigned int *OutputBuffer, unsigned int BufferSize);
bool CmdCollectAllCpuGdtEntries(__int64 FilterObject, __int64 CallbackData, _DWORD *OutputBuffer, unsigned int BufferSize);
char MiniFilterActiveRoutine(void);
char MiniFilterClientContext(void);
__int64 MiniFilterCommPortCleanup(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize);
char MiniFilterCommPortConnect(void);
char RegisterCommPortReplyCallback(void);
__int64 MiniFilterCommPortDisconnect(void);
char MiniFilterCommPortRecv(void);
NTSTATUS MiniFilterCommPortReply(void);
__int64 MiniFilterCommPortReplyDone(void);
char MiniFilterCommPortSend(void);
char StartMiniFilter(struct _DRIVER_OBJECT *DriverObject);
__int64 *MiniFilterFilterUnload(__int64 ProcessId, __int64 BaseAddress, char IsAddOperation);
char RegisterFormatNameCallback(void);
char RegisterFormatPathCallback(void);
__int64 MiniFilterFormatFileNameWithContext(void);
__int64 MiniFilterFormatFileNameEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize);
__int64 MiniFilterFormatFileNameWithPathEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize);
__int64 MiniFilterGenerateFileName(void);
char __fastcall RemoveMiniFilterContextNode(_QWORD *ContextNode);
bool __fastcall MiniFilterInstanceQuery(_OWORD *InputBuffer, int BufferSize);
NTSTATUS CmdOpenFilterVolumeFile(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags);
__int64 *__fastcall CmdCreateFileForPathAdd(__int64 Unknown, __int64 FilePath, char IsAddOperation);
__int64 MiniFilterNotifyRoutine(wchar_t *Name, ULONG NameLength);
NTSTATUS RegisterFilterUnloadCallback(void);
NTSTATUS MiniFilterNotifyRoutineEx2(void);
char MiniFilterOpLockPost(PRKPROCESS ProcessObject, char IsQwordKey, __int64 Context);
char MiniFilterOpLockPre(PRKPROCESS ProcessObject, __int64 Unknown, ULONG64 UserBuffer, char IsQwordKey);
char CmdInitFwpsDispatchTables(__int64 FilterObject, __int64 CallbackData, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 MiniFilterPostWrite(void);
__int64 MiniFilterPreAcquire(__int64 Unknown1, __int64 Unknown2, unsigned int *OutputBuffer, unsigned int OutputBufferSize);
__int64 MiniFilterPreCleanup(void);
ULONG64 FindKernelObjectFieldOffsetsWin10(void);
NTSTATUS MiniFilterPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
__int64 MiniFilterPreDelete(__int64 Unknown1, __int64 Unknown2, unsigned int *OutputBuffer, unsigned int OutputBufferSize);
ULONG64 FindKernelObjectFieldOffsetsWin8(void);
NTSTATUS CmdEnumAleEndpointLayers(void);
__int64 MiniFilterPreFlush(unsigned int *OutputBuffer, int BufferSize);
__int64 MiniFilterPreHardLink(__int64 Unknown1, __int64 Unknown2, __int64 *OutputBuffer, unsigned int OutputBufferSize);
__int64 MiniFilterPreRelease(_QWORD **ContextPtr, int ContextSize);
char __fastcall PatchPeHeaderMagic(__int64 QueryResult);
__int64 MiniFilterPreRename(__int64 Unknown, __int64 Unknown2, _BYTE *OutputBuffer, int OutputBufferSize);
ULONG64 FindKernelObjectFieldOffsetsWin10Early(void);
__int64 MiniFilterPreShutdown(_QWORD *ServicePtr, int InputSize);
__int64 MiniFilterPreVolumeDismount(PFLT_CALLBACK_DATA CallbackData, __int64 VolumeContext);
__int64 MiniFilterPreVolumeMount(char *InputBuffer, int BufferSize);
__int64 FindKernelDataSectionForDeviceIoControl2(void);
__int64 *MiniFilterQueryIdleRoutine(__int64 a1, __int64 a2, _DWORD *a3);
bool CmdForEachCpuClearGdtBit(void *Address, int ContextSize);
char CmdCollectGdtrEntries(int ProcessorNumber, unsigned int **ContextBuffer);
char MiniFilterServerContext(void);
bool CmdHandleStreamProcessInput(void *Address, int InputSize);
char MiniFilterStreamHandleEx(PRKPROCESS PROCESS, __int64 CallbackContext, ULONG64 StreamHandle, __int64 BaseOffset);
ULONG64 InitCallbackFunctionTable(unsigned int Mode);
// 【签名更正 2026-09-30】原声明 (void*, __int64, unsigned __int64) 与实物不符。
//   反编译（0x14001B23C）显示真实签名为 (OutCount, OutBuffer, MaxCount)，
//   与调用方 CmdInitFwpsDispatchTables 传的 (OutputBuffer, OutputBuffer+8, ...) 吻合。
__int64 EnumerateAleEndpointLayers(_DWORD *OutCount, __int64 OutBuffer, int MaxCount);
__int64 EnumerateAleEndpointLayer(__int64 FilePath, _DWORD *OutCount, __int64 OutBuffer, int MaxCount);
char FindAleEndpointDuplicate(__int64 EndpointData, _DWORD *EndpointList);
char CopyAleEndpointEntry(__int64 OutputBuffer, __int64 EndpointEntry);
__int64 MiniFilterUnloadCleanup(void);
__int64 ModuleOperation(__int64 *pInputBuffer, unsigned int InputSize);
__int64 ModuleOperationDispatch(void *Address, unsigned int InputSize);
void NormalizeModulePaths(__int64 OutputBuffer, unsigned int EntryCount);
void NormalizeRelativePath(WORD *Path);
void NotifyVolumeDeviceChange(char EventType, __int64 DeviceObject);
__int64 ObjectOperationDispatcher(void *InputBuffer, int BufferSize);
char ObjectPreCallback(__int64 CallbackContext, unsigned int CallbackArg);
char __fastcall OpenDriverFile(PCWSTR pFilePath);
char OpenFileCheckExists(__int64 FilePath);
__int64 OpenFileSection(__int64 EncodedPath);
__int64 OpenKbdClassDriverSection(void);
__int64 OpenMountMgrDriverSection(void);
char OpenMountPointManagerDevice(_QWORD ObjectBody);
__int64 OpenPhysicalDiskDevice(__int16 *DevicePath, void *DeviceHandle, void **ppFileHandle);
bool OpenSectionWithIoControl(__int64 DeviceHandle);
__int64 OpenTcpIpDriverSection(void);
__int64 OpenWdfDriverSection(void);
__int64 OpenWin32kSection(void);
__int64 OpenWin32kSysSection(void);
__int64 ParseExportDirForDriver(__int64 DriverInfo, __int64 Context, __int64 PeBuffer, unsigned int PeSize);
void __fastcall ParseExportSectionAndIndex(__int64 ImageBase, unsigned int ImageSize, unsigned int RegRefCount);
char ParseFilePathForSystemRoot(__int16 **pPathString, _DWORD *pPathLength);
void ParseFsFilterDriverExport(char Is64Bit);
__int64 ParseKernelDataSectionRelocs(__int64 ImageBase, unsigned int ImageSize);
__int64 ParseKernelModuleDiskInfo(void);
char ParseNtExportDir(PUCHAR ImageBase, ULONG ExportDirSize, ULONG64 ImageBaseUnused, int Flags);
char ParseNtHeaders(unsigned __int16 *SectionName, unsigned int SectionNameLength);
__int64 ParseNtImageSectionHeaders(PRKPROCESS PROCESS, __int64 SectionInfoArray);
char ParseNtImageSectionHeadersForProcess(PRKPROCESS PROCESS, __int64 SectionInfoArray);
char ParseNtKernelDataOffsets(__int64 ImageBase, unsigned int ImageSize);
char ParseNtKernelFile(__int64 ModuleEntry, __int64 OutputBuffer, int OutputSize);
void ParseObjectContextExportDir(void);
char ParsePESectionHeaders(__int64 PeBase, unsigned int PeSize, __int64 SectionName, unsigned __int8 *NameToMatch, unsigned int *OutOffset);
void ParseRegistryDriverExportDir(void);
char PatchFsFilterDriverIndex(__int64 PatchEntry, char Is64Bit);
__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize);
__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize);
char PrepareFileForPageTableScan(char *VirtualAddress, char Flags);
char ProcessCallbackRoutine(__int64 Reserved, __int64 Reserved2, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 ProcessMemoryOperationDispatch(void *InputBuffer, int BufferSize);
__int64 ProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ProcessOperationWithAttach(struct _KPROCESS *TargetProcess);
char QueryDeviceObjectInfo(__int64 DeviceObject, __int64 *pDeviceInfo);
char QueryDevicePathFromSymbolicLink(__int64 SymLink, void **pPathBuffer, _DWORD *pPathLength);
__int64 QueryDiskFsControlInfo(__int16 *FilePath, __int64 Size, char **OutBuffer, __int64 *OutBufferSize);
__int64 QueryDiskFsControlInfoEx(void *FileHandle, __int64 InputHeader, unsigned int DesiredAccess, unsigned int SectorSize, unsigned __int64 TotalBytes, char *WriteBuffer);

__int64 QueryKernelMemoryByAddress(PVOID ***VirtualAddress, char Flags);

char QueryObjectNameByAddress(unsigned __int64 ObjectAddress, _QWORD *pNameBuffer, _DWORD *pNameLength);
__int64 QueryObjectNameByType(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength);
char QueryObjectNameInfo(ULONG64 ObjectAddress, WORD *TargetName, ULONG NameLength, _QWORD *OutBuffer, _DWORD *OutSize);
char QueryObjectNameLegacy(_QWORD *Object, _QWORD *NameBuffer, _DWORD *NameLength);
char QueryObjectNameString(ULONG64 Object, _QWORD *OutBuffer, _DWORD *OutSize);
__int64 QueryObjectNameWithRetry(__int64 ObjectEntry, struct _OBJECT_NAME_INFORMATION *NameInfo, ULONG BufferSize, ULONG *OutSize);
__int64 QueryObjectTypeByAddress(__int64 Object);
__int64 QueryObjectTypeInformation(PVOID Object);
__int64 (__fastcall *__fastcall DispatchObjectTypeQuery(__int64 ObjectTypeEntry))(_QWORD);
__int64 QueryPhysicalDiskInfo(void *FileHandle, _QWORD *pDeviceObject, void **pPhysicalHandle);

char QueryProcessMemoryRegions(__int64 ProcessId, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 QueryProcessModuleInfo(volatile void **Address, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 QuerySsdHookByProcessInfo(void *Src, size_t MaxCount, _DWORD *Address, int OutputSize);
__int64 QuerySyscallHookStatus(__int64 TargetAddress);

unsigned int ReadDiskSectors(void);
__int64 ReadDiskSectorsWithAlloc(__int64 BufferSize);
__int64 ReadDiskSectorsWithPartition(char IsRead, void *Buffer, unsigned int *pSectorCount, int SectorCount, unsigned int BufferSize);
bool ReadDiskPortDriverFile(_QWORD *OutBuffer, unsigned int *OutSize);
char ReadFileIntoBuffer(__int64 SrcAddress, unsigned int BufferSize, char *DstBuffer);
__int64 ReadFileRawData(WORD *FilePath, void **OutBuffer, ULONG *OutSize, char RequirePeHeader);
void ReadGdtr(void *pGdtr);
char ReadKernelExportDirFile(_QWORD *OutBuffer, unsigned int *OutSize);
__int64 ReadKernelMemoryToUserBuffer(__int64 UnusedParam1, __int64 UnusedParam2, _QWORD *pOutputBuffer, int BufferSize);
bool ReadKbdClassSysFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadIpsecSysFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadNetioDriverFile(_QWORD *OutBuffer, unsigned int *OutSize);
char __fastcall ReadModuleFileToBuffer( const char *ModuleName, void **ppBuffer, unsigned int *pFileSize, __int64 *pExportDirBase);

__int64 ReadNtFilePartial(WORD *FilePath, void *Buffer, ULONG Size, char RequirePeHeader);
char ReadNtFileToBuffer(PUCHAR Src, ULONG MaxCount, PUCHAR *OutBuffer, PULONG OutSize);
__int64 ReadNtOsKrnlFile(__int64 *pBuffer, __int64 *pSize);
char ReadNtoskrnlFile(void);
bool ReadNtoskrnlNlsFile(_QWORD *OutBuffer, unsigned int *OutSize);
__int64 ReadObjectBodyOffset(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectHeaderCreateInfo(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectHeaderField(PVOID ***VirtualAddress, unsigned int FieldOffset, char DerefFirst);
__int64 ReadObjectHeaderHandle(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectHeaderName(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectHeaderQuota(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectHeaderType(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectNameFromCallback(__int64 Object, __int64 Context, __int64 (__fastcall *Callback)(__int64, ULONG64, __int64));
__int64 ReadObjectTypeOffset(PVOID ***VirtualAddress, char Flags);
__int64 ReadObjectTypeOffsetByIndex(void);
__int64 ReadPESectionAsmField(PUCHAR Context);
__int64 ReadPESectionEntry(PUCHAR Context, PULONG SectionInfo);
__int64 ReadPESectionField(PUCHAR Context);
__int64 ReadPESectionFieldByte(PUCHAR Context);
char ReadProcessMemoryBlock(PRKPROCESS PROCESS, void *Dst, size_t Size);
__int64 ReadProcessMemoryString(void *InputBuffer, int InputSize, void *OutputBuffer, unsigned int OutputSize);
__int64 ReadKernelMemoryViaSwap(void *InputBuffer, void *OutputBuffer, void *SwapBuffer, unsigned int BufferSize);
__int64 ReadKernelMemoryViaSwapEx(void *InputBuffer, void *OutputBuffer, void *SwapBuffer, unsigned int BufferSize);
__int64 ReadProcessMemoryWithAttach(__int64 ProcessHandle);
__int64 ReadServiceTableEntries(__int64 OutputBuffer, __int64 UnusedParam, char *PeFileData, unsigned int PeFileSize);
char ReadSystemDriverFile(_QWORD *OutBuffer, unsigned int *OutSize);
unsigned __int64 ReadDebugRegisters(unsigned __int64 *pDebugRegisters);
char ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray);
char RegNotifyCallback(void *Address, int InputSize);
void RegisterMiniFilterRegistry(void);
__int64 RegistryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RegistryOperationDispatch(void *InputBuffer, int BufferSize);
__int64 ReleaseDiskBuffer(__int64 DiskObject);
char ReleaseIrpMonitorContext(char IsAcquired, __int64 DeviceObject, unsigned int IrpMajorFunc, _OWORD *pContextBuffer);
__int64 ReleaseProcessMemoryBlock(_QWORD *pTargetEntry);
char __fastcall RelocateExportAddresses(void *Src, size_t MaxCount, int BaseDelta);
char RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType);
__int64 RemoveFromObjectTypeList(PVOID *pTargetObject);
__int64 RemoveFromObjectTypeListEx(PVOID *pTargetPointer);
char RemoveI8042prtDriverObject(ULONG64 DriverObject);
char RemoveKbdClassDriverObject(ULONG64 DriverObject);
__int64 RemoveKernelObjectEntry(__int64 TargetAddress);
char RemoveMouClassDriverObject(ULONG64 DriverObject);
char RemoveNdisDriverObject(ULONG64 DriverObject);
__int64 RemoveObjectFromTypeList(PVOID pTargetObject);
char RemoveObjectListEntry(ULONG64 DevicePath, ULONG64 EntryToRemove);
ULONG64 RemoveOplockNodeByDwordKey(unsigned int *KeyArray, ULONG Offset, __int64 Context);
char RemoveRawDriverObject(ULONG64 DriverObject);
__int64 RemoveServiceEntryFromList(ULONG_PTR *pListHead, __int64 TargetAddress);
__int64 RemoveServiceEntryFromListEx(__int64 ****pListHead, __int64 ***TargetAddress);
__int64 RemoveServiceTableNodeWin10(__int64 ***pListHead, __int64 **TargetAddress);
__int64 RemoveServiceTableNodeWin7(ULONG_PTR *pListHead, __int64 TargetAddress);
char RemoveTcpipDriverObject(ULONG64 DriverObject);
char RemoveVolmgrDriverObject(ULONG64 DriverObject);
__int64 ResetThreadStateFlag(__int64 Thread, __int64 FlagOffset);
__int64 ResolveCreateFileRelocs(__int64 TargetBase, ULONG TargetSize, __int64 Context, __int64 RelocBase);

__int64 ResolveDriverEntryAddresses(__int64 DriverInfo);
char ResolveDriverModuleNames(ULONG *DriverInfoBuffer);
__int64 ResolveDriverRelativeAddresses(__int64 DriverInfo, __int64 Flags, int **pRelocTable);
__int64 ResolveKernelModuleBasePair(__int64 CpuNumber, ULONG_PTR *pMsrPair);
__int64 ResolveKernelModuleIndex(GLOBAL_TABLE_INDEX SectionType, GLOBAL_TABLE_INDEX ResultTableIndex, GLOBAL_TABLE_INDEX TargetTableIndex);

// CPU MSR 基址查找函数
extern __int64 g_HalDispatchTable;
extern __int64 g_HalDispatchTableEnd;
extern __int64 g_CommPortContext;
__int64 FindCpuMsrBaseLegacy(int MsrAddress);
__int64 FindCpuMsrBaseWin10(int MsrAddress);
__int64 DispatchCpuMsrBaseLookup(int MsrAddress);
__int64 InitCpuMsrBaseOffsets(void);
char FindCpuMsrDifferences(char *VirtualAddress, unsigned int Size, _QWORD *pDiffOffset);
__int64 CmdCheckModuleBaseChanged(__int64 CpuNumber, __int64 pMsrPair);
char CopyKernelMemoryToTarget(PVOID VirtualAddress, size_t Size);

__int64 ResolveKernelObjectAddresses(__int64 pObjectTable);
__int64 ResolveModuleBaseAddress(void);
__int64 ResolveModuleEnumBase(void);
char ResolveObjectHeaderPointer(__int64 ObjectBody, _QWORD *OutHeader);
__int64 ResolveObjectNamePointer(__int64 ObjectAddress);
__int64 ResolvePhysicalMemoryContext(__int64 pContextTable, int ContextType, ULONG EntryCount);
char ResolvePointerSafe(_QWORD *Pointer, _QWORD *OutValue);
__int64 ResolveServiceTableBase(void);
void ResolveSyscallNumberFromKernel(void);
char ResolveSyscallNumberTable(void);
void ResolveSyscallTableEntry(void);
__int64 ResolveSyscallToAddress(unsigned int SyscallNumber);
void ResolveWin32kServiceTable(char IsWow64Process);
__int64 ResolveWin32kServiceTableDispatch(__int64 ImageBase, unsigned int ImageSize, unsigned int ExportOffset);
__int64 ResolveWin32kServiceTableEx(__int64 ImageBase, unsigned int ImageSize);
unsigned __int64 RestoreCr0WriteProtect(unsigned __int64 *pOldCr0);
void RestoreDiskIrpFunctionPointer(char State);
__int64 RestoreSyscallHookByIndex(char TableType, unsigned int HookIndex);
char ReturnFalseStub(void);
__int64 ScanDataSectionPattern(__int64 ImageBase, unsigned int ImageSize);
__int64 ScanFileForPeSectionInfo(void);
char ScanKernelMemForFsChanges(ULONG *EntryCountPtr, int ScanSize);
__int64 ScanKernelModuleDataSectionEx(void);
__int64 ScanKernelModuleInitSection(void);
__int64 ScanKernelModulePESections(void);
__int64 ScanKernelModulePageOrRsrcSection(void);
__int64 ScanKernelModuleSectionByType(void);
__int64 ScanKernelModuleSectionForWin10(void);
__int64 ScanKernelModuleSectionForWin10RS3(void);
char ScanRegValueBodyForRef(unsigned __int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, int MaxDelta, __int64 *pResult);

void ScanVadForModifiedPages(ULONG *OutputBuffer, int MaxModifiedCount);
__int64 ScanWin32kDriverForPatterns(ULONG_PTR PatternBase, ULONG_PTR PatternSize);
__int64 SendDeviceIoControlIrp(_QWORD *DeviceInfo, int Direction, void *Buffer, int BlockCount, int SectorSize, int SectorCount);
// 【新增 2026-09-30】设备 IO 控制多步发送（原 0x140073934，688B，不可反编译，逐条转写）
//   形参 3 是 UNICODE_STRING*（非 int），已由 capstone + 调用方伪代码双重定案。
char __fastcall SendIoControlWithVersionBranch(char *OutputBuffer, int Command,
        PUNICODE_STRING UnicodeString, int Param2, void *OutputBuf, SIZE_T OutputSize, __int64 Context);
char SendDeviceIoControl(unsigned char *OutFlag, int Arg2, PUNICODE_STRING PathString, int Arg4,
                         void *OutputBuffer, SIZE_T OutputSize, __int64 OutputSizePtr);
__int64 __fastcall SendDeviceIoControlWithRetry(__int64 Handle, unsigned int IoControlCode, char Flags, _DWORD **OutputHandle, __int64 IoStatusBlock);
char SendFsctlWithHookSwap(__int64 DeviceHandle, unsigned int IoControlCode, __int64 InputBuffer, unsigned int InputSize, __int64 OutputBuffer, int OutputSize, __int64 Flags);

_DWORD *SendIoControlWithUnicodeString(__int64 UnicodeString);
__int64 SerializeDataToBuffer(PUCHAR Context);
__int64 SetCallbackContextEntry(ULONG *pInputEntry);
__int64 SetDecoderStateFlags(PUCHAR Context);
__int64 SetObjectContextEntry(ULONG *pInputEntry);
__int64 SetProcessContextEntry(__int64 pInputEntry);
__int64 SetRegistryContextEntry(ULONG *pInputEntry);
__int64 SetSyscallContextByIndex(ULONG *pInputEntry);
__int64 SetUSBPortServiceTableEntry(ULONG *pInputEntry);
__int64 SetupDecodedInstructionState(PUCHAR OperandOut, PUCHAR DecodeCtx);
__int64 Sha1HashToDword(char *String);
char ShutdownCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, PUCHAR OutputBuffer);
__int64 ShutdownCallbackUnregister(PRKPROCESS *InputBuffer, int BufferSize);
__int64 StoreVolumeMountCallback(__int64 CallbackData);
__int64 StringCompare(__int64 Str1, __int64 Str2);
__int64 StringCompare3Way(__int64 Str1, unsigned __int16 *Str2, unsigned int MaxLen);
__int64 StringCompareCaseInsensitive(__int64 Str1, char *Str2, unsigned int MaxLen);
__int64 StringCompareCaseInsensitiveV2(__int64 Str1, __int64 Str2);
__int64 StringLength(_BYTE *String);
char SwapDiskIrpFunctionPointer(void);
__int64 *SwapKernelMemoryPointer(__int64 *pTarget);
__int64 __fastcall SwapKernelObjectPointerPreWin10(__int64 Handle, __int64 *OriginalValue);
__int64 __fastcall SwapKernelObjectPointerWin10(__int64 Handle, __int64 *OriginalValue);
char SwapPhysicalMemoryQword(GLOBAL_TABLE_INDEX AddressGtIndex, GLOBAL_TABLE_INDEX OldValueGtIndex);
void SystemResetCommand(void);
char ThreadCallbackRoutine(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
__int64 ThreadOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
char TraverseHashTableWithCallback( _QWORD **HashTable, int MaxDepth, __int64 (__fastcall *Callback)(_QWORD *, _QWORD *, __int64),

    __int64 Context);
__int64 UninstallHookSyscall(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 UnlinkFromMemoryBlockList(PVOID *pTargetPointer);
__int64 UnlinkFromProcessMemoryList(PVOID *pTargetPointer);
__int64 UnlinkProcessMemoryBlock(ULONG_PTR *pTargetEntry);
__int64 UnregisterCommPortCallback(void);
__int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext);
char ValidateAndEnumerateObject(char *VirtualAddress, __int64 OutputBuffer, unsigned int BufferSize, __int64 Context);
__int64 ValidateCallbackContextTable(__int64 pContextTable);
char ValidateDriverObjectAddress( __int64 pLdrEntry, __int64 pAddressOverride, char CheckAllAsciiFlag, unsigned int *pDriverTableEntry, int UnusedParam, __int64 pOutputBuffer);

char __fastcall ValidateEnumerationResult(__int64 pCheckFlagFunc, __int64 CurrentAddr, __int64 Offset);
__int64 ValidateFsFilterEntries(__int64 FilterContext);
__int64 ValidateHookEntries(__int64 HookEntries, unsigned int EntryCount);
char ValidateKernelObject(ULONG64 ObjectAddr, ULONG64 AltAddr, _QWORD *OutContext, ULONG64 *OutProcess);
void ValidateObjReferences(__int64 Object1, __int64 Object2);
char ValidateProcessObject(struct _KPROCESS *ProcessObject, struct _KPROCESS *AlternateProcess);
char ValidateProcessObjectEx(char *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 ValidateSingleHookEntry(__int64 pEntry);
char __fastcall ValidateUtf8Bytes( unsigned __int64 *BufferPtr, unsigned __int64 BufferEnd, _DWORD *ByteCount, _DWORD *StateFlags, _BYTE *ClassFlags);

char __fastcall ValidateZeroPage(__int64 Address, unsigned __int64 LimitAddress);
__int64 WStringCompare(__int64 Str1, unsigned __int16 *Str2, unsigned int MaxLen);
__int64 WStringCompareCaseInsensitive(__int64 Str1, __int64 Str2);
__int64 WalkKernelModuleList(ULONG64 *pModuleList, ULONG *pOutputBuffer, ULONG *pMaxEntries);
char WalkObjectTypeList(_QWORD **NodeStack, int MaxDepth, _DWORD *OutputBuffer, unsigned int MaxBufferSize);
__int64 WriteDiskSectorsWithPartitionCheck(char IsWrite, const void *DataBuffer, ULONG SectorCount);
char SendDiskDeviceInternalIrp(__int64 DeviceObject, struct _IRP *Irp);
char DispatchDiskIrpWithHookInit(void *DeviceObject, int Direction, void *Buffer, int SectorOffset, unsigned int SectorIndex, unsigned int SectorSize);
char CheckMbrBootablePartition(void *Buffer);
void AnalyzeDiskSectorBuffer(__int64 Buffer);
__int64 FindBootSectorWithRetry(struct _DEVICE_OBJECT *, unsigned int);
__int64 FindBootablePartitionLba(__int64 Buffer);
void CheckDiskSectorHealth(char *Buffer);
__int64 FindReadableDiskSector(struct _DEVICE_OBJECT *, unsigned int, __int64);
char CheckBootSectorAndMbr(__int64, unsigned int);
char CheckBootSectorErrors(__int64, unsigned int);
// 磁盘扇区数据处理
__int64 __fastcall ProcessDiskSectorData(__int64 ObjectHandle, __int64 arg2, __int64 arg3, unsigned int arg4);

// 进程枚举与对象类型验证
bool EnumerateProcessList(struct _KPROCESS *Process, __int64 OutputBuffer, unsigned int BufferSize);
_QWORD *ValidateObjectTypeList(_QWORD *TypeEntryCheck);

// 系统信息查询辅助
void ValidateObjectTypeEntries(__int64 OutputBuffer);
void QueryObjectDirectoryAndEnumerate(__int64 OutputBuffer, unsigned int OutputSize);

// 磁盘扇区辅助（存根，待后续完整实现）
char CheckBootSectorAndMbrReal(__int64 Buffer, unsigned int Size);
char CheckBootSectorErrorsReal(__int64 Buffer, unsigned int Size);

char ExecuteWithThreadContext(__int64 Handle, __int64 VirtualAddress);
__int64 CheckObjectTypePointerMatch(__int64 VirtualAddress);
void ClearPageTableEntryFlags(char *VirtualAddress);
char SendCdbCommandToDevice(__int64 VirtualAddress);
__int64 ExecuteWithThreadFlagCleared(__int64 VirtualAddress);
char WritePhysicalMemory(unsigned __int64 TargetAddress, __int64 pWriteContext);
char WritePhysicalMemoryBuffer(unsigned __int64 TargetAddress, const void *SourceBuffer, unsigned int BufferSize, char ProcessorMode, void *pReadBack);
void WritePhysicalMemoryDword(ULONG64 TargetAddress, ULONG Value);
char WritePhysicalMemoryFromGt(GLOBAL_TABLE_INDEX AddressGtIndex, GLOBAL_TABLE_INDEX ValueGtIndex);
char WritePhysicalMemoryQword(unsigned __int64 TargetAddress, __int64 Value);
__int64 WriteProcessContextEntry(__int64 pInputEntry);
__int64 WriteProcessContextEntryWin7(ULONG *pInputEntry);
char WriteProcessMemoryBuffer(_QWORD *InputParams);
char WriteProcessMemoryValue(_QWORD *InputParams);
__int64 __fastcall WritePtrToAddress(_QWORD *pTarget);
__int64 WriteThreadContextEntryWin10(ULONG *pInputEntry);
__int64 ZeroProcessMemoryPages(PRKPROCESS PROCESS);

// PEDecoder globals
extern const UCHAR g_PeDataDescrambleTable[5120];
extern const UCHAR g_PeLegacyDescrambleTable[5120];

// DriverEntry globals
extern wchar_t g_DeviceNameBuffer[];
extern wchar_t g_SymlinkNameBuffer[];
extern KEVENT g_Event;

// ForEachProcessor
__int64 ForEachProcessor(__int64 (*pCallbackFunc)(__int64, __int64), __int64 Context);

// PE Decoder global tables (defined in DecodeTables.c)
extern const UCHAR g_PeDecodeTableMode0[5120];
extern const UCHAR g_PeDecodeTableMode3[5120];
extern const UCHAR g_PeDecodeTableMode4[5120];
extern const UCHAR g_PeDecodeTableGrp1[960];
extern const UCHAR g_PeDecodeTableModrmMem[160];
extern const UCHAR g_PeDecodeTableGrp2[];
extern const UCHAR g_PeDecodeTableGrp3[];
extern const UCHAR g_PeDecodeTableGrp4[];
extern const UCHAR g_PeDecodeTableGrp5[];
extern const UCHAR g_PeDecodeTableGrp6[];
extern const ULONG g_PeDataTypeSizeTable[];
extern const ULONG g_PeDataTypeSubTypeTable[];
extern const ULONG64 g_PeDecodeFunctionTable[];
extern const UCHAR g_PeDecodeTableOneByte[160];
extern const UCHAR g_PeDecodeTableTwoByte0F[320];
extern const UCHAR g_PeDecodeTableTwoByte38[320];
extern const UCHAR g_PeDecodeTableTwoByte3A[320];
extern const UCHAR g_PeDecodeTableModrmReg[160];
extern const UCHAR g_PeDecodeTableOpcodeByte[];
extern const ULONG64 g_PeMultiByteTable1[];
extern const ULONG64 g_PeMultiByteTable2[];

// WDM driver entry points
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
char __fastcall DispatchFindExportTableOffset(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char __fastcall FindExportTableOffsetV1(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char __fastcall FindExportTableOffsetV2(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char __fastcall DispatchStorPortIoControl(_OWORD *FunctionTable);

// Minifilter

char MiniFilterContextCleanup(ULONG64 Unknown, ULONG Unknown2, ULONG64 OutputBuffer, ULONG BufferSize);

// Global mutex
extern KMUTEX g_Mutex;

// Missing function declarations (stubs in MissingFuncs.c)
BOOLEAN CopySectionString(__int64 OutputBuffer, __int64 DeviceEntry, __int64 DriverEntry, int DeviceType);
__int64 OpenUSBPortSection(void);
__int64 DecryptProcessContextStr(void);
__int64 OpenIpsecDriverSection(void);
char FreeProcessMemoryEntry(__int64 VirtualAddress);
__int64 GetCallbackContextBase2(void);
__int64 GetObjectContextBase(void);
__int64 BuildRegistryDriverPath(void);
__int64 GetSyscallContextBase(void);
char ModifyObjectHeaderFlagsByVersion(__int64 ObjectHeader, char SetFlag);
__int64 ResolveKernelModuleFunctionAddrs(void);
__int64 GetProcessContextBase(void);
__int64 OpenVolumeDriverSection(void);
bool ReadDisksSysFile(_QWORD *FileBuffer, unsigned int *FileSize);
bool ReadCdromSysFile(_QWORD *FileBuffer, unsigned int *FileSize);
bool ReadKbdClassSysFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadIpsecSysFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
bool ReadUSBPortDriverFile(_QWORD *OutBuffer, unsigned int *OutSize);
bool ReadVolumeSysFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
char ReadWin32kFullDriverFile(__int64 *pBuffer, unsigned int *pSize);
char ReadWin32kBaseDriverFile(__int64 *pBuffer, unsigned int *pBufferSize);
bool ReadWin32kDriverFile(_QWORD *pFileBuffer, unsigned int *pFileSize);
char VerifyServiceTableDriverFile(__int64 DiskBuffer, unsigned int DiskSize);
void BuildProcessContextExportTable(void);
__int64 QueryObjectOperationByVersion(__int64 ImageBase, int ImageSize, int SectionBase);
__int64 FindObjectOperationBaseOffset(__int64 ImageBase, int ImageSize, int SectionBase);
__int64 FindObjectOperationDataSection(__int64 ImageBase, int ImageSize, int SectionBase);
char CmdObjectOperationByHandle(__int64 *pInputBuffer, int InputSize);
char CompareKernelPageAttached(void *PageAddress, _DWORD *OutputBuffer, struct _KPROCESS *TargetProcess, __int64 (*ReadMemoryCallback)(void *));
char DecryptAesHexString(unsigned char *HexBuffer, unsigned int HexLength, _QWORD *pSyscallCount);
char DispatchObjectOperationInit(__int64 ImageBase, unsigned int ImageSize);
__int64 QueryDriverObjectByPath(__int64 TargetPath, int MaxNameLength, __int64 OutputBuffer, int MaxEntries);
__int64 GetCallbackContextBase(void);
void ReadNtOsKrnlAndParseServiceTable(void);
__int64 ParseServiceTable(char *Src, size_t MaxCount);
char ParseServiceTableWin8(char *Src, size_t MaxCount);
char ParseServiceTableWin7(char *Src, size_t MaxCount);
bool InitProcessAndQueryInfo(struct _KPROCESS *ProcessObject, char Flags);
__int16 FindNtRenameKeyTarget(__int64 TargetBase, unsigned int TargetSize, __int64 Context, unsigned __int64 MaxOffset);

// MissingFuncs.c 子函数声明
__int64 ScanWin32kPatternLegacy(__int64 OutputBuffer, unsigned int EntryCount);
__int64 ScanWin32kPatternWin10Plus(__int64 OutputBuffer, unsigned int EntryCount);
void Md5Init(char *Context);
__int64 AesInitKeySchedule(void);
__int64 AesKeyExpansion(int *KeySchedule, int *Key, int KeySize);
__int64 AesDecryptBlocks(unsigned int *KeySchedule, unsigned char *Output, unsigned char *Input, unsigned int Length);
__int64 AesDecryptRounds(unsigned int *KeySchedule, unsigned int *Output, unsigned int *Input);
void BuildNtExportIndexTable(void);
__int64 SendIrpToDiskDevice(struct _DEVICE_OBJECT *DeviceObject, int Command, void *Buffer, int SectorCount, int BlockSize, int BlockCount);
char SaveAndReplaceDiskExtension(__int64 TargetObject, _QWORD *pSavedPointer);
char SaveAndReplaceDiskExtension2(__int64 TargetObject, _QWORD *pSavedPointer);
char SaveAndReplaceDiskExtension3(__int64 TargetObject, _QWORD *pSavedPointer);
char SaveAndReplaceDiskExtension4(__int64 TargetObject, _QWORD *pSavedPointer);
char SaveAndReplaceDiskExtension5(__int64 TargetObject, _QWORD *pSavedPointer);
char LookupStorPortFunctionTable(unsigned int Index, _OWORD *ExchangeData);
char LookupStorPortFunctionTable2(unsigned int Index, _OWORD *ExchangeData);
char QueryDiskExtensionFunctionTable(_OWORD *ExchangeData, _QWORD *pPresetValue);
char SaveDiskDeviceContextByIndex(char Index, _OWORD *ContextData);
char SaveDiskDeviceContextByIndexV2(char Index, _OWORD *ContextData);
char SaveDiskDeviceContextByIndexEx(char Index, unsigned int EntryIndex, _OWORD *ContextData);
char SaveDiskDeviceContextByIndexV3(char Index, unsigned int EntryIndex, _OWORD *ContextData);
__int64 CdbCommandCompletionCallback(void *Irp);
__int64 __fastcall RxTdiRequestCompletion(void *DeviceObject, void *Irp, void *Context);
__int64 FindObjectOperationExportWin10(__int64 ImageBase, unsigned int ImageSize);
__int64 ReadSystemDllAndInitSession(void);
void InitIrpBufferWithCdb(__int64 Buffer, __int64 Address, unsigned int Flags, __int64 CompletionRoutine, unsigned int BlockSize, unsigned int BlockCount, unsigned int CdbFlags, unsigned int CdbParam);
__int64 EnumObjectLinkedListSingle(_QWORD *pObjectTable, _QWORD *pOutput, _DWORD *pCount, int MaxEntries);
__int64 FindObjectOperationOffset(__int64 ImageBase, int ImageSize, int SectionBase);
char ReadRegistryDriverFile(char **pFileBuffer, unsigned int *pFileSize);
char ParseKernelModuleSectionTable(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable);
__int64 FindObjectOperationSection(__int64 ImageBase, int ImageSize, int SectionBase);
void ScanProcessPESections(void);
char ReadNtoskrnlForObjectContext(char **pFileBuffer, unsigned int *pFileSize);
__int64 EnumObjectLinkedListWin8(_QWORD *pObjectTable, _QWORD *pOutput, _DWORD *pCount, int MaxEntries);
__int64 EnumObjectLinkedListWin7(_QWORD *pObjectTable, _QWORD *pOutput, _DWORD *pCount, int MaxEntries);
char ParseNtFileForCallbackContext(__int64 pFileBuffer, unsigned int FileSize, __int64 pExportTable);
char ParseNtSectionsForContextTable(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char ParseNtExportSectionsV3(__int64 ImageBase, unsigned int ImageSize, __int64 pTargetTable);
char ParseCallbackFunctionSections(__int64 ImageBase, unsigned int ImageSize, __int64 SectionBase, __int64 pTargetTable, __int64 pAlternateTable, char IsVersion2);
char ParseCallbackContextSections(__int64 ImageBase, unsigned int ImageSize, __int64 SectionBase, __int64 pTargetTable, __int64 pAlternateTable);
char __fastcall ParseNtSectionHeaders2(__int64 ImageBase, unsigned int ImageSize, __int64 ExportDataBase, __int64 OutputTable);
char __fastcall ParseExportDirForDiskInfo(__int64 ImageBase, unsigned int ImageSize, __int64 ExportDataBase, __int64 OutputTable);
char __fastcall FindSyscallTableDescriptor(__int64 a1, unsigned int a2, __int64 a3);
char __fastcall BuildExportSectionMapping(__int64 a1, unsigned int a2);
char __fastcall CollectSyscallEntries4(__int64 a1, unsigned int a2, __int64 a3);
char __fastcall CollectTwoSyscallTables(__int64 a1, unsigned int a2, __int64 a3);
char __fastcall CollectSyscallExportEntries(__int64 a1, unsigned int a2, __int64 a3);
char ParseNtExportSections(__int64 PeBase, unsigned int PeSize, __int64 OutputTable);
__int64 InitObjectOperationLegacy(void);
__int64 ResolveSyscallAddressesInProcess(void);
void ClearProcessPageTableFlags(struct _KPROCESS *Process);
__int64 ValidateWin32kFullDriverImage(__int64 DiskBuffer, unsigned int DiskSize);
unsigned char CheckStringPrefixNt(__int64 NamePtr);

// Batch1.c 函数声明
__int64 CmdQueryFileEndOfFile(HANDLE FileHandle, _QWORD *pResult);
char CheckTmDllSection(unsigned __int8 *NameToMatch);
char QueryDiskInfoAta(char *Buffer, unsigned int BufferSize, unsigned int *OutSize);
char SendAtaScsiCommand(char *Buffer, unsigned int BufferSize, unsigned int *OutSize);
char BuildDevicePath(char *Buffer, unsigned int BufferSize);
char QuerySystemInfoPart1(_DWORD *Buffer, unsigned int BufferSize, _DWORD *OutSize);
char QuerySystemInfoPart2(_DWORD *Buffer, unsigned int BufferSize, _DWORD *OutSize);
char InitNsiEnumerateObjects(void);
char ReadNtoskrnlToBuffer(void **FileBuffer, unsigned int *FileSize);
char ParseNtoskrnlSectionsForKernelBase(__int64 PeBase, unsigned int PeSize);
void *j_GetCurrentFiber(void);
char ReadNtFileDiskInfo(void **FileBuffer, unsigned int *FileSize);
char FindHalInitPatternOffsets(__int64 PeBase, unsigned int PeSize);
char ComparePeHeaders(__int64 Image1, unsigned int Image1Size, __int64 Image2, unsigned int Image2Size);
char InitSessionStateTable(__int64 PeBase, unsigned int PeSize);

// ===== Global table access functions =====
extern __int64 GtRead(GLOBAL_TABLE_INDEX Index);
extern __int64 GtWrite(GLOBAL_TABLE_INDEX Index, __int64 Value);

// ===== Missing function declarations needed by MissingFuncs.c =====
void ExFree(void *Buffer);
char FindExportInFileByName(__int64 PeBase, unsigned int PeSize, __int64 OutEntry);
char ComparePeModuleSignature(char *pSignature1, __int64 Signature2, unsigned int SignatureSize);
__int64 *GtAlloc(enum _GLOBAL_TABLE_INDEX Index);
__int64 InitHookFunctionTable(void);
__int64 ResolveKernelModuleFunctionAddrs(void);
__int64 ScanKernelModulePESectionsEx(void);
__int64 LookupDriverHashTable(__int64 DriverName, _DWORD *pExportIndex);
char TraverseEprocessListAndInit(struct _KPROCESS *Process);
bool ReadNtFileForSsdtTargets2(_QWORD *pFileBuffer, unsigned int *pFileSize);
__int64 ResolveSyscallAddressesWithAttach(void);
PVOID GetCurrentFiber(void);

// ===== Byte swap utilities =====
ULONG64 ByteSwap64(ULONG64 Value);

// ===== String utilities =====
_BYTE *StringCopy(_BYTE *Dest, __int64 Src, unsigned int MaxLen);
__int16 *WStringCopy(__int16 *Dest, __int16 *Src);
_WORD *WStringCopyN(_WORD *Dest, __int64 Src, unsigned int MaxLen);
// =================================================================
// ===== Functions missing from header declarations =====
__int64 EnumProcessHandleInfo(_QWORD *pHandleTable, unsigned int *pInfoList, _OWORD *OutputBuffer, int MaxCount);
__int64 FindWin32kServiceTable(__int64 PeBase, unsigned int PeSize);
void InitObjectOperationEntry(void);
__int64 ParseMsrRelatedSections(void);
__int64 ParseMsrTableFromSections(void);
__int64 ParseNtExportFunctions(void);
__int64 ParseNtExportFunctionsV2(void);
__int64 LookupMsrTableEntry(void);
__int64 QueryObjectTypeInformation(PVOID Object);
char ParseNtImageSections2(__int64 PeBase, unsigned int PeSize);
char ParseNtRelocSection(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable);
char ParseServiceTableExportEntry(void *Src, size_t MaxCount, __int64 ServiceIndex);
char RemoveObjectFromLinkedList(_QWORD *pEntry, __int64 TableIndex);
char RemoveObjectFromLinkedListLegacy(_QWORD *pEntry, __int64 TableIndex);
char RemoveObjectSingleLinkedListLegacy(_QWORD *pEntry, __int64 TableIndex);

// 以下为新添加的内部函数声明
char MiniFilterStreamHandleCleanup(PRKPROCESS PROCESS, __int64 CallbackContext, ULONG64 ContextFlag, __int64 BaseOffset, __int64 (*CallbackFunc)(void));
void InitDriverModuleParsing(void);
__int64 BuildSystemRootPath(void);
__int64 QuerySystemInfoAllocateBuffers(unsigned int SystemInformationClass, __int64 Argument2, int Argument3, __int64 *pBuffer1, int Buffer1Count, __int64 *pBuffer2, int Buffer2Count, __int64 *pBuffer3, int Buffer3Count, _QWORD *pBuffer4, int Buffer4Count, _DWORD *pRequiredSize);
void CopyUnicodeStringSafe(const void **pSrcString, _WORD *pDstBuffer, int MaxLength);
void FreeAllocatedBuffers(void *Buffer1, void *Buffer2, void *Buffer3, void *Buffer4);
__int64 ResolveStreamHandleContext(void);
__int64 GetSystemRootForThread(PRKPROCESS PROCESS);
__int64 ScanKernelDiscardableSection(unsigned int SectionIndex);
bool ReadWdfLoaderModule(_QWORD *pBuffer, unsigned int *pBufferSize);
bool ReadWdfLibraryModule(_QWORD *OutBuffer, unsigned int *OutSize);
void ParseDriverInitSection(__int64 PeBuffer, unsigned int PeSize, __int64 RelocBase);

// ===== PE 节区解析和内核数据节区查找函数 =====
__int64 ParseNtSectionsForSsdtTable(void);
__int64 ParseNtSectionsForProcessMemory(void);
__int64 ParseNtSectionsForModuleBase(void);
__int64 ParseNtSectionsForRelocBase(void);
__int64 ParseNtSectionsForShadowSsdt(void);
__int64 ParseProcessMemSections(void);
__int64 FindKernelDataSectionOffset(void);
__int64 FindKernelDataSectionOffsetEx(void);
__int64 FindKernelDataSectionOffsetV2(void);
__int64 FindKernelDataSectionOffsetV3(void);
__int64 DispatchFindKernelDataSection(void);
// 以下为内核数据节区查找子函数（由上方函数调用）
__int64 FindKernelDataSectionOffsetWin7(void);
__int64 FindKernelDataSectionOffsetWin8(void);
__int64 FindKernelDataSectionPair(void);
__int64 FindKernelDataSectionOffsetWin10(void);
ULONG64 FindKernelInitSection(void);
__int64 FindKernelDataSectionForCreateFile(void);
__int64 FindKernelDataSectionV2Dispatch(void);
__int64 FindKernelDataSectionForWriteMemory(void);
__int64 FindKernelDataSectionV3Dispatch(void);
__int64 FindKernelDataSectionForReadMemory(void);
__int64 FindKernelDataSectionForImageNotify(void);
__int64 FindKernelDataSectionForOpenSection(void);
__int64 FindKernelDataSectionForStringParam(void);
__int64 FindKernelDataSectionByDebug(void);
ULONG64 FindKernelDataSectionDispatch(void);
ULONG64 FindKernelDataSectionByCode(void);
ULONG64 FindKernelDataSectionByData(void);
__int64 InitImageNotifyWin7(void);

// SSDT 解析辅助函数（在 NT 文件/PE 节区中查找 SSDT 表指针和偏移）
char FindSsdtSignatureInNtFile(unsigned __int8 *pScanBuffer, unsigned __int64 BufferEnd, _QWORD *pSsdtTable, _QWORD *pSsdtOffset);
char FindSsdtServiceTableEntry(unsigned __int8 *pScanBuffer, unsigned __int64 BufferEnd, _QWORD *pSsdtTable, __int64 *pSsdtOffset);
char ResolveSsdtNtOffset(unsigned __int8 *pScanBuffer, unsigned __int64 BufferEnd, _QWORD *pSsdtTable, __int64 *pSsdtOffset);
bool FindSsdtTableAddresses(__int64 pSectionData, int SectionEnd, _QWORD *pSsdtTable, __int64 *pSsdtOffset);
char ResolveSsdtTablePointer(__int64 pSectionData, int SectionEnd, _QWORD *pSsdtTable, _QWORD *pSsdtOffset);
char ResolveSsdtTablePointerEx(__int64 pSectionData, int SectionEnd, _QWORD *pSsdtTable, _QWORD *pSsdtOffset);


// 缺失的辅助函数声明
__int64 GetProcessDeviceMap(_QWORD *pEprocessPtr);
__int64 FindPESectionByIndex(unsigned int SectionIndex);
__int64 DispatchParseNtExportSectionsV2(void);
char ValidateIoPortSection(__int64 Address);
char ParseNtExportSectionsV4(void);
__int64 ParseNtExportSectionsV2(void);
__int64 ParseNtExportSectionsWin10(void);
void ReadIdtr(void *pIdtr);

// ============================================================
// 跨文件函数声明（消除 C4013 未声明警告）
// ============================================================
void *AllocProcessInfoBuffer(void);
void BuildCallbackContextHookTargets(void);
_WORD *BuildDriversPath(void);
__int64 BuildFsFilterDriverPath1();
__int64 BuildFsFilterDriverPath2();
void BuildSsdtHookTargets2(void);
void BuildSsdtHookTargets3(void);
void BuildSsdtHookTargets4(void);
_WORD *BuildSystem32Path(void);
bool CallRegisteredCallback(__int64 Address);
__int64 CheckProcessAccess(void);
LONG CleanupMiniFilter(void);
__int64 SelectMiniFilterCallbackByVersion(void);
__int64 SelectMiniFilterCleanupCallback(void);
__int64 SelectMiniFilterDirEnumCallback(void);
unsigned __int64 SelectMiniFilterWriteReadCallback(void);
char MiniFilterQueryFileName(wchar_t *FileName);
bool CompareInt16Equal(__int16 Value1, __int16 Value2);
char DispatchProcessHandleTableEnum(
    __int64 OutputBuffer, unsigned int BufferSize,
    void (__fastcall *Callback)(__int64, __int64, ULONG64, __int64),
    __int64 Context);
__int64 EnumFileSystemCallbackEntries(void);
bool EnumProcessInformationWorker(char *InputBuffer, __int64 OutputBuffer, unsigned int BufferSize);
char EnumProcessPeExportData();
char EnumProcessPeExportDataByIndex();
char EnumProcessPeExportDataEx();
__int64 (__fastcall *__fastcall EnumerateDriverObjectsEx(unsigned int *pOutputBuffer, unsigned int OutputSize))(_QWORD);
__int64 EnumerateKernelModules(unsigned int *pOutputBuffer, unsigned int OutputSize);
char EnumerateProcessCallbackContext(void);
char FillExportEntrySlot(__int64 pOutputTable);
char FindPatchThreadWindowsExport(__int64 FileBuffer, unsigned int FileSize);
__int64 FindPeSectionByType0x510(__int64 FileBuffer, int FileSize, int BaseAddress, unsigned int MaxSize);
char FindSsdtServiceTableV1(void);
char FindSsdtServiceTableV2(void);
char FindSsdtServiceTableV3(void);
__int64 FindSystemRootEntry(_DWORD *ThreadInfoTable);
bool GetDeviceObjectFromFileObject(ULONG64 FileObject, ULONG64 *pDeviceObject, ULONG64 *pFileDeviceObject);
_QWORD *GetDiskDriverSection(void);
unsigned __int64 GetKernelVirtualAddressRange(__int64 DriverObject, unsigned __int64 *pStartAddress, unsigned __int64 *pEndAddress);
__int64 GetSsdtTableOffset(__int64 SsdtTable, __int64 DefaultOffset);
__int16 HookSyscallNtRenameKey(__int64 TargetAddress, unsigned int Flags, __int64 Context, unsigned __int64 MaxOffset);
__int64 InitCallbackFunctions(void);
char InitDiskQueryExportTable(void);
void InitKernelDataSectionTable(void);
char InitKernelObjectHeader(char *VirtualAddress);
_QWORD *InitKernelRoutineTable(void);
char InitObjectCallbackFiles(int ObjectName);
WORD *InitSystemPath(void);
void InitTdiExportAndRelocTable(void);
__int64 MiniFilterTeardownRoutine(void *NameBuffer, size_t BufferSize, char IsAddOperation);
__int64 OpenDeviceObjectForEnum(__int64 DeviceContext);
bool ParseNtDataSectionRelocs(__int64 SectionBase, int SectionOffset, int TargetSize, _OWORD *pRelocOffsets);
char ParseStorPortExportDir(void);
void ParseSyscallTableExportDir(void);
char __fastcall ParseSyscallTableDataSection(__int64 FileBuffer, unsigned int FileSize, __int64 Context);
char ParseSyscallTableSections(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable);
bool QueryFileInfoByHandle(__int64 Process, __int64 FileHandle, __int64 InfoBuffer);
__int64 QueryObjectTypeDirectoryPath(void);
char QueryProcessModuleFilePath(__int64 Process, __int64 ModuleBase, _WORD *pOutputBuffer, int BufferSize);
char ReadModifyWriteDiskSector(int UseProcessDiskData, unsigned int SectorIndex);
ULONG64 ReadMsr(ULONG MsrIndex);
ULONG64 WriteMsr(ULONG MsrIndex, ULONG64 Value);
char ReadNtFileForProcessContext(_QWORD *OutBuffer, unsigned int *OutSize);
char __fastcall ReadRawFileToBuffer(_QWORD *pFileBuffer, unsigned int *pFileSize);
__int64 ReadWriteKernelMemory(void);
UCHAR ReferenceObjectSafe(__int64 Object);
char RemoveDeviceObject(__int64 DriverObject);
char RemoveHarddiskVolume1Device(__int64 DriverObject);
char RemovePnpManagerDriverObject(__int64 DriverObject);
char RemoveTdxDriverObject(__int64 DriverObject);
__int64 ResolveContextMemoryBlocks(__int64 pContextTable, unsigned int EntryCount);
__int64 ResolvePESectionOffset(void);
char ResolveSyscallNumbers(void);
ULONG64 RotateLeft64Impl(ULONG64 Value, int Count);
char ScanKernelPeExportData();
char ScanKernelPeExportSection();
bool ScanPESectionPatterns(_BYTE *Pattern, char *TargetData, int DataSize, char UsePESection);
__int64 ScanProcessPESectionsV2(void);
bool __fastcall SendIoControlWithQueryBuffer(__int64 Handle, unsigned int CommandType, _BYTE *OutputBuffer, int BufferSize, size_t *ReturnSize);
void Sha1FinalTransform(PSHA1_CONTEXT Context, __int64 DigestOut);
void Sha1InitContext(PSHA1_CONTEXT Context);
void Sha1Update(PSHA1_CONTEXT Context, PUCHAR Input, ULONG Length);
char ValidateProcessContext(unsigned int *OutputBuffer, unsigned int BufferSize);
bool ValidateProcessObjectBasic(char *VirtualAddress);
char ValidateSsdtHookTargetTable(__int64 pTargetTable);
char ValidateSsdtHookTargetTable2(__int64 pTargetTable);
char __fastcall ValidateWin32kBaseDriverImage(__int64 DiskBuffer, unsigned int DiskSize);
_WORD *WStringConcat(_WORD *Dest, __int16 *Src, unsigned int MaxLen);
__int16 *WStringFindChar(__int16 *String, __int16 Char);
_WORD *WStringFindLastChar(_WORD *String, __int16 Char);
char WriteDiskSectorsWithMbr(int UseProcessDiskData, unsigned int SectorOffset);

// 未文档化 NT 内核 API（不存在于 WDK 头文件）
NTSTATUS ObCreateObject(
    KPROCESSOR_MODE PreviousMode,
    POBJECT_TYPE ObjectType,
    POBJECT_ATTRIBUTES ObjectAttributes,
    KPROCESSOR_MODE ObjectMode,
    ULONG Attributes,
    ULONG ObjectSize,
    PVOID PagedPoolQuota,
    PVOID NonPagedPoolQuota,
    PVOID *Object);
NTSTATUS SeCreateAccessState(
    PACCESS_STATE AccessState,
    PACCESS_STATE PreviousState,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping);
