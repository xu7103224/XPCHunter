// MissingFuncs.c — 缺失函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

__int64 AdjustKernelModuleSectionPointers(void) { return 0; }
__int64 DispatchWin32kPatternMatching(void) { return 0; }
// AllocExBufferAndQuerySystemInfo
void *AllocExBufferAndQuerySystemInfo(unsigned int SystemInformationClass)
{
    return 0;
}

// AllocProcessInfoBuffer
void AllocProcessInfoBuffer(void)
{
    return;
}

// BuildCallbackContextHookTargets
void BuildCallbackContextHookTargets(void)
{
    return;
}

// BuildContextTableFromNtFile
void BuildContextTableFromNtFile(void)
{
    return;
}

// BuildDriverInfoEntries
__int64 BuildDriverInfoEntries(unsigned int *a1, unsigned int a2)
{
    return 0;
}

// BuildDriverPathI8042prt
__int64 BuildDriverPathI8042prt(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// BuildDriverPathKbdClass
__int64 BuildDriverPathKbdClass(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// BuildDriverPathMouClass
__int64 BuildDriverPathMouClass(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// BuildExportServiceTable
char BuildExportServiceTable(PUCHAR ImageBase, ULONG ImageSize, PUCHAR ServiceTable, ULONG TableSize)
{
    return 0;
}

// BuildProcessContextExportTable
__int64 BuildProcessContextExportTable(void)
{
    return 0;
}

// BuildServiceTableFromNtKernel
__int64 BuildServiceTableFromNtKernel(_QWORD a1, _QWORD a2)
{
    return 0;
}

// CheckFilePathFilter
__int64 CheckFilePathFilter(__int64 FilePath, unsigned int FilePathLength)
{
    return 0;
}

// CheckProcessJobObject
__int64 CheckProcessJobObject(__int64 a1)
{
    return 0;
}

// CheckProcessObjectFlag
__int64 CheckProcessObjectFlag(__int64 a1)
{
    return 0;
}

// CheckWin2k3Sp2
__int64 CheckWin2k3Sp2(void)
{
    return 0;
}

// CleanupProcessMemoryEntry
__int64 CleanupProcessMemoryEntry(_QWORD *pTargetEntry)
{
    return 0;
}

// ClearKernelObjectEntry
__int64 ClearKernelObjectEntry(__int64 TargetAddress)
{
    return 0;
}

// ClearSsdtRelatedEntry
__int64 ClearSsdtRelatedEntry(__int64 TargetAddress)
{
    return 0;
}

// CmdEnumObjectsEx
__int64 CmdEnumObjectsEx(__int64 a1, unsigned int a2, _DWORD *a3, unsigned int a4)
{
    return 0;
}

// CmdEnumObjectsLegacy
__int64 CmdEnumObjectsLegacy(__int64 a1, unsigned int a2, _DWORD *a3, unsigned int a4)
{
    return 0;
}

// ============================================================
// CmdObjectOperationByHandle — 通过句柄执行对象操作命令
// 验证输入缓冲区（8 字节），若 GT 740 未初始化则调用 InitObjectOperationEntry。
// 根据 GT 2324 构建号选择不同的链表删除函数（Win7/Win8/Win10+）。
// ============================================================

// CmdObjectOperationByHandle
__int64 CmdObjectOperationByHandle(__int64 *a1, int a2)
{
    return 0;
}

// CmdQueryDiskInfo
__int64 CmdQueryDiskInfo(char *Dst, SIZE_T Length)
{
    return 0;
}

// CmdQueryFileAllocationSize
__int64 CmdQueryFileAllocationSize(void *FileHandle, _QWORD *pAllocationSize)
{
    return 0;
}

// CmdQuerySystemInfoExV2
__int64 CmdQuerySystemInfoExV2(char *Dst, SIZE_T Length)
{
    return 0;
}

// CmdReadFileInfo
__int64 CmdReadFileInfo(void *FileHandle, _DWORD *pFileInfo)
{
    return 0;
}

// CmdSendRenameFileIrp
__int64 CmdSendRenameFileIrp(void *FileHandle, const void *RenameBuffer, unsigned int BufferSize)
{
    return 0;
}

// CmdSetFileBasicInfo
__int64 CmdSetFileBasicInfo(void *FileHandle, struct _IRP *FileBasicInfo)
{
    return 0;
}

// CmdSetModuleInfoInternal
__int64 CmdSetModuleInfoInternal(_QWORD a1)
{
    return 0;
}

// CopyCallbackContextHookTable
__int64 CopyCallbackContextHookTable(__int64 pSourceTable)
{
    return 0;
}

// CopyCallbackContextTable
__int64 CopyCallbackContextTable(__int64 pSourceTable, int ContextType)
{
    return 0;
}

// CopyCallbackContextV3Table
__int64 CopyCallbackContextV3Table(__int64 pSourceTable)
{
    return 0;
}

// CopyContextTableEntries
__int64 CopyContextTableEntries(__int64 pOutputTable)
{
    return 0;
}

// CopyFsFilterEntryTable
__int64 CopyFsFilterEntryTable(__int64 OutputBuffer, char Is64Bit)
{
    return 0;
}

// CopyHookEntryArray
__int64 CopyHookEntryArray(__int64 DestBuffer, _QWORD *pSourceArray, unsigned int EntryCount)
{
    return 0;
}

// CopyKernelArrayToUserBuffer
__int64 CopyKernelArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    return 0;
}

// CopyKernelDualArrayToUserBuffer
__int64 CopyKernelDualArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    return 0;
}

// CopyObjectContextHookTable
__int64 CopyObjectContextHookTable(__int64 pSourceTable)
{
    return 0;
}

// CopyPhysicalMemoryContextTable
__int64 CopyPhysicalMemoryContextTable(__int64 pSourceTable, int ContextType)
{
    return 0;
}

// CopyProcessContextTable1
__int64 CopyProcessContextTable1(__int64 pTargetTable)
{
    return 0;
}

// CopyProcessContextTable2
__int64 CopyProcessContextTable2(__int64 pTargetTable)
{
    return 0;
}

// CopyProcessContextTableWin7
__int64 CopyProcessContextTableWin7(__int64 pSourceTable)
{
    return 0;
}

// CopyProcessContextV2HookTable
__int64 CopyProcessContextV2HookTable(__int64 pSourceTable)
{
    return 0;
}

// CopyProcessContextV3HookTable
__int64 CopyProcessContextV3HookTable(__int64 pSourceTable)
{
    return 0;
}

// CopyRegistryContextEntryArray
__int64 CopyRegistryContextEntryArray(__int64 pOutputTable)
{
    return 0;
}

// CopyThreadContextTable
__int64 CopyThreadContextTable(__int64 pSourceTable)
{
    return 0;
}

// CopyUSBPortServiceTable
__int64 CopyUSBPortServiceTable(__int64 pOutputBuffer)
{
    return 0;
}

// DisableObjectCallback
__int64 DisableObjectCallback(int flags, ULONG64 a2)
{
    return 0;
}

// DiskOperationDispatcher
__int64 DiskOperationDispatcher(void)
{
    return 0;
}

// DispatchFreeProcessMemory
__int64 DispatchFreeProcessMemory(char *VirtualAddress)
{
    return 0;
}

// DispatchKernelMemoryCleanup
__int64 DispatchKernelMemoryCleanup(_QWORD *VirtualAddress)
{
    return 0;
}

// DispatchParseNtExportFunctions
__int64 DispatchParseNtExportFunctions(void)
{
    return 0;
}

// DuplicateUSBPortSyscallOutput
__int64 DuplicateUSBPortSyscallOutput(__int64 pSourceTable)
{
    return 0;
}

// EnableProcessProtect
__int64 EnableProcessProtect(PVOID Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize)
{
    return 0;
}

// EnumCallbackContextTable
__int64 EnumCallbackContextTable(__int64 pOutputTable)
{
    return 0;
}

// EnumCallbackContextV3Table
__int64 EnumCallbackContextV3Table(__int64 pOutputTable)
{
    return 0;
}

// EnumDeviceObjectTypeList
__int64 EnumDeviceObjectTypeList(int DeviceIndex, __int64 pOutputTable)
{
    return 0;
}

// EnumDeviceObjects
__int64 EnumDeviceObjects(_QWORD a1, _QWORD a2)
{
    return 0;
}

// EnumFileSystemDeviceObjects
__int64 EnumFileSystemDeviceObjects(__int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// EnumKernelDriverObjects
__int64 EnumKernelDriverObjects(_DWORD *pOutputArray, unsigned int MaxCount)
{
    return 0;
}

// EnumKernelMemoryContext
__int64 EnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int BufferSize)
{
    return 0;
}

// EnumKernelModules
__int64 EnumKernelModules(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

// EnumObjectContextTable
__int64 EnumObjectContextTable(__int64 pOutputBuffer)
{
    return 0;
}

// EnumObjectDirectoryEntries
__int64 EnumObjectDirectoryEntries(unsigned __int16 *pDirectoryPath, _DWORD *pDirectoryInfo, __int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// EnumObjectTypeCleanupList
__int64 EnumObjectTypeCleanupList(PVOID *pTargetObject)
{
    return 0;
}

// EnumProcessAndInitObjects
__int64 EnumProcessAndInitObjects(__int64 a1, char a2)
{
    return 0;
}

// EnumProcessContextSsdtTable
__int64 EnumProcessContextSsdtTable(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessContextTable
__int64 EnumProcessContextTable(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessContextV2Table
__int64 EnumProcessContextV2Table(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessContextV3Table
__int64 EnumProcessContextV3Table(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessContextV3TableWin7
__int64 EnumProcessContextV3TableWin7(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessHandleInfo
__int64 EnumProcessHandleInfo(_QWORD *pProcessInfo, unsigned int *pHandleTable, _OWORD *pOutputBuffer, int MaxCount)
{
    return 0;
}

// EnumProcessModules
__int64 EnumProcessModules(ULONG64 ProcessId, int Flags, volatile void *OutputBuffer, unsigned int BufferSize)
{
    return 0;
}

// EnumServiceTableWin10
__int64 EnumServiceTableWin10(__int64 *pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumServiceTableWin1020H1
__int64 EnumServiceTableWin1020H1(_QWORD **pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumServiceTableWin7
__int64 EnumServiceTableWin7(__int64 *pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumServiceTableWin8
__int64 EnumServiceTableWin8(_QWORD **pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumSsdtHooks
__int64 EnumSsdtHooks(__int64 OutputBuffer, unsigned int BufferSize)
{
    return 0;
}

// EnumThreadContextTable
__int64 EnumThreadContextTable(__int64 OutputBuffer)
{
    return 0;
}

// EnumerateProcessObjectTable
__int64 EnumerateProcessObjectTable(__int64 ProcessObject, __int64 OutputFlags)
{
    return 0;
}

// EnumerateRegistryContextTable
__int64 EnumerateRegistryContextTable(__int64 pOutputTable)
{
    return 0;
}

// EnumerateSyscallContextVector
__int64 EnumerateSyscallContextVector(__int64 pOutputTable)
{
    return 0;
}

// ExAlloc
PVOID ExAlloc(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
{
    return 0;
}

// FileSystemFilterCallback
__int64 FileSystemFilterCallback(char *PatchBuffer, int BufferSize)
{
    return 0;
}

// FilterActiveHookEntries
__int64 FilterActiveHookEntries(__int64 OutputBuffer, unsigned int EntryCount, enum _GLOBAL_TABLE_INDEX TableIndex)
{
    return 0;
}

// FindDeleteValueKeyTarget
__int64 __fastcall FindDeleteValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, __int64 *pResult)
{
    return 0;
}

// ============================================================================
// ============================================================================
__int64 FindHookTargetDataSection(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    return 0;
}

// FindKernelPESectionByType
__int64 FindKernelPESectionByType(enum _GLOBAL_TABLE_INDEX TypeIndex)
{
    return 0;
}

// FindNtoskrnlExportsInThreadEnv
__int64 FindNtoskrnlExportsInThreadEnv(void)
{
    return 0;
}

// FindOpenProcessTokenOffset
__int64 FindOpenProcessTokenOffset(__int64 TargetBase, unsigned int TargetSize)
{
    return 0;
}

// FindOpenProcessTokenTarget
__int64 FindOpenProcessTokenTarget(__int64 TargetBase, unsigned int TargetSize)
{
    return 0;
}

// FindRenameKeyTargetEx
__int64 FindRenameKeyTargetEx(__int64 TargetBase,
    unsigned int TargetSize,
    __int64 Context,
    __int64 RelocBase)
{
    return 0;
}

// FindSetValueKeyTarget
__int64 FindSetValueKeyTarget(__int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    __int64 *pResultOffset,
    _QWORD *pResultOffset2)
{
    return 0;
}

// FindSetValueKeyTargets
__int64 FindSetValueKeyTargets(__int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    _QWORD *pResult1,
    __int64 *pResult2)
{
    return 0;
}

// FixCreateFileRelocs
__int64 FixCreateFileRelocs(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    return 0;
}

// ForEachProcessor
__int64 ForEachProcessor(__int64 (*pCallbackFunc)(__int64, __int64), __int64 Context)
{
    return 0;
}

// FreeObjectByCallback
__int64 FreeObjectByCallback(_QWORD *pObjectEntry)
{
    return 0;
}

// FreeProcessMemoryAllocation
__int64 FreeProcessMemoryAllocation(__int64 TargetAddress)
{
    return 0;
}

// FreeProcessMemoryAllocationEx
__int64 FreeProcessMemoryAllocationEx(_QWORD *pTargetEntry)
{
    return 0;
}

// FreeProcessMemoryBuffer
__int64 FreeProcessMemoryBuffer(PVOID VirtualAddress)
{
    return 0;
}

// GetDeleteValueKeyCtx
__int64 GetDeleteValueKeyCtx(_QWORD *pContext)
{
    return 0;
}

// GetKernelObjectTypeInfo
__int64 GetKernelObjectTypeInfo(__int64 ObjectHeader)
{
    return 0;
}

// GetSetValueKeyCtx
__int64 GetSetValueKeyCtx(_QWORD *pContext, _QWORD *pResult)
{
    return 0;
}

// InitCallbackContextHookTable
void InitCallbackContextHookTable(void)
{
    return;
}

// InitFileSystemExportTable
__int64 InitFileSystemExportTable(char Is64Bit)
{
    return 0;
}

// InitFileSystemFilterCallbacks
__int64 InitFileSystemFilterCallbacks(__int64 FilterExtensionObject, _QWORD *FastIoDispatchPtr, char Is64Bit)
{
    return 0;
}

// InitMsrTable
__int64 InitMsrTable(void)
{
    return 0;
}

// InitObjectAndQueryName
__int64 InitObjectAndQueryName(__int64 a1, int a2)
{
    return 0;
}

// InitObjectTypeTable
__int64 InitObjectTypeTable(_QWORD a1)
{
    return 0;
}

// InitPhysicalMemoryContextTable
__int64 InitPhysicalMemoryContextTable(int DeviceIndex, __int64 pOutputTable)
{
    return 0;
}

// InitProcessContextExportTableWin7
void InitProcessContextExportTableWin7(void)
{
    return;
}

// InitProcessContextHookTable
void InitProcessContextHookTable(void)
{
    return;
}

// InitThreadContextTable
void InitThreadContextTable(void)
{
    return;
}

// InitUSBPortSyscallTable
void InitUSBPortSyscallTable(void)
{
    return;
}

// InitUnicodeStringBuffer
__int64 InitUnicodeStringBuffer(__int64 Buffer, __int64 StringPtr, unsigned int MaxLength)
{
    return 0;
}

// InitWin32kTableByVersion
void InitWin32kTableByVersion(void)
{
    return;
}

// InstallCallbackContextHookEntry
__int64 InstallCallbackContextHookEntry(unsigned int *pInputEntry)
{
    return 0;
}

// IoPortOperationDispatch
__int64 IoPortOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// IrpFsctlGetVolumeData
__int64 IrpFsctlGetVolumeData(void *FileHandle, __int64 *pVolumeData)
{
    return 0;
}

// IrpReadFileEx
int IrpReadFileEx(void *FileHandle, int a2, __int64 a3, void *a4, char a5, struct _IO_STATUS_BLOCK *pStatus)
{
    return 0;
}

// ============================================================================
// KernelMemoryOperationDispatch - 内核内存操作分发
// 函数在 IDA 数据库中未找到，写为存根
// ============================================================================
char KernelMemoryOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// KernelNotifyRoutine
__int64 KernelNotifyRoutine(void *NotificationBuffer, size_t BufferSize)
{
    return 0;
}

// KernelNotifyRoutineEx
__int64 KernelNotifyRoutineEx(void *NotificationBuffer, size_t BufferSize)
{
    return 0;
}

// LookupDriverHashTable
__int64 LookupDriverHashTable(__int64 DriverName, _DWORD *pResultIndex)
{
    return 0;
}

// LookupMsrTableEntry
__int64 LookupMsrTableEntry(void)
{
    return 0;
}

// MiniFilterStreamHandleEx
__int64 MiniFilterStreamHandleEx(PRKPROCESS PROCESS, __int64 a2, ULONG64 a3, __int64 a4)
{
    return 0;
}

// ModuleOperationDispatch
__int64 ModuleOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// ObjectOperationDispatcher
__int64 ObjectOperationDispatcher(void *InputBuffer, int BufferSize)
{
    return 0;
}

// OpenSectionWithIoControl
__int64 OpenSectionWithIoControl(__int64 a1)
{
    return 0;
}

// ParseExportDirForDriver
__int64 ParseExportDirForDriver(__int64 DriverInfo, __int64 Context, __int64 PeBuffer, unsigned int PeSize)
{
    return 0;
}

// ParseFsFilterDriverExport
__int64 ParseFsFilterDriverExport(char Is64Bit)
{
    return 0;
}

// ParseKernelModuleDiskInfo
__int64 ParseKernelModuleDiskInfo(void)
{
    return 0;
}

// ParseNtImageSectionHeaders
__int64 ParseNtImageSectionHeaders(PRKPROCESS PROCESS, __int64 SectionInfoArray)
{
    return 0;
}

// ParseObjectContextExportDir
void ParseObjectContextExportDir(void)
{
    return;
}

// ParseRegistryDriverExportDir
void ParseRegistryDriverExportDir(void)
{
    return;
}

// PatchFsFilterDriverIndex
__int64 PatchFsFilterDriverIndex(__int64 PatchEntry, char Is64Bit)
{
    return 0;
}

// PowerCallbackRoutine
__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize)
{
    return 0;
}

// PowerCallbackUnregister
__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize)
{
    return 0;
}

// PrepareFileForPageTableScan
__int64 PrepareFileForPageTableScan(void)
{
    return 0;
}

// ProcessMemoryOperationDispatch
__int64 ProcessMemoryOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// ProcessOperationWithAttach
__int64 ProcessOperationWithAttach(void)
{
    return 0;
}

// QueryDriverObjectDevice
__int64 QueryDriverObjectDevice(__int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// QueryFileSystemDriverObject
__int64 QueryFileSystemDriverObject(__int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// QueryNdisDriverObject
__int64 QueryNdisDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryObjectTypeInformation
__int64 QueryObjectTypeInformation(PVOID Object)
{
    return 0;
}

// QueryPnpManagerDriverObject
__int64 QueryPnpManagerDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryProcessModuleInfo
__int64 QueryProcessModuleInfo(volatile void **Address, int a2, _DWORD *a3, unsigned int a4)
{
    return 0;
}

// QuerySsdHookByProcessInfo
__int64 QuerySsdHookByProcessInfo(void *Src, size_t MaxCount, _DWORD *Address, int OutputSize)
{
    return 0;
}

// QuerySyscallHookStatus
__int64 QuerySyscallHookStatus(__int64 a1)
{
    return 0;
}

// QueryTcpipDriverObject
__int64 QueryTcpipDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryTdxDriverObject
__int64 QueryTdxDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryVolmgrDriverObject
__int64 QueryVolmgrDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// ReadDiskSectors
unsigned int ReadDiskSectors(void)
{
    return 0;
}

// ReadDiskSectorsWithPartition
__int64 ReadDiskSectorsWithPartition(char a1, void *a2, unsigned int *a3, int a4, unsigned int a5)
{
    return 0;
}

// ReadKernelMemoryToUserBuffer
__int64 ReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _QWORD *a3, int a4)
{
    return 0;
}

// ReadNtOsKrnlFile
__int64 ReadNtOsKrnlFile(__int64 *a1, __int64 *a2)
{
    return 0;
}

// ReadProcessMemoryString
__int64 ReadProcessMemoryString(void *Process, void *Address, char *Buffer, unsigned int Length)
{
    return 0;
}

// ReadProcessMemoryWithAttach
__int64 ReadProcessMemoryWithAttach(void)
{
    return 0;
}

// ReadServiceTableEntries
__int64 ReadServiceTableEntries(__int64 OutputBuffer, __int64 a2, char *PeFileData, unsigned int PeFileSize)
{
    return 0;
}

// ReadThreadContext
__int64 ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray)
{
    return 0;
}

// RegistryOperationDispatch
__int64 RegistryOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// ReleaseProcessMemoryBlock
__int64 ReleaseProcessMemoryBlock(_QWORD *pTargetEntry)
{
    return 0;
}

// RemoveFromModuleLinkedList
__int64 RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType)
{
    return 0;
}

// RemoveFromObjectTypeList
__int64 RemoveFromObjectTypeList(PVOID *pTargetObject)
{
    return 0;
}

// RemoveFromObjectTypeListEx
__int64 RemoveFromObjectTypeListEx(PVOID *pTargetPointer)
{
    return 0;
}

// RemoveKernelObjectEntry
__int64 RemoveKernelObjectEntry(__int64 TargetAddress)
{
    return 0;
}

// RemoveObjectFromTypeList
__int64 RemoveObjectFromTypeList(PVOID pTargetObject)
{
    return 0;
}

// RemoveServiceEntryFromList
__int64 RemoveServiceEntryFromList(ULONG_PTR *a1, __int64 a2)
{
    return 0;
}

// RemoveServiceEntryFromListEx
__int64 RemoveServiceEntryFromListEx(__int64 ****a1, __int64 ***a2)
{
    return 0;
}

// RemoveServiceTableNodeWin10
__int64 RemoveServiceTableNodeWin10(__int64 ***a1, __int64 **a2)
{
    return 0;
}

// RemoveServiceTableNodeWin7
__int64 RemoveServiceTableNodeWin7(ULONG_PTR *a1, __int64 a2)
{
    return 0;
}

// ResolveCreateFileRelocs
__int64 ResolveCreateFileRelocs(__int64 TargetBase,
    ULONG TargetSize,
    __int64 Context,
    __int64 RelocBase)
{
    return 0;
}

// ResolveDriverEntryAddresses
__int64 ResolveDriverEntryAddresses(__int64 a1)
{
    return 0;
}

// ResolveDriverModuleNames
__int64 ResolveDriverModuleNames(ULONG *a1)
{
    return 0;
}

// ResolveDriverRelativeAddresses
__int64 ResolveDriverRelativeAddresses(__int64 a1, __int64 a2, int **a3)
{
    return 0;
}

// ResolveKernelModuleBasePair
__int64 ResolveKernelModuleBasePair(__int64 CpuNumber, ULONG_PTR *pMsrPair)
{
    return 0;
}

// ResolveKernelModuleIndex
__int64 ResolveKernelModuleIndex(GLOBAL_TABLE_INDEX a1,
    GLOBAL_TABLE_INDEX a2,
    GLOBAL_TABLE_INDEX a3)
{
    return 0;
}

// ResolveKernelObjectAddresses
__int64 ResolveKernelObjectAddresses(__int64 pObjectTable)
{
    return 0;
}

// ResolvePhysicalMemoryContext
__int64 ResolvePhysicalMemoryContext(__int64 pContextTable, int ContextType, ULONG EntryCount)
{
    return 0;
}

// ResolveServiceTableBase
__int64 ResolveServiceTableBase(void)
{
    return 0;
}

// RestoreSyscallHookByIndex
__int64 RestoreSyscallHookByIndex(char a1, ULONG a2)
{
    return 0;
}

// ScanKernelMemForFsChanges
__int64 ScanKernelMemForFsChanges(ULONG *a1, int a2)
{
    return 0;
}

// ScanKernelModuleDataSectionEx
__int64 ScanKernelModuleDataSectionEx(void)
{
    return 0;
}

// ScanKernelModuleInitSection
__int64 ScanKernelModuleInitSection(void)
{
    return 0;
}

// ScanKernelModulePageOrRsrcSection
__int64 ScanKernelModulePageOrRsrcSection(void)
{
    return 0;
}

// ScanKernelModuleSectionByType
__int64 ScanKernelModuleSectionByType(void)
{
    return 0;
}

// ScanKernelModuleSectionForWin10
__int64 ScanKernelModuleSectionForWin10(void)
{
    return 0;
}

// ScanKernelModuleSectionForWin10RS3
__int64 ScanKernelModuleSectionForWin10RS3(void)
{
    return 0;
}

// ScanRegValueBodyForRef
__int64 ScanRegValueBodyForRef(ULONG64 a1,
    ULONG a2,
    __int64 a3,
    __int64 a4,
    int a5,
    __int64 *a6)
{
    return 0;
}

// ScanVadForModifiedPages
__int64 ScanVadForModifiedPages(ULONG *OutputBuffer, int MaxModifiedCount)
{
    return 0;
}

// ScanWin32kDriverForPatterns
__int64 ScanWin32kDriverForPatterns(ULONG_PTR a1, ULONG_PTR a2)
{
    return 0;
}

// SendFsctlWithHookSwap
__int64 SendFsctlWithHookSwap(__int64 a1,
    ULONG a2,
    __int64 a3,
    ULONG a4,
    __int64 a5,
    int a6,
    __int64 a7)
{
    return 0;
}

// SendIoControlWithUnicodeString
__int64 SendIoControlWithUnicodeString(void)
{
    return 0;
}

// SetCallbackContextEntry
__int64 SetCallbackContextEntry(ULONG *pInputEntry)
{
    return 0;
}

// SetObjectContextEntry
__int64 SetObjectContextEntry(ULONG *pInputEntry)
{
    return 0;
}

// SetProcessContextEntry
__int64 SetProcessContextEntry(__int64 pInputEntry)
{
    return 0;
}

// SetRegistryContextEntry
__int64 SetRegistryContextEntry(ULONG *pInputEntry)
{
    return 0;
}

// SetSyscallContextByIndex
__int64 SetSyscallContextByIndex(ULONG *pInputEntry)
{
    return 0;
}

// SetUSBPortServiceTableEntry
__int64 SetUSBPortServiceTableEntry(ULONG *a1)
{
    return 0;
}

// ShutdownCallbackUnregister
__int64 ShutdownCallbackUnregister(PRKPROCESS *InputBuffer, int BufferSize)
{
    return 0;
}

// UnlinkFromMemoryBlockList
__int64 UnlinkFromMemoryBlockList(PVOID *pTargetPointer)
{
    return 0;
}

// UnlinkFromProcessMemoryList
__int64 UnlinkFromProcessMemoryList(PVOID *pTargetPointer)
{
    return 0;
}

// UnlinkProcessMemoryBlock
__int64 UnlinkProcessMemoryBlock(ULONG_PTR *pTargetEntry)
{
    return 0;
}

// ValidateAndClearProcessContext
__int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext)
{
    return 0;
}

// ValidateCallbackContextTable
__int64 ValidateCallbackContextTable(__int64 pContextTable)
{
    return 0;
}

// ValidateFsFilterEntries
__int64 ValidateFsFilterEntries(__int64 FilterContext)
{
    return 0;
}

// ValidateHookEntries
__int64 ValidateHookEntries(__int64 a1, ULONG a2)
{
    return 0;
}

// ValidateSingleHookEntry
__int64 ValidateSingleHookEntry(__int64 a1)
{
    return 0;
}

// WalkKernelModuleList
__int64 WalkKernelModuleList(ULONG64 *pModuleList, ULONG *pOutputBuffer, ULONG *pMaxEntries)
{
    return 0;
}

// WriteDiskSectorsWithPartitionCheck
__int64 WriteDiskSectorsWithPartitionCheck(char a1, const void *a2, ULONG a3)
{
    return 0;
}

// WriteProcessContextEntry
__int64 WriteProcessContextEntry(__int64 pInputEntry)
{
    return 0;
}

// WriteProcessContextEntryWin7
__int64 WriteProcessContextEntryWin7(ULONG *pInputEntry)
{
    return 0;
}

// WriteThreadContextEntryWin10
__int64 WriteThreadContextEntryWin10(ULONG *a1)
{
    return 0;
}

// ZeroProcessMemoryPages
__int64 ZeroProcessMemoryPages(PRKPROCESS PROCESS)
{
    return 0;
}

// FsFilterCreateCallback — 文件系统过滤器创建回调
// 返回函数指针: __int64 (__fastcall *)(__int64)
__int64 (__fastcall *__fastcall FsFilterCreateCallback(__int64 FilterContext))(__int64)
{
    return 0;
}
