// MissingFuncs.c — 已全部分配到各源文件，此文件仅保留索引
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

// ===== Minifilter.c =====
// BuildFsFilterDriverPath1, BuildFsFilterDriverPath2, BuildRegistryDriverPath
// CheckFilePathFilter, InitFileSystemExportTable

// ===== Registry.c =====
// GetDeleteValueKeyCtx, FindDeleteValueKeyTarget, FindSetValueKeyTargets
// FindSetValueKeyTarget, FindNtRenameKeyTarget, FindRenameKeyTargetEx
// GetSetValueKeyCtx, ScanRegValueBodyForRef, CopyRegistryContextEntryArray
// FindOpenProcessTokenOffset, ResolveCreateFileRelocs, FindOpenProcessTokenTarget

// ===== SSDT.c =====
// GetSsdtTableOffset, ParseServiceTable, GetSyscallContextBase
// FindNtoskrnlExportsInThreadEnv, RemoveServiceEntryFromList
// RemoveServiceEntryFromListEx, RemoveServiceTableNodeWin10
// RemoveServiceTableNodeWin7, FilterActiveHookEntries, FindKernelPESectionByType
// VerifyServiceTableDriverFile, ResolveKernelModuleFunctionAddrs
// DispatchWin32kPatternMatching, InitMsrTable, ValidateHookEntries
// ResolveServiceTableBase, RestoreSyscallHookByIndex, LookupDriverHashTable
// EnumKernelDriverObjects, ScanWin32kPatternLegacy, FindMatchingServiceEntry
// ScanWin32kPatternWin10Plus, CheckStringPrefixNt, BuildNtExportIndexTable
// ReadNtOsKrnlAndParseServiceTable, ReadNtOsKrnlFile, ReadWin32kFullDriverFile
// DispatchParseNtExportFunctions, ValidateWin32kFullDriverImage

// ===== ObjectMgmt.c =====
// CheckObjectTypePointerMatch, GetKernelObjectTypeInfo, CmdEnumObjectsEx
// CmdEnumObjectsLegacy, CmdObjectOperationByHandle, DispatchObjectOperationInit
// CompareKernelPageAttached, FindObjectOperationDataSection
// FindObjectOperationBaseOffset, QueryObjectOperationByVersion
// EnumProcessAndInitObjects, ParseObjectContextExportDir
// EnumerateProcessObjectTable, ResolveKernelObjectAddresses
// ModifyObjectHeaderFlagsByVersion, FindObjectOperationExportWin10
// EnumObjectLinkedListSingle, FindObjectOperationOffset
// FindObjectOperationSection, EnumObjectLinkedListWin8
// EnumObjectLinkedListWin7, ParseNtExportSections, InitObjectOperationLegacy
// ResolveSyscallAddressesInProcess

// ===== ModuleMgmt.c =====
// ResolveDriverRelativeAddresses, ResolveDriverEntryAddresses
// ResolveKernelModuleBasePair, ResolveKernelModuleBasePair2
// AdjustKernelModuleSectionPointers, ResolveKernelModuleIndex
// WalkKernelModuleList, BuildDriverInfoEntries, ParseKernelModuleDiskInfo
// ParseRegistryDriverExportDir, ParseExportDirForDriver
// BuildProcessContextExportTable, ReadRegistryDriverFile
// ParseKernelModuleSectionTable, ReadNtoskrnlForObjectContext
// ScanProcessPESections, ParseNtImageSectionHeaders

// ===== ProcessMgmt.c =====
// CheckProcessObjectFlag, CheckProcessJobObject, ReadProcessMemoryWithAttach
// ExecuteWithThreadContext, ExecuteWithThreadFlagCleared, EnableProcessProtect
// ResolvePhysicalMemoryContext, ProcessOperationWithAttach
// UnlinkFromProcessMemoryList, ValidateAndClearProcessContext

// ===== Protocol.c =====
// CheckMbrBootablePartition, CmdQueryFileAllocationSize, CmdReadFileInfo
// CmdSetFileBasicInfo, CmdSendRenameFileIrp, DispatchDiskIrpWithHookInit
// SendCdbCommandToDevice, SendDiskDeviceInternalIrp, OpenSectionWithIoControl
// SendFsctlWithHookSwap, IrpFsctlGetVolumeData, SendIrpToDiskDevice
// CdbCommandCompletionCallback, RxTdiRequestCompletion, ReadSystemDllAndInitSession
// InitIrpBufferWithCdb, ReadDisksSysFile, ReadCdromSysFile, ReadRawFileToBuffer
// InitSessionStateTable

// ===== MemoryOps.c =====
// ClearPageTableEntryFlags, ClearProcessPageTableFlags

// ===== SystemInfo.c =====
// ForEachProcessor, InitUnicodeStringBuffer, CmdQueryDiskInfo
// CmdQuerySystemInfoExV2

// ===== Crypto.c =====
// Md5Init, DecryptAesHexString