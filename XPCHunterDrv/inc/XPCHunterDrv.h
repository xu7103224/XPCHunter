#pragma once

//
// XPCHunterDrv.h — PCHunter 内核驱动主头文件
// 1:1 复刻 View++_Driver64.sys (Linxer)
//

// 内核模式定义（必须在 WDK 头文件之前）
// 注意：MSVC /kernel 开关会保留 _KERNEL_MODE 宏，因此不能在命令行 /D 定义
#ifndef _KERNEL_MODE
#define _KERNEL_MODE
#endif

// 注意：WDK 内核模式下 windef.h 不定义 WORD/DWORD/LONG64 等类型，
// 但 ntimage.h 使用这些类型，因此必须在 #include <ntimage.h> 之前定义
#ifndef WORD
typedef unsigned short WORD;
#endif
#ifndef PWORD
typedef WORD *PWORD;
#endif
#ifndef DWORD
typedef unsigned long DWORD;
#endif
#ifndef LONG64
typedef __int64 LONG64;
#endif
#ifndef ULONG64
typedef unsigned __int64 ULONG64;
#endif

// IDA Pro 风格类型别名（用于函数声明兼容）
typedef unsigned char _BYTE;
typedef unsigned short _WORD;
typedef unsigned long _DWORD;
typedef unsigned __int64 _QWORD;

#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntimage.h>

// 注意：intrin.h 在 WDK 内核模式下可能引起兼容性问题
// 需要 __readmsr/__writemsr/__cpuid 的源文件自行 #pragma intrinsic 声明

// bool 类型定义（WDK 已定义 BOOLEAN，仅在纯 C 模式下需要）
#ifndef __cplusplus
#ifndef bool
#define bool BOOLEAN
#endif
#endif

// 额外类型别名
// 128 位联合体，支持位域访问（用于替代 IDA 反编译中的 __int128）
typedef union _OWORD {
    unsigned __int64 qword[2];
    unsigned long dword[4];
    unsigned short word[8];
    unsigned char byte[16];
} _OWORD;

// Lvalue 兼容的字节/字访问宏（MSVC C 模式下 LOBYTE/HIWORD 等不是 lvalue）
// 注意：MSVC C 模式下不允许在带括号的表达式上做赋值（C2106），
// 因此宏定义中不能包含外层括号，以保证展开后 *(UCHAR *)&x = val 的 lvalue 语义。
// 使用 (UCHAR *) 中间转换（而非 (void *)）以保持 MSVC /Ze 扩展兼容。
#define LOBYTE_LV(x)  *(UCHAR  *)(UCHAR *)&(x)
#define HIBYTE_LV(x)  *(UCHAR  *)((UCHAR *)&(x) + 1)
#define BYTE1_LV(x)   *(UCHAR  *)((UCHAR *)&(x) + 1)
#define BYTE2_LV(x)   *(UCHAR  *)((UCHAR *)&(x) + 2)
#define BYTE3_LV(x)   *(UCHAR  *)((UCHAR *)&(x) + 3)
#define LOWORD_LV(x)  *(WORD  *)(WORD *)&(x)
#define HIWORD_LV(x)  *(WORD  *)((UCHAR *)&(x) + 2)

// 非 lvalue 字节/字宏（兼容原始反编译代码中的用法）
#define HIBYTE(x)     ((UCHAR)(((ULONG_PTR)(x) >> 8) & 0xFF))
#define BYTE1(x)      ((UCHAR)(((ULONG_PTR)(x) >> 8) & 0xFF))
#define BYTE2(x)      ((UCHAR)(((ULONG_PTR)(x) >> 16) & 0xFF))
#define LODWORD(x)    ((ULONG)((ULONG_PTR)(x) & 0xFFFFFFFF))
#define HIDWORD(x)    ((ULONG)(((ULONG_PTR)(x) >> 32) & 0xFFFFFFFF))
#define SBYTE1(x)     ((char)(((ULONG_PTR)(x) >> 8) & 0xFF))

// Minifilter 类型前向声明（Minifilter.c 包含完整的 fltKernel.h）
typedef struct _FLT_FILTER *PFLT_FILTER;
typedef struct _FLT_INSTANCE *PFLT_INSTANCE;
typedef struct _FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;
typedef struct _FLT_CALLBACK_DATA *PFLT_CALLBACK_DATA;
typedef int FLT_INSTANCE_SETUP_FLAGS;
typedef int FLT_INSTANCE_QUERY_FLAGS;
typedef int FLT_TEARDOWN_FLAGS;
typedef int FLT_FILTER_UNLOAD_FLAGS;
typedef int FLT_POST_OPERATION_FLAGS;
typedef int FLT_CONTEXT_TYPE;
typedef int FLT_CONTEXT_CLEANUP_FLAGS;

// ============================================================
// 编译时配置
// ============================================================
#define XPCHUNTER_DEVICE_NAME      L"\\Device\\View++ByLinxer"
#define XPCHUNTER_SYMLINK_NAME     L"\\DosDevices\\View++ByLinxer"
#define XPCHUNTER_REGISTRY_PATH    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\XPCHunterDrv"

#define DRIVER_TAG                 'XPCH'
#define POOL_TAG                   'xpcH'

// ============================================================
// 全局表索引枚举
// ============================================================
typedef enum _GLOBAL_TABLE_INDEX {
    // ---- 核心系统信息 (0-9) ----
    // 注意：以下命名均经过数据流追踪验证，参见 InitGtCore/InitSdstTable 的反编译分析
    GtNtBuildNumber = 0,            // InitGtCore: g_GlobalTable[0] = NtBuildNumber
    GtDriverObject = 1,             // g_DriverObjectPtr 即 g_GlobalTable[1]（地址重叠）
    GtNtoskrnlImageSize = 2,        // InitSdstTable: 写入找到的 ntoskrnl 模块大小
    GtNtoskrnlModuleBase = 3,       // InitSdstTable: 写入找到的 ntoskrnl 模块基址 (ModuleBase)
    GtPathBuffer00 = 4,             // InitSdstTable: 路径缓冲区 L"\\Sys" (4 Unicode 字符)
    GtPathBuffer01 = 5,             // InitSdstTable: 路径缓冲区 L"temR"
    GtPathBuffer02 = 6,             // InitSdstTable: 路径缓冲区 L"oot\\"
    GtPathBuffer03 = 7,             // InitSdstTable: 路径缓冲区 L"syst"
    GtPathBuffer04 = 8,             // InitSdstTable: 路径缓冲区 L"em32"
    GtSymlinkBuffer = 9,            // InitSdstTable: GtAlloc(9) 分配 0xB0 字节用于符号链接路径

    // ---- EPROCESS/KPROCESS 字段偏移表 (10-199) ----
    // 由 InitEprocessOffsets* 函数按版本初始化
    GtEprocessOffsetBase = 10,      // EPROCESS 字段偏移起始
    GtEprocessField00 = 10,         // EPROCESS 字段 0
    GtEprocessField01 = 11,
    GtEprocessField02 = 12,
    GtEprocessField03 = 13,
    GtEprocessField04 = 14,
    GtEprocessField05 = 15,
    GtEprocessField06 = 16,
    GtEprocessField07 = 17,
    GtEprocessField08 = 18,
    GtEprocessField09 = 19,
    GtEprocessField10 = 20,
    GtEprocessField11 = 21,
    GtEprocessField12 = 22,
    GtEprocessField13 = 23,
    GtEprocessField14 = 24,
    GtEprocessField15 = 25,
    GtEprocessField16 = 26,
    GtEprocessField17 = 27,
    GtEprocessField18 = 28,
    GtEprocessField19 = 29,
    GtEprocessField20 = 30,
    GtEprocessField21 = 31,
    GtEprocessField22 = 32,
    GtEprocessField23 = 33,
    GtEprocessField24 = 34,
    GtEprocessField25 = 35,
    GtEprocessField26 = 36,
    GtEprocessField27 = 37,
    GtEprocessField28 = 38,
    GtPrevModeOffset = 39,              // KTHREAD PreviousMode 偏移(DisableObjectCallbackViaDevice) 别名GtSdstServiceCount
    GtEprocessField30 = 40,
    GtEprocessField31 = 41,
    GtEprocessField32 = 42,
    GtEprocessField33 = 43,
    GtEprocessField34 = 44,
    GtEprocessField35 = 45,
    GtEprocessField36 = 46,
    GtEprocessField37 = 47,
    GtEprocessField38 = 48,
    GtEprocessField39 = 49,
    GtEprocessField40 = 50,
    GtEprocessField41 = 51,
    GtEprocessField42 = 52,
    GtEprocessField43 = 53,
    GtEprocessField44 = 54,
    GtProcessEprocess = 55,            // 进程EPROCESS偏移(InitObjectCallback)
    GtProcessOffset = 56,               // 进程结构偏移(InitObjectCallback)
    GtEprocessField47 = 57,
    GtEprocessField48 = 58,
    GtEprocessField49 = 59,
    GtProcessCreateTime = 60,          // 进程创建时间偏移(InitObjectCallback)
    GtEprocessField51 = 61,
    GtEprocessField52 = 62,
    GtEprocessField53 = 63,
    GtEprocessField54 = 64,
    GtEprocessField55 = 65,
    GtWin32kServiceEntryCount = 66, // Win32k 服务表条目数(ParseNtKernelFile/InitWin32kServiceTableEntries)
    GtEprocessField57 = 67,
    GtEprocessField58 = 68,
    GtEprocessField59 = 69,
    GtEprocessField60 = 70,
    GtEprocessField61 = 71,
    GtEprocessField62 = 72,
    GtEprocessField63 = 73,
    GtEprocessField64 = 74,
    GtObjectTypeCount = 75,            // 对象类型计数(InitObjectCallback)
    GtEprocessField66 = 76,
    GtEprocessField67 = 77,
    GtEprocessField68 = 78,
    GtEprocessField69 = 79,
    GtKernelModuleBase = 80,       // 内核模块基址(用于跨进程读取比较, ReadFileIntoBuffer)
    GtEprocessField71 = 81,
    GtEprocessField72 = 82,
    GtEprocessField73 = 83,
    GtEprocessField74 = 84,
    GtEprocessField75 = 85,
    GtEprocessField76 = 86,
    GtEprocessField77 = 87,
    GtEprocessField78 = 88,
    GtEprocessField79 = 89,
    GtEprocessField80 = 90,
    GtEprocessField81 = 91,
    GtEprocessField82 = 92,
    GtEprocessField83 = 93,
    GtEprocessField84 = 94,
    GtEprocessField85 = 95,
    GtEprocessField86 = 96,
    GtCurrentEprocess = 97,          // 当前 EPROCESS 指针(ReadFileIntoBuffer/InitWin32kServiceTableEntries)
    GtEprocessField88 = 98,
    GtPspTerminateThreadAddr = 99,    // PspTerminateThreadByPointer 函数地址(InitKernelRoutineTable)
    GtPspExitThreadAddr = 100,          // PspExitThread 函数地址(InitKernelRoutineTable)
    GtPsExitSpecialApcAddr = 101,       // PsExitSpecialApc 函数地址(InitKernelRoutineTable)
    GtSavedObPreCallback1 = 0x189,      // 393: 保存的对象前置回调函数指针1(ObjectPreCallback)
    GtSavedObPreCallback2 = 0x18A,      // 394: 保存的对象前置回调函数指针2(ObjectPreCallback)
    GtSavedDeviceObject = 0x194,         // 404: 保存的设备对象指针(DisableObjectCallback)
    GtSavedDeviceObject2 = 0x195,        // 405: 保存的设备对象指针2(EnableDeviceObjectProtection)
    GtExFreeCallBackAddr = 102,         // ExFreeCallBack 函数地址(InitKernelRoutineTable)
    GtPspExitNormalApcAddr = 103,       // PspExitNormalApc 函数地址(InitKernelRoutineTable)
    GtEprocessField94 = 104,
    GtEprocessField95 = 105,
    GtEprocessField96 = 106,
    GtModuleBuffer = 107,              // 模块缓冲区指针(ExFree在InitRegNotify中清理, LookupModuleByName/FindExportByAddress读取)(InitRegNotify/RegNotifyCallback)
    GtWin32kServiceTableVersion = 108, // Win32k 服务表版本标志(==2 表示可用, ParseNtKernelFile)
    GtEprocessField99 = 109,
    GtEprocessField100 = 110,
    GtEprocessField101 = 111,
    GtEprocessField102 = 112,
    GtEprocessField103 = 113,
    GtEprocessField104 = 114,
    GtEprocessField105 = 115,
    GtEprocessField106 = 116,
    GtEprocessField107 = 117,
    GtEprocessField108 = 118,
    GtEprocessField109 = 119,
    GtEprocessField110 = 120,
    GtEprocessField111 = 121,
    GtEprocessField112 = 122,
    GtEprocessField113 = 123,
    GtEprocessField114 = 124,
    GtEprocessField115 = 125,
    GtEprocessField116 = 126,
    GtEprocessField117 = 127,
    GtEprocessField118 = 128,
    GtEprocessField119 = 129,
    GtEprocessField120 = 130,
    GtEprocessField121 = 131,
    GtEprocessField122 = 132,
    GtEprocessField123 = 133,
    GtEprocessField124 = 134,
    GtEprocessField125 = 135,
    GtEprocessField126 = 136,
    GtEprocessField127 = 137,
    GtEprocessField128 = 138,
    GtEprocessField129 = 139,
    GtEprocessField130 = 140,
    GtEprocessField131 = 141,
    GtEprocessField132 = 142,
    GtEprocessField133 = 143,
    GtEprocessField134 = 144,
    GtEprocessField135 = 145,
    GtEprocessField136 = 146,
    GtEprocessField137 = 147,
    GtEprocessField138 = 148,
    GtEprocessField139 = 149,
    GtEprocessField140 = 150,
    GtEprocessField141 = 151,
    GtEprocessField142 = 152,
    GtEprocessField143 = 153,
    GtEprocessField144 = 154,
    GtEprocessField145 = 155,
    GtEprocessField146 = 156,
    GtEprocessField147 = 157,
    GtEprocessField148 = 158,
    GtEprocessField149 = 159,
    GtEprocessField150 = 160,
    GtEprocessField151 = 161,
    GtEprocessField152 = 162,
    GtEprocessField153 = 163,
    GtEprocessField154 = 164,
    GtEprocessField155 = 165,
    GtEprocessField156 = 166,
    GtEprocessField157 = 167,
    GtEprocessField158 = 168,
    GtEprocessField159 = 169,
    GtEprocessField160 = 170,
    GtEprocessField161 = 171,
    GtEprocessField162 = 172,
    GtEprocessField163 = 173,
    GtEprocessField164 = 174,
    GtEprocessField165 = 175,
    GtEprocessField166 = 176,
    GtEprocessField167 = 177,
    GtEprocessField168 = 178,
    GtEprocessField169 = 179,
    GtEprocessField170 = 180,
    GtEprocessField171 = 181,
    GtEprocessField172 = 182,
    GtEprocessField173 = 183,
    GtEprocessField174 = 184,
    GtEprocessField175 = 185,
    GtEprocessField176 = 186,
    GtEprocessField177 = 187,
    GtEprocessField178 = 188,
    GtEprocessField179 = 189,
    GtEprocessField180 = 190,
    GtEprocessField181 = 191,
    GtEprocessField182 = 192,
    GtEprocessField183 = 193,
    GtEprocessField184 = 194,
    GtEprocessField185 = 195,
    GtEprocessField186 = 196,
    GtEprocessField187 = 197,
    GtEprocessField188 = 198,
    GtEprocessField189 = 199,

    // ---- 子系统配置偏移 (200-479) ----
    GtSubsystemConfigBase = 200,    // 子系统配置偏移起始

    // ---- 系统服务函数指针 (410) ----
    GtNtQuerySystemInformationFunc = 0x19A, // 410: NtQuerySystemInformation 函数指针(CallQuerySystemInformation)
    GtKiFastCallEntryAddr = 0x1CD,              // 461: KiFastCallEntry 函数地址(InitKernelRoutineTable)

    // ---- ntoskrnl PE 文件映射区域 (32-36) ----
    // 由 ReadNtoskrnlFile 写入，用于 SSDT Hook 完整性检查
    GtNtoskrnlPeFileBase = 0x20,            // 32: ntoskrnl.exe PE 文件映射缓冲区基址(Src)
    GtNtoskrnlPeFileSize = 0x21,            // 33: ntoskrnl.exe PE 文件映射大小(FileSize)
    GtNtoskrnlPeSignature = 0x22,           // 34: PE 签名指针(PeSignature)
    GtNtoskrnlOptHeaderOffset = 0x23,       // 35: 可选头偏移(OptHeaderOffset)
    GtNtoskrnlSectionHeader = 0x24,         // 36: 节区头指针(NtHeaders+24)

    // ---- ntoskrnl 映像分析缓冲区 (76-78) ----
    GtNtoskrnlImageBuffer = 0x4C,           // 76: 映像分析缓冲区(ExAlloc 复制)
    GtNtoskrnlSectionHeader2 = 0x4D,        // 77: 节区头(从映像缓冲区偏移)
    GtNtoskrnlLastSectionEnd = 0x4E,        // 78: 最后一个节区头结束位置

    // ---- 加密密钥 (480-482) ----
    GtEncryptionKey = 0x1E0,        // 480: 加密密钥
    GtEncryptionKeyByte = 0x1E1,    // 481: 加密密钥字节
    GtIrpBufferSize = 0x1E2,        // 482: IRP 缓冲区大小

    // ---- 子系统运行时数据偏移 (483-506) ----
    GtRuntimeDataBase = 0x1E3,      // 483: 运行时数据起始

    // ---- 同步对象 (507) ----
    GtGlobalMutex = 0x1FB,          // 507: 全局互斥体

    // ---- 对象类型/保护系统偏移 (508-599) ----
    GtObjectTypeBase = 0x1FC,       // 508: 对象类型系统偏移起始
    GtObjectTypeField00 = 0x1FE,    // 510
    GtObjectTypeField01 = 0x1FF,    // 511
    GtObjectTypeField02 = 0x200,    // 512
    GtObjectTypeField03 = 0x206,    // 518
    GtObjectTypeField04 = 0x207,    // 519
    GtObjectTypeField05 = 0x208,    // 520
    GtObjectTypeField06 = 0x20A,    // 522
    GtObjectTypeField07 = 0x20C,    // 524
    GtObjectTypeField08 = 0x210,    // 528
    GtObjectTypeField09 = 0x218,    // 536
    GtObjectTypeField10 = 0x219,    // 537
    GtObjectTypeField11 = 0x21A,    // 538
    GtObjectTypeField12 = 0x21B,    // 539
    GtObjectTypeField13 = 0x220,    // 544
    GtObjectTypeField14 = 0x228,    // 552
    GtObjectTypeField15 = 0x22E,    // 558
    GtObjectTypeField16 = 0x230,    // 560
    GtObjectTypeField17 = 0x232,    // 562
    GtObjectTypeField18 = 0x234,    // 564
    GtObjectTypeField19 = 0x235,    // 565
    GtObjectTypeField20 = 0x236,    // 566
    GtObjectTypeField21 = 0x237,    // 567
    GtObjectTypeField22 = 0x238,    // 568
    GtWin32kServiceTable = 0x23C,       // 572: Win32k 服务表指针(InitWin32kServiceTableEntries写入)
    GtKernelRoutineTableCount = 0x23D,   // 573: 内核例程表条目数(InitKernelRoutineTable写入)
    GtKernelRoutineTable = 0x23E,         // 574: 内核例程表指针(InitKernelRoutineTable写入)
    GtKiInsertQueueApcFunc = 0x23F,        // 575: KiInsertQueueApc 函数地址(InitHookFunctionTable写入)
    GtObjectTypeField27 = 0x240,    // 576
    GtObjectTypeField28 = 0x242,    // 578
    GtObjectTypeField29 = 0x245,    // 581
    GtObjectTypeField30 = 0x246,    // 582
    GtObjectTypeField31 = 0x248,    // 584
    GtObjectTypeField32 = 0x250,    // 592
    GtObjectTypeField33 = 0x258,    // 600
    GtObjectTypeField34 = 0x25E,    // 606
    GtObjectTypeField35 = 0x260,    // 608
    GtObjectTypeField36 = 0x263,    // 611
    GtObjectTypeField37 = 0x266,    // 614
    GtObjectTypeField38 = 0x268,    // 616
    GtObjectTypeField39 = 0x269,    // 617
    GtObjectTypeField40 = 0x26C,    // 620
    GtObjectTypeField41 = 0x26F,    // 623
    GtObjectTypeField42 = 0x270,    // 624
    GtObjectTypeField43 = 0x278,    // 632
    GtObjectTypeField44 = 0x280,    // 640
    GtObjectTypeField45 = 0x284,    // 644

    // ---- 内核数据节区偏移 (600-699) ----
    GtKernelDataSectionBase = 0x28C, // 652
    GtKernelDataField00 = 0x28C,    // 652
    GtKernelDataField01 = 0x28D,    // 653
    GtKernelDataField02 = 0x28E,    // 654
    GtKernelDataField03 = 0x28F,    // 655
    GtKernelDataField04 = 0x290,    // 656
    GtKernelDataField05 = 0x291,    // 657
    GtKernelDataField06 = 0x292,    // 658
    GtKernelDataField07 = 0x298,    // 664
    GtKernelDataField08 = 0x299,    // 665
    GtKernelDataField09 = 0x29A,    // 666
    GtKernelDataField10 = 0x29B,    // 667
    GtKernelDataField11 = 0x29C,    // 668
    GtKernelDataField12 = 0x29E,    // 670
    GtKernelDataField13 = 0x29F,    // 671
    GtKernelDataField14 = 0x2A0,    // 672
    GtKernelDataField15 = 0x2A1,    // 673
    GtKernelDataField16 = 0x2A2,    // 674
    GtSavedDeviceObject3 = 0x2A3,           // 675: 保存的设备对象指针3(EnableDeviceObjectProtection)
    GtKernelDataField18 = 0x2A4,    // 676
    GtKernelDataField19 = 0x2A5,    // 677
    GtSavedObPreCallback3 = 0x2A6,      // 678: 保存的对象前置回调函数指针3(ObjectPreCallback)
    GtKernelDataField21 = 0x2A7,    // 679
    GtKernelDataField22 = 0x2A8,    // 680
    GtKernelDataField23 = 0x2A9,    // 681
    GtIopfCompleteRequestAddr = 0x2AA,  // 682: IopfCompleteRequest 函数地址(InitKernelRoutineTable)
    GtKernelDataField25 = 0x2AB,    // 683
    GtKernelDataField26 = 0x2AC,    // 684
    GtKernelDataField27 = 0x2AD,    // 685
    GtKernelDataField28 = 0x2AE,    // 686
    GtKernelDataField29 = 0x2AF,    // 687
    GtKernelDataField30 = 0x2B0,    // 688
    GtKernelDataField31 = 0x2B1,    // 689
    GtKernelDataField32 = 0x2B2,    // 690
    GtKernelDataField33 = 0x2B3,    // 691
    GtKernelDataField34 = 0x2B4,    // 692
    GtKernelDataField35 = 0x2B5,    // 693
    GtKernelDataField36 = 0x2B6,    // 694
    GtKernelDataField37 = 0x2B7,    // 695
    GtKernelDataField38 = 0x2B8,    // 696
    GtKernelDataField39 = 0x2B9,    // 697
    GtKernelDataField40 = 0x2BA,    // 698
    GtKernelDataField41 = 0x2BB,    // 699
    GtKernelDataField42 = 0x2BC,    // 700
    GtKernelDataField43 = 0x2BD,    // 701
    GtKernelDataField44 = 0x2C0,    // 704
    GtKernelDataField45 = 0x2C1,    // 705

    // ---- 回调/通知系统偏移 (706-851) ----
    GtCallbackSystemBase = 0x2C2,   // 706
    GtCallbackField00 = 0x2CA,      // 714
    GtCallbackField01 = 0x2CC,      // 716
    GtCallbackField02 = 0x2CD,      // 717
    GtCallbackField03 = 0x2CE,      // 718
    GtCallbackField04 = 0x2CF,      // 719
    GtCallbackField05 = 0x2D0,      // 720
    GtCallbackField06 = 0x2D1,      // 721
    GtCallbackField07 = 0x2D2,      // 722
    GtCallbackField08 = 0x2D3,      // 723
    GtCallbackField09 = 0x2D4,      // 724
    GtVmxEnabledFlag = 0x2D5,       // 725: VMX 虚拟化标志(InitAllHookSubsystems)
    GtCallbackField11 = 0x2D6,      // 726
    GtCallbackField12 = 0x2D7,      // 727
    GtCallbackField13 = 0x2D8,      // 728
    GtCallbackField14 = 0x2D9,      // 729
    GtCallbackField15 = 0x2DA,      // 730
    GtCallbackField16 = 0x2DC,      // 732
    GtCallbackField17 = 0x2DE,      // 734
    GtCallbackField18 = 0x2DF,      // 735
    GtCallbackField19 = 0x2E0,      // 736
    GtCallbackField20 = 0x2E2,      // 738
    GtCallbackField21 = 0x2E3,      // 739
    GtCallbackField22 = 0x2E4,      // 740
    GtCallbackField23 = 0x2E5,      // 741
    GtCallbackField24 = 0x2E6,      // 742
    GtCallbackField25 = 0x2E7,      // 743
    GtCallbackField26 = 0x2E8,      // 744
    GtCallbackField27 = 0x2E9,      // 745
    GtCallbackField28 = 0x2EA,      // 746
    GtCallbackField29 = 0x2EB,      // 747
    GtCallbackField30 = 0x2EC,      // 748
    GtCallbackField31 = 0x2ED,      // 749
    GtCallbackField32 = 0x2EE,      // 750
    GtCallbackField33 = 0x2EF,      // 751
    GtCallbackField34 = 0x2F0,      // 752
    GtFsFilterExportTable = 0x2F1,      // 753: 文件系统过滤器导出表地址(InitFileSystemExportTable/ParseFsFilterDriverExport)
    GtCallbackField36 = 0x2F2,      // 754
    GtCallbackField37 = 0x2F3,      // 755
    GtCallbackField38 = 0x2F4,      // 756
    GtCallbackField39 = 0x2F5,      // 757
    GtCallbackField40 = 0x2F6,      // 758
    GtCallbackField41 = 0x2F7,      // 759
    GtCallbackField42 = 0x2F8,      // 760
    GtCallbackField43 = 0x2F9,      // 761
    GtCallbackField44 = 0x2FA,      // 762
    GtCallbackField45 = 0x2FB,      // 763
    GtCallbackField46 = 0x2FC,      // 764
    GtCallbackField47 = 0x2FD,      // 765
    GtCallbackField48 = 0x2FE,      // 766
    GtCallbackField49 = 0x2FF,      // 767
    GtCallbackField50 = 0x300,      // 768
    GtCallbackField51 = 0x301,      // 769
    GtCallbackField52 = 0x302,      // 770
    GtCallbackField53 = 0x303,      // 771
    GtCallbackField54 = 0x304,      // 772
    GtCallbackField55 = 0x305,      // 773
    GtCallbackField56 = 0x306,      // 774
    GtCallbackField57 = 0x307,      // 775
    GtCallbackField58 = 0x308,      // 776
    GtCallbackField59 = 0x309,      // 777
    GtCallbackField60 = 0x30A,      // 778
    GtCallbackField61 = 0x30B,      // 779
    GtCallbackField62 = 0x30C,      // 780
    GtCallbackField63 = 0x30D,      // 781
    GtCallbackField64 = 0x310,      // 784
    GtCallbackField65 = 0x311,      // 785
    GtCallbackField66 = 0x312,      // 786
    GtCallbackField67 = 0x313,      // 787
    GtCallbackField68 = 0x314,      // 788
    GtCallbackField69 = 0x316,      // 790
    GtCallbackField70 = 0x317,      // 791
    GtCallbackField71 = 0x318,      // 792
    GtCallbackField72 = 0x319,      // 793
    GtCallbackField73 = 0x31A,      // 794
    GtCallbackField74 = 0x31B,      // 795
    GtCallbackField75 = 0x31C,      // 796
    GtCallbackField76 = 0x31D,      // 797
    GtCallbackField77 = 0x31E,      // 798
    GtCallbackField78 = 0x31F,      // 799
    GtCallbackField79 = 0x320,      // 800
    GtCallbackField80 = 0x321,      // 801
    GtCallbackField81 = 0x322,      // 802
    GtCallbackField82 = 0x323,      // 803
    GtCallbackField83 = 0x324,      // 804
    GtDeviceObjectProtectOffset = 0x325,      // 805: 设备对象保护标志偏移(EnableDeviceObjectProtection)
    GtSubDeviceObjectProtectOffset = 0x326, // 806: 子设备对象保护标志偏移(EnableDeviceObjectProtection)
    GtSubDeviceObjectFlagsOffset = 0x327,   // 807: 子设备对象标志偏移(EnableDeviceObjectProtection)
    GtTargetDeviceObjectProtectOffset = 0x328, // 808: 目标设备对象保护标志偏移(EnableDeviceObjectProtection)
    GtDeviceObjectChildPtrOffset = 0x329,   // 809: 设备对象子对象指针偏移(EnableDeviceObjectProtection)
    GtDeviceObjectTargetPtrOffset = 0x32A,  // 810: 设备对象目标指针偏移(EnableDeviceObjectProtection)
    GtTargetProtectionOffset = 0x32B,       // 811: 目标保护标志偏移(EnableDeviceObjectProtection)
    GtCallbackField91 = 0x32C,      // 812
    GtCallbackField92 = 0x32D,      // 813
    GtCallbackField93 = 0x32E,      // 814
    GtCallbackField94 = 0x32F,      // 815
    GtCallbackField95 = 0x330,      // 816
    GtCallbackField96 = 0x331,      // 817
    GtCallbackField97 = 0x332,      // 818
    GtCallbackField98 = 0x333,      // 819
    GtCallbackField99 = 0x334,      // 820
    GtCallbackField100 = 0x335,     // 821
    GtCallbackField101 = 0x336,     // 822
    GtCallbackField102 = 0x337,     // 823
    GtCallbackField103 = 0x338,     // 824
    GtCallbackField104 = 0x339,     // 825
    GtCallbackField105 = 0x33A,     // 826
    GtCallbackField106 = 0x33B,     // 827
    GtIopfCallDriverAddr = 0x33C,         // 828: IopfCallDriver 函数地址(InitKernelRoutineTable)
    GtCallbackField108 = 0x33D,     // 829
    GtCallbackField109 = 0x33E,     // 830
    GtProcessSectionOffset = 0x33F,         // 831: 进程 Section 偏移(InitProcessCallback/CheckProcessProtection)
    GtDebugPortOffset = 0x340,              // 832: 调试端口偏移(InitProcessCallback/CheckProcessProtection)
    GtCallbackField112 = 0x341,     // 833
    GtCallbackField113 = 0x342,     // 834
    GtNtCreateFileSyscallOffset = 0x347,    // 839: NtCreateFile 系统调用 PE 偏移(按版本初始化,HookSyscallNtCreateFile)
    GtNtCreateFileSyscallResult = 0x348,    // 840: NtCreateFile Hook 结果偏移(HookSyscallNtCreateFile写入)
    GtNtCreateFileSyscallAddress = 0x349,   // 841: NtCreateFile Hook 结果地址(HookSyscallNtCreateFile写入)
    GtCallbackField116 = 0x34A,     // 842
    GtCallbackField117 = 0x34B,     // 843
    GtCallbackField118 = 0x34C,     // 844
    GtCallbackField119 = 0x34D,     // 845
    GtCallbackField120 = 0x34E,     // 846
    GtCallbackField121 = 0x34F,     // 847
    GtCallbackField122 = 0x350,     // 848
    GtProcessFlagsOffset = 0x351,      // 849: 进程标志偏移(InitObjectCallback)
    GtCallbackField124 = 0x352,     // 850
    GtCallbackField125 = 0x353,     // 851

    // ---- 回调状态标志 (852-853) ----
    GtCallbackInitialized = 0x354,  // 852: 回调初始化标志
    GtCallbackBusy = 0x355,         // 853: 回调忙标志

    // ---- 版本特定 EPROCESS 扩展偏移 (854-920) ----
    GtEprocessExtBase = 0x356,      // 854: EPROCESS 扩展偏移起始
    GtEprocessExtField00 = 0x356,   // 854
    GtEprocessExtField01 = 0x357,   // 855
    GtEprocessExtField02 = 0x358,   // 856
    GtEprocessExtField03 = 0x359,   // 857
    GtEprocessExtField04 = 0x35A,   // 858
    GtEprocessExtField05 = 0x35B,   // 859
    GtEprocessExtField06 = 0x35C,   // 860
    GtEprocessExtField07 = 0x35D,   // 861
    GtEprocessExtField08 = 0x35E,   // 862
    GtEprocessExtField09 = 0x35F,   // 863
    GtEprocessExtField10 = 0x360,   // 864
    GtEprocessExtField11 = 0x361,   // 865
    GtEprocessExtField12 = 0x362,   // 866
    GtEprocessExtField13 = 0x363,   // 867
    GtEprocessExtField14 = 0x364,   // 868
    GtEprocessExtField15 = 0x365,   // 869
    GtEprocessExtField16 = 0x366,   // 870
    GtEprocessExtField17 = 0x367,   // 871
    GtEprocessExtField18 = 0x368,   // 872
    GtEprocessExtField19 = 0x369,   // 873
    GtEprocessExtField20 = 0x36A,   // 874
    GtEprocessExtField21 = 0x36B,   // 875
    GtEprocessExtField22 = 0x36C,   // 876
    GtEprocessExtField23 = 0x36D,   // 877
    GtEprocessExtField24 = 0x36E,   // 878
    GtEprocessExtField25 = 0x36F,   // 879
    GtEprocessExtField26 = 0x370,   // 880
    GtEprocessExtField27 = 0x371,   // 881
    GtEprocessExtField28 = 0x372,   // 882
    GtEprocessExtField29 = 0x373,   // 883
    GtEprocessExtField30 = 0x374,   // 884
    GtEprocessExtField31 = 0x375,   // 885
    GtEprocessExtField32 = 0x376,   // 886
    GtEprocessExtField33 = 0x377,   // 887
    GtEprocessExtField34 = 0x378,   // 888
    GtEprocessExtField35 = 0x379,   // 889
    GtEprocessExtField36 = 0x37A,   // 890
    GtEprocessExtField37 = 0x37B,   // 891
    GtEprocessExtField38 = 0x37C,   // 892
    GtEprocessExtField39 = 0x37D,   // 893
    GtEprocessExtField40 = 0x37E,   // 894
    GtEprocessExtField41 = 0x37F,   // 895
    GtEprocessExtField42 = 0x380,   // 896
    GtEprocessExtField43 = 0x381,   // 897
    GtEprocessExtField44 = 0x382,   // 898
    GtEprocessExtField45 = 0x383,   // 899
    GtEprocessExtField46 = 0x384,   // 900
    GtEprocessExtField47 = 0x385,   // 901
    GtEprocessExtField48 = 0x386,   // 902
    GtEprocessExtField49 = 0x387,   // 903
    GtEprocessExtField50 = 0x388,   // 904
    GtEprocessExtField51 = 0x389,   // 905
    GtEprocessExtField52 = 0x38A,   // 906
    GtEprocessExtField53 = 0x38B,   // 907
    GtEprocessExtField54 = 0x38C,   // 908
    GtEprocessExtField55 = 0x38D,   // 909
    GtEprocessExtField56 = 0x38E,   // 910
    GtEprocessExtField57 = 0x38F,   // 911
    GtEprocessExtField58 = 0x390,   // 912

    // ---- EPROCESS 模块链表偏移 (2062-2064) ----
    GtEprocessModuleEntrySize = 0x80E,      // 2062: EPROCESS 模块链表条目大小
    GtEprocessModuleEntryCount = 0x80F,     // 2063: EPROCESS 模块链表条目计数
    GtEprocessModuleListOffset = 0x810,     // 2064: EPROCESS 模块链表偏移(Win32k/非Win32k)

    // ---- 命令处理函数表 (2337) ----
    GtCommandHandlerBase = 0x921,   // 2337: 命令处理函数表基址
    GtCommandHandlerEnd = 0xA3B,    // 2619: 命令处理函数表结束 (282个处理函数)

    // ---- 系统调用哈希表 (16728-17529) ----
    GtSyscallHashTable = 0x4158,    // 16728: 系统调用哈希表起始
    GtSyscallHashEntry00 = 0x415B,  // 16731

    // ---- 内核函数指针表 (16736-17529) ----
    // 以下索引存储从 ntoskrnl 导出的函数指针，用于驱动对象枚举、设备操作等
    GtDriverObjectListHead = 0x4160,        // 16736: 驱动对象链表头指针
    GtNtFsControlFileFunc = 0x41C6,         // 16838: NtFsControlFile 函数指针
    GtObjectTypeCheckFlag = 0x41DB,         // 16859: 对象类型检查标志(InitObjectCallbackEntries)
    GtIoCreateFileFunc = 0x421A,            // 16922: IoCreateFile 函数指针
    GtRtlInitUnicodeStringFunc = 0x421D,    // 16925: RtlInitUnicodeString 函数指针
    GtQueryObjectNameFunc = 0x4220,           // 16928: 查询对象名称函数指针(InitObjectCallback)
    GtCloseHandleFunc = 0x4223,             // 16931: CloseHandle 函数指针
    GtZwCreateFileFunc = 0x422F,            // 16943: ZwCreateFile 函数指针
    GtCreateFileFunc1 = 0x4235,             // 16949: CreateFile 函数指针(替代)
    GtDeviceIoControlFunc = 0x4238,         // 16952: DeviceIoControl 函数指针
    GtCreateFileFunc2 = 0x4256,             // 16982: CreateFile 函数指针(替代)
    GtStringAllocFunc = 0x424A,             // 16970: StringAlloc 函数指针(LookupModuleByName)
    GtAnsiToUnicodeFunc = 0x424D,           // 16973: AnsiToUnicode 函数指针(LookupModuleByName)
    GtFreeStringFunc = 0x4250,              // 16976: FreeString 函数指针(LookupModuleByName)
    GtExFreePoolFunc = 0x4334,              // 17204: ExFreePool 函数指针
    GtAllocPhysPagesFunc = 0x429B,            // 17051: AllocPhysPages 函数指针(ReadFileIntoBuffer)
    GtMapPhysPagesFunc = 0x429E,             // 17054: MapPhysPages 函数指针(ReadFileIntoBuffer)
    GtMapMemoryFunc = 0x42A1,                // 17057: MapMemory 函数指针(ReadFileIntoBuffer)
    GtUnmapMemoryFunc = 0x42A4,              // 17060: UnmapMemory 函数指针(ReadFileIntoBuffer)
    GtFreePagesFunc = 0x42A7,                // 17063: FreePages 函数指针(ReadFileIntoBuffer)
    GtZeroPagesFunc = 0x4367,                // 17255: ZeroPages 函数指针(ReadFileIntoBuffer)
    GtFreeMemoryFunc = 0x436A,               // 17258: FreeMemory 函数指针(ReadFileIntoBuffer)
    GtFsIoControlRoutine = 0x434A,            // 17234: FsIoControl 例程函数指针(DisableObjectCallbackViaDevice)
    GtObjectProtectCallback = 0x43E8,        // 17384: 对象保护回调函数指针
    GtMemoryAllocFunc = 0x4370,              // 17264: 内存分配函数指针(CheckProcessProtection)
    GtMemoryCheckFunc = 0x4376,              // 17270: 内存检查函数指针(InitProcessCallback/CheckProcessProtection)
    GtMemoryAllocExFunc = 0x4379,            // 17273: 扩展内存分配函数指针(CheckProcessProtection)
    GtMemoryFreeFunc = 0x437C,               // 17276: 内存释放函数指针(CheckProcessProtection)
    GtValidateObjectTypeFunc = 0x415A,      // 16730: 验证对象类型函数指针(InitObjectCallbackEntries)
    GtReadMemoryFunc = 0x41E4,              // 16868: 读取内存函数指针(ScanKernelMemForFsChanges/ScanVadForModifiedPages)
    GtAltRegisterCallbackFunc = 0x41ED,     // 16877: 备用注册回调函数指针(InitObjectCallbackEntries)
    GtDereferenceObjectFunc = 0x41EA,       // 16874: 解除对象引用函数指针(InitObjectCallbackEntries)
    GtObjectTypeRefFunc = 0x4226,           // 16934: 对象类型引用函数指针(InitObjectCallbackEntries)
    GtCreateObjectTypeFunc = 0x4259,        // 16985: 创建对象类型函数指针(InitObjectCallbackEntries)
    GtCloseObjectTypeFunc = 0x425C,         // 16988: 关闭对象类型函数指针(InitObjectCallbackEntries)
    GtRegisterObjectCallbacksFunc = 0x4232, // 16946: 注册对象回调函数指针(InitObjectCallbackEntries)
    GtObjectTypeInfoPtr = 0x4265,           // 16997: 对象类型信息指针(InitObjectCallbackEntries)，用于比较验证

    GtSyscallHashEntryEnd = 0x4479, // 17529: 系统调用哈希表结束

    // ---- SSDT 服务计数 (已通过数据流验证) ----
    // 注意: 索引 39 与 EPROCESS 偏移占位符重叠，本名称为已验证用途
    GtSdstServiceCount = 39,           // InitSdstServiceCount: 写入 SSDT 服务数量

    // ---- Win32k 服务表 (已通过数据流验证, 与回调偏移占位符重叠) ----
    GtWin32kServiceTable32Flag = 784,  // ResolveWin32kServiceTable: 32位服务表标志
    GtWin32kServiceTable64Flag = 785,  // ResolveWin32kServiceTable: 64位服务表标志
    GtWin32kServiceTableSize32 = 786,  // ResolveWin32kServiceTable: 32位服务表大小
    GtWin32kServiceTableSize64 = 787,  // ResolveWin32kServiceTable: 64位服务表大小
    GtWin32kServiceCount = 788,        // ResolveWin32kServiceTable: Win32k 服务总数

    // ---- 系统构建号 ----
    GtWindowsBuildNumber = 0x914,      // 2324: Windows 构建号

    // ---- 内核模块基址 (2292, 2294) ----
    GtHalModuleBase = 0x8F4,             // 2292: hal.dll 模块基址(ReadFileIntoBuffer)
    GtNtoskrnlFileBase = 0x8F6,           // 2294: ntoskrnl.exe 文件基址(ReadFileIntoBuffer)
    GtFileSystemExportTable = 0x8A8,         // 2216: 文件系统导出表地址(InitFileSystemExportTable)
    GtFileSystemExportTable32 = 0x8AA,        // 2218: 32位文件系统导出表地址(InitFileSystemExportTable)
    GtFileSystemReady10 = 0x8B0,              // 2224: Win10 文件系统过滤器就绪标志(InitFileSystemExportTable)
    GtFileSystemReady7 = 0x8B1,               // 2225: Win7 文件系统过滤器就绪标志(InitFileSystemExportTable)
    GtObjectListOffset = 0x8C0,                // 2240: 进程对象列表偏移(InitObjectCallback)

    // ---- Win32k 服务缓冲区 ----
    GtWin32kServiceBuffer32 = 4568,    // 32位 Win32k 服务表缓冲区
    GtWin32kServiceBuffer64 = 5480,    // 64位 Win32k 服务表缓冲区

    // ---- 边界标记 ----
    GtTotalSize = 0x4000,              // 16384: 全局表总条目数

    // ---- fltmgr.sys 分析数据 (2174-2202) ----
    GtFltmgrBase = 0x87E,                     // 2174: fltmgr.sys 模块基址
    GtFltmgrBaseBackup = 0x87F,               // 2175: fltmgr.sys 基址备份
    GtFltEnumerateFiltersOffset = 0x880,      // 2176: FltEnumerateFilters 导出偏移
    GtFltEnumerateFiltersAddr = 0x881,        // 2177: FltEnumerateFilters 函数地址
    GtFltUnregisterFilterOffset = 0x882,      // 2178: FltUnregisterFilter 导出偏移
    GtFltUnregisterFilterAddr = 0x883,        // 2179: FltUnregisterFilter 函数地址(FsFilterCreateCallback)
    GtFltDataSectionOffset = 0x884,           // 2180: PE 分析数据节偏移(ParseNtImageSections)
    GtFltEnumerateFilterDataSection = 0x885,  // 2181: FltEnumerateFilters PE 数据节地址(ScanFltMgrExportTable)
    GtFltPeSectionOfs0 = 0x886,               // 2182: PE 节偏移/地址对 0(偏移)
    GtFltPeSectionAddr0 = 0x887,              // 2183: PE 节偏移/地址对 0(地址)
    GtFltPeSectionOfs1 = 0x888,               // 2184: PE 节偏移/地址对 1(偏移)
    GtFltPeSectionAddr1 = 0x889,              // 2185: PE 节偏移/地址对 1(地址)
    GtFltPeSectionOfs2 = 0x88A,               // 2186: PE 节偏移/地址对 2(偏移)
    GtFltPeSectionAddr2 = 0x88B,              // 2187: PE 节偏移/地址对 2(地址)
    GtFltPeSectionOfs3 = 0x88C,               // 2188: PE 节偏移/地址对 3(偏移)
    GtFltPeSectionAddr3 = 0x88D,              // 2189: PE 节偏移/地址对 3(地址)
    GtFltPeSectionOfs4 = 0x88E,               // 2190: PE 节偏移/地址对 4(偏移)
    GtFltPeSectionAddr4 = 0x88F,              // 2191: PE 节偏移/地址对 4(地址)
    GtFltPeSectionOfs5 = 0x890,               // 2192: PE 节偏移/地址对 5(偏移)
    GtFltPeSectionAddr5 = 0x891,              // 2193: PE 节偏移/地址对 5(地址)
    GtFltPeSectionOfs6 = 0x892,               // 2194: PE 节偏移/地址对 6(偏移)
    GtFltPeSectionAddr6 = 0x893,              // 2195: PE 节偏移/地址对 6(地址)
    GtFltPeSectionOfs7 = 0x894,               // 2196: PE 节偏移/地址对 7(偏移)
    GtFltPeSectionAddr7 = 0x895,              // 2197: PE 节偏移/地址对 7(地址)
    GtFltPeSectionOfs8 = 0x896,               // 2198: PE 节偏移/地址对 8(偏移)
    GtFltPeSectionAddr8 = 0x897,              // 2199: PE 节偏移/地址对 8(地址)
    GtFsFilterTableReady = 0x898,             // 2200: 过滤器表就绪标志(InitFsFilterExportTable)
    GtWin32kFilterTableReady = 0x899,         // 2201: Win32k 过滤器表就绪标志(InitFsFilterExportTable)
    GtPeExecutableSectionBase = 0x89A,        // 2202: PE 可执行节基址(FindPeExecutableSection)

    // ---- MiniFilter 回调/通信端口 (2281-2291) ----
    GtRegPathStringPtr = 0x8EB,               // 2283: 驱动注册表路径字符串指针(RegisterMiniFilterRegistry)
    GtObjectTypeIdxMatched = 0x8ED,           // 2285: 对象类型索引匹配(CmdEnumKernelObjectTable)
    GtObjectTypeIdxNotMatched = 0x8EF,        // 2287: 对象类型索引未匹配(CmdEnumKernelObjectTable)
    GtMiniFilterFormatNameReady = 0x8F0,      // 2288: MiniFilter 文件名格式化就绪标志(MiniFilterFormatFileName)
    GtMiniFilterFormatNameExReady = 0x8F1,    // 2289: MiniFilter 文件名格式化扩展就绪标志(MiniFilterFormatFileNameWithPath)
    GtCommPortCallbackReady = 0x8F2,          // 2290: 通信端口回调注册标志(MiniFilterCommPortDisconnect)
    GtMiniFilterNotifyRoutineReady = 0x8F3,   // 2291: MiniFilter 通知例程注册标志(MiniFilterNotifyRoutineEx)

    // ---- Hook 系统调用初始化偏移 (2325-2326) ----
    GtInitHookSyscallOffset = 0x915,           // 2325: Hook 系统调用初始化 PE 偏移(InitHookSyscall)
    GtInitHookSyscallAddress = 0x916,          // 2326: Hook 系统调用初始化地址(InitHookSyscall)

    // ---- 系统调用哈希表/函数指针扩展 (17518) ----
    GtInitHookSyscallPeSectionOffset = 0x446E, // 17518: InitHookSyscall PE 节区偏移

    // ---- Hook 系统调用存储索引 (用于存储各 Hook 函数结果) ----
    GtFindHookTargetResultAddr = 0x4F,           // 79: FindHookTarget 匹配结果地址(FindHookTargetInExportWin7/8)
    GtFindHookTargetDataPeOffset = 0x42EB,       // 17131: FindHookTargetData PE 偏移(FindHookTargetDataSection)
    GtNtOpenKeyResultAddr = 0x63,                // 99: NtOpenKey Hook 结果地址(HookSyscallNtOpenKey)
    GtNtOpenKeyResultValue = 0x68,               // 104: NtOpenKey Hook 结果值(HookSyscallNtOpenKey)
    GtNtDeleteKeyResultAddr = 0x34E,             // 846: NtDeleteKey Hook 结果地址(HookSyscallNtDeleteKey)
    GtFindHookTargetMatchOffset = 0x415F,        // 16735: FindHookTargetInExportWin7 匹配偏移
    GtFindHookTargetPeSectionOffset = 0x416B,    // 16747: FindHookTarget PE 节区偏移
    GtFindHookTargetFirstMatchOffset2 = 0x416E,  // 16750: FindHookTarget 首匹配偏移 2
    GtFindHookTargetFirstMatchAddr2 = 0x416F,    // 16751: FindHookTarget 首匹配地址 2
    GtNtOpenKeyPeSectionOffset = 0x41BC,         // 16828: NtOpenKey Hook PE 节区偏移
    GtNtDuplicateObjectPeSectionOffset = 0x4183, // 16771: NtDuplicateObject Hook PE 节区偏移
    GtNtWriteFilePeSectionOffset = 0x4189,       // 16777: NtWriteFile Hook PE 节区偏移
    GtNtCreateProcessPeSectionOffset = 0x429D,   // 17053: NtCreateProcess Hook PE 节区偏移
    GtDisableHookProtectionPeOffset = 0x42D9,    // 17113: 禁用 Hook 保护 PE 偏移
    GtUninstallHookSyscallPeOffset = 0x4228,     // 16936: 卸载 Hook 系统调用 PE 偏移
    GtNtDeleteKeyPeSectionOffset = 0x4393,       // 17299: NtDeleteKey Hook PE 节区偏移
    GtDisableHookProtectionAddr1 = 0x817,        // 2071: 禁用 Hook 保护目标地址 1(DisableHookProtection)
    GtDisableHookProtectionAddr2 = 0x818,        // 2072: 禁用 Hook 保护目标地址 2(DisableHookProtection)
    GtNtCreateThreadResultAddr = 0x8CE,          // 2254: NtCreateThread Hook 结果地址(HookSyscallNtCreateThread)
    GtNtCreateProcessResultAddr = 0x8CF,         // 2255: NtCreateProcess Hook 结果地址(HookSyscallNtCreateProcess)
    GtNtCreateThreadHookSuccess = 0x8EA,         // 2282: NtCreateThread Hook 成功标志(HookSyscallNtCreateThread写入0=成功)
    GtNtCreateThreadPeSectionOffset = 0x4441,    // 17473: NtCreateThread Hook PE 节区偏移
    GtUninstallHookResultOffset = 0x2B6,         // 694: 卸载 Hook 偏移(UninstallHookSyscall)
    GtUninstallHookResultAddr = 0x2B7,           // 695: 卸载 Hook 地址(UninstallHookSyscall)

    // ---- 内核数据节区扫描目标偏移 (ScanKernelModulePESections 使用) ----
    GtKernelDataSectionScanTarget1 = 0x42C1,     // 17089: 内核数据节区扫描目标偏移 1
    GtKernelDataSectionScanTarget2 = 0x42C7,     // 17095: 内核数据节区扫描目标偏移 2 (旧版本)
    GtKernelDataSectionScanTarget3 = 0x4444,     // 17476: 内核数据节区扫描目标偏移 3 (Win10 1607+)

} GLOBAL_TABLE_INDEX;

// 兼容旧名称宏定义（平滑过渡）
#define GT_NT_BUILD_NUMBER         ((int)GtNtBuildNumber)
#define GT_NTOSKRNL_BASE           ((int)GtNtoskrnlBase)
#define GT_MODULE_INFO             ((int)GtModuleInfo)
#define GT_NTOSKRNL_IMAGE_BASE     ((int)GtNtoskrnlImageBase)
#define GT_CURRENT_PROCESS         ((int)GtCurrentProcess)
#define GT_CURRENT_PROCESS_ID      ((int)GtCurrentProcessId)
#define GT_DRIVER_OBJECT           ((int)GtDriverObject)
#define GT_REGISTRY_PATH           ((int)GtRegistryPath)
#define GT_DEVICE_OBJECT           ((int)GtDeviceObject)
#define GT_SYMLINK_OBJECT          ((int)GtSymlinkObject)
#define GT_ENCRYPTION_KEY          ((int)GtEncryptionKey)
#define GT_ENCRYPTION_KEY_BYTE     ((int)GtEncryptionKeyByte)
#define GT_IRP_BUFFER_SIZE         ((int)GtIrpBufferSize)
#define GT_GLOBAL_MUTEX            ((int)GtGlobalMutex)
#define GT_CALLBACK_INITIALIZED    ((int)GtCallbackInitialized)
#define GT_CALLBACK_BUSY           ((int)GtCallbackBusy)
#define GT_COMMAND_HANDLER_BASE    ((int)GtCommandHandlerBase)

// 全局表大小
#define GT_TOTAL_SIZE              ((int)GtTotalSize)

// ============================================================
// IRP 通信协议常量
// ============================================================
#define IRP_TYPE_MAGIC             0x20202020  // IRP Type 标记
#define IRP_INPUT_BUFFER_SIZE      48          // 输入缓冲区大小 (48 字节)
#define IOCTL_METHOD               METHOD_NEITHER  // 通信方法
#define IOCTL_OPTIONS_VALUE        48          // Create.Options 验证值

// ============================================================
// 命令操作码范围
// ============================================================
#define CMD_OPCODE_MIN             32
#define CMD_OPCODE_MAX             0x11A  // 282
#define CMD_OPCODE_COUNT           (CMD_OPCODE_MAX + 1)

// ============================================================
// 基本类型定义
// ============================================================
typedef struct _IRP_INPUT_HEADER {
    ULONG Type;                     // 必须为 0x20202020
    ULONG Type2;                    // 辅助类型
    ULONG ChecksumHigh;             // 校验和高位
    ULONG ChecksumLow;              // 校验和低位
    ULONG Param1;                   // 参数 1 (Flink)
    ULONG Param2;                   // 参数 2 (Flink high)
    ULONGLONG Param3;                 // 参数 3 (UserBuffer1)
    ULONGLONG Param4;                 // 参数 4 (UserBuffer2)
    ULONGLONG Param5;                 // 参数 5 (MdlAddress)
    ULONG Opcode;                   // 操作码 (Size+1 处)
} IRP_INPUT_HEADER, *PIRP_INPUT_HEADER;

// ============================================================
// MD5 上下文
// ============================================================
typedef struct _MD5_CONTEXT {
    ULONG State[4];                 // 0x00: 状态 (A,B,C,D)
    ULONG Count[2];                 // 0x10: 位计数
    UCHAR Buffer[64];               // 0x18: 数据缓冲区
} MD5_CONTEXT, *PMD5_CONTEXT;

// ============================================================
// 回调函数类型定义
// ============================================================
typedef
NTSTATUS
(*PCOMMAND_HANDLER)(
    ULONG64 Param1,
    ULONG Param2,
    ULONG64 Param3,
    ULONG Param4
    );

// ============================================================
// 全局函数声明
// ============================================================

//

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
void AtomicWrite16Bytes(ULONG64 TargetAddress, void *Buffer);
__int64 AtomicWrite64NoWriteProtect(volatile __int64 *Target, __int64 Value);
__int64 AttachToProcessAndInitKernelMemory(void);
char __fastcall BtreeSearchByKey(unsigned __int8 *pKeyData, unsigned int *pOutOrdinal, unsigned int EntryCount);
char BugcheckCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, ULONG64 OutputBuffer);

void BuildContextTableFromNtFile(void);
__int64 BuildDriverInfoEntries(unsigned int *a1, unsigned int a2);

__int64 BuildExportIndexTable( __int64 PeBase, unsigned int PeSize, _BYTE *OutTable, unsigned int MaxEntries, unsigned char (__fastcall *FilterFunc)(__int64));

char BuildExportServiceTable(PUCHAR ImageBase, ULONG ImageSize, PUCHAR ServiceTable, ULONG TableSize);
char BuildExportServiceTableForProcess( __int64 ImageBase, struct _KPROCESS *TargetProcess, char Is64Bit, _QWORD *OutServiceTable);

void BuildHookTable(void);
char BuildJmpPatchStub(int a1, __int64 a2, __int64 a3, unsigned int a4, int a5);
__int64 BuildPeServiceNumberTable(__int64 ImageBase, unsigned int ImageSize, unsigned int ServiceTableOffset, char Is64Bit);

__int64 BuildServiceTableFromNtKernel(_QWORD a1, _QWORD a2);
__int64 BuildSyscallDriverPath(void);
__int64 CalcDiskPartitionOffset(int *a1, unsigned int a2);
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
char CheckAddressInModuleRange(__int64 a1);
char CheckAddressInPhysicalMemoryRange(unsigned __int64 Address);
char CheckAddressInSystemModuleRange(unsigned __int64 Address);
char CheckExportEntryFlags(PUCHAR ExportEntry);
char __fastcall CheckExportNamePrefixCombined(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize);
char __fastcall CheckExportNamePrefixWin10V2(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize);
__int64 CheckFilePathFilter(__int64 FilePath, unsigned int FilePathLength);
BOOLEAN CheckMemoryValid(void *Address);
char CheckObjectTypeFlag(__int64 ObjectHeader);
char CheckObjectTypeFlagWrapper(__int64 ObjectHeader);
__int64 CheckProcessJobObject(__int64 a1);
__int64 CheckProcessObjectFlag(__int64 a1);
char CheckProcessProtection(__int64 ProcessObject, _DWORD *OutProtectionType);
__int64 CheckProtectedEntry(__int64 Entry);
char CheckSsdtHookIntegrity(ULONG64 ProcessId, ULONG64 BufferSize, _DWORD *OutputBuffer, int OutputSize);
BOOLEAN CheckVmxEnabled(void);
__int64 CheckWin2k3Sp2(void);
char __fastcall ClassifyModuleTypeHalOrNt(const char *ModuleName, __int64 *pExportDirBase, unsigned int *pExportDirCount);
void CleanupHashTable(void);
__int64 CleanupNtoskrnlFile(void);
__int64 CleanupProcessMemoryEntry(_QWORD *pTargetEntry);
char CleanupProcessThreads(struct _KPROCESS *Process, unsigned int *OutputBuffer, unsigned int BufferSize);
void CleanupThreadWithBuffer(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 ClearDebugRegisters(void);
char ClearKernelMemoryPointer(void);
__int64 ClearKernelObjectEntry(__int64 TargetAddress);
__int64 ClearSsdtRelatedEntry(__int64 TargetAddress);
__int64 CmdCallKernelMemoryFunction(unsigned int *Address, int InputSize);
__int64 CmdCallSystemRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCallbackControl(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCheckBytePattern(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCheckFileExist(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCheckProcessAccess(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCheckProcessHideDetect(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdClearKernelBase(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCloseHandle(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCloseProcessHandle(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, int BufferSize);
char CmdCloseProcessHandleEx(__int64 InputBuffer);
__int64 CmdCopyFile(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCreateFile(_QWORD *Address, int InputSize);
__int64 CmdCreateFileWithPath(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDeleteFile(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDeviceIoControl(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDeviceIoControlEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDeviceIoControlSimple(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDeviceIoControlWithBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDeviceIoControlWithString(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDiskOperationDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDiskReadSector(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDiskSectorReadWrite(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDispatchSsdtByVersion(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdDriverLoadUnload(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDriverProtectOp(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDriverProtectStatus(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumCallbackContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4);
char CmdEnumDriverObjects(unsigned int *pOutputBuffer, unsigned int OutputSize, char Flags, char Flags2);
__int64 CmdEnumFileSystemContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumGdiObjects(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumHandles(__int64 a1, __int64 a2, volatile void *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumHandlesByPid(volatile void *Address, SIZE_T Length, char *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumHookDetail(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumHookInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelDriver(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelDrivers(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumKernelHandleTable(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelMemoryDetail(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelModuleInfoEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelModules(_OWORD *Address, int InputSize, volatile void *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumKernelObjectTable(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectAllTypes(__int64 OutputBuffer, __int64 OutputSize, char *UserBuffer, unsigned int UserBufferSize);
__int64 CmdEnumObjectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectHandles(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumObjectTypeDetail(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectTypeDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectTypeInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectTypeTable(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectTypes(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjects(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumObjectsEx(__int64 a1, unsigned int a2, _DWORD *a3, unsigned int a4);
__int64 CmdEnumObjectsLegacy(__int64 a1, unsigned int a2, _DWORD *a3, unsigned int a4);
__int64 CmdEnumProcessContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessContextWin7(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessContextWin8(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessHandles(__int64 Address, int InputSize, _DWORD *OutputBuffer, unsigned int OutputBufferSize);
__int64 CmdEnumProcessListEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessListWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessListWin7(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessListWin8(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessModules(__int64 DeviceObject, __int64 Irp, _DWORD *pOutputBuffer, unsigned int BufferSize);
__int64 CmdEnumProcessProtectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumProcessorInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumRegistry(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumRegistryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumServiceTable(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumServices(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumShadowSyscallEntries(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSsdtEntryTable(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int OutputBufferSize);
__int64 CmdEnumSyscallEntries(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable2(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable3(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable4(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable5(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable6(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable7(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable8(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumSyscallTable9(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 CmdEnumThreadContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumThreads(char **InputBuffer, int InputSize, _DWORD *OutputBuffer, int OutputSize);
__int64 CmdEnumThreadsEx(void **Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdEnumUSBPortSyscallTable(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdFixProcessEProcess(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdFixSsdtEntryAddress(unsigned int *pSyscallIndex, int FieldSize);
__int64 CmdFsctlOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdGetHookEntryInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdGetKernelBaseLegacy(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdGetModuleCount(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdGetSsdtTableInfo(__int64 a1, __int64 a2, _QWORD *pOutputBuffer, int OutputSize);
__int64 CmdHandleMonitor(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdInitKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdInitSsdtTable(__int64 a1, __int64 a2, _DWORD *OutputBuffer, int BufferSize);
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
__int64 CmdInstallUSBPortSyscallHook(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdIoPortOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdKernelMemoryOpDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdKernelMemoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdKernelObjectMonitor(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdLookupObjectTypeByAddr(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdMemoryQueryOp(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdModuleOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdObjectOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);

__int64 CmdObjectOperationDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdOpenFileForEnum(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdOpenFileHandle(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdOpenSectionObject(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdProcessMemoryOpDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdProcessMemoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdProcessMonitor(_OWORD *Address, int InputSize);
__int64 CmdProcessOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdProtectStatus(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQueryDiskInfo(char *Dst, SIZE_T Length);
__int64 CmdQueryFileAllocationSize(void *FileHandle, _QWORD *pAllocationSize);
__int64 CmdQueryFileInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQueryFileStandardInfo(void *FileHandle, _QWORD *pStandardInfo);
__int64 CmdQueryHookStatus(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQueryMemoryInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQueryModuleInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQueryObjectInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQueryProcessInfo(__int64 ProcessId, __int64 BufferSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdQueryProcessInfoEx(__int64 Address, int InputSize, _DWORD *a3, int a4);
__int64 CmdQueryProcessNameByPid(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQuerySsdtDetails(__int64 a1, __int64 a2, _QWORD *pOutputBuffer, int OutputSize);
__int64 CmdQuerySsdtInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQuerySystemInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQuerySystemInfoEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdQuerySystemInfoExV2(char *Dst, SIZE_T Length);
__int64 CmdReadCpuBaseAddr(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadCpuBaseAddrEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadCpuId(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadCpuInfoEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadCpuMsr(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadExportDirectory(__int64 a1, __int64 a2, char *OutputBuffer, unsigned int BufferSize);
__int64 CmdReadFile(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadFileInfo(void *FileHandle, _DWORD *pFileInfo);
__int64 CmdReadFileSize(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadKernelBase(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadKernelMemoryRange(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadKernelMemoryRangeSize(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadMsrValue(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadPhysicalMemory(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadProcessMemory(__int64 Address, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadProcessMemoryBlock(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadProcessMemoryEx(_OWORD *Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 CmdReadProcessMemoryStr(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadSsdtEntryTable(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int OutputBufferSize);
__int64 CmdReadSsdtEntryTableEx(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int OutputBufferSize);
__int64 CmdRegistryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdRegistryProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdRenameFile(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdResetDriverState(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdResetProcessContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdRestoreDriverDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdRestoreExportTable(void);
__int64 CmdRestoreSsdtTable(void);
__int64 CmdSendRenameFileIrp(void *FileHandle, const void *RenameBuffer, unsigned int BufferSize);
__int64 CmdSetCallbackContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetFileAttributes(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetFileBasicInfo(void *FileHandle, struct _IRP *FileBasicInfo);
__int64 CmdSetFileSystemContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetKernelModuleInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetModuleInfoInternal(_QWORD a1);
__int64 CmdSetObjectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetProcessContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetProcessContextWin7(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetProcessContextWin8(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetProcessProtectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetProcessorField(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetRegistryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdSetSsdtEntry(_DWORD *pInputBuffer, int InputSize);
__int64 CmdSetThreadContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdStubAlwaysTrue(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdTerminateProcessByEProcess(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdThreadMonitor(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdThreadOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdThreadProtectStatus(__int64 Address, int InputSize, _DWORD *a3, int a4);
__int64 CmdUpdateExportEntry(__int64 *pInputBuffer, int InputSize);
__int64 CmdVirtualMemoryOp(_OWORD *Address, int InputSize);
__int64 CmdWriteFile(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdWriteKernelMemoryRange(void);
__int64 CmdWriteKernelObjectField(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdWriteMsrValue(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdWriteProcessMemoryEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
void CollectObjectDirAndTypeEntries(unsigned int *a1, _DWORD *a2);
unsigned int __fastcall CompareExportNamePrefix(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned __int64 LimitAddress);
__int64 CompleteIrpAndCleanupMdl(__int64 a1, __int64 Irp, __int64 a3);
__int64 CopyCallbackContextHookTable(__int64 pSourceTable);
__int64 CopyCallbackContextTable(__int64 pSourceTable, int ContextType);
__int64 CopyCallbackContextV3Table(__int64 pSourceTable);
__int64 CopyContextTableEntries(__int64 pOutputTable);
__int64 CopyFsFilterEntryTable(__int64 OutputBuffer, char Is64Bit);
__int64 CopyHookEntryArray(__int64 DestBuffer, _QWORD *pSourceArray, unsigned int EntryCount);
__int64 CopyKernelArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4);
__int64 CopyKernelDualArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4);
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
__int64 DecodeModrmAddressingMode( PULONG Context, ULONG64 a2, INT OperandType, PUCHAR OperandOut, INT Flag);

__int64 DecodeModrmByte(ULONG64 BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx);
__int64 DecodeModrmByteSimple(PUCHAR BufferPos, ULONG64 BufferEnd, PUCHAR DecodeCtx);
__int64 DecodeModrmInstruction(PULONG64 ContextArray);
__int64 DecodeModrmOpcodeTable(PUCHAR Context);
__int64 DecodeMultiByteOpcode(PUCHAR Context, ULONG64 a2, ULONG64 a3);
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
__int64 DisableHookProtection(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 DisableObjectCallback(int flags, ULONG64 a2);
char DisableObjectProtect(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize);
char DisableObjectProtectEx(_DWORD *OutputBuffer, unsigned int BufferSize);
__int64 DisableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
char DisableProcessProtect(_OWORD *Address, int InputSize);
char DisableThreadProtect(unsigned int *Address, int ContextSize);
__int64 DiskOperationDispatcher(void);
__int64 DispatchFreeProcessMemory(char *VirtualAddress);
__int64 __fastcall DispatchHookSwapByVersion(__int64 Handle, __int64 *OriginalValue);
__int64 DispatchInstructionDecode( ULONG64 BufferPos, ULONG64 BufferEnd, ULONG64 TableEntry, ULONG64 DecodeCtx);

__int64 __fastcall DispatchIoControlByBuildNumber( __int64 (__fastcall *HandlerFunc)(__int64, __int64),

    __int64 Arg2,
    __int64 Arg3,
    unsigned __int8 Arg4,
    unsigned int Arg5);
__int64 DispatchKernelMemoryCleanup(_QWORD *VirtualAddress);
__int64 DispatchParseNtExportFunctions(void);
__int64 DispatchWin32kPatternMatching(void);
__int64 DuplicateUSBPortSyscallOutput(__int64 pSourceTable);
char EnableDeviceObjectProtection(void);
__int64 EnableHookProtection(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
char EnableObjectCallback(PVOID ObjectName, SIZE_T Length);
char EnableObjectProtect(_OWORD *Address, int BufferSize);
__int64 EnableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableProcessProtect(PVOID *Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize);
char EnableThreadProtect(__int64 *Address, int InputSize, _QWORD *OutputBuffer, int OutputSize);
__int64 EnumCallbackContextOperation(__int64 a1, __int64 a2, _WORD *pOutputBuffer, int OutputSize);
__int64 EnumCallbackContextTable(__int64 pOutputTable);
__int64 EnumCallbackContextV3Table(__int64 pOutputTable);
__int64 EnumDeviceObjectTypeList(int DeviceIndex, __int64 pOutputTable);

void EnumHandleTableToBuffer(unsigned int *OutputBuffer, _DWORD *pCount);
__int64 EnumHandlesByType(WORD *TargetName, ULONG NameLen, _DWORD *TypeTable, _DWORD *OutputBuffer, int MaxEntries);
__int64 EnumKernelDriverObjects(_DWORD *pOutputArray, unsigned int MaxCount);
__int64 EnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int BufferSize);
__int64 EnumKernelModules(__int64 a1, __int64 a2, __int64 a3, __int64 a4);
__int64 EnumObjectContextTable(__int64 pOutputBuffer);
__int64 EnumObjectDirectoryEntries(unsigned __int16 *pDirectoryPath, _DWORD *pDirectoryInfo, __int64 OutputBuffer, int MaxCount);
__int64 EnumObjectTypeCleanupList(PVOID *pTargetObject);
char EnumObjectTypeFilterCallback(__int64 a1, __int64 a2, __int64 a3);
char EnumObjectTypeList(unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessAndInitObjects(__int64 a1, char a2);
__int64 EnumProcessContextSsdtTable(__int64 pOutputTable);
__int64 EnumProcessContextTable(__int64 pOutputTable);
__int64 EnumProcessContextV2Table(__int64 pOutputTable);
__int64 EnumProcessContextV3Table(__int64 pOutputTable);
__int64 EnumProcessContextV3TableWin7(__int64 pOutputTable);

__int64 EnumProcessModules(ULONG64 ProcessId, int Flags, volatile void *OutputBuffer, unsigned int BufferSize);
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
char EnumerateProcessInformation(__int64 a1, __int64 a2, unsigned int a3);
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
char FillProcessInformationEntry( char *VirtualAddress, char *AlternateAddr, __int64 OutputBuffer, unsigned int BufferSize, char ValidateFlag, char EntryType, char a7);

__int64 FilterActiveHookEntries(__int64 OutputBuffer, unsigned int EntryCount, enum _GLOBAL_TABLE_INDEX TableIndex);
__int64 __fastcall FindDeleteValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, __int64 *pResult);
__int64 FindExportByNameInPeBody(PUCHAR PeBase, ULONG PeSize, PCHAR FuncName, int Is64Bit);
char __fastcall FindExportEntryByAddress(__int64 TargetAddress, __int64 FilterTable, unsigned int FilterTableSize);
void *FindExportEntryByName(char *Dst);
void __fastcall FindHalDllInDriverList( unsigned int *pDriverArray, __int64 ArraySize, _QWORD *pImageBase, _DWORD *pImageSize);

__int64 FindHookTargetDataSection(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
__int64 FindKernelPESectionByType(enum _GLOBAL_TABLE_INDEX TypeIndex);
char FindKernelRdataSection(__int64 a1, unsigned int a2);
char FindMatchingEntryInArray(__int64 Entry, unsigned int Type, unsigned int *Array);
__int64 FindNdisExportsBySectionScanV2(__int64 a1, unsigned int a2);
__int64 FindNtOpenThreadTargetWin7(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5);
__int64 FindNtOpenThreadTargetWin8(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5);
__int64 FindNtoskrnlExportsInThreadEnv(void);
__int64 FindOpenProcessTokenOffset(__int64 TargetBase, unsigned int TargetSize);
__int64 FindOpenProcessTokenTarget(__int64 TargetBase, unsigned int TargetSize);
__int64 FindPESectionByName(PUCHAR PeBase, PCHAR SectionName);
__int64 FindPESectionByNameReturnVa(PUCHAR PeBase, PCHAR SectionName);
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
char GetExportEntrySignBit(PUCHAR ExportEntry);
char GetIrpMonitorContext(__int64 DeviceObject, unsigned int IrpMajorFunc, _OWORD *pContextBuffer, _QWORD *pCallDriver);
__int64 GetKernelObjectTypeInfo(__int64 ObjectHeader);
__int64 GetProcessFromHandleEntry(__int64 HandleTableEntry);
char GetProcessImagePath(PRKPROCESS PROCESS, HANDLE ProcessId, void **OutBuffer, _DWORD *OutSize, int Flags);
char GetProcessImagePathByAttach(PRKPROCESS PROCESS, HANDLE ProcessId, void **a3, _DWORD *a4);
char GetProcessVirtualizationContextFallback(_DWORD *OutputBuffer, unsigned int BufferSize);
char GetSectionObjectNameFromHandle(PRKPROCESS PROCESS, HANDLE Handle, _QWORD *a3, _DWORD *a4);
__int64 GetSetValueKeyCtx(_QWORD *pContext, _QWORD *pResult);
__int64 GetSsdtFunctionBase2(void);
__int64 GetSsdtFunctionBase4(void);
__int64 GetStringLength(_WORD *String);
__int64 GetWin7Sp1EprocessOffset(void);
__int64 HookSyscallNtClose(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtCreateFile(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
__int64 HookSyscallNtCreateKey(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 HookSyscallNtCreateProcess(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 HookSyscallNtCreateThread(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 HookSyscallNtCreateToken(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtDeleteKey(unsigned __int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 HookSyscallNtDeleteValueKey(unsigned __int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5);
__int64 HookSyscallNtDuplicateObject(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtLoadDriver(__int64 TargetBase, signed int TargetSize, __int64 Context, __int64 RelocBase);
__int64 HookSyscallNtOpenFile(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtOpenKey(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 HookSyscallNtOpenKeyEx(__int64 a1, unsigned int a2);
__int64 HookSyscallNtOpenProcess(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 HookSyscallNtOpenProcessToken(__int64 TargetAddress, unsigned int TargetSize);
__int64 HookSyscallNtOpenThread(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5);
__int64 HookSyscallNtOpenThreadToken(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtQueryInformationProcess(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtQueryInformationThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtQuerySystemInfo(unsigned __int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase);
__int64 HookSyscallNtReadFile(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtResumeProcess(void);
__int64 HookSyscallNtResumeThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSetInformationProcess(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSetInformationThread(__int64 TargetBase, unsigned int TargetSize);
__int64 HookSyscallNtSetValueKey(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5);
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
__int64 InitHandleTypeTable(void);
__int64 InitHookSyscall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
char InitImageLoadCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
__int64 InitImageNotify(void);
__int64 InitImageNotifyCallbackWin7(void);
__int64 InitKernelMemoryContext(void);
__int64 InitKernelMemoryContextOperation();
__int64 InitKernelModuleSectionScan(void);
void InitMd5Context(PMD5_CONTEXT Context);
__int64 InitMsrTable(void);
__int64 InitObjectAndQueryName(__int64 a1, int a2);
char InitObjectCallback(__int64 UnusedParam, __int64 UnusedParam2, _DWORD *OutputBuffer, unsigned int OutputBufferSize);
__int64 InitObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InitObjectTypeTable(_QWORD a1);
void InitPESectionReadContext( PUCHAR Base, ULONG Size, INT Mode, LONG64 a4, INT a5, LONG64 a6, LONG64 a7, PUCHAR Context);

__int64 InitPhysicalMemoryContextTable(int DeviceIndex, __int64 pOutputTable);
char InitPowerCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
char InitProcessCallback(struct _KPROCESS **ProcessPtr, int BufferSize);
void InitProcessContextExportTableWin7(void);
void InitProcessContextHookTable(void);
__int64 InitProcessNotify(void);
char InitRegCallback(void *OutputBuffer, int OutputSize, volatile void *UserBuffer, unsigned int UserBufferSize);
char InitRegFilter(__int64 DeviceObject, __int64 Irp, _OWORD *OutputBuffer, int OutputSize);
char InitRegNotify(void);
__int64 InitSdstServiceCount(void);
char InitSdstTable(void);
char InitShutdownCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
__int64 InitSyscallNumberTable(void);
char InitThreadCallback(void);
void InitThreadContextTable(void);
__int64 InitThreadNotify(void);
void InitUSBPortSyscallTable(void);
__int64 InitUnicodeStringBuffer(__int64 Buffer, __int64 StringPtr, unsigned int MaxLength);
void InitWin32kServiceTableEntries(void);
void InitWin32kTableByVersion(void);
__int64 InstallCallbackContextHookEntry(unsigned int *pInputEntry);
__int64 InstallHookSyscall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
char InstallSsdtHookForThreadProtect(__int64 pInputEntry);
__int64 InvokeCallbackWithZeroArg(__int64 Arg1, __int64 Arg2, __int64 Arg3, __int64 (__fastcall *Callback)(__int64, __int64, __int64, ULONG64));
__int64 InvokeNullCallback(__int64 Arg1, __int64 Arg2, __int64 Arg3, __int64 (*Callback)(void));
char InvokeRegisteredCallbackWithUserData(unsigned int *Address, int InputSize);
__int64 IoPortOperationDispatch(void *InputBuffer, int BufferSize);
__int64 IrpFileSystemControl(void *FileHandle, struct _IRP *FsctlBuffer, ULONG BufferSize, ULONG FsControlCode);
__int64 IrpFsctlGetVolumeData(void *FileHandle, __int64 *pVolumeData);
__int64 IrpFsctlVolumeDismount(void *FileObject);
__int64 IrpReadFile(void *FileHandle, struct _IRP *AssociatedIrp, ULONG Length, ULONG CreateOptions);
int IrpReadFileEx(void *FileHandle, int a2, __int64 a3, void *a4, char a5, struct _IO_STATUS_BLOCK *pStatus);
__int64 IrpReadFileWithOffset( void *FileHandle, DWORD ByteOffset, void *Buffer, ULONG Length, char WaitForLock, _DWORD *pBytesRead, char UseSecondary);

__int64 IrpSetupBufferMdl(PIRP Irp, __int64 StackLocation, void *Buffer, ULONG BufferSize, char ProbeAndLock, char WriteOperation, _DWORD *pFlags);

__int64 IrpWriteFile( void *FileHandle, LARGE_INTEGER *ByteOffset, ULONG Length, void *Buffer, PLARGE_INTEGER Timeout, struct _IO_STATUS_BLOCK *IoStatusBlock);

char IsExportForwarder(PUCHAR ExportEntry);
char IsProcessThreadInList(__int64 a1, __int64 a2, __int64 a3, char a4);

__int64 KernelNotifyRoutine(void *NotificationBuffer, size_t BufferSize);
__int64 KernelNotifyRoutineEx(void *NotificationBuffer, size_t BufferSize);
__int64 LookupDriverHashTable(__int64 DriverName, _DWORD *pResultIndex);
char LookupDriverObjectEntry( unsigned int *pDriverArray, unsigned __int64 TargetAddress, __int64 pDriverEntry, __int64 EntrySize);

char LookupExportByName(PUCHAR PeBase, ULONG PeSize, PCHAR FuncName, PULONG OutRva);
__int64 LookupExportFuncAddr(__int64 ExportIndexTable, unsigned int EntryCount, int HashValue);
__int64 *LookupModuleByName(const char *ModuleName, __int64 *OutBaseAddress);
__int64 LookupMsrTableEntry(void);
char MatchObjectTypeEntry(__int64 Target, __int64 TableBase);
__int64 MatchObjectTypeFilterCallback(_QWORD *a1, _QWORD *a2, __int64 a3);
__int64 MatchObjectTypeFilterCallbackV2(_QWORD *a1, _QWORD *a2, __int64 a3);
__int64 MatchSystemProcessName(_QWORD *Process);
void Md5Final(PMD5_CONTEXT Context, ULONG Digest[2]);
void Md5Final2(PMD5_CONTEXT Context, ULONG Digest[2]);
void Md5Transform(ULONG State[4], PUCHAR Block);
void Md5Transform2(ULONG State[4], PUCHAR Block);
void Md5Update(PMD5_CONTEXT Context, PUCHAR Input, ULONG Length);
void Md5Update2(PMD5_CONTEXT Context, PUCHAR Input, ULONG Length);
__int64 MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size);
NTSTATUS MiniFilterAcquireForCcFlush(void);
NTSTATUS MiniFilterAcquireForModWrite(void);
NTSTATUS MiniFilterAcquireForSectionSync(void);
NTSTATUS MiniFilterActiveRoutine(void);
NTSTATUS MiniFilterClientContext(void);
__int64 MiniFilterCommPortCleanup(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize);
void MiniFilterCommPortConnect(void);
__int64 MiniFilterCommPortDisconnect(void);
NTSTATUS MiniFilterCommPortRecv(void);
NTSTATUS MiniFilterCommPortReply(void);
__int64 MiniFilterCommPortReplyDone(void);
NTSTATUS MiniFilterCommPortSend(void);
__int64 *MiniFilterFilterUnload(__int64 ProcessId, __int64 BaseAddress, char IsAddOperation);
__int64 MiniFilterFormatFileName(void);
__int64 MiniFilterFormatFileNameEx(void);
__int64 MiniFilterFormatFileNameWithContext(void);
__int64 MiniFilterFormatFileNameWithPath(void);
__int64 MiniFilterFormatFileNameWithPathEx(void);
__int64 MiniFilterGenerateFileName(void);
NTSTATUS MiniFilterInstanceQuery(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_FLAGS Flags);
NTSTATUS MiniFilterInstanceSetup(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags);
__int64 MiniFilterNormalizeName(void);
__int64 MiniFilterNotifyRoutine(wchar_t *Name, ULONG NameLength);
NTSTATUS MiniFilterNotifyRoutineEx(void);
NTSTATUS MiniFilterNotifyRoutineEx2(void);
char MiniFilterOpLockPost(PRKPROCESS ProcessObject, char IsQwordKey, __int64 Context);
char MiniFilterOpLockPre(PRKPROCESS ProcessObject, __int64 Unknown, ULONG64 UserBuffer, char IsQwordKey);
NTSTATUS MiniFilterPostFastIo(void);
__int64 MiniFilterPostWrite(void);
__int64 MiniFilterPreAcquire(__int64 Unknown1, __int64 Unknown2, unsigned int *OutputBuffer, unsigned int OutputBufferSize);
NTSTATUS MiniFilterPreCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS MiniFilterPreClose(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS MiniFilterPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
__int64 MiniFilterPreDelete(__int64 Unknown1, __int64 Unknown2, unsigned int *OutputBuffer, unsigned int OutputBufferSize);
NTSTATUS MiniFilterPreDirEnum(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS MiniFilterPreFastIo(void);
__int64 MiniFilterPreFlush(unsigned int *OutputBuffer, int BufferSize);
__int64 MiniFilterPreHardLink(__int64 Unknown1, __int64 Unknown2, __int64 *OutputBuffer, unsigned int OutputBufferSize);
__int64 MiniFilterPreRelease(_QWORD **ContextPtr, int ContextSize);
__int64 MiniFilterPreRename(__int64 Unknown, __int64 Unknown2, _BYTE *OutputBuffer, int OutputBufferSize);
NTSTATUS MiniFilterPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
__int64 MiniFilterPreShutdown(_QWORD *ServicePtr, int InputSize);
__int64 MiniFilterPreVolumeDismount(void);
__int64 MiniFilterPreVolumeMount(char *InputBuffer, int BufferSize);
__int64 MiniFilterPreWrite(void);
NTSTATUS MiniFilterQueryIdleRoutine(void);
NTSTATUS MiniFilterReleaseForCcFlush(void);
NTSTATUS MiniFilterReleaseForModWrite(void);
NTSTATUS MiniFilterServerContext(void);
NTSTATUS MiniFilterStreamHandle(void);
__int64 MiniFilterStreamHandleEx(PRKPROCESS PROCESS, __int64 a2, ULONG64 a3, __int64 a4);
__int64 ModuleOperation(__int64 *pInputBuffer, unsigned int InputSize);
__int64 ModuleOperationDispatch(void *InputBuffer, int BufferSize);
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
__int64 OpenPhysicalDiskDevice(__int16 *a1, void *a2, void **a3);
__int64 OpenSectionWithIoControl(__int64 a1);
__int64 OpenTcpIpDriverSection(void);
__int64 OpenWdfDriverSection(void);
__int64 OpenWin32kSection(void);
__int64 OpenWin32kSysSection(void);
__int64 ParseExportDirForDriver(__int64 DriverInfo, __int64 Context, __int64 PeBuffer, unsigned int PeSize);
void __fastcall ParseExportSectionAndIndex(__int64 ImageBase, unsigned int ImageSize, unsigned int RegRefCount);
char ParseFilePathForSystemRoot(__int16 **a1, _DWORD *a2);
__int64 ParseFsFilterDriverExport(char Is64Bit);
__int64 ParseKernelDataSectionRelocs(__int64 a1, unsigned int a2);
__int64 ParseKernelModuleDiskInfo(void);
char ParseNtExportDir(PUCHAR ImageBase, ULONG ExportDirSize, ULONG64 ImageBaseUnused, int Flags);
char ParseNtHeaders(unsigned __int16 *a1, unsigned int SectionNameLength);
__int64 ParseNtImageSectionHeaders(PRKPROCESS PROCESS, __int64 SectionInfoArray);
char ParseNtImageSectionHeadersForProcess(PRKPROCESS PROCESS, __int64 SectionInfoArray);
char ParseNtKernelDataOffsets(__int64 a1, unsigned int a2);
char ParseNtKernelFile(__int64 ModuleEntry, __int64 OutputBuffer, int OutputSize);
void ParseObjectContextExportDir(void);
char ParsePESectionHeaders(__int64 PeBase, unsigned int PeSize, __int64 SectionName, unsigned __int8 *NameToMatch, unsigned int *OutOffset);
void ParseRegistryDriverExportDir(void);
__int64 PatchFsFilterDriverIndex(__int64 PatchEntry, char Is64Bit);
__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize);
__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize);
__int64 PrepareFileForPageTableScan(void);
char ProcessCallbackRoutine(__int64 Reserved, __int64 Reserved2, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 ProcessMemoryOperationDispatch(void *InputBuffer, int BufferSize);
__int64 ProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ProcessOperationWithAttach(void);
char QueryDeviceObjectInfo(__int64 a1, __int64 *a2);
char QueryDevicePathFromSymbolicLink(__int64 a1, void **a2, _DWORD *a3);
__int64 QueryDiskFsControlInfo(__int16 *FilePath, __int64 Size, char **OutBuffer, __int64 *OutBufferSize);
__int64 QueryDiskFsControlInfoEx(void *FileHandle, __int64 a2, unsigned int a3, unsigned int a4, unsigned __int64 a5, char *a6);

__int64 QueryKernelMemoryByAddress(PVOID ***VirtualAddress, char a2);

char QueryObjectNameByAddress(unsigned __int64 a1, _QWORD *a2, _DWORD *a3);
__int64 QueryObjectNameByType(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength);
char QueryObjectNameInfo(ULONG64 ObjectAddress, WORD *TargetName, ULONG NameLength, _QWORD *OutBuffer, _DWORD *OutSize);
char QueryObjectNameLegacy(_QWORD *Object, _QWORD *NameBuffer, _DWORD *NameLength);
char QueryObjectNameString(ULONG64 Object, _QWORD *OutBuffer, _DWORD *OutSize);
__int64 QueryObjectNameWithRetry(__int64 ObjectEntry, struct _OBJECT_NAME_INFORMATION *NameInfo, ULONG BufferSize, ULONG *OutSize);
__int64 QueryObjectTypeByAddress(__int64 Object);
__int64 QueryObjectTypeInformation(PVOID Object);
__int64 QueryPhysicalDiskInfo(void *FileHandle, _QWORD *pDeviceObject, void **pPhysicalHandle);

char QueryProcessMemoryRegions(__int64 ProcessId, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 QueryProcessModuleInfo(volatile void **Address, int a2, _DWORD *a3, unsigned int a4);
__int64 QuerySsdHookByProcessInfo(void *Src, size_t MaxCount, _DWORD *Address, int OutputSize);
__int64 QuerySyscallHookStatus(__int64 a1);

unsigned int ReadDiskSectors(void);
__int64 ReadDiskSectorsWithAlloc(__int64 a1);
__int64 ReadDiskSectorsWithPartition(char a1, void *a2, unsigned int *a3, int a4, unsigned int a5);
char ReadFileIntoBuffer(__int64 SrcAddress, unsigned int BufferSize, char *DstBuffer);
__int64 ReadFileRawData(WORD *FilePath, void **OutBuffer, ULONG *OutSize, char RequirePeHeader);
void ReadGdtr(void *a1);
char ReadKernelExportDirFile(_QWORD *OutBuffer, unsigned int *OutSize);
__int64 ReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _QWORD *a3, int a4);
char __fastcall ReadModuleFileToBuffer( const char *ModuleName, void **ppBuffer, unsigned int *pFileSize, __int64 *pExportDirBase);

__int64 ReadNtFilePartial(WORD *FilePath, void *Buffer, ULONG Size, char RequirePeHeader);
char ReadNtFileToBuffer(PUCHAR Src, ULONG MaxCount, PUCHAR *OutBuffer, PULONG OutSize);
__int64 ReadNtOsKrnlFile(__int64 *a1, __int64 *a2);
char ReadNtoskrnlFile(void);
__int64 ReadObjectBodyOffset(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectHeaderCreateInfo(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectHeaderField(PVOID ***VirtualAddress, unsigned int FieldOffset, char DerefFirst);
__int64 ReadObjectHeaderHandle(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectHeaderName(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectHeaderQuota(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectHeaderType(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectNameFromCallback(__int64 a1, __int64 a2, __int64 (__fastcall *Callback)(__int64, ULONG64, __int64));
__int64 ReadObjectTypeOffset(PVOID ***VirtualAddress, char a2);
__int64 ReadObjectTypeOffsetByIndex(void);
__int64 ReadPESectionAsmField(PUCHAR Context);
__int64 ReadPESectionEntry(PUCHAR Context, PULONG SectionInfo);
__int64 ReadPESectionField(PUCHAR Context);
__int64 ReadPESectionFieldByte(PUCHAR Context);
char ReadProcessMemoryBlock(PRKPROCESS PROCESS, void *Dst, size_t Size);
__int64 ReadProcessMemoryString(void *Process, void *Address, char *Buffer, unsigned int Length);
__int64 ReadProcessMemoryWithAttach(void);
__int64 ReadServiceTableEntries(__int64 OutputBuffer, __int64 a2, char *PeFileData, unsigned int PeFileSize);
char ReadSystemDriverFile(_QWORD *OutBuffer, unsigned int *OutSize);
__int64 ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray);
NTSTATUS RegNotifyCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);
void RegisterMiniFilterRegistry(void);
__int64 RegistryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RegistryOperationDispatch(void *InputBuffer, int BufferSize);
__int64 ReleaseDiskBuffer(__int64 a1);
char ReleaseIrpMonitorContext(char IsAcquired, __int64 DeviceObject, unsigned int IrpMajorFunc, _OWORD *pContextBuffer);
__int64 ReleaseProcessMemoryBlock(_QWORD *pTargetEntry);
char __fastcall RelocateExportAddresses(void *Src, size_t MaxCount, int BaseDelta);
__int64 RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType);
__int64 RemoveFromObjectTypeList(PVOID *pTargetObject);
__int64 RemoveFromObjectTypeListEx(PVOID *pTargetPointer);
char RemoveI8042prtDriverObject(ULONG64 DriverObject);
char RemoveKbdClassDriverObject(ULONG64 DriverObject);
__int64 RemoveKernelObjectEntry(__int64 TargetAddress);
char RemoveMouClassDriverObject(ULONG64 DriverObject);
char RemoveNdisDriverObject(ULONG64 DriverObject);
__int64 RemoveObjectFromTypeList(PVOID pTargetObject);
char RemoveObjectListEntry(ULONG64 DevicePath, ULONG64 EntryToRemove);
void RemoveOplockNodeByDwordKey(unsigned int *KeyArray, ULONG Offset, __int64 Context);
char RemoveRawDriverObject(ULONG64 DriverObject);
__int64 RemoveServiceEntryFromList(ULONG_PTR *a1, __int64 a2);
__int64 RemoveServiceEntryFromListEx(__int64 ****a1, __int64 ***a2);
__int64 RemoveServiceTableNodeWin10(__int64 ***a1, __int64 **a2);
__int64 RemoveServiceTableNodeWin7(ULONG_PTR *a1, __int64 a2);
char RemoveTcpipDriverObject(ULONG64 DriverObject);
char RemoveVolmgrDriverObject(ULONG64 DriverObject);
__int64 ResetThreadStateFlag(__int64 a1, __int64 a2);
__int64 ResolveCreateFileRelocs(__int64 TargetBase, ULONG TargetSize, __int64 Context, __int64 RelocBase);

__int64 ResolveDriverEntryAddresses(__int64 a1);
__int64 ResolveDriverModuleNames(ULONG *a1);
__int64 ResolveDriverRelativeAddresses(__int64 a1, __int64 a2, int **a3);
__int64 ResolveKernelModuleBasePair(__int64 CpuNumber, ULONG_PTR *pMsrPair);
__int64 ResolveKernelModuleIndex(GLOBAL_TABLE_INDEX a1, GLOBAL_TABLE_INDEX a2, GLOBAL_TABLE_INDEX a3);

__int64 ResolveKernelObjectAddresses(__int64 pObjectTable);
__int64 ResolveModuleBaseAddress(void);
__int64 ResolveModuleEnumBase(void);
char ResolveObjectHeaderPointer(__int64 ObjectBody, _QWORD *OutHeader);
__int64 ResolveObjectNamePointer(__int64 a1);
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
void RestoreCr0WriteProtect(void);
void RestoreDiskIrpFunctionPointer(char State);
__int64 RestoreSyscallHookByIndex(char a1, ULONG a2);
char ReturnFalseStub(void);
__int64 ScanDataSectionPattern(__int64 a1, unsigned int a2);
__int64 ScanFileForPeSectionInfo(void);
__int64 ScanKernelMemForFsChanges(ULONG *a1, int a2);
__int64 ScanKernelModuleDataSectionEx(void);
__int64 ScanKernelModuleInitSection(void);
__int64 ScanKernelModulePESections(void);
__int64 ScanKernelModulePageOrRsrcSection(void);
__int64 ScanKernelModuleSectionByType(void);
__int64 ScanKernelModuleSectionForWin10(void);
__int64 ScanKernelModuleSectionForWin10RS3(void);
__int64 ScanRegValueBodyForRef(ULONG64 a1, ULONG a2, __int64 a3, __int64 a4, int a5, __int64 *a6);

__int64 ScanVadForModifiedPages(ULONG *OutputBuffer, int MaxModifiedCount);
__int64 ScanWin32kDriverForPatterns(ULONG_PTR a1, ULONG_PTR a2);
__int64 SendDeviceIoControlIrp(_QWORD *DeviceInfo, int Direction, void *Buffer, int BlockCount, int SectorSize, int a6);
__int64 __fastcall SendDeviceIoControlWithRetry(__int64 Handle, unsigned int IoControlCode, char Flags, _DWORD **OutputHandle, __int64 IoStatusBlock);
__int64 SendFsctlWithHookSwap(__int64 a1, ULONG a2, __int64 a3, ULONG a4, __int64 a5, int a6, __int64 a7);

__int64 SendIoControlWithUnicodeString(void);
__int64 SerializeDataToBuffer(PUCHAR Context);
__int64 SetCallbackContextEntry(ULONG *pInputEntry);
__int64 SetDecoderStateFlags(PUCHAR Context);
__int64 SetObjectContextEntry(ULONG *pInputEntry);
__int64 SetProcessContextEntry(__int64 pInputEntry);
__int64 SetRegistryContextEntry(ULONG *pInputEntry);
__int64 SetSyscallContextByIndex(ULONG *pInputEntry);
__int64 SetUSBPortServiceTableEntry(ULONG *a1);
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
__int64 *SwapKernelMemoryPointer(__int64 *a1);
__int64 __fastcall SwapKernelObjectPointerPreWin10(__int64 Handle, __int64 *OriginalValue);
__int64 __fastcall SwapKernelObjectPointerWin10(__int64 Handle, __int64 *OriginalValue);
char SwapPhysicalMemoryQword(GLOBAL_TABLE_INDEX AddressGtIndex, GLOBAL_TABLE_INDEX OldValueGtIndex);
void SystemResetCommand(void);
char ThreadCallbackRoutine(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer);
__int64 ThreadOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
char TraverseHashTableWithCallback( _QWORD **HashTable, int MaxDepth, __int64 (__fastcall *Callback)(_QWORD *, _QWORD *, __int64),

    __int64 Context);
__int64 UninstallHookSyscall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
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
__int64 ValidateHookEntries(__int64 a1, ULONG a2);
char ValidateKernelObject(ULONG64 ObjectAddr, ULONG64 AltAddr, _QWORD *OutContext, ULONG64 *OutProcess);
void ValidateObjReferences(__int64 Object1, __int64 Object2);
char ValidateProcessObject(struct _KPROCESS *ProcessObject, struct _KPROCESS *AlternateProcess);
char ValidateProcessObjectEx(char *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize);
__int64 ValidateSingleHookEntry(__int64 a1);
char __fastcall ValidateUtf8Bytes( unsigned __int64 *BufferPtr, unsigned __int64 BufferEnd, _DWORD *ByteCount, _DWORD *StateFlags, _BYTE *ClassFlags);

char __fastcall ValidateZeroPage(__int64 Address, unsigned __int64 LimitAddress);
__int64 WStringCompare(__int64 Str1, unsigned __int16 *Str2, unsigned int MaxLen);
__int64 WStringCompareCaseInsensitive(__int64 Str1, __int64 Str2);
__int64 WalkKernelModuleList(ULONG64 *pModuleList, ULONG *pOutputBuffer, ULONG *pMaxEntries);
char WalkObjectTypeList(_QWORD **NodeStack, int MaxDepth, _DWORD *OutputBuffer, unsigned int MaxBufferSize);
__int64 WriteDiskSectorsWithPartitionCheck(char a1, const void *a2, ULONG a3);
char WritePhysicalMemory(unsigned __int64 TargetAddress, __int64 pWriteContext);
char WritePhysicalMemoryBuffer(unsigned __int64 TargetAddress, const void *SourceBuffer, unsigned int BufferSize, char ProcessorMode, void *pReadBack);
void WritePhysicalMemoryDword(ULONG64 TargetAddress, ULONG Value);
char WritePhysicalMemoryFromGt(GLOBAL_TABLE_INDEX AddressGtIndex, GLOBAL_TABLE_INDEX ValueGtIndex);
char WritePhysicalMemoryQword(unsigned __int64 TargetAddress, __int64 Value);
__int64 WriteProcessContextEntry(__int64 pInputEntry);
__int64 WriteProcessContextEntryWin7(ULONG *pInputEntry);
char WriteProcessMemoryBuffer(_QWORD *InputParams);
char WriteProcessMemoryValue(_QWORD *InputParams);
void WritePtrToAddress(void);
__int64 WriteThreadContextEntryWin10(ULONG *a1);
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

// Minifilter

void MiniFilterContextCleanup(PVOID Arg1, PVOID Arg2);

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
__int64 QueryDriverObjectByPath(__int64 TargetPath, int MaxNameLength, __int64 OutputBuffer, int MaxEntries);
__int64 GetCallbackContextBase(void);
void ReadNtOsKrnlAndParseServiceTable(void);
__int64 ParseServiceTable(char *Src, size_t MaxCount);
__int64 ParseServiceTableWin8(char *Src, size_t MaxCount);
__int64 ParseServiceTableWin7(char *Src, size_t MaxCount);
bool InitProcessAndQueryInfo(struct _KPROCESS *ProcessObject, char a2);
__int16 FindNtRenameKeyTarget(__int64 TargetBase, unsigned int TargetSize, __int64 Context, unsigned __int64 MaxOffset);

