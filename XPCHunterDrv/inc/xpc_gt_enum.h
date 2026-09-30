// ============================================================
// GLOBAL_TABLE_INDEX 枚举与 GT 别名
// ============================================================

#include "xpc_basic.h"

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
    GtPeDataSectionVa = 111,        // PE 数据节 VA(FindKernelInitSection/MiniFilterPostWrite/PreCleanup)
    GtPeDataSectionVa2 = 112,       // PE 数据节 VA 2(MiniFilterPreCleanup)
    GtPeDataSectionVa3 = 113,       // PE 数据节 VA 3(FindKernelDataSectionByData)
    GtPeDataSectionVa4 = 114,       // PE 数据节 VA 4(MiniFilterPostCreate/MiniFilterPreRead)
    GtPeDataSectionVa5 = 115,       // PE 数据节 VA 5(MiniFilterPostRead/MiniFilterPreWrite)
    GtEprocessField106 = 116,
    GtEprocessField107 = 117,
    GtEprocessField108 = 118,
    GtPeCodeDataSectionVa = 119,    // PE CODE 节数据 VA(FindKernelDataSectionByCode)
    GtEprocessField110 = 120,
    GtPeSectionEndVa = 121,         // PE 节结束 VA(MiniFilterPostWrite/MiniFilterPreCleanup)
    GtEprocessField112 = 122,
    GtEprocessField113 = 123,
    GtPeSectionEndVa2 = 124,        // PE 节结束 VA 2(MiniFilterPostCreate/MiniFilterPreRead)
    GtPeSectionEndVa3 = 125,        // PE 节结束 VA 3(MiniFilterPostRead/MiniFilterPreWrite)
    GtEprocessField116 = 126,
    GtEprocessField117 = 127,
    GtEprocessField118 = 128,
    GtPeCodeSectionEndVa = 129,     // PE CODE 节结束 VA(FindKernelDataSectionByCode)
    GtEprocessField120 = 130,
    GtPeInitSectionEndVa = 131,    // PE INIT 节结束 VA(FindKernelInitSection)
    GtEprocessField122 = 132,
    GtEprocessField123 = 133,
    GtEprocessField124 = 134,
    GtObCallbackEntry1 = 135,       // ObRegisterCallbacks 回调入口 1(InstallObjectPreCallbackHooks)
    GtObCallbackEntry2 = 136,       // ObRegisterCallbacks 回调入口 2(InstallObjectPreCallbackHooks)
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
    GtEprocessField190 = 200,
    GtEprocessField191 = 201,
    GtEprocessField192 = 202,
    GtEprocessField193 = 203,
    GtEprocessField194 = 204,
    GtEprocessField195 = 205,
    GtEprocessField196 = 206,
    GtEprocessField197 = 207,
    GtEprocessField198 = 208,
    GtEprocessField199 = 209,
    GtEprocessField200 = 210,

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

    // ---- Fwps 调度表 (2048-2049) ----
    GtFwpsDispatchTableBase = 0x800,    // 2048: Fwps Win8 调度表基址(FindFwpsDispatchTableWin8)
    GtFwpsDispatchTableCount = 0x801,   // 2049: Fwps Win8 调度表条目数(FindFwpsDispatchTableWin8)

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
    GtIrpFsControlFunc = 0x4253,            // 16979: 返回 IRP 的 NtFsControlFile 函数指针(CmdSetModuleInfoInternal)
    GtKeWaitForObjectFunc = 0x4199,         // 16793: KeWaitForSingleObject 函数指针(CmdSetModuleInfoInternal)
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
    GtNtCreateFilePeOffset = 0x4172,            // 16754: NtCreateFile PE 偏移(QueryObjectTypeInformation)
    GtReadMemoryFunc = 0x41E4,              // 16868: 读取内存函数指针(ScanKernelMemForFsChanges/ScanVadForModifiedPages)
    GtAltRegisterCallbackFunc = 0x41ED,     // 16877: 备用注册回调函数指针(InitObjectCallbackEntries)
    GtDereferenceObjectFunc = 0x41EA,       // 16874: 解除对象引用函数指针(InitObjectCallbackEntries)
    GtObjectTypeRefFunc = 0x4226,           // 16934: 对象类型引用函数指针(InitObjectCallbackEntries)
    GtCreateObjectTypeFunc = 0x4259,        // 16985: 创建对象类型函数指针(InitObjectCallbackEntries)
    GtCloseObjectTypeFunc = 0x425C,         // 16988: 关闭对象类型函数指针(InitObjectCallbackEntries)
    GtRegisterObjectCallbacksFunc = 0x4232, // 16946: 注册对象回调函数指针(InitObjectCallbackEntries)
    GtObjectTypeInfoPtr = 0x4265,           // 16997: 对象类型信息指针(InitObjectCallbackEntries)，用于比较验证

    GtMsrTableBaseOffset = 0x4402,          // 17410: MSR 表基址偏移(LookupMsrTableEntry)
    GtMsrTableBaseOffset2 = 0x4405,         // 17413: MSR 表基址偏移2(ParseMsrRelatedSections)
    GtMsrTableBaseOffset3 = 0x443B,         // 17467: MSR 表基址偏移3(ParseMsrTableFromSections)
    GtMsrEntryOffset1 = 0x86C,              // 2156: MSR 条目偏移1(ParseMsrRelatedSections/LookupMsrTableEntry)
    GtMsrEntryOffset2 = 0x86D,              // 2157: MSR 条目偏移2(LookupMsrTableEntry)
    GtMsrEntryOffset3 = 0x86E,              // 2158: MSR 条目偏移3(ParseMsrRelatedSections/LookupMsrTableEntry)
    GtMsrEntryOffset4 = 0x86F,              // 2159: MSR 条目偏移4(LookupMsrTableEntry)
    GtMsrEntryOffset5 = 0x870,              // 2160: MSR 条目偏移5(ParseMsrRelatedSections)
    GtMsrEntryOffset6 = 0x871,              // 2161: MSR 条目偏移6(ParseMsrRelatedSections)
    GtQueryObjectTypeAttr = 0x42F2,         // 17138: 查询对象类型属性函数指针(QueryObjectTypeInformation)
    GtObjectTypeQueryFunc = 0x42F8,         // 17144: 对象类型查询函数指针(QueryObjectTypeInformation)
    GtObjectTypeCheckFunc = 0x42F5,         // 17141: 对象类型检查函数指针(QueryObjectTypeInformation)
    GtObjectTypeWalkFunc = 0x90D,           // 2317: 对象类型遍历函数指针(QueryObjectTypeInformation)
    GtMsrPhase1Offset1 = 0x813,             // 2067: MSR 阶段1偏移1(ParseMsrTableFromSections)
    GtMsrPhase1Offset2 = 0x815,             // 2069: MSR 阶段1偏移2(ParseMsrTableFromSections)

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

    // ---- NtOpenProcess Hook 目标 (2313-2314) ----
    GtNtOpenProcessHookOffset = 0x909,   // 2313: NtOpenProcess Hook 目标偏移(HookSyscallNtOpenProcess)
    GtNtOpenProcessHookAddress = 0x90A,  // 2314: NtOpenProcess Hook 目标地址(HookSyscallNtOpenProcess)
    GtFileSystemExportTable = 0x8A8,         // 2216: 文件系统导出表地址(InitFileSystemExportTable)
    GtFileSystemExportTable32 = 0x8AA,        // 2218: 32位文件系统导出表地址(InitFileSystemExportTable)
    GtExReleaseFastMutex = 0x8AC,             // 2220: ExReleaseFastMutex 函数地址(InitDriverModuleParsing)
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
    GtObjectTypeMatchIndex = 0x878,           // 2168: 对象类型匹配索引(InitObjectCallbackEntries)，用于过滤对象类型条目
    GtNtosExportSectionOffset = 0x879,        // 2169: NT 导出节区偏移(Phase1/Phase2结果, ParseNtExportSectionsV2/Win10)
    GtNtosExportSectionVa = 0x87A,            // 2170: NT 导出节区 VA(Offset+Base, ParseNtExportSectionsV2/Win10)
    GtNtosExportSectionSize = 0x87B,          // 2171: NT 导出节区大小(ParseNtExportSectionsV2=0x800)
    GtNtosExportSectionOffset2 = 0x87C,       // 2172: NT 导出节区偏移2(Phase3结果, ParseNtExportSectionsV2/Win10)
    GtNtosExportSectionVa2 = 0x87D,           // 2173: NT 导出节区 VA2(Offset2+Base)
    GtKernelDataSectionOffset = 0x821,        // 2081: 内核数据节区偏移(FindKernelDataSectionOffsetWin8)
    GtOpenProcessTokenOffset = 0x33E,         // 830: NtOpenProcess Token 偏移(FindOpenProcessTokenOffset/Target)
    GtNtoskrnlPeScanBaseOffset = 0x436C,      // 17260: NT PE 扫描基址偏移(FindOpenProcessToken*)
    GtNtoskrnlPeScanBase = 0x43CC,            // 17356: NT PE 扫描基址(FindKernelDataSectionOffsetWin8)
    GtNtoskrnlPeScanBase2 = 0x43A8,           // 17320: NT PE 扫描基址2(FindKernelDataSectionOffsetWin7)
    GtNtoskrnlPeScanBase3 = 0x43C3,           // 17347: NT PE 扫描基址3(FindKernelDataSectionOffsetWin10)
    GtKernelDataSectionOffset2 = 0x824,       // 2084: 内核数据节区偏移2(FindKernelDataSectionOffsetWin10/Pair)
    GtKernelDataSectionOffset3 = 0x825,       // 2085: 内核数据节区偏移3(FindKernelDataSectionOffsetWin10/Pair)
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
    GtMiniFilterFormatNameReady = 0x8F0,      // 2288: MiniFilter 文件名格式化就绪标志(RegisterFormatNameCallback)
    GtMiniFilterFormatNameExReady = 0x8F1,    // 2289: MiniFilter 文件名格式化扩展就绪标志(RegisterFormatPathCallback)
    GtCommPortCallbackReady = 0x8F2,          // 2290: 通信端口回调注册标志(MiniFilterCommPortDisconnect)
    GtMiniFilterNotifyRoutineReady = 0x8F3,   // 2291: MiniFilter 通知例程注册标志(RegisterFilterUnloadCallback)

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
    GtEnumObjectTypeEntryFunc = 0x41BD,         // 16829: 枚举对象类型条目函数指针(QueryObjectTypeInformation)
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

    // ---- 扩展 EPROCESS 字段 (0x171-0x1CB, 偏移 0x100) ----
    GtEprocessExtField113 = 0x171,       // 369: 扩展 EPROCESS 字段 113
    GtEprocessExtField119 = 0x177,       // 375: 扩展 EPROCESS 字段 119(PE 镜像大小)
    GtEprocessExtField124 = 0x17C,       // 380: 扩展 EPROCESS 字段 124(PE 节偏移)
    GtEprocessExtField203 = 0x1CB,       // 459: 扩展 EPROCESS 字段 203(内核内存上下文)
    GtEprocessExtField812 = 0x42C,       // 1068: 扩展 EPROCESS 字段 812

    // ---- 上下文内存区域 (0x7C8-0x7D0) ----
    GtKernelMemoryContext = 0x7C8,         // 1992: 内核内存上下文(InitKernelMemoryContext)
    GtCallbackContextBase = 0x7CC,         // 1996: 回调上下文基址(InitCallbackFunctions)
    GtKernelMemoryContextReady = 0x7D0,    // 2000: 内核内存上下文就绪标志(InitKernelMemoryContext)

    // ---- 模块链表/类型标志 (2073-2078) ----
    GtMiniFilterListHead4 = 0x819,         // 2073: MiniFilter 列表头 4(InitMiniFilterDriver)
    GtMiniFilterListHead1 = 0x81A,         // 2074: MiniFilter 列表头 1(InitMiniFilterDriver)
    GtModuleListHead1 = 0x81B,             // 2075: 模块链表头 1(CmdEnumProcessModules)
    GtModuleListHead2 = 0x81C,             // 2076: 模块链表头 2(CmdEnumProcessModules)
    GtModuleTypeFlag1 = 0x81D,             // 2077: 模块类型标志 1
    GtModuleTypeFlag2 = 0x81E,             // 2078: 模块类型标志 2

    // ---- 函数指针表: 通用/内核函数 (16733-17529) ----
    // 注：以下条目由 InitKernelRoutineTable/InitSyscallNumberTable 初始化
    GtGetCurrentProcessFunc = 0x415D,              // 16733: IoGetCurrentProcess 函数指针
    GtSyscallHashInit0 = 0x415E,                   // 16734: 系统调用哈希表初始值 0
    GtSyscallHashInit1 = 0x4161,                   // 16737: 系统调用哈希表初始值 1
    GtSyscallHashInit2 = 0x4164,                   // 16740: 系统调用哈希表初始值 2
    GtSyscallHashInit3 = 0x4167,                   // 16743: 系统调用哈希表初始值 3
    GtSyscallHashInit4 = 0x416A,                   // 16746: 系统调用哈希表初始值 4
    GtSyscallHashInit5 = 0x416D,                   // 16749: 系统调用哈希表初始值 5
    GtSyscallHashInit6 = 0x4170,                   // 16752: 系统调用哈希表初始值 6
    GtSyscallHashInit7 = 0x4173,                   // 16755: 系统调用哈希表初始值 7
    GtSyscallHashInit8 = 0x4176,                   // 16758: 系统调用哈希表初始值 8
    GtSyscallHashInit9 = 0x4179,                   // 16761: 系统调用哈希表初始值 9
    GtSyscallHashInit10 = 0x417C,                  // 16764: 系统调用哈希表初始值 10
    GtSyscallHashInit11 = 0x417F,                  // 16767: 系统调用哈希表初始值 11
    GtSyscallHashInit12 = 0x4182,                  // 16770: 系统调用哈希表初始值 12
    GtSyscallHashInit13 = 0x4185,                  // 16773: 系统调用哈希表初始值 13
    GtSyscallHashInit14 = 0x4188,                  // 16776: 系统调用哈希表初始值 14
    GtSyscallHashInit15 = 0x418B,                  // 16779: 系统调用哈希表初始值 15
    GtSyscallHashInit16 = 0x418E,                  // 16782: 系统调用哈希表初始值 16
    GtSyscallHashInit17 = 0x4191,                  // 16785: 系统调用哈希表初始值 17
    GtSyscallHashInit18 = 0x4194,                  // 16788: 系统调用哈希表初始值 18
    GtSyscallHashInit19 = 0x4197,                  // 16791: 系统调用哈希表初始值 19
    GtSyscallHashInit20 = 0x419A,                  // 16794: 系统调用哈希表初始值 20
    GtSyscallHashInit21 = 0x419D,                  // 16797: 系统调用哈希表初始值 21
    GtSyscallHashInit22 = 0x41A0,                  // 16800: 系统调用哈希表初始值 22
    GtSyscallHashInit23 = 0x41A3,                  // 16803: 系统调用哈希表初始值 23
    GtSyscallHashInit24 = 0x41A6,                  // 16806: 系统调用哈希表初始值 24
    GtSyscallHashInit25 = 0x41A9,                  // 16809: 系统调用哈希表初始值 25
    GtSyscallHashInit26 = 0x41AC,                  // 16812: 系统调用哈希表初始值 26
    GtSyscallHashInit27 = 0x41AF,                  // 16815: 系统调用哈希表初始值 27
    GtSyscallHashInit28 = 0x41B2,                  // 16818: 系统调用哈希表初始值 28
    GtSyscallHashInit29 = 0x41B5,                  // 16821: 系统调用哈希表初始值 29
    GtSyscallHashInit30 = 0x41B8,                  // 16824: 系统调用哈希表初始值 30
    GtSyscallHashInit31 = 0x41BB,                  // 16827: 系统调用哈希表初始值 31
    GtSyscallHashInit32 = 0x41BE,                  // 16830: 系统调用哈希表初始值 32
    GtSyscallHashInit33 = 0x41C1,                  // 16833: 系统调用哈希表初始值 33
    GtSyscallHashInit34 = 0x41C4,                  // 16836: 系统调用哈希表初始值 34
    GtSyscallHashInit35 = 0x41C7,                  // 16839: 系统调用哈希表初始值 35
    GtSyscallHashInit36 = 0x41CA,                  // 16842: 系统调用哈希表初始值 36
    GtSyscallHashInit37 = 0x41CD,                  // 16845: 系统调用哈希表初始值 37
    GtSyscallHashInit38 = 0x41D0,                  // 16848: 系统调用哈希表初始值 38
    GtSyscallHashInit39 = 0x41D3,                  // 16851: 系统调用哈希表初始值 39
    GtSyscallHashInit40 = 0x41D6,                  // 16854: 系统调用哈希表初始值 40
    GtSyscallHashInit41 = 0x41D9,                  // 16857: 系统调用哈希表初始值 41
    GtSyscallHashInit42 = 0x41DC,                  // 16860: 系统调用哈希表初始值 42
    GtSyscallHashInit43 = 0x41DF,                  // 16863: 系统调用哈希表初始值 43
    GtSyscallHashInit44 = 0x41E2,                  // 16866: 系统调用哈希表初始值 44
    GtSyscallHashInit45 = 0x41E5,                  // 16869: 系统调用哈希表初始值 45
    GtSyscallHashInit46 = 0x41E8,                  // 16872: 系统调用哈希表初始值 46
    GtSyscallHashInit47 = 0x41EB,                  // 16875: 系统调用哈希表初始值 47
    GtSyscallHashInit48 = 0x41EE,                  // 16878: 系统调用哈希表初始值 48
    GtSyscallHashInit49 = 0x41F1,                  // 16881: 系统调用哈希表初始值 49
    GtSyscallHashInit50 = 0x41F4,                  // 16884: 系统调用哈希表初始值 50
    GtSyscallHashInit51 = 0x41F7,                  // 16887: 系统调用哈希表初始值 51
    GtSyscallHashInit52 = 0x41FA,                  // 16890: 系统调用哈希表初始值 52
    GtSyscallHashInit53 = 0x41FD,                  // 16893: 系统调用哈希表初始值 53
    GtSyscallHashInit54 = 0x4200,                  // 16896: 系统调用哈希表初始值 54
    GtSyscallHashInit55 = 0x4203,                  // 16899: 系统调用哈希表初始值 55
    GtSyscallHashInit56 = 0x4206,                  // 16902: 系统调用哈希表初始值 56
    GtSyscallHashInit57 = 0x4209,                  // 16905: 系统调用哈希表初始值 57
    GtSyscallHashInit58 = 0x420C,                  // 16908: 系统调用哈希表初始值 58
    GtSyscallHashInit59 = 0x420F,                  // 16911: 系统调用哈希表初始值 59
    GtSyscallHashInit60 = 0x4212,                  // 16914: 系统调用哈希表初始值 60
    GtSyscallHashInit61 = 0x4215,                  // 16917: 系统调用哈希表初始值 61
    GtSyscallHashInit62 = 0x4218,                  // 16920: 系统调用哈希表初始值 62
    GtSyscallHashInit63 = 0x421B,                  // 16923: 系统调用哈希表初始值 63
    GtSyscallHashInit64 = 0x421E,                  // 16926: 系统调用哈希表初始值 64
    GtSyscallHashInit65 = 0x4221,                  // 16929: 系统调用哈希表初始值 65
    GtSyscallHashInit66 = 0x4224,                  // 16932: 系统调用哈希表初始值 66
    GtSyscallHashInit67 = 0x4227,                  // 16935: 系统调用哈希表初始值 67
    GtSyscallHashInit68 = 0x422A,                  // 16938: 系统调用哈希表初始值 68
    GtSyscallHashInit69 = 0x422D,                  // 16941: 系统调用哈希表初始值 69
    GtSyscallHashInit70 = 0x4230,                  // 16944: 系统调用哈希表初始值 70
    GtSyscallHashInit71 = 0x4233,                  // 16947: 系统调用哈希表初始值 71
    GtSyscallHashInit72 = 0x4236,                  // 16950: 系统调用哈希表初始值 72
    GtSyscallHashInit73 = 0x4239,                  // 16953: 系统调用哈希表初始值 73
    GtSyscallHashInit74 = 0x423C,                  // 16956: 系统调用哈希表初始值 74
    GtSyscallHashInit75 = 0x423F,                  // 16959: 系统调用哈希表初始值 75
    GtSyscallHashInit76 = 0x4242,                  // 16962: 系统调用哈希表初始值 76
    GtSyscallHashInit77 = 0x4245,                  // 16965: 系统调用哈希表初始值 77
    GtSyscallHashInit78 = 0x4248,                  // 16968: 系统调用哈希表初始值 78
    GtSyscallHashInit79 = 0x424B,                  // 16971: 系统调用哈希表初始值 79
    GtSyscallHashInit80 = 0x424E,                  // 16974: 系统调用哈希表初始值 80
    GtSyscallHashInit81 = 0x4251,                  // 16977: 系统调用哈希表初始值 81
    GtSyscallHashInit82 = 0x4254,                  // 16980: 系统调用哈希表初始值 82
    GtSyscallHashInit83 = 0x4257,                  // 16983: 系统调用哈希表初始值 83
    GtSyscallHashInit84 = 0x425A,                  // 16986: 系统调用哈希表初始值 84
    GtSyscallHashInit85 = 0x425D,                  // 16989: 系统调用哈希表初始值 85
    GtSyscallHashInit86 = 0x4260,                  // 16992: 系统调用哈希表初始值 86
    GtSyscallHashInit87 = 0x4263,                  // 16995: 系统调用哈希表初始值 87
    GtSyscallHashInit88 = 0x4266,                  // 16998: 系统调用哈希表初始值 88
    GtSyscallHashInit89 = 0x4269,                  // 17001: 系统调用哈希表初始值 89
    GtSyscallHashInit90 = 0x426C,                  // 17004: 系统调用哈希表初始值 90
    GtSyscallHashInit91 = 0x426F,                  // 17007: 系统调用哈希表初始值 91
    GtSyscallHashInit92 = 0x4272,                  // 17010: 系统调用哈希表初始值 92
    GtSyscallHashInit93 = 0x4275,                  // 17013: 系统调用哈希表初始值 93
    GtSyscallHashInit94 = 0x4278,                  // 17016: 系统调用哈希表初始值 94
    GtSyscallHashInit95 = 0x427B,                  // 17019: 系统调用哈希表初始值 95
    GtSyscallHashInit96 = 0x427E,                  // 17022: 系统调用哈希表初始值 96
    GtSyscallHashInit97 = 0x4281,                  // 17025: 系统调用哈希表初始值 97
    GtSyscallHashInit98 = 0x4284,                  // 17028: 系统调用哈希表初始值 98
    GtSyscallHashInit99 = 0x4287,                  // 17031: 系统调用哈希表初始值 99
    GtSyscallHashInit100 = 0x428A,                 // 17034: 系统调用哈希表初始值 100
    GtSyscallHashInit101 = 0x428D,                 // 17037: 系统调用哈希表初始值 101
    GtSyscallHashInit102 = 0x4290,                 // 17040: 系统调用哈希表初始值 102
    GtSyscallHashInit103 = 0x4293,                 // 17043: 系统调用哈希表初始值 103
    GtSyscallHashInit104 = 0x4296,                 // 17046: 系统调用哈希表初始值 104
    GtSyscallHashInit105 = 0x4299,                 // 17049: 系统调用哈希表初始值 105
    GtSyscallHashInit106 = 0x429C,                 // 17052: 系统调用哈希表初始值 106
    GtSyscallHashInit107 = 0x429F,                 // 17055: 系统调用哈希表初始值 107
    GtSyscallHashInit108 = 0x42A2,                 // 17058: 系统调用哈希表初始值 108
    GtSyscallHashInit109 = 0x42A5,                 // 17061: 系统调用哈希表初始值 109
    GtSyscallHashInit110 = 0x42A8,                 // 17064: 系统调用哈希表初始值 110
    GtSyscallHashInit111 = 0x42AB,                 // 17067: 系统调用哈希表初始值 111
    GtSyscallHashInit112 = 0x42AE,                 // 17070: 系统调用哈希表初始值 112
    GtSyscallHashInit113 = 0x42B1,                 // 17073: 系统调用哈希表初始值 113
    GtSyscallHashInit114 = 0x42B4,                 // 17076: 系统调用哈希表初始值 114
    GtSyscallHashInit115 = 0x42B7,                 // 17079: 系统调用哈希表初始值 115
    GtSyscallHashInit116 = 0x42BA,                 // 17082: 系统调用哈希表初始值 116
    GtSyscallHashInit117 = 0x42BD,                 // 17085: 系统调用哈希表初始值 117
    GtSyscallHashInit118 = 0x42C0,                 // 17088: 系统调用哈希表初始值 118
    GtSyscallHashInit119 = 0x42C3,                 // 17091: 系统调用哈希表初始值 119
    GtSyscallHashInit120 = 0x42C6,                 // 17094: 系统调用哈希表初始值 120
    GtSyscallHashInit121 = 0x42C9,                 // 17097: 系统调用哈希表初始值 121
    GtSyscallHashInit122 = 0x42CC,                 // 17100: 系统调用哈希表初始值 122
    GtSyscallHashInit123 = 0x42CF,                 // 17103: 系统调用哈希表初始值 123
    GtSyscallHashInit124 = 0x42D2,                 // 17106: 系统调用哈希表初始值 124
    GtSyscallHashInit125 = 0x42D5,                 // 17109: 系统调用哈希表初始值 125
    GtSyscallHashInit126 = 0x42D8,                 // 17112: 系统调用哈希表初始值 126
    GtSyscallHashInit127 = 0x42DB,                 // 17115: 系统调用哈希表初始值 127
    GtSyscallHashInit128 = 0x42DE,                 // 17118: 系统调用哈希表初始值 128
    GtSyscallHashInit129 = 0x42E1,                 // 17121: 系统调用哈希表初始值 129
    GtSyscallHashInit130 = 0x42E4,                 // 17124: 系统调用哈希表初始值 130
    GtSyscallHashInit131 = 0x42E7,                 // 17127: 系统调用哈希表初始值 131
    GtSyscallHashInit132 = 0x42EA,                 // 17130: 系统调用哈希表初始值 132
    GtSyscallHashInit133 = 0x42ED,                 // 17133: 系统调用哈希表初始值 133
    GtSyscallHashInit134 = 0x42F0,                 // 17136: 系统调用哈希表初始值 134
    GtSyscallHashInit135 = 0x42F3,                 // 17139: 系统调用哈希表初始值 135
    GtSyscallHashInit136 = 0x42F6,                 // 17142: 系统调用哈希表初始值 136
    GtSyscallHashInit137 = 0x42F9,                 // 17145: 系统调用哈希表初始值 137
    GtSyscallHashInit138 = 0x42FC,                 // 17148: 系统调用哈希表初始值 138
    GtSyscallHashInit139 = 0x42FF,                 // 17151: 系统调用哈希表初始值 139
    GtSyscallHashInit140 = 0x4302,                 // 17154: 系统调用哈希表初始值 140
    GtSyscallHashInit141 = 0x4305,                 // 17157: 系统调用哈希表初始值 141
    GtSyscallHashInit142 = 0x4308,                 // 17160: 系统调用哈希表初始值 142
    GtSyscallHashInit143 = 0x430B,                 // 17163: 系统调用哈希表初始值 143
    GtSyscallHashInit144 = 0x430E,                 // 17166: 系统调用哈希表初始值 144
    GtSyscallHashInit145 = 0x4311,                 // 17169: 系统调用哈希表初始值 145
    GtSyscallHashInit146 = 0x4314,                 // 17172: 系统调用哈希表初始值 146
    GtSyscallHashInit147 = 0x4317,                 // 17175: 系统调用哈希表初始值 147
    GtSyscallHashInit148 = 0x431A,                 // 17178: 系统调用哈希表初始值 148
    GtSyscallHashInit149 = 0x431D,                 // 17181: 系统调用哈希表初始值 149
    GtSyscallHashInit150 = 0x4320,                 // 17184: 系统调用哈希表初始值 150
    GtSyscallHashInit151 = 0x4323,                 // 17187: 系统调用哈希表初始值 151
    GtSyscallHashInit152 = 0x4326,                 // 17190: 系统调用哈希表初始值 152
    GtSyscallHashInit153 = 0x4329,                 // 17193: 系统调用哈希表初始值 153
    GtSyscallHashInit154 = 0x432C,                 // 17196: 系统调用哈希表初始值 154
    GtSyscallHashInit155 = 0x432F,                 // 17199: 系统调用哈希表初始值 155
    GtSyscallHashInit156 = 0x4332,                 // 17202: 系统调用哈希表初始值 156
    GtSyscallHashInit157 = 0x4335,                 // 17205: 系统调用哈希表初始值 157
    GtSyscallHashInit158 = 0x4338,                 // 17208: 系统调用哈希表初始值 158
    GtSyscallHashInit159 = 0x433B,                 // 17211: 系统调用哈希表初始值 159
    GtSyscallHashInit160 = 0x433E,                 // 17214: 系统调用哈希表初始值 160
    GtSyscallHashInit161 = 0x4341,                 // 17217: 系统调用哈希表初始值 161
    GtSyscallHashInit162 = 0x4344,                 // 17220: 系统调用哈希表初始值 162
    GtSyscallHashInit163 = 0x4347,                 // 17223: 系统调用哈希表初始值 163
    GtSyscallHashInit164 = 0x434D,                 // 17229: 系统调用哈希表初始值 164
    GtSyscallHashInit165 = 0x4350,                 // 17232: 系统调用哈希表初始值 165
    GtSyscallHashInit166 = 0x4353,                 // 17235: 系统调用哈希表初始值 166
    GtSyscallHashInit167 = 0x4356,                 // 17238: 系统调用哈希表初始值 167
    GtSyscallHashInit168 = 0x4359,                 // 17241: 系统调用哈希表初始值 168
    GtSyscallHashInit169 = 0x435C,                 // 17244: 系统调用哈希表初始值 169
    GtSyscallHashInit170 = 0x435F,                 // 17247: 系统调用哈希表初始值 170
    GtSyscallHashInit171 = 0x4362,                 // 17250: 系统调用哈希表初始值 171
    GtSyscallHashInit172 = 0x4365,                 // 17253: 系统调用哈希表初始值 172
    GtSyscallHashInit173 = 0x4368,                 // 17256: 系统调用哈希表初始值 173
    GtSyscallHashInit174 = 0x436B,                 // 17259: 系统调用哈希表初始值 174
    GtSyscallHashInit175 = 0x436E,                 // 17262: 系统调用哈希表初始值 175
    GtSyscallHashInit176 = 0x4371,                 // 17265: 系统调用哈希表初始值 176
    GtSyscallHashInit177 = 0x4374,                 // 17268: 系统调用哈希表初始值 177
    GtSyscallHashInit178 = 0x4377,                 // 17271: 系统调用哈希表初始值 178
    GtSyscallHashInit179 = 0x437A,                 // 17274: 系统调用哈希表初始值 179
    GtSyscallHashInit180 = 0x437D,                 // 17277: 系统调用哈希表初始值 180
    GtSyscallHashInit181 = 0x4380,                 // 17280: 系统调用哈希表初始值 181
    GtSyscallHashInit182 = 0x4383,                 // 17283: 系统调用哈希表初始值 182
    GtSyscallHashInit183 = 0x4386,                 // 17286: 系统调用哈希表初始值 183
    GtSyscallHashInit184 = 0x4389,                 // 17289: 系统调用哈希表初始值 184
    GtSyscallHashInit185 = 0x438C,                 // 17292: 系统调用哈希表初始值 185
    GtSyscallHashInit186 = 0x438F,                 // 17295: 系统调用哈希表初始值 186
    GtSyscallHashInit187 = 0x4392,                 // 17298: 系统调用哈希表初始值 187
    GtSyscallHashInit188 = 0x4395,                 // 17301: 系统调用哈希表初始值 188
    GtSyscallHashInit189 = 0x4398,                 // 17304: 系统调用哈希表初始值 189
    GtSyscallHashInit190 = 0x439B,                 // 17307: 系统调用哈希表初始值 190
    GtSyscallHashInit191 = 0x439E,                 // 17310: 系统调用哈希表初始值 191
    GtSyscallHashInit192 = 0x43A1,                 // 17313: 系统调用哈希表初始值 192
    GtSyscallHashInit193 = 0x43A4,                 // 17316: 系统调用哈希表初始值 193
    GtSyscallHashInit194 = 0x43A7,                 // 17319: 系统调用哈希表初始值 194
    GtSyscallHashInit195 = 0x43AA,                 // 17322: 系统调用哈希表初始值 195
    GtSyscallHashInit196 = 0x43AD,                 // 17325: 系统调用哈希表初始值 196
    GtSyscallHashInit197 = 0x43B0,                 // 17328: 系统调用哈希表初始值 197
    GtSyscallHashInit198 = 0x43B3,                 // 17331: 系统调用哈希表初始值 198
    GtSyscallHashInit199 = 0x43B6,                 // 17334: 系统调用哈希表初始值 199
    GtSyscallHashInit200 = 0x43B9,                 // 17337: 系统调用哈希表初始值 200
    GtSyscallHashInit201 = 0x43BC,                 // 17340: 系统调用哈希表初始值 201
    GtSyscallHashInit202 = 0x43BF,                 // 17343: 系统调用哈希表初始值 202
    GtSyscallHashInit203 = 0x43C2,                 // 17346: 系统调用哈希表初始值 203
    GtSyscallHashInit204 = 0x43C5,                 // 17349: 系统调用哈希表初始值 204
    GtSyscallHashInit205 = 0x43C8,                 // 17352: 系统调用哈希表初始值 205
    GtSyscallHashInit206 = 0x43CB,                 // 17355: 系统调用哈希表初始值 206
    GtSyscallHashInit207 = 0x43CE,                 // 17358: 系统调用哈希表初始值 207
    GtSyscallHashInit208 = 0x43D1,                 // 17361: 系统调用哈希表初始值 208
    GtSyscallHashInit209 = 0x43D4,                 // 17364: 系统调用哈希表初始值 209
    GtSyscallHashInit210 = 0x43D7,                 // 17367: 系统调用哈希表初始值 210
    GtSyscallHashInit211 = 0x43DA,                 // 17370: 系统调用哈希表初始值 211
    GtSyscallHashInit212 = 0x43DD,                 // 17373: 系统调用哈希表初始值 212
    GtSyscallHashInit213 = 0x43E0,                 // 17376: 系统调用哈希表初始值 213
    GtSyscallHashInit214 = 0x43E3,                 // 17379: 系统调用哈希表初始值 214
    GtSyscallHashInit215 = 0x43E6,                 // 17382: 系统调用哈希表初始值 215
    GtSyscallHashInit216 = 0x43E9,                 // 17385: 系统调用哈希表初始值 216
    GtSyscallHashInit217 = 0x43EC,                 // 17388: 系统调用哈希表初始值 217
    GtSyscallHashInit218 = 0x43EF,                 // 17391: 系统调用哈希表初始值 218
    GtSyscallHashInit219 = 0x43F2,                 // 17394: 系统调用哈希表初始值 219
    GtSyscallHashInit220 = 0x43F5,                 // 17397: 系统调用哈希表初始值 220
    GtSyscallHashInit221 = 0x43F8,                 // 17400: 系统调用哈希表初始值 221
    GtSyscallHashInit222 = 0x43FB,                 // 17403: 系统调用哈希表初始值 222
    GtSyscallHashInit223 = 0x43FE,                 // 17406: 系统调用哈希表初始值 223
    GtSyscallHashInit224 = 0x4401,                 // 17409: 系统调用哈希表初始值 224
    GtSyscallHashInit225 = 0x4404,                 // 17412: 系统调用哈希表初始值 225
    GtSyscallHashInit226 = 0x4407,                 // 17415: 系统调用哈希表初始值 226
    GtSyscallHashInit227 = 0x440A,                 // 17418: 系统调用哈希表初始值 227
    GtSyscallHashInit228 = 0x440D,                 // 17421: 系统调用哈希表初始值 228
    GtSyscallHashInit229 = 0x4410,                 // 17424: 系统调用哈希表初始值 229
    GtSyscallHashInit230 = 0x4413,                 // 17427: 系统调用哈希表初始值 230
    GtSyscallHashInit231 = 0x4416,                 // 17430: 系统调用哈希表初始值 231
    GtSyscallHashInit232 = 0x4419,                 // 17433: 系统调用哈希表初始值 232
    GtSyscallHashInit233 = 0x441C,                 // 17436: 系统调用哈希表初始值 233
    GtSyscallHashInit234 = 0x441F,                 // 17439: 系统调用哈希表初始值 234
    GtSyscallHashInit235 = 0x4422,                 // 17442: 系统调用哈希表初始值 235
    GtSyscallHashInit236 = 0x4425,                 // 17445: 系统调用哈希表初始值 236
    GtSyscallHashInit237 = 0x4428,                 // 17448: 系统调用哈希表初始值 237
    GtSyscallHashInit238 = 0x442B,                 // 17451: 系统调用哈希表初始值 238
    GtSyscallHashInit239 = 0x442E,                 // 17454: 系统调用哈希表初始值 239
    GtSyscallHashInit240 = 0x4431,                 // 17457: 系统调用哈希表初始值 240
    GtSyscallHashInit241 = 0x4434,                 // 17460: 系统调用哈希表初始值 241
    GtSyscallHashInit242 = 0x4437,                 // 17463: 系统调用哈希表初始值 242
    GtSyscallHashInit243 = 0x443A,                 // 17466: 系统调用哈希表初始值 243
    GtSyscallHashInit244 = 0x443D,                 // 17469: 系统调用哈希表初始值 244
    GtSyscallHashInit245 = 0x4440,                 // 17472: 系统调用哈希表初始值 245
    GtSyscallHashInit246 = 0x4443,                 // 17475: 系统调用哈希表初始值 246
    GtSyscallHashInit247 = 0x4446,                 // 17478: 系统调用哈希表初始值 247
    GtSyscallHashInit248 = 0x4449,                 // 17481: 系统调用哈希表初始值 248
    GtSyscallHashInit249 = 0x444C,                 // 17484: 系统调用哈希表初始值 249
    GtSyscallHashInit250 = 0x444F,                 // 17487: 系统调用哈希表初始值 250
    GtSyscallHashInit251 = 0x4452,                 // 17490: 系统调用哈希表初始值 251
    GtSyscallHashInit252 = 0x4455,                 // 17493: 系统调用哈希表初始值 252
    GtSyscallHashInit253 = 0x4458,                 // 17496: 系统调用哈希表初始值 253
    GtSyscallHashInit254 = 0x445B,                 // 17499: 系统调用哈希表初始值 254
    GtSyscallHashInit255 = 0x445E,                 // 17502: 系统调用哈希表初始值 255
    GtSyscallHashInit256 = 0x4461,                 // 17505: 系统调用哈希表初始值 256
    GtSyscallHashInit257 = 0x4464,                 // 17508: 系统调用哈希表初始值 257
    GtSyscallHashInit258 = 0x4467,                 // 17511: 系统调用哈希表初始值 258
    GtSyscallHashInit259 = 0x446A,                 // 17514: 系统调用哈希表初始值 259
    GtSyscallHashInit260 = 0x446D,                 // 17517: 系统调用哈希表初始值 260
    GtSyscallHashInit261 = 0x4470,                 // 17520: 系统调用哈希表初始值 261
    GtSyscallHashInit262 = 0x4473,                 // 17523: 系统调用哈希表初始值 262
    GtSyscallHashInit263 = 0x4476,                 // 17526: 系统调用哈希表初始值 263

    // ---- 函数指针/PE 节区偏移 (0x4244-0x4477) ----
    GtIrpDispatchFunc = 0x4244,                      // 16964: IRP 分发函数指针(Utility)
    GtHandleTablePeSectionOffset = 0x42B8,           // 17080: 句柄表 PE 节区偏移(EnumProcessHandleTable)
    GtMiniFilterSectionOffset1 = 0x42D0,             // 17104: Minifilter PE 节区偏移 1
    GtDiskIoIrpFunc = 0x4328,                        // 17192: 磁盘 IO IRP 函数指针(Utility)
    GtDiskIoCloseHandleFunc = 0x432B,                // 17195: 磁盘 IO 关闭句柄函数指针(Utility)
    GtObjectTypeUnknownFunc = 0x4340,                // 17216: 对象类型未知函数指针(ObjectMgmt)
    GtMiniFilterSectionTarget1 = 0x435D,             // 17245: Minifilter 节区扫描目标 1
    GtModuleListSectionOffset1 = 0x4420,             // 17440: 模块链表 PE 节区偏移 1(ParseNtSectionsForModuleList1)
    GtModuleListSectionOffset2 = 0x4414,             // 17428: 模块链表 PE 节区偏移 2(ParseNtSectionsForModuleList1)
    GtModuleListMatchOffset1 = 0x4477,               // 17527: 模块链表匹配偏移 1(ParseNtSectionsForModuleList1)
    GtModuleListSectionOffset3 = 0x4417,             // 17431: 模块链表 PE 节区偏移 3(ParseNtSectionsForModuleList2)
    GtMiniFilterSectionTarget2 = 0x4426,             // 17446: Minifilter 节区扫描目标 2
    GtMiniFilterSectionTarget3 = 0x4465,             // 17509: Minifilter 节区扫描目标 3

    // ---- 函数指针表: 重复使用/覆盖条目 (由 InitSyscallNumberTable 写入哈希值，后被函数指针覆盖) ----
    // 注：以下索引先由 InitSyscallNumberTable 写入哈希值，后由各 Init 函数覆盖为实际函数指针
    GtQueryObjectNameFunc2 = 0x4163,                     // 16739: ObQueryNameString 函数指针 2(ModuleMgmt)
    GtObjectTypeQueryFunc2 = 0x4166,                     // 16742: 对象类型查询函数指针 2(HandleMgmt/ObjectMgmt)
    GtKernelDataPtr = 0x416C,                            // 16748: 内核数据指针(MemoryOps/ProcessMgmt/Protocol)
    GtProcessValidateFunc = 0x4170,                      // 16752: 进程验证函数指针(ProcessMgmt)
    GtMiniFilterResultFlag = 0x4174,                     // 16756: Minifilter 结果标志(MinifilterPostWrite)
    GtMiniFilterSectionIdx2 = 0x417D,                    // 16765: Minifilter 节区索引 2
    GtProcessObjectSectionIdx = 0x4186,                  // 16774: 进程对象节区索引(ValidateKernelObject)
    GtMiniFilterSectionIdx3 = 0x418A,                    // 16778: Minifilter 节区索引 3
    GtHandleTypeTableCount = 0x41A0,                     // 16800: 句柄类型表计数(HandleMgmt)
    GtMiniFilterFormatCallback = 0x41A8,                 // 16808: Minifilter 格式化回调函数指针
    GtProcessContextDataPtr = 0x41C7,                    // 16839: 进程上下文数据指针(ProcessMgmt/Protocol)
    GtMemoryContextDataPtr = 0x41D6,                     // 16854: 内存上下文数据指针(MemoryOps)
    GtQuerySystemInfoFunc = 0x41DE,                      // 16862: NtQuerySystemInformation 函数指针(HandleMgmt/ModuleMgmt)
    GtValidateObjectFunc = 0x41E1,                       // 16865: 对象验证函数指针(HandleMgmt/ModuleMgmt)
    GtZwQuerySystemInfoFunc = 0x41F3,                    // 16883: ZwQuerySystemInformation 函数指针(DriverEntry/Protocol)
    GtMemoryAtomicFuncParam = 0x420D,                    // 16909: 内存原子操作函数参数(MemoryOps)
    GtQueryVolumeFunc = 0x420E,                          // 16910: 查询卷函数指针(ObjectMgmt/SystemInfo)
    GtMapViewFunc = 0x4210,                              // 16912: 映射视图函数指针(SystemInfo)
    GtAtomicOpFunc = 0x4214,                             // 16916: 原子操作函数指针(MemoryOps)
    GtRefCountFunc = 0x4230,                             // 16944: 引用计数函数指针(MemoryOps)
    GtObjectTypeFlag = 0x4240,                           // 16960: 对象类型标志/参数(ProcessMgmt/MemoryOps)

    // ---- SSDT 函数名哈希表详细条目 (InitSyscallNumberTable 写入，只写不读) ----
    // 这些是 SSDT 函数名查找用的预计算哈希值，仅由 InitSyscallNumberTable 写入，不被读取
    GtSyscallHash16741 = 0x4165,  // 16741: SSDT 哈希值 0xFC7D413E
    GtSyscallHash16753 = 0x4171,  // 16753: SSDT 哈希值 0xACD04BF3
    GtSyscallHash16760 = 0x4178,  // 16760: SSDT 哈希值 0xA00702AA
    GtSyscallHash16762 = 0x417A,  // 16762: SSDT 哈希值 0xECB7091E
    GtSyscallHash16763 = 0x417B,  // 16763: SSDT 哈希值 0xBEA5E2EF
    GtSyscallHash16768 = 0x4180,  // 16768: SSDT 哈希值 0xDA519BA5
    GtSyscallHash16772 = 0x4184,  // 16772: SSDT 哈希值 0xF91CE2EB
    GtSyscallHash16780 = 0x418C,  // 16780: SSDT 哈希值 0xCE61BFBB
    GtSyscallHash16781 = 0x418D,  // 16781: SSDT 哈希值 0xEA6C46EF
    GtSyscallHash16783 = 0x418F,  // 16783: SSDT 哈希值 0xEB9830DD
    GtSyscallHash16789 = 0x4195,  // 16789: SSDT 哈希值 0xD52ADA4F
    GtSyscallHash16790 = 0x4196,  // 16790: SSDT 哈希值 0xD849C233
    GtSyscallHash16796 = 0x419C,  // 16796: SSDT 哈希值 0x8B02D8A2
    GtSyscallHash16799 = 0x419F,  // 16799: SSDT 哈希值 0xC9422A37
    GtSyscallHash16801 = 0x41A1,  // 16801: SSDT 哈希值 0x9FF33383
    GtSyscallHash16804 = 0x41A4,  // 16804: SSDT 哈希值 0x9848CEAB
    GtSyscallHash16805 = 0x41A5,  // 16805: SSDT 哈希值 0xFE213B95
    GtSyscallHash16807 = 0x41A7,  // 16807: SSDT 哈希值 0xFC040A43
    GtSyscallHash16811 = 0x41AB,  // 16811: SSDT 哈希值 0xFCD830C4
    GtSyscallHash16814 = 0x41AE,  // 16814: SSDT 哈希值 0x99A62677
    GtSyscallHash16819 = 0x41B3,  // 16819: SSDT 哈希值 0xBD01010E
    GtSyscallHash16820 = 0x41B4,  // 16820: SSDT 哈希值 0xA9724E39
    GtSyscallHash16822 = 0x41B6,  // 16822: SSDT 哈希值 0xCFA77882
    GtSyscallHash16832 = 0x41C0,  // 16832: SSDT 哈希值 0xBB1A0857
    GtSyscallHash16835 = 0x41C3,  // 16835: SSDT 哈希值 0xC28E0472
    GtSyscallHash16837 = 0x41C5,  // 16837: SSDT 哈希值 0xCA66CD85
    GtSyscallHash16840 = 0x41C8,  // 16840: SSDT 哈希值 0xFDF9BD5E
    GtSyscallHash16841 = 0x41C9,  // 16841: SSDT 哈希值 0xA733E150
    GtSyscallHash16844 = 0x41CC,  // 16844: SSDT 哈希值 0xE8E050DB
    GtSyscallHash16846 = 0x41CE,  // 16846: SSDT 哈希值 0x969C12BC
    GtSyscallHash16847 = 0x41CF,  // 16847: SSDT 哈希值 0x9BED0DAF
    GtSyscallHash16852 = 0x41D4,  // 16852: SSDT 哈希值 0x8E429199
    GtSyscallHash16855 = 0x41D7,  // 16855: SSDT 哈希值 0xE1E1D2DA
    GtSyscallHash16856 = 0x41D8,  // 16856: SSDT 哈希值 0x8DB049F3
    GtSyscallHash16864 = 0x41E0,  // 16864: SSDT 哈希值 0x992020AA
    GtSyscallHash16867 = 0x41E3,  // 16867: SSDT 哈希值 0xB585B522
    GtSyscallHash16870 = 0x41E6,  // 16870: SSDT 哈希值 0xA608DEB3
    GtSyscallHash16879 = 0x41EF,  // 16879: SSDT 哈希值 0xFDED2BE9
    GtSyscallHash16880 = 0x41F0,  // 16880: SSDT 哈希值 0xA01EE269
    GtSyscallHash16885 = 0x41F5,  // 16885: SSDT 哈希值 0xE39F0C9C
    GtSyscallHash16886 = 0x41F6,  // 16886: SSDT 哈希值 0xEDDFEBDC
    GtSyscallHash16889 = 0x41F9,  // 16889: SSDT 哈希值 0xDCE054DA
    GtSyscallHash16891 = 0x41FB,  // 16891: SSDT 哈希值 0xC5F7E0A4
    GtSyscallHash16892 = 0x41FC,  // 16892: SSDT 哈希值 0x890EDED3
    GtSyscallHash16894 = 0x41FE,  // 16894: SSDT 哈希值 0xA23A41C8
    GtSyscallHash16895 = 0x41FF,  // 16895: SSDT 哈希值 0xCB14C8BC
    GtSyscallHash16898 = 0x4202,  // 16898: SSDT 哈希值 0x9759743F
    GtSyscallHash16900 = 0x4204,  // 16900: SSDT 哈希值 0xDC8DDD66
    GtSyscallHash16903 = 0x4207,  // 16903: SSDT 哈希值 0xE4F18F9E
    GtSyscallHash16907 = 0x420B,  // 16907: SSDT 哈希值 0x9827428E
    GtSyscallHash16915 = 0x4213,  // 16915: SSDT 哈希值 0xAA7C5725
    GtSyscallHash16918 = 0x4216,  // 16918: SSDT 哈希值 0x8D50A0AE
    GtSyscallHash16919 = 0x4217,  // 16919: SSDT 哈希值 0x84038C18
    GtSyscallHash16930 = 0x4222,  // 16930: SSDT 哈希值 0xC3C7B2BC
    GtSyscallHash16933 = 0x4225,  // 16933: SSDT 哈希值 0xD776C56E
    GtSyscallHash16937 = 0x4229,  // 16937: SSDT 哈希值 0xDE817CA7
    GtSyscallHash16940 = 0x422C,  // 16940: SSDT 哈希值 0xB71F96F8
    GtSyscallHash16942 = 0x422E,  // 16942: SSDT 哈希值 0xAC4060D8
    GtSyscallHash16945 = 0x4231,  // 16945: SSDT 哈希值 0xDEAF455A
    GtSyscallHash16955 = 0x423B,  // 16955: SSDT 哈希值 0xC936E5ED
    GtSyscallHash16957 = 0x423D,  // 16957: SSDT 哈希值 0xDCB2E1E3
    GtSyscallHash16958 = 0x423E,  // 16958: SSDT 哈希值 0xB025F852
    GtSyscallHash16961 = 0x4241,  // 16961: SSDT 哈希值 0x9EA7F1F5
    GtSyscallHash16963 = 0x4243,  // 16963: SSDT 哈希值 0xA566F83B
    GtSyscallHash16967 = 0x4247,  // 16967: SSDT 哈希值 0x9CBC0C9B
    GtSyscallHash16975 = 0x424F,  // 16975: SSDT 哈希值 0x81841CC1
    GtSyscallHash16981 = 0x4255,  // 16981: SSDT 哈希值 0xAE45EF20
    GtSyscallHash16991 = 0x425F,  // 16991: SSDT 哈希值 0xFF67D295
    GtSyscallHash16993 = 0x4261,  // 16993: SSDT 哈希值 0xB26A3E6A
    GtSyscallHash16994 = 0x4262,  // 16994: SSDT 哈希值 0x9BAF4E6D
    GtSyscallHash16996 = 0x4264,  // 16996: SSDT 哈希值 0xA8D092A5
    GtSyscallHash16738 = 0x4162,  // 16738: SSDT 哈希值 0x52E5A42A
    GtSyscallHash16744 = 0x4168,  // 16744: SSDT 哈希值 0x1C710C25
    GtSyscallHash16745 = 0x4169,  // 16745: SSDT 哈希值 0x596508BC
    GtSyscallHash16757 = 0x4175,  // 16757: SSDT 哈希值 0x6BCD42A9
    GtSyscallHash16759 = 0x4177,  // 16759: SSDT 哈希值 0x11443CA9
    GtSyscallHash16766 = 0x417E,  // 16766: SSDT 哈希值 0x3E171C0D
    GtSyscallHash16769 = 0x4181,  // 16769: SSDT 哈希值 0x60E6A55E
    GtSyscallHash16775 = 0x4187,  // 16775: SSDT 哈希值 0x71CF9A3E
    GtSyscallHash16784 = 0x4190,  // 16784: SSDT 哈希值 0x4C641018
    GtSyscallHash16786 = 0x4192,  // 16786: SSDT 哈希值 0x182C7ABD
    GtSyscallHash16787 = 0x4193,  // 16787: SSDT 哈希值 0x38EA43CA
    GtSyscallHash16792 = 0x4198,  // 16792: SSDT 哈希值 0x1AD07B46
    GtSyscallHash16795 = 0x419B,  // 16795: SSDT 哈希值 0x3A404733
    GtSyscallHash16798 = 0x419E,  // 16798: SSDT 哈希值 0x24E8CC0D
    GtSyscallHash16802 = 0x41A2,  // 16802: SSDT 哈希值 0x15809667
    GtSyscallHash16810 = 0x41AA,  // 16810: SSDT 哈希值 0x79352A4E
    GtSyscallHash16813 = 0x41AD,  // 16813: SSDT 哈希值 0x49733B00
    GtSyscallHash16816 = 0x41B0,  // 16816: SSDT 哈希值 0x63B8D286
    GtSyscallHash16817 = 0x41B1,  // 16817: SSDT 哈希值 0x20AF640D
    GtSyscallHash16823 = 0x41B7,  // 16823: SSDT 哈希值 0x7158131
    GtSyscallHash16825 = 0x41B9,  // 16825: SSDT 哈希值 0x1B0386BD
    GtSyscallHash16826 = 0x41BA,  // 16826: SSDT 哈希值 0xDFF75FD
    GtSyscallHash16831 = 0x41BF,  // 16831: SSDT 哈希值 0x777A6033
    GtSyscallHash16834 = 0x41C2,  // 16834: SSDT 哈希值 0x38145A3F
    GtSyscallHash16843 = 0x41CB,  // 16843: SSDT 哈希值 0x29291EB
    GtSyscallHash16849 = 0x41D1,  // 16849: SSDT 哈希值 0x4910DB26
    GtSyscallHash16850 = 0x41D2,  // 16850: SSDT 哈希值 0x5612B523
    GtSyscallHash16853 = 0x41D5,  // 16853: SSDT 哈希值 0x360B8B54
    GtSyscallHash16858 = 0x41DA,  // 16858: SSDT 哈希值 0x34FDB1E5
    GtSyscallHash16861 = 0x41DD,  // 16861: SSDT 哈希值 0x3E6F0E31
    GtSyscallHash16871 = 0x41E7,  // 16871: SSDT 哈希值 0x50AE9DEF
    GtSyscallHash16873 = 0x41E9,  // 16873: SSDT 哈希值 0x194066FF
    GtSyscallHash16876 = 0x41EC,  // 16876: SSDT 哈希值 0x7AD36E07
    GtSyscallHash16882 = 0x41F2,  // 16882: SSDT 哈希值 0x2A61C490
    GtSyscallHash16888 = 0x41F8,  // 16888: SSDT 哈希值 0x5D00C553
    GtSyscallHash16897 = 0x4201,  // 16897: SSDT 哈希值 0x377015DC
    GtSyscallHash16901 = 0x4205,  // 16901: SSDT 哈希值 0x7CCC51A6
    GtSyscallHash16904 = 0x4208,  // 16904: SSDT 哈希值 0x15248FA8
    GtSyscallHash16906 = 0x420A,  // 16906: SSDT 哈希值 0x33CFA96A
    GtSyscallHash16913 = 0x4211,  // 16913: SSDT 哈希值 0x50C6C12D
    GtSyscallHash16921 = 0x4219,  // 16921: SSDT 哈希值 0x3036CD1
    GtSyscallHash16924 = 0x421C,  // 16924: SSDT 哈希值 0x50DC4713
    GtSyscallHash16927 = 0x421F,  // 16927: SSDT 哈希值 0x56AA7C37
    GtSyscallHash16939 = 0x422B,  // 16939: SSDT 哈希值 0x13F4E81A
    GtSyscallHash16948 = 0x4234,  // 16948: SSDT 哈希值 0x5503C59B
    GtSyscallHash16951 = 0x4237,  // 16951: SSDT 哈希值 0x71BF7B31
    GtSyscallHash16954 = 0x423A,  // 16954: SSDT 哈希值 0x64E4BA3
    GtSyscallHash16966 = 0x4246,  // 16966: SSDT 哈希值 0x785354C2
    GtSyscallHash16969 = 0x4249,  // 16969: SSDT 哈希值 0x65EC3CC0
    GtSyscallHash16972 = 0x424C,  // 16972: SSDT 哈希值 0x2A0A82C4
    GtSyscallHash16978 = 0x4252,  // 16978: SSDT 哈希值 0x6AD0955E
    GtSyscallHash16984 = 0x4258,  // 16984: SSDT 哈希值 0x80850FD
    GtSyscallHash16987 = 0x425B,  // 16987: SSDT 哈希值 0x661F49E4
    GtSyscallHash16990 = 0x425E,  // 16990: SSDT 哈希值 0x66D9753C
    GtSyscallHash16999 = 0x4267,  // 16999: SSDT 哈希值 0x537EB693
    GtSyscallHash17000 = 0x4268,  // 17000: SSDT 哈希值 0x6A2E832C

} GLOBAL_TABLE_INDEX;

// EPROCESS 字段别名（源码使用原始索引编号，枚举使用偏移量）
#define GtEprocessField101  GtPsExitSpecialApcAddr   // index 101
#define GtEprocessField103  GtPspExitNormalApcAddr   // index 103
#define GtEprocessField104  GtEprocessField94         // index 104
#define GtEprocessField105  GtEprocessField95         // index 105
#define GtEprocessField106  GtEprocessField96         // index 106
#define GtEprocessField107  GtModuleBuffer            // index 107
#define GtEprocessField108  GtWin32kServiceTableVersion // index 108
#define GtEprocessField109  GtEprocessField99         // index 109
#define GtEprocessField111  GtPeDataSectionVa         // index 111
#define GtEprocessField112  GtPeDataSectionVa2        // index 112
#define GtEprocessField114  GtPeDataSectionVa4        // index 114
#define GtEprocessField115  GtPeDataSectionVa5        // index 115
#define GtEprocessField117  GtEprocessField107        // index 117
#define GtEprocessField118  GtEprocessField108        // index 118
#define GtEprocessField120  GtEprocessField110        // index 120
#define GtEprocessField121  GtPeSectionEndVa          // index 121
#define GtEprocessField122  GtEprocessField112        // index 122
#define GtEprocessField123  GtEprocessField113        // index 123
#define GtEprocessField124  GtPeSectionEndVa2         // index 124
#define GtEprocessField129  GtPeCodeSectionEndVa      // index 129
#define GtEprocessField130  GtEprocessField120        // index 130
#define GtEprocessField131  GtPeInitSectionEndVa      // index 131
#define GtEprocessField132  GtEprocessField122        // index 132
#define GtEprocessField133  GtEprocessField123        // index 133
#define GtEprocessField134  GtEprocessField124        // index 134
#define GtEprocessField135  GtObCallbackEntry1        // index 135
#define GtEprocessField136  GtObCallbackEntry2        // index 136
#define GtEprocessField138  GtEprocessField128        // index 138
#define GtEprocessField139  GtEprocessField129        // index 139

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

// ---- 缺失的 GT 别名定义（rename 脚本回退后补充） ----
// 以下值从 IDA 反编译确认，部分与新枚举条目重叠，用宏定义兼容旧代码引用
// SSDT 相关索引 (IDA 确认)
#define GtSsdtTableOffset      0x90F           // 2319: SSDT 表偏移(EnumProcessModules)
#define GtFwpsDispatchTableBase 0x910          // 2320: Fwps 调度表基址(EnumProcessModules)
#define GtPteBase              0x911           // 2321: PTE 基址(EnumProcessModules)
#define GtSsdtServiceTable     0x8B3           // 2227: SSDT 服务表基址(EnumSsdtHooks)
#define GtSsdtServiceCount     0x914           // 2324: SSDT 服务计数(EnumSsdtHooks, 同GtWindowsBuildNumber)
// 从 r15-0x14=0x90F-0x14=0x8FB 的别名
#define Gt87B                  0x8FB           // 2299: 别名(EnumProcessModules)
// mov ecx, 8F7h 的直接值
#define Gt821                  0x8F7           // 2295: 别名(EnumProcessModules)
// Win32k 基址/大小 (与 EPROCESS 模块链表偏移重叠)
#define GtWin32kBase           0x80F           // 2063: 同GtEprocessModuleEntryCount
#define GtWin32kSize           0x810           // 2064: 同GtEprocessModuleListOffset
// 文件系统过滤驱动 (开发者添加，非原始 IDA 数据)
#define GtFsFilterDriverBase   0x2F1           // 753: 同GtFsFilterExportTable(简化版使用)
#define GtFsFilterDriverSize   0x2F2           // 754: 同GtCallbackField36(简化版使用)
// 对象目录表 (开发者添加，非原始 IDA 数据)
#define GtObjectDirectoryTable 0x41C6          // 16838: 同GtNtFsControlFileFunc(简化版使用)
