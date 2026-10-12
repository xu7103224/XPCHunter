// ============================================================
// "按导出名查找并把 (偏移, 地址) 写入 GT 对" 家族（L2-1，14 个）
//
// 本族 14 个函数**结构完全同构**（各 183~300 字节），统一模板：
//   ① v5 = GtRead(GtEprocessField151|0x100)  → 模块基址（0x1A1），为 0 即返回 0；
//   ② strcpy(名字缓冲, L"<导出名>")；
//   ③ LookupExportByName(a1, a2, 名字, &Value) == 1 && Value != 0 && Value < a2
//   ④ GtWrite(<偏移槽>, Value); GtWrite(<地址槽>, v5 + Value); return 1；
//   否则返回 0。
//
// 【逆向来源】全部**可被 Hex-Rays 正常反编译**，按伪代码 1:1 转写。
// 【GT 索引】均为源码枚举未命名区间（0x7B8..0x7E1），故以裸索引书写并附原始语义注释。
// ============================================================


// FindWfpStartStreamShimExport — 按名查找 WfpStartStreamShim 导出并登记 (偏移, 地址) 到 GT 0x7c1/0x7c2
// 对应原始驱动 0x140069bcc
char __fastcall FindWfpStartStreamShimExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpStartStreamShim");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7c1, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7c2, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindWfpStopStreamShimExport — 按名查找 WfpStopStreamShim 导出并登记 (偏移, 地址) 到 GT 0x7c3/0x7c4
// 对应原始驱动 0x140069c90
char __fastcall FindWfpStopStreamShimExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpStopStreamShim");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7c3, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7c4, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindWfpStartMacShimExport — 按名查找 WfpStartMacShim 导出并登记 (偏移, 地址) 到 GT 0x7d1/0x7d2
// 对应原始驱动 0x140069998
char __fastcall FindWfpStartMacShimExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpStartMacShim");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7d1, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7d2, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdGetOffloadEpochExport — 按名查找 KfdGetOffloadEpoch 导出并登记 (偏移, 地址) 到 GT 0x7b8/0x7b9
// 对应原始驱动 0x140068458
char __fastcall FindKfdGetOffloadEpochExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdGetOffloadEpoch");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7b8, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7b9, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdGetRefCalloutExport — 按名查找 KfdGetRefCallout 导出并登记 (偏移, 地址) 到 GT 0x7da/0x7db
// 对应原始驱动 0x14006851c
char __fastcall FindKfdGetRefCalloutExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdGetRefCallout");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7da, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7db, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdDeleteCalloutEntryExport — 按名查找 KfdDeleteCalloutEntry 导出并登记 (偏移, 地址) 到 GT 0x7de/0x7df
// 对应原始驱动 0x140068260
char __fastcall FindKfdDeleteCalloutEntryExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdDeleteCalloutEntry");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7de, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7df, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdUnregisterCalloutEntryExport — 按名查找 KfdUnregisterCalloutEntry 导出并登记 (偏移, 地址) 到 GT 0x7e0/0x7e1
// 对应原始驱动 0x1400686fc
char __fastcall FindKfdUnregisterCalloutEntryExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdUnregisterCalloutEntry");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7e0, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7e1, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdDeregisterLayerCallbackExport — 按名查找 KfdDeregisterLayerChangeCallback 导出并登记 (偏移, 地址) 到 GT 0x7be/0x7bf
// 对应原始驱动 0x14006832c
char __fastcall FindKfdDeregisterLayerCallbackExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdDeregisterLayerChangeCallback");
    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) != 1)
    {
        strcpy(NameBuf, "KfdDeregisterLayerEventNotify");
        if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) != 1)
            return Result;
    }

    if (Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7be, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7bf, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdRegisterLayerCallbackExport — 按名查找 KfdRegisterLayerChangeCallback 导出并登记 (偏移, 地址) 到 GT 0x7bc/0x7bd
// 对应原始驱动 0x1400685d8
char __fastcall FindKfdRegisterLayerCallbackExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdRegisterLayerChangeCallback");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7bc, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7bd, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNsiGetModuleHandle — 按名查找 NsiGetModuleHandle 导出并登记 (偏移, 地址) 到 GT 0x7ca/0x7cb
// 对应原始驱动 0x140069000
char __fastcall FindNsiGetModuleHandle(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NsiGetModuleHandle");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7ca, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7cb, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNmrRegisterProviderExport — 按名查找 NmrRegisterProvider 导出并登记 (偏移, 地址) 到 GT 0x7d7/0x7d8
// 对应原始驱动 0x1400689f8
char __fastcall FindNmrRegisterProviderExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NmrRegisterProvider");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7d7, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7d8, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNsiDeregisterChangeNotificationEx — 按名查找 NsiDeregisterChangeNotificationEx 导出并登记 (偏移, 地址) 到 GT 0x7c8/0x7c9
// 对应原始驱动 0x140068e4c
char __fastcall FindNsiDeregisterChangeNotificationEx(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NsiDeregisterChangeNotificationEx");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7c8, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7c9, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNsiDeregisterLegacyHandler — 按名查找 NsiDeregisterLegacyHandler 导出并登记 (偏移, 地址) 到 GT 0x7ce/0x7cf
// 对应原始驱动 0x140068f2c
char __fastcall FindNsiDeregisterLegacyHandler(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NsiDeregisterLegacyHandler");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7ce, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7cf, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindSetWfpDeviceObject — 按名查找 SetWfpDeviceObject 导出并登记 (偏移, 地址) 到 GT 0x7d4/0x7d5
// 对应原始驱动 0x1400696c0
char __fastcall FindSetWfpDeviceObject(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "SetWfpDeviceObject");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7d4, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7d5, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}
