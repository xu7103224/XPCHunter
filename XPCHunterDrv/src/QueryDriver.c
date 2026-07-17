// QueryDriver.c — 驱动查询相关函数
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

// BuildDriverPathI8042prt — 构建 i8042prt 驱动路径
// 对应原始驱动 sub_140008914
__int64 BuildDriverPathI8042prt(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 3670121;
    EncodedPath[5] = 3407920;
    EncodedPath[6] = 7340082;
    EncodedPath[7] = 7602290;
    return QueryDriverObjectByPath((__int64)EncodedPath, 10, OutputBuffer, BufferSize);
}

// BuildDriverPathKbdClass — 构建 kbdclass 驱动路径
// 对应原始驱动 sub_140008994
__int64 BuildDriverPathKbdClass(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6422603;
    EncodedPath[5] = 4391012;
    EncodedPath[6] = 6357100;
    EncodedPath[7] = 7536755;
    return QueryDriverObjectByPath((__int64)EncodedPath, 8, OutputBuffer, BufferSize);
}

// BuildDriverPathMouClass — 构建 mouclass 驱动路径
// 对应原始驱动 sub_140008A14
__int64 BuildDriverPathMouClass(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7274573;
    EncodedPath[5] = 6488181;
    EncodedPath[6] = 6357100;
    EncodedPath[7] = 7536755;
    return QueryDriverObjectByPath((__int64)EncodedPath, 9, OutputBuffer, BufferSize);
}

// CopySectionString — 复制节区字符串
// 对应原始驱动 sub_140009BCC
// 从驱动条目和设备条目中复制驱动名、设备名、对象路径和文件路径到输出缓冲区
BOOLEAN CopySectionString(__int64 OutputBuffer, __int64 DeviceEntry, __int64 DriverEntry, int DeviceType)
{
    *(_DWORD *)OutputBuffer = DeviceType;
    *(_QWORD *)(OutputBuffer + 16) = DeviceEntry;
    *(_QWORD *)(OutputBuffer + 8) = 0;
    *(_WORD *)(OutputBuffer + 24) = 0;

    // Driver name
    unsigned int NameLength = *(unsigned __int16 *)(DriverEntry + 56);
    __int64 NameChars = NameLength >> 1;
    if ((unsigned int)NameChars > 0x103)
        NameChars = 259;
    void *NameBuffer = *(void **)(DriverEntry + 64);
    if (NameBuffer > MmSystemRangeStart
        && CheckMemoryValid(NameBuffer) == 1
        && CheckMemoryValid((void *)(*(_QWORD *)(DriverEntry + 64) - 2LL + 2 * NameChars)) == 1)
    {
        memmove((void *)(OutputBuffer + 24), *(const void **)(DriverEntry + 64), (unsigned int)(2 * NameChars));
    }
    if ((_DWORD)NameChars)
        *(_WORD *)(OutputBuffer + 2 * NameChars + 24) = 0;

    // Device name
    __int64 DeviceObjEntry = *(_QWORD *)(DeviceEntry + 8);
    unsigned int DeviceNameLen = *(unsigned __int16 *)(DeviceObjEntry + 56);
    *(_WORD *)(OutputBuffer + 544) = 0;
    void *DevNameBuffer = *(void **)(DeviceObjEntry + 64);
    __int64 DevNameChars = DeviceNameLen >> 1;
    if ((unsigned int)DevNameChars > 0x103)
        DevNameChars = 259;
    if (DevNameBuffer > MmSystemRangeStart
        && CheckMemoryValid(DevNameBuffer) == 1
        && CheckMemoryValid((void *)(*(_QWORD *)(DeviceObjEntry + 64) - 2LL + 2 * DevNameChars)) == 1)
    {
        memmove((void *)(OutputBuffer + 544), *(const void **)(DeviceObjEntry + 64), (unsigned int)(2 * DevNameChars));
    }
    if ((_DWORD)DevNameChars)
        *(_WORD *)(OutputBuffer + 2 * DevNameChars + 544) = 0;

    // Object name
    *(_WORD *)(OutputBuffer + 1064) = 0;
    unsigned __int16 *VisualPathPtr;
    if (ResolveObjectHeaderPointer(DeviceEntry, &VisualPathPtr) == 1)
    {
        void *ObjNameBuffer = (void *)*((_QWORD *)VisualPathPtr + 1);
        __int64 ObjNameChars = *VisualPathPtr >> 1;
        if ((unsigned int)ObjNameChars > 0x103)
            ObjNameChars = 259;
        if (ObjNameBuffer > MmSystemRangeStart
            && CheckMemoryValid(ObjNameBuffer) == 1
            && CheckMemoryValid((void *)(*((_QWORD *)VisualPathPtr + 1) - 2LL + 2 * ObjNameChars)) == 1)
        {
            memmove((void *)(OutputBuffer + 1064), *((const void **)VisualPathPtr + 1), (unsigned int)(2 * ObjNameChars));
        }
        if ((_DWORD)ObjNameChars)
            *(_WORD *)(OutputBuffer + 2 * ObjNameChars + 1064) = 0;
    }

    // File path
    *(_WORD *)(OutputBuffer + 1584) = 0;
    __int64 FileObjPtr = *(_QWORD *)(DeviceObjEntry + 40);
    if (FileObjPtr > (unsigned __int64)MmSystemRangeStart
        && *(_QWORD *)(FileObjPtr + 96)
        && *(_QWORD *)(FileObjPtr + 80))
    {
        unsigned int FilePathLen = *(unsigned __int16 *)(FileObjPtr + 72);
        *(_WORD *)(OutputBuffer + 1584) = 0;
        void *FilePathBuffer = *(void **)(FileObjPtr + 80);
        __int64 FilePathChars = FilePathLen >> 1;
        if ((unsigned int)FilePathChars > 0x103)
            FilePathChars = 259;
        if (FilePathBuffer > MmSystemRangeStart
            && CheckMemoryValid(FilePathBuffer) == 1
            && CheckMemoryValid((void *)(*(_QWORD *)(FileObjPtr + 80) - 2LL + 2 * FilePathChars)) == 1)
        {
            memmove((void *)(OutputBuffer + 1584), *(const void **)(FileObjPtr + 80), (unsigned int)(2 * FilePathChars));
        }
        if ((_DWORD)FilePathChars)
            *(_WORD *)(OutputBuffer + 2 * FilePathChars + 1584) = 0;
    }
    return 1;
}

// EnumDeviceObjects
__int64 EnumDeviceObjects(_QWORD a1, _QWORD a2)
{
    return 0;
}

// EnumFileSystemDeviceObjects — 枚举文件系统设备对象
// 对应原始驱动 sub_140008CEC
// 通过 \FileSystem\ 设备路径枚举所有文件系统设备
__int64 EnumFileSystemDeviceObjects(__int64 OutputBuffer, int MaxCount)
{
    unsigned int EntryCount = 0;
    void (__fastcall *DecodeStringFunc)(_BYTE *, _DWORD *) = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    unsigned int (__fastcall *CreateFileFunc)(_BYTE *, __int64, __int64 *, __int64 *) = (unsigned int (__fastcall *)(_BYTE *, __int64, __int64 *, __int64 *))GtRead(GtCreateFileFunc2);
    __int64 CloseHandleFuncPtr = GtRead(GtCloseHandleFunc);
    void (__fastcall *CloseHandleFunc)(__int64) = (void (__fastcall *)(__int64))CloseHandleFuncPtr;
    _DWORD EncodedPath[12];
    __int64 FileHandle;
    __int64 DeviceEntry;
    _BYTE DevicePath[16];
    if (DecodeStringFunc && CreateFileFunc && CloseHandleFuncPtr)
    {
        EncodedPath[0] = 4456540;
        EncodedPath[1] = 7733349;
        EncodedPath[2] = 6488169;
        EncodedPath[3] = 6029413;
        EncodedPath[4] = 6357064;
        EncodedPath[5] = 6553714;
        EncodedPath[6] = 6881380;
        EncodedPath[7] = 7012467;
        EncodedPath[8] = 7274582;
        EncodedPath[9] = 7667820;
        EncodedPath[10] = 6619245;
        EncodedPath[11] = 49;
        DecodeStringFunc(DevicePath, EncodedPath);
        if (!CreateFileFunc(DevicePath, 128, &FileHandle, &DeviceEntry))
        {
            if (GetDeviceObjectFromFileObject(FileHandle, &DeviceEntry, 0))
            {
                __int64 DriverFlink = *(_QWORD *)(DeviceEntry + 8);
                __int64 DeviceListIter = *(_QWORD *)(DeviceEntry + 24);
                while (1)
                {
                    DeviceEntry = DeviceListIter;
                    if (!DeviceListIter || !MaxCount)
                        break;
                    CopySectionString(OutputBuffer, DeviceListIter, DriverFlink, 3);
                    OutputBuffer += 2104;
                    DriverFlink = *(_QWORD *)(DeviceEntry + 8);
                    DeviceListIter = *(_QWORD *)(DeviceEntry + 24);
                    --MaxCount;
                    ++EntryCount;
                }
            }
            CloseHandleFunc(FileHandle);
        }
    }
    return EntryCount;
}

// QueryDriverObjectByPath — 按路径查询驱动对象
// 对应原始驱动 sub_1400083C4
// 通过驱动对象链表遍历指定路径的驱动对象，复制设备信息到输出缓冲区
__int64 QueryDriverObjectByPath(__int64 TargetPath, int MaxNameLength, __int64 OutputBuffer, int MaxEntries)
{
    unsigned int Result = 0;
    void (__fastcall *RtlInitStrFunc)(_BYTE *, __int64) = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    int (__fastcall *IoCreateFileFunc)(_BYTE *, __int64, _QWORD, _QWORD, _QWORD, _BYTE, _QWORD, __int64 *) = (int (__fastcall *)(_BYTE *, __int64, _QWORD, _QWORD, _QWORD, _BYTE, _QWORD, __int64 *))GtRead(GtIoCreateFileFunc);
    _QWORD *DriverListHead = (_QWORD *)GtRead(GtDriverObjectListHead);
    void (*CloseHandleFunc)(void) = (void (*)(void))GtRead(GtCloseHandleFunc);

    if (RtlInitStrFunc && IoCreateFileFunc && DriverListHead && CloseHandleFunc)
    {
        _BYTE ObjectNameBuffer[24];
        RtlInitStrFunc(ObjectNameBuffer, TargetPath);
        __int64 FileHandle;
        if (IoCreateFileFunc(ObjectNameBuffer, 64, 0, 0, *DriverListHead, 0, 0, &FileHandle) >= 0)
        {
            if (FileHandle)
            {
                for (_QWORD *i = *(_QWORD **)(FileHandle + 8); i; i = (_QWORD *)i[2])
                {
                    __int64 SectionBase = i[1];
                    __int64 SectionIter = i[3];
                    while (SectionIter && MaxEntries)
                    {
                        CopySectionString(OutputBuffer, SectionIter, SectionBase, MaxNameLength);
                        SectionBase = *(_QWORD *)(SectionIter + 8);
                        SectionIter = *(_QWORD *)(SectionIter + 24);
                        OutputBuffer += 2104;
                        --MaxEntries;
                        ++Result;
                    }
                }
                CloseHandleFunc();
            }
        }
    }
    return Result;
}

// QueryDriverObjectDevice — 查询驱动对象设备列表
// 对应原始驱动 sub_1400087A8
// 编码设备路径，打开 \\Driver\\Device 对象，获取设备对象链表并复制到输出缓冲区
__int64 QueryDriverObjectDevice(__int64 OutputBuffer, int MaxCount)
{
    return 0;  // TODO: implement properly (uses GetDeviceObjectFromFileObject)
}

// QueryFileSystemDriverObject — 查询文件系统驱动对象
// 对应原始驱动 sub_14000872C
__int64 QueryFileSystemDriverObject(__int64 OutputBuffer, int MaxCount)
{
    _DWORD EncodedPath[10];
    EncodedPath[0] = 4587612;
    EncodedPath[1] = 7077993;
    EncodedPath[2] = 5439589;
    EncodedPath[3] = 7536761;
    EncodedPath[4] = 6619252;
    EncodedPath[5] = 6029421;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return QueryDriverObjectByPath((__int64)EncodedPath, 2, OutputBuffer, MaxCount);
}

// QueryNdisDriverObject — 查询 NDIS 驱动对象
// 对应原始驱动 sub_140008A94
__int64 QueryNdisDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[8];
    EncodedPath[6] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 4456526;
    EncodedPath[5] = 5439561;
    return QueryDriverObjectByPath((__int64)EncodedPath, 11, OutputBuffer, BufferSize);
}

// QueryPnpManagerDriverObject — 查询 PnP 管理器驱动对象
// 对应原始驱动 sub_140008BF8
__int64 QueryPnpManagerDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[9] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7209040;
    EncodedPath[5] = 5046384;
    EncodedPath[6] = 7209057;
    EncodedPath[7] = 6750305;
    EncodedPath[8] = 7471205;
    return QueryDriverObjectByPath((__int64)EncodedPath, 12, OutputBuffer, BufferSize);
}

// QueryTcpipDriverObject — 查询 TCPIP 驱动对象
// 对应原始驱动 sub_140008B04
__int64 QueryTcpipDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6488148;
    EncodedPath[5] = 6881392;
    EncodedPath[6] = 112;
    return QueryDriverObjectByPath((__int64)EncodedPath, 5, OutputBuffer, BufferSize);
}

// QueryTdxDriverObject — 查询 TDX 驱动对象
// 对应原始驱动 sub_140008C80
__int64 QueryTdxDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[6];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6553716;
    EncodedPath[5] = 120;
    return QueryDriverObjectByPath((__int64)EncodedPath, 7, OutputBuffer, BufferSize);
}

// QueryVolmgrDriverObject — 查询卷管理器驱动对象
// 对应原始驱动 sub_140008B78
__int64 QueryVolmgrDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7536750;
    EncodedPath[5] = 7340137;
    EncodedPath[6] = 7274610;
    EncodedPath[7] = 7929976;
    return QueryDriverObjectByPath((__int64)EncodedPath, 6, OutputBuffer, BufferSize);
}
