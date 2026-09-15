// QueryDriver.c — 驱动查询相关函数
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"

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
    if (ResolveObjectHeaderPointer(DeviceEntry, (_QWORD *)&VisualPathPtr) == 1)
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
    if ((unsigned __int64)FileObjPtr > (unsigned __int64)MmSystemRangeStart
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

// EnumDeviceObjects — 枚举设备对象
// 对应原始驱动 sub_140008504
// 打开系统卷设备，通过 NtFsControlFile 获取设备句柄，遍历设备对象链
__int64 EnumDeviceObjects(__int64 OutputBuffer, int MaxCount)
{
    unsigned int EntryCount = 0;
    void (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, _DWORD *);
    __int64 (__fastcall *CreateFileFunc1)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64);
    __int64 (__fastcall *NtFsControlFileFunc)(__int64, __int64, __int64, __int64, __int64, __int64);
    __int64 *pFsControlCode;
    void (__fastcall *CloseHandleFunc)(__int64);
    void (__fastcall *ExFreePoolFunc)(__int64);

    __int64 FileHandle;
    __int64 IoStatusBlock;
    __int64 DeviceObjectPtr;
    __int64 ResultInfo;
    __int64 FsControlCode;
    ULONG OaLength;
    ULONG64 OaRootDir;
    ULONG64 OaObjectName;
    ULONG OaAttributes;
    _OWORD IoStatusBlockBuf;
    ULONG PathBuffer[4];
    ULONG InitResult;

    // 读取函数指针
    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc1 = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64))GtRead(GtCreateFileFunc1);
    NtFsControlFileFunc = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))GtRead(GtNtFsControlFileFunc);
    pFsControlCode = (__int64 *)GtRead(GtZwCreateFileFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))GtRead(GtCloseHandleFunc);
    ExFreePoolFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);

    // 检查所有函数指针非空
    if (!RtlInitUnicodeStringFunc || !CreateFileFunc1 || !NtFsControlFileFunc ||
        !pFsControlCode || !CloseHandleFunc || !ExFreePoolFunc)
    {
        return 0;
    }

    // 构造设备路径缓冲区：L"\\??\\X:\\"
    // 初始化为 L"\\??\\C:\\"，稍后通过 InitSystemPath 获取的驱动器号替换 'C'
    PathBuffer[0] = 0x3F005C;   // L"\\?"
    PathBuffer[1] = 0x5C003F;   // L"?\\"
    PathBuffer[2] = 0x3A0043;   // L"C:"
    PathBuffer[3] = 0x5C;       // L"\\"

    // 获取系统根路径，提取驱动器号
    InitResult = (ULONG)(ULONG_PTR)InitSystemPath();
    if (!InitResult)
    {
        return 0;
    }

    // 替换路径中的驱动器号
    ((WORD *)PathBuffer)[4] = *(WORD *)(ULONG_PTR)InitResult;
    ExFree((void *)(ULONG_PTR)InitResult);

    // 初始化 Unicode 字符串
    RtlInitUnicodeStringFunc((_BYTE *)&ResultInfo, (_DWORD *)PathBuffer);

    // 设置 OBJECT_ATTRIBUTES
    OaLength = 0x30;                       // sizeof(OBJECT_ATTRIBUTES)
    OaRootDir = 0;                         // 根目录为空
    OaAttributes = 0x240;                  // OBJ_CASE_INSENSITIVE
    OaObjectName = (ULONG64)&ResultInfo;   // 指向 Unicode 字符串

    // 清零 IO_STATUS_BLOCK
    ((ULONG64 *)&IoStatusBlockBuf)[0] = 0;
    ((ULONG64 *)&IoStatusBlockBuf)[1] = 0;

    // 调用 CreateFile 打开设备
    if ((ULONG)CreateFileFunc1(
        (__int64)&FileHandle,
        0x100000,                     // DesiredAccess: SYNCHRONIZE
        (__int64)&OaLength,           // ObjectAttributes
        (__int64)&IoStatusBlockBuf,   // IoStatusBlock
        0,                            // AllocationSize
        0,                            // FileAttributes
        3,                            // ShareAccess: FILE_SHARE_READ|FILE_SHARE_WRITE
        1,                            // CreateDisposition: FILE_OPEN
        0x21,                         // CreateOptions: FILE_SYNCHRONOUS_IO_NONALERT
        0) != 0)                      // EaLength
    {
        return 0;
    }

    // 读取 FSCTL 码
    FsControlCode = *pFsControlCode;

    // 调用 NtFsControlFile 获取设备句柄
    // 从文件对象获取设备对象
    if ((ULONG)NtFsControlFileFunc(
        FileHandle,
        1,                            // Event
        FsControlCode,                // 第 3 参数（实际为 FSCTL 码）
        0,                            // 第 4 参数
        (__int64)&IoStatusBlock,      // IoStatusBlock 输出
        0) != 0)                      // 第 6 参数
    {
        ExFreePoolFunc(FileHandle);
        return 0;
    }

    // 从文件对象获取设备对象
    if (!GetDeviceObjectFromFileObject(IoStatusBlock, (ULONG64 *)&DeviceObjectPtr, NULL))
    {
        CloseHandleFunc(IoStatusBlock);
        ExFreePoolFunc(FileHandle);
        return 0;
    }

    // 遍历设备对象链
    // 从 DeviceObjectPtr 的 NextDevice 开始遍历
    while (DeviceObjectPtr)
    {
        __int64 NextDevice = *(__int64 *)(DeviceObjectPtr + 0x18);
        __int64 DriverObject = *(__int64 *)(DeviceObjectPtr + 0x08);
        DeviceObjectPtr = NextDevice;
        if (!DeviceObjectPtr || !MaxCount)
            break;
        CopySectionString(OutputBuffer, DeviceObjectPtr, DriverObject, 4);
        OutputBuffer += 0x838;
        --MaxCount;
        ++EntryCount;
    }

    // 清理
    CloseHandleFunc(IoStatusBlock);
    ExFreePoolFunc(FileHandle);
    return EntryCount;
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
// 通过编码设备路径打开 \\Driver\\Device 对象，获取设备对象链表并复制到输出缓冲区
// 对应原始驱动 sub_1400087A8
__int64 QueryDriverObjectDevice(__int64 OutputBuffer, int MaxCount)
{
    unsigned int EntryCount;
    void (__fastcall *DecodeStringFunc)(_BYTE *, _DWORD *);
    unsigned int (__fastcall *CreateFileFunc)(_BYTE *, __int64, __int64 *, __int64 *);
    __int64 CloseHandleFuncPtr;
    void (__fastcall *CloseHandleFunc)(__int64);
    __int64 DriverFlink;
    __int64 DeviceListIter;
    __int64 DeviceEntry;
    __int64 FileHandle;
    _BYTE DevicePath[16];
    _DWORD EncodedPath[12];

    EntryCount = 0;
    DecodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (unsigned int (__fastcall *)(_BYTE *, __int64, __int64 *, __int64 *))GtRead(GtCreateFileFunc2);
    CloseHandleFuncPtr = GtRead(GtCloseHandleFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandleFuncPtr;
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
        EncodedPath[8] = 6029360;
        EncodedPath[9] = 5374020;
        EncodedPath[10] = 48;
        DecodeStringFunc(DevicePath, EncodedPath);
        if (!CreateFileFunc(DevicePath, 128, &FileHandle, &DeviceEntry))
        {
            if (GetDeviceObjectFromFileObject(FileHandle, &DeviceEntry, 0))
            {
                DriverFlink = *(_QWORD *)(DeviceEntry + 8);
                DeviceListIter = *(_QWORD *)(DeviceEntry + 24);
                while (1)
                {
                    DeviceEntry = DeviceListIter;
                    if (!DeviceListIter || !MaxCount)
                        break;
                    CopySectionString(OutputBuffer, DeviceListIter, DriverFlink, 1);
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
