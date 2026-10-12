// OpenFileQueryInfo — 打开文件对象并查询其基本信息
// 对应原始驱动 0x140019678（265 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪 + 逐字节提取：
//   读 0x41F3（ZwCreateFile 族函数指针）
//   读 0x4208（ZwQueryInformationFile 族函数指针）
//   读 0x4334（GtExFreePoolFunc，此处用作句柄关闭函数）
// 【结构】v12 起是 OBJECT_ATTRIBUTES 形态的 {Length=48, RootDir=0, Name=FilePath,
//   Attributes=576(0x240)}；v17[32] 为输出信息缓冲（32 字节），v11 为 IO_STATUS。
// 【返回值】Result 初值 1；只有走到"打开成功"分支才被赋值为
//   (查询结果 != STATUS_OBJECT_NAME_NOT_FOUND(0xC0000034))，
//   即"打开失败 / 函数指针缺失"都返回 1（原始如此，非笔误）。
char __fastcall OpenFileQueryInfo(__int64 FilePath, __int64 Context)
{
    char     Result = 1;
    __int64  CreateFileFunc;
    __int64  QueryInfoFunc;
    __int64  CloseFunc;
    __int64  Handle = 0;             // v10
    UCHAR    IoStatus[8];            // v11
    UCHAR    ObjAttr[0x30];          // v12 起：Length/RootDir/Name/Attributes
    UCHAR    InfoBuf[32];            // v17
    int      QueryStatus;
    __int128 OutInfo = { 0 };        // v16

    CreateFileFunc = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x41F3);   // 0x1400196B3
    QueryInfoFunc  = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4208);   // 0x1400196C0
    CloseFunc      = (__int64)GtRead(GtExFreePoolFunc);             // 0x1400196CD（0x4334）

    if (!CreateFileFunc || !QueryInfoFunc || !CloseFunc)            // 0x1400196DB~6E5
        return Result;

    // 0x1400196F6~711：布置 OBJECT_ATTRIBUTES（Length=48、Attributes=0x240、ObjectName=FilePath）
    *(ULONG *)&ObjAttr[0x00] = 48;                                  // v12
    *(ULONG64 *)&ObjAttr[0x08] = 0;                                 // v13（RootDirectory）
    *(ULONG64 *)&ObjAttr[0x10] = FilePath;                          // v14（ObjectName）
    *(ULONG *)&ObjAttr[0x18] = 576;                                 // v15（Attributes = 0x240）

    if ((int)((__int64(__fastcall *)(__int64 *, __int64, void *))CreateFileFunc)(
            &Handle, 1, ObjAttr) >= 0)                              // 0x14001971A
    {
        QueryStatus = (int)((__int64(__fastcall *)(__int64, __int64, __int64,
                                                  void *, int, void *))QueryInfoFunc)(
            Handle, Context, 0, InfoBuf, 32, IoStatus);             // 0x14001974D
        Result = (QueryStatus != (int)0xC0000034) ? 1 : 0;          // STATUS_OBJECT_NAME_NOT_FOUND
        ((void(__fastcall *)(__int64))CloseFunc)(Handle);            // 0x140019751
    }
    (void)OutInfo;
    return Result;                                                  // 0x140019755
}

// QueryAllocFilePath — 查询文件对象名并按需分配缓冲返回完整路径
// 对应原始驱动 0x1400197BC（220 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】逐字节提取：读 0x4220（ObQueryNameString 族函数指针）。
// 【算法】先以 (FileObject,0,0,&Size) 调查询函数，期望返回 STATUS_BUFFER_TOO_SMALL
//   (0xC0000023) 且 Size+100 无溢出 → ExAlloc(PagedPool, Size+100)；
//   再以 (FileObject, buf, Size+32, &Size) 查询，成功且
//   buf[1](OBJECT_NAME_INFORMATION.NameBuffer) == buf+2（即名字紧跟结构体）
//   且 (WORD)buf == Size+16 <= Size+32 且 (UINT)(WORD)buf < Size+32 →
//   在名字末尾补 NUL 并返回该缓冲；否则 ExFree 后返回 0。
_QWORD *__fastcall QueryAllocFilePath(__int64 FileObject)
{
    __int64  Result = 0;
    __int64  QueryNameFunc;
    _QWORD  *NameBuffer;
    ULONG    RequiredSize = 0;
    int      Status;

    QueryNameFunc = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4220);    // 0x1400197DA
    if (!FileObject || !QueryNameFunc)                              // 0x1400197E5 / 7EE
        return (_QWORD *)Result;

    Status = (int)((__int64(__fastcall *)(__int64, __int64, __int64, ULONG *))QueryNameFunc)(
        FileObject, 0, 0, &RequiredSize);                           // 0x140019801
    if (Status != (int)0xC0000023)                                  // 0x140019813
        return (_QWORD *)Result;
    if ((ULONG64)RequiredSize + 100 <= (ULONG64)RequiredSize)       // 溢出保护
        return (_QWORD *)Result;

    NameBuffer = (_QWORD *)ExAlloc(1 /*PagedPool*/, RequiredSize + 100);   // 0x14001981A
    if (!NameBuffer)                                                // 0x140019825
        return (_QWORD *)Result;

    Status = (int)((__int64(__fastcall *)(__int64, _QWORD *, __int64, ULONG *))QueryNameFunc)(
        FileObject, NameBuffer, (__int64)RequiredSize + 32, &RequiredSize);   // 0x140019869
    if (Status >= 0)
    {
        _QWORD *NameInfo = (_QWORD *)NameBuffer[1];
        ULONG64 BufferSize = *(USHORT *)NameBuffer;
        if (NameBuffer + 2 == NameInfo                                  // 0x140019869
            && BufferSize + 16 <= (ULONG64)RequiredSize + 32
            && (ULONG)BufferSize < RequiredSize + 32)
        {
            *((WORD *)NameInfo + (BufferSize >> 1)) = 0;                // 0x14001986E
            return NameBuffer;                                          // 0x140019873
        }
    }
    ExFree(NameBuffer);                                             // 0x14001987B
    return (_QWORD *)Result;                                        // 0x140019880
}