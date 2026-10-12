// CheckCommPortFilePathExists — 拼接/规范化通信端口文件路径并检查其是否存在
// 对应原始驱动 0x140019438（362 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【入参结构】FilePathInfo 是含两个元素的指针数组：
//   FilePathInfo[0] = 指向 UNICODE_STRING 的指针（*FilePathInfo = 该 UNICODE_STRING 首址，
//     其 +0x00 是 Length(字节数)、+0x08 是 Buffer）
//   FilePathInfo[1] = 文件对象（供 QueryAllocFilePath 查询其完整路径）
// 【逻辑】
//   ① 取 UNICODE_STRING 的 Length；< 2 直接返回 0；
//   ② 若 名字缓冲首字符 == L'\\'(92)（已是完整路径）：
//        ExAlloc(PagedPool, Length+4) → memmove(名字, Length) → 末尾补 NUL；
//   ③ 否则（相对路径）：QueryAllocFilePath(FilePathInfo[1]) 取目录完整路径，
//        总长 = 目录长 + 名字长 + 10；溢出三重检查通过后 ExAlloc(PagedPool, 总长) →
//        memmove(目录, 目录长) → 在目录末尾写 L'\\' → memmove(名字, 名字长) → 末尾补 NUL；
//        随后 ExFree(目录缓冲)；
//   ④ 若拼出完整路径：Result = (OpenFileCheckExists(路径) == 0)，再 ExFree(路径)。
bool __fastcall CheckCommPortFilePathExists(unsigned __int16 **FilePathInfo)
{
    unsigned __int16 *NameStruct;
    bool    Result = 0;
    USHORT  NameLen;
    _WORD  *FullPath = 0;
    const void **DirPath;
    int     DirLen, TotalLen;

    NameStruct = *FilePathInfo;                                     // 0x140019455
    NameLen    = *NameStruct;                                       // 0x14001945D（UNICODE_STRING.Length）
    if (NameLen < 2)                                                // 0x140019468
        return Result;

    if (*(WORD *)(*((_WORD **)NameStruct + 1)) == 92)               // 0x14001947C（L'\\'，即 +0x08 = Buffer）
    {
        /* ---- 已是完整路径：直接复制 ---- */
        FullPath = (_WORD *)ExAlloc(1 /*PagedPool*/, (ULONG64)NameLen + 4);   // 0x14001948C
        if (!FullPath)                                              // 0x140019497
            return Result;

        memmove(FullPath, *((const void **)NameStruct + 1), NameLen);        // 0x1400194AB
        FullPath[(ULONG64)NameLen >> 1] = 0;                        // 0x1400194B9
    }
    else
    {
        /* ---- 相对路径：取目录全路径后拼接 ---- */
        DirPath = (const void **)QueryAllocFilePath((__int64)FilePathInfo[1]);   // 0x1400194C6
        if (!DirPath)                                               // 0x1400194D1
            return Result;

        DirLen   = *(USHORT *)DirPath;                              // 0x1400194E3（目录 UNICODE_STRING.Length）
        TotalLen = DirLen + NameLen + 10;                           // 0x1400194EB
        if (TotalLen > DirLen && TotalLen > NameLen                  // 0x1400194FA（三重溢出检查）
            && TotalLen > DirLen + NameLen)
        {
            FullPath = (_WORD *)ExAlloc(1 /*PagedPool*/, (ULONG64)TotalLen);   // 0x140019502
            if (FullPath)                                           // 0x14001950D
            {
                memmove(FullPath, DirPath[1], *(USHORT *)DirPath);            // 0x14001951B
                *(WORD *)((char *)FullPath + *(USHORT *)DirPath) = 92;        // 0x140019524（L'\\'）
                memmove((char *)FullPath + *(USHORT *)DirPath + 2,            // 0x14001953E
                        *((const void **)NameStruct + 1), NameLen);
                FullPath[(ULONG64)(NameLen + *(USHORT *)DirPath + 2) >> 1] = 0;   // 0x140019557
            }
        }
        ExFree((void *)DirPath);                                    // 0x14001955E
    }

    if (FullPath)                                                   // 0x140019566
    {
        Result = (OpenFileCheckExists((__int64)FullPath) == 0) ? 1 : 0;   // 0x140019578
        ExFree(FullPath);                                           // 0x14001957C
    }
    return Result;                                                  // 0x140019581
}