// BuildSystemRootPath — 构建系统根路径（0x140047C50，109 条指令）
// 【⚠ 修正记录 2026-10-16】原实现是**伪造实现**：只探测 KUSER_SHARED_DATA
//   (0xFFFFF78000000030) 的两个字节然后 `return 1`，与原始函数体毫无关系。
//   发现方式：逐函数差分报 gt_index_mismatch —— 原始首读 GT 0x421D(16925)，
//   我方首读 0x304(772)，且原始函数体 109 条指令 vs 我方十几条。
// 【逆向来源】IDA 无法反编译该函数，按 capstone 反汇编逐条转写
//   （0x140047C50..0x140047DFB），全部栈位移已用 get_bytes 核对（判据 F）。
// 【语义】先用三个 GT 函数指针（0x421D=RtlInitUnicodeString、0x4244=ZwCreateFile、
//   0x4334=ZwClose）打开 `\SystemRoot\`，再用 NtQuerySystemInformation 类 16
//   （系统句柄表）枚举句柄，按「句柄项 +6 处的类型索引 == 刚打开句柄的类型索引」
//   且「句柄项 +0 处的名字 == 当前进程 EPROCESS 指针低16位」两者比对，
//   命中后把该句柄项 +0x0C 的字节写入 GT[0x60]（系统根对象的类型索引），
//   最后 ExFree 系统信息缓冲并调用 0x4334 指针关闭句柄。
// 【字段映射（栈）】var_48 = 路径字符串缓冲（L"\\SystemRoot\\"，6 个 WCHAR）；
//   var_A0 = ZwCreateFile 输出的句柄；var_98 = UNICODE_STRING（RtlInitUnicodeString 输出）；
//   var_88 = OBJECT_ATTRIBUTES（长度 0x30）；var_68 = FILE_BASIC_INFORMATION(0x10)；
//   var_58 = IO_STATUS_BLOCK(0x10)。
// 【参数】无。
// 【返回值】原始无显式返回值使用（eax 为 RtlInitUnicodeString 尾值），此处返回 0。
__int64 BuildSystemRootPath(void)
{
    /* ① 栈上构造路径 L"\\SystemRoot\\"（原始：6 个立即数分别写入 var_48..var_34） */
    static const WCHAR kSysRoot[] = L"\\SystemRoot\\";
    WCHAR   PathBuf[8];
    SIZE_T  i;

    for (i = 0; i < 7 && kSysRoot[i]; ++i) PathBuf[i] = kSysRoot[i];
    PathBuf[i] = 0;

    /* ② 取三个 GT 函数指针 */
    __int64 pRtlInitUnicodeString = GtRead(GtRtlInitUnicodeStringFunc);   // 0x140047CB3
    __int64 pZwCreateFile          = GtRead(GtIrpDispatchFunc);            // 0x140047CC0
    __int64 pZwClose               = GtRead(GtExFreePoolFunc);             // 0x140047CCD

    /* ③ 任一为空则整个函数直接跳过（原始 test/jz 到函数尾） */
    if (!pRtlInitUnicodeString || !pZwCreateFile || !pZwClose)
        return 0;

    /* ④ RtlInitUnicodeString(&UnicodeString, 路径) */
    struct _UNICODE_STRING UniStr;
    ((void (__fastcall *)(_UNICODE_STRING *, const WCHAR *))pRtlInitUnicodeString)(
        &UniStr, PathBuf);                                                 // 0x140047CF8

    /* ⑤ 构造 OBJECT_ATTRIBUTES + FILE_BASIC_INFORMATION + IO_STATUS_BLOCK 并 ZwCreateFile
     *    原始填充（逐条对应）：
     *      var_88(+0x00)=0x30(Length)  var_80(+0x08)=0(RootDirectory)
     *      var_78(+0x10)=&UniStr       var_70(+0x18)=0x240(Attributes)
     *      var_68(0x10 字节)=0         var_58(=0)
     *      栈参数：var_E0=0(AllocationSize) var_D8=0x80(FileAttributes)
     *              var_D0=1(ShareAccess)     var_C8=1(Disposition=FILE_OPEN)
     *              var_C0=0x20(CreateOptions=FILE_SYNCHRONOUS_IO_NONALERT)
     *    调用：ZwCreateFile(&Handle, 0x80000000, &OA, &IOSB, NULL, 0x80, 0, 1, 1, 0x20)
     */
    struct _OBJECT_ATTRIBUTES ObjAttr;
    struct _IO_STATUS_BLOCK   IoStatus;
    FILE_BASIC_INFORMATION    BasicInfo;
    HANDLE                    Handle = 0;
    __int64                   Status;

    ObjAttr.Length                   = sizeof(ObjAttr);        // 0x30
    ObjAttr.RootDirectory            = 0;
    ObjAttr.ObjectName               = &UniStr;
    ObjAttr.Attributes               = 0x240;
    ObjAttr.SecurityDescriptor       = 0;
    ObjAttr.SecurityQualityOfService = 0;
    BasicInfo = (FILE_BASIC_INFORMATION){0};
    IoStatus.Status = 0;
    IoStatus.Information = 0;

    Status = ((__int64 (__fastcall *)(HANDLE *, unsigned int, struct _OBJECT_ATTRIBUTES *,
                                      struct _IO_STATUS_BLOCK *, __int64, unsigned int,
                                      unsigned int, unsigned int, unsigned int,
                                      unsigned int))pZwCreateFile)(
                 &Handle, 0x80000000u, &ObjAttr, &IoStatus,
                 0, 0x80u, 1u, 1u, 0x20u, 0);                          // 0x140047D56
    if (Status < 0)
        return 0;                                                       // 0x140047D5A

    /* ⑥ AllocExBufferAndQuerySystemInfo(16)：取系统句柄表 */
    __int64 pInfoBuffer = (__int64)AllocExBufferAndQuerySystemInfo(16);     // 0x140047D5F
    if (pInfoBuffer)
    {
        unsigned int EntryCount = *(unsigned int *)pInfoBuffer;             // 0x140047D6C
        __int64      TypeIndex  = GtRead(GtCurrentProcessId);               // 0x140047D74（GT 0x878）

        if (EntryCount)
        {
            char  *pEntry = (char *)(pInfoBuffer + 8);                      // 0x140047D81
            unsigned int idx = 0;
            for (;;)
            {
                /* 句柄项 +6 的 WORD 若等于刚打开句柄的类型索引（UniStr 前 2 字节），
                 * 且 CompareInt16Equal(句柄项+0 的 WORD, TypeIndex 低16位)==1 则命中 */
                if (*(WORD *)(pEntry + 6) == *(WORD *)&UniStr &&
                    CompareInt16Equal(*(__int16 *)pEntry, (__int16)TypeIndex) == 1)
                {
                    /* 命中：把该项 +0x0C 的字节写入 GT[0x60] */
                    GtWrite((GLOBAL_TABLE_INDEX)0x60,
                            (__int64)*(UCHAR *)(pEntry + 0x0C));            // 0x140047DBB
                    break;
                }
                ++idx;
                pEntry += 0x18;                                             // 0x140047DA0
                if (idx >= EntryCount)
                    break;                                                  // 0x140047DA7
            }
        }
        ExFree((void *)pInfoBuffer);                                        // 0x140047DC3
    }

    /* ⑦ 关闭句柄（经 GT 0x4334 指针） */
    ((void (__fastcall *)(HANDLE))pZwClose)(Handle);                        // 0x140047DCC
    return 0;
}