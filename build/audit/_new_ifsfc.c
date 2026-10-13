// InitFileSystemFilterCallbacks — 初始化文件系统过滤回调表
// 对应原始驱动 0x14000DC28（1569 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：一段约 25 行的通用循环
//   （遍历 FilterExtensionObject[0..0x20] 收集"像内核地址"的项），
//   与原始函数体毫无关系。注释称"从 GT 获取 minifilter 扩展对象"亦不符。
//   发现方式：windows-driver-emulation skill 逐函数差分显示原始读到 GT 0x421D
//   （= GtRtlInitUnicodeStringFunc，经 OpenFileSection），我方完全没有 GT 访问；
//   逐条反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写（IDA 对此函数无伪代码）。
// 【原始汇编骨架】
//   1) `cmp r8b,1; jne ...`：按 Is64Bit 选路径构造器
//        Is64Bit==1 → call BuildFsFilterDriverPath2 (0x14000EADC)
//        否则        → call BuildFsFilterDriverPath1 (0x14000DBC0)
//      两者内部都经 OpenFileSection（0x140078F48）打开节对象，
//      这也是差分里看到 GT 0x421D 的来源。
//   2) 取对象链： rsi = *(rax + 0x30)；要求非 0
//                rsi = *(rsi + 0x28)；要求非 0
//   3) `CheckMemoryValid(rsi, 1)` 与 `CheckMemoryValid(rsi + 0x1A9, 1)`
//      都必须返回 1。
//   4) *(r14) = *(rsi)            —— 把源结构首字段写到第 2 个参数
//   5) 展开 40 条表项（无循环，逐条硬编码）：
//        表项索引序列 = {3..13, 16..21, 24..34, 37..48}（跳过 14/15/22/23/35/36）
//        对第 k 条（idx = 序列[k]）：
//          target = rbx + 0xC0 + (idx-3)*0x38
//          *(DWORD *)(target - 0x14) = idx      ← 索引字段
//          *(QWORD *)target          = *(rsi + 0x38 + (idx-3)*8)   ← 回调指针
//          if (回调指针) *(BYTE *)(target - 0x18) = 1               ← 有效标志
//      步长 0x38、源步长 8、标志位在 target-0x18、索引在 target-0x14，
//      均由反汇编逐条核对（40/40 吻合）。
//   6) 返回 1（表填完）；任一前置校验失败返回 0（edi 初值 0）。
// 【参数】rbx = rcx（回调表基址）；r14 = rdx（输出首字段目标）；
//   r8b = Is64Bit。
__int64 InitFileSystemFilterCallbacks(__int64 FilterCallbackTable, _QWORD *OutFirstField, char Is64Bit)
{
    __int64 Result = 0;          // dil
    __int64 Object;              // rax：路径构造器返回
    __int64 Inner;               // rsi
    const int kSlotIndex[40] = {
        3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13,
        16, 17, 18, 19, 20, 21,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48
    };
    int i;

    /* 1) 按 Is64Bit 选择路径构造器 */
    if (Is64Bit == 1)
        Object = BuildFsFilterDriverPath2();      // 0x14000DC4B
    else
        Object = BuildFsFilterDriverPath1();      // 0x14000DC52

    if (!Object)                                   // 0x14000DC5A
        return Result;

    /* 2) 取对象链 */
    Inner = *(__int64 *)(Object + 0x30);           // 0x14000DC60
    if (!Inner)                                    // 0x14000DC67
        return Result;
    Inner = *(__int64 *)(Inner + 0x28);            // 0x14000DC6D
    if (!Inner)                                    // 0x14000DC74
        return Result;

    /* 3) 两级内存校验 */
    if ((char)CheckMemoryValid((void *)Inner) != 1)              // 0x14000DC7F
        return Result;
    if ((char)CheckMemoryValid((void *)(Inner + 0x1A9)) != 1)    // 0x14000DC95
        return Result;

    /* 4) 源结构首字段 → 第 2 个参数指向处 */
    *OutFirstField = *(_QWORD *)Inner;             // 0x14000DCA2/CA5

    /* 5) 展开填表（40 条） */
    for (i = 0; i < 40; ++i)
    {
        int    idx    = kSlotIndex[i];
        __int64 target = FilterCallbackTable + 0xC0 + (__int64)(idx - 3) * 0x38;
        __int64 cb     = *(__int64 *)(Inner + 0x38 + (__int64)(idx - 3) * 8);

        *(ULONG *)(target - 0x14) = (ULONG)idx;    // 索引字段
        *(__int64 *)target        = cb;            // 回调指针
        if (cb)                                    // 0x14000DCBD 起 test/je
            *(UCHAR *)(target - 0x18) = 1;         // 有效标志
    }

    return 1;                                      // 0x14000E22D mov dil,1
}
