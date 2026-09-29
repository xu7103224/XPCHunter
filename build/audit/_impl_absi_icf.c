// AllocBufferAndSendIoControl — 分配中间缓冲并发送 IO 控制
// 对应原始驱动 0x140075D94（436 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（54 行伪代码），按伪代码实现
// 【参数】9 个：a1=处理函数、a2/a3=句柄、a4=类型、a5=标志、
//   Dst=输出缓冲、NumberOfBytes=大小、a8=输出大小指针
// 【逻辑】与 SendIoControlWithQuotaBuffer **同源**，差异是处理函数多一个参数
//   （9 参 vs 8 参）且多传一个 0。结构同样是：
//   构建号 < 0x42EE → 直接用栈上 64 字节缓冲 P[]（或配额池，当大小 > 0x40）
//   → 调用处理函数 → 把结果 memmove 到 Dst → 释放配额池（P 不释放）。
//   ⚠ 注意：内层 `if (GtRead >= 0x42EE)` 在外层 `< 0x42EE` 条件下是**死分支**
//   （编译器保留的冗余判断），故实际只走 else 那条直调路径 —— 与
//   SendIoControlWithQuotaBuffer 的情况相同（那边是外层 >= 时内层必然成立）。
// 【⚠ 上层调用约定】调用方 SendWriteMemoryIoControl 按 8 实参调用，
//   而本函数声明 9 个形参 —— 差异见该函数的【⚠ 未实现依赖】说明。
__int64 __fastcall AllocBufferAndSendIoControl(
    __int64 (__fastcall *a1)(__int64, __int64, _QWORD, _QWORD, int, _BYTE *, _DWORD, size_t *, _QWORD),
    __int64 a2, __int64 a3, unsigned int a4, int a5,
    _BYTE *Dst, SIZE_T NumberOfBytes, size_t *a8)
{
    unsigned int v11 = (unsigned int)NumberOfBytes;
    int v12 = -1073741823;
    _BYTE *PoolWithQuotaTag;
    unsigned int v14;
    size_t MaxCount = 0;
    __int64 v18 = a3;
    _BYTE P[64];

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x42EE)
    {
        if ((unsigned int)NumberOfBytes > 0x40)
            PoolWithQuotaTag = ExAllocatePoolWithQuotaTag((POOL_TYPE)9, (unsigned int)NumberOfBytes, 0x42424D43u);
        else
            PoolWithQuotaTag = P;

        if (PoolWithQuotaTag)
        {
            v12 = (int)a1(a2, v18, 0, a4, a5, PoolWithQuotaTag, (_DWORD)NumberOfBytes, &MaxCount, 0);
            if (v12 >= 0)
            {
                v14 = (unsigned int)MaxCount;
                *(_DWORD *)a8 = (unsigned int)MaxCount;
                if ((unsigned int)NumberOfBytes > v14)
                    v11 = v14;
                memmove(Dst, PoolWithQuotaTag, v11);
            }
            if (PoolWithQuotaTag != P)
                ExFreePoolWithTag(PoolWithQuotaTag, 0x42424D43u);
        }
        return (unsigned int)v12;
    }
    else
    {
        return (unsigned int)a1(a2, a3, 0, a4, a5, Dst, (_DWORD)NumberOfBytes, a8, 0);
    }
}

// InitCallbackFunctions — 初始化回调函数（补全空壳）
// 对应原始驱动 0x140033EE8（84 字节）
// 【逆向来源】可反编译（15 行伪代码）
// 【⚠ 修正记录】此前是空壳（`return 1;` 且 doc 注释写着"InitProcessNotify();
//   InitThreadNotify();"两个被注释掉的调用），而它在 MemoryOperation.c:809 被真实调用。
// 【逻辑】先调 InitProcessNotify + InitThreadNotify；
//   然后按三个"结果槽是否已填"分别以**模式 0 / 2 / 1** 调 InitCallbackFunctionTable：
//     GT (GtEprocessField133|0x100) == 0  → InitCallbackFunctionTable(0)
//     GT (GtEprocessField134|0x100) == 0  → InitCallbackFunctionTable(2)
//     GT GtKernelDataField18 == 0         → InitCallbackFunctionTable(1)
//   （模式与结果槽的对应关系：0→GT 0x18F/0x18F 族、2→GT 0x190 族、1→GT 0x2A4 族，
//     见 InitCallbackFunctionTable 的实现与 §待实现文档）
//   返回最后一个 GtRead 的值（全已填时返回该值）。
__int64 InitCallbackFunctions(void)
{
    __int64 Status;

    InitProcessNotify();
    InitThreadNotify();

    if (!(unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField133 | 0x100)))
        InitCallbackFunctionTable(0);
    if (!(unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField134 | 0x100)))
        InitCallbackFunctionTable(2);

    Status = (__int64)GtRead(GtKernelDataField18);
    if (!(_DWORD)Status)
        return InitCallbackFunctionTable(1);
    return Status;
}