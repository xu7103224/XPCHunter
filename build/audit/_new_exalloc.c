// ExAlloc — 分配池内存（封装 ExAllocatePoolWithTag）
// 对应原始驱动 0x140077A00（50 字节）
// 【⚠ 修正记录 2026-10-13】原实现的 Tag 是**硬编码的 'XPHC'**，而原驱动
//   的 Tag 取自全局表索引 **0x877**（该索引在本项目枚举中未命名，
//   位于 MSR/对象类型字段区 2167）。硬编码 Tag 的后果：
//   ① 产物行为与原驱动不一致（分配出来的池标记不同，池标记枚举会看到差异）；
//   ② 载入真实内核时，若原驱动的其它部分按 0x877 的值来识别自己的分配，
//      硬编码会导致识别失败。
//   发现方式：windows-driver-emulation skill 逐函数差分显示
//   `FindModuleInLoaderList`（0x140007290）原始侧读到 GT 0x877 而我方没有——
//   追查发现该 GT 读发生在它调用的 ExAlloc 里。
// 【原始汇编】0x140077A00：
//   edi = PoolType（rcx 保存）；rbx = Size（rdx 保存）
//   ecx = 0x877 ; call GtRead          ; Tag = 全局表[0x877]
//   rdx = Size ; ecx = PoolType ; r8d = eax(Tag)
//   jmp ExAllocatePoolWithTag          ; 尾调用
void *ExAlloc(ULONG PoolType, ULONG Size)
{
    ULONG Tag = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x877);   // 0x140077A0C/14
    return ExAllocatePoolWithTag((POOL_TYPE)PoolType, Size, Tag);   // 0x140077A2B
}

// ExFree — 释放池内存（封装 ExFreePoolWithTag）
// 对应原始驱动 0x140077A34（36 字节）
// 【⚠ 修正记录 2026-10-13】同 ExAlloc：Tag 硬编码为 'XPHC'，
//   原始取自 GtRead(0x877)。
// 【原始汇编】0x140077A34：
//   rbx = Buffer（rcx 保存）
//   ecx = 0x877 ; call GtRead          ; Tag = 全局表[0x877]
//   rcx = Buffer ; edx = eax(Tag)
//   jmp ExFreePoolWithTag              ; 尾调用
void ExFree(void *Buffer)
{
    ULONG Tag = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x877);   // 0x140077A3D
    ExFreePoolWithTag(Buffer, Tag);                          // 0x140077A51
}
