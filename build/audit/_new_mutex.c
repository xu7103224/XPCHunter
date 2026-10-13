#define GT_NOINLINE __declspec(noinline)

// AcquireMiniFilterMutex — 获取 Minifilter 互斥锁
// 对应原始驱动 0x14007182C（72 字节）
// 【⚠ 修正记录 2026-10-13】原实现为 `KeWaitForSingleObject(&g_Mutex,Executive,0,0,0);`
//   —— 与原驱动无关。原始实现在 0x4274/0x4277 两个全局表槽里取出**函数指针**，
//   再以 GtAlloc(0x1FB)（全局互斥体）为参数间接调用其中一个。
//   发现方式：windows-driver-emulation skill 逐函数差分时，原始侧读到 GT 0x4274
//   而我方侧为 0（函数被内联且语义不同）；逐条反汇编核对后确认。
// 【原始汇编】0x14007182C：
//   rbx = GtRead(0x4274)        ; 取函数指针 A
//   rdi = GtRead(0x4277)        ; 取函数指针 B
//   rax = GtAlloc(0x1FB)        ; 全局互斥体
//   if (rbx && rdi) rdi(rax)    ; 本函数调 B
// 【说明】本函数与 AcquireMiniFilterMutexEx 结构完全相同，唯一差异是**调用哪一个**：
//   本函数 `call rdi`（0x4277），Ex 版 `call rbx`（0x4274）。
//   两槽的语义应为「取锁/放锁」一对，槽名待考，故此处以裸索引标注。
GT_NOINLINE void AcquireMiniFilterMutex(void)
{
    __int64 FuncA = GtRead((GLOBAL_TABLE_INDEX)0x4274);   // 0x140071836
    __int64 FuncB = GtRead((GLOBAL_TABLE_INDEX)0x4277);   // 0x140071848
    __int64 Mutex = (__int64)GtAlloc(GtGlobalMutex);      // 0x140071855（0x1FB）

    if (FuncA && FuncB)                                   // 0x14007185A/85F
    {
        ((void (__fastcall *)(__int64))FuncB)(Mutex);     // 0x140071867（call rdi）
    }
}

// AcquireMiniFilterMutexEx — 获取 Minifilter 互斥锁（扩展）
// 对应原始驱动 0x140071874（72 字节）
// 【⚠ 修正记录 2026-10-13】同 AcquireMiniFilterMutex：原实现是
//   `KeWaitForSingleObject(...)` 的伪造版，且因函数体简单被 LTCG 内联消除，
//   导致 7 处调用点全部退化为"间接调用一个从未定义的导入桩"。
// 【原始汇编】0x140071874：与 0x14007182C 逐指令相同，仅最后调用不同——
//   `if (rbx && rdi) rbx(rax)`（call rbx = 调 0x4274 处的指针）。
GT_NOINLINE void AcquireMiniFilterMutexEx(void)
{
    __int64 FuncA = GtRead((GLOBAL_TABLE_INDEX)0x4274);   // 0x14007187E
    __int64 FuncB = GtRead((GLOBAL_TABLE_INDEX)0x4277);   // 0x140071890
    __int64 Mutex = (__int64)GtAlloc(GtGlobalMutex);      // 0x14007189D（0x1FB）

    if (FuncA && FuncB)                                   // 0x1400718A2/8A7
    {
        ((void (__fastcall *)(__int64))FuncA)(Mutex);     // 0x1400718AF（call rbx）
    }
}
