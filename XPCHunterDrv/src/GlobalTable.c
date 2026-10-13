// GlobalTable.c — 全局表操作
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 全局表是驱动核心数据存储，16384 个 64 位条目，用于存储所有运行时数据

#include "XPCHunterDrv.h"

// 全局表 g_GlobalTable：16384 个 64 位条目
// 对应原始驱动中的 qword_1400A84F0
volatile __int64 g_GlobalTable[GT_TOTAL_SIZE] = {0};

// 全局同步对象
KMUTEX g_GlobalMutex;               // 全局互斥体(用于 XpchAcquireGlobalLock/XpchReleaseGlobalLock)
KEVENT g_GlobalEvent;               // 全局事件
volatile LONG g_GlobalLock;         // 全局锁

// MiniFilter 链表互斥体与链表头指针
KMUTEX g_Mutex;                     // MiniFilter 链表互斥体
volatile PVOID g_Pointer;           // MiniFilter 链表头指针 (单向链表)
__int64 g_CommPortContext;          // MiniFilter 通信端口上下文

// 驱动初始化同步事件
KEVENT g_Event;                     // 驱动初始化完成事件

// 设备名称与符号链接名称缓冲区 (256 WCHAR 各)
WCHAR g_DeviceNameBuffer[256];      // 设备名称缓冲区
WCHAR g_SymlinkNameBuffer[256];     // 符号链接名称缓冲区

// 【必须禁止内联】GtAlloc / GtRead / GtWrite 是原驱动的实体函数
//   （sub_140029EEC / sub_140029EFC / sub_140029FF4），全驱动通过 call 访问。
//   它们的实现过于简单（一次数组索引），LTCG 会把它们整体内联消除，
//   导致产物里既没有这几个符号、调用点也变成直接读写 g_GlobalTable。
//   后果：① 与原驱动结构不一致；② 运行时无法观测 GT 访问序列
//   （差分审计工具与任何 hook 都失效）。故强制 noinline。
//   依据：2026-10-13 用 windows-driver-emulation skill 做逐函数差分时发现，
//   原始侧 `mov ecx,0x20; call GtRead` 我方侧变成 `mov r12,[rip+...]`，
//   且链接 map 中已无 GtRead/GtWrite 符号。
#define GT_NOINLINE __declspec(noinline)

// GtAlloc — 返回全局表中指定索引的指针
// 对应原始驱动 sub_140029EEC
GT_NOINLINE __int64* GtAlloc(GLOBAL_TABLE_INDEX Index)
{
    return (__int64 *)(ULONG_PTR)&g_GlobalTable[Index];
}

// GtRead — 读取全局表指定索引的 64 位值
// 对应原始驱动 sub_140029EFC
GT_NOINLINE __int64 GtRead(GLOBAL_TABLE_INDEX Index)
{
    return g_GlobalTable[Index];
}

// GtWrite — 写入 64 位值到全局表指定索引
// 对应原始驱动 sub_140029FF4
GT_NOINLINE __int64 GtWrite(GLOBAL_TABLE_INDEX Index, __int64 Value)
{
    g_GlobalTable[Index] = Value;
    return Value;
}

// InitGtCore — 初始化全局表核心条目
// 对应原始驱动 sub_140029FC0
HANDLE InitGtCore(__int64 NtBuildNumber, __int64 DriverObject)
{
    GtWrite(GtNtBuildNumber, NtBuildNumber);
    GtWrite(GtDriverObject, DriverObject);
    return (HANDLE)DriverObject;
}
