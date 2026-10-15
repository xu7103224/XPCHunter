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
// 对应原始驱动 sub_140029FC0（49 字节）
// 【⚠ 修正记录 2026-10-15】本函数此前有**三处**实质性错误，是实机加载
//   失败（sc start 报错误 31 = ERROR_GEN_FAILURE，即 DriverEntry 返回
//   STATUS_UNSUCCESSFUL）的直接原因：
//     错误A（最致命）：原有形参顺序为 (NtBuildNumber, DriverObject)，而调用点
//       传的是 (DriverObject, &NtBuildNumber)，于是 GT[1]（= 驱动对象指针，
//       全驱动都靠它）被写成了 **栈局部变量的地址**。InitSdstTable 随即用
//       `*(GT[1] + 40)` 去取模块链表头 —— 读到的是栈垃圾 → 找不到 ntoskrnl
//       → 返回 0 → DriverEntry 走 `goto Cleanup1` 返回 0xC0000001 → 错误 31。
//     错误B：GT[0] 被写成"构建号的值"。而 GT[0] 的语义是
//       **`nt!NtBuildNumber` 这个内核数据符号的地址**（不是它的值）。
//       证据：原始 DriverEntry 的 `mov rbx, cs:NtBuildNumber`（0x140080EF0）
//       是读 IAT 槽内容 —— 即该内核符号的运行时地址；随后把它写入 GT[0]。
//       InitSdstTable 正是拿 GT[0] 当**指针**做区间判断
//       （`GT0 > ModuleBase && GT0 < ModuleEnd`）来识别哪个模块是 ntoskrnl。
//     错误C：漏写 g_CurrentProcess / g_CurrentProcessId 两个槽。
// 【原始反汇编（判据 F，get_bytes 核对 0x140029FC0..0x140029FF0，9 条指令）】
//     sub rsp,28h
//     mov cs:g_DriverObjectPtr, rcx      ; rcx=参数1=DriverObject → GT[1]
//     mov cs:g_GlobalTable,     rdx      ; rdx=参数2=NtBuildNumber 地址 → GT[0]
//     call cs:IoGetCurrentProcess
//     mov cs:g_CurrentProcess,   rax     ; 0x1400A87F8 = GT + 0x308 = GT[97]
//     call cs:PsGetCurrentProcessId
//     mov cs:g_CurrentProcessId, rax     ; 0x1400AC8B0 = GT + 0x43C0 = GT[0x878]
//     add rsp,28h ; retn
//   g_DriverObjectPtr(0x1400A84F8) 紧邻 g_GlobalTable(0x1400A84F0)，即 GT[1]。
// 【参数】rcx=DriverObject（→GT[1]），rdx=NtBuildNumber 的**地址**（→GT[0]）。
// 【返回值】rax = PsGetCurrentProcessId() 的结果（原始返回该值）。
HANDLE InitGtCore(__int64 DriverObject, __int64 NtBuildNumberAddress)
{
    HANDLE ProcessId;

    GtWrite(GtDriverObject, DriverObject);                     // g_DriverObjectPtr = rcx
    GtWrite(GtNtBuildNumber, NtBuildNumberAddress);            // g_GlobalTable[0] = rdx

    GtWrite(GtCurrentProcess, (__int64)IoGetCurrentProcess()); // g_CurrentProcess   = GT[97]
    ProcessId = PsGetCurrentProcessId();
    GtWrite(GtCurrentProcessId, (__int64)ProcessId);           // g_CurrentProcessId = GT[0x878]

    return ProcessId;
}
