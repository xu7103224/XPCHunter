// ============================================================================
// FeStealthCode.c — 隐蔽代码扫描（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.1 的 CStealthCodeDialog。
//
// 【为什么这个可以不用驱动】
//   "隐蔽代码"的定义是：进程内存里存在可执行页，但该页不属于任何已加载模块
//   （即典型的 shellcode / 反射式 DLL / 手动映射 PE）。
//   判定只需两件事：
//     1. VirtualQueryEx 枚举目标进程的所有 MEM_COMMIT 区域，筛选可执行的
//        （PAGE_EXECUTE*）
//     2. 与该进程已加载模块的 [Base, Base+Size) 区间做包含判断
//   两者都是 100% 用户态 API（OpenProcess + VirtualQueryEx +
//   EnumProcessModulesEx），不需要驱动。
//
//   原版同样如此——它只在"读不可读页内容"时才需要驱动；单纯判定
//   "哪块可执行内存不在模块里"是用户态就可完成的。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#define STL_MAX_HITS 2048
#define STL_MAX_MODS 1024

typedef struct _STL_HIT {
    ULONG64 Base;
    ULONG64 Size;
    ULONG   Protect;
    ULONG   Type;
    char    Note[128];
} STL_HIT;

typedef struct _STL_MOD {
    ULONG64 Base;
    ULONG64 Size;
    char    Name[128];
} STL_MOD;

static STL_HIT *g_StlHits = NULL;
static ULONG g_StlCount = 0;
static ULONG g_StlModules = 0;
static ULONG64 g_StlScannedBytes = 0;

static const char *StlProtectName(DWORD Prot)
{
    switch (Prot & 0xFF) {
    case PAGE_EXECUTE:            return "X";
    case PAGE_EXECUTE_READ:       return "RX";
    case PAGE_EXECUTE_READWRITE:  return "RWX";
    case PAGE_EXECUTE_WRITECOPY:  return "RWC";
    default:                      return "?";
    }
}

/* 判断地址是否落在任一模块区间内 */
static BOOL StlInModule(const STL_MOD *Mods, ULONG ModCount, ULONG64 Addr)
{
    ULONG i;
    for (i = 0; i < ModCount; i++) {
        if (Addr >= Mods[i].Base && Addr < Mods[i].Base + Mods[i].Size)
            return TRUE;
    }
    return FALSE;
}

/* 主入口：扫描指定 PID 的隐蔽可执行页。
   返回命中数；结果在 g_StlHits[0..g_StlCount)。 */
ULONG FeScanStealthCode(ULONG Pid)
{
    HANDLE hProc;
    STL_MOD *mods = NULL;
    ULONG modCount = 0;
    ULONG64 addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    if (g_StlHits) {
        free(g_StlHits);
        g_StlHits = NULL;
    }
    g_StlCount = 0;
    g_StlModules = 0;
    g_StlScannedBytes = 0;
    if (!Pid)
        return 0;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
    if (!hProc)
        return 0;   /* 无权限：调用方负责给状态提示 */

    /* 收集模块区间 */
    mods = (STL_MOD *)calloc(STL_MAX_MODS, sizeof(STL_MOD));
    if (!mods) {
        CloseHandle(hProc);
        return 0;
    }
    {
        HMODULE hMods[STL_MAX_MODS];
        DWORD needed = 0;
        if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &needed, LIST_MODULES_ALL)) {
            DWORD n = needed / sizeof(HMODULE);
            DWORD i;
            if (n > STL_MAX_MODS)
                n = STL_MAX_MODS;
            for (i = 0; i < n; i++) {
                MODULEINFO mi;
                if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi))) {
                    mods[modCount].Base = (ULONG64)mi.lpBaseOfDll;
                    mods[modCount].Size = (ULONG64)mi.SizeOfImage;
                    GetModuleBaseNameA(hProc, hMods[i], mods[modCount].Name,
                                       sizeof(mods[modCount].Name));
                    modCount++;
                }
            }
        }
    }
    g_StlModules = modCount;

    /* 枚举所有已提交区域 */
    g_StlHits = (STL_HIT *)calloc(STL_MAX_HITS, sizeof(STL_HIT));
    if (!g_StlHits) {
        free(mods);
        CloseHandle(hProc);
        return 0;
    }

    while (g_StlCount < STL_MAX_HITS &&
           VirtualQueryEx(hProc, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        ULONG64 base = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
        ULONG64 size = (ULONG64)mbi.RegionSize;

        /* 只统计真正提交的区域（未提交的 MEM_FREE 区间会填满整个地址空间，
           累加它会让"已扫描字节数"变成 0x7FFFFFFF0000 这种无意义值）。 */
        if (mbi.State == MEM_COMMIT)
            g_StlScannedBytes += size;

        /* 只看已提交且可执行的区域 */
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            if (!StlInModule(mods, modCount, base)) {
                STL_HIT *h = &g_StlHits[g_StlCount];
                h->Base = base;
                h->Size = size;
                h->Protect = mbi.Protect;
                h->Type = mbi.Type;
                sprintf_s(h->Note, sizeof(h->Note),
                          "executable %s page outside every loaded module",
                          StlProtectName(mbi.Protect));
                g_StlCount++;
            }
        }

        /* 防溢出：地址前进 */
        if (size == 0 || base + size <= base)
            break;
        addr = base + size;
        /* 用户态上限 */
        if (addr >= 0x7FFFFFFF0000ULL)
            break;
    }

    free(mods);
    CloseHandle(hProc);
    return g_StlCount;
}

BOOL FeStealthGet(ULONG Index, ULONG64 *Base, ULONG64 *Size, ULONG *Protect, const char **Note)
{
    if (!g_StlHits || Index >= g_StlCount)
        return FALSE;
    if (Base) *Base = g_StlHits[Index].Base;
    if (Size) *Size = g_StlHits[Index].Size;
    if (Protect) *Protect = g_StlHits[Index].Protect;
    if (Note) *Note = g_StlHits[Index].Note;
    return TRUE;
}

ULONG FeStealthCount(void)
{
    return g_StlCount;
}

ULONG FeStealthModules(void)
{
    return g_StlModules;
}

ULONG64 FeStealthScannedBytes(void)
{
    return g_StlScannedBytes;
}

void FeStealthFree(void)
{
    if (g_StlHits) {
        free(g_StlHits);
        g_StlHits = NULL;
    }
    g_StlCount = 0;
    g_StlModules = 0;
    g_StlScannedBytes = 0;
}