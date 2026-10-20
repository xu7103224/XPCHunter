// ============================================================================
// XPCHunter Frontend — Process 页各子视图的数据层
//
// 子视图与数据源（依据命令表 + 193 条 HANDLED 校准，见
// docs/reversing/命令可用性校准_2026-10-21.md）：
//
//   子视图     数据源                          当前状态
//   --------   -----------------------------   ------------------------------
//   Windows    EnumWindows + GetWindowThreadProcessId（纯用户态）   本文件已实现
//   Modules    0x49 CmdEnumProcessModules      待逆向输出布局
//   Threads    0x3B CmdEnumThreadsEx           待逆向输出布局
//              （注意 0x2A 虽名为 EnumThreads，实际实现是映像路径查询且会挂死）
//   Handles    0x54 CmdEnumProcessHandles / 0x61 CmdEnumHandlesByPid   待逆向输出布局
//   Memory     0x37 CmdReadProcessMemoryEx（内部 QueryProcessMemoryRegions）待逆向输出布局
//   Timers     无对应命令，需另找（可能是 0xC2/对象枚举路径）          待定
//   HotKey     无对应命令（窗口热键表在 win32k，需 ShadowSSDT 侧支持）  待定
//
// 进程操作：0x28 CmdProcessOperation（结束/挂起，属破坏性，扫描时主动跳过）、
//           0xA2 CmdTerminateProcessByEProcess、0xD2/0xD3 Enable/DisableProcessProtect。
// ============================================================================

#include "XPCHunterUM.h"
#include <stdio.h>
#include <psapi.h>   /* EnumProcessModulesEx / GetModuleInformation / GetModuleFileNameExW */

typedef struct _FE_ENUM_CTX {
    FE_WINDOW_LIST *List;
    ULONG           ProcessId;
    ULONG           Dropped;      /* 超出容量的条数 */
} FE_ENUM_CTX;

static BOOL CALLBACK FeEnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    FE_ENUM_CTX *ctx = (FE_ENUM_CTX *)lParam;
    DWORD pid = 0;
    DWORD tid;
    FE_WINDOW_ENTRY *e;

    (void)GetWindowThreadProcessId(hWnd, &pid);
    if ((ULONG)pid != ctx->ProcessId)
        return TRUE;

    if (ctx->List->Count >= ctx->List->Capacity) {
        ctx->Dropped++;
        return TRUE;
    }

    tid = GetWindowThreadProcessId(hWnd, NULL);
    e = &ctx->List->Items[ctx->List->Count];
    ZeroMemory(e, sizeof(*e));
    e->Hwnd = (ULONG64)(ULONG_PTR)hWnd;
    e->ThreadId = (ULONG)tid;
    e->ProcessId = (ULONG)pid;
    GetClassNameA(hWnd, e->ClassName, sizeof(e->ClassName) - 1);
    GetWindowTextW(hWnd, e->Title, (int)(sizeof(e->Title) / sizeof(e->Title[0])) - 1);
    ctx->List->Count++;
    return TRUE;
}

/* 枚举指定进程的顶层窗口。纯用户态，不需要驱动。 */
BOOL FeLoadProcessWindows(ULONG Pid, ULONG MaxCount, FE_WINDOW_LIST *List)
{
    FE_ENUM_CTX ctx;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!MaxCount)
        MaxCount = 256;

    List->Items = (FE_WINDOW_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               (SIZE_T)MaxCount * sizeof(FE_WINDOW_ENTRY));
    if (!List->Items)
        return FALSE;
    List->Capacity = MaxCount;

    ZeroMemory(&ctx, sizeof(ctx));
    ctx.List = List;
    ctx.ProcessId = Pid;

    if (!EnumWindows(FeEnumWindowsProc, (LPARAM)&ctx)) {
        FeFreeProcessWindows(List);
        return FALSE;
    }
    return TRUE;
}

void FeFreeProcessWindows(FE_WINDOW_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* 无头调试入口：xpch_frontend.exe --windows-cli <pid> */
BOOL FePrintProcessWindows(ULONG Pid)
{
    FE_WINDOW_LIST list;
    ULONG i;

    if (!FeLoadProcessWindows(Pid, 256, &list)) {
        printf("enum windows failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }

    printf("windows of pid %lu: %lu\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++) {
        char title[FE_WINDOW_ENTRY_TITLE_CHARS];
        FeWideToAnsi(list.Items[i].Title, title, sizeof(title));
        printf("  hwnd=%p tid=%-6lu class=%-30s title=%s\n",
               (void *)(ULONG_PTR)list.Items[i].Hwnd, list.Items[i].ThreadId,
               list.Items[i].ClassName[0] ? list.Items[i].ClassName : "(?)", title);
    }

    FeFreeProcessWindows(&list);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Modules 子视图：EnumProcessModulesEx + GetModuleFileNameExW（纯用户态）
//
// 为什么不用 0x49：0x49 是**内核**模块表，且依赖 GT[0x89C]/GT[0x89D]，
// 而后者的两个 Parse 函数又被 GT[0x4477] 门控 —— 该槽在原始驱动里只读不写
// （IDB 里搜 0x4477 只有两处，都是 GtRead），属于外部输入，当前为 0，
// 所以 0x49 一直是空表（见 docs/reversing/Process页落地_2026-10-21.md 第十二节）。
// Process 页的 Modules 视图要的是"选中进程的模块"，用 psapi 即可，且可验证。
// ---------------------------------------------------------------------------

BOOL FeLoadProcessModules(ULONG Pid, ULONG MaxCount, FE_MODULE_LIST *List)
{
    HANDLE h;
    HMODULE *mods = NULL;
    DWORD needed = 0, count = 0, i;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!MaxCount)
        MaxCount = 256;

    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
    if (!h)
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!h)
        return FALSE;

    mods = (HMODULE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                (SIZE_T)MaxCount * sizeof(HMODULE));
    if (!mods) {
        CloseHandle(h);
        return FALSE;
    }

    if (!EnumProcessModulesEx(h, mods, MaxCount * sizeof(HMODULE),
                              &needed, LIST_MODULES_ALL)) {
        HeapFree(GetProcessHeap(), 0, mods);
        CloseHandle(h);
        return FALSE;
    }

    count = needed / sizeof(HMODULE);
    if (count > MaxCount)
        count = MaxCount;

    List->Items = (FE_MODULE_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               (SIZE_T)count * sizeof(FE_MODULE_ENTRY));
    if (!List->Items) {
        HeapFree(GetProcessHeap(), 0, mods);
        CloseHandle(h);
        return FALSE;
    }
    List->Capacity = count;

    for (i = 0; i < count; i++) {
        MODULEINFO mi;
        FE_MODULE_ENTRY *e = &List->Items[List->Count];

        ZeroMemory(&mi, sizeof(mi));
        ZeroMemory(e, sizeof(*e));
        e->Base = (ULONG64)(ULONG_PTR)mods[i];
        if (GetModuleInformation(h, mods[i], &mi, sizeof(mi)))
            e->Size = mi.SizeOfImage;
        GetModuleFileNameExW(h, mods[i], e->Path,
                             (DWORD)(sizeof(e->Path) / sizeof(e->Path[0])));
        {
            const WCHAR *name = e->Path;
            const WCHAR *p = e->Path;
            while (*p) { if (*p == (WCHAR)0x5C || *p == L'/') name = p + 1; p++; }
            wcsncpy_s(e->Name, sizeof(e->Name) / sizeof(e->Name[0]), name, _TRUNCATE);
        }
        List->Count++;
    }

    HeapFree(GetProcessHeap(), 0, mods);
    CloseHandle(h);
    return TRUE;
}

void FeFreeProcessModules(FE_MODULE_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintProcessModules(ULONG Pid)
{
    FE_MODULE_LIST list;
    ULONG i;

    if (!FeLoadProcessModules(Pid, 512, &list)) {
        printf("enum modules failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("modules of pid %lu: %lu\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++) {
        char path[FE_MODULE_PATH_CHARS];
        FeWideToAnsi(list.Items[i].Path, path, sizeof(path));
        printf("  base=%p size=0x%-8lX %s\n",
               (void *)(ULONG_PTR)list.Items[i].Base, list.Items[i].Size, path);
    }
    FeFreeProcessModules(&list);
    return TRUE;
}
