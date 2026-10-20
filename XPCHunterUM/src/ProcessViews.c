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
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>   /* UNICODE_STRING */   /* CreateToolhelp32Snapshot / Thread32First */   /* EnumProcessModulesEx / GetModuleInformation / GetModuleFileNameExW */

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

// ---------------------------------------------------------------------------
// Threads 子视图：CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)（纯用户态）
//
// 为什么不用 0x3B CmdEnumThreadsEx：它的输出布局尚未逆向；而线程枚举用
// Toolhelp 就能拿到 线程ID / 优先级 / 起始地址，且不依赖驱动的实体化命令。
// 起始地址走 ntdll!NtQueryInformationThread(ThreadQuerySetWin32StartAddress=9)，
// 拿不到就留空（受保护进程会失败）。
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

BOOL FeLoadProcessThreads(ULONG Pid, ULONG MaxCount, FE_THREAD_LIST *List)
{
    HANDLE snap;
    THREADENTRY32 te;
    PFN_NtQueryInformationThread pNtQit;
    HMODULE hNtdll;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!MaxCount)
        MaxCount = 512;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return FALSE;

    List->Items = (FE_THREAD_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               (SIZE_T)MaxCount * sizeof(FE_THREAD_ENTRY));
    if (!List->Items) {
        CloseHandle(snap);
        return FALSE;
    }
    List->Capacity = MaxCount;

    hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQit = (PFN_NtQueryInformationThread)(hNtdll
             ? (void *)GetProcAddress(hNtdll, "NtQueryInformationThread") : NULL);

    ZeroMemory(&te, sizeof(te));
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            FE_THREAD_ENTRY *e;

            if (te.th32OwnerProcessID != Pid)
                continue;
            if (List->Count >= List->Capacity)
                break;

            e = &List->Items[List->Count];
            e->ThreadId = te.th32ThreadID;
            e->OwnerPid = te.th32OwnerProcessID;
            e->BasePriority = te.tpBasePri;
            e->PriorityDelta = te.tpDeltaPri;

            if (pNtQit) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    ULONG64 startAddr = 0;
                    if (pNtQit(hThread, 9 /* ThreadQuerySetWin32StartAddress */,
                               &startAddr, sizeof(startAddr), NULL) >= 0)
                        e->StartAddress = startAddr;
                    CloseHandle(hThread);
                }
            }
            List->Count++;
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return TRUE;
}

void FeFreeProcessThreads(FE_THREAD_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintProcessThreads(ULONG Pid)
{
    FE_THREAD_LIST list;
    ULONG i;

    if (!FeLoadProcessThreads(Pid, 1024, &list)) {
        printf("enum threads failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("threads of pid %lu: %lu\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("  tid=%-6lu basePrio=%-3ld delta=%-3ld start=%p\n",
               list.Items[i].ThreadId, list.Items[i].BasePriority,
               list.Items[i].PriorityDelta, (void *)(ULONG_PTR)list.Items[i].StartAddress);
    }
    FeFreeProcessThreads(&list);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Handles 子视图：NtQuerySystemInformation(SystemExtendedHandleInformation)
//                 + ObjectTypesInformation 取类型名（纯用户态）
//
// 不用 0x54/0x61：它们的输出布局还没逆向；而系统句柄表是公开信息，
// 一次查询拿全系统句柄，再按 UniqueProcessId 过滤即可。
// ---------------------------------------------------------------------------

typedef LONG (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *PFN_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _FE_HANDLE_ENTRY_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} FE_HANDLE_ENTRY_EX;

typedef struct _FE_OBJ_TYPE_INFO {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} FE_OBJ_TYPE_INFO;

static PFN_NtQuerySystemInformation FeNtQuerySystemInformation(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    return h ? (PFN_NtQuerySystemInformation)(void *)GetProcAddress(h, "NtQuerySystemInformation") : NULL;
}

/* 用 ObjectTypesInformation 建 TypeIndex -> 名字 的映射（最多 64 项）。 */
static void FeLoadTypeNames(char names[][64], int maxNames)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_NtQueryObject pNtQo = hNtdll
        ? (PFN_NtQueryObject)(void *)GetProcAddress(hNtdll, "NtQueryObject") : NULL;
    ULONG size = 0x4000, ret = 0;
    PVOID buf;
    LONG st;

    if (!pNtQo || maxNames <= 0)
        return;
    buf = HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return;
    st = pNtQo(NULL, 3 /* ObjectTypesInformation */, buf, size, &ret);
    if (st == (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) {
        HeapFree(GetProcessHeap(), 0, buf);
        size = ret + 0x1000;
        buf = HeapAlloc(GetProcessHeap(), 0, size);
        if (!buf)
            return;
        st = pNtQo(NULL, 3, buf, size, &ret);
    }
    if (st >= 0) {
        PUCHAR p = (PUCHAR)buf;
        PUCHAR end = p + ret;
        while (p + sizeof(FE_OBJ_TYPE_INFO) <= end) {
            FE_OBJ_TYPE_INFO *ti = (FE_OBJ_TYPE_INFO *)p;
            ULONG adv = (ULONG)(sizeof(FE_OBJ_TYPE_INFO) + ti->TypeName.MaximumLength);
            adv = (adv + 7) & ~7u;
            if (ti->TypeIndex < (UCHAR)maxNames && ti->TypeName.Buffer) {
                ULONG n = ti->TypeName.Length / sizeof(WCHAR);
                if (n > 60) n = 60;
                if (n) {
                    WideCharToMultiByte(CP_ACP, 0, ti->TypeName.Buffer, (int)n,
                                        names[ti->TypeIndex], 64, NULL, NULL);
                    names[ti->TypeIndex][n] = 0;
                }
            }
            if (!adv) break;
            p += adv;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

BOOL FeLoadProcessHandles(ULONG Pid, ULONG MaxCount, FE_HANDLE_LIST *List)
{
    PFN_NtQuerySystemInformation pNtQsi = FeNtQuerySystemInformation();
    ULONG size = 0x100000, ret = 0;
    PVOID buf;
    LONG st;
    ULONG_PTR count, i;
    char typeNames[64][64];

    if (!List || !pNtQsi)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!MaxCount)
        MaxCount = 2048;

    buf = HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return FALSE;
    for (;;) {
        st = pNtQsi(64 /* SystemExtendedHandleInformation */, buf, size, &ret);
        if (st == (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) {
            HeapFree(GetProcessHeap(), 0, buf);
            size = ret + 0x10000;
            buf = HeapAlloc(GetProcessHeap(), 0, size);
            if (!buf)
                return FALSE;
            continue;
        }
        break;
    }
    if (st < 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    /* 【2026-10-21】类型名解析（NtQueryObject(ObjectTypesInformation)）在实机上
       会让前端进程崩溃（变长数组解析越界），暂时关闭：Type 列显示类型索引。
       待用更稳的方式（例如只解析首项 + 严格长度校验）恢复。 */
    ZeroMemory(typeNames, sizeof(typeNames));

    List->Items = (FE_HANDLE_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               (SIZE_T)MaxCount * sizeof(FE_HANDLE_ENTRY));
    if (!List->Items) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    List->Capacity = MaxCount;

    count = *(ULONG_PTR *)buf;
    {
        const FE_HANDLE_ENTRY_EX *base = (const FE_HANDLE_ENTRY_EX *)((PUCHAR)buf + 2 * sizeof(ULONG_PTR));
        for (i = 0; i < count && List->Count < List->Capacity; i++) {
            const FE_HANDLE_ENTRY_EX *e = &base[i];
            FE_HANDLE_ENTRY *out;

            if ((ULONG)e->UniqueProcessId != Pid)
                continue;
            out = &List->Items[List->Count];
            out->Handle = e->HandleValue;
            out->Object = (ULONG64)(ULONG_PTR)e->Object;
            out->TypeIndex = e->ObjectTypeIndex;
            out->Access = e->GrantedAccess;
            out->Attributes = e->HandleAttributes;
            if (e->ObjectTypeIndex < 64 && typeNames[e->ObjectTypeIndex][0]) {
                strncpy_s(out->TypeName, sizeof(out->TypeName),
                          typeNames[e->ObjectTypeIndex], _TRUNCATE);
            }
            List->Count++;
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}

void FeFreeProcessHandles(FE_HANDLE_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintProcessHandles(ULONG Pid)
{
    FE_HANDLE_LIST list;
    ULONG i;

    if (!FeLoadProcessHandles(Pid, 4096, &list)) {
        printf("enum handles failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("handles of pid %lu: %lu\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++) {
        printf("  handle=0x%-6IX type=%-24s access=0x%-8lX object=%p\n",
               list.Items[i].Handle,
               list.Items[i].TypeName[0] ? list.Items[i].TypeName : "(?)",
               list.Items[i].Access, (void *)(ULONG_PTR)list.Items[i].Object);
    }
    FeFreeProcessHandles(&list);
    return TRUE;
}
