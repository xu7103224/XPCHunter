// ============================================================================
// XPCHunter Frontend — Process 页各子视图的数据层
//
// 子视图与数据源（依据命令表 + 193 条 HANDLED 校准，见
// doc/archive/reversing/命令可用性校准_2026-10-21.md）：
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
// 所以 0x49 一直是空表（见 doc/archive/reversing/Process页落地_2026-10-21.md 第十二节）。
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
        /* ObjectTypesInformation 的返回缓冲区开头是 ULONG NumberOfTypes，
           数组从 +8 开始（8 字节对齐）。之前从 buf 起解析，把 NumberOfTypes
           和填充当成了第一个 OBJECT_TYPE_INFORMATION，于是所有 TypeName
           都指向错位地址，读出来是垃圾。 */
        PUCHAR p = (PUCHAR)buf + 2 * sizeof(ULONG);
        PUCHAR end = (PUCHAR)buf + ret;
        while (p + sizeof(FE_OBJ_TYPE_INFO) <= end) {
            FE_OBJ_TYPE_INFO *ti = (FE_OBJ_TYPE_INFO *)p;
            ULONG adv;
            USHORT maxLen = ti->TypeName.MaximumLength;
            USHORT len = ti->TypeName.Length;

            /* 严格校验：MaximumLength 必须合理、Length 不得大于 MaximumLength，
               推进量必须 >= 头部且不越界。任何一条不满足就停止解析，
               保留已经解析出来的部分（宁缺勿崩）。 */
            if (maxLen > 0x200 || len > maxLen) {
                break;
            }
            adv = (ULONG)(sizeof(FE_OBJ_TYPE_INFO) + maxLen);
            adv = (adv + 7) & ~7u;
            if (adv < (ULONG)sizeof(FE_OBJ_TYPE_INFO) || (PUCHAR)(p + adv) > end)
                break;

            if (ti->TypeIndex < (UCHAR)maxNames && ti->TypeName.Buffer && len) {
                ULONG n = len / sizeof(WCHAR);
                if (n > 60) n = 60;
                if (n) {
                    /* TypeName.Buffer 是内核写回的指针，在用户态地址空间里
                       指向同一块缓冲区的内部——用它之前先确认落在 buf..end 内。 */
                    PUCHAR nb = (PUCHAR)ti->TypeName.Buffer;
                    if (nb >= (PUCHAR)buf && nb + n * sizeof(WCHAR) <= end) {
                        WideCharToMultiByte(CP_ACP, 0, (WCHAR *)nb, (int)n,
                                            names[ti->TypeIndex], 64, NULL, NULL);
                        names[ti->TypeIndex][n] = 0;
                    }
                }
            }
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

    /* 类型名解析（NtQueryObject(ObjectTypesInformation)）。
       2026-10-21 之前这里被 ZeroMemory 关掉过，原因是变长数组解析越界导致前端崩溃。
       现在恢复了，但加了严格的长度校验（见 FeLoadTypeNames 的 adv 检查）：
         · 每项的 TypeName.Length 必须 <= MaximumLength
         · 推进量必须 >= 头部大小，且不得越过缓冲区末尾
         · 最多解析 maxNames 项、名字截断到 60 字符
       有了名字之后，Process 页的 Handles Type 列和 Registry 页的 Reg Handle
       才能按类型过滤（"Key"）。 */
    FeLoadTypeNames(typeNames, 64);

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


// ---------------------------------------------------------------------------
// Memory 子视图：VirtualQueryEx + GetMappedFileNameW（纯用户态）
//
// 不用 0x37 CmdReadProcessMemoryEx（QueryProcessMemoryRegions）：输出布局未逆向；
// VirtualQueryEx 能直接给出 基址/大小/保护/类型，映射区还能用 GetMappedFileNameW
// 取到模块路径。
// ---------------------------------------------------------------------------

BOOL FeLoadProcessMemory(ULONG Pid, ULONG MaxCount, FE_MEMORY_LIST *List)
{
    HANDLE h;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG64 addr = 0;
    const ULONG64 userLimit = 0x7FFFFFFEFFFFULL;

    if (!List)
        return FALSE;
    ZeroMemory(List, sizeof(*List));
    if (!MaxCount)
        MaxCount = 8192;

    h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!h)
        return FALSE;

    List->Items = (FE_MEMORY_ENTRY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                               (SIZE_T)MaxCount * sizeof(FE_MEMORY_ENTRY));
    if (!List->Items) {
        CloseHandle(h);
        return FALSE;
    }
    List->Capacity = MaxCount;

    while (addr < userLimit && List->Count < List->Capacity) {
        SIZE_T got = VirtualQueryEx(h, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi));
        FE_MEMORY_ENTRY *e;

        if (!got)
            break;
        if (mbi.State == MEM_FREE || mbi.RegionSize == 0) {
            addr = (ULONG64)(ULONG_PTR)mbi.BaseAddress + (mbi.RegionSize ? mbi.RegionSize : 0x1000);
            continue;
        }

        e = &List->Items[List->Count];
        e->Base = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
        e->Size = (ULONG64)mbi.RegionSize;
        e->Protect = mbi.Protect;
        e->State = mbi.State;
        e->Type = mbi.Type;
        if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
            GetMappedFileNameW(h, mbi.BaseAddress, e->Name,
                               (DWORD)(sizeof(e->Name) / sizeof(e->Name[0])));
        }
        List->Count++;

        addr = (ULONG64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(h);
    return TRUE;
}

void FeFreeProcessMemory(FE_MEMORY_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FePrintProcessMemory(ULONG Pid)
{
    FE_MEMORY_LIST list;
    ULONG i;

    if (!FeLoadProcessMemory(Pid, 16384, &list)) {
        printf("enum memory failed, GetLastError=%lu\n", GetLastError());
        return FALSE;
    }
    printf("memory regions of pid %lu: %lu\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++) {
        char nm[FE_MEMORY_NAME_CHARS];
        FeWideToAnsi(list.Items[i].Name, nm, sizeof(nm));
        printf("  base=%p size=0x%-9I64X protect=0x%-4lX type=0x%-4lX %s\n",
               (void *)(ULONG_PTR)list.Items[i].Base, list.Items[i].Size,
               list.Items[i].Protect, list.Items[i].Type, nm);
    }
    FeFreeProcessMemory(&list);
    return TRUE;
}


// ---------------------------------------------------------------------------
// 进程操作：命令 0x28 CmdProcessOperation
//
// 入参 16 字节 = { QWORD[0] = PID, QWORD[1] = EPROCESS（可为 0，由驱动按 PID 解析） }。
// 处理器内部：PsLookupProcessByProcessId → 跳过当前进程/自身 →
//             ZeroProcessMemoryPages（挂载到目标、逐 4KB 页清零用户空间）+ ProcessOperationWithAttach。
//
// 【2026-10-21 修正】0xA2 与 0x28 的入参格式**不同**，此前两者共用 16 字节输入，
// 导致 0xA2 永远失败：
//   0x28 CmdProcessOperation              要求 InputSize == 16，qword[0]=PID、qword[1]=EPROCESS
//   0xA2 TerminateProcessByEProcessOperation 要求 InputSize == 8，qword[0]=**EPROCESS**
//      （原始 0x140054430 `cmp edx,8 / jnz`：InputSize != 8 直接返回 0，
//        随后把前 8 字节当 EPROCESS 解引用；实机 trace 停在该校验上，stage=6）
// 所以按 ByEprocess 分别组装输入。
//
// 【2026-10-21 实测】0xA2 在 Win10 上**不终止进程**：驱动 build >= 0x1DB0 分支读
//   GT[0x42BC]（18362 上解析为 KeCancelTimer，见 doc/reversing/Process页落地
//   第 21 节），原始驱动同样如此。真正生效的是 **0x28**：内部
//   ZeroProcessMemoryPages 把目标用户空间逐页清零，实机验证
//   （build/audit/kill28b.txt）调用后目标 timeout.exe 从任务列表消失。
//
// 返回值语义：0x28 处理器的返回值按设计可能就是 0（分派校准文档已归类为
// "result==0 但处理器确实执行"），所以这里**不看结果字节，改为按效果判定**：
// 调用后重新枚举进程列表，PID 已消失才算成功。
//
// 注意：这是**破坏性操作**，GUI 侧必须二次确认；测试时只对自建进程使用。
// ---------------------------------------------------------------------------

/* 重新枚举进程列表，判断 PID 是否已不存在。
 *
 * 清零用户空间只是"让进程无法继续运行"；EPROCESS 真正从 PsActiveProcessHead
 * 摘链、进程退出，要等目标线程被调度后由内核完成，有可观测的延迟。
 * 所以这里做有限次重试（每次间隔 200ms），避免刚调用完就判失败。 */
static BOOL FeProcessPidGone(XPCH_CLIENT *Client, ULONG Pid)
{
    FE_PROCESS_LIST list;
    ULONG i, attempt;

    for (attempt = 0; attempt < 25; attempt++)
    {
        BOOL present = FALSE;

        if (FeLoadProcessList(Client, FE_PROC_DEFAULT_MAX, &list))
        {
            for (i = 0; i < list.Count; i++)
            {
                if (list.Items[i].Pid == Pid) { present = TRUE; break; }
            }
            FeFreeProcessList(&list);
            if (!present)
                return TRUE;
        }
        Sleep(200);
    }
    return FALSE;
}

BOOL FeKillProcess(XPCH_CLIENT *Client, ULONG Pid, ULONG64 Eprocess, BOOL ByEprocess)
{
    ULONG64 in[2];
    UCHAR res = 0;

    if (!Client || !Client->Opened || !Pid)
        return FALSE;

    if (ByEprocess)
    {
        /* 0xA2：只要 EPROCESS（8 字节）。 */
        if (!Eprocess)
            return FALSE;
        in[0] = Eprocess;
        XpchInvoke(Client, 0xA2, in, 8, NULL, 0, &res);
    }
    else
    {
        /* 0x28：PID + EPROCESS（16 字节）。 */
        in[0] = (ULONG64)Pid;
        in[1] = Eprocess;
        XpchInvoke(Client, 0x28, in, sizeof(in), NULL, 0, &res);
    }

    /* 结果字节在 0x28 上按设计可能就是 0，不能作为成功判据；
       以"PID 是否已从进程列表消失"为准。 */
    if (FeProcessPidGone(Client, Pid))
        return TRUE;

    /* 【2026-10-22】0x28 的处理函数在 ValidateProcessObject 不通过时会
       `return ValidateProcessObject(...) != 1`，即直接返回"成功"却什么都不做。
       实测部分进程（timeout.exe 等）因此报成功但没死。这里回落到 0xA2 的
       终止路径，仍以"进程是否消失"判定，避免 Kill 变成空操作。 */
    if (!ByEprocess && Eprocess)
    {
        in[0] = Eprocess;
        XpchInvoke(Client, 0xA2, in, 8, NULL, 0, &res);
        return FeProcessPidGone(Client, Pid);
    }
    return FALSE;
}


// ---------------------------------------------------------------------------
// View HotKey：命令 0x33 CmdEnumObjects（Win8 链表枚举路径）
//
// 原版 PCHunter64.exe 的对话框 CProcessHotkeyDialog::RefreshList（0x14015E0E0）
// 通过 sub_14004D560 发 0x33，输出缓冲 0x200000 字节：
//   +0x00 DWORD count
//   +0x08 起每条 0x38 字节：
//     +0x00 桶指针            （对话框列 1，0x%p）
//     +0x08 桶[2]             （对话框未用）
//     +0x10 桶[8]             （对话框列 2，0x%08X）
//     +0x14 修饰键 WORD       （8=Win 2=Ctrl 1=Alt 4=Shift）
//     +0x18 虚拟键码 DWORD
//     +0x20 PID（QUAD 的低 32 位，对话框列 4，%d）
//     +0x28 EPROCESS（QUAD，对话框列 7 及过滤依据）
//     +0x30 TID（QUAD 的低 32 位，对话框列 5，%d）
//   列 3 是热键名（对话框由修饰键+VK 在本机格式化，列 6 是进程名）。
//
// 驱动侧 WriteEnumObjectEntry 恒定写 8 字节，客户端 sub_14004D560 按 0x38 步长
// 复制；此处按同样的 0x38 步长解析。
// ---------------------------------------------------------------------------

/* 虚拟键名表（对应原版 qword_140527800，0x80 项，覆盖 VK 0x00-0x7F）。
 * 原表对未定义的 0x01-0x07/0x0A-0x0C 等使用 ASCII 控制符名（SOH…BEL/LF/VT/FF），
 * 这里按提取结果复刻；0x5E 为空，0x70-0x7F 为 F1-F16。 */
static const WCHAR * const g_HotkeyVkNames[0x80] = {
    NULL,
    L"SOH", L"STX", L"ETX", L"EOT", L"ENQ", L"ACK", L"BEL",
    L"Backspace", L"Tab", L"LF", L"VT", L"FF", L"Enter", L"SO", L"SI",
    L"Shift", L"Ctrl", L"Alt", L"Pause", L"Caps Lock", L"NAK", L"SYN", L"ETB",
    L"CAN", L"EM", L"SUB", L"Esc", L"FS", L"GS", L"RS", L"US",
    L"Space", L"PageUp", L"PageDown", L"End", L"Home", L"Left", L"Up", L"Right",
    L"Down", L"Select", L"Print", L"Execute", L"Snapshot", L"Insert", L"Delete", L"Help",
    L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7",
    L"8", L"9", L":", L";", L"<", L"=", L">", L"?",
    L"@", L"A", L"B", L"C", L"D", L"E", L"F", L"G",
    L"H", L"I", L"J", L"K", L"L", L"M", L"N", L"O",
    L"P", L"Q", L"R", L"S", L"T", L"U", L"V", L"W",
    L"X", L"Y", L"Z", L"LWIN", L"RWIN", L"Apps", NULL, L"Sleep",
    L"NumPad0", L"NumPad1", L"NumPad2", L"NumPad3", L"NumPad4", L"NumPad5", L"NumPad6", L"NumPad7",
    L"NumPad8", L"NumPad9", L"*", L"+", L"Separator", L"-", L"Decimal", L"Divide",
    L"F1", L"F2", L"F3", L"F4", L"F5", L"F6", L"F7", L"F8",
    L"F9", L"F10", L"F11", L"F12", L"F13", L"F14", L"F15", L"F16"
};

/* 复刻原版 sub_14004D2F0：按修饰键拼 "Win + "/"Ctrl + "/"Alt + "/"Shift + "，
 * 再拼 VK 名；末尾把空格和 '+' 截掉。修饰键无对应位时不加。 */
void FeFormatHotkey(WCHAR *Out, size_t OutChars, ULONG Modifiers, ULONG VirtualKey)
{
    size_t len;

    if (!Out || !OutChars)
        return;
    Out[0] = 0;

    if (Modifiers & 8)
        wcscat_s(Out, OutChars, L"Win + ");
    if (Modifiers & 2)
        wcscat_s(Out, OutChars, L"Ctrl + ");
    if (Modifiers & 1)
        wcscat_s(Out, OutChars, L"Alt + ");
    if (Modifiers & 4)
        wcscat_s(Out, OutChars, L"Shift + ");

    if (VirtualKey < 0x80 && g_HotkeyVkNames[VirtualKey])
        wcscat_s(Out, OutChars, g_HotkeyVkNames[VirtualKey]);

    len = wcslen(Out);
    while (len && (Out[len - 1] == L' ' || Out[len - 1] == L'+'))
        Out[--len] = 0;
}

void FeFreeProcessHotkeys(FE_HOTKEY_LIST *List)
{
    if (!List)
        return;
    if (List->Items)
        HeapFree(GetProcessHeap(), 0, List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

BOOL FeLoadProcessHotkeys(XPCH_CLIENT *Client, ULONG64 Eprocess,
                          ULONG MaxCount, FE_HOTKEY_LIST *List)
{
    const ULONG OutSize = 0x200000;
    const ULONG EntrySize = 0x38;
    UCHAR *buf;
    UCHAR result = 0;
    ULONG count, limit, i, kept = 0;

    if (!List)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    ZeroMemory(List, sizeof(*List));

    if (!Client || !Client->Opened)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    buf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, OutSize);
    if (!buf)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    /* 驱动要求 InputSize=0、OutputSize>=0x40；原版 sub_14004D560 也传 0x200000。 */
    if (!XpchInvoke(Client, XPCH_CMD_ENUM_OBJECTS, NULL, 0, buf, OutSize, &result))
    {
        HeapFree(GetProcessHeap(), 0, buf);
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }

    /* 驱动按 (OutSize-64)/0x38+1 限定条数，这里做同样的上界校验。 */
    count = *(ULONG *)buf;
    limit = (OutSize - 64) / EntrySize + 1;
    if (count > limit)
        count = limit;

    if (count)
    {
        List->Items = (FE_HOTKEY_ENTRY *)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            (SIZE_T)count * sizeof(FE_HOTKEY_ENTRY));
        if (!List->Items)
        {
            HeapFree(GetProcessHeap(), 0, buf);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        List->Capacity = count;
    }

    for (i = 0; i < count; i++)
    {
        const UCHAR *p = buf + 8 + (SIZE_T)i * EntrySize;
        ULONG64 entryEprocess = *(ULONG64 *)(p + 0x28);
        FE_HOTKEY_ENTRY *e;

        /* Eprocess=0 表示不过滤（原版对话框“全部进程”模式 flag=1）。 */
        if (Eprocess && entryEprocess != Eprocess)
            continue;
        if (MaxCount && kept >= MaxCount)
            break;

        e = &List->Items[kept];
        e->Bucket = *(ULONG64 *)(p + 0x00);
        e->Flags = *(ULONG *)(p + 0x10);
        e->Modifiers = *(USHORT *)(p + 0x14);
        e->VirtualKey = *(ULONG *)(p + 0x18);
        e->Pid = *(ULONG *)(p + 0x20);
        e->Eprocess = entryEprocess;
        e->Tid = *(ULONG *)(p + 0x30);
        FeFormatHotkey(e->Hotkey, FE_HOTKEY_NAME_CHARS, e->Modifiers, e->VirtualKey);

        /* 原版列 6 用 sub_14002AB70(pid) 取映像路径再取 basename；
         * 用户态等价物是 QueryFullProcessImageName。取不到留空。 */
        if (e->Pid)
        {
            char path[FE_HOTKEY_PROC_NAME_CHARS];
            char *slash;

            if (FeGetProcessImagePath(e->Pid, path, sizeof(path)))
            {
                slash = strrchr(path, '\\');
                lstrcpynA(e->ProcessName, slash ? slash + 1 : path,
                          sizeof(e->ProcessName));
            }
        }
        kept++;
    }

    List->Count = kept;
    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}

BOOL FePrintProcessHotkeys(XPCH_CLIENT *Client, ULONG Pid)
{
    FE_PROCESS_LIST procs;
    FE_HOTKEY_LIST list;
    ULONG64 eprocess = 0;
    ULONG i;

    if (!Client || !Client->Opened || !Pid)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (FeLoadProcessList(Client, FE_PROC_DEFAULT_MAX, &procs))
    {
        for (i = 0; i < procs.Count; i++)
        {
            if (procs.Items[i].Pid == Pid)
            {
                eprocess = procs.Items[i].Eprocess;
                break;
            }
        }
        FeFreeProcessList(&procs);
    }
    if (!eprocess)
    {
        printf("process %lu not found (cannot resolve EPROCESS)\n", Pid);
        return FALSE;
    }

    if (!FeLoadProcessHotkeys(Client, eprocess, 0, &list))
    {
        /* 驱动 0x33 被拒时的可辨识提示。本机上对象表指针（GT[0x2E4]）
           为 0 或指向无效页（win32k 会话空间，session 0 不可读），
           原版驱动同样返回 REJECTED —— 不是实现缺陷。 */
        printf("enum hotkeys failed, GetLastError=%lu\n", GetLastError());
        printf("  (driver rejected cmd 0x33: the win32k hotkey table pointer\n"
               "   GT[0x2E4] is null or points into session space that is not\n"
               "   mapped in this process context; the original driver returns\n"
               "   REJECTED here too)\n");
        return FALSE;
    }
    printf("hotkeys of pid %lu: %lu\n", Pid, list.Count);
    for (i = 0; i < list.Count; i++)
    {
        FE_HOTKEY_ENTRY *e = &list.Items[i];
        char name[FE_HOTKEY_PROC_NAME_CHARS];
        FeWideToAnsi(e->Hotkey, name, sizeof(name));
        printf("  vk=0x%02lX mod=0x%lX tid=%lu bucket=%p flags=0x%08lX %s\n",
               e->VirtualKey, e->Modifiers, e->Tid,
               (void *)(ULONG_PTR)e->Bucket, e->Flags, name);
    }
    FeFreeProcessHotkeys(&list);
    return TRUE;
}

