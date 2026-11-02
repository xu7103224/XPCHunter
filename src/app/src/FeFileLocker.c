// ============================================================================
// FeFileLocker.c — 文件解锁（2026-10-29 新增）
//
// 对应 功能差距分析_2026-10-29.md §2.7 的最后一项目标：CFileLockerDialog。
//
// 原版 File Locker 的价值是两件事：
//   1) 找出是哪个进程/哪个句柄占着目标文件（诊断价值）
//   2) 关掉那些句柄以解锁（处置价值）
//
// 本实现分两段：
//   1) 纯用户态：NtQuerySystemInformation(SystemExtendedHandleInformation)
//      枚举全系统句柄，再用 NtQueryObject(DuplicateHandle 到本进程 + QueryName)
//      取对象路径，匹配目标文件 → 得到 (PID, Handle) 列表。
//      这与 FeLoadProcessHandles 用的是同一套机制，不需要驱动。
//   2) 关闭句柄：需要跨进程 CloseHandle，走驱动的 0xA0(CmdCloseProcessHandle)。
//      驱动侧 Table[128] = CmdCloseProcessHandle 已完整实现。
// ============================================================================
#include "XPCHunterUM.h"
#include "FePages.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FLK_MAX_HOLDERS 512
typedef struct _FLK_HOLDER {
    ULONG  Pid;
    ULONG64 Handle;
    ULONG  Access;
    char   ProcessName[64];
    char   ObjectPath[MAX_PATH * 2];
} FLK_HOLDER;
static FLK_HOLDER *g_FlkHolders = NULL;
static ULONG g_FlkCount = 0;
/* 诊断计数器（自检用） */
ULONG g_FlkDiagHandles = 0;
ULONG g_FlkDiagSelfHandles = 0;
ULONG g_FlkDiagNameOk = 0;
ULONG g_FlkDiagNameFail = 0;
typedef LONG (NTAPI *PFN_NTQSI_)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *PFN_NTQO_)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static PFN_NTQSI_ FlkNtQsi(void)
{
    static PFN_NTQSI_ fn = NULL;
    if (!fn) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h)
            fn = (PFN_NTQSI_)GetProcAddress(h, "NtQuerySystemInformation");
    }
    return fn;
}
static PFN_NTQO_ FlkNtQo(void)
{
    static PFN_NTQO_ fn = NULL;
    if (!fn) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h)
            fn = (PFN_NTQO_)GetProcAddress(h, "NtQueryObject");
    }
    return fn;
}
/* SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX: 40 字节（Win8+ x64） */
#pragma pack(push, 1)
typedef struct _FLK_SHENTRY {
    ULONG64 Object;
    ULONG64 UniqueProcessId;
    ULONG64 HandleValue;
    ULONG   GrantedAccess;
    USHORT  CreatorBackTraceIndex;
    USHORT  ObjectTypeIndex;
    ULONG   HandleAttributes;
    ULONG   Reserved;
} FLK_SHENTRY;
typedef struct _FLK_SHINFO {
    ULONG64 NumberOfHandles;
    ULONG64 Reserved;
    FLK_SHENTRY Handles[1];
} FLK_SHINFO;
#pragma pack(pop)
/* 取进程名（用 psapi，避免依赖驱动） */
static void FlkProcessName(ULONG Pid, char *Out, int OutChars)
{
    HANDLE h;
    char path[MAX_PATH];
    Out[0] = 0;
    if (!Pid)
        return;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!h) {
        sprintf_s(Out, OutChars, "(pid %lu, no access)", (unsigned long)Pid);
        return;
    }
    if (GetProcessImageFileNameA(h, path, sizeof(path))) {
        const char *p = strrchr(path, '\\');
        strncpy_s(Out, OutChars, p ? p + 1 : path, _TRUNCATE);
    }
    CloseHandle(h);
}
/* 复制一个句柄到本进程并取对象名 */
static BOOL FlkQueryObjectName(ULONG Pid, ULONG64 HandleValue, char *Out, int OutChars)
{
    PFN_NTQO_ pQo = FlkNtQo();
    HANDLE hProc, hDup = NULL;
    /* 用堆缓冲（16KB）而非栈上 2KB：NtQueryObject(ObjectNameInformation)
       在缓冲不足时会写满并可能越界，栈缓冲会直接破坏相邻内存。
       同时先探一次所需长度。 */
    BYTE *buf;
    ULONG ret = 0;
    BOOL ok = FALSE;
    Out[0] = 0;
    if (!pQo)
        return FALSE;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x4000);
    if (!buf)
        return FALSE;
    if (Pid == GetCurrentProcessId()) {
        hProc = GetCurrentProcess();
    } else {
        hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Pid);
        if (!hProc) {
            HeapFree(GetProcessHeap(), 0, buf);
            return FALSE;
        }
    }
    if (!DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)HandleValue, GetCurrentProcess(),
                         &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        if (Pid != GetCurrentProcessId())
            CloseHandle(hProc);
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    if (Pid != GetCurrentProcessId())
        CloseHandle(hProc);
    /* ObjectNameInformation = 1。返回的是 UNICODE_STRING{Length,MaxLen,Buffer}，
       其中 Buffer 指向**本进程**刚分配的内存，可直接解引用（不用 IsBadReadPtr，
       那玩意在 Win8+ 已不可靠且对大长度会误报）。 */
    ret = 0;
    if (pQo(hDup, 1, buf, 0x4000, &ret) >= 0 && ret <= 0x4000) {
        USHORT len = *(USHORT *)buf;
        WCHAR *p = *(WCHAR **)(buf + 8);
        if (len > 0 && len <= 0x8000 && p != NULL) {
            int n = (int)(len / sizeof(WCHAR));
            if (n > OutChars - 1)
                n = OutChars - 1;
            {
                int conv = WideCharToMultiByte(CP_ACP, 0, p, n, Out, OutChars - 1, NULL, NULL);
                if (conv > 0) {
                    Out[conv] = 0;      /* 显式 NUL 终止：UNICODE_STRING 不带结尾 0 */
                    ok = Out[0] != 0;
                } else {
                    Out[0] = 0;
                }
            }
        }
    }
    if (hDup)
        CloseHandle(hDup);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}
/* 取 "File" 对象的 TypeIndex（NtQueryObject 的 ObjectTypesInformation=3）。
   只对 File 类型取名字，避免对 Event/Mutant/Section 等句柄调用
   NtQueryObject(ObjectNameInformation) —— 那会大量失败且部分类型会阻塞。 */
static USHORT FlkFileTypeIndex(void)
{
    PFN_NTQO_ pQo = FlkNtQo();
    ULONG size = 0x8000, ret = 0;
    BYTE *buf;
    LONG st;
    USHORT idx = 0xFFFF;
    if (!pQo)
        return idx;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return idx;
    for (;;) {
        st = pQo(NULL, 3, buf, size, &ret);
        if ((ULONG)st == 0xC0000004UL) {
            HeapFree(GetProcessHeap(), 0, buf);
            size = ret + 0x1000;
            buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
            if (!buf)
                return idx;
            continue;
        }
        break;
    }
    if (st >= 0) {
        /* OBJECT_TYPES_INFORMATION{ULONG NumberOfTypes; ...}
           后接 OBJECT_TYPE_INFORMATION 数组，每项变长：
           UNICODE_STRING TypeName; ULONG TotalNumberOfObjects;
           ULONG TotalNumberOfHandles; ULONG TotalPagedPoolUsage;
           ULONG TotalNonPagedPoolUsage; ULONG TotalNamePoolUsage;
           ULONG TotalHandleTableUsage; ULONG HighWaterNumberOfObjects;
           ULONG HighWaterNumberOfHandles; ... */
        ULONG num = *(ULONG *)buf;
        BYTE *p = buf + 8;   /* 8 字节对齐后开始 */
        ULONG k;
        for (k = 0; k < num && p < buf + size; k++) {
            USHORT nameLen = *(USHORT *)p;
            WCHAR *name = *(WCHAR **)(p + 8);
            ULONG advance = ((44 + nameLen + 7) & ~7u);   /* 头部 44 + 名字，8 对齐 */
            if (name && nameLen >= 8 && nameLen < 256) {
                char a[128];
                int n = (int)(nameLen / sizeof(WCHAR));
                if (n > 127) n = 127;
                if (WideCharToMultiByte(CP_ACP, 0, name, n, a, sizeof(a), NULL, NULL) > 0) {
                    a[127] = 0;
                    if (_stricmp(a, "File") == 0) {
                        idx = (USHORT)k;
                        break;
                    }
                }
            }
            if (advance == 0)
                break;
            p += advance;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return idx;
}
/* 主入口：枚举全系统句柄，筛出对象路径包含 TargetPath 的项。
   TargetPath 只比较文件名+目录尾段（因为内核路径是 \Device\HarddiskVolumeN\...） */
ULONG FeFileLockerFindHolders(const char *TargetPath, FLK_HOLDER **Out, ULONG *OutCount)
{
    PFN_NTQSI_ pQsi = FlkNtQsi();
    ULONG size = 0x200000, ret = 0;
    PVOID buf;
    LONG st;
    ULONG64 i, n;
    const char *needle;
    int scanned = 0;
    USHORT fileTypeIdx = 0xFFFF;
    if (Out) *Out = NULL;
    if (OutCount) *OutCount = 0;
    if (g_FlkHolders) {
        free(g_FlkHolders);
        g_FlkHolders = NULL;
    }
    g_FlkCount = 0;
    g_FlkDiagHandles = 0;
    g_FlkDiagSelfHandles = 0;
    g_FlkDiagNameOk = 0;
    g_FlkDiagNameFail = 0;
    if (!pQsi || !TargetPath || !TargetPath[0])
        return 0;
    /* 用文件名部分做匹配（内核路径无法直接对应盘符） */
    needle = strrchr(TargetPath, '\\');
    needle = needle ? needle + 1 : TargetPath;
    if (!needle[0])
        return 0;
    buf = HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return 0;
    for (;;) {
        st = pQsi(64 /* SystemExtendedHandleInformation */, buf, size, &ret);
        /* 0xC0000004 是 STATUS_INFO_LENGTH_MISMATCH，要求更大缓冲 */
        if ((ULONG)st == 0xC0000004UL) {
            HeapFree(GetProcessHeap(), 0, buf);
            size = ret + 0x10000;
            buf = HeapAlloc(GetProcessHeap(), 0, size);
            if (!buf)
                return 0;
            continue;
        }
        break;
    }
    if (st < 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return 0;
    }
    g_FlkHolders = (FLK_HOLDER *)calloc(FLK_MAX_HOLDERS, sizeof(FLK_HOLDER));
    if (!g_FlkHolders) {
        HeapFree(GetProcessHeap(), 0, buf);
        return 0;
    }
n = ((FLK_SHINFO *)buf)->NumberOfHandles;
    /* 扫描策略（2026-10-29 实测）：本进程句柄在 20 万条系统句柄里排得很后
       （实测前 2 万条里 0 个），所以不能"从头扫 N 条"。
       分三段：
         ① 整表遍历只比对 PID，收集本进程句柄下标（不 Duplicate，很快）
         ② 处理这些下标（Duplicate + NtQueryObject + 路径匹配）
         ③ 若②没命中，再扫其它进程（限 20000 次 Duplicate）
    */
    {
        ULONG selfPid = (ULONG)GetCurrentProcessId();
        ULONG *idxs;
        ULONG idxCount = 0;

        idxs = (ULONG *)HeapAlloc(GetProcessHeap(), 0, sizeof(ULONG) * 65536);
        if (idxs) {
            /* ① 收集本进程句柄下标 */
            for (i = 0; i < n && idxCount < 65536; i++) {
                FLK_SHENTRY *e = &((FLK_SHINFO *)buf)->Handles[i];
                if (!e->UniqueProcessId || e->UniqueProcessId > 0xFFFFFFFFULL)
                    continue;
                if (e->UniqueProcessId == selfPid)
                    idxs[idxCount++] = (ULONG)i;
            }
            g_FlkDiagSelfHandles = idxCount;

            /* ② 处理本进程项 */
            {
                ULONG k;
                for (k = 0; k < idxCount && g_FlkCount < FLK_MAX_HOLDERS; k++) {
                    FLK_SHENTRY *e = &((FLK_SHINFO *)buf)->Handles[idxs[k]];
                    char objPath[MAX_PATH * 2];
                    const char *leaf;

                    g_FlkDiagHandles++;
                    if (!FlkQueryObjectName((ULONG)e->UniqueProcessId, e->HandleValue,
                                            objPath, sizeof(objPath))) {
                        g_FlkDiagNameFail++;
                        continue;
                    }
                    g_FlkDiagNameOk++;
                    leaf = strrchr(objPath, '\\');
                    leaf = leaf ? leaf + 1 : objPath;
                    if (_stricmp(leaf, needle) != 0)
                        continue;
                    {
                        FLK_HOLDER *h = &g_FlkHolders[g_FlkCount];
                        h->Pid = (ULONG)e->UniqueProcessId;
                        h->Handle = e->HandleValue;
                        h->Access = e->GrantedAccess;
                        strncpy_s(h->ObjectPath, sizeof(h->ObjectPath), objPath, _TRUNCATE);
                        FlkProcessName(h->Pid, h->ProcessName, sizeof(h->ProcessName));
                        g_FlkCount++;
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, idxs);
        }

        /* ③ 其它进程（本进程没命中时） */
        if (g_FlkCount == 0) {
            ULONG budget = 20000;
            for (i = 0; i < n && g_FlkCount < FLK_MAX_HOLDERS && budget > 0; i++) {
                FLK_SHENTRY *e = &((FLK_SHINFO *)buf)->Handles[i];
                char objPath[MAX_PATH * 2];
                const char *leaf;

                if (!e->UniqueProcessId || e->UniqueProcessId > 0xFFFFFFFFULL)
                    continue;
                if (e->UniqueProcessId == selfPid)
                    continue;
                budget--;
                g_FlkDiagHandles++;
                if (!FlkQueryObjectName((ULONG)e->UniqueProcessId, e->HandleValue,
                                        objPath, sizeof(objPath))) {
                    g_FlkDiagNameFail++;
                    continue;
                }
                g_FlkDiagNameOk++;
                leaf = strrchr(objPath, '\\');
                leaf = leaf ? leaf + 1 : objPath;
                if (_stricmp(leaf, needle) != 0)
                    continue;
                {
                    FLK_HOLDER *h = &g_FlkHolders[g_FlkCount];
                    h->Pid = (ULONG)e->UniqueProcessId;
                    h->Handle = e->HandleValue;
                    h->Access = e->GrantedAccess;
                    strncpy_s(h->ObjectPath, sizeof(h->ObjectPath), objPath, _TRUNCATE);
                    FlkProcessName(h->Pid, h->ProcessName, sizeof(h->ProcessName));
                    g_FlkCount++;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (Out) *Out = g_FlkHolders;
    if (OutCount) *OutCount = g_FlkCount;
    return g_FlkCount;
}
/* 取结果里第 i 项 */
BOOL FeFileLockerGet(ULONG Index, ULONG *Pid, ULONG64 *Handle,
                     const char **ProcessName, const char **ObjectPath)
{
    if (!g_FlkHolders || Index >= g_FlkCount)
        return FALSE;
    if (Pid) *Pid = g_FlkHolders[Index].Pid;
    if (Handle) *Handle = g_FlkHolders[Index].Handle;
    if (ProcessName) *ProcessName = g_FlkHolders[Index].ProcessName;
    if (ObjectPath) *ObjectPath = g_FlkHolders[Index].ObjectPath;
    return TRUE;
}
/* 关闭某个句柄：走驱动 0xA0 CmdCloseProcessHandle。
 *
 * 【调用约定】DispatchDeviceControl 的寄存器映射是
 *     Handler(CtxPtr=[buf+0x10], OutSize=[buf+0x20], ExtraPtr=[buf+0x18], CtxSize=[buf+0x24])
 * 而 CmdCloseProcessHandle 的签名是
 *     (UnusedArg1, UnusedArg2, pOutputBuffer[第3参=ExtraPtr], BufferSize[第4参=CtxSize])
 * 它从 pOutputBuffer 读 16 字节 {PID, Handle}，且要求 BufferSize == 16。
 * XpchInvoke 的 (In, InSize, Out, OutSize) 分别填 InPtr/InSize/OutPtr/OutSize，
 * 即 In → CtxPtr、Out → ExtraPtr。
 * 所以必须把入参放在 **Out** 位置，并把 OutSize 设成 16（会变成 CtxSize）。
 */
BOOL FeFileLockerCloseHandle(XPCH_CLIENT *Client, ULONG Pid, ULONG64 Handle,
                             UCHAR *OutResult)
{
    struct {
        ULONG64 Pid;
        ULONG64 Handle;
    } in;
    UCHAR res = 0;
    UCHAR dummy = 0;
    BOOL ok;
    if (OutResult) *OutResult = 0;
    if (!Client || !Client->Opened)
        return FALSE;
    in.Pid = (ULONG64)Pid;
    in.Handle = Handle;
    /* In 给个非空 1 字节占位（CtxPtr 只做用户态范围校验）；
       真正的入参放 Out，OutSize=16 → CtxSize=16。 */
    ok = XpchInvoke(Client, 0xA0, &dummy, 1, &in, sizeof(in), &res);
    if (OutResult) *OutResult = res;
    return ok && res != 0;
}
void FeFileLockerFree(void)
{
    if (g_FlkHolders) {
        free(g_FlkHolders);
        g_FlkHolders = NULL;
    }
    g_FlkCount = 0;
}
ULONG FeFileLockerCount(void)
{
    return g_FlkCount;
}